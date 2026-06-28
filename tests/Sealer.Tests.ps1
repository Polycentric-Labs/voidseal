#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for scripts/lib/Sealer.ps1 (the Importer + Sealer + seal gate).

.DESCRIPTION
    Contract under test: the IMPORTER (one-way asset injection BEFORE seal), the SEALER
    (cut the VM to the tier's required isolation), and ASSERT-SEALED (the host-verified
    seal gate — the security heart of the deployer).

        Import-SandboxAsset  -Descriptor <d> -Source <path> -As <Iso|TransferVhd> [-Backend]
        Dismount-SandboxAsset -Descriptor <d> -Path <vhdx>  [-Backend]   (scripted transfer-VHD detach)
        Test-AssetIntegrity  -Path <path> -ExpectedSha256 <hex>
        Lock-Sandbox         -Descriptor <d> [-Backend]
        Assert-Sealed        -Descriptor <d> [-Backend]

    EVERYTHING touches Hyper-V through the backend abstraction (HyperVBackend.ps1) — this
    file's implementation NEVER calls a raw Hyper-V cmdlet. Tests inject the FAKE backend
    (New-FakeHyperVBackend) and assert against its in-memory state.

    Calling convention reminder: every backend method takes a SINGLE hashtable of named
    args, invoked as `& $backend.X @{ key = val }`. Collection-returning methods
    (GetNetworkAdapter / GetCheckpoint) preserve array semantics — read `.Count` directly.

    SECURITY MODEL: the SEAL is host-verified. For Tier >= 2,
    Get-VMNetworkAdapter MUST be empty (NIC removed, not just disconnected), no import media
    (DVD / transfer-VHD) attached, and all host channels off — the guest's own view is never
    authoritative. Assert-Sealed FAILS CLOSED: if a check cannot be performed, it refuses to
    certify. A deliberately-not-sealed VM MUST fail this gate.

    TDD: written FIRST; drives the Sealer.ps1 implementation.
#>

BeforeAll {
    # Resolve the skill root from this test file's location: <root>/tests/ -> <root>
    $script:SkillRoot   = Split-Path -Parent $PSScriptRoot
    $script:SealerPath  = Join-Path $script:SkillRoot 'scripts/lib/Sealer.ps1'
    $script:BackendPath = Join-Path $script:SkillRoot 'scripts/lib/HyperVBackend.ps1'
    $script:LoaderPath  = Join-Path $script:SkillRoot 'scripts/lib/ProfileLoader.ps1'
    $script:ProvPath    = Join-Path $script:SkillRoot 'scripts/lib/Provisioner.ps1'
    $script:TierDir     = Join-Path $script:SkillRoot 'tier-profiles'

    Test-Path $script:SealerPath  | Should -BeTrue -Because 'the Sealer script must exist to be tested'
    Test-Path $script:BackendPath | Should -BeTrue -Because 'the backend must exist'
    Test-Path $script:ProvPath    | Should -BeTrue -Because 'the Provisioner must exist'

    . $script:BackendPath
    . $script:LoaderPath
    . $script:ProvPath
    . $script:SealerPath

    $script:Tier1 = Import-TierProfile -Path (Join-Path $script:TierDir 'tier1.psd1')

    # --- a Tier-2 fixture profile (disposable no-net) built in-memory from the Tier-1 shape,
    # satisfying the loader's Tier>=2 invariants (Credentials/EgressMode None, empty allowlist,
    # cold-VHDX extraction). The repo ships only tier0/tier1 .psd1 today; the seal/gate logic
    # must work for the no-NIC tiers, so we synthesize a valid Tier-2 normalized profile here.
    $script:Tier2 = $script:Tier1.Clone()
    $script:Tier2['Tier']            = 2
    $script:Tier2['Description']     = 'TEST FIXTURE — Tier 2 disposable no-net VM.'
    $script:Tier2['Network']         = 'Private-NoNIC'
    $script:Tier2['EgressMode']      = 'None'
    $script:Tier2['EgressAllowlist'] = @()
    $script:Tier2['Credentials']     = 'None'
    $script:Tier2['Extraction']      = 'ColdVHDX-Quarantine-CDR'
    $script:Tier2['Lifecycle']       = 'CreateDestroy'
    # Sanity: the fixture is a VALID Tier-2 profile (fails closed here if we mis-built it).
    Assert-TierProfileValid -Profile $script:Tier2 -Context 'TEST Tier-2 fixture'

    # Build a real ISO source file on disk (Test-AssetIntegrity hashes host-side inputs).
    $script:TmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vmdep-t4-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $script:TmpRoot -Force | Out-Null
    $script:IsoSrc = Join-Path $script:TmpRoot 'seed-assets.iso'
    Set-Content -LiteralPath $script:IsoSrc -Value 'fake-iso-payload-for-hash-tests' -NoNewline -Encoding ascii
    $script:IsoSrcSha = (Get-FileHash -LiteralPath $script:IsoSrc -Algorithm SHA256).Hash

    # Provision a fresh VM on a fresh fake backend, returning @{ Backend; Desc }. Defined as a
    # script-scoped SCRIPTBLOCK (not a plain function) so Pester's child-scope It/BeforeEach
    # blocks can reach it via `& $script:NewTestSandbox` (a top-level `function` is not visible
    # in those child scopes; the repo's other test files inline this — we centralize it here).
    $script:NewTestSandbox = {
        param($Profile = $script:Tier1, [string] $Name = 'sbx-t4')
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $Profile -Name $Name -Backend $b
        return @{ Backend = $b; Desc = $d }
    }
}

AfterAll {
    if ($script:TmpRoot -and (Test-Path -LiteralPath $script:TmpRoot)) {
        Remove-Item -LiteralPath $script:TmpRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ===========================================================================
#  Test-AssetIntegrity — host-side hash verification of import inputs
# ===========================================================================
Describe 'Test-AssetIntegrity — host-side SHA-256 verification' {

    It 'passes when the file hash matches the expected SHA-256' {
        { Test-AssetIntegrity -Path $script:IsoSrc -ExpectedSha256 $script:IsoSrcSha } |
            Should -Not -Throw -Because 'a correct hash must verify'
        Test-AssetIntegrity -Path $script:IsoSrc -ExpectedSha256 $script:IsoSrcSha |
            Should -BeTrue -Because 'a matching hash returns $true'
    }

    It 'is case-insensitive about the expected hex digest' {
        Test-AssetIntegrity -Path $script:IsoSrc -ExpectedSha256 ($script:IsoSrcSha.ToLowerInvariant()) |
            Should -BeTrue -Because 'hex digests compare case-insensitively'
    }

    It 'throws when the file hash does NOT match (tamper / wrong file)' {
        $wrong = ('0' * 64)
        { Test-AssetIntegrity -Path $script:IsoSrc -ExpectedSha256 $wrong } |
            Should -Throw -Because 'a hash mismatch must fail closed (the asset is not what was expected)'
    }

    It 'throws when the source file does not exist' {
        { Test-AssetIntegrity -Path (Join-Path $script:TmpRoot 'no-such-file.iso') -ExpectedSha256 $script:IsoSrcSha } |
            Should -Throw -Because 'cannot verify an absent file — fail closed'
    }
}

# ===========================================================================
#  Import-SandboxAsset — ISO (one-way, read-only into the guest)
# ===========================================================================
Describe 'Import-SandboxAsset -As Iso — attaches a read-only ISO (DVD)' {

    BeforeEach {
        $sb = & $script:NewTestSandbox -Name 'sbx-iso'
        $script:B = $sb.Backend; $script:Desc = $sb.Desc
    }

    It 'attaches the ISO to the VM as a DVD drive' {
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:IsoSrc -As Iso -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-iso' }).DvdDrive |
            Should -Be $script:IsoSrc -Because 'an ISO import attaches via SetDvdDrive (one-way, read-only to the guest)'
    }

    It 'records the imported ISO on the descriptor so the Sealer knows to detach it' {
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:IsoSrc -As Iso -Backend $script:B
        @($script:Desc.ImportedMedia) | Should -Contain $script:IsoSrc -Because 'the seal must later detach import-only media; it must be tracked'
    }

    It 'throws when the ISO source file does not exist (fail closed before attaching)' {
        { Import-SandboxAsset -Descriptor $script:Desc -Source (Join-Path $script:TmpRoot 'ghost.iso') -As Iso -Backend $script:B } |
            Should -Throw -Because 'a missing import source must fail before touching the VM'
        (& $script:B.GetVM @{ Name = 'sbx-iso' }).DvdDrive |
            Should -BeNullOrEmpty -Because 'nothing should attach when the source is missing'
    }

    It 'verifies the ISO hash when -ExpectedSha256 is supplied (mismatch refuses to attach)' {
        { Import-SandboxAsset -Descriptor $script:Desc -Source $script:IsoSrc -As Iso -ExpectedSha256 ('f' * 64) -Backend $script:B } |
            Should -Throw -Because 'a hash mismatch must refuse the import (hashed pre-attach)'
        (& $script:B.GetVM @{ Name = 'sbx-iso' }).DvdDrive |
            Should -BeNullOrEmpty -Because 'a failed integrity check must not attach the ISO'
    }

    It 'attaches when -ExpectedSha256 matches' {
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:IsoSrc -As Iso -ExpectedSha256 $script:IsoSrcSha -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-iso' }).DvdDrive | Should -Be $script:IsoSrc
    }
}

# ===========================================================================
#  Import-SandboxAsset — TransferVhd (attach -> [guest copies] -> SCRIPTED detach)
# ===========================================================================
Describe 'Import-SandboxAsset -As TransferVhd — attaches a transfer disk; the detach is the seal step' {

    BeforeEach {
        $sb = & $script:NewTestSandbox -Name 'sbx-xfer'
        $script:B = $sb.Backend; $script:Desc = $sb.Desc
        # The transfer VHD must already exist on disk (the fake mirrors real Add-VMHardDiskDrive).
        $script:Xfer = Join-Path (Get-SandboxStorageRoot -Name 'sbx-xfer') 'transfer.vhdx'
        & $script:B.NewVHD @{ Path = $script:Xfer; SizeBytes = 8GB; Dynamic = $true }
    }

    It 'attaches the transfer VHD to the VM as a hard disk' {
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:Xfer -As TransferVhd -Backend $script:B
        @((& $script:B.GetVM @{ Name = 'sbx-xfer' }).HardDrives) |
            Should -Contain $script:Xfer -Because 'a TransferVhd import attaches via AddHardDiskDrive (caller copies inside the guest)'
    }

    It 'records the transfer VHD as import media (NOT inherently one-way; the seal must detach it)' {
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:Xfer -As TransferVhd -Backend $script:B
        @($script:Desc.ImportedMedia) | Should -Contain $script:Xfer
        @($script:Desc.TransferDisks) | Should -Contain $script:Xfer -Because 'transfer disks are tracked separately so the scripted detach knows what to remove'
    }

    It 'Dismount-SandboxAsset detaches the transfer VHD (the scripted, explicit detach)' {
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:Xfer -As TransferVhd -Backend $script:B
        @((& $script:B.GetVM @{ Name = 'sbx-xfer' }).HardDrives) | Should -Contain $script:Xfer

        Dismount-SandboxAsset -Descriptor $script:Desc -Path $script:Xfer -Backend $script:B
        @((& $script:B.GetVM @{ Name = 'sbx-xfer' }).HardDrives) |
            Should -Not -Contain $script:Xfer -Because 'the scripted detach removes the transfer disk; this is part of the seal'
    }

    It 'the detach leaves the transfer VHDX FILE on disk (detach != delete; data was copied in-guest)' {
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:Xfer -As TransferVhd -Backend $script:B
        Dismount-SandboxAsset -Descriptor $script:Desc -Path $script:Xfer -Backend $script:B
        (& $script:B.GetVHDInfo @{ Path = $script:Xfer }) |
            Should -Not -BeNullOrEmpty -Because 'detach only removes the attachment; the VHDX file persists (it is not the system disk)'
    }

    It 'the system disk (NOT import media) is never tracked as transfer media' {
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:Xfer -As TransferVhd -Backend $script:B
        @($script:Desc.TransferDisks) | Should -Not -Contain $script:Desc.DiskPath -Because 'the system disk must survive the seal; it is not import media'
    }
}

# ===========================================================================
#  Lock-Sandbox — Tier 2 (no-NIC) seal: detach media + remove NIC + channels off
# ===========================================================================
Describe 'Lock-Sandbox — seals a Tier-2 VM (NIC removed, media detached, channels off, State=Sealed)' {

    BeforeEach {
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-seal2'
        $script:B = $sb.Backend; $script:Desc = $sb.Desc

        # Import both kinds of media so the seal has something to detach.
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:IsoSrc -As Iso -Backend $script:B
        $script:Xfer = Join-Path (Get-SandboxStorageRoot -Name 'sbx-seal2') 'transfer.vhdx'
        & $script:B.NewVHD @{ Path = $script:Xfer; SizeBytes = 8GB; Dynamic = $true }
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:Xfer -As TransferVhd -Backend $script:B
    }

    It 'removes the NIC (GetNetworkAdapter is empty afterward) for a Tier>=2 seal' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        (& $script:B.GetNetworkAdapter @{ VMName = 'sbx-seal2' }).Count |
            Should -Be 0 -Because 'a Tier>=2 seal removes the NIC (no egress at all)'
    }

    It 'detaches the import ISO (DVD empty afterward)' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-seal2' }).DvdDrive |
            Should -BeNullOrEmpty -Because 'the import-only ISO must be detached as part of the seal'
    }

    It 'detaches the transfer VHD (the scripted, seal-enforced detach)' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        @((& $script:B.GetVM @{ Name = 'sbx-seal2' }).HardDrives) |
            Should -Not -Contain $script:Xfer -Because 'transfer media is NOT inherently one-way; the seal MUST detach it'
    }

    It 'turns OFF every host channel (clipboard / shares / guest-services / enhanced-session)' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        $ch = & $script:B.GetHostChannels @{ VMName = 'sbx-seal2' }
        $ch.Clipboard       | Should -BeFalse
        $ch.Shares          | Should -BeFalse
        $ch.GuestServices   | Should -BeFalse
        $ch.EnhancedSession | Should -BeFalse
    }

    It 'leaves the SYSTEM disk attached (the seal removes import media, not the boot disk)' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        @((& $script:B.GetVM @{ Name = 'sbx-seal2' }).HardDrives) |
            Should -Contain $script:Desc.DiskPath -Because 'the VM must still boot from its system disk after sealing'
    }

    It 'sets the descriptor State to Sealed' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        $script:Desc.State | Should -Be 'Sealed'
    }

    It 'does NOT power the VM on (the seal runs before first boot)' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-seal2' }).State |
            Should -Be 'Off' -Because 'sealing must not start the VM'
    }
}

# ===========================================================================
#  Lock-Sandbox — Tier 1 (net-restricted) seal KEEPS the NIC
# ===========================================================================
Describe 'Lock-Sandbox — a Tier-1 net-restricted seal keeps the NIC but still detaches media + channels off' {

    BeforeEach {
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-seal1'
        $script:B = $sb.Backend; $script:Desc = $sb.Desc
        Import-SandboxAsset -Descriptor $script:Desc -Source $script:IsoSrc -As Iso -Backend $script:B
    }

    It 'KEEPS the NIC for a Tier-1 net-restricted VM (egress is the nftables/allowlist concern, not the seal)' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        (& $script:B.GetNetworkAdapter @{ VMName = 'sbx-seal1' }).Count |
            Should -Be 1 -Because 'Tier-1 is net-restricted, not no-net; Lock-Sandbox does not strip the NIC at Tier 1'
    }

    It 'still detaches import media + turns host channels off + marks Sealed at Tier 1' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-seal1' }).DvdDrive | Should -BeNullOrEmpty
        (& $script:B.GetHostChannels @{ VMName = 'sbx-seal1' }).EnhancedSession | Should -BeFalse
        $script:Desc.State | Should -Be 'Sealed'
    }
}

# ===========================================================================
#  Assert-Sealed — THE GATE (host-verified, fails closed)
# ===========================================================================
Describe 'Assert-Sealed — certifies a properly-sealed Tier-2/3 VM' {

    It 'PASSES for a properly-sealed Tier-2 VM (no NIC, no media, channels off)' {
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-ok2'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        { Assert-Sealed -Descriptor $d -Backend $b } | Should -Not -Throw -Because 'a correctly-sealed Tier-2 VM must certify'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'PASSES for a properly-sealed Tier-3 VM' {
        $t3 = $script:Tier2.Clone()
        $t3['Tier'] = 3
        $t3['Lifecycle'] = 'DetonateWipe'
        Assert-TierProfileValid -Profile $t3 -Context 'TEST Tier-3 fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t3 -Name 'sbx-ok3' -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        { Assert-Sealed -Descriptor $d -Backend $b } | Should -Not -Throw
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }
}

Describe 'Assert-Sealed — FAILS CLOSED on any residual host channel / NIC / media (the security heart)' {

    BeforeEach {
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-gate'
        $script:B = $sb.Backend; $script:Desc = $sb.Desc
    }

    It 'FAILS when a NIC is still attached (Tier>=2 must have no NIC)' {
        # Seal everything EXCEPT removing the NIC: re-attach a NIC after a full seal.
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        & $script:B.NewSwitch @{ Name = 'leak-sw'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'sbx-gate'; SwitchName = 'leak-sw' }
        (& $script:B.GetNetworkAdapter @{ VMName = 'sbx-gate' }).Count | Should -Be 1 -Because 'precondition: a NIC is present'

        { Assert-Sealed -Descriptor $script:Desc -Backend $script:B } |
            Should -Throw -ExpectedMessage '*network adapter*' -Because 'a Tier>=2 VM with ANY NIC must FAIL the seal gate (host-verified, not guest-trusted)'
    }

    It 'FAILS when an import DVD (ISO) is still attached' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        # Re-attach an ISO after sealing (simulating a missed detach).
        & $script:B.SetDvdDrive @{ VMName = 'sbx-gate'; Path = $script:IsoSrc }
        { Assert-Sealed -Descriptor $script:Desc -Backend $script:B } |
            Should -Throw -ExpectedMessage '*DVD*' -Because 'an attached import DVD is a live host<->guest path; the gate must refuse'
    }

    It 'FAILS when a transfer VHD is still attached (import media not detached)' {
        # Import a transfer disk, seal, then RE-attach it (simulating a detach that did not run).
        $xfer = Join-Path (Get-SandboxStorageRoot -Name 'sbx-gate') 'transfer.vhdx'
        & $script:B.NewVHD @{ Path = $xfer; SizeBytes = 8GB; Dynamic = $true }
        Import-SandboxAsset -Descriptor $script:Desc -Source $xfer -As TransferVhd -Backend $script:B
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        # Re-attach the transfer disk after the seal.
        & $script:B.AddHardDiskDrive @{ VMName = 'sbx-gate'; Path = $xfer }

        { Assert-Sealed -Descriptor $script:Desc -Backend $script:B } |
            Should -Throw -ExpectedMessage '*transfer*' -Because 'a still-attached transfer VHD is import media that was not detached; fail closed'
    }

    It 'FAILS when a host channel is still ON (e.g. GuestServices left enabled)' {
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        & $script:B.SetHostChannel @{ VMName = 'sbx-gate'; Channel = 'GuestServices'; Enabled = $true }
        { Assert-Sealed -Descriptor $script:Desc -Backend $script:B } |
            Should -Throw -ExpectedMessage '*GuestServices*' -Because 'a live Guest Service Interface is a bidirectional VMBus channel; the seal gate must refuse'
    }

    It 'FAILS for a never-sealed VM (the deliberately-not-sealed case)' {
        # No Lock-Sandbox call at all: the VM still has its NIC + all channels on. For a Tier-2
        # VM the FIRST host-verified violation is the still-attached NIC (no-net tier must have
        # none) — pin that specific reason so a wrong-reason throw (e.g. a StrictMode $null.Count)
        # cannot pass this security-critical test green.
        { Assert-Sealed -Descriptor $script:Desc -Backend $script:B } |
            Should -Throw -ExpectedMessage '*network adapter*' -Because 'a VM that was never sealed MUST NOT pass the gate (a Tier>=2 VM fails first on its still-attached NIC)'
    }

    It 'FAILS when a (simulated) attached secret volume is present (SCHEMA invariant 6)' {
        # SCHEMA.md invariant 6: refuse to certify SEALED if ANY attached secret volume is
        # detected. Simulate by attaching a secret-shaped VHD after an otherwise-complete seal.
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        $secretVhd = Join-Path (Get-SandboxStorageRoot -Name 'sbx-gate') 'op-secrets.vhdx'
        & $script:B.NewVHD @{ Path = $secretVhd; SizeBytes = 1GB; Dynamic = $true }
        & $script:B.AddHardDiskDrive @{ VMName = 'sbx-gate'; Path = $secretVhd }
        # NB 'op-secrets.vhdx' is NOT secret-SHAPED by Test-IsSecretPath, so at Tier-2 the
        # STRUCTURAL "only the system disk" check (branch c) is what refuses it — its message
        # names it a 'residual secret/transfer volume'. Pin '*secret*' to lock that reason (the
        # Tier-1 sibling test exercises the name-shape branch (b) in isolation).
        { Assert-Sealed -Descriptor $script:Desc -Backend $script:B } |
            Should -Throw -ExpectedMessage '*secret*' -Because 'an attached secret-shaped volume must fail the Tier>=2 seal gate (invariant 6)'
    }
}

Describe 'Assert-Sealed — fails CLOSED when a host-side check cannot be performed' {

    It 'FAILS when the backend is unavailable (cannot verify => cannot certify)' {
        # Build a properly-sealed VM, then certify against a backend that reports unavailable.
        # If Assert-Sealed cannot run its host-side checks, it must REFUSE, never assume sealed.
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-failclosed'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b

        $bad = New-FakeHyperVBackend -SimulateUnavailable
        { Assert-Sealed -Descriptor $d -Backend $bad } |
            Should -Throw -ExpectedMessage '*cannot verify*' -Because 'if the host cannot verify the seal, the gate fails closed (never certifies on inability to check)'
    }

    It 'FAILS when the VM does not exist on the backend (nothing to verify)' {
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-gone'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        & $b.RemoveVM @{ Name = 'sbx-gone'; Force = $true }
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*no VM named*' -Because 'a missing VM cannot be certified sealed — fail closed'
    }

    It 'FAILS a Tier>=2 seal when the descriptor records NO system disk (cannot run the structural check)' {
        # A blank DiskPath means the "only the system disk may be attached" invariant-6 check
        # cannot run; certifying without it would be fail-OPEN. The gate must refuse.
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-nosys'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        $d.DiskPath = ''     # erase the recorded system disk
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*system disk*' -Because 'a Tier>=2 seal cannot be certified without knowing the legitimate system disk — fail closed'
    }

    It 'FAILS (does NOT certify) when a host-channel read THROWS — an unreadable channel must propagate, never be coerced to off' {
        # THE CENTRAL SAFETY BUG: a transient failure of the host-channel
        # read (e.g. the Guest Service Interface query) must NOT be swallowed into "off". If the
        # host cannot REPORT a channel's state, Assert-Sealed cannot know whether the bidirectional
        # Copy-VMFile / ESM channel is live, so it MUST fail closed — refuse to certify. A backend
        # that coerces an unreadable channel to $false would let Assert-Sealed certify SEALED with
        # the channel actually ON. Here the fake's GetHostChannels is made to throw (simulating one
        # channel's read failing); the gate must surface that as a refusal, not a pass.
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-chanerr'
        $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $sb.Backend     # a complete, correct seal on the working backend

        # A backend whose host-channel READ throws (one channel unreadable). Everything else
        # about the VM is identically sealed; only the channel query is broken.
        $errBackend = New-FakeHyperVBackend -SimulateChannelReadError
        $errDesc    = (New-SandboxVM -Profile $script:Tier2 -Name 'sbx-chanerr2' -Backend $errBackend)
        Lock-Sandbox -Descriptor $errDesc -Backend $errBackend
        { Assert-Sealed -Descriptor $errDesc -Backend $errBackend } |
            Should -Throw -ExpectedMessage '*channel*' -Because 'an unreadable host channel must propagate so the gate fails closed — never coerced to off'
    }
}

Describe 'Assert-Sealed — Tier-1 certifies the net-restricted seal WITHOUT requiring NIC removal' {

    It 'PASSES a Tier-1 sealed VM that legitimately still has a NIC (media detached, channels off)' {
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-t1seal'
        $b = $sb.Backend; $d = $sb.Desc
        Import-SandboxAsset -Descriptor $d -Source $script:IsoSrc -As Iso -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        # Tier-1 legitimately keeps its NIC.
        (& $b.GetNetworkAdapter @{ VMName = 'sbx-t1seal' }).Count | Should -Be 1 -Because 'precondition: Tier-1 keeps the NIC'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'the Tier-1 seal (media off, channels off) certifies without requiring NIC removal'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'a Tier-1 VM with a still-attached import DVD FAILS even though its NIC is allowed' {
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-t1leak'
        $b = $sb.Backend; $d = $sb.Desc
        Import-SandboxAsset -Descriptor $d -Source $script:IsoSrc -As Iso -Backend $b
        # Seal, then re-attach the ISO (a missed media detach) — NIC stays (Tier-1 allowed).
        Lock-Sandbox -Descriptor $d -Backend $b
        & $b.SetDvdDrive @{ VMName = 'sbx-t1leak'; Path = $script:IsoSrc }
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*DVD*' -Because 'import media must be detached for ANY tier seal, even when the NIC is legitimately present'
    }

    It 'a Tier-1 VM with a SECRET-SHAPED attached disk FAILS (exercises branch (b) in isolation — no Tier>=2 structural mask)' {
        # The existing secret-volume test is Tier-2, where the structural "only the system disk"
        # check (branch c) would refuse the disk regardless of its shape, masking branch (b). At
        # Tier-1 there is NO structural mask, so a secret-SHAPED attached disk must be caught
        # specifically by Test-IsSecretPath (branch b). This isolates that path.
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-t1secret'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        # A secret-shaped VHDX path (matches Test-IsSecretPath's leaf rules), attached post-seal.
        $secretVhd = Join-Path (Get-SandboxStorageRoot -Name 'sbx-t1secret') 'id_rsa.vhdx'
        & $b.NewVHD @{ Path = $secretVhd; SizeBytes = 1GB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-t1secret'; Path = $secretVhd }
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*secret*' -Because 'a secret-shaped attached volume must fail at ANY tier (invariant 6), even Tier-1 where no structural disk check applies'
    }

    It 'a Tier-1 VM with an UNEXPECTED residual disk (not secret-shaped, not import media) FAILS (best-effort backend-truth backstop)' {
        # IMPORTANT: at Tier-1 the strict "only the system disk" structural
        # check is gated Tier>=2, so a residual disk that is neither secret-shaped by name NOR in
        # the descriptor's import/transfer lists would slip through. The seal gate must apply a
        # best-effort backstop at ALL tiers: any attached disk that is NOT an EXPECTED disk
        # (system disk + the descriptor's CreatedDisks/DiskPaths) is a residual and must be refused.
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-t1resid'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        # A perfectly innocuous-LOOKING path (NOT secret-shaped, NOT recorded as import media):
        # a leftover data disk. Pre-fix this passes at Tier-1; post-fix the backstop catches it.
        $residual = Join-Path (Get-SandboxStorageRoot -Name 'sbx-t1resid') 'leftover-data.vhdx'
        & $b.NewVHD @{ Path = $residual; SizeBytes = 4GB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-t1resid'; Path = $residual }
        # Precondition: it is genuinely not flagged by the name-shape matcher (so this exercises
        # the new backstop, not branch (b)).
        (Test-IsSecretPath -Path $residual) | Should -BeFalse -Because 'precondition: the residual disk is NOT secret-shaped, so only the backend-truth backstop can catch it'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*unexpected*' -Because 'an unexpected residual disk (not an expected/created disk) must be refused as a best-effort backstop at every tier'
    }

    It 'a Tier-1 VM with ONLY its expected (system) disk attached still PASSES (no false-positive from the backstop)' {
        # The backstop must NOT reject a legitimately-sealed Tier-1 VM whose only attached disk is
        # the recorded system disk (an EXPECTED/created disk). Guards against over-eager refusal.
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-t1clean'
        $b = $sb.Backend; $d = $sb.Desc
        Import-SandboxAsset -Descriptor $d -Source $script:IsoSrc -As Iso -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        @((& $b.GetVM @{ Name = 'sbx-t1clean' }).HardDrives) | Should -Contain $d.DiskPath -Because 'precondition: only the system disk remains'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'the system disk is an expected disk; the backstop must not false-positive on it'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }
}

# ===========================================================================
#  Assert-Sealed — recorded workload data disks: the gate ACCEPTS a
#  data disk whose path is RECORDED on the descriptor (InputDiskPath/OutputDiskPath)
#  — an EXPECTED disk, not a residual — while STILL refusing an UNRECORDED attached
#  disk at every tier, and keeping the Tier>=2 structural rule for unrecorded disks.
# ===========================================================================
#  The disk-passing design attaches an INPUT + OUTPUT data disk to the VM BEFORE the seal. The
#  earlier gate (system disk + CreatedDisks + DiskPaths only) treats those data disks as
#  residual "unexpected" volumes and refuses to certify. The gate now records them as expected
#  WITHOUT weakening the unrecorded-disk refusal, the secret-shaped-path refusal, the NIC
#  check, or the DVD check. Each test below provisions via the SAME flow the green
#  Assert-Sealed tests use (New-SandboxVM -> Lock-Sandbox) so the host-channel / NIC / DVD
#  dimensions are already correct and ONLY the disk dimension varies.
Describe 'Assert-Sealed — accepts RECORDED workload data disks, still rejects UNRECORDED (disk-passing model)' {

    It 'ACCEPTS a recorded OUTPUT data disk attached to a Tier-0 sealed VM' {
        # A Tier-0 Linux VM, correctly sealed, with a RECORDED output data disk also attached.
        # The recorded OutputDiskPath is EXPECTED (not a residual) so the gate must certify.
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 (recorded-output-disk).'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST Tier-0 fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-g4out0' -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        # Create + attach a recorded OUTPUT data disk (the host-formatted exFAT result disk).
        $outDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4out0') 'out.vhdx'
        & $b.NewOutputVhdx @{ Path = $outDisk; Label = 'OUTPUT'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4out0'; Path = $outDisk }
        $d.OutputDiskPath = $outDisk   # RECORDED on the descriptor -> expected, not residual
        # Precondition: the output disk is NOT secret-shaped (so this exercises the expected-set
        # acceptance, not a secret-path or import-media path).
        (Test-IsSecretPath -Path $outDisk) | Should -BeFalse -Because 'precondition: the output data disk is not secret-shaped'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'a data disk recorded on the descriptor (OutputDiskPath) is an EXPECTED disk, not a residual — the gate must certify'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'ACCEPTS a recorded INPUT data disk attached to a Tier-0 sealed VM' {
        # Same as above but for the recorded INPUT data disk (the host-populated payload disk).
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 (recorded-input-disk).'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST Tier-0 in fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-g4in0' -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        $inDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4in0') 'in.vhdx'
        & $b.NewOutputVhdx @{ Path = $inDisk; Label = 'INPUT'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4in0'; Path = $inDisk }
        $d.InputDiskPath = $inDisk     # RECORDED -> expected
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'a data disk recorded on the descriptor (InputDiskPath) is an EXPECTED disk, not a residual'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'still REFUSES an UNRECORDED extra disk on a Tier-0 sealed VM (security regression guard)' {
        # The SAME certifiable sealed Tier-0 VM, but the extra attached disk is NOT recorded on the
        # descriptor (no InputDiskPath / OutputDiskPath). It must STILL be refused as a residual —
        # the unrecorded-disk refusal MUST NOT be weakened by the recorded-disk acceptance above.
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 (unrecorded-disk regression).'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST Tier-0 unrecorded fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-g4rogue0' -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        # An innocuous-LOOKING leftover disk: NOT secret-shaped, NOT import media, and crucially
        # NOT recorded on InputDiskPath/OutputDiskPath. The recorded-disk acceptance must not let it through.
        $rogue = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4rogue0') 'rogue.vhdx'
        & $b.NewVHD @{ Path = $rogue; SizeBytes = 64MB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4rogue0'; Path = $rogue }
        (Test-IsSecretPath -Path $rogue) | Should -BeFalse -Because 'precondition: the rogue disk is not secret-shaped, so only the expected-set backstop can catch it'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*unexpected*' -Because 'an UNRECORDED attached disk is still a residual and MUST be refused — accepting recorded data disks must not weaken this'
    }

    It 'ACCEPTS a recorded OUTPUT data disk on a Tier-2 sealed VM (structural rule allows recorded data disks)' {
        # At Tier>=2 the STRUCTURAL invariant-6 rule (branch c) previously allowed ONLY the system
        # disk. The recorded OutputDiskPath is EXPECTED (attached before seal, read via the cold-VHDX
        # quarantine path), so the structural rule must allow it too — at every tier it is recorded.
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-g4out2'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        $outDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4out2') 'out.vhdx'
        & $b.NewOutputVhdx @{ Path = $outDisk; Label = 'OUTPUT'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4out2'; Path = $outDisk }
        $d.OutputDiskPath = $outDisk
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'the recorded OutputDiskPath is an EXPECTED data disk at Tier-2 too — the structural rule must allow recorded data disks'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'still REFUSES an UNRECORDED extra disk on a Tier-2 sealed VM (structural rule stays strict for unrecorded)' {
        # The Tier>=2 structural rule must STILL refuse an UNRECORDED attached disk — even with a
        # recorded OutputDiskPath also present. Recording one data disk must not open the door to
        # arbitrary residual volumes on a no-net tier (the authoritative structural guarantee).
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-g4rogue2'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        $outDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4rogue2') 'out.vhdx'
        & $b.NewOutputVhdx @{ Path = $outDisk; Label = 'OUTPUT'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4rogue2'; Path = $outDisk }
        $d.OutputDiskPath = $outDisk   # one recorded data disk is fine...
        # ...but an UNRECORDED extra disk must still be refused.
        $rogue = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4rogue2') 'rogue.vhdx'
        & $b.NewVHD @{ Path = $rogue; SizeBytes = 64MB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4rogue2'; Path = $rogue }
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*unexpected*' -Because 'a Tier>=2 VM with an UNRECORDED extra disk must still fail the structural seal gate, even alongside a recorded data disk'
    }

    # --- Laundering regression: recording a secret-shaped path as a DATA disk
    #     must NOT launder the secret. The secret-shape check (branch b) runs BEFORE the
    #     recorded-data-disk allowance (branches c/d) in the SAME attached-disk loop iteration,
    #     so a path that is secret-SHAPED by Test-IsSecretPath is still REFUSED even when it is
    #     recorded on OutputDiskPath/InputDiskPath. These tests lock that ordering against any
    #     future refactor that might move the recorded-disk allowance ahead of the secret check.
    #     They MUST pass against the current code (they assert existing-correct behavior).
    It 'Assert-Sealed REFUSES a secret-shaped path recorded as OutputDiskPath (recording cannot launder a secret)' {
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 (secret-laundering-via-OutputDiskPath).'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST Tier-0 secret-output fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-g4secout0' -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        # A SECRET-SHAPED disk path (leaf '.env.vhdx' matches Test-IsSecretPath's '.env.*' glob),
        # attached to the VM AND recorded as the descriptor's OutputDiskPath. The recording must
        # NOT launder it past the secret check.
        $secretOut = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4secout0') '.env.vhdx'
        & $b.NewVHD @{ Path = $secretOut; SizeBytes = 64MB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4secout0'; Path = $secretOut }
        $d.OutputDiskPath = $secretOut   # RECORDED — must still NOT bypass the secret check
        (Test-IsSecretPath -Path $secretOut) | Should -BeTrue -Because 'precondition: the recorded OutputDiskPath is genuinely secret-shaped'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*secret*' -Because 'a secret-shaped path recorded as OutputDiskPath must STILL be refused — recording a disk cannot launder a secret (the secret check runs before the recorded-disk allowance)'
    }

    It 'Assert-Sealed REFUSES a secret-shaped path recorded as InputDiskPath (recording cannot launder a secret)' {
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 (secret-laundering-via-InputDiskPath).'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST Tier-0 secret-input fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-g4secin0' -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        # A SECRET-SHAPED disk path (leaf 'id_rsa.vhdx' matches Test-IsSecretPath's 'id_rsa*' glob),
        # attached AND recorded as the descriptor's InputDiskPath. Must STILL be refused.
        $secretIn = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4secin0') 'id_rsa.vhdx'
        & $b.NewVHD @{ Path = $secretIn; SizeBytes = 64MB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4secin0'; Path = $secretIn }
        $d.InputDiskPath = $secretIn     # RECORDED — must still NOT bypass the secret check
        (Test-IsSecretPath -Path $secretIn) | Should -BeTrue -Because 'precondition: the recorded InputDiskPath is genuinely secret-shaped'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*secret*' -Because 'a secret-shaped path recorded as InputDiskPath must STILL be refused — recording a disk cannot launder a secret'
    }

    # --- Path canonicalization / availability: a RECORDED data disk and the
    #     host-truth attached path that differ only by FORM (here a '..' round-trip:
    #     'C:\...\.\..\<dir>\out.vhdx' vs the attached 'C:\...\<dir>\out.vhdx') must be treated
    #     as the SAME disk and ACCEPTED. Before canonicalization the exact-string compare made
    #     them DIFFERENT and the gate wrongly threw "*unexpected*" (an availability bug — a
    #     legitimately-recorded disk refused, not a security hole). Canonicalizing both sides
    #     (GetFullPath + trailing-slash trim) makes the equivalent forms match.
    It 'ACCEPTS a recorded OUTPUT data disk whose recorded form is non-canonical (C:\..\..\out.vhdx) but resolves to the attached path' {
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 (non-canonical recorded path).'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST Tier-0 noncanonical fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-g4canon0' -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        # Attach the disk at its CANONICAL absolute path (host truth).
        $storageRoot = Get-SandboxStorageRoot -Name 'sbx-g4canon0'
        $outDisk     = Join-Path $storageRoot 'out.vhdx'
        & $b.NewOutputVhdx @{ Path = $outDisk; Label = 'OUTPUT'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4canon0'; Path = $outDisk }
        # RECORD it under a NON-CANONICAL but equivalent form: a '..' round-trip through the leaf
        # dir. '<root>\<leaf>\..\<leaf>\out.vhdx' resolves (via GetFullPath) back to '<root>\<leaf>\out.vhdx'.
        $leafDir         = Split-Path -Leaf $storageRoot
        $parentDir       = Split-Path -Parent $storageRoot
        $nonCanonical    = Join-Path (Join-Path (Join-Path (Join-Path $parentDir $leafDir) '..') $leafDir) 'out.vhdx'
        $d.OutputDiskPath = $nonCanonical
        # Sanity: the recorded form differs by exact string from the attached path, but canonicalizes
        # to it — so without canonicalization the gate would wrongly throw "*unexpected*".
        ($nonCanonical -ieq $outDisk) | Should -BeFalse -Because 'precondition: the recorded form is NOT exact-string-equal to the attached path (it differs by a .. round-trip)'
        ([System.IO.Path]::GetFullPath($nonCanonical).TrimEnd('\','/')) -ieq ([System.IO.Path]::GetFullPath($outDisk).TrimEnd('\','/')) |
            Should -BeTrue -Because 'precondition: the two forms canonicalize to the same path'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'a recorded data disk given in a non-canonical-but-equivalent form must be matched after canonicalization (availability: it is the SAME disk)'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    # --- RC6: the CIDATA seed DATA DISK is a recorded, expected disk that survives the seal ---
    #     The seal ejects DVDs, so the disk-mode cloud-init seed rides a recorded CIDATA data disk
    #     instead. Assert-Sealed must ACCEPT a disk recorded on SeedDiskPath exactly like INPUT/OUTPUT
    #     (at every tier, including the Tier>=2 structural rule), WITHOUT weakening the unrecorded-disk
    #     refusal or letting a secret-shaped seed path launder past the secret check.
    It 'ACCEPTS a recorded CIDATA SEED data disk attached to a Tier-0 sealed VM (RC6)' {
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 (recorded-seed-disk RC6).'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST Tier-0 seed-disk fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-g4seed0' -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        $seedDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4seed0') 'sbx-g4seed0-cidata.vhdx'
        & $b.NewOutputVhdx @{ Path = $seedDisk; Label = 'CIDATA'; FileSystem = 'FAT32'; SizeBytes = 64MB }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4seed0'; Path = $seedDisk }
        $d.SeedDiskPath = $seedDisk   # RECORDED -> expected, not residual
        (Test-IsSecretPath -Path $seedDisk) | Should -BeFalse -Because 'precondition: the CIDATA seed disk is not secret-shaped'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'a data disk recorded on the descriptor (SeedDiskPath) is an EXPECTED disk that survives the seal — the gate must certify'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'ACCEPTS a recorded CIDATA SEED data disk on a Tier-2 sealed VM (structural rule allows it too) (RC6)' {
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-g4seed2'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        $seedDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4seed2') 'sbx-g4seed2-cidata.vhdx'
        & $b.NewOutputVhdx @{ Path = $seedDisk; Label = 'CIDATA'; FileSystem = 'FAT32'; SizeBytes = 64MB }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4seed2'; Path = $seedDisk }
        $d.SeedDiskPath = $seedDisk
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'the recorded SeedDiskPath is an EXPECTED data disk at Tier-2 too — the structural rule must allow it'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'still REFUSES an UNRECORDED extra disk even alongside a recorded CIDATA seed disk (RC6 regression guard)' {
        # Recording the seed disk must NOT open the door to an arbitrary residual at any tier.
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 (seed-disk + unrecorded residual RC6).'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST Tier-0 seed+residual fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-g4seedrogue0' -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        $seedDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4seedrogue0') 'sbx-g4seedrogue0-cidata.vhdx'
        & $b.NewOutputVhdx @{ Path = $seedDisk; Label = 'CIDATA'; FileSystem = 'FAT32'; SizeBytes = 64MB }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4seedrogue0'; Path = $seedDisk }
        $d.SeedDiskPath = $seedDisk   # one recorded seed disk is fine...
        # ...but an UNRECORDED extra disk must still be refused.
        $rogue = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4seedrogue0') 'rogue.vhdx'
        & $b.NewVHD @{ Path = $rogue; SizeBytes = 64MB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4seedrogue0'; Path = $rogue }
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*unexpected*' -Because 'an UNRECORDED attached disk is still a residual — accepting the recorded seed disk must not weaken this'
    }

    It 'Assert-Sealed REFUSES a secret-shaped path recorded as SeedDiskPath (recording cannot launder a secret) (RC6)' {
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 (secret-laundering-via-SeedDiskPath RC6).'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST Tier-0 secret-seed fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-g4secseed0' -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        # A SECRET-SHAPED disk path (leaf '.env.vhdx' matches Test-IsSecretPath), attached AND recorded
        # as the descriptor's SeedDiskPath. The recording must NOT bypass the secret-shape check (b),
        # which runs BEFORE the recorded-disk allowance (c)/(d) in the same loop iteration.
        $secretSeed = Join-Path (Get-SandboxStorageRoot -Name 'sbx-g4secseed0') '.env.vhdx'
        & $b.NewVHD @{ Path = $secretSeed; SizeBytes = 64MB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-g4secseed0'; Path = $secretSeed }
        $d.SeedDiskPath = $secretSeed   # RECORDED — must still NOT bypass the secret check
        (Test-IsSecretPath -Path $secretSeed) | Should -BeTrue -Because 'precondition: the recorded SeedDiskPath is genuinely secret-shaped'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*secret*' -Because 'a secret-shaped path recorded as SeedDiskPath must STILL be refused — recording a disk cannot launder a secret'
    }
}

# ===========================================================================
#  Assert-Sealed — POSITIVE post-seal COM1-liveness assertion (the seal must
#  not sever the Runner's serial command channel)
# ===========================================================================
#  The seal closes host channels / removes NICs / ejects media. None of that may collaterally
#  sever COM1 — the ONLY no-NIC management path for a Linux guest (PowerShell Direct is Windows-
#  guest-only). A live run confirmed Disable-VMConsoleSupport does NOT break COM1, but inference
#  is not host truth: Assert-Sealed POSITIVELY host-verifies (via the backend's GetComPort) that
#  COM1 is still attached after sealing — for a serial-managed guest only. The Provisioner wires
#  COM1 for a Com1Serial profile and records ManagementChannel + ComPipePath on the descriptor.
Describe 'Assert-Sealed — POSITIVE COM1-liveness (the seal must not sever the Runner serial channel)' {

    It 'PASSES a properly-sealed Com1Serial VM with COM1 still attached (the happy path)' {
        # The Provisioner wired COM1 for this Com1Serial Tier-2 profile; the seal leaves it intact.
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-com1ok'
        $b = $sb.Backend; $d = $sb.Desc
        $d.ManagementChannel | Should -Be 'Com1Serial' -Because 'precondition: the fixture is a serial-managed guest'
        (& $b.GetComPort @{ VMName = 'sbx-com1ok'; Number = 1 }) | Should -Not -BeNullOrEmpty -Because 'precondition: COM1 is wired by the Provisioner'
        Lock-Sandbox -Descriptor $d -Backend $b
        # COM1 must SURVIVE the seal.
        (& $b.GetComPort @{ VMName = 'sbx-com1ok'; Number = 1 }) | Should -Not -BeNullOrEmpty -Because 'the seal must not sever COM1'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'a correctly-sealed serial-managed VM with COM1 intact must certify'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'FAILS CLOSED when COM1 was severed after the seal (the channel the seal must never cut)' {
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-com1cut'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        # Simulate the seal having severed COM1: clear the recorded COM port on the live fake VM
        # record (the fake's GetVM hands back the live hashtable). GetComPort then returns $null.
        (& $b.GetVM @{ Name = 'sbx-com1cut' }).ComPorts.Remove(1) | Out-Null
        (& $b.GetComPort @{ VMName = 'sbx-com1cut'; Number = 1 }) | Should -BeNullOrEmpty -Because 'precondition: COM1 is gone'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*COM1*' -Because 'a sealed serial-managed VM whose COM1 was severed must FAIL closed — the seal must never cut the Runner command channel'
    }

    It 'SKIPS the COM1 check for a NON-serial descriptor (no spurious failure on a tier with no COM1 channel)' {
        # A container-ish / non-serial tier has no Com1Serial management channel and no ComPipePath,
        # so it legitimately has no COM1. The check must be SKIPPED — not spuriously fail. Build a
        # sealed Tier-2 VM, then strip its serial-management markers AND its COM1 port so ONLY the
        # skip can make it pass (if the check ran, the missing COM1 would fail it).
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-noserial'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        # Remove the serial-management markers from the descriptor + the COM1 port from the VM.
        $d.ManagementChannel = $null
        $d.ComPipePath       = $null
        (& $b.GetVM @{ Name = 'sbx-noserial' }).ComPorts.Remove(1) | Out-Null
        (& $b.GetComPort @{ VMName = 'sbx-noserial'; Number = 1 }) | Should -BeNullOrEmpty -Because 'precondition: no COM1 on this non-serial tier'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'a non-serial descriptor (no Com1Serial / no ComPipePath) must SKIP the COM1-liveness check, not fail it'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'still triggers the check when ManagementChannel is absent but a ComPipePath is recorded' {
        # The trigger is Com1Serial OR a recorded ComPipePath — a descriptor that only carries the
        # pipe path (no explicit ManagementChannel) is still serial-managed and must be checked.
        $sb = & $script:NewTestSandbox -Profile $script:Tier2 -Name 'sbx-pipeonly'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        $d.ManagementChannel = $null                 # drop the explicit channel marker...
        $d.ComPipePath | Should -Not -BeNullOrEmpty   # ...but the ComPipePath remains (Provisioner-recorded)
        # Sever COM1: with ComPipePath still present the check must run and FAIL.
        (& $b.GetVM @{ Name = 'sbx-pipeonly' }).ComPorts.Remove(1) | Out-Null
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*COM1*' -Because 'a recorded ComPipePath alone marks a serial-managed guest; the COM1 check must run even without an explicit ManagementChannel'
    }
}

# ===========================================================================
#  Assert-Sealed — the LINUX-GUEST seal can finally CERTIFY
# ===========================================================================
#  THE END-TO-END REGRESSION for a real-backend bug found during live debugging. On a real Gen2 VM,
#  Disable-VMConsoleSupport does NOT flip Msvm_VirtualSystemSettingData.ConsoleMode (it stays 0),
#  so the old GetHostChannels read (`ConsoleMode -ne 3` => ESM ON) reported the three ESM facets
#  ON forever and Assert-Sealed could NEVER certify a correctly-sealed Linux VM — the seal refused
#  during live debugging with "host channel 'Clipboard' is still ON". The Linux-guest model makes
#  the ESM facets OFF BY CONSTRUCTION (Clipboard/Shares/EnhancedSession need a Windows-guest ESM
#  stack a stock Debian cloud image structurally lacks), keeping ONLY GuestServices as the real
#  fail-closed channel. These tests prove a correctly-sealed Linux-guest VM now PASSES the gate at
#  the no-net tiers AND at Tier-0/1, and that GuestServices remains the hard, host-verified channel.
Describe 'Assert-Sealed — a correctly-sealed Linux-guest VM can finally certify (end-to-end)' {

    It 'the Tier-1 descriptor carries a Linux GuestImage (precondition: the seal model is exercised for a Linux guest)' {
        # The shipped tier1 profile is a Debian 12 cloud image; the descriptor must carry that GuestImage
        # so the Linux-guest seal model is what these tests exercise (per ProfileLoader's LinuxImageRegex).
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-lxprecond'
        [string]$sb.Desc.GuestImage | Should -Match '(?i)(debian|ubuntu|alpine|fedora|remnux|linux)' -Because 'tier1 is a Debian cloud image — a Linux guest'
    }

    It 'PASSES a correctly-sealed Tier-0 Linux-guest VM (the seal can now certify — ESM facets are off by construction)' {
        # Tier 0 is the lowest tier; build it from the Tier-1 shape so we have a valid normalized profile
        # with a Linux GuestImage, then drop the tier to 0. Lock-Sandbox seals it; the gate must certify.
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 Linux guest.'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST Tier-0 Linux fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-lx0' -Backend $b
        Import-SandboxAsset -Descriptor $d -Source $script:IsoSrc -As Iso -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'a correctly-sealed Tier-0 Linux VM must certify — the ESM facets are off by construction, not stuck ON via a non-flipping ConsoleMode'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'PASSES a correctly-sealed Tier-1 Linux-guest VM (net-restricted, NIC kept, media + channels off)' {
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-lx1'
        $b = $sb.Backend; $d = $sb.Desc
        Import-SandboxAsset -Descriptor $d -Source $script:IsoSrc -As Iso -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'a correctly-sealed Tier-1 Linux VM must certify (the whole point of the Linux-guest seal fix)'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }

    It 'after Lock-Sandbox, the three ESM facets read OFF (the seal disabled them; the read reports them off)' {
        # Mirror of the new logical contract: SetHostChannel disabling the ESM facets -> GetHostChannels
        # reports them off. (On the real backend this is "off by construction"; on the fake it is recorded.)
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-lxch'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        $ch = & $b.GetHostChannels @{ VMName = 'sbx-lxch' }
        $ch.EnhancedSession | Should -BeFalse
        $ch.Clipboard       | Should -BeFalse
        $ch.Shares          | Should -BeFalse
    }

    It 'STILL fails closed if GuestServices is ON — the one REAL channel remains a hard, host-verified gate' {
        # The Linux-guest model must NOT weaken the GuestServices check: it is the real autonomous
        # host<->guest data channel (Copy-VMFile). A correctly-sealed Linux VM with GuestServices
        # re-enabled post-seal MUST still be refused, even though the ESM facets are off by construction.
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-lxgsi'
        $b = $sb.Backend; $d = $sb.Desc
        Lock-Sandbox -Descriptor $d -Backend $b
        & $b.SetHostChannel @{ VMName = 'sbx-lxgsi'; Channel = 'GuestServices'; Enabled = $true }
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*GuestServices*' -Because 'GuestServices is the real Copy-VMFile channel; the Linux-guest model keeps it a hard fail-closed gate'
    }
}

# ===========================================================================
#  Import-SandboxAsset — input validation
# ===========================================================================
Describe 'Import-SandboxAsset / Lock-Sandbox / Assert-Sealed — input validation' {

    It 'Import-SandboxAsset throws on a null descriptor' {
        $b = New-FakeHyperVBackend
        { Import-SandboxAsset -Descriptor $null -Source $script:IsoSrc -As Iso -Backend $b } |
            Should -Throw -ExpectedMessage '*Descriptor is null*'
    }

    It 'Lock-Sandbox throws on a null descriptor' {
        $b = New-FakeHyperVBackend
        { Lock-Sandbox -Descriptor $null -Backend $b } |
            Should -Throw -ExpectedMessage '*Descriptor is null*'
    }

    It 'Assert-Sealed throws on a null descriptor' {
        $b = New-FakeHyperVBackend
        # The security-critical gate must refuse a null descriptor for the RIGHT reason — pin the
        # message so a StrictMode/$null-member error elsewhere cannot pass this test green.
        { Assert-Sealed -Descriptor $null -Backend $b } |
            Should -Throw -ExpectedMessage '*Descriptor is null*'
    }
}

# ===========================================================================
#  Assert-Sealed — processor (Network=None) checks
#  Task 1.3: a Tier-0 processor profile (Network='None') is structurally no-NIC
#  like Tier>=2 — the seal gate MUST enforce NIC absence even though the tier
#  integer does not reach the Tier>=2 threshold. The recorded DepsDiskPath is an
#  expected disk (attached before seal, survives it), never a residual.
# ===========================================================================
Describe 'Assert-Sealed — processor (Network=None) checks' {

    BeforeAll {
        # Helper: build a sealed Tier-0 descriptor marked as a processor (Network='None'),
        # with the NIC removed and all channels off. Returns @{ Backend; Desc }.
        # The descriptor does NOT carry Network in the standard shape (New-SandboxDescriptor
        # omits it), so we add it via Set-DescriptorField after provisioning — exactly the
        # same pattern test fixtures use for SeedDiskPath / InputDiskPath / etc.
        $script:NewSealedProcessor = {
        param([string] $Name = 'sbx-proc')
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 processor (Network=None).'
        Assert-TierProfileValid -Profile $t0 -Context "TEST processor fixture '$Name'"
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name $Name -Backend $b
        # Mark the descriptor as a processor (no-NIC intent).
        Set-DescriptorField -Descriptor $d -Name 'Network' -Value 'None'
        # Remove the NIC the provisioner wired (processor VMs have no NIC by contract;
        # Lock-Sandbox does not strip the NIC for Tier<2, so we do it here in the fixture
        # to represent a correctly-configured processor VM before sealing).
        $null = & $b.RemoveNetworkAdapter @{ VMName = $Name }
        # Seal: eject media + turn off channels + mark State=Sealed (no NIC removal by
        # Lock-Sandbox for Tier-0, but the NIC was already removed above).
        Lock-Sandbox -Descriptor $d -Backend $b
        return @{ Backend = $b; Desc = $d }
        }
    }

    It 'processor with a NIC still attached FAILS the seal gate (0-NIC processor check)' {
        # A Tier-0 descriptor with Network='None' and a NIC still attached must be REFUSED —
        # the processor check must fire regardless of the tier integer (Tier<2 but Network='None').
        # Build the VM, mark it as a processor, and seal WITHOUT removing the NIC first.
        $t0 = $script:Tier1.Clone()
        $t0['Tier']        = 0
        $t0['Description'] = 'TEST FIXTURE — Tier 0 processor (NIC-still-attached).'
        Assert-TierProfileValid -Profile $t0 -Context 'TEST processor NIC fixture'
        $b = New-FakeHyperVBackend
        $d = New-SandboxVM -Profile $t0 -Name 'sbx-proc-nic' -Backend $b
        Set-DescriptorField -Descriptor $d -Name 'Network' -Value 'None'
        # Seal WITHOUT removing the NIC — this is the error condition.
        Lock-Sandbox -Descriptor $d -Backend $b
        # Precondition: the NIC is still present (Lock-Sandbox does not strip at Tier<2).
        (& $b.GetNetworkAdapter @{ VMName = 'sbx-proc-nic' }).Count |
            Should -Be 1 -Because 'precondition: the NIC was not removed (Tier<2 + Network=None misconfiguration)'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*network adapter*' -Because 'a processor (Network=None) with ANY NIC MUST fail the seal gate — it is structurally no-NIC like Tier>=2'
    }

    It 'processor with recorded DepsDiskPath PASSES; an unrecorded extra disk FAILS' {
        # Phase A — a correctly-sealed processor with a recorded DEPS disk PASSES.
        $r = & $script:NewSealedProcessor -Name 'sbx-proc-deps'
        $b = $r.Backend; $d = $r.Desc
        # Attach + record a DEPS disk (the expected, pre-provisioned dependency payload).
        $depsDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-proc-deps') 'sbx-proc-deps-deps.vhdx'
        & $b.NewOutputVhdx @{ Path = $depsDisk; Label = 'DEPS'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-proc-deps'; Path = $depsDisk }
        Set-DescriptorField -Descriptor $d -Name 'DepsDiskPath' -Value $depsDisk   # RECORDED -> expected
        (Test-IsSecretPath -Path $depsDisk) | Should -BeFalse -Because 'precondition: the DEPS disk is not secret-shaped'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'a recorded DepsDiskPath is an EXPECTED disk (not a residual); the gate must certify'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue

        # Phase B — an UNRECORDED extra disk alongside the recorded DEPS disk FAILS.
        $rogue = Join-Path (Get-SandboxStorageRoot -Name 'sbx-proc-deps') 'rogue.vhdx'
        & $b.NewVHD @{ Path = $rogue; SizeBytes = 64MB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-proc-deps'; Path = $rogue }
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*unexpected*' -Because 'an UNRECORDED extra disk must still be refused — accepting the recorded DEPS disk must not open the door to residual volumes'
    }

    It 'a secret-shaped DepsDiskPath is still REFUSED (recording cannot launder a secret)' {
        # Even a disk recorded as DepsDiskPath must be refused if it is secret-shaped — the
        # secret check (branch b) runs BEFORE the recorded-disk allowance (branches c/d) in
        # the same attached-disk loop iteration. This locks the ordering against refactors.
        $r = & $script:NewSealedProcessor -Name 'sbx-proc-sec'
        $b = $r.Backend; $d = $r.Desc
        # A secret-shaped path (leaf 'id_rsa' matches Test-IsSecretPath), attached AND recorded.
        $secretDeps = Join-Path (Get-SandboxStorageRoot -Name 'sbx-proc-sec') 'id_rsa.vhdx'
        & $b.NewVHD @{ Path = $secretDeps; SizeBytes = 64MB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'sbx-proc-sec'; Path = $secretDeps }
        Set-DescriptorField -Descriptor $d -Name 'DepsDiskPath' -Value $secretDeps   # RECORDED — must still be refused
        (Test-IsSecretPath -Path $secretDeps) | Should -BeTrue -Because 'precondition: the recorded DepsDiskPath is genuinely secret-shaped'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Throw -ExpectedMessage '*secret*' -Because 'a secret-shaped path recorded as DepsDiskPath must STILL be refused — recording a disk cannot launder a secret (the secret check runs before the recorded-disk allowance)'
    }

    It 'a non-processor Tier-0 VM with a NIC is NOT failed by the processor check (regression guard)' {
        # The processor check fires ONLY when Network='None' is on the descriptor. A normal
        # Tier-0/1 descriptor (no Network field, or Network != 'None') with a NIC must certify
        # exactly as before — the new guard must NOT add behavior for any other descriptor.
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-nonproc'
        $b = $sb.Backend; $d = $sb.Desc
        Import-SandboxAsset -Descriptor $d -Source $script:IsoSrc -As Iso -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        # Precondition: the descriptor carries NO Network='None' marker — it is a normal Tier-1 VM.
        [string](Get-DescriptorField -Descriptor $d -Name 'Network') |
            Should -BeNullOrEmpty -Because 'precondition: a standard Tier-1 descriptor has no Network=None marker'
        # Precondition: the NIC is still present (Tier-1 keeps it).
        (& $b.GetNetworkAdapter @{ VMName = 'sbx-nonproc' }).Count |
            Should -Be 1 -Because 'precondition: Tier-1 keeps its NIC'
        { Assert-Sealed -Descriptor $d -Backend $b } |
            Should -Not -Throw -Because 'a standard Tier-1 VM with a NIC and no Network=None marker must NOT be failed by the processor check'
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
    }
}
