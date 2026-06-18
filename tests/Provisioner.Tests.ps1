#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for scripts/lib/Provisioner.ps1 (the Provisioner + Reaper).

.DESCRIPTION
    Contract under test: the Provisioner + Reaper — create a sandbox VM from a
    normalized tier/workload profile (Import-TierProfile's output), and tear it
    down. EVERYTHING goes through the backend abstraction (HyperVBackend.ps1);
    no raw Hyper-V cmdlet is ever called. Tests inject the FAKE backend
    (New-FakeHyperVBackend) and assert against its in-memory state.

    Functions:
        New-SandboxVM       -Profile <hashtable> -Name <vmname> [-Backend]
        Checkpoint-Sandbox  -Name <vmname> -SnapshotName <name> [-Backend]
        Restore-Sandbox     -Name <vmname> -SnapshotName <name> [-Backend]
        Remove-Sandbox      -Name <vmname> [-DeleteDisks] [-Backend]

    Calling convention reminder: every backend method takes a SINGLE
    hashtable of named args, invoked as `& $backend.X @{ key = val }`. Collection-
    returning methods (GetNetworkAdapter / GetCheckpoint) already preserve array
    semantics — read `.Count` directly, never re-wrap in @().

    TDD: written FIRST; drives the Provisioner.ps1 implementation.
#>

BeforeAll {
    # Resolve the skill root from this test file's location: <root>/tests/ -> <root>
    $script:SkillRoot   = Split-Path -Parent $PSScriptRoot
    $script:LibPath     = Join-Path $script:SkillRoot 'scripts/lib/Provisioner.ps1'
    $script:BackendPath = Join-Path $script:SkillRoot 'scripts/lib/HyperVBackend.ps1'
    $script:LoaderPath  = Join-Path $script:SkillRoot 'scripts/lib/ProfileLoader.ps1'
    $script:TierDir     = Join-Path $script:SkillRoot 'tier-profiles'

    Test-Path $script:LibPath     | Should -BeTrue -Because 'the Provisioner script must exist to be tested'
    Test-Path $script:BackendPath | Should -BeTrue -Because 'the backend must exist'
    Test-Path $script:LoaderPath  | Should -BeTrue -Because 'the profile loader must exist'

    . $script:BackendPath
    . $script:LoaderPath
    . $script:LibPath

    # The real Tier-1 profile, loaded the same way production loads it. This is the
    # canonical "VM tier" input the Provisioner consumes (Gen2, SecureBoot, COM1, etc.).
    $script:Tier1 = Import-TierProfile -Path (Join-Path $script:TierDir 'tier1.psd1')
}

# ===========================================================================
#  New-SandboxVM — Tier-1 provisioning from the real tier1.psd1
# ===========================================================================
Describe 'New-SandboxVM — provisions a Tier-1 VM from tier1.psd1 (via the fake backend)' {

    BeforeEach {
        $script:B    = New-FakeHyperVBackend
        $script:Desc = New-SandboxVM -Profile $script:Tier1 -Name 'sbx-t1' -Backend $script:B
    }

    It 'creates a VM recorded in the backend' {
        $vm = & $script:B.GetVM @{ Name = 'sbx-t1' }
        $vm | Should -Not -BeNullOrEmpty -Because 'the provisioner must have created the VM'
        $vm.Name | Should -Be 'sbx-t1'
    }

    It 'creates a Generation 2 VM' {
        (& $script:B.GetVM @{ Name = 'sbx-t1' }).Generation | Should -Be 2 -Because 'all sandbox VMs are Gen2 (UEFI SecureBoot)'
    }

    It 'sets memory from the profile (4GB)' {
        (& $script:B.GetVM @{ Name = 'sbx-t1' }).MemoryStartupBytes | Should -Be 4GB -Because "tier1.psd1 declares Memory='4GB'"
    }

    It 'sets the processor count from the profile (4)' {
        (& $script:B.GetVM @{ Name = 'sbx-t1' }).ProcessorCount | Should -Be 4 -Because 'tier1.psd1 declares Cpu=4'
    }

    It 'sets the SecureBoot template (MicrosoftUEFICertificateAuthority for Debian)' {
        $vm = & $script:B.GetVM @{ Name = 'sbx-t1' }
        $vm.SecureBootEnabled  | Should -BeTrue
        $vm.SecureBootTemplate | Should -Be 'MicrosoftUEFICertificateAuthority' -Because 'tier1.psd1 SecureBootTemplate is the Debian Gen2 CA'
    }

    It 'sets COM1 to a named pipe (the Linux management channel)' {
        $vm = & $script:B.GetVM @{ Name = 'sbx-t1' }
        $vm.ComPorts.ContainsKey(1) | Should -BeTrue -Because 'ManagementChannel=Com1Serial means COM1 must be wired'
        [string]$vm.ComPorts[1] | Should -Match '(?i)pipe' -Because 'the Linux mgmt channel is a host named pipe on COM1'
    }

    It 'creates an Internal vSwitch and connects a NIC to it' {
        # Tier 1 Network is Internal+Allowlist -> Internal switch + connected NIC.
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'sbx-t1' }
        $nics.Count | Should -Be 1 -Because 'Tier 1 attaches exactly one NIC on an Internal switch'

        $swName = $nics[0].SwitchName
        $swName | Should -Not -BeNullOrEmpty
        $sw = & $script:B.GetSwitch @{ Name = $swName }
        $sw | Should -Not -BeNullOrEmpty -Because 'the NIC must be bound to a switch that was actually created'
        $sw.SwitchType | Should -Be 'Internal' -Because 'Tier 1 uses an Internal vSwitch (no external connectivity)'
    }

    It 'creates a VHD for the VM' {
        # The descriptor reports the created disk(s); each must be a real VHD record.
        $script:Desc.CreatedDisks.Count | Should -BeGreaterThan 0 -Because 'the provisioner creates at least the system disk'
        foreach ($d in $script:Desc.CreatedDisks) {
            (& $script:B.GetVHDInfo @{ Path = $d }) | Should -Not -BeNullOrEmpty -Because "the provisioner must have created VHD '$d'"
        }
    }

    It 'attaches the created system disk to the VM' {
        $vm = & $script:B.GetVM @{ Name = 'sbx-t1' }
        @($vm.HardDrives).Count | Should -BeGreaterThan 0 -Because 'the system disk must be attached'
        @($vm.HardDrives) | Should -Contain $script:Desc.DiskPath
    }

    It 'does NOT set ExposeVirtualizationExtensions when NestedVirt is $false (tier1 default)' {
        (& $script:B.GetVM @{ Name = 'sbx-t1' }).ExposeVirtualizationExtensions |
            Should -BeFalse -Because 'tier1.psd1 declares NestedVirt=$false'
    }
}

# ===========================================================================
#  New-SandboxVM — the returned sandbox descriptor (consumed by the Sealer/Runner/Reaper)
# ===========================================================================
Describe 'New-SandboxVM — returns a sandbox descriptor the Sealer/Runner/Reaper consume' {

    BeforeEach {
        $script:B    = New-FakeHyperVBackend
        $script:Desc = New-SandboxVM -Profile $script:Tier1 -Name 'sbx-desc' -Backend $script:B
    }

    It 'returns a single descriptor object (hashtable / PSCustomObject)' {
        $script:Desc | Should -Not -BeNullOrEmpty
        @($script:Desc).Count | Should -Be 1 -Because 'New-SandboxVM must emit exactly one descriptor, not a stream of backend return values'
    }

    It 'descriptor carries the identity + tier fields the later components need' {
        $script:Desc.Name | Should -Be 'sbx-desc'
        $script:Desc.Tier | Should -Be 1
        $script:Desc.Generation | Should -Be 2
        $script:Desc.GuestImage | Should -Be $script:Tier1.GuestImage
    }

    It 'descriptor carries the disk path(s)' {
        $script:Desc.DiskPath | Should -Not -BeNullOrEmpty -Because 'the Reaper + Runner need the system disk path'
        @($script:Desc.DiskPaths).Count | Should -BeGreaterThan 0
        @($script:Desc.DiskPaths) | Should -Contain $script:Desc.DiskPath
    }

    It 'descriptor carries the switch name (for Sealer / teardown)' {
        $script:Desc.SwitchName | Should -Not -BeNullOrEmpty -Because 'the Sealer reconfigures/strips this switch'
    }

    It 'descriptor carries the management channel + COM pipe path (the Runner drives this)' {
        $script:Desc.ManagementChannel | Should -Be 'Com1Serial'
        $script:Desc.ComPipePath | Should -Not -BeNullOrEmpty -Because 'the Runner connects to COM1 via this host pipe'
    }

    It 'descriptor reports the VM state (Off after provisioning — never auto-started)' {
        $script:Desc.State | Should -Be 'Off' -Because 'provisioning must not power the VM on; the Sealer runs before first boot'
    }

    It 'descriptor lists the disks it created (so Remove-Sandbox -DeleteDisks knows what to delete)' {
        @($script:Desc.CreatedDisks).Count | Should -BeGreaterThan 0
    }
}

# ===========================================================================
#  New-SandboxDescriptor — InputDiskPath / OutputDiskPath fields (disk-passing model)
# ===========================================================================
Describe 'New-SandboxDescriptor — InputDiskPath / OutputDiskPath fields' {

    It 'New-SandboxDescriptor carries InputDiskPath and OutputDiskPath (default $null)' {
        $d = New-SandboxDescriptor -Name 'x' -Tier 0
        $d.PSObject.Properties.Name | Should -Contain 'InputDiskPath'
        $d.PSObject.Properties.Name | Should -Contain 'OutputDiskPath'
        $d.InputDiskPath  | Should -BeNullOrEmpty
        $d.OutputDiskPath | Should -BeNullOrEmpty
    }

    It 'New-SandboxDescriptor accepts and stores InputDiskPath/OutputDiskPath when given' {
        $d = New-SandboxDescriptor -Name 'x' -Tier 0 -InputDiskPath 'C:\s\in.vhdx' -OutputDiskPath 'C:\s\out.vhdx'
        $d.InputDiskPath  | Should -Be 'C:\s\in.vhdx'
        $d.OutputDiskPath | Should -Be 'C:\s\out.vhdx'
    }
}

# ===========================================================================
#  New-SandboxVM — nested virtualization toggle
# ===========================================================================
Describe 'New-SandboxVM — NestedVirt controls ExposeVirtualizationExtensions' {

    It 'NestedVirt=$true -> ExposeVirtualizationExtensions is set on the VM' {
        $b = New-FakeHyperVBackend
        $p = $script:Tier1.Clone()
        $p['NestedVirt'] = $true
        New-SandboxVM -Profile $p -Name 'sbx-nv' -Backend $b | Out-Null
        (& $b.GetVM @{ Name = 'sbx-nv' }).ExposeVirtualizationExtensions |
            Should -BeTrue -Because 'NestedVirt=$true must expose virtualization extensions'
    }

    It 'NestedVirt=$false -> ExposeVirtualizationExtensions stays off' {
        $b = New-FakeHyperVBackend
        $p = $script:Tier1.Clone()
        $p['NestedVirt'] = $false
        New-SandboxVM -Profile $p -Name 'sbx-nonv' -Backend $b | Out-Null
        (& $b.GetVM @{ Name = 'sbx-nonv' }).ExposeVirtualizationExtensions |
            Should -BeFalse -Because 'NestedVirt=$false must NOT expose virtualization extensions'
    }

    It 'a profile with no NestedVirt key -> ExposeVirtualizationExtensions stays off (safe default)' {
        $b = New-FakeHyperVBackend
        $p = $script:Tier1.Clone()
        $p.Remove('NestedVirt')
        New-SandboxVM -Profile $p -Name 'sbx-defnv' -Backend $b | Out-Null
        (& $b.GetVM @{ Name = 'sbx-defnv' }).ExposeVirtualizationExtensions |
            Should -BeFalse -Because 'absent NestedVirt must default to NOT nested (least privilege)'
    }
}

# ===========================================================================
#  New-SandboxVM — preflight fail-closed (Hyper-V unavailable / not elevated)
# ===========================================================================
Describe 'New-SandboxVM — preflight fails closed when Hyper-V is unavailable' {

    It 'throws a clear fail-closed message when the backend reports unavailable' {
        $b = New-FakeHyperVBackend -SimulateUnavailable
        { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-unavail' -Backend $b } |
            Should -Throw -Because 'preflight TestAvailable=$false must abort before any half-create'
    }

    It 'the fail-closed message is actionable (mentions Hyper-V / privilege / elevation / availability)' {
        $b = New-FakeHyperVBackend -SimulateUnavailable
        $msg = $null
        try { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-unavail2' -Backend $b } catch { $msg = $_.Exception.Message }
        $msg | Should -Not -BeNullOrEmpty
        $msg | Should -Match '(?i)(Hyper-V|privilege|elevat|administrator|unavailable)'
    }

    It 'does NOT half-create a VM when preflight fails' {
        $b = New-FakeHyperVBackend -SimulateUnavailable
        try { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-nohalf' -Backend $b } catch { }
        # The fake's TestAvailable reports unavailable, but its mutators still work; the
        # provisioner MUST bail at preflight, so nothing should have been created.
        (& $b.GetVM @{ Name = 'sbx-nohalf' }) | Should -BeNullOrEmpty -Because 'a failed preflight must leave no partial VM'
    }

    It 'creates NOTHING (no VM, no system VHD, no switch) when preflight fails' {
        # Prove "nothing created" — a fail-closed preflight must not have reached
        # ANY backend mutator (NewVHD / NewVM / NewSwitch all come AFTER the preflight gate).
        $b = New-FakeHyperVBackend -SimulateUnavailable
        try { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-nada' -Backend $b } catch { }

        (& $b.GetVM @{ Name = 'sbx-nada' }) | Should -BeNullOrEmpty -Because 'preflight failure: no VM'

        # The system VHD path the provisioner would have created (mirrors Get-SandboxStorageRoot).
        $sysDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-nada') 'sbx-nada-system.vhdx'
        (& $b.GetVHDInfo @{ Path = $sysDisk }) | Should -BeNullOrEmpty -Because 'preflight failure: no system VHD'

        # The Internal vSwitch the provisioner would have created for a HyperV-Gen2 tier.
        (& $b.GetSwitch @{ Name = 'sbx-nada-int' }) | Should -BeNullOrEmpty -Because 'preflight failure: no switch'
    }
}

# ===========================================================================
#  New-SandboxVM — idempotency (a name that already exists)
# ===========================================================================
Describe 'New-SandboxVM — idempotency on an existing VM name' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        New-SandboxVM -Profile $script:Tier1 -Name 'sbx-dup' -Backend $script:B | Out-Null
    }

    It 'provisioning the same name again throws a clear "already exists" error (does not duplicate / corrupt)' {
        # Design choice: error clearly rather than silently no-op, so an accidental re-provision
        # is surfaced. The backend itself would also reject a duplicate NewVM; the provisioner
        # detects it up front via GetVM and throws BEFORE touching anything.
        { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-dup' -Backend $script:B } |
            Should -Throw -ExpectedMessage '*already exists*' -Because 'a duplicate provision must fail clearly, not silently clobber'
    }

    It 'the original VM is untouched after a rejected re-provision' {
        try { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-dup' -Backend $script:B } catch { }
        $vm = & $script:B.GetVM @{ Name = 'sbx-dup' }
        $vm | Should -Not -BeNullOrEmpty
        $vm.Generation | Should -Be 2
    }
}

# ===========================================================================
#  New-SandboxVM — mid-provision failure rolls back (no orphans, retry works)
# ===========================================================================
Describe 'New-SandboxVM — a mid-provision failure tears down what it created (no retry-wedge)' {

    It 'a throw at SetFirmware (step 5/8) leaves NO VM and NO system VHD, and rethrows' {
        # Inject a failure mid-provision by monkeypatching ONE backend method (SetFirmware,
        # step 5 of 8) to throw AFTER NewVHD (step 1) + NewVM (step 2) have already created
        # artifacts. Without rollback those are orphaned and the idempotency guard wedges a retry.
        $b = New-FakeHyperVBackend
        $b.SetFirmware = { param($P) throw 'INJECTED: SetFirmware blew up mid-provision' }.GetNewClosure()

        { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-fail' -Backend $b } |
            Should -Throw -ExpectedMessage '*INJECTED*' -Because 'the ORIGINAL error must propagate (rethrown after best-effort cleanup)'

        # The VM created at step 2 must have been torn back down.
        (& $b.GetVM @{ Name = 'sbx-fail' }) | Should -BeNullOrEmpty -Because 'a failed provision must leave no orphaned VM'

        # The system VHD created at step 1 must have been deleted.
        $sysDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-fail') 'sbx-fail-system.vhdx'
        (& $b.GetVHDInfo @{ Path = $sysDisk }) | Should -BeNullOrEmpty -Because 'a failed provision must delete the system VHD it created'
    }

    It 're-provisioning the SAME name after a mid-provision failure SUCCEEDS (no idempotency wedge)' {
        $b = New-FakeHyperVBackend

        # Wrap SetFirmware so it throws ONCE (the transient fault on the first provision) then
        # delegates to the REAL fake method on every later call. Delegating to the ORIGINAL
        # closure (not a foreign fake's) keeps the SAME in-memory $state, so the retry's
        # SetFirmware operates on the actual VM. Use a script-scoped flag (a child scope can't
        # mutate a parent local), and capture the original method by value into the closure.
        $script:firmwareFailedOnce = $false
        $origSetFirmware = $b.SetFirmware
        $b.SetFirmware = {
            param($P)
            if (-not $script:firmwareFailedOnce) {
                $script:firmwareFailedOnce = $true
                throw 'INJECTED: first attempt fails at firmware (transient)'
            }
            & $origSetFirmware $P
        }.GetNewClosure()

        # First attempt: fails mid-provision -> rollback removes the orphan.
        try { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-retry' -Backend $b } catch { }
        (& $b.GetVM @{ Name = 'sbx-retry' }) | Should -BeNullOrEmpty -Because 'the failed first attempt must have rolled back its orphan'

        # Second attempt of the SAME name now succeeds (the "already exists" guard is not wedged).
        { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-retry' -Backend $b } |
            Should -Not -Throw -Because 'the orphan cleanup means the "already exists" guard does not block the retry'

        (& $b.GetVM @{ Name = 'sbx-retry' }) | Should -Not -BeNullOrEmpty -Because 'the retry must actually create the VM'
        (& $b.GetVM @{ Name = 'sbx-retry' }).Generation | Should -Be 2
    }

    It 'a throw at AddHardDiskDrive (step 8/8) also cleans up the VM, disk AND switch' {
        # A LATER-stage failure proves switch cleanup too: by AddHardDiskDrive the VM, the
        # system VHD, and the Internal vSwitch all exist; rollback must remove every one.
        $b = New-FakeHyperVBackend
        $b.AddHardDiskDrive = { param($P) throw 'INJECTED: AddHardDiskDrive blew up at the last step' }.GetNewClosure()

        { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-late' -Backend $b } |
            Should -Throw -ExpectedMessage '*INJECTED*'

        (& $b.GetVM @{ Name = 'sbx-late' }) | Should -BeNullOrEmpty -Because 'rollback removes the VM'
        $sysDisk = Join-Path (Get-SandboxStorageRoot -Name 'sbx-late') 'sbx-late-system.vhdx'
        (& $b.GetVHDInfo @{ Path = $sysDisk }) | Should -BeNullOrEmpty -Because 'rollback deletes the system VHD'
        (& $b.GetSwitch @{ Name = 'sbx-late-int' }) | Should -BeNullOrEmpty -Because 'rollback removes the switch the provision created'
    }
}

# ===========================================================================
#  New-SandboxVM / Remove-Sandbox — differencing-disk PARENT survival
# ===========================================================================
Describe 'New-SandboxVM differencing + Remove-Sandbox -DeleteDisks never deletes the golden PARENT' {

    It 'provisions a differencing child off a parent and -DeleteDisks deletes ONLY the child (parent survives)' {
        # SAFETY-CRITICAL: -DeleteDisks must never destroy a shared golden base image. A
        # differencing child's PARENT is never in CreatedDisks, so it must survive teardown.
        $b = New-FakeHyperVBackend

        # Pre-create a golden PARENT vhd (as a base-image library would have on disk). It must be a
        # REAL on-disk file: New-SandboxVM's sparse-parent preflight (pure host-FS) requires the
        # supplied parent to EXIST. Create it under $TestDrive and record it in the fake too.
        $parent = Join-Path $TestDrive 'debian-12-golden.vhdx'
        Set-Content -LiteralPath $parent -Value 'golden-parent-payload' -NoNewline -Encoding ascii
        & $b.NewVHD @{ Path = $parent; SizeBytes = 40GB; Dynamic = $true }
        (& $b.GetVHDInfo @{ Path = $parent }) | Should -Not -BeNullOrEmpty -Because 'precondition: the golden parent exists'

        # Provision a VM whose system disk is a DIFFERENCING child off that parent.
        $desc = New-SandboxVM -Profile $script:Tier1 -Name 'sbx-diff' -ParentDiskPath $parent -Backend $b

        $child = $desc.DiskPath
        (& $b.GetVHDInfo @{ Path = $child })  | Should -Not -BeNullOrEmpty -Because 'the differencing child system disk was created'
        $childInfo = & $b.GetVHDInfo @{ Path = $child }
        $childInfo.Differencing | Should -BeTrue -Because 'with -ParentDiskPath the system disk must be a differencing disk'
        $childInfo.ParentPath   | Should -Be $parent -Because 'the child must point at the golden parent'

        # The parent must NOT be in the created-disks list (the thing -DeleteDisks targets).
        @($desc.CreatedDisks) | Should -Not -Contain $parent -Because 'the provision did not create the parent; it must never be a deletion target'

        # Tear down WITH -DeleteDisks.
        Remove-Sandbox -Name 'sbx-diff' -DeleteDisks -Descriptor $desc -Backend $b

        (& $b.GetVM @{ Name = 'sbx-diff' }) | Should -BeNullOrEmpty -Because 'the VM is removed'
        (& $b.GetVHDInfo @{ Path = $child })  | Should -BeNullOrEmpty -Because '-DeleteDisks deletes the differencing child'
        (& $b.GetVHDInfo @{ Path = $parent }) | Should -Not -BeNullOrEmpty -Because 'the golden PARENT must SURVIVE -DeleteDisks (it is not a created disk)'
    }
}

# ===========================================================================
#  New-SandboxVM — sparse-parent preflight guard (the live-run 0xC03A001A bug)
# ===========================================================================
#  A qemu-img-converted golden disk is commonly SPARSE, and Hyper-V refuses a differencing child off
#  a sparse parent with an opaque raw `0xC03A001A: ... must not be sparse` error (this bit a live
#  run). New-SandboxVM preflights the parent's NTFS sparse attribute (pure host-FS, no Hyper-V) and
#  fails closed with an actionable message naming the path + the `fsutil sparse setflag <path> 0` fix
#  BEFORE any artifact is created. The sparse-detection is split into the mockable Test-IsSparseFile.
Describe 'New-SandboxVM — sparse-parent preflight (fail closed before any creation)' {

    It 'Test-IsSparseFile returns $false for a normal (non-sparse) file' {
        $f = Join-Path $TestDrive 'plain.vhdx'
        Set-Content -LiteralPath $f -Value 'not-sparse' -NoNewline -Encoding ascii
        Test-IsSparseFile -Path $f | Should -BeFalse -Because 'a freshly-written normal file carries no SPARSE attribute'
    }

    It 'THROWS naming the path + the fsutil fix when the parent is SPARSE (mocked sparse-check — always runs)' {
        # Mock Test-IsSparseFile so the guard branch is exercised regardless of whether the host/CI
        # can fabricate a real sparse file. The parent must still EXIST (the guard checks existence
        # first), so create a real placeholder file and force the sparse verdict to $true.
        $parent = Join-Path $TestDrive 'sparse-golden.vhdx'
        Set-Content -LiteralPath $parent -Value 'payload' -NoNewline -Encoding ascii
        Mock Test-IsSparseFile { return $true } -ParameterFilter { $Path -eq $parent }

        $b = New-FakeHyperVBackend
        $msg = $null
        try { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-sparse' -ParentDiskPath $parent -Backend $b }
        catch { $msg = $_.Exception.Message }
        $msg | Should -Not -BeNullOrEmpty -Because 'a sparse parent must fail closed'
        $msg | Should -Match '(?i)sparse'                   -Because 'the message must say the parent is sparse'
        $msg | Should -Match ([regex]::Escape($parent))      -Because 'the message must name the offending parent path'
        $msg | Should -Match '(?i)fsutil sparse setflag'     -Because 'the message must name the actionable fix'
        # Fail-closed BEFORE any creation: no VM, no system disk left behind.
        (& $b.GetVM @{ Name = 'sbx-sparse' }) | Should -BeNullOrEmpty -Because 'the guard runs before any artifact is created'
    }

    It 'a NON-sparse parent passes the sparse check and provisions a differencing child' {
        # The happy path: a real, non-sparse parent is accepted; the system disk becomes a
        # differencing child. (Test-IsSparseFile genuinely returns $false here — no mock.)
        $parent = Join-Path $TestDrive 'good-golden.vhdx'
        Set-Content -LiteralPath $parent -Value 'good-payload' -NoNewline -Encoding ascii
        Test-IsSparseFile -Path $parent | Should -BeFalse -Because 'precondition: the parent is not sparse'
        $b = New-FakeHyperVBackend
        & $b.NewVHD @{ Path = $parent; SizeBytes = 40GB; Dynamic = $true }   # also record in the fake
        # Assign OUTSIDE a Should -Not -Throw block — that block runs in a child scope, so an
        # assignment inside it would not reach the test scope. A throw here fails the test directly,
        # which IS the no-throw assertion.
        $desc = New-SandboxVM -Profile $script:Tier1 -Name 'sbx-nonsparse' -ParentDiskPath $parent -Backend $b
        (& $b.GetVHDInfo @{ Path = $desc.DiskPath }).Differencing | Should -BeTrue -Because 'the system disk is a differencing child off the non-sparse parent'
    }

    It 'THROWS its own clear message when the parent does not exist (a missing parent is fail-closed too)' {
        $missing = Join-Path $TestDrive 'no-such-golden.vhdx'
        $b = New-FakeHyperVBackend
        $msg = $null
        try { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-noparent' -ParentDiskPath $missing -Backend $b }
        catch { $msg = $_.Exception.Message }
        $msg | Should -Not -BeNullOrEmpty
        $msg | Should -Match '(?i)does not exist' -Because 'a missing parent must fail closed with its own clear message'
        $msg | Should -Match ([regex]::Escape($missing)) -Because 'the message must name the missing parent path'
    }

    It 'a REAL fsutil-marked sparse file is rejected (end-to-end; skipped if fsutil cannot set sparse here)' {
        # The real-attribute path: mark a real file SPARSE via fsutil and prove the UNMOCKED preflight
        # rejects it. Skipped (not failed) on a host/CI where fsutil can't set the flag (e.g. non-NTFS
        # TestDrive) — the mocked test above covers the guard branch unconditionally.
        $parent = Join-Path $TestDrive 'real-sparse-golden.vhdx'
        Set-Content -LiteralPath $parent -Value 'payload' -NoNewline -Encoding ascii
        $fsutil = Get-Command fsutil.exe -ErrorAction SilentlyContinue
        if (-not $fsutil) { Set-ItResult -Skipped -Because 'fsutil is not available on this host'; return }
        & fsutil.exe sparse setflag "$parent" 1 2>&1 | Out-Null
        if (-not (Test-IsSparseFile -Path $parent)) {
            Set-ItResult -Skipped -Because 'fsutil could not set the SPARSE attribute here (likely a non-NTFS TestDrive)'; return
        }
        $b = New-FakeHyperVBackend
        { New-SandboxVM -Profile $script:Tier1 -Name 'sbx-realsparse' -ParentDiskPath $parent -Backend $b } |
            Should -Throw -ExpectedMessage '*sparse*' -Because 'the unmocked preflight must reject a genuinely-sparse parent'
    }
}

# ===========================================================================
#  Reaper — Checkpoint-Sandbox / Restore-Sandbox roundtrip
# ===========================================================================
Describe 'Reaper — Checkpoint-Sandbox / Restore-Sandbox roundtrip' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        New-SandboxVM -Profile $script:Tier1 -Name 'sbx-cp' -Backend $script:B | Out-Null
    }

    It 'Checkpoint-Sandbox records a named snapshot' {
        Checkpoint-Sandbox -Name 'sbx-cp' -SnapshotName 'golden' -Backend $script:B
        $cps = & $script:B.GetCheckpoint @{ VMName = 'sbx-cp' }
        $cps.Name | Should -Contain 'golden'
    }

    It 'Restore-Sandbox rolls the VM back to the checkpointed state' {
        Checkpoint-Sandbox -Name 'sbx-cp' -SnapshotName 'golden' -Backend $script:B
        & $script:B.StartVM @{ Name = 'sbx-cp' }
        (& $script:B.GetVM @{ Name = 'sbx-cp' }).State | Should -Be 'Running'

        Restore-Sandbox -Name 'sbx-cp' -SnapshotName 'golden' -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-cp' }).State | Should -Be 'Off' -Because 'restore returns the VM to the checkpointed (Off) state'
    }

    It 'Checkpoint-Sandbox on a missing VM fails clearly' {
        { Checkpoint-Sandbox -Name 'ghost-vm' -SnapshotName 'x' -Backend $script:B } |
            Should -Throw -ExpectedMessage '*ghost-vm*'
    }
}

# ===========================================================================
#  Reaper — Remove-Sandbox (stop, unregister, optional disk delete; idempotent)
# ===========================================================================
Describe 'Reaper — Remove-Sandbox' {

    BeforeEach {
        $script:B    = New-FakeHyperVBackend
        $script:Desc = New-SandboxVM -Profile $script:Tier1 -Name 'sbx-rm' -Backend $script:B
    }

    It 'removes the VM (GetVM returns nothing afterward)' {
        Remove-Sandbox -Name 'sbx-rm' -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-rm' }) | Should -BeNullOrEmpty
    }

    It 'stops a RUNNING VM before removing it (no "cannot remove running VM" surprise)' {
        & $script:B.StartVM @{ Name = 'sbx-rm' }
        (& $script:B.GetVM @{ Name = 'sbx-rm' }).State | Should -Be 'Running'
        { Remove-Sandbox -Name 'sbx-rm' -Backend $script:B } | Should -Not -Throw
        (& $script:B.GetVM @{ Name = 'sbx-rm' }) | Should -BeNullOrEmpty
    }

    It 'WITHOUT -DeleteDisks, the created VHDX record SURVIVES (Remove-VM leaves disks)' {
        $disk = $script:Desc.DiskPath
        (& $script:B.GetVHDInfo @{ Path = $disk }) | Should -Not -BeNullOrEmpty -Because 'precondition: the disk exists'
        Remove-Sandbox -Name 'sbx-rm' -Backend $script:B
        (& $script:B.GetVHDInfo @{ Path = $disk }) |
            Should -Not -BeNullOrEmpty -Because 'Remove-Sandbox without -DeleteDisks must NOT delete the VHDX'
    }

    It 'WITH -DeleteDisks, the created VHDX record is removed' {
        $disk = $script:Desc.DiskPath
        (& $script:B.GetVHDInfo @{ Path = $disk }) | Should -Not -BeNullOrEmpty -Because 'precondition: the disk exists'
        Remove-Sandbox -Name 'sbx-rm' -DeleteDisks -Backend $script:B
        (& $script:B.GetVHDInfo @{ Path = $disk }) |
            Should -BeNullOrEmpty -Because 'Remove-Sandbox -DeleteDisks must explicitly delete the VHDs it created'
    }

    It 'WITH -DeleteDisks, deletes EVERY disk the descriptor created' {
        foreach ($d in $script:Desc.CreatedDisks) {
            (& $script:B.GetVHDInfo @{ Path = $d }) | Should -Not -BeNullOrEmpty
        }
        Remove-Sandbox -Name 'sbx-rm' -DeleteDisks -Backend $script:B
        foreach ($d in $script:Desc.CreatedDisks) {
            (& $script:B.GetVHDInfo @{ Path = $d }) | Should -BeNullOrEmpty -Because "every created disk '$d' must be deleted"
        }
    }

    It 'removing a NON-EXISTENT VM is a clean no-op (warns, does not throw)' {
        { Remove-Sandbox -Name 'never-existed-vm' -Backend $script:B } |
            Should -Not -Throw -Because 'idempotent teardown: removing an absent VM is a no-op, not a crash'
    }

    It 'removing a non-existent VM with -DeleteDisks is also a clean no-op' {
        { Remove-Sandbox -Name 'never-existed-vm' -DeleteDisks -Backend $script:B } |
            Should -Not -Throw
    }

    It 'is idempotent: calling Remove-Sandbox twice does not throw on the second call' {
        Remove-Sandbox -Name 'sbx-rm' -Backend $script:B
        { Remove-Sandbox -Name 'sbx-rm' -Backend $script:B } | Should -Not -Throw -Because 'a second teardown of the same VM is a no-op'
    }
}

# ===========================================================================
#  Provisioner does NOT touch a profile that is incompatible (defensive)
# ===========================================================================
Describe 'New-SandboxVM — input validation' {

    It 'throws on a $null profile' {
        $b = New-FakeHyperVBackend
        { New-SandboxVM -Profile $null -Name 'x' -Backend $b } | Should -Throw
    }

    It 'throws on a blank VM name' {
        $b = New-FakeHyperVBackend
        { New-SandboxVM -Profile $script:Tier1 -Name '   ' -Backend $b } | Should -Throw
    }
}

Describe 'Get-VMField — reads a field off EITHER backend VM shape (fake hashtable vs real PSObject)' {

    It 'reads a field off a REAL-shaped (PSObject) VM record' {
        # The REAL GetVM returns a Microsoft.HyperV.PowerShell.VirtualMachine PSObject (fields are
        # properties, NO .ContainsKey). A hashtable-only accessor (.ContainsKey / ['State']) THROWS
        # on this shape — the live-poll bug class. Get-VMField must read .State off the property bag.
        $vm = [pscustomobject]@{ Name = 'x'; State = 'Off' }
        Get-VMField -VM $vm -Name 'State' -Default 'Unknown' | Should -Be 'Off'
    }

    It 'reads a field off a FAKE-shaped (hashtable) VM record' {
        $vm = @{ Name = 'x'; State = 'Running' }
        Get-VMField -VM $vm -Name 'State' -Default 'Unknown' | Should -Be 'Running'
    }

    It 'returns the default for a $null VM (missing-VM read)' {
        # GetVM of a non-existent VM returns $null; the accessor must yield the default, not throw.
        Get-VMField -VM $null -Name 'State' -Default 'Unknown' | Should -Be 'Unknown'
    }

    It 'returns the default for an absent field on either shape' {
        Get-VMField -VM ([pscustomobject]@{ Name = 'x' }) -Name 'State' -Default 'Unknown' | Should -Be 'Unknown'
        Get-VMField -VM @{ Name = 'x' }                    -Name 'State' -Default 'Unknown' | Should -Be 'Unknown'
    }
}
