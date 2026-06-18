#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for scripts/lib/Runner.ps1 (Runner + Capturer + Extractor).

.DESCRIPTION
    Contract under test:

        Start-SandboxWorkload  -Descriptor <d> -Entrypoint <cmd> [-ArtifactRoot <dir>] [-TimeoutSeconds <n>] [-Backend]
                               starts the VM, delivers the entrypoint over the COM1 serial seam
                               (the backend's InvokeGuestCommand), arms host-side capture, and
                               returns a run-result the orchestrator + Extractor consume.

        Export-SandboxArtifact -Descriptor <d> -ResultPath <guest-or-shared> -Destination <host-dir> [-Backend]
                               Tier 0/1: host reads the designated result file/dir into the host
                               destination (one-way OUT). Tier >= 2: routes to the quarantine STUB
                               (Export-ColdVhdxQuarantine) which THROWS NotImplemented — it must NOT
                               fall through to the trusting Tier-0/1 read.

    THE SERIAL SEAM: the guest is a Linux VM driven over the COM1 named-pipe serial
    console (PowerShell Direct is Windows-guest-only). For v1/testability the Runner models command
    delivery through a NEW backend method, InvokeGuestCommand, added to the backend (manifest + both factories
    + parity/drift tests) following the RemoveVHD/RemoveSwitch/SetHostChannel precedent. The FAKE
    records the command and returns canned output; the REAL impl wires to the COM1 pipe. This keeps
    the Runner unit-testable with no live VM.

    CAPTURE (host-side, out-of-band): never trust the guest to self-report. v1 is
    pragmatic: the Runner records run metadata (start/end, exit status, captured stdout/stderr) to a
    host-side artifact dir and returns the path. The captured output comes via the serial seam (the
    backend), not from a guest-written file we blindly trust.

    EXTRACTION BOUNDARY: Tier 0/1 is a trusting host-read of a result the (non-hostile)
    workload emitted. Tier >= 2 is presumed-hostile — the cold-VHDX → quarantine → CDR flow is
    scaffolded/benign-only and NOT implemented in v1; the Tier>=2 path must THROW via the
    clearly-marked quarantine stub, never use the Tier-0/1 trusting read.

    TDD: written FIRST; drives Runner.ps1 + the InvokeGuestCommand backend addendum.
#>

BeforeAll {
    # Resolve the skill root from this test file's location: <root>/tests/ -> <root>
    $script:SkillRoot   = Split-Path -Parent $PSScriptRoot
    $script:RunnerPath  = Join-Path $script:SkillRoot 'scripts/lib/Runner.ps1'
    $script:BackendPath = Join-Path $script:SkillRoot 'scripts/lib/HyperVBackend.ps1'
    $script:LoaderPath  = Join-Path $script:SkillRoot 'scripts/lib/ProfileLoader.ps1'
    $script:ProvPath    = Join-Path $script:SkillRoot 'scripts/lib/Provisioner.ps1'
    $script:SealerPath  = Join-Path $script:SkillRoot 'scripts/lib/Sealer.ps1'
    $script:TierDir     = Join-Path $script:SkillRoot 'tier-profiles'

    Test-Path $script:RunnerPath  | Should -BeTrue -Because 'the Runner script must exist to be tested'
    Test-Path $script:BackendPath | Should -BeTrue -Because 'the backend must exist'
    Test-Path $script:ProvPath    | Should -BeTrue -Because 'the Provisioner must exist'
    Test-Path $script:SealerPath  | Should -BeTrue -Because 'the Sealer must exist'

    . $script:BackendPath
    . $script:LoaderPath
    . $script:ProvPath
    . $script:SealerPath
    . $script:RunnerPath

    $script:Tier0 = Import-TierProfile -Path (Join-Path $script:TierDir 'tier0.psd1')
    $script:Tier1 = Import-TierProfile -Path (Join-Path $script:TierDir 'tier1.psd1')

    # A Tier-2 fixture profile (disposable no-net), synthesized from Tier-1 (see Sealer.Tests.ps1).
    $script:Tier2 = $script:Tier1.Clone()
    $script:Tier2['Tier']            = 2
    $script:Tier2['Description']     = 'TEST FIXTURE — Tier 2 disposable no-net VM.'
    $script:Tier2['Network']         = 'Private-NoNIC'
    $script:Tier2['EgressMode']      = 'None'
    $script:Tier2['EgressAllowlist'] = @()
    $script:Tier2['Credentials']     = 'None'
    $script:Tier2['Extraction']      = 'ColdVHDX-Quarantine-CDR'
    $script:Tier2['Lifecycle']       = 'CreateDestroy'
    Assert-TierProfileValid -Profile $script:Tier2 -Context 'TEST Tier-2 fixture'

    # A host-side artifact root for the Runner's capture output + the Extractor's destination.
    $script:TmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vmdep-t5-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $script:TmpRoot -Force | Out-Null

    # Provision a fresh VM on a fresh fake backend, returning @{ Backend; Desc }. Script-scoped
    # SCRIPTBLOCK so Pester's child-scope It/BeforeEach blocks reach it via `& $script:NewTestSandbox`.
    $script:NewTestSandbox = {
        param($Profile = $script:Tier1, [string] $Name = 'sbx-t5')
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
#  Backend addendum — InvokeGuestCommand (the serial seam) is part of the surface
# ===========================================================================
Describe 'Backend addendum — InvokeGuestCommand (the COM1 serial seam) is in the manifest + both factories' {

    It 'the manifest documents InvokeGuestCommand with its arg keys' {
        $manifest = Get-HyperVBackendMethodManifest
        $manifest.Keys | Should -Contain 'InvokeGuestCommand' -Because 'the Runner delivers the entrypoint over the serial seam; it must be a backend method, not a raw cmdlet'
        @($manifest['InvokeGuestCommand']) | Should -Contain 'VMName'
        @($manifest['InvokeGuestCommand']) | Should -Contain 'Command'
    }

    It 'both the real and fake backends implement InvokeGuestCommand as a scriptblock' {
        $real = New-RealHyperVBackend
        $fake = New-FakeHyperVBackend
        $real['InvokeGuestCommand'] | Should -BeOfType [scriptblock] -Because 'the real backend must wire the COM1 pipe'
        $fake['InvokeGuestCommand'] | Should -BeOfType [scriptblock] -Because 'the fake must simulate the serial seam'
    }

    It 'the FAKE InvokeGuestCommand requires VMName + Command (omitting either throws)' {
        $fake = New-FakeHyperVBackend
        & $fake.NewVM @{ Name = 'vm-cmd'; Generation = 2 }
        { & $fake.InvokeGuestCommand @{ Command = 'echo hi' } }      | Should -Throw -Because 'VMName is a required arg'
        { & $fake.InvokeGuestCommand @{ VMName = 'vm-cmd' } }        | Should -Throw -Because 'Command is a required arg'
    }

    It 'the FAKE InvokeGuestCommand on a missing VM throws naming the VM' {
        $fake = New-FakeHyperVBackend
        { & $fake.InvokeGuestCommand @{ VMName = 'ghost'; Command = 'echo hi' } } |
            Should -Throw -ExpectedMessage '*ghost*'
    }

    It 'the FAKE InvokeGuestCommand returns a structured result (ExitCode / Stdout / Stderr) and records the command' {
        $fake = New-FakeHyperVBackend
        & $fake.NewVM @{ Name = 'vm-cmd'; Generation = 2 }
        $res = & $fake.InvokeGuestCommand @{ VMName = 'vm-cmd'; Command = 'ralph_loop.sh' }
        $res | Should -BeOfType [System.Collections.IDictionary]
        $res.ContainsKey('ExitCode') | Should -BeTrue
        $res.ContainsKey('Stdout')   | Should -BeTrue
        $res.ContainsKey('Stderr')   | Should -BeTrue
        $res.ExitCode | Should -Be 0 -Because 'the default canned result is a success'
        # The fake records the delivered command so a test can assert the Runner sent the right one.
        $vm = & $fake.GetVM @{ Name = 'vm-cmd' }
        @($vm.GuestCommands) | Should -Contain 'ralph_loop.sh' -Because 'the fake records what was sent over the serial seam'
    }

    It 'the FAKE InvokeGuestCommand can be forced to a non-zero exit (SimulateGuestCommandFailure)' {
        $bad = New-FakeHyperVBackend -SimulateGuestCommandFailure
        & $bad.NewVM @{ Name = 'vm-bad'; Generation = 2 }
        $res = & $bad.InvokeGuestCommand @{ VMName = 'vm-bad'; Command = 'boom' }
        $res.ExitCode | Should -Not -Be 0 -Because 'the failure-simulating fake returns a non-zero exit so the Runner failure path is testable'
    }
}

# ===========================================================================
#  Start-SandboxWorkload — starts the VM, delivers the entrypoint, arms capture
# ===========================================================================
Describe 'Start-SandboxWorkload — runs the workload over the serial seam + records capture' {

    BeforeEach {
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-run'
        $script:B = $sb.Backend; $script:Desc = $sb.Desc
        # Seal first (the Runner runs a sealed VM; the orchestrator enforces this, but the Runner
        # itself just needs a provisioned VM to start). Sealing is harmless here.
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        $script:ArtRoot = Join-Path $script:TmpRoot ("run-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'STARTS the VM (it was Off after provisioning/sealing)' {
        (& $script:B.GetVM @{ Name = 'sbx-run' }).State | Should -Be 'Off' -Because 'precondition: a sealed VM is powered off'
        Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' -ArtifactRoot $script:ArtRoot -Backend $script:B | Out-Null
        (& $script:B.GetVM @{ Name = 'sbx-run' }).State | Should -Be 'Running' -Because 'the Runner must start the VM before delivering the workload'
    }

    It 'DELIVERS the entrypoint command over the serial seam (InvokeGuestCommand records it)' {
        Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' -ArtifactRoot $script:ArtRoot -Backend $script:B | Out-Null
        @((& $script:B.GetVM @{ Name = 'sbx-run' }).GuestCommands) |
            Should -Contain 'bash ralph_loop.sh' -Because 'the Runner delivers the entrypoint over COM1 via the backend seam, not a raw cmdlet'
    }

    It 'RETURNS a run-result the orchestrator + Extractor consume (VMName, ExitCode, capture path)' {
        $result = Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' -ArtifactRoot $script:ArtRoot -Backend $script:B
        $result | Should -Not -BeNullOrEmpty
        $result.VMName    | Should -Be 'sbx-run'
        $result.Entrypoint | Should -Be 'bash ralph_loop.sh'
        $result.ExitCode  | Should -Be 0 -Because 'the fake canned result is a success'
        $result.PSObject.Properties.Name | Should -Contain 'CapturePath' -Because 'the run-result must point at the host-side capture artifact'
        $result.PSObject.Properties.Name | Should -Contain 'StartedAt'
        $result.PSObject.Properties.Name | Should -Contain 'EndedAt'
    }

    It 'ARMS host-side capture: writes a run-metadata artifact under the artifact root' {
        $result = Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' -ArtifactRoot $script:ArtRoot -Backend $script:B
        $result.CapturePath | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $result.CapturePath | Should -BeTrue -Because 'host-side capture is out-of-band: the run metadata is written to a host file'
        # The capture metadata must record the run (exit + the captured stdout/stderr from the seam).
        $meta = Get-Content -LiteralPath $result.CapturePath -Raw | ConvertFrom-Json
        $meta.VMName     | Should -Be 'sbx-run'
        $meta.Entrypoint | Should -Be 'bash ralph_loop.sh'
        $meta.ExitCode   | Should -Be 0
    }

    It 'records capture under the per-run artifact dir (host-side, not in the guest)' {
        $result = Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' -ArtifactRoot $script:ArtRoot -Backend $script:B
        # The capture path lives under the host-side artifact root we supplied (out-of-band).
        $result.CapturePath | Should -BeLike "$script:ArtRoot*" -Because 'capture is host-side under the supplied artifact root'
    }

    It 'FAILS CLOSED when the backend is unavailable (does not pretend the workload ran)' {
        $bad = New-FakeHyperVBackend -SimulateUnavailable
        # Provision/seal on the working backend, then try to run against an unavailable one.
        { Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' -ArtifactRoot $script:ArtRoot -Backend $bad } |
            Should -Throw -Because 'if Hyper-V is unreachable the Runner must fail closed, never claim a phantom run'
    }

    It 'throws on a null descriptor (the RIGHT reason)' {
        { Start-SandboxWorkload -Descriptor $null -Entrypoint 'x' -ArtifactRoot $script:ArtRoot -Backend $script:B } |
            Should -Throw -ExpectedMessage '*Descriptor is null*'
    }

    It 'throws on a blank entrypoint' {
        { Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint '  ' -ArtifactRoot $script:ArtRoot -Backend $script:B } |
            Should -Throw -ExpectedMessage '*Entrypoint*'
    }

    It 'surfaces a non-zero guest exit in the run-result (does not throw on a workload failure)' {
        # A workload that exits non-zero is a RUN OUTCOME, not a Runner error — the Runner reports
        # it on the result (ExitCode) so the orchestrator can decide. Use a failure-simulating backend
        # but provision/seal on it first so the VM exists.
        $bad = New-FakeHyperVBackend -SimulateGuestCommandFailure
        $d = New-SandboxVM -Profile $script:Tier1 -Name 'sbx-runfail' -Backend $bad
        Lock-Sandbox -Descriptor $d -Backend $bad
        $art = Join-Path $script:TmpRoot ("runfail-{0}" -f ([guid]::NewGuid().ToString('N')))
        $result = Start-SandboxWorkload -Descriptor $d -Entrypoint 'bash will-fail.sh' -ArtifactRoot $art -Backend $bad
        $result.ExitCode | Should -Not -Be 0 -Because 'a non-zero guest exit is reported on the result, not thrown'
    }
}

# ===========================================================================
#  Start-SandboxWorkload — BootWaitSeconds default raised to 180 (the live 60s timeout)
# ===========================================================================
#  A FIRST cloud-init boot off a fresh differencing disk needs ~90-180s, but the original default
#  of 60 timed out on the live run (60s / 13 probes). The default is raised to 180. Pinned via the
#  function's parameter AST (the default literal) so a regression back to 60 is caught — tests still
#  inject 0 so they never sleep, which is why a behavioral assertion can't observe the default.
Describe 'Start-SandboxWorkload — BootWaitSeconds default is 180 (raised from the live-timeout 60)' {

    It 'the BootWaitSeconds parameter default is 180' {
        $fn = Get-Command Start-SandboxWorkload -CommandType Function
        $param = $fn.ScriptBlock.Ast.Body.ParamBlock.Parameters |
            Where-Object { $_.Name.VariablePath.UserPath -eq 'BootWaitSeconds' } | Select-Object -First 1
        $param | Should -Not -BeNullOrEmpty -Because 'Start-SandboxWorkload must declare a BootWaitSeconds parameter'
        $param.DefaultValue | Should -Not -BeNullOrEmpty -Because 'BootWaitSeconds must carry an explicit default'
        [int]$param.DefaultValue.Extent.Text |
            Should -Be 180 -Because 'a first cloud-init boot off a fresh differencing disk needs ~90-180s; the old default of 60 timed out on the live run'
    }
}

# ===========================================================================
#  Export-SandboxArtifact — Tier 0/1 one-way host read of a result artifact
# ===========================================================================
Describe 'Export-SandboxArtifact — Tier 0/1 reads a result artifact to a host dir (one-way OUT)' {

    BeforeEach {
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-ext'
        $script:B = $sb.Backend; $script:Desc = $sb.Desc

        # The "result" the workload emitted (e.g. the Firefox Netscape-HTML export). For v1 Tier 0/1
        # this is a host-readable path (shared result dir / collected out-of-band). Create it on disk.
        $script:ResultDir = Join-Path $script:TmpRoot ("result-{0}" -f ([guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $script:ResultDir -Force | Out-Null
        $script:ResultFile = Join-Path $script:ResultDir 'bookmarks.html'
        Set-Content -LiteralPath $script:ResultFile -Value '<html>bookmarks</html>' -NoNewline -Encoding utf8

        $script:DestDir = Join-Path $script:TmpRoot ("dest-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'copies a result FILE into the host destination (one-way out)' {
        $out = Export-SandboxArtifact -Descriptor $script:Desc -ResultPath $script:ResultFile -Destination $script:DestDir -Backend $script:B
        $out | Should -Not -BeNullOrEmpty
        $copied = Join-Path $script:DestDir 'bookmarks.html'
        Test-Path -LiteralPath $copied | Should -BeTrue -Because 'Tier 0/1 extraction reads the emitted artifact into the host destination'
        (Get-Content -LiteralPath $copied -Raw) | Should -Be '<html>bookmarks</html>'
    }

    It 'copies a result DIRECTORY (recursively) into the host destination' {
        $out = Export-SandboxArtifact -Descriptor $script:Desc -ResultPath $script:ResultDir -Destination $script:DestDir -Backend $script:B
        Test-Path -LiteralPath (Join-Path $script:DestDir 'bookmarks.html') | Should -BeTrue -Because 'a result directory is collected recursively'
    }

    It 'returns the host-side path(s) it wrote (so the orchestrator can report the extracted artifact)' {
        $out = Export-SandboxArtifact -Descriptor $script:Desc -ResultPath $script:ResultFile -Destination $script:DestDir -Backend $script:B
        @($out) | Should -Not -BeNullOrEmpty
        @($out)[0] | Should -BeLike "$script:DestDir*" -Because 'the returned path is the host-side extracted artifact'
    }

    It 'creates the destination dir if it does not exist' {
        $freshDest = Join-Path $script:TmpRoot ("dest-fresh-{0}" -f ([guid]::NewGuid().ToString('N')))
        Test-Path -LiteralPath $freshDest | Should -BeFalse -Because 'precondition: destination does not exist yet'
        Export-SandboxArtifact -Descriptor $script:Desc -ResultPath $script:ResultFile -Destination $freshDest -Backend $script:B | Out-Null
        Test-Path -LiteralPath (Join-Path $freshDest 'bookmarks.html') | Should -BeTrue
    }

    It 'works for Tier 0 too (the trusting host-read tier)' {
        $b0 = New-FakeHyperVBackend
        # Tier 0 is a Container substrate; New-SandboxVM is Hyper-V-only, so for the extractor test we
        # build a minimal Tier-0 descriptor by hand (the extractor only reads Tier off the descriptor).
        $d0 = [pscustomobject]@{ Name = 'sbx-ext0'; Tier = 0; DiskPath = $null }
        $dest0 = Join-Path $script:TmpRoot ("dest0-{0}" -f ([guid]::NewGuid().ToString('N')))
        Export-SandboxArtifact -Descriptor $d0 -ResultPath $script:ResultFile -Destination $dest0 -Backend $b0 | Out-Null
        Test-Path -LiteralPath (Join-Path $dest0 'bookmarks.html') | Should -BeTrue -Because 'Tier 0 uses the same one-way host-read'
    }

    It 'throws when the result path does not exist (nothing to extract)' {
        { Export-SandboxArtifact -Descriptor $script:Desc -ResultPath (Join-Path $script:ResultDir 'ghost.html') -Destination $script:DestDir -Backend $script:B } |
            Should -Throw -Because 'a missing result artifact is a clear caller error'
    }

    It 'throws on a null descriptor' {
        { Export-SandboxArtifact -Descriptor $null -ResultPath $script:ResultFile -Destination $script:DestDir -Backend $script:B } |
            Should -Throw -ExpectedMessage '*Descriptor is null*'
    }
}

# ===========================================================================
#  Export-SandboxArtifact — Tier >= 2 routes to the quarantine STUB (THROWS)
# ===========================================================================
Describe 'Export-SandboxArtifact — Tier >= 2 must route to the quarantine stub and THROW (never the Tier-0/1 trusting read)' {

    BeforeEach {
        # A real-shaped Tier-2 descriptor. The point: the extractor must NOT read its result with the
        # trusting Tier-0/1 path; it must route to the cold-VHDX quarantine flow, which is a stub.
        $b = New-FakeHyperVBackend
        $script:Desc2 = New-SandboxVM -Profile $script:Tier2 -Name 'sbx-ext2' -Backend $b
        $script:B2 = $b

        # A result file that WOULD be trustingly read by the Tier-0/1 path — proving the Tier>=2 path
        # does NOT touch it (we assert nothing gets copied to the destination).
        $script:HostileResult = Join-Path $script:TmpRoot ("hostile-{0}.bin" -f ([guid]::NewGuid().ToString('N')))
        Set-Content -LiteralPath $script:HostileResult -Value 'pretend-malware-output' -NoNewline -Encoding ascii
        $script:Dest2 = Join-Path $script:TmpRoot ("dest2-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'THROWS a clear NotImplemented for a Tier-2 extraction (cold-VHDX quarantine is post-v1)' {
        { Export-SandboxArtifact -Descriptor $script:Desc2 -ResultPath $script:HostileResult -Destination $script:Dest2 -Backend $script:B2 } |
            Should -Throw -ExpectedMessage '*not implemented*' -Because 'the Tier>=2 cold-VHDX->quarantine->CDR flow is scaffolded/benign-only and not built in v1; it must fail loudly, not silently extract'
    }

    It 'the Tier-2 throw NAMES the cold-VHDX / quarantine flow (so the operator knows why)' {
        { Export-SandboxArtifact -Descriptor $script:Desc2 -ResultPath $script:HostileResult -Destination $script:Dest2 -Backend $script:B2 } |
            Should -Throw -ExpectedMessage '*quarantine*' -Because 'the refusal must point at the cold-VHDX quarantine path it is gating'
    }

    It 'does NOT trustingly read/copy the hostile result via the Tier-0/1 path (no artifact extracted)' {
        try { Export-SandboxArtifact -Descriptor $script:Desc2 -ResultPath $script:HostileResult -Destination $script:Dest2 -Backend $script:B2 } catch { }
        # The destination must be empty / non-existent: the Tier-0/1 trusting copy must NOT have run.
        if (Test-Path -LiteralPath $script:Dest2) {
            @(Get-ChildItem -LiteralPath $script:Dest2 -Force -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because 'a Tier>=2 extraction must NEVER fall through to the Tier-0/1 trusting host-read'
        }
        else {
            Test-Path -LiteralPath $script:Dest2 | Should -BeFalse -Because 'the hostile-tier path must not have created/populated the destination'
        }
    }

    It 'Tier 3 also routes to the quarantine stub (THROWS), never the trusting read' {
        $t3 = $script:Tier2.Clone(); $t3['Tier'] = 3; $t3['Lifecycle'] = 'DetonateWipe'
        Assert-TierProfileValid -Profile $t3 -Context 'TEST Tier-3 fixture'
        $b3 = New-FakeHyperVBackend
        $d3 = New-SandboxVM -Profile $t3 -Name 'sbx-ext3' -Backend $b3
        { Export-SandboxArtifact -Descriptor $d3 -ResultPath $script:HostileResult -Destination $script:Dest2 -Backend $b3 } |
            Should -Throw -ExpectedMessage '*not implemented*' -Because 'Tier 3 is the strictest hostile tier; it must also refuse the v1 trusting read'
    }

    It 'Export-ColdVhdxQuarantine (the stub) exists and THROWS NotImplemented when called directly' {
        # The stub is the single clearly-marked sink for Tier>=2 extraction. Calling it directly must
        # throw, guaranteeing no accidental Tier-0/1-style read can be wired through it later by mistake.
        (Get-Command Export-ColdVhdxQuarantine -ErrorAction SilentlyContinue) |
            Should -Not -BeNullOrEmpty -Because 'the Tier>=2 extraction sink must be a named, discoverable function'
        { Export-ColdVhdxQuarantine -Descriptor $script:Desc2 -ResultPath $script:HostileResult -Destination $script:Dest2 -Backend $script:B2 } |
            Should -Throw -ExpectedMessage '*not implemented*'
    }
}

# ===========================================================================
#  Export-SandboxArtifact — an UNDETERMINABLE tier FAILS CLOSED (never the trusting read)
# ===========================================================================
Describe 'Export-SandboxArtifact — an undeterminable / out-of-range tier is treated as HOSTILE (fail closed, never the Tier-0/1 read)' {
    # Hardening: the extractor must not DEFAULT a missing / $null / non-integer
    # / out-of-range descriptor Tier to 0 (which would route to the TRUSTING Tier-0/1 host-read). For a
    # boundary guarding artifact exfil from a possibly-hostile VM, "unknown tier => trusting read" is the
    # wrong default. An undeterminable tier must be treated as hostile: refuse to extract via the trusting
    # path (throw / route to the quarantine stub), and copy NOTHING to the destination.

    BeforeEach {
        # A host-readable result that the Tier-0/1 path WOULD trustingly copy — its presence-or-absence at
        # the destination is the proof of whether the trusting read fired.
        $script:UResult = Join-Path $script:TmpRoot ("uncertain-{0}.bin" -f ([guid]::NewGuid().ToString('N')))
        Set-Content -LiteralPath $script:UResult -Value 'must-not-be-extracted' -NoNewline -Encoding ascii
        $script:UDest = Join-Path $script:TmpRoot ("udest-{0}" -f ([guid]::NewGuid().ToString('N')))
        $script:UBackend = New-FakeHyperVBackend
    }

    # Assert BOTH the throw AND that nothing leaked to the destination, for each undeterminable shape.
    It 'a descriptor with NO Tier field fails closed (no trusting read, nothing extracted)' {
        $d = [pscustomobject]@{ Name = 'sbx-notier' }   # Tier absent entirely
        { Export-SandboxArtifact -Descriptor $d -ResultPath $script:UResult -Destination $script:UDest -Backend $script:UBackend } |
            Should -Throw -Because 'a missing Tier is undeterminable; defaulting to 0 (trusting read) would defeat containment'
        if (Test-Path -LiteralPath $script:UDest) {
            @(Get-ChildItem -LiteralPath $script:UDest -Force -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because 'an undeterminable tier must NEVER fall through to the Tier-0/1 trusting host-read'
        }
        else { Test-Path -LiteralPath $script:UDest | Should -BeFalse }
    }

    It 'a descriptor with Tier = $null fails closed (no trusting read, nothing extracted)' {
        $d = [pscustomobject]@{ Name = 'sbx-nulltier'; Tier = $null }
        { Export-SandboxArtifact -Descriptor $d -ResultPath $script:UResult -Destination $script:UDest -Backend $script:UBackend } |
            Should -Throw -Because 'a $null Tier is undeterminable; it must not default to the trusting Tier-0/1 read'
        if (Test-Path -LiteralPath $script:UDest) {
            @(Get-ChildItem -LiteralPath $script:UDest -Force -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because 'a $null tier must not be trustingly extracted'
        }
        else { Test-Path -LiteralPath $script:UDest | Should -BeFalse }
    }

    It 'a descriptor with a NON-INTEGER Tier ("banana") fails closed (no trusting read, nothing extracted)' {
        $d = [pscustomobject]@{ Name = 'sbx-bananatier'; Tier = 'banana' }
        { Export-SandboxArtifact -Descriptor $d -ResultPath $script:UResult -Destination $script:UDest -Backend $script:UBackend } |
            Should -Throw -Because 'a non-integer Tier cannot be classified; it must fail closed, not be coerced to 0'
        if (Test-Path -LiteralPath $script:UDest) {
            @(Get-ChildItem -LiteralPath $script:UDest -Force -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because 'a non-integer tier must not be trustingly extracted'
        }
        else { Test-Path -LiteralPath $script:UDest | Should -BeFalse }
    }

    It 'a descriptor with an OUT-OF-RANGE Tier (7) fails closed (no trusting read, nothing extracted)' {
        $d = [pscustomobject]@{ Name = 'sbx-tier7'; Tier = 7 }
        { Export-SandboxArtifact -Descriptor $d -ResultPath $script:UResult -Destination $script:UDest -Backend $script:UBackend } |
            Should -Throw -Because 'a Tier outside 0..3 is undeterminable; it must fail closed, never the trusting read'
        if (Test-Path -LiteralPath $script:UDest) {
            @(Get-ChildItem -LiteralPath $script:UDest -Force -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because 'an out-of-range tier must not be trustingly extracted'
        }
        else { Test-Path -LiteralPath $script:UDest | Should -BeFalse }
    }

    It 'the refusal message explains the tier could not be determined (operator clarity)' {
        $d = [pscustomobject]@{ Name = 'sbx-whytier' }
        { Export-SandboxArtifact -Descriptor $d -ResultPath $script:UResult -Destination $script:UDest -Backend $script:UBackend } |
            Should -Throw -ExpectedMessage '*tier*' -Because 'the fail-closed refusal must point at the undeterminable tier as the reason'
    }

    It 'a valid STRING tier "2" still routes to the quarantine stub (parseable hostile tier — unchanged)' {
        # Regression guard: the new strict parse must still accept a numeric STRING in range and route a
        # Tier-2 to the quarantine stub (this already worked via the [int] cast; keep it working).
        $d = [pscustomobject]@{ Name = 'sbx-strtier2'; Tier = '2' }
        { Export-SandboxArtifact -Descriptor $d -ResultPath $script:UResult -Destination $script:UDest -Backend $script:UBackend } |
            Should -Throw -ExpectedMessage '*not implemented*' -Because 'a parseable in-range Tier 2 routes to the cold-VHDX quarantine stub'
    }

    It 'an explicit Tier 0 (int) still does the trusting host-read (the fix must not break the valid path)' {
        $d = [pscustomobject]@{ Name = 'sbx-tier0ok'; Tier = 0 }
        Export-SandboxArtifact -Descriptor $d -ResultPath $script:UResult -Destination $script:UDest -Backend $script:UBackend | Out-Null
        Test-Path -LiteralPath (Split-Path -Parent (Join-Path $script:UDest (Split-Path -Leaf $script:UResult))) | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:UDest (Split-Path -Leaf $script:UResult)) |
            Should -BeTrue -Because 'an explicit, in-range Tier 0 must still perform the trusting one-way host-read'
    }

    It 'an explicit Tier 1 (int) still does the trusting host-read' {
        $d = [pscustomobject]@{ Name = 'sbx-tier1ok'; Tier = 1 }
        Export-SandboxArtifact -Descriptor $d -ResultPath $script:UResult -Destination $script:UDest -Backend $script:UBackend | Out-Null
        Test-Path -LiteralPath (Join-Path $script:UDest (Split-Path -Leaf $script:UResult)) |
            Should -BeTrue -Because 'an explicit, in-range Tier 1 must still perform the trusting one-way host-read'
    }
}
