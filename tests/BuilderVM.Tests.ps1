#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for scripts/lib/BuilderVM.ps1 (Invoke-BuilderVM orchestrator).

.DESCRIPTION
    Task 2.4: Tier-1 builder orchestration — provision->seed->run->detach->whole-image-hash->emit.
    No seal (the builder keeps its NIC + Squid egress for the whole run).
    The integrity artifact is the whole-image hash (raw, no mount). The deps (OUTPUT) disk is never read by the
    host; the verdict (exit code and manifest) comes from a second, small RAW disk in the user-space outbox
    format, read before the move and the hash.
    Success = exit code exactly 0 + manifest present (E7); a bad verdict = FetchFailed; timeout = Failed.
    The finished deps.vhdx is moved out of the sandbox folder and survives teardown (E7).

    TDD: written FIRST; drives scripts/lib/BuilderVM.ps1.
#>

BeforeAll {
    $script:SkillRoot   = Split-Path -Parent $PSScriptRoot
    $script:BVMPath     = Join-Path $script:SkillRoot 'scripts/lib/BuilderVM.ps1'
    $script:OrchPath    = Join-Path $script:SkillRoot 'scripts/Invoke-Voidseal.ps1'
    $script:BackendPath = Join-Path $script:SkillRoot 'scripts/lib/HyperVBackend.ps1'

    Test-Path $script:BVMPath  | Should -BeTrue  -Because 'BuilderVM.ps1 must exist'
    Test-Path $script:OrchPath | Should -BeTrue  -Because 'Invoke-Voidseal.ps1 (with all dot-sourced deps) must exist'

    # Dot-source the orchestrator (which transitively dot-sources HyperVBackend.ps1,
    # ProfileLoader.ps1, Provisioner.ps1, Sealer.ps1, Runner.ps1, Workload.ps1, SeedBuilder.ps1,
    # SensitivityGate.ps1 — all the engine libs BuilderVM.ps1 reuses). Then dot-source BuilderVM.ps1.
    . $script:OrchPath
    . $script:BVMPath

    # What a builder guest packs into its raw verdict disk is a guest/outbox.py container holding
    # result.exitcode and deps-manifest.json. Build it with the real producer the guest runs
    # (run_disk_workload.py --transport-only), so the fixture cannot drift from the format. Blobs are cached
    # per content: each build is a python call.
    $script:VerdictBlobCache = @{}
    function script:New-VerdictBlob {
        param([hashtable] $Files)
        $key = (@($Files.Keys | Sort-Object) | ForEach-Object { '{0}={1}' -f $_, $Files[$_] }) -join '|'
        if ($script:VerdictBlobCache.ContainsKey($key)) { return ,[byte[]]$script:VerdictBlobCache[$key] }
        $work = Join-Path ([System.IO.Path]::GetTempPath()) ('vs-verdict-fx-{0}' -f [guid]::NewGuid().ToString('N'))
        $staging = Join-Path $work 'staging'
        New-Item -ItemType Directory -Path $staging -Force | Out-Null
        try {
            foreach ($k in @($Files.Keys)) {
                [System.IO.File]::WriteAllText((Join-Path $staging $k), [string]$Files[$k], [System.Text.UTF8Encoding]::new($false))
            }
            $out = Join-Path $work 'outbox.bin'
            $py  = Resolve-PythonExe
            $log = & $py (Join-Path $script:SkillRoot 'guest/run_disk_workload.py') --staging $staging --verdicts (Join-Path $work 'verdicts.json') --out $out --transport-only 2>&1
            if ($LASTEXITCODE -ne 0) { throw "the verdict fixture could not be packed: $log" }
            $bytes = [System.IO.File]::ReadAllBytes($out)
        }
        finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
        $script:VerdictBlobCache[$key] = $bytes
        return ,[byte[]]$bytes
    }

    # What a green builder guest leaves in its verdict outbox: exit code 0 and the deps manifest.
    $script:BuilderOkBlob = script:New-VerdictBlob @{ 'result.exitcode' = '0'; 'deps-manifest.json' = '{"files":[]}' }
}

# ===========================================================================
#  Happy path — a clean builder run emits a deps.vhdx + whole-image hash
# ===========================================================================
Describe 'Invoke-BuilderVM — Tier-1 builder orchestration (Phase 2.4)' {

    It 'a clean builder run emits a deps.vhdx + the whole-image hash (== SHA256 of the deps bytes) and Status=Success' {
        $blob = [byte[]](1..64)
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob $blob
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld1' -Backend $fake -DepsDiskPath (Join-Path $TestDrive 'deps.vhdx')
        $r.Status | Should -Be 'Success'
        $r.DepsDiskPath | Should -Not -BeNullOrEmpty
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $want = [System.BitConverter]::ToString($sha.ComputeHash($blob)).Replace('-','').ToLowerInvariant(); $sha.Dispose()
        $r.WholeImageHash | Should -Be $want
    }

    It 'the OUTPUT (deps) disk is DETACHED before the host hash (no read of a locked/attached disk)' {
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..8))
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld2' -Backend $fake -DepsDiskPath (Join-Path $TestDrive 'd2.vhdx')
        $r.Status | Should -Be 'Success'   # GetVhdxImageHash THROWS if still attached -> Success proves detach-before-hash
        $ops = @($fake.FakeCallLog | Where-Object { $_.Op -in @('RemoveHardDiskDrive','GetVhdxImageHash') } | ForEach-Object { $_.Op })
        # TR-2: assert BOTH ops actually ran BEFORE the IndexOf ordering check — IndexOf returns -1 when an
        # op is absent, and `-1 -BeLessThan <positive>` is vacuously TRUE, so the ordering assertion alone
        # would pass even if the detach never happened (mirror InvokeVoidseal.Tests.ps1's 'attaches BOTH data disks before the seal' It).
        $ops | Should -Contain 'RemoveHardDiskDrive' -Because 'the OUTPUT/deps disk must be detached'
        $ops | Should -Contain 'GetVhdxImageHash'    -Because 'the whole-image hash must run'
        ($ops.IndexOf('RemoveHardDiskDrive')) | Should -BeLessThan ($ops.IndexOf('GetVhdxImageHash'))
    }

    It 'a hung builder (SimulateNeverOff) times out -> Status=Failed, NO deps artifact, no hash' {
        $fake = New-FakeHyperVBackend -SimulateNeverOff -SimulateDepsImageBlob ([byte[]](1..8))
        # TR-3: capture the lifecycle-abort WARNING (instead of letting it leak into Pester output) and
        # assert it — turning the warning into a real behavioral check that the timeout path was hit.
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld3' -Backend $fake -WorkloadTimeoutSeconds 0 -DepsDiskPath (Join-Path $TestDrive 'd3.vhdx') -WarningVariable wv -WarningAction SilentlyContinue
        $r.Status | Should -Be 'Failed'
        $r.WholeImageHash | Should -BeNullOrEmpty
        (@($wv) -join "`n") | Should -Match 'did not power off' -Because 'the timeout path must emit the lifecycle-abort warning'
    }

    It 'a non-builder profile (EgressMode != SquidSniProxy) is refused' {
        { Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/firefox.psd1" -Backend (New-FakeHyperVBackend) } |
            Should -Throw -ExpectedMessage '*builder*'
    }
}

# ===========================================================================
#  Teardown — deps.vhdx persists (M2), other disks are removed
# ===========================================================================
Describe 'Invoke-BuilderVM — teardown removes the VM (no orphan), on success and timeout' {

    It 'the VM is removed after a successful builder run (no orphan)' {
        $blob = [byte[]](1..16)
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob $blob
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-teardown' -Backend $fake -DepsDiskPath (Join-Path $TestDrive 'deps-td.vhdx')
        $r.Status | Should -Be 'Success'
        (& $fake.GetVM @{ Name = 'bld-teardown' }) | Should -BeNullOrEmpty -Because 'the builder VM is removed at teardown'
    }

    It 'the VM is removed after a timed-out builder run (no orphan)' {
        $fake = New-FakeHyperVBackend -SimulateNeverOff
        # TR-3: capture + assert the lifecycle-abort warning (no leak into Pester output).
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-timeout-td' -Backend $fake -WorkloadTimeoutSeconds 0 -DepsDiskPath (Join-Path $TestDrive 'deps-t2.vhdx') -WarningVariable wv -WarningAction SilentlyContinue
        $r.Status | Should -Be 'Failed'
        (@($wv) -join "`n") | Should -Match 'did not power off' -Because 'the timeout path must emit the lifecycle-abort warning'
        (& $fake.GetVM @{ Name = 'bld-timeout-td' }) | Should -BeNullOrEmpty -Because 'the builder VM is removed even on a timeout'
    }
}

# ===========================================================================
#  No seal — the builder keeps its NIC + Squid egress
# ===========================================================================
Describe 'Invoke-BuilderVM — no seal (builder keeps NIC for the fetch)' {

    It 'the builder run does NOT call Lock-Sandbox (no NIC removal, no host-channel zeroing)' {
        $blob = [byte[]](1..8)
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob $blob
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-noseal' -Backend $fake -DepsDiskPath (Join-Path $TestDrive 'deps-ns.vhdx')
        $r.Status | Should -Be 'Success'
        # A sealed NoAdapter VM has its network adapter removed. The builder is a Tier-1 non-processor
        # that never seals and KEEPS its NIC.
        # The VM is torn down so we can't read it back, so assert via CallLog. Lock-Sandbox removes the
        # adapter unless the policy is IsolatedInternalSwitch, and the builder is a Tier-1 non-processor
        # (it keeps its NIC), so a zero count here ALONE does not prove Lock-Sandbox was never called: a
        # regression invoking Lock-Sandbox on this VM would still log zero RemoveNetworkAdapter entries.
        # SetHostChannel is Lock-Sandbox's UNCONDITIONAL op (every tier, every channel) and is what pins the claim.
        $removeNicCalls = @($fake.FakeCallLog | Where-Object { $_.Op -eq 'RemoveNetworkAdapter' })
        $removeNicCalls.Count | Should -Be 0 -Because 'a sealed NoAdapter VM would have its NIC removed; the builder is a Tier-1 non-processor that keeps its NIC, so this check alone does not discriminate Lock-Sandbox invocation'
        $setChannelCalls = @($fake.FakeCallLog | Where-Object { $_.Op -eq 'SetHostChannel' })
        $setChannelCalls.Count | Should -Be 0 -Because 'SetHostChannel is Lock-Sandbox''s unconditional op across every tier — zero entries is what actually proves Lock-Sandbox was never called'
    }

    It 'the builder run does NOT record a SealVerdict (SealVerdict is not a builder output)' {
        $blob = [byte[]](1..8)
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob $blob
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-nosealt' -Backend $fake -DepsDiskPath (Join-Path $TestDrive 'deps-nst.vhdx')
        # The Invoke-BuilderVM result hashtable has no SealVerdict key (a builder output, not a seal output).
        $r.ContainsKey('SealVerdict') | Should -BeFalse -Because 'SealVerdict is an Invoke-Voidseal concept; Invoke-BuilderVM does not produce a seal verdict'
    }
}

# ===========================================================================
#  AutomaticCheckpoints=OFF (RC7) — before StartVM
# ===========================================================================
Describe 'Invoke-BuilderVM — RC7: SetAutomaticCheckpoints called before StartVM' {

    It 'SetAutomaticCheckpoints(Enabled=$false) is applied before StartVM: the deps hash is non-empty (AutomaticCheckpoints=ON would hide the blob in a child .avhdx -> empty hash)' {
        # When AutomaticCheckpointsEnabled is still ON at StartVM, the fake routes the
        # DepsImageBlob into DepsImageChildLayer (the .avhdx child — inaccessible to GetVhdxImageHash,
        # which reads the base). So GetVhdxImageHash would return SHA256 of empty bytes, NOT the
        # blob's hash. If RC7 is applied (Enabled=$false) before StartVM, the blob goes into
        # DepsImageRegion (the base layer) and the hash matches the blob. So a non-empty/correct
        # hash here is the proof that AutomaticCheckpoints were OFF before StartVM.
        $blob = [byte[]](1..8)
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob $blob
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-rc7' -Backend $fake -DepsDiskPath (Join-Path $TestDrive 'deps-rc7.vhdx')
        $r.Status | Should -Be 'Success'
        # Compute the expected hash of the blob.
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $want = [System.BitConverter]::ToString($sha.ComputeHash($blob)).Replace('-','').ToLowerInvariant(); $sha.Dispose()
        $r.WholeImageHash | Should -Be $want -Because 'RC7 applied (AutomaticCheckpoints=OFF before StartVM): blob in base layer, hash matches'
        # Sanity: the hash of empty bytes is DIFFERENT — prove the non-trivial result.
        $emptyHash = [System.BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash([byte[]]::new(0))).Replace('-','').ToLowerInvariant()
        $r.WholeImageHash | Should -Not -Be $emptyHash -Because 'if AutomaticCheckpoints were ON the blob would be hidden in the child .avhdx -> hash would be of empty bytes'
    }
}

# ===========================================================================
#  Resolve-PythonExe unit test (fold-in #1)
# ===========================================================================
Describe 'Resolve-PythonExe — robust host python resolution (fold-in #1)' {

    BeforeAll {
        # The alias tests inject -CommandLookup, so they never read this machine's PATH. Each fake
        # match carries the fields Get-Command returns for an Application, although the resolver
        # reads only Source. Paths are listed per name in PATH order, as Get-Command -All yields them.
        function New-FakeCommandLookup {
            param([Parameter(Mandatory)] [hashtable] $PathsByName)
            $matchesByName = @{}
            foreach ($name in $PathsByName.Keys) {
                $matchesByName[$name] = @(foreach ($p in $PathsByName[$name]) {
                    [pscustomobject]@{
                        Name        = Split-Path -Leaf $p
                        CommandType = [System.Management.Automation.CommandTypes]::Application
                        Source      = $p
                        Path        = $p
                        Definition  = $p
                    }
                })
            }
            { param($Name) if ($matchesByName.ContainsKey($Name)) { $matchesByName[$Name] } }.GetNewClosure()
        }
        $script:AliasPython3 = 'C:\Users\operator\AppData\Local\Microsoft\WindowsApps\python3.exe'
        $script:AliasPython  = 'C:\Users\operator\AppData\Local\Microsoft\WindowsApps\python.exe'
        $script:RealPython   = 'C:\Program Files\Python314\python.exe'
    }

    It 'throws a clear fail-closed message naming both python3 and python when neither command resolves' {
        # Mock Get-Command to simulate neither python3 nor python being on PATH.
        # Resolve-PythonExe must throw, naming BOTH missing commands.
        Mock Get-Command {
            param($Name)
            $null  # simulating CommandNotFoundException-equivalent: returns $null
        }
        { Resolve-PythonExe } | Should -Throw -ExpectedMessage '*python3*'
        { Resolve-PythonExe } | Should -Throw -ExpectedMessage '*python*'
    }

    It 'skips a WindowsApps App Execution Alias for python3 and returns the first real python on PATH' {
        # The common Windows shape: python3 exists only as an alias, while python resolves to a real
        # install that sits ahead of its own alias.
        $lookup = New-FakeCommandLookup @{
            python3 = @($script:AliasPython3)
            python  = @($script:RealPython, $script:AliasPython)
        }
        Resolve-PythonExe -CommandLookup $lookup | Should -Be $script:RealPython
    }

    It 'still prefers python3: a real python3 later on PATH wins over the alias ahead of it' {
        $realPython3 = 'C:\Tools\Python\python3.exe'
        $lookup = New-FakeCommandLookup @{
            python3 = @($script:AliasPython3, $realPython3)
            python  = @($script:RealPython)
        }
        Resolve-PythonExe -CommandLookup $lookup | Should -Be $realPython3
    }

    It 'recognizes the alias directory in any letter case, under a relocated profile, and in a package subfolder' {
        $lookup = New-FakeCommandLookup @{
            python3 = @(
                'D:\Profiles\operator\AppData\Local\MICROSOFT\windowsapps\python3.exe',
                'C:\Users\operator\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\python3.exe'
            )
            python  = @($script:RealPython)
        }
        Resolve-PythonExe -CommandLookup $lookup | Should -Be $script:RealPython
    }

    It 'does not skip a real interpreter whose directory only resembles the alias directory' {
        $lookAlike = 'C:\Tools\Microsoft\WindowsAppsTools\python3.exe'
        $lookup = New-FakeCommandLookup @{ python3 = @($lookAlike); python = @($script:RealPython) }
        Resolve-PythonExe -CommandLookup $lookup | Should -Be $lookAlike
    }

    It 'fails closed when PATH offers only aliases, naming both commands and each alias it skipped' {
        $lookup = New-FakeCommandLookup @{ python3 = @($script:AliasPython3); python = @($script:AliasPython) }
        $err = { Resolve-PythonExe -CommandLookup $lookup } | Should -Throw -PassThru
        $err.Exception.Message | Should -BeLike "*'python3'*'python'*"
        $err.Exception.Message | Should -BeLike "*$($script:AliasPython3)*" -Because 'the operator needs to see which alias was refused'
        $err.Exception.Message | Should -BeLike "*$($script:AliasPython)*"
    }

    It 'skips a .bat shim that sits ahead of a real .exe and returns the .exe' {
        # Get-Command -CommandType Application matches any PATHEXT file; a shim runs through cmd.exe.
        $lookup = New-FakeCommandLookup @{
            python3 = @('C:\Tools\shims\python3.bat')
            python  = @('C:\Tools\shims\python.cmd', $script:RealPython)
        }
        Resolve-PythonExe -CommandLookup $lookup | Should -Be $script:RealPython
    }

    It 'skips a shim in any extension case and prefers a later real python3.exe' {
        $realPython3 = 'C:\Tools\Python\python3.exe'
        $lookup = New-FakeCommandLookup @{
            python3 = @('C:\Tools\shims\python3.BAT', $realPython3)
            python  = @($script:RealPython)
        }
        Resolve-PythonExe -CommandLookup $lookup | Should -Be $realPython3
    }

    It 'fails closed when PATH offers only shims, naming each shim it skipped' {
        $lookup = New-FakeCommandLookup @{
            python3 = @('C:\Tools\shims\python3.bat')
            python  = @('C:\Tools\shims\python.cmd')
        }
        $err = { Resolve-PythonExe -CommandLookup $lookup } | Should -Throw -PassThru
        $err.Exception.Message | Should -BeLike "*'python3'*'python'*"
        $err.Exception.Message | Should -BeLike '*C:\Tools\shims\python3.bat*' -Because 'the operator needs to see which shim was refused'
        $err.Exception.Message | Should -BeLike '*C:\Tools\shims\python.cmd*'
    }

    It 'names both skipped aliases and skipped shims when PATH offers nothing else' {
        $lookup = New-FakeCommandLookup @{
            python3 = @($script:AliasPython3)
            python  = @('C:\Tools\shims\python.bat')
        }
        $err = { Resolve-PythonExe -CommandLookup $lookup } | Should -Throw -PassThru
        $err.Exception.Message | Should -BeLike "*$($script:AliasPython3)*"
        $err.Exception.Message | Should -BeLike '*C:\Tools\shims\python.bat*'
    }

    It 'by default asks Get-Command for every Application match, so a real python behind an alias is reachable' {
        # Without -All, Get-Command stops at the first match on PATH; when that match is an alias, a
        # real interpreter further down would never be seen.
        Mock Get-Command { }
        Mock Get-Command {
            [pscustomobject]@{
                Name        = 'python.exe'
                CommandType = [System.Management.Automation.CommandTypes]::Application
                Source      = $script:RealPython
                Path        = $script:RealPython
                Definition  = $script:RealPython
            }
        } -ParameterFilter {
            $Name -eq 'python' -and $All -and $CommandType -eq [System.Management.Automation.CommandTypes]::Application
        }
        Resolve-PythonExe | Should -Be $script:RealPython
    }
}

# ===========================================================================
#  -HostMemoryMarginBytes reaches the provisioner's free-RAM gate (E1)
# ===========================================================================
Describe 'Invoke-BuilderVM - passes -HostMemoryMarginBytes to the provisioner (E1)' {

    It 'a margin the host cannot meet fails the run before anything is created' {
        $b = New-FakeHyperVBackend
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-margin' `
            -HostMemoryMarginBytes 100GB -Backend $b -WarningAction SilentlyContinue
        $r.Status | Should -Be 'Failed'
        $r.Error  | Should -Match '(?i)free memory'
        (& $b.GetVM @{ Name = 'bld-margin' }) | Should -BeNullOrEmpty
    }
}

# ===========================================================================
#  -StorageRoot covers the builder's disks (E2)
# ===========================================================================
Describe 'Invoke-BuilderVM - honors -StorageRoot (E2)' {

    BeforeEach { $script:SavedRoot = $env:VOIDSEAL_STORAGE_ROOT; $env:VOIDSEAL_STORAGE_ROOT = $null }
    AfterEach  { $env:VOIDSEAL_STORAGE_ROOT = $script:SavedRoot }

    BeforeAll {
        function script:New-DiskPathRecorder {
            $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..8))
            $made = [System.Collections.Generic.List[string]]::new()
            $origVhd = $b.NewVHD; $origOut = $b.NewOutputVhdx
            $b.NewVHD        = { param($P) $made.Add([string]$P.Path); & $origVhd $P }.GetNewClosure()
            $b.NewOutputVhdx = { param($P) $made.Add([string]$P.Path); & $origOut $P }.GetNewClosure()
            $b['Made'] = $made
            return $b
        }
    }

    It 'creates every disk (system, input, output, verdict, seed) under the per-VM folder below -StorageRoot' {
        $b = script:New-DiskPathRecorder
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-root' -StorageRoot 'D:\vs-bld' `
            -Backend $b -DepsDiskPath (Join-Path $TestDrive 'deps-root.vhdx')
        $r.Status | Should -Be 'Success'
        $dir = Join-Path 'D:\vs-bld' 'bld-root'
        $b.Made.Count | Should -BeGreaterThan 4
        @($b.Made | Where-Object { $_ -like '*-verdict.vhdx' }).Count | Should -Be 1
        foreach ($p in $b.Made) { $p | Should -BeLike "$dir*" }
    }

    It 'honors VOIDSEAL_STORAGE_ROOT when the parameter is omitted' {
        $env:VOIDSEAL_STORAGE_ROOT = 'D:\vs-bld-env'
        $b = script:New-DiskPathRecorder
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-root-env' `
            -Backend $b -DepsDiskPath (Join-Path $TestDrive 'deps-root-env.vhdx')
        $r.Status | Should -Be 'Success'
        foreach ($p in $b.Made) { $p | Should -BeLike (Join-Path 'D:\vs-bld-env' 'bld-root-env*') }
    }

    It 'a relative -StorageRoot is refused before anything is created' {
        $b = New-FakeHyperVBackend
        { Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-root-bad' -StorageRoot 'relative\dir' -Backend $b } |
            Should -Throw -ExpectedMessage '*absolute local path*'
        (& $b.GetVM @{ Name = 'bld-root-bad' }) | Should -BeNullOrEmpty
    }
}

# ===========================================================================
#  WorkloadTimeoutSeconds: explicit parameter > profile key > 600 (E3)
# ===========================================================================
Describe 'Invoke-BuilderVM - the deadline comes from -WorkloadTimeoutSeconds, then the profile, then 600 (E3)' {

    BeforeAll {
        function script:New-BuilderProfileWithTimeout {
            param($Timeout)
            $p = @{} + (Import-WorkloadProfile -Path "$script:SkillRoot/profiles/builder.psd1" -TierProfileDir "$script:SkillRoot/tier-profiles")
            if ($null -ne $Timeout) { $p['WorkloadTimeoutSeconds'] = $Timeout }
            return $p
        }
    }
    BeforeEach { Mock Wait-WorkloadComplete { @{ State = 'Off'; TimedOut = $false } } }

    It 'uses the profile key when the parameter is not given' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..8))
        $null = Invoke-BuilderVM -Profile (script:New-BuilderProfileWithTimeout -Timeout 3600) -Name 'bld-to-prof' -Backend $b `
            -DepsDiskPath (Join-Path $TestDrive 'to-prof.vhdx')
        Should -Invoke Wait-WorkloadComplete -Times 1 -Exactly -ParameterFilter { $TimeoutSeconds -eq 3600 }
    }

    It 'an explicit parameter beats the profile key' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..8))
        $null = Invoke-BuilderVM -Profile (script:New-BuilderProfileWithTimeout -Timeout 3600) -Name 'bld-to-exp' -Backend $b `
            -WorkloadTimeoutSeconds 0 -DepsDiskPath (Join-Path $TestDrive 'to-exp.vhdx')
        Should -Invoke Wait-WorkloadComplete -Times 1 -Exactly -ParameterFilter { $TimeoutSeconds -eq 0 }
    }

    It 'falls back to 600 when neither is given' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..8))
        $null = Invoke-BuilderVM -Profile (script:New-BuilderProfileWithTimeout -Timeout $null) -Name 'bld-to-def' -Backend $b `
            -DepsDiskPath (Join-Path $TestDrive 'to-def.vhdx')
        Should -Invoke Wait-WorkloadComplete -Times 1 -Exactly -ParameterFilter { $TimeoutSeconds -eq 600 }
    }
}

# ===========================================================================
#  Verdict: Success needs the verdict's exit code to read exactly 0 and the manifest present (E7)
# ===========================================================================
Describe 'Invoke-BuilderVM - the verdict comes from the raw verdict disk (exit code and manifest), not from a clean power-off (E7)' {

    BeforeAll {
        # One builder run on a fake whose guest powers off after packing exactly $Files (or the raw $Blob)
        # into its raw verdict disk. Neither given = the guest packed nothing (the disk stays zeros).
        function script:Invoke-VerdictRun {
            param([string] $Name, [hashtable] $Files, [byte[]] $Blob, [hashtable] $FakeExtra = @{})
            $fakeArgs = @{ SimulateSelfPowerOff = $true; SimulateDepsImageBlob = [byte[]](1..16) } + $FakeExtra
            if ($null -ne $Blob) { $fakeArgs.SimulateVerdictBlob = $Blob }
            elseif ($null -ne $Files) { $fakeArgs.SimulateVerdictBlob = (script:New-VerdictBlob $Files) }
            $b = New-FakeHyperVBackend @fakeArgs
            $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name $Name -Backend $b `
                -DepsDiskPath (Join-Path $TestDrive "$Name.vhdx") -WarningAction SilentlyContinue
            return @{ Result = $r; Backend = $b; Name = $Name }
        }
        # A failed verdict must emit nothing and must not have moved or hashed the disk.
        function script:Assert-NoArtifact {
            param($Run)
            $Run.Result.Status          | Should -Be 'FetchFailed'
            $Run.Result.DepsDiskPath    | Should -BeNullOrEmpty
            $Run.Result.DepsImageHash   | Should -BeNullOrEmpty
            $Run.Result.WholeImageHash  | Should -BeNullOrEmpty
            @($Run.Backend.FakeCallLog | Where-Object { $_.Op -in @('MoveVhdxFile', 'GetVhdxImageHash') }).Count | Should -Be 0
            (& $Run.Backend.GetVM @{ Name = $Run.Name }) | Should -BeNullOrEmpty -Because 'teardown still removes the VM'
        }
    }

    It 'exit code 0 with the manifest present is Success and reports ExitCode 0' {
        $run = script:Invoke-VerdictRun -Name 'bld-v-ok' -Files @{ 'result.exitcode' = '0'; 'deps-manifest.json' = '{"files":[]}' }
        $run.Result.Status   | Should -Be 'Success'
        $run.Result.ExitCode | Should -Be 0
        $run.Result.Error    | Should -BeNullOrEmpty
        @($run.Result.States) | Should -Contain 'VERDICT'
    }

    It 'surrounding whitespace on the exit code is ignored (the runner writes no newline, an editor might)' {
        $run = script:Invoke-VerdictRun -Name 'bld-v-ws' -Files @{ 'result.exitcode' = " 0`n"; 'deps-manifest.json' = '{"files":[]}' }
        $run.Result.Status | Should -Be 'Success'
    }

    It 'a guest that packed no verdict at all is FetchFailed, even though it powered off cleanly' {
        $run = script:Invoke-VerdictRun -Name 'bld-v-none'
        script:Assert-NoArtifact $run
        $run.Result.ExitCode | Should -BeNullOrEmpty
        $run.Result.Error    | Should -Match 'no valid verdict outbox'
    }

    It 'a verdict outbox without an exit-code entry is FetchFailed' {
        $run = script:Invoke-VerdictRun -Name 'bld-v-noexit' -Files @{ 'deps-manifest.json' = '{"files":[]}' }
        script:Assert-NoArtifact $run
        $run.Result.ExitCode | Should -BeNullOrEmpty
        $run.Result.Error    | Should -Match "no 'result.exitcode' entry"
    }

    It 'a non-zero exit code is FetchFailed and is reported' {
        $run = script:Invoke-VerdictRun -Name 'bld-v-rc2' -Files @{ 'result.exitcode' = '2'; 'deps-manifest.json' = '{"files":[]}' }
        script:Assert-NoArtifact $run
        $run.Result.ExitCode | Should -Be 2
        $run.Result.Error    | Should -Match 'exit code 2'
    }

    It 'a large code such as 70 is just another non-zero exit code, so FetchFailed' {
        $run = script:Invoke-VerdictRun -Name 'bld-v-rc70' -Files @{ 'result.exitcode' = '70' }
        script:Assert-NoArtifact $run
        $run.Result.ExitCode | Should -Be 70
    }

    It 'content that is not a plain exit code is FetchFailed, and the reason does not repeat the content' -ForEach @(
        @{ Content = 'not-a-number' }, @{ Content = '00' }, @{ Content = '0x0' }, @{ Content = '+0' }, @{ Content = '-1' },
        @{ Content = '0 1' }, @{ Content = '1.0' }, @{ Content = '' }, @{ Content = '   ' }, @{ Content = '99999999999' },
        @{ Content = ('secret-looking-' + ('x' * 40)) }
    ) {
        $name = 'bld-v-junk{0}' -f ([guid]::NewGuid().ToString('N').Substring(0, 6))
        $run = script:Invoke-VerdictRun -Name $name -Files @{ 'result.exitcode' = $Content; 'deps-manifest.json' = '{"files":[]}' }
        script:Assert-NoArtifact $run
        $run.Result.Error | Should -Match 'not a plain exit code'
        if ($Content.Trim().Length -gt 3) { $run.Result.Error | Should -Not -BeLike "*$($Content.Trim())*" }
    }

    It 'exit code 0 but no manifest (or a blank one) is FetchFailed' -ForEach @(
        @{ Case = 'absent'; Files = @{ 'result.exitcode' = '0' } },
        @{ Case = 'blank';  Files = @{ 'result.exitcode' = '0'; 'deps-manifest.json' = "  `n" } },
        @{ Case = 'empty';  Files = @{ 'result.exitcode' = '0'; 'deps-manifest.json' = '' } }
    ) {
        $name = "bld-v-nm-$Case"
        $run = script:Invoke-VerdictRun -Name $name -Files $Files
        script:Assert-NoArtifact $run
        $run.Result.ExitCode | Should -Be 0
        $run.Result.Error    | Should -Match 'deps-manifest.json'
    }

    It 'a container that fails its checks is FetchFailed with a fixed reason (garbage, a flipped payload byte, a truncated blob)' -ForEach @(
        @{ Case = 'garbage';   Mutate = { [byte[]](1..96) } }
        @{ Case = 'flipped';   Mutate = { param($b) $c = [byte[]]$b.Clone(); $c[$c.Length - 1] = $c[$c.Length - 1] -bxor 0xFF; $c } }
        @{ Case = 'truncated'; Mutate = { param($b) [byte[]]$b[0..($b.Length - 5)] } }
    ) {
        $good = script:New-VerdictBlob @{ 'result.exitcode' = '0'; 'deps-manifest.json' = '{"files":[]}' }
        $blob = [byte[]](& $Mutate $good)
        $run = script:Invoke-VerdictRun -Name "bld-v-bad-$Case" -Blob $blob
        script:Assert-NoArtifact $run
        $run.Result.Error | Should -Match 'no valid verdict outbox'
        $run.Result.Error | Should -Not -Match '(?i)sha256|tamper|OutboxError|magic' -Because 'the reason never relays the reader''s own text'
    }

    It 'a failed fetch deletes the verdict and OUTPUT disks with the rest of the sandbox (nothing durable is left)' {
        $run = script:Invoke-VerdictRun -Name 'bld-v-clean' -Files @{ 'result.exitcode' = '2' }
        $detached = @($run.Backend.FakeCallLog | Where-Object { $_.Op -eq 'RemoveHardDiskDrive' } | ForEach-Object { $_.Path } | Select-Object -Unique)
        @($detached | Where-Object { $_ -like '*-verdict.vhdx' }).Count | Should -Be 1
        @($detached | Where-Object { $_ -like '*-output.vhdx' }).Count  | Should -Be 1
        foreach ($p in $detached) { (& $run.Backend.GetVHDInfo @{ Path = $p }) | Should -BeNullOrEmpty -Because "$p is a run-created disk" }
        (Test-Path -LiteralPath (Join-Path $TestDrive 'bld-v-clean.vhdx')) | Should -BeFalse
    }

    It 'a timeout stays Status=Failed (a lifecycle failure), not FetchFailed, and a hung guest''s disks are never read' {
        $b = New-FakeHyperVBackend -SimulateNeverOff
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-v-to' -Backend $b -WorkloadTimeoutSeconds 0 `
            -DepsDiskPath (Join-Path $TestDrive 'bld-v-to.vhdx') -WarningAction SilentlyContinue
        $r.Status | Should -Be 'Failed'
        @($b.FakeCallLog | Where-Object { $_.Op -in @('ReadVhdxFile', 'ReadVhdxFileBytes', 'ReadVhdxRawRegion') }).Count | Should -Be 0
    }

    It 'a host-side read failure (the verdict disk stays locked) is Failed, never a guessed FetchFailed or Success' {
        $run = script:Invoke-VerdictRun -Name 'bld-v-locked' -Files @{ 'result.exitcode' = '0'; 'deps-manifest.json' = '{}' } -FakeExtra @{ SimulateDetachSettleLag = 99 }
        $run.Result.Status | Should -Be 'Failed'
        $run.Result.Error  | Should -Match '(?i)still locked'
        $run.Result.DepsDiskPath | Should -BeNullOrEmpty
        @($run.Backend.FakeCallLog | Where-Object { $_.Op -in @('MoveVhdxFile', 'GetVhdxImageHash') }).Count | Should -Be 0
    }

    It 'the verdict is read after both detaches and before the move and the hash' {
        $run = script:Invoke-VerdictRun -Name 'bld-v-order' -Blob $script:BuilderOkBlob
        $log = @($run.Backend.FakeCallLog)
        $ops = @($log | Where-Object { $_.Op -in @('RemoveHardDiskDrive', 'ReadVhdxRawRegion', 'MoveVhdxFile', 'GetVhdxImageHash') } | ForEach-Object { $_.Op })
        foreach ($op in 'RemoveHardDiskDrive', 'ReadVhdxRawRegion', 'MoveVhdxFile', 'GetVhdxImageHash') { $ops | Should -Contain $op }
        $ops.LastIndexOf('RemoveHardDiskDrive') | Should -BeLessThan $ops.IndexOf('ReadVhdxRawRegion')
        $ops.LastIndexOf('ReadVhdxRawRegion')   | Should -BeLessThan $ops.IndexOf('MoveVhdxFile')
        $ops.IndexOf('MoveVhdxFile')            | Should -BeLessThan $ops.IndexOf('GetVhdxImageHash')
        @($log | Where-Object { $_.Op -eq 'RemoveHardDiskDrive' } | ForEach-Object { $_.Path } | Select-Object -Unique).Count |
            Should -BeGreaterOrEqual 2 -Because 'the deps disk and the verdict disk are both detached before any read'
    }

    It 'the host never mounts or file-reads a guest-written disk: no ReadVhdxFile or ReadVhdxFileBytes, and the only raw reads are of the verdict disk' -ForEach @(
        @{ Case = 'success';        Files = @{ 'result.exitcode' = '0'; 'deps-manifest.json' = '{"files":[]}' } }
        @{ Case = 'nonzero';        Files = @{ 'result.exitcode' = '2' } }
        @{ Case = 'no verdict';     Files = $null }
    ) {
        $run = script:Invoke-VerdictRun -Name ('bld-v-nomount-' + ($Case -replace '\W', '')) -Files $Files
        $log = @($run.Backend.FakeCallLog)
        @($log | Where-Object { $_.Op -in @('ReadVhdxFile', 'ReadVhdxFileBytes') }).Count | Should -Be 0 -Because 'both are a read-write Mount-VHD of a guest-written volume'
        $raw = @($log | Where-Object { $_.Op -eq 'ReadVhdxRawRegion' })
        $raw.Count | Should -BeGreaterThan 0
        foreach ($r in $raw) { $r.Path | Should -BeLike '*-verdict.vhdx' -Because 'the deps (OUTPUT) disk is never read by the host' }
        # The host does write the INPUT and seed disks (it formats them), but it writes nothing to the verdict
        # or deps disk, which carry only what the guest puts there.
        foreach ($w in @($log | Where-Object { $_.Op -eq 'WriteVhdxFile' })) { $w.Path | Should -Not -BeLike '*-verdict.vhdx'; $w.Path | Should -Not -BeLike '*-output.vhdx' }
    }
}

Describe 'Read-BuilderVerdict (the host read of the guest verdict, in isolation)' {

    BeforeAll {
        # A powered-off VM that "wrote" $Blob (or nothing) into its raw VERDICT disk, which is then detached:
        # the state Read-BuilderVerdict gets at the end of a run.
        function script:New-VerdictDisk {
            param([byte[]] $Blob, [switch] $LeaveAttached)
            $fakeArgs = @{ SimulateSelfPowerOff = $true }
            if ($null -ne $Blob) { $fakeArgs.SimulateVerdictBlob = $Blob }
            $b = New-FakeHyperVBackend @fakeArgs
            & $b.NewVM @{ Name = 'v1'; MemoryStartupBytes = 512MB }
            & $b.NewOutputVhdx @{ Path = 'C:\v\verdict.vhdx'; Label = 'VERDICT'; FileSystem = 'Raw'; SizeBytes = $script:BuilderVerdictDiskBytes }
            & $b.AddHardDiskDrive @{ VMName = 'v1'; Path = 'C:\v\verdict.vhdx' }
            & $b.SetAutomaticCheckpoints @{ VMName = 'v1'; Enabled = $false }   # as the builder does (RC7)
            & $b.StartVM @{ Name = 'v1' }
            if (-not $LeaveAttached) { & $b.RemoveHardDiskDrive @{ VMName = 'v1'; Path = 'C:\v\verdict.vhdx' } }
            return $b
        }
        function script:Get-VerdictTempDirs { @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter 'voidseal-verdict-*' -ErrorAction SilentlyContinue) }
    }

    It 'is Ok only for exactly 0 plus a non-empty manifest' {
        $b = script:New-VerdictDisk -Blob (script:New-VerdictBlob @{ 'result.exitcode' = '0'; 'deps-manifest.json' = '{}' })
        $v = Read-BuilderVerdict -VerdictDiskPath 'C:\v\verdict.vhdx' -Backend $b
        $v.Ok | Should -BeTrue
        $v.ExitCode | Should -Be 0
        $v.ManifestPresent | Should -BeTrue
        $v.Reason | Should -BeNullOrEmpty
    }

    It 'a non-zero exit code is not ok, whatever the manifest says' {
        $b = script:New-VerdictDisk -Blob (script:New-VerdictBlob @{ 'result.exitcode' = '3'; 'deps-manifest.json' = '{}' })
        $v = Read-BuilderVerdict -VerdictDiskPath 'C:\v\verdict.vhdx' -Backend $b
        $v.Ok | Should -BeFalse
        $v.ExitCode | Should -Be 3
        $v.ManifestPresent | Should -BeFalse
    }

    It 'a disk the guest never wrote to (all zeros) is not ok, with a fixed reason' {
        $b = script:New-VerdictDisk
        $v = Read-BuilderVerdict -VerdictDiskPath 'C:\v\verdict.vhdx' -Backend $b
        $v.Ok | Should -BeFalse
        $v.ExitCode | Should -BeNullOrEmpty
        $v.Reason | Should -Match 'no valid verdict outbox'
    }

    It 'reads only the verdict disk, only in user space: raw region reads, no file read, no write' {
        $b = script:New-VerdictDisk -Blob $script:BuilderOkBlob
        $null = Read-BuilderVerdict -VerdictDiskPath 'C:\v\verdict.vhdx' -Backend $b
        $ops = @($b.FakeCallLog | Where-Object { $_.Op -match '^(Read|Write|Mount)' } | ForEach-Object { $_.Op } | Select-Object -Unique)
        $ops.Count | Should -Be 1
        $ops[0] | Should -Be 'ReadVhdxRawRegion'
    }

    It 'a read failure propagates (fail-closed: the run becomes Failed, never a guessed verdict)' {
        $b = New-FakeHyperVBackend
        { Read-BuilderVerdict -VerdictDiskPath 'C:\v\missing.vhdx' -Backend $b } | Should -Throw -ExpectedMessage '*does not exist*'
    }

    It 'a disk still attached to a running VM propagates the lock error instead of reading it' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob
        & $b.NewVM @{ Name = 'v1'; MemoryStartupBytes = 512MB }
        & $b.NewOutputVhdx @{ Path = 'C:\v\verdict.vhdx'; Label = 'VERDICT'; FileSystem = 'Raw'; SizeBytes = $script:BuilderVerdictDiskBytes }
        & $b.AddHardDiskDrive @{ VMName = 'v1'; Path = 'C:\v\verdict.vhdx' }
        $vm = & $b.GetVM @{ Name = 'v1' }
        $vm.State = 'Running'
        { Read-BuilderVerdict -VerdictDiskPath 'C:\v\verdict.vhdx' -Backend $b } | Should -Throw -ExpectedMessage '*locked*'
    }

    It 'removes its private temp folder, on a good verdict, a bad one, and a failed read' {
        $before = @(script:Get-VerdictTempDirs).Count
        $ok  = script:New-VerdictDisk -Blob $script:BuilderOkBlob
        $bad = script:New-VerdictDisk -Blob ([byte[]](1..96))
        $null = Read-BuilderVerdict -VerdictDiskPath 'C:\v\verdict.vhdx' -Backend $ok
        $null = Read-BuilderVerdict -VerdictDiskPath 'C:\v\verdict.vhdx' -Backend $bad
        { Read-BuilderVerdict -VerdictDiskPath 'C:\v\missing.vhdx' -Backend $ok } | Should -Throw
        @(script:Get-VerdictTempDirs).Count | Should -Be $before
    }

    It 'with -WorkDir the caller owns the folder: the parsed entries land there and are left in place' {
        $b = script:New-VerdictDisk -Blob $script:BuilderOkBlob
        $dir = Join-Path $TestDrive 'verdict-work'
        $null = Read-BuilderVerdict -VerdictDiskPath 'C:\v\verdict.vhdx' -Backend $b -WorkDir $dir
        Test-Path -LiteralPath (Join-Path $dir 'gate-input/staging/result.exitcode') | Should -BeTrue
    }
}

Describe 'The raw verdict disk (New-BuilderVerdictDisk)' {

    It 'is sized to the outbox bounds: the largest container guest/outbox.py allows fits, rounded up to a whole MiB' {
        $py = Resolve-PythonExe
        $facts = & $py -c "import sys; sys.path.insert(0, r'$($script:SkillRoot)/guest'); import outbox; print(outbox.MAX_ENTRIES, outbox.MAX_TOTAL, outbox._HEADER.size, outbox._REC.size)"
        $e, $t, $h, $r = [long[]]($facts -split ' ')
        $maxBlob = $h + $e * $r + $t
        $script:BuilderVerdictDiskBytes | Should -BeGreaterOrEqual $maxBlob
        $script:BuilderVerdictDiskBytes | Should -BeLessThan ($maxBlob + 1MB) -Because 'the size is the bound rounded up, not a larger guess'
        ($script:BuilderVerdictDiskBytes % 1MB) | Should -Be 0
    }

    It 'is created Raw (no partition table, no file system), labelled VERDICT, attached, and recorded as a run-created disk' {
        $b = New-FakeHyperVBackend
        $d = New-SandboxDescriptor -Name 'vd1' -Tier 1 -CreatedDisks @('C:\s\vd1.vhdx')
        & $b.NewVM @{ Name = 'vd1'; MemoryStartupBytes = 512MB }
        $d = New-BuilderVerdictDisk -Descriptor $d -StorageRoot 'C:\s\vd1' -Backend $b
        $path = Join-Path 'C:\s\vd1' 'vd1-verdict.vhdx'
        $d.VerdictDiskPath | Should -Be $path
        @($d.CreatedDisks) | Should -Contain $path
        @($d.CreatedDisks) | Should -Contain 'C:\s\vd1.vhdx' -Because 'the earlier entries are kept'
        $info = & $b.GetVHDInfo @{ Path = $path }
        $info.SizeBytes | Should -Be $script:BuilderVerdictDiskBytes
        $info.FileSystem | Should -Be 'Raw'
        $info.Label | Should -Be 'VERDICT'
        @((& $b.GetVM @{ Name = 'vd1' }).HardDrives) | Should -Contain $path
    }

    It 'records the disk before attaching it, so a failed attach still leaves it on CreatedDisks for teardown' {
        $b = New-FakeHyperVBackend
        $b.AddHardDiskDrive = { param($P) throw 'simulated attach failure' }.GetNewClosure()
        $d = New-SandboxDescriptor -Name 'vd2' -Tier 1
        { New-BuilderVerdictDisk -Descriptor $d -StorageRoot 'C:\s\vd2' -Backend $b } | Should -Throw -ExpectedMessage '*simulated attach failure*'
        @($d.CreatedDisks) | Should -Contain (Join-Path 'C:\s\vd2' 'vd2-verdict.vhdx')
        $d.VerdictDiskPath | Should -Be (Join-Path 'C:\s\vd2' 'vd2-verdict.vhdx')
    }

    It 'a builder run attaches it beside the deps disk, counts it in the free-space budget, and deletes it at teardown' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..8))
        $attached = [System.Collections.Generic.List[string]]::new()
        $realAdd = $b.AddHardDiskDrive
        $b.AddHardDiskDrive = { param($P) $attached.Add([string]$P.Path); & $realAdd $P }.GetNewClosure()
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-vd' -Backend $b -DepsDiskPath (Join-Path $TestDrive 'bld-vd.vhdx')
        $r.Status | Should -Be 'Success'
        $verdict = @($attached | Where-Object { $_ -like '*-verdict.vhdx' })
        $verdict.Count | Should -Be 1
        @($attached | Where-Object { $_ -like '*-output.vhdx' }).Count | Should -Be 1
        (& $b.GetVHDInfo @{ Path = $verdict[0] }) | Should -BeNullOrEmpty -Because 'the verdict disk is a run-created disk and teardown deletes it'
    }

    It 'the free-space preflight budgets the verdict disk with the INPUT and OUTPUT disks' {
        Mock Test-HostFreeSpace { }
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..8))
        $null = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-vd-space' -Backend $b -DepsDiskPath (Join-Path $TestDrive 'bld-vd-space.vhdx')
        $want = 2GB + $script:BuilderVerdictDiskBytes   # the builder profile leaves INPUT and OUTPUT at the 1GB default
        Should -Invoke Test-HostFreeSpace -ParameterFilter { $RequiredBytes -eq $want } -Times 1 -Exactly
    }

    It 'seeds the verdict producer (run_disk_workload.py and outbox.py) onto the INPUT disk beside the runner, byte for byte' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..8))
        $null = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-vd-in' -Backend $b -DepsDiskPath (Join-Path $TestDrive 'bld-vd-in.vhdx')
        $written = @($b.FakeCallLog | Where-Object { $_.Op -eq 'WriteVhdxFile' -and $_.Path -like '*-input.vhdx' })
        foreach ($name in 'fetch_deps.py', 'deps-spec.json', 'run_disk_workload.py', 'outbox.py') {
            @($written | Where-Object { $_.InnerPath -eq $name }).Count | Should -Be 1 -Because "$name rides the INPUT disk"
        }
        foreach ($name in 'run_disk_workload.py', 'outbox.py') {
            $want = [System.IO.File]::ReadAllText((Join-Path $script:SkillRoot "guest/$name"))
            ($written | Where-Object { $_.InnerPath -eq $name }).Content | Should -BeExactly $want
        }
    }
}

Describe 'BuilderVM.ps1 never mounts or file-reads a guest-written disk (the C1 rule, pinned on the AST)' {

    BeforeAll {
        # Every string constant, command name and member name in $Ast that names a host-mount reader.
        function script:Find-HostMountReaders {
            param($Ast)
            $pattern = '^(ReadVhdxFile|ReadVhdxFileBytes|Mount-VHD|Mount-DiskImage)$'
            @($Ast.FindAll({ param($n)
                ($n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -match $pattern) -or
                ($n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -match $pattern)
            }, $true) | ForEach-Object { $_.Extent.Text })
        }
    }

    It 'the file contains no ReadVhdxFile, ReadVhdxFileBytes or Mount-VHD call, member, key or command' {
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:BVMPath, [ref]$tokens, [ref]$errs)
        @($errs).Count | Should -Be 0
        @(script:Find-HostMountReaders $ast) | Should -BeNullOrEmpty
    }

    It 'the detector is not vacuous: it sees each way of reaching a host-mount reader' -ForEach @(
        @{ Snippet = '& $Backend.ReadVhdxFile @{ Path = $p; InnerPath = "x" }' }
        @{ Snippet = '& $Backend.ReadVhdxFileBytes @{ Path = $p }' }
        @{ Snippet = '& $Backend[''ReadVhdxFile''] @{ Path = $p }' }
        @{ Snippet = 'Mount-VHD -Path $p' }
        @{ Snippet = '$m = ''Mount-VHD''; & $m $p' }
    ) {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($Snippet, [ref]$null, [ref]$null)
        @(script:Find-HostMountReaders $ast).Count | Should -BeGreaterThan 0
    }

    It 'the verdict path reaches the guest only through the shared user-space outbox reader' {
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:BVMPath, [ref]$tokens, [ref]$errs)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Read-BuilderVerdict' }, $true)
        $fn | Should -Not -BeNullOrEmpty
        $calls = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        $calls | Should -Contain 'Read-OutboxToGateInput'
    }
}

# ===========================================================================
#  deps.vhdx survives teardown (E7)
# ===========================================================================
Describe 'Invoke-BuilderVM - deps.vhdx is moved out of the sandbox folder and survives teardown (E7)' {

    BeforeEach { $script:SavedRoot2 = $env:VOIDSEAL_STORAGE_ROOT; $env:VOIDSEAL_STORAGE_ROOT = $null }
    AfterEach  { $env:VOIDSEAL_STORAGE_ROOT = $script:SavedRoot2 }

    BeforeAll {
        function script:New-GreenBuilderBackend { New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..32)) }
    }

    It 'the file lands in -DepsOutputDir, is hashed THERE, and is still present after teardown' {
        $b = script:New-GreenBuilderBackend
        $dir = Join-Path $TestDrive 'out-keep'
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-keep' -Backend $b -DepsOutputDir $dir
        $r.Status | Should -Be 'Success'
        $r.DepsDiskPath | Should -Be (Join-Path $dir 'deps-bld-keep.vhdx')
        (& $b.GetVHDInfo @{ Path = $r.DepsDiskPath }) | Should -Not -BeNullOrEmpty -Because 'teardown must not delete the moved deps disk'
        $r.DepsImageHash | Should -Be ([string](& $b.GetVhdxImageHash @{ Path = $r.DepsDiskPath }))
        $r.WholeImageHash | Should -Be $r.DepsImageHash
        $hashed = @($b.FakeCallLog | Where-Object { $_.Op -eq 'GetVhdxImageHash' })
        $hashed[0].Path | Should -Be $r.DepsDiskPath -Because 'the hash describes the moved file, which is what a consumer copies'
        @($r.States) | Should -Contain 'MOVED'
        @($r.States) | Should -Contain 'DESTROYED'
    }

    It 'the old OUTPUT path is gone (a move, not a copy) and no teardown delete ever names the new path' {
        $b = script:New-GreenBuilderBackend
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-mv' -Backend $b -DepsOutputDir (Join-Path $TestDrive 'out-mv')
        $mv = @($b.FakeCallLog | Where-Object { $_.Op -eq 'MoveVhdxFile' })
        $mv.Count | Should -Be 1
        $mv[0].Destination | Should -Be $r.DepsDiskPath
        (& $b.GetVHDInfo @{ Path = $mv[0].Path }) | Should -BeNullOrEmpty
        $deleted = @($b.FakeCallLog | Where-Object { $_.Op -eq 'RemoveVHD' } | ForEach-Object { $_.Path })
        $deleted | Should -Not -Contain $r.DepsDiskPath
        # The run's own disks (system, INPUT, seed) are gone; only the deps disk remains of its VHDs.
        (& $b.GetVHDInfo @{ Path = $mv[0].Path }) | Should -BeNullOrEmpty
    }

    It 'the default destination is the deps folder under the artifact root (the per-run temp artifact dir when -ArtifactRoot is not given)' {
        $b = script:New-GreenBuilderBackend
        $art = Join-Path $TestDrive 'art-root'
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-art' -Backend $b -ArtifactRoot $art
        $r.DepsDiskPath | Should -Be (Join-Path (Join-Path $art 'deps') 'deps-bld-art.vhdx')

        $b2 = script:New-GreenBuilderBackend
        $r2 = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-art2' -Backend $b2
        $r2.DepsDiskPath | Should -Be (Join-Path ([System.IO.Path]::GetTempPath()) 'Voidseal\artifacts\bld-art2\deps\deps-bld-art2.vhdx')
    }

    It '-DepsDiskPath names the exact file' {
        $b = script:New-GreenBuilderBackend
        $dest = Join-Path $TestDrive 'exact\my-deps.vhdx'
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-exact' -Backend $b -DepsDiskPath $dest
        $r.DepsDiskPath | Should -Be $dest
        (& $b.GetVHDInfo @{ Path = $dest }) | Should -Not -BeNullOrEmpty
    }

    It 'refuses a destination inside the storage root, lexically or through a junction, before anything is created' {
        $root = Join-Path $TestDrive 'sandboxes-e7'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $link = Join-Path $TestDrive 'link-e7'
        New-Item -ItemType Junction -Path $link -Target $root | Out-Null
        foreach ($dest in @((Join-Path $root 'keep\deps.vhdx'), (Join-Path $link 'keep\deps.vhdx'), (Join-Path $root 'deps.vhdx'))) {
            $b = New-FakeHyperVBackend
            { Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-inside' -StorageRoot $root -Backend $b -DepsDiskPath $dest } |
                Should -Throw -ExpectedMessage '*inside the sandbox storage root*'
            @($b.FakeCallLog).Count | Should -Be 0 -Because 'the refusal comes before any backend call'
        }
    }

    It 'a sibling folder that only shares the storage root prefix is allowed' {
        $root = Join-Path $TestDrive 'sandboxes-e7b'
        $b = script:New-GreenBuilderBackend
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-sib' -StorageRoot $root -Backend $b `
            -DepsOutputDir ($root + '-deps')
        $r.Status | Should -Be 'Success'
    }

    It 'refuses bad destinations before anything is created' -ForEach @(
        @{ Why = 'a relative directory';  Splat = @{ DepsOutputDir = 'relative\deps' };            Msg = '*absolute local path*' }
        @{ Why = 'a UNC directory';       Splat = @{ DepsOutputDir = '\\server\share\deps' };      Msg = '*absolute local path*' }
        @{ Why = 'a relative file';       Splat = @{ DepsDiskPath = 'deps.vhdx' };                 Msg = '*absolute local path*' }
        @{ Why = 'a non-vhdx file';       Splat = @{ DepsDiskPath = 'C:\keep\deps.img' };          Msg = '*must end in*vhdx*' }
        @{ Why = 'both parameters';       Splat = @{ DepsDiskPath = 'C:\keep\a.vhdx'; DepsOutputDir = 'C:\keep' }; Msg = '*alternatives*' }
    ) {
        $b = New-FakeHyperVBackend
        { Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-bad-dest' -Backend $b @Splat } |
            Should -Throw -ExpectedMessage $Msg
        @($b.FakeCallLog).Count | Should -Be 0
    }

    It 'refuses a destination that already exists, before the build, and leaves the old file alone' {
        $dir = Join-Path $TestDrive 'out-exists'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $old = Join-Path $dir 'deps-bld-exists.vhdx'
        Set-Content -LiteralPath $old -Value 'previous build'
        $b = New-FakeHyperVBackend
        { Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-exists' -Backend $b -DepsOutputDir $dir } |
            Should -Throw -ExpectedMessage '*already exists*'
        @($b.FakeCallLog).Count | Should -Be 0
        (Get-Content -LiteralPath $old -Raw).Trim() | Should -Be 'previous build'
    }

    It 'a hash that cannot be taken after the move fails the run and emits no artifact' {
        $b = script:New-GreenBuilderBackend
        $realHash = $b.GetVhdxImageHash
        $b.GetVhdxImageHash = { param($P) throw 'simulated hash failure' }.GetNewClosure()
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-nohash' -Backend $b `
            -DepsOutputDir (Join-Path $TestDrive 'out-nohash') -WarningAction SilentlyContinue
        $r.Status | Should -Be 'Failed'
        $r.DepsDiskPath | Should -BeNullOrEmpty
        $r.DepsImageHash | Should -BeNullOrEmpty
        $r.Error | Should -Match 'NOT verified'
    }
}

Describe 'A builder run feeds a later consumer run straight from its result (E7)' {

    BeforeAll {
        # A Disk-mode processor profile (Network=None, ScreenConfig): the kind of run that attaches a DEPS disk.
        $tierDir = Join-Path $script:SkillRoot 'tier-profiles'
        $fx = @{} + (Import-TierProfile -Path (Join-Path $tierDir 'tier0.psd1'))
        $fx['Name']         = 'e7-consumer'
        $fx['WorkloadMode'] = 'Disk'
        $fx['FileSystem']   = 'exFAT'
        $fx['Entrypoint']   = 'python3 /mnt/in/summarize.py --out /run/staging/result.html'
        $fx['Network']      = 'None'; $fx['EgressMode'] = 'None'; $fx['EgressAllowlist'] = @()
        $fx['ScreenConfig'] = @{ mode = 'aggressive' }
        $fx['Inputs']       = @{}
        foreach ($helper in @('run_disk_workload.py', 'outbox.py', 'screener.py')) {
            $fx['Inputs'][$helper] = Get-Content -LiteralPath (Join-Path $script:SkillRoot "guest/$helper") -Raw
        }
        $script:E7Consumer = $fx
    }

    It 'the processor attaches a verified working copy of the builder output, never the builder file itself' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..48))
        $attached = [System.Collections.Generic.List[string]]::new()
        $realAdd = $b.AddHardDiskDrive
        $b.AddHardDiskDrive = { param($P) $attached.Add([string]$P.Path); & $realAdd $P }.GetNewClosure()

        $built = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-e7' -Backend $b `
            -DepsOutputDir (Join-Path $TestDrive 'out-e7')
        $built.Status | Should -Be 'Success'

        $report = Invoke-Voidseal -Tier 0 -Profile $script:E7Consumer `
            -Workload @{ WorkloadMode = 'Disk'; DepsDiskPath = $built.DepsDiskPath; DepsImageHash = $built.DepsImageHash } `
            -Name 'sbx-e7' -ArtifactRoot (Join-Path $TestDrive 'art-e7') -Destination (Join-Path $TestDrive 'dest-e7') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b -RateLedgerPath (Join-Path $TestDrive 'ledger-e7.json') -WarningAction SilentlyContinue

        @($report.States) | Should -Contain 'SEALED'
        $copy = Join-Path (Get-SandboxStorageRoot -Name 'sbx-e7') 'sbx-e7-deps.vhdx'
        $report.Descriptor.DepsSourcePath | Should -Be $built.DepsDiskPath
        $report.Descriptor.DepsDiskPath   | Should -Be $copy
        $report.Descriptor.DepsImageHash  | Should -Be $built.DepsImageHash
        $attached | Should -Contain $copy
        $attached | Should -Not -Contain $built.DepsDiskPath
        (& $b.GetVHDInfo @{ Path = $copy }) | Should -BeNullOrEmpty -Because 'the consumer''s teardown deletes its working copy'
        (& $b.GetVHDInfo @{ Path = $built.DepsDiskPath }) | Should -Not -BeNullOrEmpty -Because 'the builder output stays for the next run'
    }

    It 'a wrong hash from the caller is still refused (the hand-off check is unchanged)' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob $script:BuilderOkBlob -SimulateDepsImageBlob ([byte[]](1..48))
        $built = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-e7b' -Backend $b `
            -DepsOutputDir (Join-Path $TestDrive 'out-e7b')
        $report = Invoke-Voidseal -Tier 0 -Profile $script:E7Consumer `
            -Workload @{ WorkloadMode = 'Disk'; DepsDiskPath = $built.DepsDiskPath; DepsImageHash = ('0' * 64) } `
            -Name 'sbx-e7b' -ArtifactRoot (Join-Path $TestDrive 'art-e7b') -Destination (Join-Path $TestDrive 'dest-e7b') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b -RateLedgerPath (Join-Path $TestDrive 'ledger-e7b.json') -WarningAction SilentlyContinue
        @($report.States) | Should -Not -Contain 'SEALED'
        $report.Error | Should -Match '(?i)hash'
    }
}

# ===========================================================================
#  The MoveVhdxFile backend method (E7)
# ===========================================================================
Describe 'MoveVhdxFile backend method' {

    It 'is in the manifest with Path and Destination, and both factories implement it' {
        (Get-HyperVBackendMethodManifest)['MoveVhdxFile'] | Should -Be @('Path', 'Destination')
        (New-FakeHyperVBackend).MoveVhdxFile | Should -BeOfType [scriptblock]
        (New-RealHyperVBackend).MoveVhdxFile | Should -BeOfType [scriptblock]
    }

    It 'fake: re-keys the record, so the old path is gone and the image bytes, label and hash travel with it' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path = 'C:\sb\out.vhdx'; Label = 'OUTPUT'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        $before = [string](& $b.GetVhdxImageHash @{ Path = 'C:\sb\out.vhdx' })
        & $b.MoveVhdxFile @{ Path = 'C:\sb\out.vhdx'; Destination = 'C:\keep\deps.vhdx' }
        (& $b.GetVHDInfo @{ Path = 'C:\sb\out.vhdx' }) | Should -BeNullOrEmpty
        $info = & $b.GetVHDInfo @{ Path = 'C:\keep\deps.vhdx' }
        $info.Path | Should -Be 'C:\keep\deps.vhdx'
        $info.Label | Should -Be 'OUTPUT'
        [string](& $b.GetVhdxImageHash @{ Path = 'C:\keep\deps.vhdx' }) | Should -Be $before
    }

    It 'fake: refuses a missing source, an existing destination and a source attached to a running VM' {
        $b = New-FakeHyperVBackend
        { & $b.MoveVhdxFile @{ Path = 'C:\nope.vhdx'; Destination = 'C:\keep\x.vhdx' } } | Should -Throw -ExpectedMessage '*does not exist*'
        & $b.NewVHD @{ Path = 'C:\a.vhdx'; SizeBytes = 64MB; Dynamic = $true }
        & $b.NewVHD @{ Path = 'C:\b.vhdx'; SizeBytes = 64MB; Dynamic = $true }
        { & $b.MoveVhdxFile @{ Path = 'C:\a.vhdx'; Destination = 'C:\b.vhdx' } } | Should -Throw -ExpectedMessage '*already exists*'
        & $b.NewVM @{ Name = 'vm-mv' }
        & $b.AddHardDiskDrive @{ VMName = 'vm-mv'; Path = 'C:\a.vhdx' }
        & $b.StartVM @{ Name = 'vm-mv' }
        { & $b.MoveVhdxFile @{ Path = 'C:\a.vhdx'; Destination = 'C:\keep\y.vhdx' } } | Should -Throw -ExpectedMessage '*locked*'
        (& $b.GetVHDInfo @{ Path = 'C:\a.vhdx' }) | Should -Not -BeNullOrEmpty -Because 'a refused move leaves the source alone'
    }

    Context 'real body, in-process on temp files (it runs no Hyper-V cmdlet)' {
        BeforeAll {
            $script:RealMv = New-RealHyperVBackend
            $script:MvDir = Join-Path $TestDrive 'realmove'
            New-Item -ItemType Directory -Path $script:MvDir -Force | Out-Null
            $script:MvBytes = [byte[]](0..255 + 0..255)
            $script:NewSrc = {
                param([string] $Leaf)
                $p = Join-Path $script:MvDir $Leaf
                [System.IO.File]::WriteAllBytes($p, $script:MvBytes)
                (Get-Item -LiteralPath $p).IsReadOnly = $true
                return $p
            }
        }

        It 'moves byte for byte into a new folder, clears ReadOnly, and leaves nothing behind' {
            $src = & $script:NewSrc 'a.vhdx'
            $dst = Join-Path $script:MvDir 'newdir\moved.vhdx'
            & $script:RealMv.MoveVhdxFile @{ Path = $src; Destination = $dst }
            [System.IO.File]::ReadAllBytes($dst) | Should -Be $script:MvBytes
            (Get-Item -LiteralPath $dst).IsReadOnly | Should -BeFalse
            Test-Path -LiteralPath $src | Should -BeFalse
            @(Get-ChildItem -LiteralPath (Split-Path -Parent $dst) -Filter '*.partial-*').Count | Should -Be 0
        }

        It 'refuses an existing destination and a missing source, touching neither' {
            $src = & $script:NewSrc 'b.vhdx'
            $dst = Join-Path $script:MvDir 'taken.vhdx'
            Set-Content -LiteralPath $dst -Value 'keep me'
            { & $script:RealMv.MoveVhdxFile @{ Path = $src; Destination = $dst } } | Should -Throw -ExpectedMessage '*already exists*'
            (Get-Content -LiteralPath $dst -Raw).Trim() | Should -Be 'keep me'
            Test-Path -LiteralPath $src | Should -BeTrue
            { & $script:RealMv.MoveVhdxFile @{ Path = (Join-Path $script:MvDir 'nope.vhdx'); Destination = (Join-Path $script:MvDir 'n2.vhdx') } } |
                Should -Throw -ExpectedMessage '*does not exist*'
        }

        It 'leaves the source in place and nothing at the destination when the source is held open exclusively' {
            $src = & $script:NewSrc 'c.vhdx'
            $dst = Join-Path $script:MvDir 'c-moved.vhdx'
            $fs = [System.IO.File]::Open($src, 'Open', 'Read', 'None')
            try {
                { & $script:RealMv.MoveVhdxFile @{ Path = $src; Destination = $dst } } | Should -Throw
            }
            finally { $fs.Dispose() }
            Test-Path -LiteralPath $dst | Should -BeFalse
            Test-Path -LiteralPath $src | Should -BeTrue
        }

        It 'the cross-volume branch copies, renames into place and deletes the source (a SUBST drive, skipped when none is free)' {
            if (-not $IsWindows) { Set-ItResult -Skipped -Because 'SUBST is Windows only'; return }
            $used = @((Get-PSDrive -PSProvider FileSystem).Name)
            $letter = @('Z','Y','X','W','V','U','T') | Where-Object { $_ -notin $used } | Select-Object -First 1
            if (-not $letter) { Set-ItResult -Skipped -Because 'no free drive letter for SUBST'; return }
            $target = Join-Path $TestDrive 'substroot'
            New-Item -ItemType Directory -Path $target -Force | Out-Null
            & subst "${letter}:" $target 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Set-ItResult -Skipped -Because 'subst could not create a drive'; return }
            try {
                $src = & $script:NewSrc 'x.vhdx'
                $dst = "${letter}:\deps\moved.vhdx"
                & $script:RealMv.MoveVhdxFile @{ Path = $src; Destination = $dst }
                [System.IO.File]::ReadAllBytes($dst) | Should -Be $script:MvBytes
                (Get-Item -LiteralPath $dst).IsReadOnly | Should -BeFalse
                Test-Path -LiteralPath $src | Should -BeFalse
                @(Get-ChildItem -LiteralPath "${letter}:\deps" -Filter '*.partial-*').Count | Should -Be 0
            }
            finally { & subst "${letter}:" /D 2>&1 | Out-Null }
        }
    }
}
