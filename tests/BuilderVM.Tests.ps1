#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for scripts/lib/BuilderVM.ps1 (Invoke-BuilderVM orchestrator).

.DESCRIPTION
    Task 2.4: Tier-1 builder orchestration — provision->seed->run->detach->whole-image-hash->emit.
    No seal (the builder keeps its NIC + Squid egress for the whole run).
    No host-mount (the integrity artifact is the whole-image hash, raw, no mount).
    Success = clean power-off this phase; timeout = Failed, no deps artifact.

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
}

# ===========================================================================
#  Happy path — a clean builder run emits a deps.vhdx + whole-image hash
# ===========================================================================
Describe 'Invoke-BuilderVM — Tier-1 builder orchestration (Phase 2.4)' {

    It 'a clean builder run emits a deps.vhdx + the whole-image hash (== SHA256 of the deps bytes) and Status=Success' {
        $blob = [byte[]](1..64)
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateDepsImageBlob $blob
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld1' -Backend $fake -DepsDiskPath (Join-Path $TestDrive 'deps.vhdx')
        $r.Status | Should -Be 'Success'
        $r.DepsDiskPath | Should -Not -BeNullOrEmpty
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $want = [System.BitConverter]::ToString($sha.ComputeHash($blob)).Replace('-','').ToLowerInvariant(); $sha.Dispose()
        $r.WholeImageHash | Should -Be $want
    }

    It 'the OUTPUT (deps) disk is DETACHED before the host hash (no read of a locked/attached disk)' {
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateDepsImageBlob ([byte[]](1..8))
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld2' -Backend $fake -DepsDiskPath (Join-Path $TestDrive 'd2.vhdx')
        $r.Status | Should -Be 'Success'   # GetVhdxImageHash THROWS if still attached -> Success proves detach-before-hash
        $ops = @($fake.FakeCallLog | Where-Object { $_.Op -in @('RemoveHardDiskDrive','GetVhdxImageHash') } | ForEach-Object { $_.Op })
        # TR-2: assert BOTH ops actually ran BEFORE the IndexOf ordering check — IndexOf returns -1 when an
        # op is absent, and `-1 -BeLessThan <positive>` is vacuously TRUE, so the ordering assertion alone
        # would pass even if the detach never happened (mirror InvokeVoidseal.Tests.ps1:352-363).
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
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateDepsImageBlob $blob
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
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateDepsImageBlob $blob
        $r = Invoke-BuilderVM -Profile "$script:SkillRoot/profiles/builder.psd1" -Name 'bld-noseal' -Backend $fake -DepsDiskPath (Join-Path $TestDrive 'deps-ns.vhdx')
        $r.Status | Should -Be 'Success'
        # A sealed VM would have no network adapters; the builder KEEPS its NIC.
        # The VM is torn down so we can't read it back — assert via CallLog: RemoveNetworkAdapter
        # must NOT appear (the seal calls RemoveNetworkAdapter; the builder must not call Lock-Sandbox).
        $removeNicCalls = @($fake.FakeCallLog | Where-Object { $_.Op -eq 'RemoveNetworkAdapter' })
        $removeNicCalls.Count | Should -Be 0 -Because 'the builder keeps its NIC — Lock-Sandbox must never be called'
    }

    It 'the builder run does NOT record a SealVerdict (SealVerdict is not a builder output)' {
        $blob = [byte[]](1..8)
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateDepsImageBlob $blob
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
        $fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateDepsImageBlob $blob
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
}
