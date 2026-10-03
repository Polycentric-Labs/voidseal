#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for the cloud-init CIDATA seed + guest boot-wait.

.DESCRIPTION
    Two first-boot gaps the MOCK backend can't model surfaced while prepping the first LIVE boot:

    PART A: the cloud-init NoCloud SEED (what the guest reads on its FIRST boot):
        cloud-init needs the seed at first boot to configure the guest (serial-getty AUTOLOGIN on
        ttyS0 = the Runner's command channel; run-user; packages). No seed -> no serial console ->
        InvokeGuestCommand finds nothing on the COM1 pipe and times out.

        The seal runs BEFORE that first boot and ejects every import DVD, so the seed cannot ride
        the DVD slot (RC6: proven live for Disk mode on 2026-06-25; Serial mode followed on
        2026-10-03, after its seed DVD turned out to be ejected the same way). Contract: the
        orchestrator builds the seed itself from the resolved profile (New-WorkloadSeedDisk ->
        New-CidataUserData) on a recorded CIDATA DATA DISK that survives the seal, for every run that
        boots a guest. It never reads the profile's SeedIso path (that is only New-CidataSeed's
        default output path), and the old DVD helper Add-SandboxSeed is gone. The first-boot
        assertions themselves (the seed is attached when StartVM fires) live in
        InvokeVoidseal.Tests.ps1; the host-truth DVD walk moved to Sealer.Tests.ps1.

    PART B — the guest BOOT-WAIT in the Runner:
        Start-SandboxWorkload called StartVM then IMMEDIATELY InvokeGuestCommand with no delay. A
        real Debian guest needs ~20-60s to boot + run cloud-init before the serial console accepts a
        command. Even with the seed attached, the first command would race the boot. The Runner now
        runs a boot-readiness PROBE (a cheap InvokeGuestCommand retried until it succeeds or a
        deadline) BEFORE delivering the entrypoint. The probe/delay is INJECTABLE so tests don't
        sleep 60s: a `-BootWaitSeconds 0` and a mockable inter-attempt delay keep tests instant; the
        FAKE backend returns canned success immediately so the probe passes on the first attempt.

    EVERYTHING touches Hyper-V through the backend abstraction — no raw Hyper-V cmdlets.
    TDD: written FIRST; drives the seed-ISO + boot-wait changes in ProfileLoader / Provisioner-orchestrator / Sealer /
    Runner + the two shipped profiles.
#>

BeforeAll {
    $script:SkillRoot   = Split-Path -Parent $PSScriptRoot
    $script:OrchPath    = Join-Path $script:SkillRoot 'scripts/Invoke-Voidseal.ps1'
    $script:BackendPath = Join-Path $script:SkillRoot 'scripts/lib/HyperVBackend.ps1'
    $script:LoaderPath  = Join-Path $script:SkillRoot 'scripts/lib/ProfileLoader.ps1'
    $script:ProvPath    = Join-Path $script:SkillRoot 'scripts/lib/Provisioner.ps1'
    $script:SealerPath  = Join-Path $script:SkillRoot 'scripts/lib/Sealer.ps1'
    $script:RunnerPath  = Join-Path $script:SkillRoot 'scripts/lib/Runner.ps1'
    $script:TierDir     = Join-Path $script:SkillRoot 'tier-profiles'
    $script:ProfileDir  = Join-Path $script:SkillRoot 'profiles'

    Test-Path $script:OrchPath    | Should -BeTrue -Because 'the orchestrator must exist'
    Test-Path $script:BackendPath | Should -BeTrue -Because 'the backend must exist'

    # The orchestrator dot-sources the whole engine; dot-source it to get every public function +
    # the backend factories the tests use.
    . $script:OrchPath

    $script:Tier1 = Import-TierProfile -Path (Join-Path $script:TierDir 'tier1.psd1')

    # A placeholder file at the path the SeedIso key points at, so the fixture mirrors a real profile.
    # Invoke-Voidseal never opens it (it builds the seed itself); InvokeVoidseal.Tests.ps1 proves that
    # with a SeedIso that points at a missing file.
    $script:TmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vmdep-t8-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $script:TmpRoot -Force | Out-Null
    $script:SeedIso = Join-Path $script:TmpRoot 'cidata-seed.iso'
    Set-Content -LiteralPath $script:SeedIso -Value 'fake-cidata-nocloud-seed' -NoNewline -Encoding ascii

    # A normalized Tier-1 profile that DECLARES a SeedIso (the value flows into the orchestrator).
    $script:Tier1Seed = $script:Tier1.Clone()
    $script:Tier1Seed['SeedIso'] = $script:SeedIso

    # A workload spec emitting a result file the Tier-0/1 extractor can collect.
    $script:NewWorkload = {
        param([string] $Tag = 'wl')
        $resDir = Join-Path $script:TmpRoot ("res-$Tag-{0}" -f ([guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $resDir -Force | Out-Null
        $resFile = Join-Path $resDir 'artifact.txt'
        Set-Content -LiteralPath $resFile -Value "artifact-for-$Tag" -NoNewline -Encoding utf8
        return @{ Entrypoint = 'bash run.sh'; ResultPath = $resFile; Name = $Tag }
    }

    # Provision a fresh VM on a fresh fake backend, returning @{ Backend; Desc }.
    $script:NewTestSandbox = {
        param($Profile = $script:Tier1, [string] $Name = 'sbx-t8')
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
#  PART A — the loader carries SeedIso through to the merged profile
# ===========================================================================
Describe 'Part A — Import-WorkloadProfile carries the SeedIso key onto the merged profile' {

    It 'layers a workload SeedIso onto the merged tier profile' {
        $tmp = Join-Path $TestDrive 'seed-wl.psd1'
        $body = @(
            '@{'
            "    BaseTier   = 1"
            "    Name       = 'seed-wl'"
            "    Entrypoint = 'bash run.sh'"
            "    SeedIso    = 'C:\sandbox\assets\cidata-seed.iso'"
            '}'
        ) -join [Environment]::NewLine
        Set-Content -LiteralPath $tmp -Value $body -Encoding UTF8
        $merged = Import-WorkloadProfile -Path $tmp -TierProfileDir $script:TierDir
        $merged.ContainsKey('SeedIso') | Should -BeTrue -Because 'SeedIso must merge onto the profile so the orchestrator can attach it at boot'
        [string]$merged['SeedIso'] | Should -Be 'C:\sandbox\assets\cidata-seed.iso'
    }

    It 'a profile WITHOUT SeedIso simply has no SeedIso key (no regression)' {
        $tmp = Join-Path $TestDrive 'noseed-wl.psd1'
        $body = @(
            '@{'
            "    BaseTier   = 1"
            "    Name       = 'noseed-wl'"
            "    Entrypoint = 'bash run.sh'"
            '}'
        ) -join [Environment]::NewLine
        Set-Content -LiteralPath $tmp -Value $body -Encoding UTF8
        $merged = Import-WorkloadProfile -Path $tmp -TierProfileDir $script:TierDir
        $merged.ContainsKey('SeedIso') | Should -BeFalse -Because 'SeedIso is OPTIONAL; its absence must change nothing'
    }
}

# ===========================================================================
#  PART A: the orchestrator builds the seed itself on a recorded CIDATA DATA
#          DISK that survives the seal. Nothing attaches a seed DVD any more.
# ===========================================================================
Describe 'Part A: Invoke-Voidseal seeds the guest on a data disk; nothing attaches a seed DVD' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        $script:Workload = & $script:NewWorkload -Tag 'seed'
        $script:Art  = Join-Path $script:TmpRoot ("art-seed-{0}" -f ([guid]::NewGuid().ToString('N')))
        $script:Dest = Join-Path $script:TmpRoot ("dest-seed-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'Add-SandboxSeed no longer exists (no helper attaches a seed DVD that the seal would eject before boot)' {
        Get-Command -Name 'Add-SandboxSeed' -ErrorAction SilentlyContinue |
            Should -BeNullOrEmpty -Because 'the seal ejects every DVD before the guest''s only boot, so a DVD seed can never reach cloud-init'
    }

    It 'a profile WITH a SeedIso runs INIT..DESTROYED with its seed on a data disk, not in the DVD slot' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1Seed -Workload $script:Workload `
            -Name 'sbx-seed1' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        $expected = @('INIT', 'PROVISIONED', 'STAGED', 'SEALED', 'RUNNING', 'CAPTURED', 'EXTRACTED', 'DESTROYED')
        @($report.States) | Should -Be $expected
        $report.SealVerdict | Should -BeTrue -Because 'the recorded seed disk is an expected disk for the gate'
        $report.Error | Should -BeNullOrEmpty
        [string]$report.Descriptor.SeedDiskPath | Should -Not -BeNullOrEmpty -Because 'the seed rides a recorded CIDATA data disk'
        # ImportedMedia only exists once something has been imported, so read it without assuming it.
        $imported = $report.Descriptor.PSObject.Properties['ImportedMedia']
        @(if ($null -ne $imported) { $imported.Value }) | Should -Not -Contain $script:SeedIso -Because 'the SeedIso file is not imported as a DVD any more'
    }

    It 'a profile WITHOUT a SeedIso gets the same seed disk (the field is not needed)' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-noseed-full' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        @($report.States)[-1] | Should -Be 'DESTROYED'
        $report.Error | Should -BeNullOrEmpty
        [string]$report.Descriptor.SeedDiskPath | Should -Not -BeNullOrEmpty -Because 'every Serial run with an entrypoint is seeded from the profile'
    }
}

# ===========================================================================
#  PART B — the Runner waits for guest boot readiness BEFORE the entrypoint
# ===========================================================================
Describe 'Part B — Start-SandboxWorkload probes boot readiness BEFORE delivering the entrypoint' {

    BeforeEach {
        $sb = & $script:NewTestSandbox -Profile $script:Tier1 -Name 'sbx-bootwait'
        $script:B = $sb.Backend; $script:Desc = $sb.Desc
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:B
        $script:ArtRoot = Join-Path $script:TmpRoot ("bootwait-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'still runs the entrypoint + returns a success result with the fake (instant-ready probe, no real sleep)' {
        # The fake returns canned success immediately, so the readiness probe passes on the first
        # attempt. -BootWaitSeconds 0 keeps the test instant (no real delay).
        $result = Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' `
            -ArtifactRoot $script:ArtRoot -BootWaitSeconds 0 -Backend $script:B
        $result | Should -Not -BeNullOrEmpty
        $result.ExitCode | Should -Be 0 -Because 'with the seed + a ready guest the entrypoint runs and returns success'
        @((& $script:B.GetVM @{ Name = 'sbx-bootwait' }).GuestCommands) |
            Should -Contain 'bash ralph_loop.sh' -Because 'the entrypoint is still delivered after the readiness probe'
    }

    It 'attempts the readiness PROBE before the entrypoint (the probe command precedes the entrypoint in the delivered sequence)' {
        Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' `
            -ArtifactRoot $script:ArtRoot -BootWaitSeconds 0 -Backend $script:B | Out-Null
        $cmds = @((& $script:B.GetVM @{ Name = 'sbx-bootwait' }).GuestCommands)
        $cmds.Count | Should -BeGreaterThan 1 -Because 'a readiness probe is delivered in addition to the entrypoint'
        # The entrypoint is the LAST command; at least one probe precedes it.
        $cmds[-1] | Should -Be 'bash ralph_loop.sh' -Because 'the entrypoint is delivered only AFTER the boot-readiness probe succeeds'
        $probeIdx = [array]::IndexOf($cmds, $cmds[0])
        $probeIdx | Should -BeLessThan ($cmds.Count - 1) -Because 'the probe precedes the entrypoint'
    }

    It 'reports the run result of the ENTRYPOINT, not the probe (the probe output is not the workload result)' {
        $result = Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' `
            -ArtifactRoot $script:ArtRoot -BootWaitSeconds 0 -Backend $script:B
        $result.Entrypoint | Should -Be 'bash ralph_loop.sh' -Because 'the returned result is the workload, not the readiness probe'
    }

    It 'does NOT actually sleep (a 0 boot-wait + instant-ready fake completes well under a second)' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' `
            -ArtifactRoot $script:ArtRoot -BootWaitSeconds 0 -Backend $script:B | Out-Null
        $sw.Stop()
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 5 -Because 'the boot-wait must be injectable so tests never sleep the real ~60s'
    }
}

# ===========================================================================
#  PART B — a guest that never becomes ready reports a CLEAR timeout in the run result
#           (not a crash) and teardown still runs.
# ===========================================================================
Describe 'Part B — a guest that never becomes ready reports a clear timeout (no crash; teardown still runs)' {

    BeforeEach {
        # -SimulateGuestCommandFailure makes EVERY InvokeGuestCommand return a non-zero exit, so the
        # boot-readiness probe never succeeds — modeling a guest that does not come up.
        $script:Bad = New-FakeHyperVBackend -SimulateGuestCommandFailure
        $script:Desc = New-SandboxVM -Profile $script:Tier1 -Name 'sbx-noboot' -Backend $script:Bad
        Lock-Sandbox -Descriptor $script:Desc -Backend $script:Bad
        $script:ArtRoot = Join-Path $script:TmpRoot ("noboot-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'reports a clear boot-readiness timeout in the run result (does NOT crash) when the guest never becomes ready' {
        # A short deadline that elapses immediately (BootWaitSeconds 0 -> a single probe attempt that
        # fails). The Runner must surface this as a reported run outcome, not an unhandled throw.
        $result = Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' `
            -ArtifactRoot $script:ArtRoot -BootWaitSeconds 0 -Backend $script:Bad
        $result | Should -Not -BeNullOrEmpty -Because 'a never-ready guest must produce a structured result, not a crash'
        $result.ExitCode | Should -Not -Be 0 -Because 'a boot-readiness timeout is a failed run outcome'
        ([string]$result.Stderr + [string]$result.BootWaitStatus) |
            Should -Match '(?i)(boot|ready|timeout|timed out)' -Because 'the result must say the guest never became ready'
    }

    It 'does NOT deliver the entrypoint when the guest never becomes ready (the probe gate held)' {
        Start-SandboxWorkload -Descriptor $script:Desc -Entrypoint 'bash ralph_loop.sh' `
            -ArtifactRoot $script:ArtRoot -BootWaitSeconds 0 -Backend $script:Bad | Out-Null
        @((& $script:Bad.GetVM @{ Name = 'sbx-noboot' }).GuestCommands) |
            Should -Not -Contain 'bash ralph_loop.sh' -Because 'the entrypoint must not race a guest that never came up'
    }

    It 'the orchestrator still TEARS DOWN when the guest never becomes ready (no orphan)' {
        $b = New-FakeHyperVBackend -SimulateGuestCommandFailure
        $wl = & $script:NewWorkload -Tag 'noboot-orch'
        $art  = Join-Path $script:TmpRoot ("art-noboot-{0}" -f ([guid]::NewGuid().ToString('N')))
        $dest = Join-Path $script:TmpRoot ("dest-noboot-{0}" -f ([guid]::NewGuid().ToString('N')))
        # Run the full orchestrator; the workload "fails" (never-ready probe -> non-zero), but teardown
        # must still reap the VM regardless of the run outcome.
        Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $wl `
            -Name 'sbx-noboot-orch' -ArtifactRoot $art -Destination $dest `
            -BootWaitSeconds 0 -BootPollDelaySeconds 0 -Backend $b -ErrorAction SilentlyContinue | Out-Null
        (& $b.GetVM @{ Name = 'sbx-noboot-orch' }) |
            Should -BeNullOrEmpty -Because 'teardown always runs — a never-ready guest must not orphan a VM'
    }
}

# ===========================================================================
#  PART C — both shipped profiles declare a SeedIso and still load cleanly
# ===========================================================================
Describe 'Part C — the shipped firefox + ralph profiles declare a SeedIso and still pass Import-WorkloadProfile' {

    BeforeAll {
        . $script:LoaderPath
        $script:RalphPath   = Join-Path $script:ProfileDir 'ralph.psd1'
        $script:FirefoxPath = Join-Path $script:ProfileDir 'firefox.psd1'
    }

    It 'ralph.psd1 declares a SeedIso and merges cleanly' {
        $ralph = Import-WorkloadProfile -Path $script:RalphPath -TierProfileDir $script:TierDir
        $ralph.ContainsKey('SeedIso') | Should -BeTrue -Because 'ralph keeps SeedIso as New-CidataSeed''s default output path (Invoke-Voidseal builds the seed itself)'
        [string]$ralph['SeedIso'] | Should -Match '(?i)cidata-seed\.iso' -Because 'the smoke-test seed path'
    }

    It 'firefox.psd1 declares a SeedIso and merges cleanly' {
        $firefox = Import-WorkloadProfile -Path $script:FirefoxPath -TierProfileDir $script:TierDir
        $firefox.ContainsKey('SeedIso') | Should -BeTrue -Because 'firefox keeps SeedIso as New-CidataSeed''s default output path (Invoke-Voidseal builds the seed itself)'
        [string]$firefox['SeedIso'] | Should -Match '(?i)cidata-seed\.iso' -Because 'the smoke-test seed path'
    }
}
