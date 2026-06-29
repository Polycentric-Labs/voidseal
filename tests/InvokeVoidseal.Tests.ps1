#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for scripts/Invoke-Voidseal.ps1 (the top-level orchestrator).

.DESCRIPTION
    Contract under test: Invoke-Voidseal wires the lifecycle state machine end-to-end over
    the backend abstraction:

        INIT -> PROVISIONED -> STAGED -> SEALED -> RUNNING -> CAPTURED -> EXTRACTED -> DESTROYED

    binding the profile load+validate, New-SandboxVM, the asset import + Lock-Sandbox +
    Assert-Sealed as a HARD GATE, Start-SandboxWorkload, Export-SandboxArtifact, and Remove-Sandbox.

        Invoke-Voidseal -Tier <0..3> -Profile <name|path> [-Workload <spec>] [-ArtifactRoot <dir>] [-Backend]

    THE SEAL GATE IS MANDATORY BEFORE RUNNING: a profile that FAILS Assert-Sealed must NEVER
    reach the workload-run state. On a seal-gate failure (or any mid-flow failure) the orchestrator
    tears down (reuses Remove-Sandbox) so no orphaned VM/disk/switch is left.

    Returns a structured run report: states traversed, seal verdict, run result, extracted artifact
    path, teardown status.

    SEAL-FAILURE INJECTION (realistic, no monkeypatching): a fake backend built with
    -SimulateChannelReadError seals fine (Lock-Sandbox only SETS channels) but makes Assert-Sealed's
    host-side GetHostChannels THROW — a genuine fail-closed seal-gate failure (proven in Sealer.Tests.ps1).
    The orchestrator must catch that, ABORT before RUNNING, and tear down.

    MID-FLOW FAILURE INJECTION: a fake built with -SimulateStartVMError provisions + seals + passes the
    gate, then throws when the Runner starts the VM — exercising teardown-on-failure with a real VM to reap.

    TDD: written FIRST; drives Invoke-Voidseal.ps1.
#>

BeforeAll {
    $script:SkillRoot   = Split-Path -Parent $PSScriptRoot
    $script:OrchPath    = Join-Path $script:SkillRoot 'scripts/Invoke-Voidseal.ps1'
    $script:BackendPath = Join-Path $script:SkillRoot 'scripts/lib/HyperVBackend.ps1'
    $script:TierDir     = Join-Path $script:SkillRoot 'tier-profiles'

    Test-Path $script:OrchPath    | Should -BeTrue -Because 'the orchestrator script must exist to be tested'
    Test-Path $script:BackendPath | Should -BeTrue -Because 'the backend must exist'

    # Invoke-Voidseal.ps1 dot-sources all the lib files itself; dot-source the orchestrator to get
    # Invoke-Voidseal + (transitively) the backend factories the tests use.
    . $script:OrchPath

    $script:Tier1Path = Join-Path $script:TierDir 'tier1.psd1'
    $script:Tier1 = Import-TierProfile -Path $script:Tier1Path

    # A valid Tier-2 fixture file does not ship; synthesize a normalized Tier-2 profile in-memory and
    # pass it as the -Profile object (Invoke-Voidseal accepts a name, a path, or a normalized hashtable).
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

    $script:TmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vmdep-t5orch-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $script:TmpRoot -Force | Out-Null

    # A workload spec emitting a result file the Tier-0/1 extractor can collect. The orchestrator's
    # Workload contract: @{ Entrypoint=<cmd>; ResultPath=<host-readable artifact> [; Name=...] }.
    # We pre-create the ResultPath so the extraction step has something to read (the fake guest does
    # not actually write files — the result is staged on the host for the test, mirroring a shared dir).
    $script:NewWorkload = {
        param([string] $Tag = 'wl')
        $resDir = Join-Path $script:TmpRoot ("res-$Tag-{0}" -f ([guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $resDir -Force | Out-Null
        $resFile = Join-Path $resDir 'artifact.txt'
        Set-Content -LiteralPath $resFile -Value "artifact-for-$Tag" -NoNewline -Encoding utf8
        return @{ Entrypoint = 'bash run.sh'; ResultPath = $resFile; Name = $Tag }
    }
}

AfterAll {
    if ($script:TmpRoot -and (Test-Path -LiteralPath $script:TmpRoot)) {
        Remove-Item -LiteralPath $script:TmpRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ===========================================================================
#  Happy path — a full Tier-1 deploy traverses INIT..DESTROYED
# ===========================================================================
Describe 'Invoke-Voidseal — full Tier-1 happy path runs the whole state machine and returns the report' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        $script:Workload = & $script:NewWorkload -Tag 'happy'
        $script:Art = Join-Path $script:TmpRoot ("art-happy-{0}" -f ([guid]::NewGuid().ToString('N')))
        $script:Dest = Join-Path $script:TmpRoot ("dest-happy-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'returns a report whose states traversed cover INIT..DESTROYED in order' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-happy' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        $report | Should -Not -BeNullOrEmpty
        $expected = @('INIT', 'PROVISIONED', 'STAGED', 'SEALED', 'RUNNING', 'CAPTURED', 'EXTRACTED', 'DESTROYED')
        @($report.States) | Should -Be $expected -Because 'the orchestrator must traverse the lifecycle state machine in order'
    }

    It 'the seal verdict in the report is a PASS' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-happy2' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        $report.SealVerdict | Should -BeTrue -Because 'a correctly-sealed Tier-1 VM passes Assert-Sealed'
    }

    It 'the run result records the workload ran (exit 0) and the entrypoint that was delivered' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-happy3' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        $report.RunResult | Should -Not -BeNullOrEmpty
        $report.RunResult.ExitCode   | Should -Be 0
        $report.RunResult.Entrypoint | Should -Be 'bash run.sh'
    }

    It 'extracts the artifact to the host destination (one-way OUT) and records the path' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-happy4' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        $report.ExtractedArtifact | Should -Not -BeNullOrEmpty
        @($report.ExtractedArtifact)[0] | Should -BeLike "$script:Dest*" -Because 'the extracted artifact lands in the host destination'
        Test-Path -LiteralPath (Join-Path $script:Dest 'artifact.txt') | Should -BeTrue -Because 'the Tier-1 one-way read collected the emitted artifact'
    }

    It 'tears down the VM at the end (no VM left on the backend) and reports teardown OK' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-happy5' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-happy5' }) | Should -BeNullOrEmpty -Because 'the lifecycle ends in DESTROYED — the VM is removed'
        $report.TeardownStatus | Should -Match '(?i)(ok|success|destroyed|removed)' -Because 'the report records a clean teardown'
    }

    It 'the VM was actually sealed (Assert-Sealed would pass) before it ran — the run happened on a sealed VM' {
        # We cannot inspect the (now-destroyed) VM, so assert via the report: SEALED precedes RUNNING.
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-happy6' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        $sealedIdx  = [array]::IndexOf(@($report.States), 'SEALED')
        $runningIdx = [array]::IndexOf(@($report.States), 'RUNNING')
        $sealedIdx  | Should -BeGreaterThan -1
        $runningIdx | Should -BeGreaterThan $sealedIdx -Because 'RUNNING must come strictly after SEALED — the seal gate precedes the run'
    }

    It 'accepts a tier-profile PATH as -Profile (loads + validates it via the loader)' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1Path -Workload $script:Workload `
            -Name 'sbx-bypath' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        @($report.States)[-1] | Should -Be 'DESTROYED' -Because 'a path-supplied profile must drive the same lifecycle'
    }
}

# ===========================================================================
#  THE SEAL GATE — a profile that FAILS Assert-Sealed ABORTS before RUNNING
# ===========================================================================
Describe 'Invoke-Voidseal — Assert-Sealed is a HARD gate: a seal failure aborts BEFORE the workload runs' {

    BeforeEach {
        # -SimulateChannelReadError: Lock-Sandbox still seals (it only SETS channels), but Assert-Sealed's
        # host-side GetHostChannels THROWS — a genuine fail-closed seal-gate failure (per Sealer.Tests.ps1).
        $script:BadSeal = New-FakeHyperVBackend -SimulateChannelReadError
        $script:Workload = & $script:NewWorkload -Tag 'sealfail'
        $script:Art = Join-Path $script:TmpRoot ("art-sf-{0}" -f ([guid]::NewGuid().ToString('N')))
        $script:Dest = Join-Path $script:TmpRoot ("dest-sf-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'does NOT reach the RUNNING state when the seal gate fails' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-sealfail' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:BadSeal -ErrorAction SilentlyContinue
        @($report.States) | Should -Not -Contain 'RUNNING' -Because 'a VM that fails Assert-Sealed must NEVER reach the workload-run state'
        @($report.States) | Should -Not -Contain 'CAPTURED'
        @($report.States) | Should -Not -Contain 'EXTRACTED'
    }

    It 'records the seal verdict as a FAILURE in the report' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-sealfail2' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:BadSeal -ErrorAction SilentlyContinue
        $report.SealVerdict | Should -BeFalse -Because 'the seal gate failed; the verdict must say so'
        $report.Error | Should -Not -BeNullOrEmpty -Because 'the report must carry why it aborted'
    }

    It 'NEVER started the workload (the entrypoint was not delivered over the serial seam)' {
        # The VM is torn down on abort, so assert the workload never ran via the report's run result.
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-sealfail3' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:BadSeal -ErrorAction SilentlyContinue
        $report.RunResult | Should -BeNullOrEmpty -Because 'the workload must not have started when the seal gate failed'
        # And no capture artifact should have been written (the run never happened).
        if (Test-Path -LiteralPath $script:Art) {
            @(Get-ChildItem -LiteralPath $script:Art -Recurse -File -ErrorAction SilentlyContinue).Count |
                Should -Be 0 -Because 'no run => no capture artifact'
        }
    }

    It 'TEARS DOWN the half-built VM on a seal-gate abort (no orphan left)' {
        Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-sealfail4' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:BadSeal -ErrorAction SilentlyContinue | Out-Null
        (& $script:BadSeal.GetVM @{ Name = 'sbx-sealfail4' }) |
            Should -BeNullOrEmpty -Because 'an aborted deploy must tear down its VM — no orphans'
    }

    It 'reports teardown ran even on the abort path' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-sealfail5' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:BadSeal -ErrorAction SilentlyContinue
        $report.TeardownStatus | Should -Not -BeNullOrEmpty -Because 'teardown status must be recorded even when the deploy aborts'
    }
}

# ===========================================================================
#  Mid-flow failure — teardown, no orphans (the Runner throws after seal)
# ===========================================================================
Describe 'Invoke-Voidseal — a mid-flow failure tears down (no orphaned VM/disk/switch)' {

    BeforeEach {
        # -SimulateStartVMError: provision + seal + gate all pass; StartVM throws during the RUNNING
        # transition. The orchestrator must catch it and reap the (already-provisioned, sealed) VM.
        $script:BadRun = New-FakeHyperVBackend -SimulateStartVMError
        $script:Workload = & $script:NewWorkload -Tag 'runfail'
        $script:Art = Join-Path $script:TmpRoot ("art-rf-{0}" -f ([guid]::NewGuid().ToString('N')))
        $script:Dest = Join-Path $script:TmpRoot ("dest-rf-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'tears down the VM when the workload-launch throws mid-flow (no orphan)' {
        Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-runfail' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:BadRun -ErrorAction SilentlyContinue | Out-Null
        (& $script:BadRun.GetVM @{ Name = 'sbx-runfail' }) |
            Should -BeNullOrEmpty -Because 'a mid-flow failure must trigger teardown so no VM is orphaned'
    }

    It 'the report records the failure and that the run did not complete' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-runfail2' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:BadRun -ErrorAction SilentlyContinue
        $report.Error | Should -Not -BeNullOrEmpty -Because 'a mid-flow failure must surface on the report'
        @($report.States) | Should -Not -Contain 'EXTRACTED' -Because 'extraction must not happen if the run failed'
        @($report.States) | Should -Not -Contain 'DESTROYED' | Out-Null  # DESTROYED may or may not be recorded; teardown still runs (asserted above)
    }

    It 'the seal gate still PASSED before the run failed (the failure is post-seal, not a seal failure)' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-runfail3' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:BadRun -ErrorAction SilentlyContinue
        $report.SealVerdict | Should -BeTrue -Because 'this scenario seals correctly; the failure is the Runner, not the gate'
        @($report.States) | Should -Contain 'SEALED' -Because 'SEALED was reached before the mid-flow failure'
    }
}

# ===========================================================================
#  Defense-in-depth — the SealVerdict guard: even if Assert-Sealed RETURNED $false
#  (instead of throwing) due to a future refactor, the workload must NOT run.
# ===========================================================================
Describe 'Invoke-Voidseal — SealVerdict guard: a non-throwing FALSE verdict still blocks RUNNING (defense-in-depth)' {
    # Defense-in-depth hardening: today Assert-Sealed is throw-only, so RUNNING is protected
    # by the gate throwing. This guards a FUTURE regression where a refactor makes Assert-Sealed RETURN
    # $false instead of throwing — the explicit `if (-not $sealOk) { throw }` must still block the run.
    # We inject that regression via a Pester Mock of Assert-Sealed (the clean seam — no production change).

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        $script:Workload = & $script:NewWorkload -Tag 'verdictguard'
        $script:Art  = Join-Path $script:TmpRoot ("art-vg-{0}" -f ([guid]::NewGuid().ToString('N')))
        $script:Dest = Join-Path $script:TmpRoot ("dest-vg-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'does NOT reach RUNNING when Assert-Sealed returns $false (instead of throwing)' {
        Mock Assert-Sealed { return $false }
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-verdictguard' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B -ErrorAction SilentlyContinue
        @($report.States) | Should -Not -Contain 'RUNNING' -Because 'a non-true seal verdict must block the workload even if Assert-Sealed did not throw'
        @($report.States) | Should -Not -Contain 'CAPTURED'
        @($report.States) | Should -Not -Contain 'EXTRACTED'
        $report.RunResult | Should -BeNullOrEmpty -Because 'the workload must not have started on an uncertified VM'
        $report.Error     | Should -Not -BeNullOrEmpty -Because 'the guard records why it refused to run'
    }

    It 'tears down the VM when the verdict guard refuses (no orphan)' {
        Mock Assert-Sealed { return $false }
        Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-verdictguard2' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B -ErrorAction SilentlyContinue | Out-Null
        (& $script:B.GetVM @{ Name = 'sbx-verdictguard2' }) |
            Should -BeNullOrEmpty -Because 'the verdict-guard abort still runs teardown — no orphaned VM'
    }
}

# ===========================================================================
#  Disk mode — the data-disk-driven workload path wires end-to-end
# ===========================================================================
Describe 'Invoke-Voidseal — Disk mode: full lifecycle seals, attaches+detaches data disks, reads+classifies' {

    BeforeEach {
        # A Tier-0 Disk-mode profile, synthesized in-memory (no StageAssets/SeedIso host-file deps so
        # STAGED is a clean no-op against the fake). WorkloadMode='Disk' routes the orchestrator down the
        # data-disk path: New-WorkloadDisks creates+attaches+records the INPUT/OUTPUT disks BEFORE the
        # seal, the VM starts, the host waits for self-power-off, detaches the data disks, then reads +
        # classifies the OUTPUT volume. The fake guest writes no sentinel -> Read-WorkloadResult honestly
        # classifies Failed (no-sentinel), which still proves the whole wiring traversed.
        $script:Tier0Disk = Import-TierProfile -Path (Join-Path $script:TierDir 'tier0.psd1')
        $script:Tier0Disk = @{} + $script:Tier0Disk          # mutable copy
        $script:Tier0Disk['Name']         = 'firefox-test'
        $script:Tier0Disk['WorkloadMode'] = 'Disk'
        $script:Tier0Disk['Inputs']       = @{}              # empty inputs -> input disk created with no files
        $script:Tier0Disk['FileSystem']   = 'exFAT'
        Assert-TierProfileValid -Profile $script:Tier0Disk -Context 'TEST Tier-0 Disk-mode fixture'

        # SimulateSelfPowerOff: the guest boots, runs, self-powers-off before the first poll, so
        # Wait-WorkloadComplete reads the happy (Off, not-timed-out) branch and Read-WorkloadResult runs.
        $script:DiskB = New-FakeHyperVBackend -SimulateSelfPowerOff
        $script:Art   = Join-Path $script:TmpRoot ("art-disk-{0}"  -f ([guid]::NewGuid().ToString('N')))
        $script:Dest  = Join-Path $script:TmpRoot ("dest-disk-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'Invoke-Voidseal Disk mode: full lifecycle runs, seals, detaches+reads, classifies (fake guest = no sentinel = Failed)' {
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Disk `
            -Workload @{ WorkloadMode = 'Disk'; ResultInnerName = 'result.html'; SentinelInnerName = 'result.exitcode' } `
            -Name 'sbx-disk' -ArtifactRoot $script:Art -Destination $script:Dest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $script:DiskB
        $report                  | Should -Not -BeNullOrEmpty
        $report.States           | Should -Contain 'SEALED'
        $report.SealVerdict      | Should -BeTrue -Because 'the recorded data disks are attached BEFORE the seal, so Assert-Sealed accepts them'
        $report.States           | Should -Contain 'RUNNING'
        $report.States           | Should -Contain 'CAPTURED'
        $report.States           | Should -Contain 'DESTROYED'
        $report.RunResult        | Should -Not -BeNullOrEmpty
        $report.RunResult.Status | Should -Be 'Failed' -Because 'the fake guest wrote no sentinel; Read-WorkloadResult honestly classifies Failed'
        $report.RunResult.Reason | Should -Match '(?i)sentinel' -Because 'the no-sentinel reason proves the host-read path ran (not the timeout path)'
    }

    It 'Disk mode resolves WorkloadMode from the PROFILE (no -Workload override needed)' {
        # WorkloadMode='Disk' lives on the profile; with no -Workload spec the orchestrator must still
        # take the Disk path (defaults: result.html / result.exitcode).
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Disk `
            -Name 'sbx-disk-prof' -ArtifactRoot $script:Art -Destination $script:Dest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $script:DiskB
        $report.States    | Should -Contain 'RUNNING' -Because 'profile WorkloadMode=Disk drives the disk path with no -Workload'
        $report.RunResult | Should -Not -BeNullOrEmpty
    }

    It 'Disk mode attaches BOTH data disks before the seal, folds them into CreatedDisks, and DETACHES them before the host read (proven via the call log)' {
        # The data disks are recorded on the descriptor and attached pre-seal; after the run they are
        # detached (RemoveHardDiskDrive) BEFORE the host reads the OUTPUT volume (ReadVhdxFile) — the
        # host must never read a disk still attached to a (possibly live) guest. The VM is destroyed at
        # the end, so we cannot read the VM's .HardDrives post-run; instead prove the detach actually
        # RAN — and ran before the read — via the fake's persistent call log (survives RemoveVM).
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Disk `
            -Name 'sbx-disk-detach' -ArtifactRoot $script:Art -Destination $script:Dest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $script:DiskB
        $inDisk  = $report.Descriptor.InputDiskPath
        $outDisk = $report.Descriptor.OutputDiskPath
        $inDisk  | Should -Not -BeNullOrEmpty
        $outDisk | Should -Not -BeNullOrEmpty
        # the data disks were folded into CreatedDisks so the Reaper's -DeleteDisks pass cleans them up
        @($report.Descriptor.CreatedDisks) | Should -Contain $outDisk
        @($report.Descriptor.CreatedDisks) | Should -Contain $inDisk

        # PROVE THE DETACH RAN: both data disks were detached via RemoveHardDiskDrive.
        $log     = @($script:DiskB.FakeCallLog)
        $detached = @($log | Where-Object { $_.Op -eq 'RemoveHardDiskDrive' } | ForEach-Object { $_.Path })
        $detached | Should -Contain $inDisk  -Because 'the INPUT data disk must be detached before the host read'
        $detached | Should -Contain $outDisk -Because 'the OUTPUT data disk must be detached before the host read'

        # PROVE THE ORDERING: the OUTPUT disk is detached BEFORE the host reads it (ReadVhdxFile).
        $detachOutIdx = [array]::FindIndex([object[]]$log, [Predicate[object]]{ param($e) $e.Op -eq 'RemoveHardDiskDrive' -and $e.Path -eq $outDisk })
        $readOutIdx   = [array]::FindIndex([object[]]$log, [Predicate[object]]{ param($e) $e.Op -eq 'ReadVhdxFile' -and $e.Path -eq $outDisk })
        $detachOutIdx | Should -BeGreaterThan -1 -Because 'the OUTPUT disk detach must be logged'
        $readOutIdx   | Should -BeGreaterThan -1 -Because 'the host read of the OUTPUT disk must be logged'
        $detachOutIdx | Should -BeLessThan $readOutIdx -Because 'the host must detach the OUTPUT disk BEFORE it reads the OUTPUT volume'
    }

    It 'Disk mode SUCCESS path: a guest-seeded sentinel+result drives Read-WorkloadResult to Success and extracts the artifact (EXTRACTED)' {
        # The Failed-path e2e above never exercises the orchestrator's happy artifact-extraction wiring
        # (if ($runResult.ArtifactPath) { $report.ExtractedArtifact = ... } + the EXTRACTED state). This
        # seeds the OUTPUT disk with a sentinel (exitcode 0) + a result file when the guest "self-powers-
        # off": -SimulateWorkloadOutput makes StartVM write those inner files onto the OUTPUT-labelled
        # disk (modelling the guest writing output then powering off), so Read-WorkloadResult classifies
        # Success and the extraction path runs end-to-end through Invoke-Voidseal.
        $html   = '<!DOCTYPE NETSCAPE-Bookmark-file-1><DL><DT>seeded</DL>'
        $okB = New-FakeHyperVBackend -SimulateSelfPowerOff `
            -SimulateWorkloadOutput @{ 'result.exitcode' = '0'; 'result.html' = $html }
        $art  = Join-Path $script:TmpRoot ("art-disk-ok-{0}"  -f ([guid]::NewGuid().ToString('N')))
        $dest = Join-Path $script:TmpRoot ("dest-disk-ok-{0}" -f ([guid]::NewGuid().ToString('N')))

        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Disk `
            -Workload @{ WorkloadMode = 'Disk'; ResultInnerName = 'result.html'; SentinelInnerName = 'result.exitcode' } `
            -Name 'sbx-disk-ok' -ArtifactRoot $art -Destination $dest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $okB

        $report.States           | Should -Contain 'EXTRACTED' -Because 'a Success run reaches the EXTRACTED state'
        $report.RunResult.Status   | Should -Be 'Success' -Because 'the seeded sentinel (0) + result file classify Success'
        $report.RunResult.ExitCode | Should -Be 0
        $report.ExtractedArtifact  | Should -Not -BeNullOrEmpty -Because 'the orchestrator records the extracted artifact path on a Success run'
        Test-Path -LiteralPath $report.ExtractedArtifact | Should -BeTrue -Because 'the result file was copied to the host destination'
        Get-Content -LiteralPath $report.ExtractedArtifact -Raw | Should -Match 'NETSCAPE-Bookmark' -Because 'the extracted artifact carries the seeded HTML content'
    }

    It 'Invoke-Voidseal Disk mode folds -Workload.Inputs onto the INPUT disk' {
        # CONTRACT GAP: the profile's Inputs is empty (the .psd1 keeps it empty; live runs populate
        # it at deploy time). The documented live-acceptance path passes the inputs through -Workload.Inputs.
        # Without the orchestrator folding -Workload.Inputs into the resolved profile BEFORE New-WorkloadDisks,
        # the override is silently dropped -> the INPUT disk is created with no files -> no organizer script in
        # the guest -> the workload can't run. This proves the injected content actually reaches the INPUT
        # volume through the orchestrator. We assert via the fake's WriteVhdxFile call log (which captures the
        # Content and survives teardown — the disk itself is deleted by the Reaper's -DeleteDisks pass at the
        # end of the lifecycle, so it can't be read back post-run).
        $script:Tier0Disk['Inputs'] | Should -BeNullOrEmpty -Because 'the fixture profile carries an EMPTY Inputs — the override must be what populates the disk'
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Disk `
            -Workload @{ WorkloadMode = 'Disk'; Inputs = @{ 'organize_bookmarks.py' = 'print(1)'; 'sample.json' = '{}' } } `
            -Name 'sbx-inputs' -ArtifactRoot $script:Art -Destination $script:Dest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $script:DiskB
        $inPath = $report.Descriptor.InputDiskPath
        $inPath | Should -Not -BeNullOrEmpty

        # PROVE THE INJECTED CONTENT REACHED THE INPUT DISK: the fake logged a WriteVhdxFile onto the INPUT
        # disk path for each injected inner file, carrying the exact Content the override supplied.
        $writes = @($script:DiskB.FakeCallLog | Where-Object { $_.Op -eq 'WriteVhdxFile' -and $_.Path -eq $inPath })
        $organizer = $writes | Where-Object { $_.InnerPath -eq 'organize_bookmarks.py' } | Select-Object -First 1
        $sample    = $writes | Where-Object { $_.InnerPath -eq 'sample.json' }            | Select-Object -First 1
        $organizer        | Should -Not -BeNullOrEmpty -Because 'the -Workload.Inputs organizer script must be written onto the INPUT disk through the orchestrator'
        $organizer.Content | Should -Be 'print(1)'    -Because 'the exact injected organizer content must reach the INPUT volume'
        $sample           | Should -Not -BeNullOrEmpty -Because 'the -Workload.Inputs sample must be written onto the INPUT disk through the orchestrator'
        $sample.Content    | Should -Be '{}'          -Because 'the exact injected sample content must reach the INPUT volume'
    }

    It 'Disk mode tears down the VM at the end (no orphan) and reports teardown OK' {
        Invoke-Voidseal -Tier 0 -Profile $script:Tier0Disk `
            -Name 'sbx-disk-teardown' -ArtifactRoot $script:Art -Destination $script:Dest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $script:DiskB | Out-Null
        (& $script:DiskB.GetVM @{ Name = 'sbx-disk-teardown' }) |
            Should -BeNullOrEmpty -Because 'the Disk-mode lifecycle ends in DESTROYED — the VM is removed'
    }

    It 'Disk mode SEAL GATE still gates RUNNING: a seal failure aborts before the workload disk-run' {
        $badSeal = New-FakeHyperVBackend -SimulateChannelReadError -SimulateSelfPowerOff
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Disk `
            -Name 'sbx-disk-sealfail' -ArtifactRoot $script:Art -Destination $script:Dest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $badSeal -ErrorAction SilentlyContinue
        @($report.States)   | Should -Not -Contain 'RUNNING' -Because 'a Disk-mode VM that fails the seal gate must never start its disk workload'
        $report.SealVerdict | Should -BeFalse
        $report.RunResult   | Should -BeNullOrEmpty -Because 'no run when the seal gate failed'
        (& $badSeal.GetVM @{ Name = 'sbx-disk-sealfail' }) | Should -BeNullOrEmpty -Because 'an aborted Disk-mode deploy tears down its VM'
    }

    It 'Disk mode: a transient data-disk DETACH failure is a Failed run, NOT a lifecycle abort (host read skipped, teardown still runs)' {
        # A real Remove-VMHardDiskDrive can throw transiently right after a force-stop. That must NOT
        # propagate to the outer catch (which would record a lifecycle .Error and mis-report a successful
        # guest run as a hard abort, sending the operator hunting a guest bug that doesn't exist). The
        # orchestrator's detach try/catch records a Failed run, SKIPS the host read (never read a disk that
        # may still be attached), and teardown still runs. The guest "succeeded" here (seeded sentinel +
        # result) to prove that even a would-be Success is honestly downgraded to Failed when we cannot
        # safely detach-then-read — the seam is RemoveHardDiskDrive, which teardown does not use.
        $html  = '<!DOCTYPE NETSCAPE-Bookmark-file-1><DL></DL>'
        $failB = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateDetachError `
            -SimulateWorkloadOutput @{ 'result.exitcode' = '0'; 'result.html' = $html }
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Disk `
            -Workload @{ WorkloadMode = 'Disk'; ResultInnerName = 'result.html'; SentinelInnerName = 'result.exitcode' } `
            -Name 'sbx-disk-detachfail' -ArtifactRoot $script:Art -Destination $script:Dest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $failB
        $report.Error            | Should -BeNullOrEmpty -Because 'a transient detach failure must NOT abort the lifecycle via the outer catch (.Error stays null)'
        $report.RunResult        | Should -Not -BeNullOrEmpty
        $report.RunResult.Status | Should -Be 'Failed' -Because 'an undetachable data disk cannot be safely read; the run is honestly Failed, not Success'
        $report.RunResult.Reason | Should -Match '(?i)detach' -Because 'the reason names the detach, pointing the operator host-side (not at the guest)'
        @($report.States)        | Should -Not -Contain 'EXTRACTED' -Because 'the host read is skipped when the disks could not be detached'
        @($report.States)        | Should -Contain 'DESTROYED' -Because 'teardown still runs (Remove-Sandbox uses RemoveVM/RemoveVHD, not RemoveHardDiskDrive)'
        (& $failB.GetVM @{ Name = 'sbx-disk-detachfail' }) | Should -BeNullOrEmpty -Because 'the VM is torn down even on the detach-failure path (no orphan)'
    }

    It 'Disk mode: a guest-written EMPTY result.html (sentinel rc=0) is classified Failed, NOT a false-green Success' {
        # A 0-byte result.html (a guest double-write or a truncated-flush race) must NOT classify Success
        # just because the sentinel says 0 — an empty artifact imports nothing. SimulateWorkloadOutput
        # seeds the OUTPUT disk's Files table directly (the guest "wrote" an empty result.html + rc 0), so
        # Read-WorkloadResult sees a present sentinel (0) but empty content -> Failed, and no artifact is
        # extracted. (This is the realistic path: the GUEST writes the empty file; the host's WriteVhdxFile
        # rejects empty content as a caller bug, so this scenario only arises guest-side.)
        $emptyB = New-FakeHyperVBackend -SimulateSelfPowerOff `
            -SimulateWorkloadOutput @{ 'result.exitcode' = '0'; 'result.html' = '' }
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Disk `
            -Workload @{ WorkloadMode = 'Disk'; ResultInnerName = 'result.html'; SentinelInnerName = 'result.exitcode' } `
            -Name 'sbx-disk-empty' -ArtifactRoot $script:Art -Destination $script:Dest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $emptyB
        $report.RunResult.Status  | Should -Be 'Failed' -Because 'sentinel rc=0 but an EMPTY result.html is not a usable artifact (no false-green)'
        $report.RunResult.Reason  | Should -Match '(?i)empty|absent' -Because 'the reason explains the empty result'
        $report.ExtractedArtifact | Should -BeNullOrEmpty -Because 'an empty result is not extracted as an artifact'
    }
}

# ===========================================================================
#  RC6 — Disk mode delivers the cloud-init seed on a CIDATA DATA DISK that
#  survives the seal (NOT an ejected DVD), and the disk-mode path emits no dual-DVD warning.
# ===========================================================================
#  RC6 (2026-06-25 live): the seal EJECTS the seed DVD before the guest's ONLY boot, so cloud-init had
#  no datasource and the disk-mode runner never ran. In disk mode the orchestrator must now create the
#  CIDATA seed DATA DISK (New-WorkloadSeedDisk) instead of attaching the SeedIso DVD (Add-SandboxSeed),
#  so the seed survives the seal as a recorded data disk. A disk-mode profile that declares a SeedIso
#  must NOT take the DVD path (and so must NOT emit the dual-DVD warning). Serial mode is UNCHANGED.
Describe 'Invoke-Voidseal — Disk mode delivers the seed on a CIDATA data disk that survives the seal (RC6)' {

    BeforeEach {
        # A Tier-0 Disk-mode profile WITH an Entrypoint (the disk-mode seed carries the runner, which
        # needs an entrypoint) AND a SeedIso path (to prove the disk path does NOT attach it as a DVD or
        # warn). The SeedIso host file need not exist: the disk-mode path builds the seed CONTENT from the
        # Entrypoint and never reads the SeedIso file.
        $script:Tier0Seed = Import-TierProfile -Path (Join-Path $script:TierDir 'tier0.psd1')
        $script:Tier0Seed = @{} + $script:Tier0Seed
        $script:Tier0Seed['Name']         = 'firefox-seed-test'
        $script:Tier0Seed['WorkloadMode'] = 'Disk'
        $script:Tier0Seed['Inputs']       = @{}
        $script:Tier0Seed['FileSystem']   = 'exFAT'
        $script:Tier0Seed['Entrypoint']   = 'python3 /mnt/in/organize_bookmarks.py --profile /mnt/in --out /mnt/out/result.html'
        $script:Tier0Seed['SeedIso']      = 'C:\sandbox\assets\cidata-seed.iso'   # declared; disk mode must NOT attach it as a DVD
        Assert-TierProfileValid -Profile $script:Tier0Seed -Context 'TEST Tier-0 Disk-mode seed fixture'

        $script:SeedB = New-FakeHyperVBackend -SimulateSelfPowerOff
        $script:Art2  = Join-Path $script:TmpRoot ("art-seed-{0}"  -f ([guid]::NewGuid().ToString('N')))
        $script:Dest2 = Join-Path $script:TmpRoot ("dest-seed-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'creates + attaches + records a CIDATA seed data disk carrying user-data + meta-data' {
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Seed `
            -Name 'sbx-seed-disk' -ArtifactRoot $script:Art2 -Destination $script:Dest2 `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $script:SeedB
        $seedPath = $report.Descriptor.SeedDiskPath
        $seedPath | Should -Not -BeNullOrEmpty -Because 'RC6: disk mode records the CIDATA seed disk on the descriptor'
        # The seed disk is on CreatedDisks so the Reaper cleans it up.
        @($report.Descriptor.CreatedDisks) | Should -Contain $seedPath
        # The seed disk carried both NoCloud documents (proven via the persistent write log — the disk
        # itself is deleted by teardown). The user-data is the disk-mode runner with the entrypoint.
        $writes = @($script:SeedB.FakeCallLog | Where-Object { $_.Op -eq 'WriteVhdxFile' -and $_.Path -eq $seedPath })
        ($writes | Where-Object { $_.InnerPath -eq 'user-data' } | Select-Object -First 1) | Should -Not -BeNullOrEmpty
        ($writes | Where-Object { $_.InnerPath -eq 'meta-data' } | Select-Object -First 1) | Should -Not -BeNullOrEmpty
        $ud = ($writes | Where-Object { $_.InnerPath -eq 'user-data' } | Select-Object -First 1).Content
        $ud | Should -Match '#cloud-config' -Because 'the seed user-data is a cloud-init document'
        $ud | Should -Match 'organize_bookmarks' -Because 'the disk-mode runner embeds the profile Entrypoint'
    }

    It 'the seal CERTIFIES with the CIDATA seed disk present and the lifecycle runs INIT...DESTROYED with SealVerdict=$true' {
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Seed `
            -Name 'sbx-seed-seal' -ArtifactRoot $script:Art2 -Destination $script:Dest2 `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $script:SeedB
        $report.SealVerdict | Should -BeTrue -Because 'RC6: the recorded CIDATA seed disk is an EXPECTED disk — the seal must certify with it attached'
        @($report.States) | Should -Contain 'SEALED'
        @($report.States) | Should -Contain 'RUNNING'
        @($report.States) | Should -Contain 'DESTROYED'
    }

    It 'teardown DELETES the CIDATA seed disk (it is on CreatedDisks)' {
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Seed `
            -Name 'sbx-seed-teardown' -ArtifactRoot $script:Art2 -Destination $script:Dest2 `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $script:SeedB
        $seedPath = $report.Descriptor.SeedDiskPath
        $seedPath | Should -Not -BeNullOrEmpty
        (& $script:SeedB.GetVHDInfo @{ Path = $seedPath }) |
            Should -BeNullOrEmpty -Because 'the Reaper -DeleteDisks pass deletes the CIDATA seed disk (it is recorded on CreatedDisks)'
    }

    It 'disk mode does NOT attach the SeedIso as a DVD (no SetDvdDrive for the seed)' {
        # In disk mode the seed rides a DATA DISK, not the DVD slot. Prove no DVD was ever attached.
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Tier0Seed `
            -Name 'sbx-seed-nodvd' -ArtifactRoot $script:Art2 -Destination $script:Dest2 `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $script:SeedB
        # SetDvdDrive is not logged by the fake's CallLog, but the descriptor's SeedIso field must NOT be
        # set by the disk path (Add-SandboxSeed sets it; the disk path must not call Add-SandboxSeed).
        $seedIsoField = $report.Descriptor.PSObject.Properties['SeedIso']
        ($null -eq $seedIsoField -or [string]::IsNullOrWhiteSpace([string]$seedIsoField.Value)) |
            Should -BeTrue -Because 'RC6: the disk path must NOT call Add-SandboxSeed (which records SeedIso for the DVD); the seed is a data disk'
    }

    It 'disk mode does NOT emit the dual-DVD warning even when a SeedIso is declared (RC6)' {
        # The dual-DVD warning is a DVD-path concern. In disk mode the seed is a data disk, so even a
        # profile declaring both a SeedIso and the disk seed must NOT warn about a single DVD slot.
        Invoke-Voidseal -Tier 0 -Profile $script:Tier0Seed `
            -Name 'sbx-seed-nowarn' -ArtifactRoot $script:Art2 -Destination $script:Dest2 `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $script:SeedB `
            -WarningVariable seedWarnings -WarningAction SilentlyContinue | Out-Null
        $dualDvd = @($seedWarnings | Where-Object { [string]$_ -match '(?i)single DVD slot|StageAssets ISO that must|SeedIso takes the boot DVD' })
        @($dualDvd).Count | Should -Be 0 -Because 'RC6: disk mode delivers the seed on a data disk, so the single-DVD-slot warning must not fire'
    }
}

# ===========================================================================
#  Task 1.4 — processor (gate) wiring: Invoke-Voidseal attaches+records the DEPS
#  disk BEFORE the seal (so Assert-Sealed accepts it) and wires the POST-DETACH
#  Sensitivity Gate (processor workloads only). The gate runs HOST-SIDE after the
#  OUTPUT disk is detached, partitioning the in-guest screener's candidates into
#  Released (auto-certified SAFE) vs Held (everything else), and stamps GateRan
#  on the descriptor + Released/Held/SensitivityReport on the report.
# ===========================================================================
Describe 'Invoke-Voidseal — processor (gate) wiring' {

    BeforeEach {
        # A Tier-0 PROCESSOR profile: Network='None' (structurally no-NIC; Tier-0 Container substrate
        # wires no NIC, so it seals clean) + a ScreenConfig (mode='aggressive') that routes the post-
        # detach gate, + WorkloadMode='Disk' (a processor IS a Disk-mode workload) + an Entrypoint (so
        # the disk-mode CIDATA seed disk is built, exactly like the RC6 path). EgressMode/EgressAllowlist
        # MUST be 'None'/@() for a Network='None' profile (the loader's processor rule).
        $script:Proc = Import-TierProfile -Path (Join-Path $script:TierDir 'tier0.psd1')
        $script:Proc = @{} + $script:Proc                    # mutable copy
        $script:Proc['Name']            = 'firefox-proc-test'
        $script:Proc['WorkloadMode']    = 'Disk'
        $script:Proc['Inputs']          = @{}
        $script:Proc['FileSystem']      = 'exFAT'
        $script:Proc['Network']         = 'None'             # processor: structurally no-NIC
        $script:Proc['EgressMode']      = 'None'             # processor rule: Network=None => EgressMode=None
        $script:Proc['EgressAllowlist'] = @()                # processor rule: empty allowlist
        $script:Proc['ScreenConfig']    = @{ mode = 'aggressive' }   # routes the post-detach gate
        $script:Proc['Entrypoint']      = 'python3 /mnt/in/organize_bookmarks.py --profile /mnt/in --out /mnt/out/result.html'
        Assert-TierProfileValid -Profile $script:Proc -Context 'TEST Tier-0 processor fixture'

        # SimulateSelfPowerOff: the guest self-powers-off before the first poll, so Wait-WorkloadComplete
        # reads the happy (Off, not-timed-out) branch and the detach+read+gate path runs.
        $script:ProcB = New-FakeHyperVBackend -SimulateSelfPowerOff
        $script:ProcArt  = Join-Path $script:TmpRoot ("art-proc-{0}"  -f ([guid]::NewGuid().ToString('N')))
        $script:ProcDest = Join-Path $script:TmpRoot ("dest-proc-{0}" -f ([guid]::NewGuid().ToString('N')))

        # The HOST-readable gate inputs the orchestrator consumes via -Workload (Phase-1 mock injection;
        # Phase-2 derives these from host-mounting the detached OUTPUT VHDX). The staging dir is a real
        # temp dir with the messy-drive fixture copied in; the verdicts.json is hand-written to cover all
        # seven staged files (the gate's completeness guard refuses an unaccounted staged file).
        $script:GateStaging = Join-Path $script:TmpRoot ("gate-staging-{0}" -f ([guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $script:GateStaging -Force | Out-Null
        Copy-Item (Join-Path $script:SkillRoot 'tests/fixtures/messy-drive/*') $script:GateStaging

        $script:GateVerdicts = Join-Path $script:TmpRoot ("gate-verdicts-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        @(
            [pscustomobject]@{ name = 'creds.txt';             verdict = 'SENSITIVE'; detectors = @('credential-pattern') }
            [pscustomobject]@{ name = 'finance-statement.txt'; verdict = 'SENSITIVE'; detectors = @('financial-keyword') }
            [pscustomobject]@{ name = 'health-note.txt';       verdict = 'SENSITIVE'; detectors = @('health-keyword') }
            [pscustomobject]@{ name = 'prose-essay.txt';       verdict = 'SAFE';      detectors = @() }
            [pscustomobject]@{ name = 'prose-letter.md';       verdict = 'SAFE';      detectors = @() }
            [pscustomobject]@{ name = 'spreadsheet-dump.csv';  verdict = 'UNCERTAIN'; detectors = @('non-prose') }
            [pscustomobject]@{ name = 'prose-with-token.md';   verdict = 'SENSITIVE'; detectors = @('token-pattern') }
        ) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:GateVerdicts -Encoding utf8

        # A mock DEPS disk: a pre-existing VHDX the builder would have produced (Phase 2). The fake's
        # AddHardDiskDrive requires the VHD to exist in its state (real Add-VMHardDiskDrive requires the
        # file), so we create it on the backend with NewVHD first — mirroring how a real deps.vhdx exists
        # on disk before the orchestrator attaches it.
        # D3-B (Phase 3): the shared BeforeAll also pre-computes the whole-image hash so each It that
        # needs to PASS the verify step can supply DepsImageHash = $script:DepsDiskHash without a per-It
        # NewVHD call. Tests that override the hash (mismatch) or omit it (missing) create their own
        # local backend + disk so the shared fixture stays unaffected.
        $script:DepsDisk = Join-Path $script:TmpRoot ("deps-{0}.vhdx" -f ([guid]::NewGuid().ToString('N')))
        & $script:ProcB.NewVHD @{ Path = $script:DepsDisk; SizeBytes = 1GB; Differencing = $false; Dynamic = $true }
        $script:DepsDiskHash = [string](& $script:ProcB.GetVhdxImageHash @{ Path = $script:DepsDisk })   # the (empty) fixture's whole-image hash
    }

    It 'releases the SAFE candidates end-to-end: detached OUTPUT outbox -> ReadVhdxRawRegion -> read_outbox.py -> gate' {
        # Build a REAL outbox blob from the SAME staging + verdicts the old test injected, via guest/outbox.py.
        $blobFile = Join-Path $script:TmpRoot ("outbox-{0}.bin" -f ([guid]::NewGuid().ToString('N')))
        & python -c "import sys; sys.path.insert(0, 'guest'); import outbox; outbox.write_outbox_from_dir(r'$script:GateStaging', r'$script:GateVerdicts', r'$blobFile')"
        $LASTEXITCODE | Should -Be 0 -Because 'the outbox fixture must pack cleanly'
        $blob = [System.IO.File]::ReadAllBytes($blobFile)

        # The guest "wrote" that blob to the OUTPUT disk's raw region (SelfPowerOff = clean flush). Build a
        # fresh backend with the blob + re-create the DEPS disk on it (fake state is per-instance).
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateOutboxBlob $blob
        & $b.NewVHD @{ Path = $script:DepsDisk; SizeBytes = 1GB; Differencing = $false; Dynamic = $true }
        $depsHash = [string](& $b.GetVhdxImageHash @{ Path = $script:DepsDisk })   # the (empty) fixture's whole-image hash

        $report = Invoke-Voidseal -Tier 0 -Profile $script:Proc `
            -Workload @{ WorkloadMode = 'Disk'; DepsDiskPath = $script:DepsDisk; DepsImageHash = $depsHash } `
            -Name 'sbx-proc-outbox' -ArtifactRoot $script:ProcArt -Destination $script:ProcDest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b

        @($report.States) | Should -Contain 'SEALED'
        $report.Descriptor.GateRan | Should -BeTrue -Because 'the processor gate ran off the OUTPUT outbox'
        $relNames = @($report.Released | ForEach-Object { $_.name })
        $helNames = @($report.Held     | ForEach-Object { $_.name })
        $relNames | Should -Contain 'prose-essay.txt' -Because 'a SAFE prose file is released'
        $relNames | Should -Contain 'prose-letter.md'
        $relNames | Should -Not -Contain 'creds.txt'  -Because 'a SENSITIVE credential file is NEVER released'
        $helNames | Should -Contain 'creds.txt'
        $report.SensitivityReport | Should -Not -BeNullOrEmpty
    }

    It 'DENY-on-tamper: a corrupted OUTPUT outbox -> read_outbox.py exits non-zero -> gate releases NOTHING' {
        $blobFile = Join-Path $script:TmpRoot ("outbox-bad-{0}.bin" -f ([guid]::NewGuid().ToString('N')))
        & python -c "import sys; sys.path.insert(0, 'guest'); import outbox; outbox.write_outbox_from_dir(r'$script:GateStaging', r'$script:GateVerdicts', r'$blobFile')"
        $bad = [System.IO.File]::ReadAllBytes($blobFile)
        $bad[$bad.Length - 1] = $bad[$bad.Length - 1] -bxor 0xFF   # flip a payload byte -> SHA mismatch

        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateOutboxBlob $bad
        & $b.NewVHD @{ Path = $script:DepsDisk; SizeBytes = 1GB; Differencing = $false; Dynamic = $true }
        $depsHash = [string](& $b.GetVhdxImageHash @{ Path = $script:DepsDisk })   # the (empty) fixture's whole-image hash

        $report = Invoke-Voidseal -Tier 0 -Profile $script:Proc `
            -Workload @{ WorkloadMode = 'Disk'; DepsDiskPath = $script:DepsDisk; DepsImageHash = $depsHash } `
            -Name 'sbx-proc-tamper' -ArtifactRoot $script:ProcArt -Destination $script:ProcDest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b

        $report.Released          | Should -BeNullOrEmpty -Because 'a tampered outbox fails closed — nothing is released'
        $report.SensitivityReport | Should -BeNullOrEmpty
        $report.Error             | Should -Match '(?i)gate|outbox|read'
        # GateRan must NOT be stamped (the gate never partitioned).
        $gateRanField = $report.Descriptor.PSObject.Properties['GateRan']
        ($null -eq $gateRanField -or -not [bool]$gateRanField.Value) | Should -BeTrue
    }

    It 'DENY-on-timeout: a hung processor (SimulateNeverOff) -> gate does NOT run, Released stays $null' {
        $b = New-FakeHyperVBackend -SimulateNeverOff   # never self-powers-off -> Wait-WorkloadComplete force-stops -> TimedOut
        & $b.NewVHD @{ Path = $script:DepsDisk; SizeBytes = 1GB; Differencing = $false; Dynamic = $true }
        $depsHash = [string](& $b.GetVhdxImageHash @{ Path = $script:DepsDisk })   # the (empty) fixture's whole-image hash

        $report = Invoke-Voidseal -Tier 0 -Profile $script:Proc `
            -Workload @{ WorkloadMode = 'Disk'; DepsDiskPath = $script:DepsDisk; DepsImageHash = $depsHash } `
            -Name 'sbx-proc-timeout' -ArtifactRoot $script:ProcArt -Destination $script:ProcDest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b

        $report.Released | Should -BeNullOrEmpty -Because 'a timed-out run releases nothing (DENY-on-timeout)'
        $gateRanField = $report.Descriptor.PSObject.Properties['GateRan']
        ($null -eq $gateRanField -or -not [bool]$gateRanField.Value) | Should -BeTrue -Because 'the gate must not run on a timeout'
    }

    It 'a NON-processor Disk-mode deploy does NOT run the gate (Released stays $null; GateRan not set)' {
        # Reuse the established Tier-0 NON-processor Disk-mode fixture (no Network='None', no ScreenConfig).
        $nonProc = Import-TierProfile -Path (Join-Path $script:TierDir 'tier0.psd1')
        $nonProc = @{} + $nonProc
        $nonProc['Name']         = 'firefox-nonproc-test'
        $nonProc['WorkloadMode'] = 'Disk'
        $nonProc['Inputs']       = @{}
        $nonProc['FileSystem']   = 'exFAT'
        Assert-TierProfileValid -Profile $nonProc -Context 'TEST Tier-0 non-processor Disk-mode fixture'

        $b = New-FakeHyperVBackend -SimulateSelfPowerOff
        $report = Invoke-Voidseal -Tier 0 -Profile $nonProc `
            -Workload @{ WorkloadMode = 'Disk'; ResultInnerName = 'result.html'; SentinelInnerName = 'result.exitcode' } `
            -Name 'sbx-nonproc' -ArtifactRoot $script:ProcArt -Destination $script:ProcDest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b

        @($report.States)         | Should -Contain 'SEALED' -Because 'a non-processor Disk-mode deploy still seals + runs'
        $report.Released          | Should -BeNullOrEmpty -Because 'the gate did not run on a non-processor deploy'
        $report.Held              | Should -BeNullOrEmpty -Because 'the gate did not run on a non-processor deploy'
        $report.SensitivityReport | Should -BeNullOrEmpty -Because 'no gate => no sensitivity report'
        # GateRan must NOT be set on the descriptor (the gate never ran). A descriptor without the field,
        # or one whose field is falsey/absent, both satisfy "GateRan is not set".
        $gateRanField = $report.Descriptor.PSObject.Properties['GateRan']
        ($null -eq $gateRanField -or -not [bool]$gateRanField.Value) |
            Should -BeTrue -Because 'GateRan is never stamped when the gate did not run'
    }

    It 'DENY-on-deps-mismatch: a deps disk whose hash != the expected (builder-recorded) hash is REFUSED (no attach, no run)' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff
        & $b.NewVHD @{ Path = $script:DepsDisk; SizeBytes = 1GB; Differencing = $false; Dynamic = $true }
        # wrong hash — 64 zero hex chars; the actual hash of an empty VHDX is non-zero
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Proc `
            -Workload @{ WorkloadMode = 'Disk'; DepsDiskPath = $script:DepsDisk; DepsImageHash = ('0' * 64) } `
            -Name 'sbx-proc-depsmismatch' -ArtifactRoot $script:ProcArt -Destination $script:ProcDest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b
        @($report.States) | Should -Not -Contain 'SEALED' -Because 'a tampered/substituted deps disk aborts BEFORE the seal'
        $report.Error | Should -Match '(?i)deps.*(integrity|hash)|integrity check' -Because 'the abort names the deps integrity failure'
        $report.Released | Should -BeNullOrEmpty
    }

    It 'DENY-on-missing-deps-hash: a deps disk with NO DepsImageHash is REFUSED (mandatory verification)' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff
        & $b.NewVHD @{ Path = $script:DepsDisk; SizeBytes = 1GB; Differencing = $false; Dynamic = $true }
        # NO DepsImageHash supplied — should trigger mandatory-verification refusal
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Proc `
            -Workload @{ WorkloadMode = 'Disk'; DepsDiskPath = $script:DepsDisk } `
            -Name 'sbx-proc-nodepshash' -ArtifactRoot $script:ProcArt -Destination $script:ProcDest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b
        @($report.States) | Should -Not -Contain 'SEALED'
        $report.Error | Should -Match '(?i)DepsImageHash|no .*hash|unverified' -Because 'a deps disk without a verified hash is refused'
        $report.Released | Should -BeNullOrEmpty -Because 'a missing-hash abort is fail-closed — nothing is released (symmetry with DENY-on-deps-mismatch)'
    }

    It 'GC invariant (D3-D): the verified deps.vhdx is NOT in CreatedDisks -> teardown LEAVES it (builder-owned, reusable)' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff
        & $b.NewVHD @{ Path = $script:DepsDisk; SizeBytes = 1GB; Differencing = $false; Dynamic = $true }
        $depsHash = [string](& $b.GetVhdxImageHash @{ Path = $script:DepsDisk })   # detached -> hashable
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Proc `
            -Workload @{ WorkloadMode = 'Disk'; DepsDiskPath = $script:DepsDisk; DepsImageHash = $depsHash } `
            -Name 'sbx-proc-depsgc' -ArtifactRoot $script:ProcArt -Destination $script:ProcDest `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b
        @($report.States) | Should -Contain 'SEALED' -Because 'a verified deps disk attaches + the run proceeds'
        @($report.Descriptor.CreatedDisks) | Should -Not -Contain $script:DepsDisk -Because 'the builder-owned deps.vhdx is never in CreatedDisks; the Reaper leaves it'
        $report.Descriptor.DepsImageHash | Should -Be $depsHash -Because 'the verified hash is recorded on the descriptor'
    }
}

# ===========================================================================
#  Input validation
# ===========================================================================
Describe 'Invoke-Voidseal — input validation' {

    It 'throws on an out-of-range tier (only 0..3 are valid)' {
        $b = New-FakeHyperVBackend
        { Invoke-Voidseal -Tier 7 -Profile $script:Tier1 -Backend $b } |
            Should -Throw -Because 'tiers outside 0..3 are invalid'
    }

    It 'throws when -Profile resolves to nothing (unknown name / missing path)' {
        $b = New-FakeHyperVBackend
        { Invoke-Voidseal -Tier 1 -Profile (Join-Path $script:TmpRoot 'no-such-profile.psd1') -Backend $b } |
            Should -Throw -Because 'a profile path that does not exist must fail closed'
    }
}
