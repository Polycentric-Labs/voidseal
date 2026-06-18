#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for the cloud-init CIDATA seed ISO + guest boot-wait.

.DESCRIPTION
    Two first-boot gaps the MOCK backend can't model surfaced while prepping the first LIVE boot:

    PART A — the cloud-init NoCloud SEED ISO (a first-class `SeedIso` workload/tier key):
        The orchestrator's STAGED step imports StageAssets ISOs (workload payload) but NOTHING
        attached the CIDATA NoCloud seed ISO cloud-init needs at FIRST BOOT to configure the guest
        (serial-getty AUTOLOGIN on ttyS0 = the Runner's command channel; run-user; packages). No
        seed -> no serial console -> InvokeGuestCommand finds nothing on the COM1 pipe and times out.

        Contract: when the resolved profile declares `SeedIso`, the orchestrator attaches it as a
        READ-ONLY DVD (via the existing one-way Import-SandboxAsset -As Iso machinery) BEFORE the
        seal, so it is present at first boot. It is import-only: Lock-Sandbox detaches/ejects it as
        part of the seal, and Assert-Sealed must NOT fail on it being gone (expected, ejected) but
        MUST still fail if it is STILL attached post-seal (a sealed VM has no import DVD). The seed
        is recorded on the descriptor (ImportedMedia / SeedIso) so the seal + gate know about it.

        DVD-SLOT NOTE: the backend models a SINGLE DVD slot (the VM record's `DvdDrive` scalar).
        The SeedIso is the BOOT-CONFIG disc — it is the disc in the DVD slot at first boot. A
        StageAssets ISO that must coexist with the seed cannot share the one DVD slot and must be a
        transfer-VHD for a real coexistence run; the orchestrator emits a caveat when both are
        present and gives the SEED the boot DVD slot (attached LAST so it occupies the slot at boot).

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

    # Build a real CIDATA seed ISO file on disk (the host source the SeedIso key points at). The fake
    # backend never reads it, but Import-SandboxAsset -As Iso does a host-side Test-Path before attach.
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
#  PART A — the orchestrator attaches the SeedIso as a read-only DVD at provision/stage
#           (present at FIRST BOOT) and the seal ejects it; the gate stays correct.
# ===========================================================================
Describe 'Part A — Invoke-Voidseal attaches a SeedIso read-only DVD before the seal, then ejects it on seal' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        $script:Workload = & $script:NewWorkload -Tag 'seed'
        $script:Art  = Join-Path $script:TmpRoot ("art-seed-{0}" -f ([guid]::NewGuid().ToString('N')))
        $script:Dest = Join-Path $script:TmpRoot ("dest-seed-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'runs the WHOLE state machine with a SeedIso profile (INIT..DESTROYED) — the seal ejected the seed so the gate passes' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1Seed -Workload $script:Workload `
            -Name 'sbx-seed1' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        $expected = @('INIT', 'PROVISIONED', 'STAGED', 'SEALED', 'RUNNING', 'CAPTURED', 'EXTRACTED', 'DESTROYED')
        @($report.States) | Should -Be $expected -Because 'a SeedIso must be attached then ejected by the seal so the lifecycle completes'
        $report.SealVerdict | Should -BeTrue -Because 'the seed is ejected as part of the seal, so Assert-Sealed certifies'
        $report.Error | Should -BeNullOrEmpty
    }

    It 'attaches the SeedIso as a read-only DVD at provision time (present at FIRST BOOT, recorded on ImportedMedia)' {
        # Provision + stage WITHOUT sealing, to observe the boot-time DVD state. Mirror the
        # orchestrator's pre-seal steps directly so we can inspect the live VM before Lock-Sandbox.
        $d = New-SandboxVM -Profile $script:Tier1Seed -Name 'sbx-seed-attach' -Backend $script:B
        Add-SandboxSeed -Descriptor $d -SeedIso $script:Tier1Seed['SeedIso'] -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-seed-attach' }).DvdDrive |
            Should -Be $script:SeedIso -Because 'the seed is the boot-config disc in the single DVD slot at FIRST BOOT'
        @($d.ImportedMedia) | Should -Contain $script:SeedIso -Because 'the seed is import-only; the seal must later detach it, so it is recorded'
    }

    It 'records the SeedIso on the descriptor so the seal + gate know about it' {
        $d = New-SandboxVM -Profile $script:Tier1Seed -Name 'sbx-seed-rec' -Backend $script:B
        Add-SandboxSeed -Descriptor $d -SeedIso $script:Tier1Seed['SeedIso'] -Backend $script:B
        [string]$d.SeedIso | Should -Be $script:SeedIso -Because 'the descriptor must record the seed path for audit + the seal/gate'
    }

    It 'EJECTS the seed DVD as part of the seal (no import DVD remains after Lock-Sandbox)' {
        $d = New-SandboxVM -Profile $script:Tier1Seed -Name 'sbx-seed-eject' -Backend $script:B
        Add-SandboxSeed -Descriptor $d -SeedIso $script:Tier1Seed['SeedIso'] -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-seed-eject' }).DvdDrive | Should -Be $script:SeedIso -Because 'precondition: the seed is attached before the seal'
        Lock-Sandbox -Descriptor $d -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-seed-eject' }).DvdDrive |
            Should -BeNullOrEmpty -Because 'the seal must eject the import-only seed DVD'
    }

    It 'Assert-Sealed PASSES once the seed is ejected (its absence is EXPECTED, not a failure)' {
        $d = New-SandboxVM -Profile $script:Tier1Seed -Name 'sbx-seed-pass' -Backend $script:B
        Add-SandboxSeed -Descriptor $d -SeedIso $script:Tier1Seed['SeedIso'] -Backend $script:B
        Lock-Sandbox -Descriptor $d -Backend $script:B
        { Assert-Sealed -Descriptor $d -Backend $script:B } |
            Should -Not -Throw -Because 'an ejected seed is the sealed state; the gate must NOT fail on the seed being gone'
        Assert-Sealed -Descriptor $d -Backend $script:B | Should -BeTrue
    }

    It 'Assert-Sealed FAILS if the seed DVD is STILL attached post-seal (a sealed VM has no import DVD)' {
        $d = New-SandboxVM -Profile $script:Tier1Seed -Name 'sbx-seed-fail' -Backend $script:B
        Add-SandboxSeed -Descriptor $d -SeedIso $script:Tier1Seed['SeedIso'] -Backend $script:B
        Lock-Sandbox -Descriptor $d -Backend $script:B
        # Re-attach the seed AFTER the seal to simulate a botched/incomplete seal — the gate must catch it.
        & $script:B.SetDvdDrive @{ VMName = 'sbx-seed-fail'; Path = $script:SeedIso }
        { Assert-Sealed -Descriptor $d -Backend $script:B } |
            Should -Throw -ExpectedMessage '*DVD*' -Because 'a still-attached seed DVD MUST fail the gate — the seed handling must not open a hole'
    }

    # ---- HOST-TRUTH DVD path — the seal/gate must route through GetDvdDrives ----
    # CRITICAL real-backend bug found during live debugging: the Sealer read DVD state off the
    # GetVM object's .DvdDrive field. The FAKE carries that scalar, but a REAL Get-VM object has
    # NO DvdDrive property (DVD state lives in the DVDDrives collection / Get-VMDvdDrive). So on
    # real Hyper-V the seal NEVER detached the seed and the gate NEVER saw it — a still-attached
    # seed would PASS. The fix routes the seal + gate through the backend's GetDvdDrives collection
    # method (host truth). This test walks the WHOLE host-truth DVD lifecycle through GetDvdDrives
    # so the fake now exercises the same collection seam the real backend uses end to end.
    It 'walks the seed through the host-truth GetDvdDrives collection: attach->1, seal->0, re-attach->gate throws *DVD*' {
        $d = New-SandboxVM -Profile $script:Tier1Seed -Name 'sbx-seed-hosttruth' -Backend $script:B
        Add-SandboxSeed -Descriptor $d -SeedIso $script:Tier1Seed['SeedIso'] -Backend $script:B

        # Host truth BEFORE the seal: the seed is the one disc in the DVD slot (read as a collection).
        $before = & $script:B.GetDvdDrives @{ VMName = 'sbx-seed-hosttruth' }
        $before.Count | Should -Be 1 -Because 'the seed is attached at first boot; host-truth GetDvdDrives reports it'
        $before[0] | Should -Be $script:SeedIso

        # The seal must EJECT it — read host truth again (the gate''s authority, not the GetVM scalar).
        Lock-Sandbox -Descriptor $d -Backend $script:B
        (& $script:B.GetDvdDrives @{ VMName = 'sbx-seed-hosttruth' }).Count |
            Should -Be 0 -Because 'the seal detaches the seed; host-truth GetDvdDrives now reports NO attached DVD'
        { Assert-Sealed -Descriptor $d -Backend $script:B } |
            Should -Not -Throw -Because 'with the seed ejected (host-verified via GetDvdDrives) the gate certifies'

        # Re-attach post-seal -> host truth shows 1 again -> the gate MUST refuse on *DVD*.
        & $script:B.SetDvdDrive @{ VMName = 'sbx-seed-hosttruth'; Path = $script:SeedIso }
        (& $script:B.GetDvdDrives @{ VMName = 'sbx-seed-hosttruth' }).Count |
            Should -Be 1 -Because 'the re-attached seed is host-visible again'
        { Assert-Sealed -Descriptor $d -Backend $script:B } |
            Should -Throw -ExpectedMessage '*DVD*' -Because 'the gate reads host-truth DVD state via GetDvdDrives; a still-attached seed fails it'
    }
}

# ===========================================================================
#  PART A — a profile WITHOUT SeedIso behaves exactly as today (no regression)
# ===========================================================================
Describe 'Part A — a profile WITHOUT a SeedIso behaves exactly as before (no DVD attached at provision)' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        $script:Workload = & $script:NewWorkload -Tag 'noseed'
        $script:Art  = Join-Path $script:TmpRoot ("art-noseed-{0}" -f ([guid]::NewGuid().ToString('N')))
        $script:Dest = Join-Path $script:TmpRoot ("dest-noseed-{0}" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'no SeedIso -> no DVD attached at provision (the existing behavior is unchanged)' {
        $d = New-SandboxVM -Profile $script:Tier1 -Name 'sbx-noseed-attach' -Backend $script:B
        # The orchestrator would call Add-SandboxSeed only when SeedIso is present; with a tier
        # profile that declares none, the helper is a no-op given a $null/blank seed.
        Add-SandboxSeed -Descriptor $d -SeedIso ([string]$null) -Backend $script:B
        (& $script:B.GetVM @{ Name = 'sbx-noseed-attach' }).DvdDrive |
            Should -BeNullOrEmpty -Because 'with no SeedIso the boot DVD slot stays empty, exactly as today'
        $d.PSObject.Properties['SeedIso'] | Should -BeNullOrEmpty -Because 'no seed recorded when none is declared'
    }

    It 'a full deploy with no SeedIso still traverses INIT..DESTROYED' {
        $report = Invoke-Voidseal -Tier 1 -Profile $script:Tier1 -Workload $script:Workload `
            -Name 'sbx-noseed-full' -ArtifactRoot $script:Art -Destination $script:Dest -Backend $script:B
        @($report.States)[-1] | Should -Be 'DESTROYED' -Because 'the no-seed lifecycle is the existing happy path'
        $report.Error | Should -BeNullOrEmpty
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
        $ralph.ContainsKey('SeedIso') | Should -BeTrue -Because 'ralph needs a cloud-init seed for serial-getty autologin on first boot'
        [string]$ralph['SeedIso'] | Should -Match '(?i)cidata-seed\.iso' -Because 'the smoke-test seed path'
    }

    It 'firefox.psd1 declares a SeedIso and merges cleanly' {
        $firefox = Import-WorkloadProfile -Path $script:FirefoxPath -TierProfileDir $script:TierDir
        $firefox.ContainsKey('SeedIso') | Should -BeTrue -Because 'firefox needs a cloud-init seed for first-boot config'
        [string]$firefox['SeedIso'] | Should -Match '(?i)cidata-seed\.iso' -Because 'the smoke-test seed path'
    }
}
