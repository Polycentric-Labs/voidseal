<#
.SYNOPSIS
    Voidseal — Invoke-Voidseal, the top-level lifecycle orchestrator.

.DESCRIPTION
    Wires the lifecycle state machine end-to-end, binding the lower components:

        INIT -> PROVISIONED -> STAGED -> SEALED -> RUNNING -> CAPTURED -> EXTRACTED -> DESTROYED

      INIT        load + validate the tier/workload profile (Import-TierProfile / a passed
                  normalized profile). Fail-closed on a bad/unknown profile.
      PROVISIONED New-SandboxVM — create the substrate from the profile.
      STAGED      Import-SandboxAsset for any StageAssets the profile declares (one-way IN,
                  BEFORE the seal). With nothing to stage this is a recorded no-op transition.
      SEALED      Lock-Sandbox then Assert-Sealed as a **HARD GATE**. If Assert-Sealed
                  THROWS, the deploy ABORTS here: the workload-run state is NEVER reached, and the
                  VM is torn down. A profile that fails the seal gate must never run its workload.
      RUNNING     Start-SandboxWorkload — start the (sealed) VM + deliver the entrypoint over
                  the COM1 serial seam + arm host-side capture.
      CAPTURED    the run-result + its host-side capture artifact are recorded (out-of-band).
      EXTRACTED   Export-SandboxArtifact — one-way OUT. Tier 0/1: a trusting host-read of the
                  workload's emitted result. Tier >= 2: routes to the quarantine stub (THROWS).
      DESTROYED   Remove-Sandbox — stop + unregister + delete the created disks. ALWAYS runs
                  (teardown is in a finally), so a mid-flow failure leaves NO orphaned VM/disk/switch.

    EVERYTHING that touches Hyper-V goes through the backend abstraction; this orchestrator and
    every component it calls NEVER touch a raw Hyper-V cmdlet. Tests inject `-Backend (New-FakeHyperVBackend)`
    and assert against the returned report + the fake's in-memory state.

    FAILURE MODEL: input-validation errors (bad tier, missing profile) THROW. A failure DURING the
    lifecycle (seal-gate refusal, a mid-flow exception) is CAUGHT, recorded on the report (.Error +
    .SealVerdict), teardown is run, and the report is RETURNED (not rethrown) so the caller always
    gets a structured account of how far the deploy got and that it cleaned up after itself.

    RETURNS a run report [pscustomobject]:
        States            the states actually traversed, in order (e.g. up to DESTROYED on success,
                          or stopping before RUNNING on a seal-gate abort).
        SealVerdict       $true if Assert-Sealed certified the VM; $false if the gate failed.
        RunResult         the Start-SandboxWorkload result (VMName/ExitCode/CapturePath/...) or $null
                          if the workload never ran.
        ExtractedArtifact the host-side path(s) the Extractor wrote, or $null.
        TeardownStatus    a human string recording the teardown outcome.
        Error             the failure message if the deploy aborted; $null on full success.
        Name / Tier       the VM name + tier for cross-reference.
#>

Set-StrictMode -Version Latest

# --------------------------------------------------------------------------
# Dot-source the engine. This script is the entry point; it pulls in
# the backend + the loader + the Provisioner/Reaper + the Sealer/gate
# + the Runner/Extractor. Resolve paths relative to THIS file so it works
# from any working directory.
# --------------------------------------------------------------------------
$script:DeployLibDir = Join-Path $PSScriptRoot 'lib'
. (Join-Path $script:DeployLibDir 'HyperVBackend.ps1')
. (Join-Path $script:DeployLibDir 'ProfileLoader.ps1')
. (Join-Path $script:DeployLibDir 'Provisioner.ps1')
. (Join-Path $script:DeployLibDir 'Sealer.ps1')
. (Join-Path $script:DeployLibDir 'Runner.ps1')
. (Join-Path $script:DeployLibDir 'Workload.ps1')
. (Join-Path $script:DeployLibDir 'SeedBuilder.ps1')
. (Join-Path $script:DeployLibDir 'SensitivityGate.ps1')

# --------------------------------------------------------------------------
# Fold-in #1: Resolve-PythonExe — robust host python3/python resolution.
#
# A hard `& python3` BREAKS the Windows host: the Windows Python installer provides
# `python`, not `python3`. The in-guest binary is `python3` (Debian), but the HOST
# shelling `host/read_outbox.py` at the seam-#2 gate is Windows PowerShell, which
# needs the Windows `python` executable. Get-Command probes both names; throw fail-
# closed naming both if NEITHER resolves (prefer python3 on non-Windows for safety).
# --------------------------------------------------------------------------
<#
.SYNOPSIS
    Resolve the host Python executable path (python3 preferred, python fallback).
.DESCRIPTION
    A hard `& python3` breaks on Windows hosts where the Python installer provides
    `python`. This probes both names via Get-Command and returns the resolved path.
    Throws a clear fail-closed message naming both candidates if neither resolves.
#>
function Resolve-PythonExe {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $cmd = Get-Command python3 -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }

    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($null -ne $cmd) { return $cmd.Source }

    throw ("Resolve-PythonExe: neither 'python3' nor 'python' was found on PATH. " +
           "Install Python and ensure it is on the PATH (Windows: the Python installer " +
           "adds 'python'; Linux/macOS: 'python3'). Failing closed.")
}

# --------------------------------------------------------------------------
# Internal: resolve the -Profile argument to a normalized profile hashtable (loader output).
# --------------------------------------------------------------------------
<#
.SYNOPSIS
    Resolve -Profile (a normalized hashtable | a .psd1 path | a bare tier/workload name) +
    the -Tier hint into a validated, normalized profile hashtable. Fail-closed.
.DESCRIPTION
    Accepts, in priority order:
      * an already-normalized [hashtable] (e.g. a test fixture or a caller-built profile) — re-validated;
      * a path to a .psd1 file — loaded as a tier profile (Import-TierProfile) if it sits in a
        tier-profiles dir / is named tierN.psd1, else as a workload profile (Import-WorkloadProfile);
      * a bare NAME — resolved against the skill's tier-profiles/ (tier<Tier>.psd1 when the name looks
        like 'tierN' or matches the -Tier hint) or profiles/<name>.psd1 (a workload profile).
.PARAMETER Profile
    The -Profile argument (hashtable | path | name).
.PARAMETER Tier
    The -Tier hint (0..3), used to locate a tier file when a bare name is ambiguous.
.PARAMETER TierProfileDir
    The tier-profiles directory (defaults to <skillroot>/tier-profiles).
.PARAMETER WorkloadProfileDir
    The workload profiles directory (defaults to <skillroot>/profiles).
#>
function Resolve-DeployProfile {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Profile,
        [Parameter(Mandatory)] [int] $Tier,
        [string] $TierProfileDir,
        [string] $WorkloadProfileDir
    )

    if ($null -eq $Profile) {
        throw "Invoke-Voidseal: -Profile is null. Pass a tier/workload profile name, a .psd1 path, or a normalized profile hashtable."
    }

    # Default the profile dirs relative to this script's skill root (<skillroot>/scripts -> <skillroot>).
    $skillRoot = Split-Path -Parent $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($TierProfileDir))     { $TierProfileDir     = Join-Path $skillRoot 'tier-profiles' }
    if ([string]::IsNullOrWhiteSpace($WorkloadProfileDir)) { $WorkloadProfileDir = Join-Path $skillRoot 'profiles' }

    # 1) Already a normalized hashtable -> re-validate (defense in depth) + return.
    if ($Profile -is [System.Collections.IDictionary]) {
        $clone = @{}
        foreach ($k in $Profile.Keys) { $clone[$k] = $Profile[$k] }
        Assert-TierProfileValid -Profile $clone -Context 'Invoke-Voidseal -Profile (hashtable)'
        return $clone
    }

    $name = [string]$Profile

    # 2) A path to an existing .psd1.
    if ($name -match '\.psd1$' -or (Test-Path -LiteralPath $name -PathType Leaf)) {
        if (-not (Test-Path -LiteralPath $name -PathType Leaf)) {
            throw "Invoke-Voidseal: -Profile path '$name' does not exist (fail closed)."
        }
        $leaf = [System.IO.Path]::GetFileName($name)
        if ($leaf -match '^tier\d+\.psd1$') {
            return (Import-TierProfile -Path $name)
        }
        # Treat any other .psd1 as a workload profile (it declares BaseTier).
        return (Import-WorkloadProfile -Path $name -TierProfileDir $TierProfileDir)
    }

    # 3) A bare name. 'tierN' (or a name equal to the tier hint) -> the tier file; else a workload profile.
    if ($name -match '^tier(\d+)$') {
        $tierFile = Join-Path $TierProfileDir ("{0}.psd1" -f $name)
        if (-not (Test-Path -LiteralPath $tierFile -PathType Leaf)) {
            throw "Invoke-Voidseal: tier profile '$name' resolves to no file (expected '$tierFile')."
        }
        return (Import-TierProfile -Path $tierFile)
    }

    $wlFile = Join-Path $WorkloadProfileDir ("{0}.psd1" -f $name)
    if (Test-Path -LiteralPath $wlFile -PathType Leaf) {
        return (Import-WorkloadProfile -Path $wlFile -TierProfileDir $TierProfileDir)
    }

    # Fall back to a tier file named by the -Tier hint, then give up.
    $tierFile = Join-Path $TierProfileDir ("tier{0}.psd1" -f $Tier)
    if (Test-Path -LiteralPath $tierFile -PathType Leaf) {
        return (Import-TierProfile -Path $tierFile)
    }

    throw "Invoke-Voidseal: could not resolve -Profile '$name' to a tier profile or a workload profile (looked in '$TierProfileDir' and '$WorkloadProfileDir')."
}

# --------------------------------------------------------------------------
# Internal: read a field off a workload spec hashtable with a default.
# --------------------------------------------------------------------------
function Get-WorkloadField {
    [CmdletBinding()]
    param([AllowNull()] $Workload, [Parameter(Mandatory)] [string] $Name, $Default = $null)
    if ($null -eq $Workload) { return $Default }
    if ($Workload -is [System.Collections.IDictionary]) {
        if ($Workload.Contains($Name) -and $null -ne $Workload[$Name]) { return $Workload[$Name] }
        return $Default
    }
    $prop = $Workload.PSObject.Properties[$Name]
    if ($null -ne $prop -and $null -ne $prop.Value) { return $prop.Value }
    return $Default
}

# --------------------------------------------------------------------------
# Public: Invoke-Voidseal  (the orchestrator)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Run the full provision -> stage -> seal(+gate) -> run -> capture -> extract -> destroy lifecycle
    for a risk-tiered sandbox VM. Returns a structured run report. See the file header for the model.
.PARAMETER Tier
    The risk tier (0..3). Used to locate a tier profile when -Profile is a bare/ambiguous name and
    cross-checked against the resolved profile's own Tier.
.PARAMETER Profile
    A tier/workload profile NAME, a .psd1 PATH, or an already-normalized profile HASHTABLE.
.PARAMETER Workload
    (Optional) the workload spec. Two modes:
      * SERIAL (default): @{ Entrypoint=<cmd>; ResultPath=<host-readable artifact> [; Name] }. The
        entrypoint is delivered over the COM1 serial seam and ResultPath is the Tier-0/1 emitted
        artifact the Extractor collects. Entrypoint may also come from a workload profile's Entrypoint.
        With no workload + no profile Entrypoint, RUNNING/CAPTURED/EXTRACTED are skipped (provision ->
        seal -> destroy only).
      * DISK: @{ WorkloadMode='Disk' [; ResultInnerName='result.html'] [; SentinelInnerName='result.exitcode'] }.
        The guest runs off its SEED at boot, writes its result + an exit-code sentinel onto the OUTPUT
        data disk, and self-powers-off; the host detaches the data disks then reads + classifies the
        result (Read-WorkloadResult). WorkloadMode also resolves from the profile (firefox.psd1 declares
        WorkloadMode='Disk'). The ResultInnerName/SentinelInnerName default to the cloud-init runner's
        emitted names (result.html / result.exitcode).
.PARAMETER Name
    (Optional) the VM name. Defaults to a unique 'sbx-<tier>-<rand>'.
.PARAMETER ArtifactRoot
    (Optional) host-side dir for the Runner's capture artifact. Defaults under the system temp path.
.PARAMETER Destination
    (Optional) host-side dir the Extractor copies the result into (Tier 0/1). Defaults under ArtifactRoot.
.PARAMETER ParentDiskPath
    (Optional) a golden base .vhdx (passed to New-SandboxVM for a differencing system disk).
.PARAMETER BootWaitSeconds
    (Optional) the guest BOOT-READINESS deadline passed to Start-SandboxWorkload — how long the
    Runner probes the serial console for readiness before delivering the entrypoint (a FIRST cloud-init
    boot off a fresh differencing disk needs ~90-180s; a live run timed out at 60s). Default 180. Tests
    inject 0 (a single instant probe) so they never sleep.
.PARAMETER BootPollDelaySeconds
    (Optional) seconds between failed boot-readiness probe attempts (default 5; tests inject 0).
    Also reused as the POLL cadence for the Disk-mode completion wait (Wait-WorkloadComplete) — how
    long between VM-State polls while waiting for the guest to self-power-off (tests inject 0).
.PARAMETER WorkloadTimeoutSeconds
    (Optional, Disk mode) the wall-clock deadline for the self-power-off completion wait. In Disk
    mode the guest runs its boot workload then powers ITSELF off; the host polls VM State until Off or
    this deadline fires (Wait-WorkloadComplete force-stops a hung guest on timeout). Default 600. Tests
    inject 0 (one instant poll then trip the deadline) so they never sleep. Unused by Serial mode.
.PARAMETER Backend
    The Hyper-V backend. Defaults to the real one; tests inject the fake.
#>
function Invoke-Voidseal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [int] $Tier,
        [Parameter(Mandatory)] [AllowNull()] $Profile,
        $Workload,
        [string] $Name,
        [string] $ArtifactRoot,
        [string] $Destination,
        [string] $ParentDiskPath,
        [int]    $BootWaitSeconds = 180,
        [int]    $BootPollDelaySeconds = 5,
        [int]    $WorkloadTimeoutSeconds = 600,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    # --- input validation (these THROW — they are caller errors, not lifecycle failures) ----
    if ($Tier -lt 0 -or $Tier -gt 3) {
        throw "Invoke-Voidseal: -Tier must be in range 0..3 (got $Tier)."
    }

    # Resolve + validate the profile up front (INIT). A bad/unknown profile is a caller error -> throw.
    $resolved = Resolve-DeployProfile -Profile $Profile -Tier $Tier

    # Cross-check the resolved tier against the -Tier hint (a mismatch is a caller error).
    $profileTier = [int]$resolved['Tier']
    if ($profileTier -ne $Tier) {
        throw "Invoke-Voidseal: -Tier $Tier does not match the resolved profile's Tier $profileTier. Pass a consistent tier."
    }

    if ([string]::IsNullOrWhiteSpace($Name)) {
        $Name = "sbx-{0}-{1}" -f $Tier, ([guid]::NewGuid().ToString('N').Substring(0, 8))
    }
    if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
        $ArtifactRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("Voidseal\artifacts\{0}" -f $Name)
    }
    if ([string]::IsNullOrWhiteSpace($Destination)) {
        $Destination = Join-Path $ArtifactRoot 'extracted'
    }

    # The entrypoint: prefer the workload spec, fall back to a workload profile's Entrypoint.
    $entrypoint = [string](Get-WorkloadField -Workload $Workload -Name 'Entrypoint')
    if ([string]::IsNullOrWhiteSpace($entrypoint) -and $resolved.ContainsKey('Entrypoint')) {
        $entrypoint = [string]$resolved['Entrypoint']
    }
    $resultPath = [string](Get-WorkloadField -Workload $Workload -Name 'ResultPath')

    # --- workload MODE: 'Serial' (the default serial-seam path) or 'Disk' (the data-disk path) ---
    # Resolve from the -Workload spec first, then the resolved profile's WorkloadMode (a workload profile
    # like firefox.psd1 declares WorkloadMode='Disk'), defaulting to 'Serial' so every existing profile
    # keeps the unchanged Serial behavior. The Disk-mode result/sentinel INNER names flow from -Workload
    # (defaults match the cloud-init runner's emitted names: result.html + result.exitcode).
    $workloadMode = [string](Get-WorkloadField -Workload $Workload -Name 'WorkloadMode')
    if ([string]::IsNullOrWhiteSpace($workloadMode) -and $resolved.ContainsKey('WorkloadMode')) {
        $workloadMode = [string]$resolved['WorkloadMode']
    }
    if ([string]::IsNullOrWhiteSpace($workloadMode)) { $workloadMode = 'Serial' }
    $resultInnerName   = [string](Get-WorkloadField -Workload $Workload -Name 'ResultInnerName'   -Default 'result.html')
    $sentinelInnerName = [string](Get-WorkloadField -Workload $Workload -Name 'SentinelInnerName' -Default 'result.exitcode')

    # --- the report, built up as we traverse ----------------------------
    $states     = [System.Collections.Generic.List[string]]::new()
    $report = [pscustomobject]@{
        Name              = $Name
        Tier              = $Tier
        States            = @()
        SealVerdict       = $false
        RunResult         = $null
        ExtractedArtifact = $null
        TeardownStatus    = '(not run)'
        Error             = $null
        Descriptor        = $null
        # Processor-workload Sensitivity Gate outputs (set only when the post-detach gate runs — see
        # the Disk-mode RUNNING block). Released/Held are arrays of the screener's per-file verdict
        # objects (auto-certified-SAFE vs held-for-review); SensitivityReport is the host path to the
        # gate's sensitivity-report.json. They stay $null for a non-processor deploy (the gate did not
        # run). GateRan (the boolean fact that the gate executed) lives on the DESCRIPTOR, not here.
        Released          = $null
        Held              = $null
        SensitivityReport = $null
    }

    $descriptor = $null
    $states.Add('INIT')

    try {
        # --- PROVISIONED ---------------------------------------------------
        $provArgs = @{ Profile = $resolved; Name = $Name; Backend = $Backend }
        if (-not [string]::IsNullOrWhiteSpace($ParentDiskPath)) { $provArgs.ParentDiskPath = $ParentDiskPath }
        $descriptor = New-SandboxVM @provArgs
        $report.Descriptor = $descriptor
        $states.Add('PROVISIONED')

        # --- STAGED: one-way asset import BEFORE the seal ------------------
        # Import every StageAssets entry the profile declares (host source -> in-guest). The loader
        # already refused any secret-shaped source, so staging cannot smuggle a secret in. With no
        # StageAssets this is a recorded no-op transition (the state is still traversed).
        $seedIso       = if ($resolved.ContainsKey('SeedIso')) { [string]$resolved['SeedIso'] } else { $null }
        $hasSeed       = -not [string]::IsNullOrWhiteSpace($seedIso)
        $stageIsoCount = 0
        if ($resolved.ContainsKey('StageAssets') -and $resolved['StageAssets'] -is [System.Collections.IDictionary]) {
            foreach ($src in @($resolved['StageAssets'].Keys)) {
                # StageAssets values describe how to attach; default to a read-only ISO import.
                Import-SandboxAsset -Descriptor $descriptor -Source ([string]$src) -As Iso -Backend $Backend
                $stageIsoCount++
            }
        }

        # --- the cloud-init NoCloud SEED: how it is delivered depends on the workload MODE -----
        # SERIAL mode: the seed is the BOOT-CONFIG DVD cloud-init consumes on the guest's first boot
        #   (serial-getty autologin on ttyS0 = the Runner's command channel, run-user, packages). It is
        #   the disc in the single DVD slot at boot, attached AFTER any StageAssets ISO. DVD-SLOT CAVEAT:
        #   the backend models ONE DVD slot — a StageAssets ISO that must COEXIST with the seed cannot
        #   share it and must be a transfer-VHD. Warn when both ISOs are present so the live run knows the
        #   seed took the boot DVD. The seed rides the import-only path, so the seal ejects it and
        #   Assert-Sealed verifies it is gone.
        # DISK mode (RC6): the seal EJECTS the seed DVD before the guest's ONLY boot, so a DVD seed never
        #   survives to the boot cloud-init reads it on. Instead the seed rides a recorded CIDATA DATA
        #   DISK (New-WorkloadSeedDisk, built below alongside the INPUT/OUTPUT disks) that survives the
        #   seal. So in disk mode we do NOT call Add-SandboxSeed (the DVD path) and emit NO dual-DVD
        #   warning — the seed is not a DVD here.
        if ($workloadMode -ne 'Disk' -and $hasSeed) {
            if ($stageIsoCount -gt 0) {
                Write-Warning ("Invoke-Voidseal: '$Name' declares BOTH a SeedIso and $stageIsoCount StageAssets ISO(s). " +
                    "The backend has a single DVD slot; the SeedIso takes the boot DVD. A StageAssets ISO that must " +
                    "coexist with the seed at boot should be a transfer-VHD for the live run.")
            }
            Add-SandboxSeed -Descriptor $descriptor -SeedIso $seedIso -Backend $Backend
        }

        # --- Disk-mode: create + attach + RECORD the workload data disks (+ the CIDATA seed disk) BEFORE the seal ---
        # The INPUT/OUTPUT data disks must be attached AND recorded on the descriptor (InputDiskPath/
        # OutputDiskPath) BEFORE Lock-Sandbox so Assert-Sealed's host-truth scan accepts them as known
        # data disks (an UNRECORDED attached disk fails the seal gate). Use the SAME storage root the
        # provisioner derives for the system disk (Get-SandboxStorageRoot -Name $Name) so the data disks
        # land beside it and the Reaper's storage-root cleanup covers them. Serial mode skips this.
        if ($workloadMode -eq 'Disk') {
            # Allow -Workload.Inputs to override/populate the profile's Inputs (innerName -> content), so a
            # live run can inject the organizer script + sample at deploy time without editing the static
            # .psd1 (firefox.psd1 ships Inputs={} on purpose; InputFiles documents the host sources). The
            # orchestrator otherwise consumes -Workload only for SCALARS (WorkloadMode/ResultInnerName/...),
            # so WITHOUT this fold the documented `Invoke-Voidseal -Workload @{ Inputs=$inputs }` snippet is
            # silently dropped -> New-WorkloadDisks (which reads $Profile['Inputs']) populates an EMPTY INPUT
            # disk -> no organizer in the guest -> the workload fails every live run. $resolved is a mutable
            # hashtable (Resolve-DeployProfile clones it), so set the key in place; the override wins over a
            # profile-declared Inputs by design (deploy-time injection is the documented live-run path).
            $workloadInputs = Get-WorkloadField -Workload $Workload -Name 'Inputs'
            if ($null -ne $workloadInputs -and $workloadInputs -is [System.Collections.IDictionary] -and $workloadInputs.Count -gt 0) {
                $resolved['Inputs'] = $workloadInputs
            }

            $diskStorageRoot = Get-SandboxStorageRoot -Name $Name
            # New-WorkloadDisks now RECORDS each data disk on the descriptor INCREMENTALLY (its path
            # field AND a deduped append to CreatedDisks) right after it is created — so the INPUT/
            # OUTPUT VHDX files are on CreatedDisks for the Reaper's -DeleteDisks pass, and a mid-
            # creation throw still leaves the already-created disk recorded for cleanup (orphan-window
            # fix). The orchestrator therefore no longer needs to fold the data disks into CreatedDisks
            # here — that fold moved into New-WorkloadDisks (which dedupes against the provisioner's
            # system disk). Just refresh $report.Descriptor with the mutated descriptor.
            $descriptor = New-WorkloadDisks -Descriptor $descriptor -Profile $resolved `
                -StorageRoot $diskStorageRoot -Backend $Backend
            $report.Descriptor = $descriptor

            # RC6: the CIDATA seed DATA DISK — built from the resolved profile's Entrypoint (the disk-mode
            # runner) and recorded on the descriptor (SeedDiskPath + CreatedDisks) so it survives the seal
            # and is cleaned up at teardown. Only built when there IS an entrypoint to run (the disk-mode
            # seed carries the workload runner; with no entrypoint there is nothing to seed — the bare
            # mock fixtures, like a no-entrypoint serial run, skip this). New-CidataUserData fails closed
            # on a bad entrypoint, so a rejected one aborts here (caught by the outer catch + teardown).
            if (-not [string]::IsNullOrWhiteSpace($entrypoint)) {
                # Fold the EFFECTIVE entrypoint (a -Workload.Entrypoint override beats the profile's) onto
                # $resolved so New-WorkloadSeedDisk -> New-CidataUserData substitutes the right command into
                # the disk-mode runner. Mirrors the -Workload.Inputs fold above; $resolved is the mutable
                # clone Resolve-DeployProfile returned.
                $resolved['Entrypoint'] = $entrypoint
                $descriptor = New-WorkloadSeedDisk -Descriptor $descriptor -Profile $resolved `
                    -StorageRoot $diskStorageRoot -Backend $Backend
                $report.Descriptor = $descriptor
            }

            # --- PROCESSOR: attach + RECORD the DEPS disk BEFORE the seal -------------------------
            # A processor profile (Network='None') runs against a pre-built, read-only DEPENDENCY disk.
            # PHASE-1 ONLY: the deps.vhdx is a fixture supplied via -Workload.DepsDiskPath (or the resolved
            # profile's DepsDiskPath); PHASE-2 (real): the builder produces deps.vhdx and hands its path in.
            # Like the INPUT/OUTPUT/SeedDisk data disks, it must be
            # ATTACHED and RECORDED (DepsDiskPath) on the descriptor BEFORE Lock-Sandbox so Assert-Sealed's
            # host-truth scan ACCEPTS it as an expected disk — an UNRECORDED extra attached disk fails the
            # seal gate as a residual. We attach via the existing AddHardDiskDrive (no read-only attach:
            # Hyper-V cannot host-enforce a read-only VHDX — D3). The DEPS disk is the BUILDER's pre-
            # existing file, so it is NOT added to CreatedDisks (we did not create it; teardown's
            # Remove-Sandbox detaches it by removing the VM, but the deps.vhdx FILE is left on disk).
            $depsDiskPath = [string](Get-WorkloadField -Workload $Workload -Name 'DepsDiskPath')
            if ([string]::IsNullOrWhiteSpace($depsDiskPath) -and $resolved.ContainsKey('DepsDiskPath')) { $depsDiskPath = [string]$resolved['DepsDiskPath'] }
            if ($resolved['Network'] -eq 'None' -and -not [string]::IsNullOrWhiteSpace($depsDiskPath)) {
                $null = & $Backend.AddHardDiskDrive @{ VMName = $Name; Path = $depsDiskPath }   # existing method; no read-only attach (D3)
                Set-DescriptorField -Descriptor $descriptor -Name 'DepsDiskPath' -Value $depsDiskPath
                $report.Descriptor = $descriptor
            }
        }
        $states.Add('STAGED')

        # --- SEALED: cut to the tier's isolation, THEN the HARD GATE -------
        Lock-Sandbox -Descriptor $descriptor -Backend $Backend

        # Assert-Sealed is the MANDATORY gate before RUNNING. It is host-verified + fails closed. If
        # it THROWS, we do NOT catch-and-continue — we let it propagate to the outer catch, which
        # records the seal failure and runs teardown. The workload-run state is unreachable on failure.
        $sealOk = Assert-Sealed -Descriptor $descriptor -Backend $Backend
        $report.SealVerdict = [bool]$sealOk
        # Belt-and-braces (defense-in-depth): today Assert-Sealed is throw-only, so reaching here means
        # the gate certified. But if a FUTURE refactor ever made it RETURN $false instead of throwing,
        # this explicit verdict gate ensures the workload still cannot run on an uncertified VM. We throw
        # into the same outer catch (records the failure + tears down), exactly as a thrown gate would.
        if (-not $sealOk) {
            throw "Invoke-Voidseal: seal gate did not certify '$Name' (Assert-Sealed returned a non-true verdict); refusing to run the workload."
        }
        $states.Add('SEALED')

        # --- RUNNING / CAPTURED / EXTRACTED -------------------------------
        if ($workloadMode -eq 'Disk') {
            # DISK MODE: the guest runs its boot workload off the SEED, writes its result + an
            # exit-code sentinel onto the OUTPUT data disk, then powers ITSELF off. There is NO live
            # control channel (the Sealer severed them), so the host learns completion by POLLING VM
            # State until Off (Wait-WorkloadComplete) — or until WorkloadTimeoutSeconds force-stops a
            # hung guest. Then the host DETACHES the data disks (VM is Off) and reads + classifies the
            # result off the OUTPUT volume.
            $null = & $Backend.StartVM @{ Name = $Name }
            $states.Add('RUNNING')
            $wait = Wait-WorkloadComplete -Descriptor $descriptor -Backend $Backend `
                        -TimeoutSeconds $WorkloadTimeoutSeconds -PollDelaySeconds $BootPollDelaySeconds
            $states.Add('CAPTURED')
            # Detach the data disks BEFORE the host reads the output (VM is Off, or force-stopped on
            # timeout). The host must not read a disk still attached to a (potentially live) guest.
            # A transient real-Hyper-V Remove-VMHardDiskDrive failure right after a force-stop (VM still
            # settling / slot already detached) must NOT propagate to the outer catch — that would record
            # a lifecycle .Error and mis-report a SUCCESSFUL guest run as a hard abort, sending the
            # operator hunting a guest bug that doesn't exist. Catch here: record a Failed run and SKIP
            # the read (never read a disk that may still be attached to a not-fully-stopped guest).
            # Teardown (the finally) still force-stops + deletes, so nothing leaks.
            $detachOk = $true
            try {
                if ($descriptor.InputDiskPath)  { $null = & $Backend.RemoveHardDiskDrive @{ VMName = $Name; Path = $descriptor.InputDiskPath } }
                if ($descriptor.OutputDiskPath) { $null = & $Backend.RemoveHardDiskDrive @{ VMName = $Name; Path = $descriptor.OutputDiskPath } }
            } catch {
                $detachOk = $false
                $report.RunResult = @{ Status = 'Failed'; ExitCode = -1; ArtifactPath = $null; Reason = "data-disk detach failed: $($_.Exception.Message)" }
            }
            if ($detachOk -and -not $wait.TimedOut) {
                # Tier>=2 Read-WorkloadResult THROWS (quarantine NotImplemented) — try/catch so a gated
                # hostile-tier read is reported as a failed run, not an unhandled crash that aborts the
                # whole deploy. The seal/teardown invariants are unaffected either way.
                try {
                    $runResult = Read-WorkloadResult -Descriptor $descriptor -Destination $Destination `
                                    -ResultInnerName $resultInnerName -SentinelInnerName $sentinelInnerName -Backend $Backend
                } catch {
                    $runResult = @{ Status = 'Failed'; ExitCode = -1; ArtifactPath = $null; Reason = "result read failed: $($_.Exception.Message)" }
                }
                $report.RunResult = $runResult
                if ($runResult.ArtifactPath) { $report.ExtractedArtifact = $runResult.ArtifactPath }
                $states.Add('EXTRACTED')
            } elseif ($detachOk) {
                # The guest never self-powered-off within the deadline (hung/runaway). Wait-WorkloadComplete
                # already force-stopped it so the Reaper inherits a clean Off VM. Record a failed run; do
                # NOT read the output disk of a workload that did not signal completion.
                $report.RunResult = @{ Status = 'Failed'; ExitCode = -1; ArtifactPath = $null; Reason = 'boot/workload timed out' }
            }
            # (detach failed -> RunResult already set above; EXTRACTED intentionally not reached)

            # --- POST-DETACH SENSITIVITY GATE (processor workloads) -------------------
            # The in-guest screener wrote candidates + verdicts.json as a memory-safe "outbox" onto the
            # OUTPUT disk's raw region. Now that OUTPUT is DETACHED, read it in USER-SPACE (ReadVhdxRawRegion
            # = qemu-img slice; NEVER Mount-VHD) and parse it fail-closed (read_outbox.py), then the EXISTING
            # gate partitions only auto-certified-SAFE artifacts. DENY-on-timeout/failed-run EXPLICIT: the
            # gate runs ONLY after a clean detach AND a non-timed-out run — a timed-out/force-stopped guest
            # released NOTHING. The $detachOk guard stays load-bearing (never read a disk still attached to a
            # possibly-live guest). (Phase-2/4 repoints the read at the dedicated FIXED raw outbox disk.)
            if ($detachOk -and -not $wait.TimedOut -and $resolved['Network'] -eq 'None' -and $resolved.ContainsKey('ScreenConfig')) {
                $gateInput = Join-Path $Destination 'gate-input'
                try {
                    $outboxPath = [string]$descriptor.OutputDiskPath
                    if ([string]::IsNullOrWhiteSpace($outboxPath)) { throw 'processor gate: no OUTPUT disk to read the outbox from.' }
                    # Two-phase user-space read: probe the 24-byte header for the exact blob length, then read exactly that.
                    $hdr = [byte[]](& $Backend.ReadVhdxRawRegion @{ Path = $outboxPath; Offset = 0; Length = 24 })
                    if ($hdr.Length -lt 24 -or [System.Text.Encoding]::ASCII.GetString($hdr, 0, 8) -ne 'VSOUTBX1') {
                        throw 'processor gate: OUTPUT outbox header missing/!magic (empty base read? check AutomaticCheckpoints).'
                    }
                    $count = [System.BitConverter]::ToUInt32($hdr, 12)
                    $total = [System.BitConverter]::ToUInt64($hdr, 16)
                    if ($count -gt 256 -or $total -gt 67108864) { throw "processor gate: outbox header count/total over bound ($count/$total)." }
                    $exact = 24L + ([int64]$count * 104L) + [int64]$total
                    $blob  = [byte[]](& $Backend.ReadVhdxRawRegion @{ Path = $outboxPath; Offset = 0; Length = $exact })
                    # Bridge PS bytes -> read_outbox.py via a host temp file (binary stdin is fragile on Windows PowerShell).
                    $blobFile = Join-Path $Destination 'outbox.bin'
                    [System.IO.File]::WriteAllBytes($blobFile, $blob)
                    # Fold-in #1: use Resolve-PythonExe (robust host python3/python resolution).
                    # Fold-in #6: capture stderr so any read_outbox.py diagnostic is surfaced in
                    #             the throw message rather than silently swallowed.
                    # Outbox constants (single source of truth: guest/outbox.py):
                    #   MAGIC   = b'VSOUTBX1'  (8 bytes, offset 0)
                    #   Header  = 24 bytes     (MAGIC[8] + version[4] + count[4] + total_bytes[8])
                    #   Record  = 104 bytes    (label[64] + mime[32] + offset[4] + length[4])
                    $readScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'host/read_outbox.py'   # <repo>/host/read_outbox.py (see line ~103 skillRoot pattern)
                    $pyExe = Resolve-PythonExe
                    $pyOut = & $pyExe $readScript --blob $blobFile --out $gateInput 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        $pyStderr = ($pyOut | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
                                    ForEach-Object { $_.Exception.Message }) -join '; '
                        if ([string]::IsNullOrWhiteSpace($pyStderr)) {
                            # Capture any stdout lines as well (non-ErrorRecord items)
                            $pyStderr = ($pyOut | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join '; '
                        }
                        $stderrSuffix = if ([string]::IsNullOrWhiteSpace($pyStderr)) { '' } else { " stderr: $pyStderr" }
                        throw "processor gate: read_outbox.py failed (exit $LASTEXITCODE) — outbox invalid/tampered; releasing nothing.$stderrSuffix"
                    }
                    $gateStaging  = Join-Path $gateInput 'staging'
                    $gateVerdicts = Join-Path $gateInput 'verdicts.json'

                    $gateOut   = Join-Path $Destination 'gate'
                    $screenCfg = Resolve-ScreenConfig -Profile $resolved
                    $gateResult = Invoke-SensitivityGate -StagingDir $gateStaging -OutputDir $gateOut `
                                    -Mode $screenCfg.mode -VerdictsPath $gateVerdicts
                    Set-DescriptorField -Descriptor $descriptor -Name 'GateRan' -Value $true
                    $report.Descriptor        = $descriptor
                    $report.Released          = $gateResult.Released
                    $report.Held              = $gateResult.Held
                    $report.SensitivityReport = $gateResult.ManifestPath
                }
                catch {
                    # Fail-closed like the seal gate: record + let teardown run. APPEND (do not clobber a
                    # detach/read error already on $report.Error) so neither failure is lost.
                    $gateErr = "Sensitivity gate failed: $($_.Exception.Message)"
                    if ([string]::IsNullOrWhiteSpace([string]$report.Error)) { $report.Error = $gateErr }
                    else { $report.Error = "$($report.Error) | $gateErr" }
                    Write-Warning "Invoke-Voidseal: '$Name' sensitivity gate failed: $($_.Exception.Message)"
                }
            }
        }
        else {
            # SERIAL MODE (default): RUNNING/CAPTURED/EXTRACTED only when there is an entrypoint to deliver.
            if (-not [string]::IsNullOrWhiteSpace($entrypoint)) {
                # RUNNING: start the sealed VM, WAIT for boot-readiness (the first command must not race
                # cloud-init), deliver the entrypoint over the serial seam, and arm capture. The boot-wait is
                # injectable (tests pass 0 so they never sleep the real ~60s).
                $runResult = Start-SandboxWorkload -Descriptor $descriptor -Entrypoint $entrypoint `
                    -ArtifactRoot $ArtifactRoot -BootWaitSeconds $BootWaitSeconds `
                    -BootPollDelaySeconds $BootPollDelaySeconds -Backend $Backend
                $report.RunResult = $runResult
                $states.Add('RUNNING')

                # CAPTURED: the run-result + its out-of-band capture artifact are now recorded.
                $states.Add('CAPTURED')

                # EXTRACTED: one-way OUT. Tier 0/1 reads the emitted result; Tier >= 2 routes to the
                # quarantine stub (which THROWS — so a hostile-tier extraction aborts here, by design).
                if (-not [string]::IsNullOrWhiteSpace($resultPath)) {
                    $extracted = Export-SandboxArtifact -Descriptor $descriptor -ResultPath $resultPath `
                        -Destination $Destination -Backend $Backend
                    $report.ExtractedArtifact = $extracted
                    $states.Add('EXTRACTED')
                }
            }
        }
    }
    catch {
        # A lifecycle failure (seal-gate refusal or any mid-flow exception). Record it; do NOT rethrow
        # — the caller gets the report (how far we got + that teardown ran). SealVerdict already
        # reflects the gate outcome (still $false if we failed at/just-before SEALED).
        $report.Error = $_.Exception.Message
        Write-Warning "Invoke-Voidseal: aborting '$Name' after a lifecycle failure: $($_.Exception.Message)"
    }
    finally {
        # --- DESTROYED: teardown ALWAYS runs (no orphaned VM/disk/switch) --
        # Reuse Remove-Sandbox (idempotent: a no-op if the VM was never created / already gone).
        # -DeleteDisks targets the descriptor's CreatedDisks; pass the descriptor when we have one.
        try {
            if ($null -ne $descriptor) {
                Remove-Sandbox -Name $Name -DeleteDisks -Descriptor $descriptor -Backend $Backend
            }
            else {
                # No descriptor (provisioning never returned) — best-effort remove by name.
                Remove-Sandbox -Name $Name -Backend $Backend
            }
            # Only the FULL-success path records DESTROYED as a traversed state (it completed the
            # lifecycle). On an abort, teardown still runs but the state machine did not "reach"
            # DESTROYED as a normal transition — the report's TeardownStatus carries that fact.
            if ($null -eq $report.Error) { $states.Add('DESTROYED') }
            $report.TeardownStatus = 'OK (VM removed, created disks deleted)'
        }
        catch {
            $report.TeardownStatus = "FAILED: $($_.Exception.Message)"
            Write-Warning "Invoke-Voidseal: teardown of '$Name' failed: $($_.Exception.Message)"
        }
        $report.States = $states.ToArray()
    }

    return $report
}
