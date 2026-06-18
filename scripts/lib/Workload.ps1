<#
.SYNOPSIS
    Voidseal — Workload disks (disk-passing workload).

.DESCRIPTION
    Creates the two data disks a sandbox workload runs against and wires them onto the VM
    BEFORE the seal, then records their host-side paths on the sandbox descriptor:

        New-WorkloadDisks -Descriptor <descriptor> -Profile <hashtable> -StorageRoot <dir> [-Backend]

      * INPUT disk  — created + host-formatted (NewOutputVhdx), then POPULATED from the profile's
        `Inputs` map (innerPath -> content) via WriteVhdxFile, so the guest boots with its seed/
        input files already on a mountable, host-readable volume. Labelled INPUT by default.
      * OUTPUT disk — created + host-formatted (NewOutputVhdx), left EMPTY; the guest writes its
        results here and the host reads them back off the named OUTPUT volume after the seal.

    Both disks are ATTACHED to the VM (AddHardDiskDrive) BEFORE the Sealer runs — so the seal's
    host-truth scan records them as known data disks (Assert-Sealed accepts recorded data disks).
    The descriptor's InputDiskPath / OutputDiskPath fields carry the paths the Runner reads results
    from and the Reaper cleans up.

    EVERYTHING touches Hyper-V / the host disk through the backend (HyperVBackend.ps1) — this
    file NEVER calls a raw New-VHD / Format-Volume / Add-VMHardDiskDrive cmdlet. Dot-source this
    file AFTER HyperVBackend.ps1 + Provisioner.ps1.

    INJECTION: `-Backend <hashtable>` defaults to `(New-RealHyperVBackend)`; tests pass the fake.

    OUTPUT-STREAM DISCIPLINE (same class as the Provisioner's real-backend bug found during live debugging): every
    effect-only backend call is routed to `$null = & $Backend.X @{...}` so a real-backend object
    emission can't leak into this function's return stream. New-WorkloadDisks returns EXACTLY the
    (mutated) descriptor.

    FILESYSTEM / LABEL: the backend's NewOutputVhdx validates FileSystem (exFAT/FAT32/NTFS/FAT) and
    enforces per-FS label-length ceilings identically in both factories (the fake≠real guard), so a
    bad profile value fails the SAME way against the fake as it would live. Defaults: FileSystem
    exFAT, InputLabel INPUT, OutputLabel OUTPUT.

    LATER TASKS (Wait-WorkloadComplete / Read-WorkloadResult) will be appended to THIS file —
    they consume the descriptor's OutputDiskPath via the backend's ReadVhdxFile seam.
#>

Set-StrictMode -Version Latest

function New-WorkloadDisks {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Descriptor,
        [Parameter(Mandatory)] [hashtable] $Profile,
        [Parameter(Mandatory)] [string] $StorageRoot,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    $name     = [string]$Descriptor.Name
    $fs       = if ($Profile.ContainsKey('FileSystem'))  { [string]$Profile['FileSystem']  } else { 'exFAT' }
    $inLabel  = if ($Profile.ContainsKey('InputLabel'))  { [string]$Profile['InputLabel']  } else { 'INPUT' }
    $outLabel = if ($Profile.ContainsKey('OutputLabel')) { [string]$Profile['OutputLabel'] } else { 'OUTPUT' }

    $inPath  = Join-Path $StorageRoot ("{0}-input.vhdx"  -f $name)
    $outPath = Join-Path $StorageRoot ("{0}-output.vhdx" -f $name)

    # INCREMENTAL-RECORD INVARIANT (orphan-window fix): each data disk is recorded on the descriptor
    # — its path field AND a deduped append to CreatedDisks — IMMEDIATELY after it is CREATED, before
    # the NEXT disk is created/attached. CreatedDisks is teardown's authoritative cleanup set (Remove-
    # Sandbox -DeleteDisks deletes exactly it). If we recorded both paths only at the END (the prior
    # shape), a throw from the OUTPUT NewOutputVhdx/AddHardDiskDrive would leave the already-created+
    # attached INPUT disk UNRECORDED -> teardown would ORPHAN it. Recording the INPUT before touching
    # the OUTPUT guarantees a mid-failure still leaves the INPUT disk on CreatedDisks for cleanup.
    # The append DEDUPES against the system disk the provisioner already recorded (no double-add); this
    # folding makes the orchestrator's later CreatedDisks fold redundant-but-idempotent.
    $appendCreated = {
        param([string] $Path)
        $set = [System.Collections.Generic.List[string]]::new()
        foreach ($cd in @($Descriptor.CreatedDisks)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$cd)) { $set.Add([string]$cd) }
        }
        if (-not [string]::IsNullOrWhiteSpace($Path) -and ($set -notcontains $Path)) { $set.Add($Path) }
        $Descriptor.CreatedDisks = $set.ToArray()
    }

    # INPUT disk: create -> RECORD (field + CreatedDisks) -> populate from the profile's Inputs -> attach.
    # Effect-only backend calls are suppressed ($null = ...) so a real-backend emission can't leak into
    # this function's return stream (output-stream-pollution discipline). The record happens right after
    # CREATE (before populate/attach) so even a populate/attach throw leaves the disk recorded for teardown.
    $null = & $Backend.NewOutputVhdx @{ Path = $inPath; Label = $inLabel; FileSystem = $fs; SizeBytes = 1GB }
    $Descriptor.InputDiskPath = $inPath
    & $appendCreated $inPath
    if ($Profile.ContainsKey('Inputs') -and $Profile['Inputs'] -is [System.Collections.IDictionary]) {
        foreach ($k in @($Profile['Inputs'].Keys)) {
            $null = & $Backend.WriteVhdxFile @{ Path = $inPath; InnerPath = [string]$k; Content = [string]$Profile['Inputs'][$k] }
        }
    }
    $null = & $Backend.AddHardDiskDrive @{ VMName = $name; Path = $inPath }

    # OUTPUT disk: create -> RECORD (field + CreatedDisks) -> attach. The INPUT disk is already recorded
    # above, so a throw anywhere in THIS block leaves the INPUT recorded on CreatedDisks for teardown.
    $null = & $Backend.NewOutputVhdx @{ Path = $outPath; Label = $outLabel; FileSystem = $fs; SizeBytes = 1GB }
    $Descriptor.OutputDiskPath = $outPath
    & $appendCreated $outPath
    $null = & $Backend.AddHardDiskDrive @{ VMName = $name; Path = $outPath }

    return $Descriptor
}

<#
.SYNOPSIS
    Voidseal — wait for a sandbox workload to finish (disk-passing workload).

.DESCRIPTION
    The self-power-off completion model. The sandbox has NO live host<->guest control channel
    (the Sealer severed them), so there is no channel to ask "are you done?". Instead the guest
    workload runs at boot and then powers ITSELF off; the host learns completion by POLLING the
    VM's State until it reads Off — or until a wall-clock timeout fires:

        Wait-WorkloadComplete -Descriptor <descriptor> [-Backend] [-TimeoutSeconds] [-PollDelaySeconds]

      * State == 'Off'  -> the guest finished + self-powered-off; returns @{ State='Off'; TimedOut=$false }.
      * deadline hit     -> a hung / runaway guest; FORCE-STOP it (StopVM -Force) so the Reaper
        inherits a clean Off VM rather than a still-running one, then returns
        @{ State=<lastReadState>; TimedOut=$true }.

    The VM State is read through the backend's GetVM seam (host-truth — the same record Hyper-V
    reports), NEVER a raw Get-VM cmdlet. -TimeoutSeconds 0 makes exactly one poll then trips the
    deadline immediately (no sleep), so the timeout path is unit-testable in zero real time.

    INJECTION: `-Backend <hashtable>` defaults to `(New-RealHyperVBackend)`; tests pass the fake.
    Returns EXACTLY a result hashtable @{ State; TimedOut } — no backend object leaks into the stream
    (effect-only StopVM is routed to `$null = & ...`, output-stream-pollution discipline).
#>
function Wait-WorkloadComplete {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] $Descriptor,
        [hashtable] $Backend = (New-RealHyperVBackend),
        [int] $TimeoutSeconds = 600,
        [int] $PollDelaySeconds = 5
    )
    $name = [string]$Descriptor.Name
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $vm = & $Backend.GetVM @{ Name = $name }
        # The FAKE GetVM returns a [hashtable] (has .ContainsKey, indexed by ['State']); the REAL
        # GetVM returns a Microsoft.HyperV.PowerShell.VirtualMachine PSObject (NO .ContainsKey, read
        # via .State). Get-VMField (Provisioner.ps1) type-branches both shapes + handles a $null VM
        # (returns the default) — so this reads correctly on the LIVE backend's first poll, not just
        # the fake. (Same fake≠real class as the prior real-backend bugs found during live debugging.)
        $state = [string](Get-VMField -VM $vm -Name 'State' -Default 'Unknown')
        if ($state -eq 'Off') { return @{ State = 'Off'; TimedOut = $false } }
        if ((Get-Date) -ge $deadline) {
            $null = & $Backend.StopVM @{ Name = $name; Force = $true }   # force-stop a hung guest so teardown is clean
            return @{ State = $state; TimedOut = $true }
        }
        if ($PollDelaySeconds -gt 0) { Start-Sleep -Seconds $PollDelaySeconds }
    }
}

<#
.SYNOPSIS
    Voidseal — read + classify a finished sandbox workload's result (disk-passing workload).

.DESCRIPTION
    The host NEVER assumes "Off == success". After the guest self-powers-off (Wait-WorkloadComplete)
    and the host detaches the OUTPUT disk, Read-WorkloadResult reads the output disk off the named
    OUTPUT volume and classifies the run from a guest-written exit-code SENTINEL + the result file:

        Read-WorkloadResult -Descriptor <d> -Destination <host-dir> [-ResultInnerName] [-SentinelInnerName] [-Backend]

    CLASSIFICATION (Tier 0/1 — the trusting host-read):
      * SENTINEL ('result.exitcode' by default) is the guest's last act — it writes its own exit code
        there only after the workload completes. A MISSING sentinel therefore means the workload
        crashed, hung, or never reached the write -> Failed (ExitCode $null). The host does not infer
        success from a powered-off VM.
      * Sentinel present, parsed to 0, AND the result file present -> Success.
      * Sentinel present but non-zero (or unparseable -> -1), OR the result file absent -> Failed.
      The result file ('result.html' by default) is copied verbatim into -Destination (UTF-8, no
      trailing-newline drift) and its host path returned as ArtifactPath.

    TIER >= 2 (HOSTILE): the host MUST NOT direct-mount/direct-read a presumed-hostile output disk.
    The whole containment model would be defeated by a trusting host-read of a hostile tier. So this
    routes to Export-ColdVhdxQuarantine (Runner.ps1) — the clearly-marked cold-VHDX -> quarantine-VM
    -> CDR sink, a NotImplemented stub this round that THROWS *before* any read. The tier is read
    from OUR descriptor (a pscustomobject) via direct property access — correct here; the Get-VMField
    concern was only for backend GetVM results, not our own descriptor.

    READS go through the backend's ReadVhdxFile seam (returns the file content STRING or $null if
    absent — verified no BOM/newline drift fake-vs-real), NEVER a raw mount/Get-Content of the VHDX.

    INJECTION: `-Backend <hashtable>` defaults to `(New-RealHyperVBackend)`; tests pass the fake.
    Returns EXACTLY a result hashtable @{ Status; ExitCode; ArtifactPath; Reason } — no backend object
    leaks into the stream (effect-only writes are routed to `$null = ...`, output-stream discipline).
#>
function Read-WorkloadResult {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] $Descriptor,
        [Parameter(Mandatory)] [string] $Destination,
        [string] $ResultInnerName = 'result.html',
        [string] $SentinelInnerName = 'result.exitcode',
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    # Resolve the tier through the SAME fail-closed resolver the sibling exfil boundary
    # (Export-SandboxArtifact) uses — NOT a bare [int]$Descriptor.Tier cast. A bare cast turns an
    # absent/null/non-integer Tier into 0 (a TRUSTING Tier-0 host-read) — the wrong default for a
    # boundary guarding a host-read of guest output. Resolve-RunnerTier returns a definite 0..3 or
    # $null (undeterminable); an undeterminable tier is presumed HOSTILE and refused here, before any
    # read, so it can never fall through to the trusting Tier-0/1 path. (New-SandboxDescriptor enforces
    # an int Tier, so shipped descriptors always resolve — this is defense-in-depth + cross-boundary
    # consistency.)
    $tier = Resolve-RunnerTier -Descriptor $Descriptor
    if ($null -eq $tier) {
        throw ("Read-WorkloadResult: cannot determine the tier of the descriptor (Tier is " +
               "absent/null/non-integer/out-of-range). Refusing the trusting Tier-0/1 host-read — an " +
               "undeterminable tier is presumed HOSTILE and must route through the cold-VHDX quarantine " +
               "flow. Set an explicit Tier in 0..3.")
    }
    $outPath = [string]$Descriptor.OutputDiskPath
    if ([string]::IsNullOrWhiteSpace($outPath)) { throw "Read-WorkloadResult: descriptor has no OutputDiskPath." }

    # Tier >= 2 (hostile): NEVER direct-mount a possibly-malicious disk on the host. Route through the
    # quarantine extraction path (Export-ColdVhdxQuarantine — NotImplemented stub this round, THROWS
    # before any read). -ResultPath is omitted (optional on the sink; it throws before using it).
    if ($tier -ge 2) {
        return (Export-ColdVhdxQuarantine -Descriptor $Descriptor -Destination $Destination -Backend $Backend)
    }

    if (-not (Test-Path -LiteralPath $Destination)) { $null = New-Item -ItemType Directory -Path $Destination -Force }

    $sentinel = & $Backend.ReadVhdxFile @{ Path = $outPath; InnerPath = $SentinelInnerName }
    if ($null -eq $sentinel) {
        return @{ Status = 'Failed'; ExitCode = $null; ArtifactPath = $null;
                  Reason = "no sentinel '$SentinelInnerName' on the output disk (workload crashed, hung, or never wrote)" }
    }
    $rc = -1
    $parsed = 0
    if ([int]::TryParse($sentinel.Trim(), [ref]$parsed)) { $rc = $parsed }

    # A present-but-EMPTY/whitespace-only result is NOT a usable artifact — classify Failed, never
    # Success. (The guest's double-write or a truncated-flush race can leave a 0-byte result.html on
    # disk; with a bare `$null -ne $content` an empty string is non-null, so rc==0 would FALSE-GREEN a
    # run that produced nothing importable. Require non-whitespace content for Success.)
    $content = & $Backend.ReadVhdxFile @{ Path = $outPath; InnerPath = $ResultInnerName }
    $hasContent = -not [string]::IsNullOrWhiteSpace($content)
    $artifact = $null
    if ($hasContent) {
        $artifact = Join-Path $Destination $ResultInnerName
        Set-Content -LiteralPath $artifact -Value $content -NoNewline -Encoding utf8
    }
    if ($rc -eq 0 -and $hasContent) {
        return @{ Status = 'Success'; ExitCode = $rc; ArtifactPath = $artifact; Reason = $null }
    }
    $reason = if ($rc -ne 0) { "workload exited non-zero (exit code $rc)" }
              elseif (-not $hasContent) { "result '$ResultInnerName' is absent or empty (workload produced no usable output)" }
              else { $null }
    return @{ Status = 'Failed'; ExitCode = $rc; ArtifactPath = $artifact; Reason = $reason }
}
