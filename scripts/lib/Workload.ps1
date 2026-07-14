<#
.SYNOPSIS
    Voidseal — Workload disks (disk-passing workload).

.DESCRIPTION
    Creates the two data disks a sandbox workload runs against and wires them onto the VM
    BEFORE the seal, then records their host-side paths on the sandbox descriptor:

        New-WorkloadDisks -Descriptor <descriptor> -Profile <hashtable> -StorageRoot <dir> [-Backend]

      * INPUT disk  — created + host-formatted (NewOutputVhdx), then POPULATED from the profile's
        `Inputs` map (innerPath -> content) via WriteVhdxFile (string content) or WriteVhdxFileBytes
        ([byte[]] content — I2b), so the guest boots with its seed/input files already on a
        mountable, host-readable volume. Labelled INPUT by default.
      * OUTPUT disk — created + host-formatted (NewOutputVhdx), left EMPTY; the guest writes its
        results here and the host reads them back off the named OUTPUT volume after the seal.

    Both disks are ATTACHED to the VM (AddHardDiskDrive) BEFORE the Sealer runs — so the seal's
    host-truth scan records them as known data disks (Assert-Sealed accepts recorded data disks).
    The descriptor's InputDiskPath / OutputDiskPath fields carry the paths the Runner reads results
    from and the Reaper cleans up.

    BYTE-CLEAN INPUTS (I2b): the pre-Task-5 shape STRING-CAST every Input value (WriteVhdxFile
    Content=[string]$v), which silently corrupted a [byte[]] Input to its .ToString() representation
    ("System.Byte[]") instead of its actual bytes. New-WorkloadDisks now branches on the Input
    VALUE's runtime type: a [byte[]] value routes through the byte-clean WriteVhdxFileBytes (Task 5);
    a [string] value keeps using the string WriteVhdxFile (text profiles unchanged, zero behavior
    change). An EMPTY [byte[]] Input is SKIPPED (not written) — $SbAssertArg's `return $P[$Key]`
    unrolls a 0-length byte[] arg to $null (a pre-existing bug on BOTH the real and fake backend,
    parity-preserving, flagged by the Task-5 gate), so passing one through would throw a confusing
    "required argument missing" rather than doing anything useful; no shipped profile emits an empty
    binary Input, so skipping is a safe, documented no-op rather than a silent corruption risk.

    DISK SIZES (I2b): INPUT/OUTPUT disk sizes were hardcoded to 1GB regardless of profile. They are
    now read from the profile's InputDiskSizeBytes / OutputDiskSizeBytes keys, each DEFAULTING to
    1GB when the key is absent — so every existing profile (which declares neither key) is unaffected.

    HOST-FREE-SPACE PREFLIGHT (I2b, folds I6b coverage): Provisioner.ps1's Test-HostFreeSpace (I6b)
    originally guarded only the SYSTEM disk. An OUTPUT disk is a DIRECT guest fill vector (the guest
    writes its result there), so New-WorkloadDisks now calls Test-HostFreeSpace with the SUMMED
    INPUT+OUTPUT disk budget, measured against the volume hosting $StorageRoot, BEFORE either data
    disk is created — fail-closed, mirroring the Provisioner's system-disk preflight exactly (same
    helper, same fixed 1GB headroom default).

    ENOSPC SENTINEL (I2b, FAIL-CLOSED — review Critical fix): a HOST-side disk-full write (during Inputs
    population, OR creating either data disk — e.g. a race where free space was consumed between the
    preflight above and the actual write) is classified as a distinct DiskFull outcome: the descriptor is
    stamped ($Descriptor.WorkloadDiskStatus='DiskFull' + a captured WorkloadDiskStatusReason) and the
    classified error is RE-THROWN — NEVER swallowed. New-WorkloadDisks does NOT return normally on this
    path. A caller (Invoke-Voidseal.ps1) that returns early here without re-throwing would proceed to
    Lock-Sandbox/Assert-Sealed/VM-start with a MISSING OUTPUT disk and a PARTIALLY-populated INPUT disk —
    Assert-Sealed does not check for a null OutputDiskPath, so a swallow-and-continue would seal a broken
    sandbox and only surface the failure much later at Read-WorkloadResult. Re-throwing lets the existing
    outer lifecycle try/catch (Invoke-Voidseal.ps1) abort + tear down immediately, the same way any other
    mid-flow throw (e.g. a StartVM failure) already does — no new orchestrator wiring needed.

    CLASSIFICATION is locale-independent: it keys PRIMARILY on the caught exception's HResult matching
    either Win32 ERROR_DISK_FULL (0x80070070 / -2147024784) or ERROR_HANDLE_DISK_FULL (0x80070027 /
    -2147024857) — the same codes a real disk-full System.IO.IOException carries on Windows — with the
    prior English-only message pattern ('(?i)ENOSPC|disk full|not enough space') kept only as a fallback
    for a caught exception that doesn't carry one of those HResults. Mirrors SbIsUnavailableError's
    precedent (HyperVBackend.ps1) of classifying on exception shape/code, not message text alone.

    This covers HOST-write failures during Inputs population AND HOST-side ENOSPC creating either data
    disk (NewOutputVhdx, both INPUT and OUTPUT). A GUEST filling the OUTPUT disk DURING its own run is a
    live/run-time concern this function cannot observe (no live channel once sealed) and is NOT modelled
    here — see Wait-WorkloadComplete / Read-WorkloadResult for the guest-side completion/classification
    path.

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

    # DiskFull classification (I2b, FAIL-CLOSED — review Critical fix). LOCALE-INDEPENDENT: keys
    # primarily on the caught exception's HResult matching Win32 ERROR_DISK_FULL (0x80070070 /
    # -2147024784) or ERROR_HANDLE_DISK_FULL (0x80070027 / -2147024857) — the same codes a real
    # disk-full System.IO.IOException carries on Windows (LIVE-ONLY-UNPROVEN: not exercised against a
    # real host-disk-full write in this mock-green pass, but HResult-based matching is correct by
    # construction and does not depend on message wording/locale). Falls back to the prior English-
    # only message pattern only when the HResult doesn't match (e.g. a non-.NET or wrapped exception).
    # Mirrors SbIsUnavailableError's precedent (HyperVBackend.ps1) of classifying on exception
    # shape/code, not message text alone.
    $ERROR_DISK_FULL        = -2147024784   # 0x80070070
    $ERROR_HANDLE_DISK_FULL = -2147024857   # 0x80070027
    $isDiskFullError = {
        param($ErrorRecord)
        if ($null -eq $ErrorRecord) { return $false }
        $ex = $ErrorRecord.Exception
        if ($null -eq $ex) { return $false }
        $hresultMatch = $false
        try {
            # HResult is present on every System.Exception; guard with try/catch anyway in case a
            # non-.NET wrapper doesn't expose it cleanly under StrictMode.
            $hresultMatch = ($ex.HResult -eq $ERROR_DISK_FULL) -or ($ex.HResult -eq $ERROR_HANDLE_DISK_FULL)
        } catch { $hresultMatch = $false }
        if ($hresultMatch) { return $true }
        return ([string]$ex.Message -match '(?i)ENOSPC|disk full|not enough space')
    }.GetNewClosure()

    # FAIL-CLOSED helper: stamp the DiskFull sentinel on the descriptor (diagnostics survive even
    # though the function never returns normally) then RE-THROW a distinctly-classified error. NEVER
    # `return $Descriptor` here — a swallow-and-continue would let the orchestrator proceed to
    # Lock-Sandbox/Assert-Sealed/VM-start with a missing/partial workload disk (Assert-Sealed does not
    # check for a null OutputDiskPath). The re-thrown error is caught by Invoke-Voidseal.ps1's existing
    # outer lifecycle try/catch, which aborts the run and tears down — no new orchestrator wiring needed.
    $failClosedDiskFull = {
        param([string] $Reason, $ErrorRecord)
        $Descriptor.WorkloadDiskStatus = 'DiskFull'
        $Descriptor.WorkloadDiskStatusReason = $Reason
        $inner = if ($ErrorRecord -and $ErrorRecord.Exception) { $ErrorRecord.Exception.Message } else { '' }
        throw "New-WorkloadDisks: DiskFull — $Reason ($inner)"
    }.GetNewClosure()

    # Profile-driven disk sizes (I2b) — default to the prior hardcoded 1GB when the profile declares
    # neither key, so every existing profile (firefox/ralph/builder — none declare these keys) is
    # unaffected. $null/absent both fall through to the default via ContainsKey (not a bare index),
    # matching the FileSystem/label defaulting idiom immediately above.
    $inSizeBytes  = if ($Profile.ContainsKey('InputDiskSizeBytes'))  { [long]$Profile['InputDiskSizeBytes']  } else { 1GB }
    $outSizeBytes = if ($Profile.ContainsKey('OutputDiskSizeBytes')) { [long]$Profile['OutputDiskSizeBytes'] } else { 1GB }

    $inPath  = Join-Path $StorageRoot ("{0}-input.vhdx"  -f $name)
    $outPath = Join-Path $StorageRoot ("{0}-output.vhdx" -f $name)

    # --- workload-disk host-free-space preflight (I2b; folds I6b coverage; fail-closed, BEFORE any
    # creation) --------------------------------------------------------------------------------------
    # I6b added Test-HostFreeSpace (Provisioner.ps1) for the SYSTEM disk only. An OUTPUT disk is a
    # DIRECT guest fill vector (the guest writes its result there) — same class of host-disk-
    # exhaustion risk I6b closed for the system disk. Reuse the SAME helper with the SUMMED INPUT+
    # OUTPUT budget, measured against the volume hosting $StorageRoot (the same root both data disks
    # land on), before either NewOutputVhdx call — so a refusal here leaves NEITHER disk created.
    $null = Test-HostFreeSpace -Path $StorageRoot -RequiredBytes ($inSizeBytes + $outSizeBytes)

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
    # CREATE-path ENOSPC coverage (review Critical #3): the preflight above makes an ENOSPC HERE unlikely
    # in practice, but wrapping is defense-in-depth — a disk-full creating the INPUT .vhdx itself must
    # classify + fail closed exactly like the populate-time write, not propagate as a generic throw.
    try {
        $null = & $Backend.NewOutputVhdx @{ Path = $inPath; Label = $inLabel; FileSystem = $fs; SizeBytes = $inSizeBytes }
    }
    catch {
        if (& $isDiskFullError $_) {
            & $failClosedDiskFull "host-side disk-full creating the INPUT disk ($inPath)" $_
        }
        throw
    }
    $Descriptor.InputDiskPath = $inPath
    & $appendCreated $inPath
    if ($Profile.ContainsKey('Inputs') -and $Profile['Inputs'] -is [System.Collections.IDictionary]) {
        foreach ($k in @($Profile['Inputs'].Keys)) {
            $v = $Profile['Inputs'][$k]
            if ($v -is [byte[]]) {
                # Byte-clean path (I2b/Task 5): a [byte[]] Input must NEVER be string-cast (silent
                # binary corruption — WriteVhdxFile Content=[string]$v would yield "System.Byte[]").
                # F2 fix: $SbAssertArg now comma-wraps its return (HyperVBackend.ps1), so a
                # genuinely-empty [byte[]] Input survives the WriteVhdxFileBytes round-trip
                # shape-intact and is written as an empty inner file — no skip needed. ENOSPC
                # sentinel: a host-side disk-full write during this populate is caught, classified
                # DiskFull, and RE-THROWN below — fail-closed, never a swallow-and-continue.
                try {
                    $null = & $Backend.WriteVhdxFileBytes @{ Path = $inPath; InnerPath = [string]$k; Bytes = $v }
                }
                catch {
                    if (& $isDiskFullError $_) {
                        & $failClosedDiskFull `
                            "host-side disk-full writing Input '$k' onto the INPUT disk ($inPath)" $_
                    }
                    throw
                }
            }
            else {
                $null = & $Backend.WriteVhdxFile @{ Path = $inPath; InnerPath = [string]$k; Content = [string]$v }
            }
        }
    }
    $null = & $Backend.AddHardDiskDrive @{ VMName = $name; Path = $inPath }

    # OUTPUT disk: create -> RECORD (field + CreatedDisks) -> attach. The INPUT disk is already recorded
    # above, so a throw anywhere in THIS block leaves the INPUT recorded on CreatedDisks for teardown.
    # Raw-OUTPUT predicate: a PROCESSOR (Network='None' AND ScreenConfig) OR any profile that opts into the
    # user-space outbox transport (OutboxOutput=$true — firefox post-C1 convergence). Either way the OUTPUT is
    # Raw (no host-mountable FS; offset 0 = the outbox the guest writes; host reads via ReadVhdxRawRegion,
    # NEVER Mount-VHD). Everything else (INPUT disks, legacy non-outbox non-processors) stays exFAT.
    $isProcessor  = ($Profile['Network'] -eq 'None') -and $Profile.ContainsKey('ScreenConfig')
    $wantsOutbox  = $Profile.ContainsKey('OutboxOutput') -and [bool]$Profile['OutboxOutput']
    $outFs = if ($isProcessor -or $wantsOutbox) { 'Raw' } else { $fs }
    # CREATE-path ENOSPC coverage (review Critical #3): the OUTPUT .vhdx create is the other host-write
    # the free-space preflight is meant to make unreachable in practice; wrap for defense-in-depth so a
    # disk-full here classifies + fails closed the same way, rather than a generic throw with the INPUT
    # disk already created+recorded+attached but the OUTPUT missing.
    try {
        $null = & $Backend.NewOutputVhdx @{ Path = $outPath; Label = $outLabel; FileSystem = $outFs; SizeBytes = $outSizeBytes }
    }
    catch {
        if (& $isDiskFullError $_) {
            & $failClosedDiskFull "host-side disk-full creating the OUTPUT disk ($outPath)" $_
        }
        throw
    }
    $Descriptor.OutputDiskPath = $outPath
    & $appendCreated $outPath
    $null = & $Backend.AddHardDiskDrive @{ VMName = $name; Path = $outPath }

    return $Descriptor
}

<#
.SYNOPSIS
    Voidseal — RC6: deliver the disk-mode cloud-init NoCloud seed on a CIDATA DATA DISK that survives
    the seal (the seal ejects DVDs; a recorded data disk stays attached through it).

.DESCRIPTION
    RC6 (2026-06-25 live): the seal EJECTS the seed DVD before the guest's ONLY boot, so cloud-init had
    no datasource and the disk-mode runner never ran (the sealed deploy timed out). E8 proved cloud-init
    NoCloud reads `user-data` + `meta-data` off a vfat DATA DISK labelled `CIDATA`. So in disk mode the
    seed must ride a recorded data disk, NOT an ejected DVD.

        New-WorkloadSeedDisk -Descriptor <descriptor> -Profile <hashtable> -StorageRoot <dir> [-Backend]

    Creates a small CIDATA-labelled data disk (NewOutputVhdx, FAT32 — a vfat cloud-init reads), writes
    `user-data` (= New-CidataUserData -Profile <resolved>, the disk-mode runner with the Entrypoint
    substituted) and `meta-data` (= New-CidataMetaData) at the disk ROOT (WriteVhdxFile), ATTACHES it
    (AddHardDiskDrive), and RECORDS it on the descriptor (a SeedDiskPath field AND a deduped append to
    CreatedDisks) BEFORE the seal — exactly like the INPUT/OUTPUT data disks — so:
      * teardown (Remove-Sandbox -DeleteDisks, CreatedDisks-authoritative) deletes it, and
      * Assert-Sealed ACCEPTS it as an EXPECTED disk (it adds the recorded SeedDiskPath to its
        expected/data-disk sets) instead of refusing it as a residual.

    LINE ENDINGS: New-CidataUserData LF-normalizes its output (the embedded `#!/bin/sh` runner needs LF
    — a CRLF yields a `/bin/sh\r` bad-interpreter failure). The host write goes through the backend's
    WriteVhdxFile, which writes the content STRING verbatim (Set-Content -NoNewline -Encoding utf8
    preserves LF + adds no BOM — verified on this host). We LF-normalize once more here as belt-and-
    braces so the seed disk's user-data is LF-only regardless of any future content-source change.

    FAIL-CLOSED: New-CidataUserData refuses a blank/single-quote/multi-line Disk-mode Entrypoint, so a
    bad entrypoint throws here BEFORE any disk is created — the same gate the SeedBuilder applies.

    EVERYTHING touches Hyper-V / the host disk through the backend; effect-only calls go through
    `$null = & $Backend.X @{...}` (output-stream-pollution discipline). Returns the mutated descriptor.
    Dot-source AFTER HyperVBackend.ps1 + Provisioner.ps1 + SeedBuilder.ps1 (function resolution is at
    call time, so the dot-source ORDER among the libs does not matter for the runtime call).
.PARAMETER Descriptor
    The sandbox descriptor (consumed + mutated: SeedDiskPath + CreatedDisks).
.PARAMETER Profile
    The resolved profile (must declare WorkloadMode='Disk' + a non-blank Entrypoint).
.PARAMETER StorageRoot
    The host-side storage dir the seed disk lands in (beside the INPUT/OUTPUT data disks).
.PARAMETER Backend
    The Hyper-V backend. Defaults to the real one; tests inject the fake.
#>
function New-WorkloadSeedDisk {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Descriptor,
        [Parameter(Mandatory)] [hashtable] $Profile,
        [Parameter(Mandatory)] [string] $StorageRoot,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    $name     = [string]$Descriptor.Name
    $seedPath = Join-Path $StorageRoot ("{0}-cidata.vhdx" -f $name)

    # Build the NoCloud documents FIRST. New-CidataUserData fails closed on a bad Disk-mode Entrypoint
    # (blank / single-quote / multi-line) BEFORE we create any disk — so a rejected entrypoint produces
    # no seed disk. Both documents are LF-normalized (the user-data embeds a #!/bin/sh runner; a CRLF
    # there is a guest bad-interpreter failure). Belt-and-braces re-normalize so the on-disk seed is
    # LF-only regardless of the content source.
    $userData = ConvertTo-LfText -Text ([string](New-CidataUserData -Profile $Profile))
    $metaData = ConvertTo-LfText -Text ([string](New-CidataMetaData))

    # CIDATA disk: create -> RECORD (field + CreatedDisks) -> populate -> attach. The record happens
    # right after CREATE (before populate/attach) so even a populate/attach throw leaves the disk
    # recorded for teardown (the same incremental-record invariant New-WorkloadDisks uses). FAT32 is a
    # vfat cloud-init reads; the CIDATA label is how NoCloud finds the seed. ~64MB is ample for two
    # tiny text files. Effect-only backend calls are suppressed ($null = ...) so a real-backend
    # emission can't leak into this function's return stream.
    $null = & $Backend.NewOutputVhdx @{ Path = $seedPath; Label = 'CIDATA'; FileSystem = 'FAT32'; SizeBytes = 64MB }
    # Record the seed disk on the descriptor BEFORE populate/attach (orphan-window fix) AND so
    # Assert-Sealed accepts it as an EXPECTED disk. SeedDiskPath is its own field (audit / the seal+gate
    # know it by name; New-SandboxDescriptor declares it, so a direct assignment is StrictMode-safe) and
    # it joins CreatedDisks (teardown's authoritative cleanup set), deduped.
    $Descriptor.SeedDiskPath = $seedPath
    $set = [System.Collections.Generic.List[string]]::new()
    foreach ($cd in @($Descriptor.CreatedDisks)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$cd)) { $set.Add([string]$cd) }
    }
    if ($set -notcontains $seedPath) { $set.Add($seedPath) }
    $Descriptor.CreatedDisks = $set.ToArray()

    # Write the two NoCloud documents at the disk ROOT (cloud-init NoCloud expects user-data + meta-data
    # at the volume root). WriteVhdxFile writes the content verbatim (LF preserved, no BOM).
    $null = & $Backend.WriteVhdxFile @{ Path = $seedPath; InnerPath = 'user-data'; Content = $userData }
    $null = & $Backend.WriteVhdxFile @{ Path = $seedPath; InnerPath = 'meta-data'; Content = $metaData }

    # Attach the seed disk to the VM BEFORE the seal so the seal's host-truth scan records it.
    $null = & $Backend.AddHardDiskDrive @{ VMName = $name; Path = $seedPath }

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
