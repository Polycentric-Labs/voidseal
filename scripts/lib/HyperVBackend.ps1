<#
.SYNOPSIS
    Voidseal — mockable Hyper-V backend abstraction.

.DESCRIPTION
    The SINGLE seam through which every later component (Provisioner, Sealer,
    Runner) touches Hyper-V. Later components call backend methods; they MUST NOT call
    raw `New-VM` / `Set-VM*` / `Checkpoint-VM` / `*VMSwitch` / `*VMDvdDrive` /
    `*VMHardDiskDrive` / `Set-VMComPort` directly.

    Dot-source this file to get three functions:

        Get-HyperVBackendMethodManifest   -> [hashtable] method-name -> @(argKeys) (the contract)
        New-RealHyperVBackend             -> a backend wrapping the real Hyper-V cmdlets
        New-FakeHyperVBackend [-SimulateUnavailable]
                                          -> an in-memory backend (the test seam for the consumers)

    A "backend" is a [hashtable] of scriptblocks, one per operation. Both factories
    return the SAME shape (same method-name set), so code written against the fake works
    unchanged against the real one (proven by the interface-parity tests). Every method
    is invoked uniformly with a SINGLE hashtable of named args:

        & $backend.NewVM @{ Name = 'vm1'; Generation = 2; MemoryStartupBytes = 4GB }
        $vm = & $backend.GetVM @{ Name = 'vm1' }

    INJECTION (how the consumers use this):
        Consumer cmdlets take a `-Backend <hashtable>` parameter defaulting to
        `(New-RealHyperVBackend)`. Production passes nothing (real). Tests pass
        `-Backend (New-FakeHyperVBackend)` and assert against the fake's in-memory state.

    FAIL-CLOSED (real backend):
        Hyper-V may be unreachable (module absent) or refuse the call (this process not
        elevated / not in the Hyper-V Administrators group). The real backend catches
        those and rethrows ONE clear, actionable exception:

            "Hyper-V unavailable or insufficient privilege (need elevation / Hyper-V
             Administrators group): <original message>"

        so callers get a consistent, diagnosable failure instead of a raw cmdlet error.

    CAPABILITY PROBE:
        TestAvailable() returns @{ Available=<bool>; Elevated=<bool>; Reason=<string> }
        and NEVER throws — it wraps `Get-VM` in try/catch and classifies the result.
        Callers use it to decide whether to proceed or to print remediation up front.

    NOTE: This file performs NO Hyper-V calls at load/define time. The real cmdlets are
    only invoked when a real-backend method is actually called. Safe to dot-source in any
    session (including a non-elevated one).
#>

Set-StrictMode -Version Latest

# --------------------------------------------------------------------------
# Shared constants
# --------------------------------------------------------------------------

# The clear, actionable prefix every fail-closed Hyper-V error carries. Callers
# can match on this stable substring.
$script:HyperVUnavailablePrefix =
    'Hyper-V unavailable or insufficient privilege (need elevation / Hyper-V Administrators group): '

# The canonical host<->guest channel names the SEAL controls (matches the tier-profile
# HostChannels hashtable keys). SINGLE SOURCE OF TRUTH: SetHostChannel
# validates against this set; GetHostChannels returns exactly these keys; the fake seeds
# every VM with all four = $true (the UNSEALED default — Hyper-V enables these by default,
# so the Sealer must explicitly turn them off and Assert-Sealed must host-verify they are).
$script:HostChannelNames = @('Clipboard', 'Shares', 'GuestServices', 'EnhancedSession')

# --------------------------------------------------------------------------
# Method manifest — SINGLE SOURCE OF TRUTH for the backend surface.
# --------------------------------------------------------------------------
# method name -> the named-arg keys the method accepts (documentation + a parity
# contract; both factories build EXACTLY this key set). Keeping the surface here
# means the completeness gate (do the consumers ever need a raw cmdlet?) lives in one place.

<#
.SYNOPSIS
    Returns the canonical backend method manifest: name -> accepted arg keys.
#>
function Get-HyperVBackendMethodManifest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    # Ordered for readability; callers treat it as an unordered set of names.
    return [ordered]@{
        # ---- capability probe ----
        TestAvailable        = @()                                  # -> @{ Available; Elevated; Reason }

        # ---- VM lifecycle ----
        NewVM                = @('Name', 'Generation', 'MemoryStartupBytes', 'Path', 'SwitchName', 'NoVHD')
        GetVM                = @('Name')                            # -> VM object/record or $null
        StartVM              = @('Name')
        StopVM               = @('Name', 'TurnOff', 'Force')
        RemoveVM             = @('Name', 'Force')                   # does NOT delete VHDX (caller's step)

        # ---- hardware ----
        SetProcessor         = @('VMName', 'Count', 'ExposeVirtualizationExtensions')
        SetMemory            = @('VMName', 'StartupBytes', 'DynamicMemoryEnabled', 'MinimumBytes', 'MaximumBytes')
        SetFirmware          = @('VMName', 'EnableSecureBoot', 'SecureBootTemplate', 'BootOrder')
        # RC7 (2026-06-25 live): disable Hyper-V's automatic checkpoints. Hyper-V defaults
        # AutomaticCheckpointsEnabled=ON, so each disk gets a differencing .avhdx at VM start; the guest
        # writes its result into the .avhdx while the host reads the BASE .vhdx (the empty pre-write
        # layer) -> every host read came back empty. The Provisioner calls this at provision time to turn
        # automatic checkpoints OFF for a disposable sandbox. REAL = Set-VM -AutomaticCheckpointsEnabled
        # <bool>; FAKE = flips the recorded AutomaticCheckpointsEnabled flag on the VM record. Added per
        # the SetFirmware/RemoveVHD addendum precedent (manifest + both factories + parity/drift tests).
        SetAutomaticCheckpoints = @('VMName', 'Enabled')           # Set-VM -AutomaticCheckpointsEnabled
        SetComPort           = @('VMName', 'Number', 'Path')        # COM1 named-pipe (Linux mgmt channel)
        # Host-TRUTH read of a VM's COM port (the Runner's COM1 serial command channel). Returns
        # @{ Number; Path } for the requested port, or $null when no port / an empty path. Backs
        # the post-seal COM1-liveness assertion (Assert-Sealed): the seal must NEVER collaterally
        # sever the Runner's serial command channel, so the gate POSITIVELY host-verifies COM1 is
        # still attached after sealing. The Sealer MUST NOT reach for a raw Get-VMComPort. Follows the
        # GetDvdDrives / SetHostChannel / RemoveVHD addendum precedent (manifest + both factories +
        # parity/drift tests). REAL = Get-VMComPort -VMName <vm> -Number <n>; FAKE = reads the
        # com-port state SetComPort records.
        GetComPort           = @('VMName', 'Number')               # -> @{ Number; Path } or $null

        # ---- guest command delivery (RUNNER serial seam) ----
        # Deliver a command to a Linux guest over the COM1 named-pipe serial console and read back
        # its result. PowerShell Direct is Windows-guest-only, so the management
        # channel for a Linux guest is the serial console wired by SetComPort. The Runner MUST
        # NOT open the named pipe / drive the serial console with a raw cmdlet — it goes through this
        # seam so the FAKE can simulate it (record the command + return canned output) and the build
        # stays unit-testable without a live VM. Follows the RemoveVHD / RemoveSwitch / SetHostChannel
        # addendum precedent (manifest + both factories + parity/drift tests).
        # Returns @{ ExitCode = <int>; Stdout = <string>; Stderr = <string> }.
        InvokeGuestCommand   = @('VMName', 'Command', 'TimeoutSeconds')

        # ---- host channels (SEAL surface) ----
        # The bidirectional host<->guest VMBus channels the Sealer must turn OFF and
        # Assert-Sealed must host-verify: Clipboard / Shares / GuestServices / EnhancedSession.
        # Follows the RemoveVHD/RemoveSwitch addendum precedent (manifest + both factories +
        # parity/drift tests) — the backend previously had no way to toggle/read these, and the
        # Sealer MUST NOT reach for a raw Set-VM/*-VMIntegrationService.
        SetHostChannel       = @('VMName', 'Channel', 'Enabled')    # set ONE channel on/off
        GetHostChannels      = @('VMName')                          # -> @{ Clipboard; Shares; GuestServices; EnhancedSession } (bools)

        # ---- disk ----
        NewVHD               = @('Path', 'SizeBytes', 'Differencing', 'ParentPath', 'Dynamic')
        # Create AND host-format a data VHDX in one shot — the workload "output disk". A bare
        # New-VHD makes an UNINITIALIZED disk (no partition table, no filesystem); the guest can't
        # mount it and the host can't read results back off it. So this method creates the dynamic
        # VHDX, then mounts it on the HOST, GPT-initializes it, makes one max-size partition, and
        # formats that partition with the requested filesystem + volume label, then dismounts. The
        # Provisioner attaches the resulting formatted disk as the workload's output volume so
        # the guest writes results to a host-readable filesystem (Label is how the host finds the
        # volume after the run). Added per the GetDvdDrives/RemoveVHD addendum precedent (manifest +
        # both factories + parity/drift tests). REAL = New-VHD + Mount/Initialize/New-Partition/
        # Format-Volume/Dismount; FAKE models a formatted disk in its VHD state so GetVHDInfo (and
        # any later read of the volume) sees the Label + FileSystem.
        NewOutputVhdx        = @('Path', 'Label', 'FileSystem', 'SizeBytes')  # create + host-format a data VHDX
        WriteVhdxFile        = @('Path', 'InnerPath', 'Content')   # host writes one file onto a VHDX (rw)
        ReadVhdxFile         = @('Path', 'InnerPath')              # host reads one file from a VHDX (ro) -> string or $null
        # Read a raw byte range from a FIXED VHDX's payload in USER-SPACE (qemu-img convert -O raw +
        # file-slice). NEVER Mount-VHD / Add-VMHardDiskDrive — host attach kernel-parses attacker FS
        # bytes (Pass-5). The host reads the in-guest "outbox" (guest/outbox.py) off the DETACHED OUTPUT
        # disk through THIS method; the Sensitivity Gate consumes the parsed verdicts. REAL = qemu-img
        # convert -f vhdx -O raw then FileStream seek/read (with an RC8 detach-settle-lag lock-retry +
        # qemu stderr-in-throw); FAKE = return the recorded outbox-region bytes, modeling detach/file-lock
        # ordering + the .avhdx child-layer trap (RC7) + the SelfPowerOff write-flush gate + a zero-padded
        # FIXED-disk tail. Added per the GetDvdDrives/ReadVhdxFile addendum precedent (manifest + both
        # factories + parity/drift tests). Interface: -> [byte[]] of length Length.
        #
        # DISK MODEL CAVEAT (MUST-FIX 3): the FAKE models a ZERO-INITIALIZED raw disk with the outbox at
        # disk byte OFFSET 0. The REAL OUTPUT disk is NOT guaranteed zero outside the outbox region this
        # phase — it may be an NTFS-formatted disk with a boot sector / MFT at low offsets until the
        # dedicated FIXED raw outbox disk lands (Phase 2/4). THEREFORE the consumer MUST SELF-DELIMIT: the
        # outbox is length-prefixed (header carries entry_count + payload_total_len), so the seam reads the
        # 24-byte header then EXACTLY 24 + entry_count*104 + payload_total_len bytes from offset 0 and never
        # reads arbitrary / low offsets expecting zeros.
        ReadVhdxRawRegion    = @('Path', 'Offset', 'Length')   # user-space raw read (NEVER Mount-VHD)
        # Hash the WHOLE .vhdx FILE (as shipped) with SHA-256, in USER-SPACE (FileStream -> SHA256) —
        # NEVER Mount-VHD / Add-VMHardDiskDrive. The supply-chain ARTIFACT FINGERPRINT: the builder
        # records it for deps.vhdx; Phase 3 re-streams the same file before AddHardDiskDrive and refuses
        # a mismatch (tamper/substitution -> fail closed). NO qemu (D-3): an integrity fingerprint needs
        # no FS interpretation, so there is zero reason to let the host kernel parse attacker bytes
        # (Pass-5). REQUIRES the .vhdx DETACHED + VM Off (an attached disk is locked) — the orchestrator's
        # detach guard enforces it. REAL = $LockRetry-wrapped (RC8 settle-lag) streaming hash; FAKE =
        # SHA256 of the recorded DepsImageRegion, modeling detach-ordering + settle-lag + determinism.
        # Added per the ReadVhdxRawRegion addendum precedent (manifest + both factories + parity/drift).
        # Interface: -> [string] lowercase hex SHA-256.
        GetVhdxImageHash     = @('Path')   # whole-.vhdx-file SHA-256, user-space (NEVER Mount-VHD)
        GetVHDInfo           = @('Path')                            # -> @{ Path; SizeBytes; Differencing; ParentPath; Label; FileSystem } or $null
        RemoveVHD            = @('Path')                            # delete a DETACHED .vhdx file (the Reaper's explicit cleanup)
        AddHardDiskDrive     = @('VMName', 'Path')
        RemoveHardDiskDrive  = @('VMName', 'Path')
        SetDvdDrive          = @('VMName', 'Path')                  # ISO attach
        RemoveDvdDrive       = @('VMName')                          # ISO detach
        # Host-TRUTH read of the attached DVD media (SEAL/GATE addendum). Returns @() of
        # attached DVD paths. The Sealer's Get-AttachedDvdPath + Assert-Sealed read DVD state
        # through THIS method, NOT off the GetVM object: a real Get-VM object has NO DvdDrive
        # property (DVD state lives in the DVDDrives COLLECTION, read via Get-VMDvdDrive). Reading
        # the scalar off GetVM worked only against the FAKE (which carries .DvdDrive) — a fake≠real
        # divergence on the security seam that let a seed DVD survive the seal on live Hyper-V.
        # ADDED following the SetHostChannel/RemoveVHD addendum precedent (manifest + both
        # factories + parity/drift tests) so the Sealer never reaches for a raw *-VMDvdDrive cmdlet.
        GetDvdDrives         = @('VMName')                          # -> @() of attached DVD media paths

        # ---- switch / network ----
        NewSwitch            = @('Name', 'SwitchType', 'NetAdapterName')   # Internal | Private | External
        GetSwitch            = @('Name')                           # -> switch record or $null
        RemoveSwitch         = @('Name')                           # delete a vSwitch (rollback orphan-cleanup; idempotent)
        ConnectNetworkAdapter= @('VMName', 'SwitchName')
        RemoveNetworkAdapter = @('VMName')                         # the SEAL operation
        GetNetworkAdapter    = @('VMName')                         # -> @() of NIC records

        # ---- checkpoint ----
        Checkpoint           = @('VMName', 'SnapshotName')
        RestoreCheckpoint    = @('VMName', 'SnapshotName')
        GetCheckpoint        = @('VMName')                         # -> @() of checkpoint records
        RemoveCheckpoint     = @('VMName', 'SnapshotName')
    }
}

# --------------------------------------------------------------------------
# Internal helper scriptblocks — defined as VARIABLES, not functions.
# --------------------------------------------------------------------------
# WHY variables: each backend method is a scriptblock sealed with .GetNewClosure()
# and later invoked from a DIFFERENT scope (the caller / a Pester test). A closure
# captures *variables* it can see at creation time, but it does NOT capture script-
# scoped FUNCTION definitions (those resolve via the function table at call time,
# against the wrong scope, and fail "not recognized"). So the helpers below are
# scriptblock variables; each factory hoists them into factory-locals which the
# method closures then capture by value (the only reliably-portable pattern here).
#
# Calling convention: every backend method takes a SINGLE hashtable of named args,
# invoked as `& $backend.X @{ key = val; ... }`. NB the method parameter is named
# `$P` (NOT `$Args`): `$Args` is an automatic variable and `& $sb @{...}` mis-binds
# the hashtable onto it.

# Read an optional arg key (missing -> $Default). StrictMode-safe.
$script:SbGetArg = {
    param([System.Collections.IDictionary] $P, [string] $Key, $Default = $null)
    if ($null -ne $P -and $P.Contains($Key)) { return $P[$Key] }
    return $Default
}

# Read a required arg key; throw a clear message naming the method + key if absent.
$script:SbAssertArg = {
    param([System.Collections.IDictionary] $P, [string] $Key, [string] $Method)
    if ($null -eq $P -or -not $P.Contains($Key) -or $null -eq $P[$Key] -or
        ($P[$Key] -is [string] -and [string]::IsNullOrWhiteSpace($P[$Key]))) {
        throw "HyperVBackend.${Method}: required argument '$Key' is missing."
    }
    return $P[$Key]
}

# Classify a caught Hyper-V error as the unavailable/insufficient-privilege case.
# Matches the live signature from this host (VirtualizationException +
# "You do not have the required permission ...") plus module-missing / generic
# Hyper-V-not-running shapes, so the fail-closed branch is robust across hosts.
$script:SbIsUnavailableError = {
    param([System.Management.Automation.ErrorRecord] $ErrorRecord)

    if ($null -eq $ErrorRecord) { return $false }
    $ex  = $ErrorRecord.Exception
    $msg = if ($ex) { [string]$ex.Message } else { '' }
    $typeName = if ($ex) { $ex.GetType().FullName } else { '' }

    # Hyper-V's own exception namespace (permission, service-down). Treat the
    # management-access failures as unavailable.
    if ($typeName -like 'Microsoft.HyperV.PowerShell*') {
        if ($msg -match '(?i)(do not have the required permission|access is denied|insufficient)') { return $true }
        if ($msg -match '(?i)(Hyper-V.*not (running|installed|enabled)|virtual machine management service)') { return $true }
    }

    # CommandNotFound -> the Hyper-V PowerShell module/cmdlet isn't present at all.
    if ($ErrorRecord.CategoryInfo -and $ErrorRecord.CategoryInfo.Category -eq 'ObjectNotFound' -and
        $ex -is [System.Management.Automation.CommandNotFoundException]) { return $true }

    # Generic permission / elevation phrasing from any layer.
    if ($msg -match '(?i)(do not have the required permission|requires elevation|access is denied|run as administrator|Hyper-V Administrators)') {
        return $true
    }

    return $false
}

# Detect whether the current process is elevated (best-effort, Windows only).
$script:SbIsElevated = {
    try {
        if (-not $IsWindows) { return $false }
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($id)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

# SHARED real-backend helper (RC5): run a Set-VMFirmware operation with bounded retry on the
# transient Secure-Boot-template enumeration wedge, then a CLEAR actionable failure if it persists.
#
# RC5 (2026-06-24 live): after ~10 rapid create/destroy cycles Hyper-V's vmms wedged its Secure Boot
# template enumeration — `Set-VMFirmware -SecureBootTemplate <any>` failed
#   "... matches none of the secure boot templates known to the host ..."
# for EVERY template (even MicrosoftWindows), and `Restart-Service vmms` did NOT clear it (needed a
# host reboot). The symptom is transient WMI churn, NOT a wrong template, so a few retries with a short
# sleep often ride it out. If it still fails we throw a clear remediation message rather than leave a
# half-provisioned VM (the differencing system disk + VM already exist by the firmware step).
#
# ONLY the enumeration error is retried; any OTHER error rethrows immediately (retrying a genuine
# failure would only waste time and mask the real cause). Factored out as a shared scriptblock so the
# real SetFirmware uses it AND it is unit-testable in-process (drive -Operation with a stub that throws
# the enumeration error N times) without a live Hyper-V. The FAKE SetFirmware does not use it.
$script:SbInvokeFirmwareWithRetry = {
    param(
        [Parameter(Mandatory)] [scriptblock] $Operation,
        [int] $MaxAttempts = 4,
        [int] $DelayMilliseconds = 750
    )
    # The transient-wedge signature (case-insensitive substring of the real Hyper-V message).
    $enumWedge = '*matches none of the secure boot templates*'
    if ($MaxAttempts -lt 1) { $MaxAttempts = 1 }
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return (& $Operation)
        }
        catch {
            $caught = $_
            $message = if ($caught -and $caught.Exception) { [string]$caught.Exception.Message } else { [string]$caught }
            # Not the transient wedge -> a real failure; rethrow unchanged (do NOT retry).
            if ($message -notlike $enumWedge) { throw }
            # The transient wedge: retry until attempts are exhausted, then fail closed with remediation.
            if ($attempt -ge $MaxAttempts) {
                throw ("HyperVBackend.SetFirmware: Set-VMFirmware -SecureBootTemplate kept failing with a " +
                       "Secure Boot template-enumeration error after $MaxAttempts attempts " +
                       "(`"$message`"). This is a known transient Hyper-V vmms wedge under rapid " +
                       "create/destroy churn. Remediation: `Restart-Service vmms`; if that does not clear " +
                       "it, REBOOT the host (a vmms restart is often insufficient). The half-provisioned VM " +
                       "should be torn down before retrying. Failing closed.")
            }
            if ($DelayMilliseconds -gt 0) { Start-Sleep -Milliseconds $DelayMilliseconds }
            # loop and retry
        }
    }
}

# SHARED real-backend helper (RC8): run an operation with bounded retry on a transient FILE-LOCK / sharing-
# violation, then a CLEAR fail-closed failure if the lock persists. Mirrors SbInvokeFirmwareWithRetry.
#
# RC8 (detach settle-lag): `Remove-VMHardDiskDrive` / `Stop-VM` returning does NOT guarantee the Hyper-V
# worker-process handle on the `.vhdx` has been released — a sub-second lag can make ReadVhdxRawRegion's
# qemu-img `convert` first open hit a sharing violation, spuriously failing a SUCCESSFUL run. The symptom
# is a transient handle-release lag, NOT a real failure, so a few retries with a short sleep ride it out.
# If the lock PERSISTS we fail closed with a clear message rather than return garbage / hang.
#
# ONLY a lock-class error is retried (case-insensitive substring match of any of the well-known Windows /
# qemu sharing-violation phrasings); any OTHER error (e.g. a malformed image) rethrows IMMEDIATELY (retrying
# a genuine failure would only waste time and mask the real cause). Factored out as a shared scriptblock so
# the real ReadVhdxRawRegion uses it AND it is unit-testable in-process (drive -Operation with a stub that
# throws a lock-class error N times then returns a sentinel) without a live VM. The FAKE does not use it —
# it models the same bounded tolerance via -SimulateDetachSettleLag; the two budgets share the SAME default
# MaxAttempts (5) so they agree (see the fake ReadVhdxRawRegion + its -SimulateDetachSettleLag tests).
$script:SbInvokeWithLockRetry = {
    param(
        [Parameter(Mandatory)] [scriptblock] $Operation,
        [int] $MaxAttempts = 5,
        [int] $DelayMilliseconds = 400,
        [string] $Context = 'ReadVhdxRawRegion'   # method name for the fail-closed message (backward-compat default)
    )
    # Lock-class signatures (case-insensitive). These are the Windows + qemu-img phrasings for a file that
    # is still open by another handle (the unreleased Hyper-V worker-process handle, here).
    $lockPatterns = @(
        'sharing violation',
        'used by another process',
        'being used by another',
        'Failed to get shared lock',
        'Permission denied'
    )
    if ($MaxAttempts -lt 1) { $MaxAttempts = 1 }
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return (& $Operation)
        }
        catch {
            $caught = $_
            $message = if ($caught -and $caught.Exception) { [string]$caught.Exception.Message } else { [string]$caught }
            $isLock = $false
            foreach ($pat in $lockPatterns) { if ($message -match ('(?i)' + [regex]::Escape($pat))) { $isLock = $true; break } }
            # Not a lock-class error -> a real failure (e.g. malformed image); rethrow unchanged (do NOT retry).
            if (-not $isLock) { throw }
            # A lock-class error: retry until attempts are exhausted, then fail closed with remediation.
            if ($attempt -ge $MaxAttempts) {
                throw ("${Context}: the VHDX is still locked after $MaxAttempts attempts " +
                       "(`"$message`"). The VHDX handle may not have been released after detach " +
                       "(a sub-second Hyper-V worker-process settle-lag that did not clear). " +
                       "Ensure the disk is detached and the VM is Off, then retry. Failing closed.")
            }
            if ($DelayMilliseconds -gt 0) { Start-Sleep -Milliseconds $DelayMilliseconds }
            # loop and retry
        }
    }
}

# Validate a NewOutputVhdx FileSystem + Label EARLY and IDENTICALLY in BOTH factories
# (the fake≠real divergence guard). A bad FileSystem (e.g. 'ext4') or an over-length Label
# is recorded VERBATIM by the fake (test green) yet FAILS live on Format-Volume — so both
# factories call THIS before any cmdlet runs / state write, so they fail the SAME way.
# Returns the FileSystem normalized to its canonical Windows casing (callers store THAT).
# Label length ceilings are the real Windows volume-label limits per filesystem.
$script:SbValidateVhdxFormat = {
    param([string] $FileSystem, [string] $Label)
    # Allowed filesystems -> canonical casing. Case-insensitive lookup; reject anything else.
    $canon = @{ exfat = 'exFAT'; fat32 = 'FAT32'; ntfs = 'NTFS'; fat = 'FAT' }
    $key = if ($null -ne $FileSystem) { ([string]$FileSystem).Trim().ToLowerInvariant() } else { '' }
    if (-not $canon.ContainsKey($key)) {
        throw ("NewOutputVhdx: unsupported FileSystem '$FileSystem' " +
               "(allowed: exFAT, FAT32, NTFS, FAT) — live Format-Volume would reject it.")
    }
    $normalized = $canon[$key]
    # Max volume-label length per filesystem (real Format-Volume limits).
    $maxLabel = @{ exFAT = 15; FAT32 = 11; NTFS = 32; FAT = 11 }[$normalized]
    $labelLen = if ($null -ne $Label) { ([string]$Label).Length } else { 0 }
    if ($labelLen -gt $maxLabel) {
        throw ("NewOutputVhdx: Label '$Label' is $labelLen chars, exceeding the " +
               "$normalized maximum of $maxLabel — live Format-Volume would reject it.")
    }
    return $normalized
}

# SHARED real-backend helper: resolve a usable host drive letter for a just-mounted VHDX, returning
# a validated single A-Z letter (caller builds "<letter>:\<inner>"). This is the "first reuse site"
# the WriteVhdxFile note anticipated — WriteVhdxFile AND ReadVhdxFile both mount a data VHDX and need
# the same volume on the host, so the discovery lives here once instead of drifting in two copies.
#
# It closes two fake≠real first-live-run defects the mock suite structurally cannot exercise (the
# fake models an in-memory Files table, never Mount-VHD/Get-Partition/drive letters):
#   * NULL-$part StrictMode crash — the partition can be slow to surface right after Mount-VHD on a
#     freshly-formatted exFAT volume (the same PnP settle-lag that makes `$img | Get-Disk` transiently
#     $null, which the code already polls for). The Get-Partition discovery had NO retry and then
#     dereferenced `$part.DriveLetter`, so a $null $part threw under Set-StrictMode -Version Latest and
#     aborted the op. Both Get-Disk and Get-Partition are now settle-polled (5x200ms each).
#   * INVALID drive letter — Add-PartitionAccessPath -AssignDriveLetter is an async PnP volume-arrival
#     op; the immediate re-read can return [char]0/blank, and `-not $letter` did not catch [char]0 (it
#     builds a "\0:\file" path and fails confusingly). We poll the assigned letter and HARD-VALIDATE it
#     matches ^[A-Za-z]$, throwing a clear named error otherwise.
# Takes the Mount-VHD -Passthru image + a context string for error messages; runs the storage cmdlets
# directly (the caller invokes it inside its own `& $InvokeOp { }` so a throw is wrapped uniformly).
$script:SbResolveVolumeLetter = {
    param($Image, [string] $Context)
    # Settle-poll the disk (same transient-$null lag NewOutputVhdx guards).
    $disk = $null
    for ($i = 0; $i -lt 5; $i++) {
        $disk = $Image | Get-Disk
        if ($null -ne $disk) { break }
        Start-Sleep -Milliseconds 200
    }
    if ($null -eq $disk) { throw "${Context}: mounted VHD did not surface a disk within the retry window." }
    # Settle-poll the first non-Reserved partition (NO retry here was the StrictMode null-deref bug).
    $part = $null
    for ($i = 0; $i -lt 5; $i++) {
        $part = $disk | Get-Partition | Where-Object { $_.Type -ne 'Reserved' } | Select-Object -First 1
        if ($null -ne $part) { break }
        Start-Sleep -Milliseconds 200
    }
    if ($null -eq $part) { throw "${Context}: mounted VHD's volume did not surface a partition within the retry window." }
    # Assign a drive letter only if one isn't already present. Treat [char]0/blank as 'no letter'
    # (a bare `-not $letter` did not catch [char]0); validate the assigned letter is a real A-Z.
    $letter = $part.DriveLetter
    if ($letter -notmatch '^[A-Za-z]$') {
        $null = $part | Add-PartitionAccessPath -AssignDriveLetter -ErrorAction Stop
        for ($i = 0; $i -lt 5; $i++) {
            # Read the partition OBJECT then the property — Get-Partition can transiently return $null
            # during the same PnP settle-lag the loops above guard, and `($null).DriveLetter` THROWS
            # under StrictMode (it does NOT yield $null), which would defeat this very retry. A $null
            # $letter just continues the loop ($null -notmatch '^[A-Za-z]$' is true).
            $p2 = Get-Partition -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber -ErrorAction SilentlyContinue
            $letter = if ($null -ne $p2) { $p2.DriveLetter } else { $null }
            if ($letter -match '^[A-Za-z]$') { break }
            Start-Sleep -Milliseconds 200
        }
    }
    if ($letter -notmatch '^[A-Za-z]$') {
        throw "${Context}: mounted VHD's volume did not surface a valid drive letter (A-Z) within the retry window."
    }
    return [string]$letter
}

# ==========================================================================
#  REAL BACKEND
# ==========================================================================

<#
.SYNOPSIS
    Build a backend that wraps the REAL Hyper-V cmdlets (fails closed, see file help).
#>
function New-RealHyperVBackend {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    # Hoist the shared helper scriptblocks into factory-locals so each method's
    # .GetNewClosure() captures THEM by value (a closure can't reach a script-scoped
    # function, only a captured variable — see the helpers' header note).
    $GetArg        = $script:SbGetArg
    $AssertArg     = $script:SbAssertArg
    $IsUnavailable = $script:SbIsUnavailableError
    $IsElevated    = $script:SbIsElevated
    $ValidateFmt   = $script:SbValidateVhdxFormat
    $ResolveVol    = $script:SbResolveVolumeLetter
    $FirmwareRetry = $script:SbInvokeFirmwareWithRetry   # RC5: Secure-Boot template-enumeration retry
    $LockRetry     = $script:SbInvokeWithLockRetry       # RC8: detach settle-lag sharing-violation retry
    $unavailPrefix = $script:HyperVUnavailablePrefix

    # Run a real Hyper-V op; convert an availability/permission failure into the single
    # clear fail-closed exception, leave any other error untouched. Local closure so it
    # captures $IsUnavailable + $unavailPrefix and travels with each method.
    $InvokeOp = {
        param([scriptblock] $Operation)
        try { return (& $Operation) }
        catch {
            if (& $IsUnavailable $_) { throw ($unavailPrefix + $_.Exception.Message) }
            throw
        }
    }.GetNewClosure()

    $b = @{}

    # ---- capability probe (NEVER throws) --------------------------------
    $b.TestAvailable = {
        param([System.Collections.IDictionary] $P)
        $elevated = & $IsElevated
        try {
            # The cheapest real management call; reaching it without error means usable.
            Get-VM -ErrorAction Stop | Out-Null
            return @{ Available = $true; Elevated = $elevated; Reason = 'Hyper-V reachable.' }
        }
        catch {
            $reason = if (& $IsUnavailable $_) {
                $unavailPrefix + $_.Exception.Message
            }
            else {
                # Unexpected error — still report unavailable rather than throwing.
                "Hyper-V probe failed: $($_.Exception.Message)"
            }
            return @{ Available = $false; Elevated = $elevated; Reason = $reason }
        }
    }.GetNewClosure()

    # ---- VM lifecycle ----------------------------------------------------
    $b.NewVM = {
        param([System.Collections.IDictionary] $P)
        # Hoist all $P reads into locals BEFORE $InvokeOp (see NewVHD note: an in-InvokeOp
        # `& $GetArg $P ...` is a cross-frame read that can misfire).
        $name  = & $AssertArg $P 'Name' 'NewVM'
        $gen   = & $GetArg $P 'Generation'
        $mem   = & $GetArg $P 'MemoryStartupBytes'
        $path  = & $GetArg $P 'Path'
        $sw    = & $GetArg $P 'SwitchName'
        $noVhd = [bool](& $GetArg $P 'NoVHD')
        & $InvokeOp {
            $p = @{ Name = $name; ErrorAction = 'Stop' }
            if ($null -ne $gen)  { $p.Generation = $gen }
            if ($null -ne $mem)  { $p.MemoryStartupBytes = $mem }
            if ($null -ne $path) { $p.Path = $path }
            if ($null -ne $sw)   { $p.SwitchName = $sw }
            if ($noVhd)          { $p.NoVHD = $true }
            New-VM @p
        }
    }.GetNewClosure()

    $b.GetVM = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'GetVM'
        & $InvokeOp {
            # A missing VM is NOT an error to us: return $null. But we must distinguish
            # "no such VM" (fine) from "can't talk to Hyper-V" (fail closed). Probe first.
            Get-VM -ErrorAction Stop | Out-Null            # raises the permission/availability error if unreachable
            Get-VM -Name $name -ErrorAction SilentlyContinue
        }
    }.GetNewClosure()

    $b.StartVM = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'StartVM'
        & $InvokeOp { Start-VM -Name $name -ErrorAction Stop }
    }.GetNewClosure()

    $b.StopVM = {
        param([System.Collections.IDictionary] $P)
        # Hoist $P reads into locals BEFORE $InvokeOp (see NewVHD note).
        $name    = & $AssertArg $P 'Name' 'StopVM'
        $turnOff = [bool](& $GetArg $P 'TurnOff')
        $force   = [bool](& $GetArg $P 'Force')
        & $InvokeOp {
            $p = @{ Name = $name; ErrorAction = 'Stop' }
            if ($turnOff) { $p.TurnOff = $true }
            if ($force)   { $p.Force   = $true }
            Stop-VM @p
        }
    }.GetNewClosure()

    $b.RemoveVM = {
        param([System.Collections.IDictionary] $P)
        # Mirrors Hyper-V: Remove-VM unregisters the VM but LEAVES its VHDX files on disk.
        # Explicit disk cleanup is the caller's step (the Reaper).
        # Hoist $P reads into locals BEFORE $InvokeOp (see NewVHD note).
        $name  = & $AssertArg $P 'Name' 'RemoveVM'
        $force = [bool](& $GetArg $P 'Force' $true)
        & $InvokeOp {
            Remove-VM -Name $name -Force:$force -ErrorAction Stop
        }
    }.GetNewClosure()

    # ---- hardware --------------------------------------------------------
    $b.SetProcessor = {
        param([System.Collections.IDictionary] $P)
        # Hoist $P reads into locals BEFORE $InvokeOp (see NewVHD note).
        $vm  = & $AssertArg $P 'VMName' 'SetProcessor'
        $cnt = & $GetArg $P 'Count'
        $ext = & $GetArg $P 'ExposeVirtualizationExtensions'
        & $InvokeOp {
            $p = @{ VMName = $vm; ErrorAction = 'Stop' }
            if ($null -ne $cnt) { $p.Count = $cnt }
            if ($null -ne $ext) { $p.ExposeVirtualizationExtensions = [bool]$ext }
            Set-VMProcessor @p
        }
    }.GetNewClosure()

    $b.SetMemory = {
        param([System.Collections.IDictionary] $P)
        # Hoist $P reads into locals BEFORE $InvokeOp (see NewVHD note).
        $vm = & $AssertArg $P 'VMName' 'SetMemory'
        $s  = & $GetArg $P 'StartupBytes'
        $d  = & $GetArg $P 'DynamicMemoryEnabled'
        $mn = & $GetArg $P 'MinimumBytes'
        $mx = & $GetArg $P 'MaximumBytes'
        & $InvokeOp {
            $p = @{ VMName = $vm; ErrorAction = 'Stop' }
            if ($null -ne $s)  { $p.StartupBytes = $s }
            if ($null -ne $d)  { $p.DynamicMemoryEnabled = [bool]$d }
            if ($null -ne $mn) { $p.MinimumBytes = $mn }
            if ($null -ne $mx) { $p.MaximumBytes = $mx }
            Set-VMMemory @p
        }
    }.GetNewClosure()

    $b.SetFirmware = {
        param([System.Collections.IDictionary] $P)
        # Hoist $P reads into locals BEFORE $InvokeOp (see NewVHD note).
        $vm   = & $AssertArg $P 'VMName' 'SetFirmware'
        $sb   = & $GetArg $P 'EnableSecureBoot'
        $tmpl = & $GetArg $P 'SecureBootTemplate'
        $bo   = & $GetArg $P 'BootOrder'
        & $InvokeOp {
            $p = @{ VMName = $vm; ErrorAction = 'Stop' }
            if ($null -ne $sb)   { $p.EnableSecureBoot = ([bool]$sb ? 'On' : 'Off') }
            if ($null -ne $tmpl) { $p.SecureBootTemplate = $tmpl }
            if ($null -ne $bo)   { $p.BootOrder = $bo }
            # RC5: route through the bounded retry so a transient Secure-Boot template-enumeration wedge
            # (vmms WMI hiccup under rapid create/destroy churn) is ridden out, and a persistent one
            # fails closed with a clear restart-vmms/reboot-host message instead of a raw cmdlet error.
            # The helper only retries that specific enumeration error; any other failure rethrows at once.
            & $FirmwareRetry -Operation { Set-VMFirmware @p }
        }
    }.GetNewClosure()

    # RC7: turn Hyper-V's automatic checkpoints OFF (or on). Hyper-V defaults
    # AutomaticCheckpointsEnabled=ON, which pins a differencing .avhdx per disk at VM start so the host
    # reads the empty BASE .vhdx instead of the guest's writes. The Provisioner calls this at provision
    # time with Enabled=$false. Effect-only; route through $InvokeOp like the rest of the real backend.
    # Hoist $P reads into locals BEFORE $InvokeOp (see NewVHD note).
    $b.SetAutomaticCheckpoints = {
        param([System.Collections.IDictionary] $P)
        $vm      = & $AssertArg $P 'VMName' 'SetAutomaticCheckpoints'
        $enabled = [bool](& $GetArg $P 'Enabled' $false)
        & $InvokeOp {
            $null = Set-VM -Name $vm -AutomaticCheckpointsEnabled $enabled -ErrorAction Stop
        }
    }.GetNewClosure()

    $b.SetComPort = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $AssertArg $P 'VMName' 'SetComPort'
        $num  = & $GetArg $P 'Number' 1
        $path = & $AssertArg $P 'Path' 'SetComPort'
        & $InvokeOp {
            Set-VMComPort -VMName $vm -Number $num -Path $path -ErrorAction Stop
        }
    }.GetNewClosure()

    # Host-TRUTH read of a VM's COM port. The post-seal COM1-liveness assertion (Assert-Sealed) reads
    # the Runner's serial command channel through THIS method so the seal can be POSITIVELY verified to
    # have NOT severed it. Returns @{ Number; Path } when the port carries a pipe path, or $null when
    # there is no such port OR its path is empty (an unattached / placeholder COM port is "not live").
    # Hoist $P reads into locals BEFORE $InvokeOp (see NewVHD note).
    $b.GetComPort = {
        param([System.Collections.IDictionary] $P)
        $vm  = & $AssertArg $P 'VMName' 'GetComPort'
        $num = [int](& $GetArg $P 'Number' 1)
        & $InvokeOp {
            $port = Get-VMComPort -VMName $vm -Number $num -ErrorAction SilentlyContinue
            if ($null -eq $port) { return $null }
            $portPath = [string]$port.Path
            if ([string]::IsNullOrWhiteSpace($portPath)) { return $null }
            return @{ Number = [int]$port.Number; Path = $portPath }
        }
    }.GetNewClosure()

    # ---- guest command delivery over the COM1 serial console (RUNNER seam) -----
    # Drive a Linux guest's serial-getty console over the host-side COM1 NAMED PIPE wired by
    # SetComPort (\\.\pipe\<vm>-com1). PowerShell Direct is Windows-guest-only; for a Linux guest
    # the only no-NIC management channel is this serial console. We open the named pipe as a client,
    # write the command terminated by a newline (the guest's getty/shell executes it), then read the
    # response with a timeout. We wrap the command so the guest emits a parseable exit-code marker:
    #   <command>; echo "__VMDEP_RC__:$?"
    # and parse the trailing RC marker out of the captured stream. This is a BEST-EFFORT v1 serial
    # transport: the live-VM serial protocol is exercised in the live smoke test (operator-run,
    # elevated), not here (the real backend's internals are not behaviorally unit-tested —
    # the FAKE carries the Runner's behavioral assertions). Fails closed through $InvokeOp like the
    # rest of the real backend. The guest is presumed to have serial-getty@ttyS0 + autologin per the
    # cloud-init recipe; if the pipe is unreachable this throws a clear error rather than hanging.
    $b.InvokeGuestCommand = {
        param([System.Collections.IDictionary] $P)
        $vm      = & $AssertArg $P 'VMName'  'InvokeGuestCommand'
        $command = & $AssertArg $P 'Command' 'InvokeGuestCommand'
        $timeout = [int](& $GetArg $P 'TimeoutSeconds' 300)
        & $InvokeOp {
            # The COM1 pipe SetComPort wires for this VM (matches the Provisioner's ComPipePath).
            $pipeName = "{0}-com1" -f $vm
            $marker   = '__VMDEP_RC__'
            $client   = $null
            $reader   = $null
            $writer   = $null
            try {
                $client = [System.IO.Pipes.NamedPipeClientStream]::new(
                    '.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
                # Connect with a bounded wait so an unreachable pipe fails fast (ms).
                $client.Connect([Math]::Min($timeout, 30) * 1000)

                $writer = [System.IO.StreamWriter]::new($client)
                $writer.AutoFlush = $true
                $reader = [System.IO.StreamReader]::new($client)

                # Send the command + an RC sentinel so we can parse the exit code out of the stream.
                $writer.WriteLine("{0}; echo `"{1}:`$?`"" -f $command, $marker)

                # Read until we see the RC marker or the timeout elapses.
                $sb       = [System.Text.StringBuilder]::new()
                $exitCode = $null
                $deadline = (Get-Date).AddSeconds($timeout)
                while ((Get-Date) -lt $deadline) {
                    $line = $reader.ReadLine()
                    if ($null -eq $line) { break }
                    if ($line -match [regex]::Escape($marker) + ':(\d+)') {
                        $exitCode = [int]$Matches[1]
                        break
                    }
                    [void]$sb.AppendLine($line)
                }
                if ($null -eq $exitCode) {
                    throw "InvokeGuestCommand: timed out after ${timeout}s waiting for the guest to complete '$command' on COM1 pipe '$pipeName' (no '$marker' marker seen)."
                }
                return @{ ExitCode = $exitCode; Stdout = $sb.ToString(); Stderr = '' }
            }
            finally {
                if ($null -ne $reader) { $reader.Dispose() }
                if ($null -ne $writer) { $writer.Dispose() }
                if ($null -ne $client) { $client.Dispose() }
            }
        }
    }.GetNewClosure()

    # ---- host channels (SEAL surface) ---------------------------------
    # Toggle ONE host<->guest channel on/off. The four logical channels split into TWO classes on a
    # Linux guest (the deployer's target — stock Debian/Ubuntu/etc. cloud images):
    #
    #   GuestServices  = the ONE REAL autonomous host<->guest DATA channel. Maps to
    #                    Enable/Disable-VMIntegrationService 'Guest Service Interface' (the
    #                    Copy-VMFile / file-copy VMBus channel). This is the channel the seal MUST
    #                    close and Assert-Sealed MUST host-verify (its GET reads the real .Enabled,
    #                    fail-closed). Kept exactly as-is — DO NOT weaken.
    #
    #   EnhancedSession / Clipboard / Shares = ESM facets. On Hyper-V there is NO per-facet cmdlet
    #                    and — critically — NO per-VM "ESM off" toggle at all. ESM clipboard / drive-
    #                    redirection is delivered by Windows-guest components (xrdp + hv_sock RDP-over-
    #                    VMBus) that a stock Linux cloud image structurally LACKS, and it is an
    #                    INTERACTIVE channel (a human at a VMConnect window), never an autonomous
    #                    exfil path. So these are NOT live autonomous channels on a Linux guest. The
    #                    seal still closes the interactive KVM surface BEST-EFFORT via
    #                    Disable-VMConsoleSupport (belt-and-braces — confirmed on a live host NOT to
    #                    break the COM1 serial management pipe); the enable path is kept symmetric.
    #
    # A real-backend bug found during live debugging (retained): the EnhancedSession disable previously
    # mapped to `Set-VM -EnhancedSessionTransportType None|HvSocket`. That enum has ONLY `VMBus`/`HvSocket`
    # (no `None`) so the disable was an INVALID BIND that threw before any cmdlet ran and aborted the
    # seal. The correct per-VM mechanism is `Disable-VMConsoleSupport` (console/KVM off); ON is
    # `Enable-VMConsoleSupport`. We NEVER touch Set-VM's transport enum and NEVER
    # `Set-VMHost -EnableEnhancedSessionMode` (host-global; default ON; flipping it would mutate
    # every VM's config and is not a per-VM seal anyway).
    #
    # A further live bug — the GET half (see GetHostChannels below): the earlier GET keyed the three ESM
    # facets off the WMI `Msvm_VirtualSystemSettingData.ConsoleMode`. A LIVE diagnostic proved
    # Disable-VMConsoleSupport does NOT change ConsoleMode (it stays 0), so that read reported the
    # facets ON forever and Assert-Sealed could NEVER certify a real Linux VM. The fix reports the
    # ESM facets OFF BY CONSTRUCTION (see GetHostChannels). The SET path here is unchanged.
    $channelNames = $script:HostChannelNames
    $b.SetHostChannel = {
        param([System.Collections.IDictionary] $P)
        $vm      = & $AssertArg $P 'VMName'  'SetHostChannel'
        $channel = & $AssertArg $P 'Channel' 'SetHostChannel'
        if ($channelNames -notcontains $channel) {
            throw "HyperVBackend.SetHostChannel: unknown channel '$channel' (expected one of: $($channelNames -join ', '))."
        }
        $enabled = [bool](& $GetArg $P 'Enabled' $false)
        & $InvokeOp {
            switch ($channel) {
                'GuestServices' {
                    if ($enabled) { Enable-VMIntegrationService  -VMName $vm -Name 'Guest Service Interface' -ErrorAction Stop }
                    else          { Disable-VMIntegrationService -VMName $vm -Name 'Guest Service Interface' -ErrorAction Stop }
                }
                'EnhancedSession' {
                    # Per-VM Enhanced Session / console channel. Disable = the seal (KVM off, no
                    # clipboard / drive redirection). NEVER Set-VM -EnhancedSessionTransportType
                    # (None is not a valid enum value) and NEVER Set-VMHost (host-global).
                    if ($enabled) { Enable-VMConsoleSupport  -VMName $vm -ErrorAction Stop }
                    else          { Disable-VMConsoleSupport -VMName $vm -ErrorAction Stop }
                }
                default {
                    # Clipboard / Shares are facets of Enhanced Session — disabling the ESM/console
                    # channel disables them; enabling re-enables. The Sealer only ever turns them
                    # OFF, so disable rides on Disable-VMConsoleSupport (same mechanism as above);
                    # the enable path is kept symmetric. No transport-enum, no host-global toggle.
                    if ($enabled) { Enable-VMConsoleSupport  -VMName $vm -ErrorAction Stop }
                    else          { Disable-VMConsoleSupport -VMName $vm -ErrorAction Stop }
                }
            }
        }
    }.GetNewClosure()

    $b.GetHostChannels = {
        param([System.Collections.IDictionary] $P)
        $vm = & $AssertArg $P 'VMName' 'GetHostChannels'
        & $InvokeOp {
            # Host-side read of the host<->guest channels — the authoritative seal check.
            #
            # GuestServices = the ONE channel the host can read as TRUE per-VM state: the Guest
            # Service Interface integration service (the Copy-VMFile / file-copy VMBus channel — the
            # one REAL autonomous host<->guest data channel). This read is FAIL-CLOSED: the catch
            # RETHROWS. If it fails, the host cannot know whether the bidirectional Copy-VMFile
            # channel is live, so the seal gate (Assert-Sealed) MUST fail closed. Swallowing the
            # error to $gsiOn=$false would report GuestServices OFF while actually ON and let
            # Assert-Sealed certify SEALED with the worst channel live — a fail-OPEN. DO NOT weaken.
            $gsiOn = $false
            try {
                $gsi = Get-VMIntegrationService -VMName $vm -Name 'Guest Service Interface' -ErrorAction Stop
                $gsiOn = [bool]$gsi.Enabled
            }
            catch { throw }   # SECURITY: an unreadable REAL channel MUST propagate — never coerce to off.

            # EnhancedSession / Clipboard / Shares = ESM facets, reported OFF BY CONSTRUCTION.
            #
            # A live bug fix: there is NO per-VM "ESM on" signal the host can read. The earlier GET
            # tried the WMI console-mode property, but a LIVE diagnostic on a real Gen2 VM proved
            # Disable-VMConsoleSupport does NOT change that property (it stays at its default both
            # before AND after the call). So a property-keyed read ALWAYS evaluated "ESM on" => these
            # three reported ON forever => Assert-Sealed could NEVER certify a real, correctly-sealed
            # Linux VM (the seal refused on the live host every time). The ESM clipboard / drive-
            # redirection facets are also structurally absent on a stock Linux guest (they need
            # Windows-guest xrdp + hv_sock RDP-over-VMBus components the image lacks) AND are
            # interactive-only (a human at a VMConnect window), never an autonomous exfil path. So they
            # cannot be a live autonomous channel regardless of any per-VM setting. We therefore report
            # them OFF: the seal closes the interactive KVM surface BEST-EFFORT via
            # Disable-VMConsoleSupport (SetHostChannel above) and relies on their structural absence.
            # This keeps the gate HONEST — it stops asserting on a phantom per-VM ESM signal that does
            # not exist — WITHOUT weakening the GuestServices/NIC/DVD/secret-disk checks that are the
            # real boundary.
            #
            # NB: this is host-OS-agnostic by design (Option A) — the host genuinely cannot expose a
            # per-VM ESM-on signal for ANY guest, and ESM is interactive+Windows-only, so reporting
            # the facets off is correct for the deployer's Linux-guest target and not unsafe for any
            # other guest (the autonomous boundary is GuestServices + NIC + DVD + disks, all still
            # hard-verified below in Assert-Sealed).
            return @{
                Clipboard       = $false
                Shares          = $false
                GuestServices   = $gsiOn
                EnhancedSession = $false
            }
        }
    }.GetNewClosure()

    # ---- disk ------------------------------------------------------------
    $b.NewVHD = {
        param([System.Collections.IDictionary] $P)
        # Read EVERY $P/$GetArg/$AssertArg-derived arg into method-body LOCALS *before* entering
        # $InvokeOp. The inner op block (a plain scriptblock run via `& $Operation` from $InvokeOp's
        # frame) must reference ONLY plain locals — a cross-frame `& $GetArg $P ...` evaluated as an
        # `if` condition inside that block misfires (it read Differencing=$true yet took the ELSE
        # branch, asserting SizeBytes and throwing on a differencing child — a real-backend bug found during live debugging).
        $path   = & $AssertArg $P 'Path' 'NewVHD'
        $isDiff = [bool](& $GetArg $P 'Differencing')
        if ($isDiff) {
            $parent = & $AssertArg $P 'ParentPath' 'NewVHD(-Differencing)'
        }
        else {
            $size = & $AssertArg $P 'SizeBytes' 'NewVHD'
            # Default to dynamic unless explicitly told fixed.
            $dyn  = [bool](& $GetArg $P 'Dynamic' $true)
        }
        & $InvokeOp {
            $p = @{ Path = $path; ErrorAction = 'Stop' }
            if ($isDiff) {
                $p.Differencing = $true
                $p.ParentPath   = $parent
            }
            else {
                $p.SizeBytes = $size
                if ($dyn) { $p.Dynamic = $true } else { $p.Fixed = $true }
            }
            New-VHD @p
        }
    }.GetNewClosure()

    # Create AND host-format a data VHDX in one shot (the workload output disk). A bare New-VHD
    # leaves an UNINITIALIZED disk; this also GPT-initializes it, makes one max-size partition, and
    # formats that partition with the requested filesystem + label so the guest can mount it and the
    # host can read results off the named volume afterward. Hoist EVERY $P read into method-body
    # locals BEFORE $InvokeOp (see NewVHD note: a cross-frame $P-read inside the op block misfires).
    $b.NewOutputVhdx = {
        param([System.Collections.IDictionary] $P)
        $path  = & $AssertArg $P 'Path'       'NewOutputVhdx'
        $label = & $AssertArg $P 'Label'      'NewOutputVhdx'
        $fs    = & $AssertArg $P 'FileSystem' 'NewOutputVhdx'
        $size  = & $AssertArg $P 'SizeBytes'  'NewOutputVhdx'
        # Shared fake≠real guard: validate FileSystem + Label BEFORE any cmdlet runs, so a bad
        # FileSystem / over-length Label fails here (identically to the fake) instead of deep
        # inside live Format-Volume. Use the NORMALIZED filesystem casing from here on.
        $fs = & $ValidateFmt $fs $label
        & $InvokeOp {
            # If create succeeds but Mount/Initialize/Partition/Format throws, the .vhdx is left on
            # disk and a re-run trips on the orphan. Wrap so on failure we dismount AND remove the
            # half-created file before rethrowing. (Note for the Provisioner: this self-cleanup
            # of its OWN orphan must not double-fight the Provisioner's rollback — RemoveVHD is
            # idempotent, so a later rollback delete of an already-gone path is a harmless no-op.)
            $null = New-VHD -Path $path -Dynamic -SizeBytes $size -ErrorAction Stop
            try {
                $img = Mount-VHD -Path $path -Passthru -ErrorAction Stop
                try {
                    # On live Hyper-V `$img | Get-Disk` can transiently return $null during the
                    # mount-settle lag, so $disk.Number would throw under StrictMode. Poll briefly.
                    $disk = $null
                    for ($i = 0; $i -lt 5; $i++) {
                        $disk = $img | Get-Disk
                        if ($null -ne $disk) { break }
                        Start-Sleep -Milliseconds 200
                    }
                    if ($null -eq $disk) { throw "NewOutputVhdx: mounted VHD '$path' did not surface a disk within the retry window." }
                    # Only initialize a RAW disk — a re-attached/already-initialized disk throws.
                    if ($disk.PartitionStyle -eq 'RAW') { $null = Initialize-Disk -Number $disk.Number -PartitionStyle GPT -ErrorAction Stop }
                    $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -ErrorAction Stop
                    $null = Format-Volume -Partition $part -FileSystem $fs -NewFileSystemLabel $label -Confirm:$false -ErrorAction Stop
                }
                finally {
                    # A swallowed dismount failure here would surface later as an opaque sharing-violation
                    # when New-WorkloadDisks attaches the disk. Log it, but don't let it mask a format error.
                    try { Dismount-VHD -Path $path -ErrorAction Stop }
                    catch { Write-Warning "NewOutputVhdx: host VHDX '$path' did not dismount cleanly ($($_.Exception.Message)); it may remain locked for the next host operation." }
                }
            }
            catch {
                # Format failed after the file was created — remove the orphan so a re-run isn't blocked.
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
                throw
            }
        }
    }.GetNewClosure()

    # Host-populate / host-read a single file INSIDE a VHDX. The Provisioner uses these to drop
    # a workload's seed/input onto the data disk before boot (write) and to read the run's results
    # back off the named output volume after the seal (read). BOTH mount READ-WRITE (the read mounts RW
    # too — a read-only mount often won't auto-assign a drive letter; see the ReadVhdxFile note). The
    # shared $script:SbResolveVolumeLetter helper does the mount-settle-tolerant disk+partition discovery
    # and drive-letter validation for both (this IS the "first reuse site" the old inline note flagged).
    # ALWAYS dismount in finally (loudly — a swallowed stuck mount bites the next op). Hoist every $P
    # read into locals BEFORE $InvokeOp.
    $b.WriteVhdxFile = {
        param([System.Collections.IDictionary] $P)
        $path = & $AssertArg $P 'Path' 'WriteVhdxFile'
        $inner = & $AssertArg $P 'InnerPath' 'WriteVhdxFile'
        $content = & $AssertArg $P 'Content' 'WriteVhdxFile'
        & $InvokeOp {
            $img = Mount-VHD -Path $path -Passthru -ErrorAction Stop
            try {
                $letter = & $ResolveVol $img 'WriteVhdxFile'
                Set-Content -LiteralPath ("{0}:\{1}" -f $letter, $inner) -Value $content -NoNewline -Encoding utf8 -ErrorAction Stop
            }
            finally {
                # Don't silently swallow a dismount failure: a stuck mount surfaces two steps later as an
                # opaque sharing-violation on the next Mount/Attach of the same VHDX. Log loudly, but catch
                # inside the finally so a dismount failure never masks the primary (write) error.
                try { Dismount-VHD -Path $path -ErrorAction Stop }
                catch { Write-Warning "WriteVhdxFile: host VHDX '$path' did not dismount cleanly ($($_.Exception.Message)); it may remain locked for the next host operation." }
            }
        }
    }.GetNewClosure()

    # Mount READ-WRITE (not -ReadOnly), deliberately mirroring WriteVhdxFile. A read-only mount on
    # Windows frequently does NOT auto-assign a drive letter, and `Add-PartitionAccessPath
    # -AssignDriveLetter` against a write-protected volume can throw — which would make the FIRST
    # live result-read spuriously fail ("result read failed") and send the operator hunting a guest
    # bug that is actually host-side. RW is safe HERE because the volume is the deployer's OWN
    # host-formatted OUTPUT disk, already detached from the now-powered-off guest, and reading does
    # not mutate the file content. The untrusted-guest-output case (Tier >= 2) never reaches this
    # method — Read-WorkloadResult routes those to cold quarantine (throws) BEFORE calling ReadVhdxFile.
    $b.ReadVhdxFile = {
        param([System.Collections.IDictionary] $P)
        $path = & $AssertArg $P 'Path' 'ReadVhdxFile'
        $inner = & $AssertArg $P 'InnerPath' 'ReadVhdxFile'
        & $InvokeOp {
            $img = Mount-VHD -Path $path -Passthru -ErrorAction Stop
            try {
                $letter = & $ResolveVol $img 'ReadVhdxFile'
                $fp = "{0}:\{1}" -f $letter, $inner
                if (Test-Path -LiteralPath $fp) { return (Get-Content -LiteralPath $fp -Raw -ErrorAction Stop) }
                return $null
            }
            finally {
                # Log a stuck dismount loudly (it would surface later as an opaque lock), but catch inside
                # the finally so it never masks the primary (read) error.
                try { Dismount-VHD -Path $path -ErrorAction Stop }
                catch { Write-Warning "ReadVhdxFile: host VHDX '$path' did not dismount cleanly ($($_.Exception.Message)); it may remain locked for the next host operation." }
            }
        }
    }.GetNewClosure()

    # Read a raw byte range from a FIXED VHDX's payload WITHOUT attaching/mounting it. qemu-img does the
    # VHDX -> logical-block translation (so a logical Offset == the byte offset in the flat raw output);
    # we then seek/read the requested slice. NEVER Mount-VHD: even -ReadOnly host-attach runs partmgr.sys
    # + FS-recognizer parses on attacker bytes (Pass-5, verified). REQUIRES the VHDX DETACHED + the VM Off
    # (qemu-img cannot open a Hyper-V-locked file) — the orchestrator's $detachOk guard enforces that.
    # LIVE-ONLY-UNPROVEN until Phase 6 (the mock never runs this); re-resolve the exact qemu-img
    # invocation at fire. Fails closed with a clear message if qemu-img is absent or the file is locked.
    # Hoist every $P read into locals BEFORE $InvokeOp (see NewVHD note).
    $b.ReadVhdxRawRegion = {
        param([System.Collections.IDictionary] $P)
        $path   = & $AssertArg $P 'Path'   'ReadVhdxRawRegion'
        $offset = [int64](& $AssertArg $P 'Offset' 'ReadVhdxRawRegion')
        $length = [int64](& $AssertArg $P 'Length' 'ReadVhdxRawRegion')
        & $InvokeOp {
            # Bounds FIRST (matches the fake's check-order). Non-negative, then the 2GB single-read ceiling:
            # [byte[]]::new($length) + [int][Math]::Min(...) only accept Int32, so a >2GB value would throw an
            # opaque CLR exception — guard with a clear fail-closed message instead (M-d). The outbox MAX_TOTAL
            # is 64MiB so this is a clean message, not a real limit.
            if ($offset -lt 0 -or $length -lt 0) { throw "ReadVhdxRawRegion: Offset/Length must be non-negative (got Offset=$offset, Length=$length)." }
            if ($length -gt [int]::MaxValue -or $offset -gt [int]::MaxValue) {
                throw "ReadVhdxRawRegion: Offset/Length exceeds the supported 2GB single-read limit ($offset/$length) — failing closed."
            }
            $qemu = Get-Command qemu-img -ErrorAction SilentlyContinue
            if ($null -eq $qemu) {
                throw "ReadVhdxRawRegion: qemu-img not found on PATH. The user-space OUTPUT read needs qemu-img (host attach of an untrusted guest disk is FORBIDDEN — host attach kernel-parses attacker bytes; Pass-5). Install qemu-img and retry. Failing closed."
            }
            $tmpRaw = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "voidseal-outbox-$([System.IO.Path]::GetRandomFileName()).raw")
            try {
                # RC8 (detach settle-lag): Remove-VMHardDiskDrive/Stop-VM returning does NOT guarantee the
                # Hyper-V worker-process handle on the .vhdx is released — qemu-img's first open can hit a
                # transient sharing violation and spuriously fail a SUCCESSFUL run. Route the convert through
                # the shared lock-retry helper: a LOCK-CLASS error rides out (the handle is releasing), a real
                # failure (e.g. malformed image) rethrows at once, and a persistent lock fails closed clearly.
                # qemu-img is a NATIVE exe (non-zero $LASTEXITCODE, not a thrown error), so the Operation block
                # converts a non-zero exit INTO a throw that INCLUDES the trimmed qemu output — that also
                # surfaces qemu's stderr (M-a) AND lets the helper's pattern match classify lock vs malformed.
                & $LockRetry -Operation {
                    # -f vhdx pins the input format (never auto-probe an attacker-influenced header into a
                    # surprising driver); -O raw flattens to logical-block order. '--' ends option parsing.
                    $out = & $qemu.Source convert -f vhdx -O raw -- $path $tmpRaw 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        $detail = ([string]($out -join "`n")).Trim()
                        throw "ReadVhdxRawRegion: qemu-img convert failed (exit $LASTEXITCODE) for '$path' — the VHDX may still be attached/locked (detach first) or be malformed. qemu-img output: $detail"
                    }
                }
                # M-a post-convert sanity: a successful (exit 0) convert must have produced a non-empty raw
                # image. A missing / zero-byte $tmpRaw indicates a silently-failed convert — fail closed
                # rather than read zeros and report a false-empty outbox.
                if (-not (Test-Path -LiteralPath $tmpRaw) -or ((Get-Item -LiteralPath $tmpRaw).Length -le 0)) {
                    throw "ReadVhdxRawRegion: qemu-img convert reported success but produced no raw output for '$path' — failing closed."
                }
                $fsr = [System.IO.File]::OpenRead($tmpRaw)
                try {
                    $buf = [byte[]]::new($length)   # zero-initialized: an over-read past EOF keeps the zero tail (honest FIXED-disk)
                    if ($offset -lt $fsr.Length) {
                        $null  = $fsr.Seek($offset, [System.IO.SeekOrigin]::Begin)
                        $avail = [int][Math]::Min($length, $fsr.Length - $offset)
                        $read  = 0
                        while ($read -lt $avail) {
                            $n = $fsr.Read($buf, $read, $avail - $read)
                            if ($n -le 0) { break }
                            $read += $n
                        }
                    }
                    return ,$buf   # unary comma: return the byte[] as ONE array (PS unrolls a bare array)
                }
                finally { $fsr.Dispose() }
            }
            finally { Remove-Item -LiteralPath $tmpRaw -Force -ErrorAction SilentlyContinue }
        }
    }.GetNewClosure()

    # Whole-.vhdx-file SHA-256 in USER-SPACE — the supply-chain artifact fingerprint Phase 3 verifies
    # before AddHardDiskDrive. NEVER Mount-VHD / attach: an integrity fingerprint needs no FS parse, so
    # the host kernel never touches attacker bytes (Pass-5). NO qemu (D-3) — we stream the file as-is.
    # REQUIRES the .vhdx DETACHED + the VM Off (an attached disk is locked) — the orchestrator's
    # $detachOk guard enforces that. RC8: the FIRST OpenRead after a detach can hit a transient sharing
    # violation while the Hyper-V worker handle releases; route open+hash through the shared $LockRetry
    # (a lock-class error rides out, a real failure — e.g. a missing file — rethrows at once, a
    # persistent lock fails closed clearly with Context='GetVhdxImageHash'). LIVE-ONLY-UNPROVEN until
    # Phase 6 (the mock never runs this).
    $b.GetVhdxImageHash = {
        param([System.Collections.IDictionary] $P)
        $path = & $AssertArg $P 'Path' 'GetVhdxImageHash'
        & $InvokeOp {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "GetVhdxImageHash: VHDX '$path' does not exist (cannot hash a missing artifact). Failing closed."
            }
            return (& $LockRetry -Context 'GetVhdxImageHash' -Operation {
                $fsr = [System.IO.File]::OpenRead($path)   # a lock-class IOException here is what $LockRetry rides out
                try {
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    try { $digest = $sha.ComputeHash($fsr) } finally { $sha.Dispose() }
                    return [System.BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
                }
                finally { $fsr.Dispose() }
            })
        }
    }.GetNewClosure()

    $b.GetVHDInfo = {
        param([System.Collections.IDictionary] $P)
        $path = & $AssertArg $P 'Path' 'GetVHDInfo'
        & $InvokeOp {
            $v = Get-VHD -Path $path -ErrorAction SilentlyContinue
            if ($null -eq $v) { return $null }
            return @{
                Path         = $v.Path
                SizeBytes    = $v.Size
                Differencing = ($v.VhdType -eq 'Differencing')
                ParentPath   = $v.ParentPath
            }
        }
    }.GetNewClosure()

    # Delete a DETACHED .vhdx file. Addendum method (the Reaper's explicit disk-cleanup
    # step, the thing RemoveVM intentionally does NOT do). On the real host a VHDX is a plain
    # file once the VM is unregistered, so this is a filesystem delete — NOT a Hyper-V cmdlet.
    # Idempotent: deleting an absent path is a no-op (mirrors the fake). The caller (Remove-
    # Sandbox -DeleteDisks) is responsible for detaching/unregistering first.
    $b.RemoveVHD = {
        param([System.Collections.IDictionary] $P)
        $path = & $AssertArg $P 'Path' 'RemoveVHD'
        & $InvokeOp {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            }
        }
    }.GetNewClosure()

    $b.AddHardDiskDrive = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $AssertArg $P 'VMName' 'AddHardDiskDrive'
        $path = & $AssertArg $P 'Path'   'AddHardDiskDrive'
        & $InvokeOp {
            Add-VMHardDiskDrive -VMName $vm -Path $path -ErrorAction Stop
        }
    }.GetNewClosure()

    $b.RemoveHardDiskDrive = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $AssertArg $P 'VMName' 'RemoveHardDiskDrive'
        $path = & $AssertArg $P 'Path'   'RemoveHardDiskDrive'
        & $InvokeOp {
            # Find the controller slot holding this path, then detach (Remove-VMHardDiskDrive
            # takes controller coords, not a path). Detach only — the VHDX file is left on disk.
            $drive = Get-VMHardDiskDrive -VMName $vm -ErrorAction Stop |
                     Where-Object { $_.Path -eq $path } | Select-Object -First 1
            if ($null -ne $drive) { $drive | Remove-VMHardDiskDrive -ErrorAction Stop }
        }
    }.GetNewClosure()

    $b.SetDvdDrive = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $AssertArg $P 'VMName' 'SetDvdDrive'
        $path = & $AssertArg $P 'Path'   'SetDvdDrive'
        & $InvokeOp {
            $existing = Get-VMDvdDrive -VMName $vm -ErrorAction SilentlyContinue
            if ($existing) { Set-VMDvdDrive -VMName $vm -Path $path -ErrorAction Stop }
            else           { Add-VMDvdDrive -VMName $vm -Path $path -ErrorAction Stop }
        }
    }.GetNewClosure()

    $b.RemoveDvdDrive = {
        param([System.Collections.IDictionary] $P)
        $vm = & $AssertArg $P 'VMName' 'RemoveDvdDrive'
        & $InvokeOp {
            Get-VMDvdDrive -VMName $vm -ErrorAction Stop | Remove-VMDvdDrive -ErrorAction Stop
        }
    }.GetNewClosure()

    # Host-TRUTH read of the attached DVD media (SEAL/GATE addendum). A real Get-VM object has
    # NO DvdDrive property — DVD state lives in the DVDDrives collection, read via Get-VMDvdDrive.
    # Each DVD slot exposes its media path via .Path; a slot with no media has a $null Path and is
    # EXCLUDED (an empty slot is not an attached medium). Returns a unary-comma-wrapped collection
    # so a single attached DVD keeps `.Count` semantics for an unwrapped caller (same contract as
    # GetNetworkAdapter / GetCheckpoint). The comma MUST be at the OUTERMOST return — $InvokeOp's
    # `return (& $op)` re-enumerates and would strip an inner comma, re-unrolling a single element.
    $b.GetDvdDrives = {
        param([System.Collections.IDictionary] $P)
        $vm = & $AssertArg $P 'VMName' 'GetDvdDrives'
        return ,@(& $InvokeOp {
            Get-VMDvdDrive -VMName $vm -ErrorAction Stop |
                Where-Object { $_.Path } | ForEach-Object { [string]$_.Path }
        })
    }.GetNewClosure()

    # ---- switch / network ------------------------------------------------
    $b.NewSwitch = {
        param([System.Collections.IDictionary] $P)
        # Hoist ALL $P reads into locals BEFORE $InvokeOp (see NewVHD note): the External branch
        # previously read `& $AssertArg $P 'NetAdapterName'` INSIDE the op block — the same
        # cross-frame $P-read pattern that bit NewVHD.
        $name = & $AssertArg $P 'Name' 'NewSwitch'
        $type = & $GetArg $P 'SwitchType' 'Internal'
        $adapter = $null
        if ($type -eq 'External') {
            $adapter = & $AssertArg $P 'NetAdapterName' 'NewSwitch(External)'
        }
        & $InvokeOp {
            if ($type -eq 'External') {
                New-VMSwitch -Name $name -NetAdapterName $adapter -ErrorAction Stop
            }
            else {
                New-VMSwitch -Name $name -SwitchType $type -ErrorAction Stop
            }
        }
    }.GetNewClosure()

    $b.GetSwitch = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'GetSwitch'
        & $InvokeOp {
            Get-VMSwitch -ErrorAction Stop | Out-Null     # availability probe
            Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
        }
    }.GetNewClosure()

    # Delete a vSwitch. Addendum method (the Provisioner's mid-provision ROLLBACK deletes
    # any switch it created so a failed provision leaves no orphaned vSwitch; also usable by
    # the Sealer). Idempotent: removing an absent switch is a no-op (mirrors the fake).
    $b.RemoveSwitch = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'RemoveSwitch'
        & $InvokeOp {
            $sw = Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $sw) { Remove-VMSwitch -Name $name -Force -ErrorAction Stop }
        }
    }.GetNewClosure()

    $b.ConnectNetworkAdapter = {
        param([System.Collections.IDictionary] $P)
        $vm = & $AssertArg $P 'VMName'     'ConnectNetworkAdapter'
        $sw = & $AssertArg $P 'SwitchName' 'ConnectNetworkAdapter'
        & $InvokeOp {
            # If the VM has no NIC yet, add one bound to the switch; otherwise connect it.
            $nic = Get-VMNetworkAdapter -VMName $vm -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $nic) { Add-VMNetworkAdapter -VMName $vm -SwitchName $sw -ErrorAction Stop }
            else                { Connect-VMNetworkAdapter -VMName $vm -SwitchName $sw -ErrorAction Stop }
        }
    }.GetNewClosure()

    $b.RemoveNetworkAdapter = {
        param([System.Collections.IDictionary] $P)
        # The SEAL operation: strip ALL NICs so Assert-Sealed (host-side) sees none.
        $vm = & $AssertArg $P 'VMName' 'RemoveNetworkAdapter'
        & $InvokeOp {
            Remove-VMNetworkAdapter -VMName $vm -ErrorAction Stop
        }
    }.GetNewClosure()

    $b.GetNetworkAdapter = {
        param([System.Collections.IDictionary] $P)
        $vm = & $AssertArg $P 'VMName' 'GetNetworkAdapter'
        # Unary-comma wrap at the OUTERMOST return so a single NIC stays an array for an
        # unwrapped caller's `.Count` (parity with the fake; see the fake's note). The comma
        # MUST be here, not inside the op: $InvokeOp's `return (& $op)` re-enumerates and
        # would strip an inner comma, re-unrolling a single element to a bare object.
        return ,@(& $InvokeOp { Get-VMNetworkAdapter -VMName $vm -ErrorAction Stop })
    }.GetNewClosure()

    # ---- checkpoint ------------------------------------------------------
    $b.Checkpoint = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $AssertArg $P 'VMName'       'Checkpoint'
        $snap = & $AssertArg $P 'SnapshotName' 'Checkpoint'
        & $InvokeOp {
            Checkpoint-VM -Name $vm -SnapshotName $snap -ErrorAction Stop
        }
    }.GetNewClosure()

    $b.RestoreCheckpoint = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $AssertArg $P 'VMName'       'RestoreCheckpoint'
        $snap = & $AssertArg $P 'SnapshotName' 'RestoreCheckpoint'
        & $InvokeOp {
            $cp = Get-VMSnapshot -VMName $vm -Name $snap -ErrorAction Stop
            Restore-VMSnapshot -VMSnapshot $cp -Confirm:$false -ErrorAction Stop
        }
    }.GetNewClosure()

    $b.GetCheckpoint = {
        param([System.Collections.IDictionary] $P)
        $vm = & $AssertArg $P 'VMName' 'GetCheckpoint'
        # Unary-comma wrap at the OUTERMOST return (see GetNetworkAdapter): keeps a single
        # checkpoint an array for an unwrapped caller's `.Count`; placing the comma inside the
        # op would be stripped by $InvokeOp's re-enumeration.
        return ,@(& $InvokeOp { Get-VMSnapshot -VMName $vm -ErrorAction Stop })
    }.GetNewClosure()

    $b.RemoveCheckpoint = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $AssertArg $P 'VMName'       'RemoveCheckpoint'
        $snap = & $AssertArg $P 'SnapshotName' 'RemoveCheckpoint'
        & $InvokeOp {
            Remove-VMSnapshot -VMName $vm -Name $snap -ErrorAction Stop
        }
    }.GetNewClosure()

    return $b
}

# ==========================================================================
#  FAKE BACKEND  (in-memory; the test seam for ALL the consumers)
# ==========================================================================

# Deep-clones a fake VM record so a checkpoint captures an independent snapshot of
# the VM's state (and restore can roll it back without aliasing live state).
# Scriptblock variable (not a function) for the same closure-capture reason as the
# other helpers — see the helpers' header note above.
$script:SbCopyFakeVM = {
    param([hashtable] $VM)
    $copy = @{}
    foreach ($k in $VM.Keys) {
        $v = $VM[$k]
        if ($v -is [System.Collections.IDictionary]) {
            $inner = @{}
            foreach ($ik in $v.Keys) { $inner[$ik] = $v[$ik] }
            $copy[$k] = $inner
        }
        elseif ($v -is [System.Collections.IList]) {
            # Clone the list; elements are scalars (paths) or shallow NIC hashtables.
            $list = [System.Collections.Generic.List[object]]::new()
            foreach ($el in $v) {
                if ($el -is [System.Collections.IDictionary]) {
                    $eclone = @{}; foreach ($ek in $el.Keys) { $eclone[$ek] = $el[$ek] }
                    $list.Add($eclone)
                }
                else { $list.Add($el) }
            }
            $copy[$k] = $list
        }
        else { $copy[$k] = $v }
    }
    return $copy
}

<#
.SYNOPSIS
    Build an in-memory fake backend (same surface as the real one). The test seam.
.PARAMETER SimulateUnavailable
    Make TestAvailable report Available=$false (to exercise callers' fail-closed paths).
.PARAMETER SimulateChannelReadError
    Make GetHostChannels THROW (simulating a transient failure of the underlying host-channel
    read — e.g. the Guest Service Interface query failing for one channel). Used to prove the
    seal gate fails CLOSED: an unreadable channel must propagate, NEVER be coerced to off. The
    real backend's GetHostChannels rethrows such a read failure for exactly this reason.
.PARAMETER SimulateGuestCommandFailure
    Make InvokeGuestCommand return a NON-ZERO ExitCode (simulating a guest workload that exited
    with failure). Used to exercise the Runner's "a non-zero guest exit is a RUN OUTCOME reported
    on the result, not a thrown error" path.
.PARAMETER SimulateStartVMError
    Make StartVM THROW (simulating a VM that won't boot). Used to exercise the Invoke-Voidseal
    orchestrator's teardown-on-mid-flow-failure path: the VM provisions + seals + passes the gate,
    then the workload-launch (StartVM) throws, so the orchestrator must reap the VM (no orphan).
.PARAMETER SimulateNeverOff
    Make GetVM report State='Running' regardless of the VM's recorded state (simulating a guest
    workload that never powers itself off — a hung guest). The completion model has no live
    channel: the guest runs at boot then powers ITSELF off, and Wait-WorkloadComplete polls VM
    State until Off (or a timeout). This seam models the timeout branch — a VM that never reaches
    Off so the deadline is the only exit, exercising Wait-WorkloadComplete's force-stop teardown.
.PARAMETER SimulateSelfPowerOff
    Make StartVM leave the VM in State='Off' (instead of 'Running') — modelling a guest that boots,
    runs its boot workload, and SELF-POWERS-OFF before the host's first completion poll. This is the
    HAPPY-path complement to SimulateNeverOff: it lets the Disk-mode completion model reach the
    Wait-WorkloadComplete 'Off' (not-timed-out) branch and the subsequent Read-WorkloadResult host-
    read, so the orchestrator's detach+read+classify wiring is exercisable against the fake (the fake
    guest writes no sentinel, so Read-WorkloadResult honestly classifies Failed — the wiring still runs).
.PARAMETER SimulateSecondNewOutputVhdxError
    Make the SECOND NewOutputVhdx call THROW (the first succeeds; the second raises). New-WorkloadDisks
    creates the INPUT disk first (NewOutputVhdx #1) then the OUTPUT disk (NewOutputVhdx #2), so this
    models a real-world failure while creating the OUTPUT disk AFTER the INPUT disk is already created+
    attached. It exercises the incremental-record orphan-window fix: the INPUT disk must already be
    recorded on the descriptor (InputDiskPath + CreatedDisks) when the OUTPUT creation throws, so
    teardown (which treats CreatedDisks as authoritative) can still clean the INPUT disk up.
.PARAMETER SimulateWorkloadOutput
    A @{ <innerName> = <content>; ... } map written onto the OUTPUT data disk when StartVM is called
    (paired with SimulateSelfPowerOff). It models the guest writing its result + exit-code sentinel to
    the OUTPUT volume and then powering itself off. Without a live guest the OUTPUT disk would stay
    empty, so a positive Success-path e2e through Invoke-Voidseal could never be reached; this seam lets
    StartVM seed e.g. @{ 'result.exitcode' = '0'; 'result.html' = '<html/>' } onto the most-recently-
    created OUTPUT-labelled disk so Read-WorkloadResult classifies Success and the EXTRACTED happy path
    runs. The seam writes through the same WriteVhdxFile state the host later reads, so it stays honest.
.PARAMETER SimulateDepsImageBlob
    A byte array representing the deps image bytes the builder guest "wrote" to the OUTPUT (deps) disk
    during its boot run, recorded at StartVM when paired with -SimulateSelfPowerOff. Stored as
    DepsImageRegion on the VHD record. GetVhdxImageHash returns SHA-256 of these bytes (the stand-in for
    the whole .vhdx file content the real streaming hash reads). Same write-flush gate as the outbox:
    no clean power-off -> no recorded blob -> hash returns SHA-256 of empty bytes (fail-closed, not a
    false match). Models the builder supply-chain artifact fingerprint path (Task 2.3/Phase 3).
.PARAMETER SimulateDetachError
    Make RemoveHardDiskDrive THROW — modelling a transient real-Hyper-V detach failure right after a
    force-stop (VM still settling / slot already detached). The orchestrator detaches the data disks
    (Invoke-Voidseal) BEFORE the host read; this seam proves a detach throw is caught and reported as a
    Failed run (with the host read SKIPPED), NOT propagated to the outer catch as a lifecycle .Error
    abort. Teardown (Remove-Sandbox) uses RemoveVM/RemoveVHD, NOT RemoveHardDiskDrive, so this seam
    affects only the orchestrator's explicit detach — teardown still completes (DESTROYED).
#>
function New-FakeHyperVBackend {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [switch] $SimulateUnavailable,
        [switch] $SimulateChannelReadError,
        [switch] $SimulateGuestCommandFailure,
        [switch] $SimulateStartVMError,
        [switch] $SimulateNeverOff,
        [switch] $SimulateSelfPowerOff,
        [switch] $SimulateSecondNewOutputVhdxError,
        [hashtable] $SimulateWorkloadOutput,
        [byte[]] $SimulateOutboxBlob,
        [byte[]] $SimulateDepsImageBlob,
        [int] $SimulateDetachSettleLag = 0,
        [switch] $SimulateDetachError
    )

    # Hoist shared helpers into factory-locals so the method closures capture them
    # (see the helpers' header note — closures can't reach script-scoped functions).
    $GetArg       = $script:SbGetArg
    $AssertArg    = $script:SbAssertArg
    $CopyVM       = $script:SbCopyFakeVM
    $ValidateFmt  = $script:SbValidateVhdxFormat
    $channelNames = $script:HostChannelNames
    # Captured by the GetHostChannels closure to simulate an unreadable channel (see param help).
    $channelReadThrows = $SimulateChannelReadError.IsPresent
    # Captured by the relevant method closures (see param help) — test-only failure seams.
    $guestCmdFails     = $SimulateGuestCommandFailure.IsPresent
    $startVmThrows     = $SimulateStartVMError.IsPresent
    # Captured by the GetVM closure: model a guest that never powers itself off (the timeout branch
    # of the self-power-off completion model — Wait-WorkloadComplete).
    $neverOff          = $SimulateNeverOff.IsPresent
    # Captured by the StartVM closure: model a guest that boots, runs, and self-powers-off before the
    # first host poll (the happy completion branch of the Disk-mode model — leaves State Off).
    $selfPowerOff      = $SimulateSelfPowerOff.IsPresent
    # Captured by the NewOutputVhdx closure: throw on the 2nd NewOutputVhdx call (the OUTPUT disk),
    # exercising New-WorkloadDisks's incremental-record orphan-window fix. A mutable single-element
    # array is the counter (a closure can mutate an array element but not rebind a captured [int]).
    $secondVhdxThrows  = $SimulateSecondNewOutputVhdxError.IsPresent
    $newOutputVhdxCalls = @(0)
    # Captured by the StartVM closure: the inner files the guest "writes" to the OUTPUT disk on boot,
    # so a positive Success-path e2e can reach Read-WorkloadResult -> Success -> EXTRACTED. $null = none.
    $workloadOutput    = $SimulateWorkloadOutput
    $outboxBlob = $SimulateOutboxBlob   # raw bytes the guest "wrote" to the OUTPUT disk's outbox region
    $depsImageBlob = $SimulateDepsImageBlob   # deps bytes the builder guest "wrote" to the OUTPUT (deps) disk
    # Captured by the ReadVhdxRawRegion closure: model the RC8 detach settle-lag — qemu-img's first open can
    # hit a transient sharing violation while the Hyper-V worker-process handle is still releasing. A lag
    # WITHIN the read's internal retry budget (matches the real SbInvokeWithLockRetry MaxAttempts default of
    # 5) rides out and returns the bytes; a lag EXCEEDING it fails closed with the same lock message the real
    # helper throws. 0 (default) = no lag (the instantaneous-detach model the suite used before).
    $detachSettleLag = $SimulateDetachSettleLag
    # Captured by the RemoveHardDiskDrive closure: model a transient detach failure so the orchestrator's
    # detach try/catch (Failed run, host read skipped — NOT a lifecycle abort) is unit-testable.
    $detachThrows      = $SimulateDetachError.IsPresent

    # ---- in-memory state (captured by every method closure) --------------
    $state = @{
        VMs         = @{}                      # name -> VM record (hashtable)
        Switches    = @{}                      # name -> @{ Name; SwitchType }
        VHDs        = @{}                      # path -> @{ Path; SizeBytes; Differencing; ParentPath }
        Available   = -not $SimulateUnavailable.IsPresent
        # Cross-cutting CALL LOG that survives RemoveVM (the VM record is gone after teardown, so a
        # test that needs to prove detach/read ordering after a full Invoke-Voidseal run reads it here).
        # Each entry: @{ Op=<method>; Path=<path>; VMName=<vm> }. Appended by RemoveHardDiskDrive (the
        # detach) and ReadVhdxFile (the host read) so a test can assert detach-precedes-read ordering.
        CallLog     = [System.Collections.Generic.List[object]]::new()
    }

    # Helper: fetch a VM record or throw a clear "no such VM" naming it.
    $requireVM = {
        param([string] $Name, [string] $Method)
        if ([string]::IsNullOrWhiteSpace($Name)) { throw "HyperVBackend(fake).${Method}: VM name is required." }
        if (-not $state.VMs.ContainsKey($Name)) {
            throw "HyperVBackend(fake).${Method}: no such VM '$Name'."
        }
        return $state.VMs[$Name]
    }.GetNewClosure()

    # Helper (M-b): find the OUTPUT-labelled VHD path attached to a VM record, or $null. New-WorkloadDisks
    # labels the output disk 'OUTPUT'; both StartVM write-back blocks (SimulateWorkloadOutput AND
    # SimulateOutboxBlob) need this same discovery, so it lives here once instead of drifting in two copies.
    $findOutputDisk = {
        param($vm)
        foreach ($hd in @($vm.HardDrives)) {
            if ($state.VHDs.ContainsKey([string]$hd)) {
                $rec = $state.VHDs[[string]$hd]
                if ($rec.Contains('Label') -and [string]$rec['Label'] -eq 'OUTPUT') { return [string]$hd }
            }
        }
        return $null
    }.GetNewClosure()

    $b = @{}

    # ---- capability probe ----
    $b.TestAvailable = {
        param([System.Collections.IDictionary] $P)
        if ($state.Available) {
            return @{ Available = $true; Elevated = $true; Reason = 'Fake backend (in-memory) — always available.' }
        }
        return @{ Available = $false; Elevated = $false
                  Reason = 'Fake backend forced unavailable (SimulateUnavailable) — simulating insufficient privilege / Hyper-V unreachable.' }
    }.GetNewClosure()

    # ---- VM lifecycle ----
    $b.NewVM = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'NewVM'
        if ($state.VMs.ContainsKey($name)) {
            throw "HyperVBackend(fake).NewVM: a VM named '$name' already exists."
        }
        $vm = @{
            Name                           = $name
            Generation                     = (& $GetArg $P 'Generation' 2)
            State                          = 'Off'
            MemoryStartupBytes             = (& $GetArg $P 'MemoryStartupBytes')
            DynamicMemoryEnabled           = $false
            ProcessorCount                 = 1
            ExposeVirtualizationExtensions = $false
            SecureBootEnabled              = $false
            SecureBootTemplate             = $null
            # RC7: seed Hyper-V's REAL default (automatic checkpoints ON) so SetAutomaticCheckpoints's
            # flip to $false is OBSERVABLE — a test can assert New-SandboxVM turns it off.
            AutomaticCheckpointsEnabled    = $true
            ComPorts                       = @{}                                       # number -> pipe path
            GuestCommands                  = [System.Collections.Generic.List[object]]::new()  # commands delivered over the COM1 serial seam (Runner)
            HardDrives                     = [System.Collections.Generic.List[object]]::new()
            DvdDrive                       = $null
            NetworkAdapters                = [System.Collections.Generic.List[object]]::new()
            Checkpoints                    = [System.Collections.Generic.List[object]]::new()  # @{ Name; Snapshot=<vm copy> }
            # Host<->guest channels seeded to the UNSEALED default (all $true) — Hyper-V enables
            # Guest Services / Enhanced Session by default, so a freshly-provisioned VM is NOT
            # sealed until the Sealer turns them off. Assert-Sealed host-verifies these are off.
            HostChannels                   = @{ Clipboard = $true; Shares = $true; GuestServices = $true; EnhancedSession = $true }
        }
        $sw = & $GetArg $P 'SwitchName'
        if ($null -ne $sw) { $vm.NetworkAdapters.Add(@{ SwitchName = $sw; Name = 'Network Adapter' }) }
        $state.VMs[$name] = $vm
    }.GetNewClosure()

    $b.GetVM = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'GetVM'
        if ($state.VMs.ContainsKey($name)) {
            $vm = $state.VMs[$name]
            # SimulateNeverOff: the host READ always reports Running (a hung guest that never
            # self-powers-off). Return a shallow CLONE with State overridden so the underlying
            # record is untouched — StopVM's timeout force-stop can still flip the real record to
            # Off (the force-stop is host-truth; the poll read is what stays "Running").
            if ($neverOff) {
                $clone = @{}
                foreach ($k in @($vm.Keys)) { $clone[$k] = $vm[$k] }
                $clone['State'] = 'Running'
                return $clone
            }
            return $vm
        }
        return $null
    }.GetNewClosure()

    $b.StartVM = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'StartVM'
        # Resolve the VM first (a missing VM throws "no such VM" — same as a real start of a ghost).
        $vm = & $requireVM $name 'StartVM'
        # Test-only seam: simulate a VM that refuses to boot, so the orchestrator's teardown-on-
        # mid-flow-failure path can be exercised (the VM exists + is sealed, then the launch throws).
        if ($startVmThrows) {
            throw "HyperVBackend(fake).StartVM: simulated VM-start failure for '$name' (SimulateStartVMError) — the guest would not boot."
        }
        # SimulateWorkloadOutput (paired with SimulateSelfPowerOff): model the guest writing its result
        # + exit-code sentinel onto the OUTPUT data disk at boot, then powering off. Target the OUTPUT-
        # labelled VHD attached to THIS VM (New-WorkloadDisks labels it 'OUTPUT'); write each inner file
        # through the same Files table the host's ReadVhdxFile later reads — so Read-WorkloadResult sees
        # a real sentinel/result and can classify Success, letting the EXTRACTED happy path run e2e.
        if ($null -ne $workloadOutput -and $workloadOutput.Count -gt 0 -and $selfPowerOff) {
            $outDisk = & $findOutputDisk $vm
            if ($null -ne $outDisk) {
                if (-not $state.VHDs[$outDisk].ContainsKey('Files')) { $state.VHDs[$outDisk]['Files'] = @{} }
                foreach ($inner in @($workloadOutput.Keys)) {
                    $state.VHDs[$outDisk]['Files'][[string]$inner] = [string]$workloadOutput[$inner]
                }
            }
        }
        # SimulateOutboxBlob (paired with SimulateSelfPowerOff): model the guest packing guest/outbox.py
        # and dd-ing it onto the OUTPUT disk's RAW region at boot, then powering off (write-flush axis).
        # WRITE-FLUSH GATE (MUST-FIX 2): the outbox exists ONLY after a CLEAN self-power-off — a guest that
        # never powers off (timeout path) leaves the RAW region UNFLUSHED, so a host read sees zeros. Gating
        # on $selfPowerOff stops a future timeout-path e2e from going mock-green while a live unflushed disk
        # reads zeros (the canonical mock-green/live-empty trap). So: NO clean power-off -> no recorded blob.
        # The .avhdx identity trap (RC7): if AutomaticCheckpointsEnabled is ON, the guest's writes land
        # in a per-disk .avhdx CHILD layer that a host BASE raw-read does NOT expose — model that by
        # stashing the blob where ReadVhdxRawRegion can't see it (OutboxChildLayer), so the base read
        # returns zeros and the gate releases nothing. Checkpoints OFF (the provisioner's RC7 fix) -> the
        # base OutboxRegion is host-readable.
        if ($null -ne $outboxBlob -and $selfPowerOff) {
            $outDisk = & $findOutputDisk $vm
            if ($null -ne $outDisk) {
                if ([bool]$vm['AutomaticCheckpointsEnabled']) {
                    $state.VHDs[$outDisk]['OutboxChildLayer'] = [byte[]]$outboxBlob   # base raw-read can't see it (RC7)
                } else {
                    $state.VHDs[$outDisk]['OutboxRegion'] = [byte[]]$outboxBlob        # base raw-read sees it
                }
            }
        }
        # SimulateDepsImageBlob (paired with SimulateSelfPowerOff): model the BUILDER guest fetching deps
        # over the Squid egress, writing them onto the OUTPUT (deps) disk, then self-powering-off. SAME
        # write-flush gate as the outbox: no clean power-off -> no flushed deps image -> a host hash of an
        # empty disk (fail-closed, not a false match). Recorded as DepsImageRegion (the stand-in for the
        # .vhdx file bytes the real GetVhdxImageHash streams). No .avhdx split is modeled — the deps hash is
        # a whole-FILE fingerprint, not a region read, so the RC7 child-layer trap does not apply.
        if ($null -ne $depsImageBlob -and $selfPowerOff) {
            $depsDisk = & $findOutputDisk $vm
            if ($null -ne $depsDisk) { $state.VHDs[$depsDisk]['DepsImageRegion'] = [byte[]]$depsImageBlob }
        }
        # SimulateSelfPowerOff: the guest booted, ran its boot workload, and powered itself off before
        # the host's first completion poll — leave State Off so Wait-WorkloadComplete reads the happy
        # (not-timed-out) completion branch on its first poll. Default: the VM is now Running.
        $vm.State = if ($selfPowerOff) { 'Off' } else { 'Running' }
    }.GetNewClosure()

    $b.StopVM = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'StopVM'
        (& $requireVM $name 'StopVM').State = 'Off'
    }.GetNewClosure()

    $b.RemoveVM = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'RemoveVM'
        [void](& $requireVM $name 'RemoveVM')
        # Unregister the VM only. Its VHDX records persist in $state.VHDs — mirroring
        # Hyper-V (Remove-VM leaves disks); explicit cleanup is the caller's step.
        $state.VMs.Remove($name) | Out-Null
    }.GetNewClosure()

    # ---- hardware ----
    $b.SetProcessor = {
        param([System.Collections.IDictionary] $P)
        $vm = & $requireVM (& $GetArg $P 'VMName') 'SetProcessor'
        $cnt = & $GetArg $P 'Count'; if ($null -ne $cnt) { $vm.ProcessorCount = $cnt }
        $ext = & $GetArg $P 'ExposeVirtualizationExtensions'
        if ($null -ne $ext) { $vm.ExposeVirtualizationExtensions = [bool]$ext }
    }.GetNewClosure()

    $b.SetMemory = {
        param([System.Collections.IDictionary] $P)
        $vm = & $requireVM (& $GetArg $P 'VMName') 'SetMemory'
        $s = & $GetArg $P 'StartupBytes'; if ($null -ne $s) { $vm.MemoryStartupBytes = $s }
        $d = & $GetArg $P 'DynamicMemoryEnabled'; if ($null -ne $d) { $vm.DynamicMemoryEnabled = [bool]$d }
    }.GetNewClosure()

    $b.SetFirmware = {
        param([System.Collections.IDictionary] $P)
        $vm = & $requireVM (& $GetArg $P 'VMName') 'SetFirmware'
        $sb = & $GetArg $P 'EnableSecureBoot'; if ($null -ne $sb) { $vm.SecureBootEnabled = [bool]$sb }
        $tmpl = & $GetArg $P 'SecureBootTemplate'; if ($null -ne $tmpl) { $vm.SecureBootTemplate = $tmpl }
    }.GetNewClosure()

    # RC7: the fake's analogue of Set-VM -AutomaticCheckpointsEnabled — flip the recorded flag on the VM
    # record. Mirrors the real backend (which calls Set-VM); the fake models the resulting host-truth
    # state so a test can assert New-SandboxVM turns automatic checkpoints off (true -> false).
    $b.SetAutomaticCheckpoints = {
        param([System.Collections.IDictionary] $P)
        $vm = & $requireVM (& $GetArg $P 'VMName') 'SetAutomaticCheckpoints'
        $vm.AutomaticCheckpointsEnabled = [bool](& $GetArg $P 'Enabled' $false)
    }.GetNewClosure()

    $b.SetComPort = {
        param([System.Collections.IDictionary] $P)
        $vm  = & $requireVM (& $GetArg $P 'VMName') 'SetComPort'
        $num = & $GetArg $P 'Number' 1
        $path = & $AssertArg $P 'Path' 'SetComPort'
        $vm.ComPorts[$num] = $path
    }.GetNewClosure()

    # Host-TRUTH read of a VM's COM port — the fake's analogue of Get-VMComPort. Reads the com-port
    # state SetComPort records (number -> pipe path). Returns @{ Number; Path } for the requested port,
    # or $null when no port was wired OR its recorded path is blank (mirrors the real backend: an
    # unattached / empty-path COM port is "not live"). The post-seal COM1-liveness assertion in
    # Assert-Sealed reads through this so the seal is host-verified NOT to have severed COM1.
    $b.GetComPort = {
        param([System.Collections.IDictionary] $P)
        $vm  = & $requireVM (& $GetArg $P 'VMName') 'GetComPort'
        $num = [int](& $GetArg $P 'Number' 1)
        if (-not $vm.ComPorts.ContainsKey($num)) { return $null }
        $portPath = [string]$vm.ComPorts[$num]
        if ([string]::IsNullOrWhiteSpace($portPath)) { return $null }
        return @{ Number = $num; Path = $portPath }
    }.GetNewClosure()

    # ---- guest command delivery over the (simulated) COM1 serial seam (RUNNER) ----
    # The fake's analogue of the real serial transport: RECORD the delivered command on the VM
    # (so a Runner test can assert the right entrypoint was sent) and RETURN canned output. The
    # default canned result is a success (ExitCode 0); -SimulateGuestCommandFailure flips it to a
    # non-zero exit so the Runner's "non-zero exit is a reported run outcome, not a throw" path is
    # testable. Requires VMName + Command (mirrors the real AssertArg wiring) and throws on a
    # missing VM (a Runner targeting a ghost VM is a caller bug we must surface).
    $b.InvokeGuestCommand = {
        param([System.Collections.IDictionary] $P)
        $vm      = & $requireVM (& $GetArg $P 'VMName') 'InvokeGuestCommand'
        $command = & $AssertArg $P 'Command' 'InvokeGuestCommand'
        [void](& $GetArg $P 'TimeoutSeconds' 300)   # accepted + ignored by the fake (documented arg)
        $vm.GuestCommands.Add([string]$command)
        if ($guestCmdFails) {
            return @{ ExitCode = 1; Stdout = ''; Stderr = "fake: simulated guest command failure for '$command'." }
        }
        return @{ ExitCode = 0; Stdout = "fake: ran '$command'."; Stderr = '' }
    }.GetNewClosure()

    # ---- host channels (SEAL surface) ----
    $b.SetHostChannel = {
        param([System.Collections.IDictionary] $P)
        $vm      = & $requireVM (& $GetArg $P 'VMName') 'SetHostChannel'
        $channel = & $AssertArg $P 'Channel' 'SetHostChannel'
        if ($channelNames -notcontains $channel) {
            throw "HyperVBackend(fake).SetHostChannel: unknown channel '$channel' (expected one of: $($channelNames -join ', '))."
        }
        $vm.HostChannels[$channel] = [bool](& $GetArg $P 'Enabled' $false)
    }.GetNewClosure()

    $b.GetHostChannels = {
        param([System.Collections.IDictionary] $P)
        $vm = & $requireVM (& $GetArg $P 'VMName') 'GetHostChannels'
        # SimulateChannelReadError: model a transient failure of the underlying host-channel read
        # (e.g. the Guest Service Interface query throwing for one channel). The read MUST surface
        # the error so the seal gate fails closed — never silently report the channel as off.
        if ($channelReadThrows) {
            throw "HyperVBackend(fake).GetHostChannels: simulated host-channel read failure for '$vm' (the underlying channel query threw; an unreadable channel must propagate, not be coerced to off)."
        }
        # Return a COPY (callers must not mutate live state through the read) covering exactly
        # the canonical channel set, defaulting a missing channel to $true (unsealed) so a
        # caller never reads $null for a known channel.
        $out = @{}
        foreach ($name in $channelNames) {
            $out[$name] = if ($vm.HostChannels.ContainsKey($name)) { [bool]$vm.HostChannels[$name] } else { $true }
        }
        return $out
    }.GetNewClosure()

    # ---- disk ----
    $b.NewVHD = {
        param([System.Collections.IDictionary] $P)
        $path = & $AssertArg $P 'Path' 'NewVHD'
        $diff = [bool](& $GetArg $P 'Differencing' $false)
        $rec  = @{
            Path         = $path
            SizeBytes    = (& $GetArg $P 'SizeBytes')
            Differencing = $diff
            ParentPath   = (& $GetArg $P 'ParentPath')
        }
        if ($diff -and [string]::IsNullOrWhiteSpace([string]$rec.ParentPath)) {
            throw "HyperVBackend(fake).NewVHD: -Differencing requires a ParentPath."
        }
        $state.VHDs[$path] = $rec
    }.GetNewClosure()

    # Create + host-format a data VHDX in one shot (the workload output disk). The fake models
    # the FORMATTED disk in its VHD state — the same $state.VHDs record NewVHD writes, plus the
    # Label + FileSystem the host-format step would stamp on the volume — so GetVHDInfo (and any
    # later read of the formatted volume) sees them. Mirrors the real backend's create-then-format,
    # without touching disk. Requires all four documented args (Path/Label/FileSystem/SizeBytes),
    # matching the real AssertArg wiring.
    $b.NewOutputVhdx = {
        param([System.Collections.IDictionary] $P)
        $path  = & $AssertArg $P 'Path'       'NewOutputVhdx'
        $label = & $AssertArg $P 'Label'      'NewOutputVhdx'
        $fs    = & $AssertArg $P 'FileSystem' 'NewOutputVhdx'
        $size  = & $AssertArg $P 'SizeBytes'  'NewOutputVhdx'
        # SimulateSecondNewOutputVhdxError: throw on the 2nd call (the OUTPUT disk in New-WorkloadDisks)
        # BEFORE any state write — modelling a real NewOutputVhdx that fails creating the OUTPUT disk
        # after the INPUT disk already succeeded. Exercises the incremental-record orphan-window fix.
        $newOutputVhdxCalls[0]++
        if ($secondVhdxThrows -and $newOutputVhdxCalls[0] -eq 2) {
            throw "HyperVBackend(fake).NewOutputVhdx: simulated OUTPUT-disk creation failure (SimulateSecondNewOutputVhdxError) — the 2nd NewOutputVhdx call (the OUTPUT data disk) fails after the INPUT disk was already created+recorded."
        }
        # SHARED fake≠real guard (same helper the real backend calls): reject a bad FileSystem /
        # over-length Label EARLY and store the NORMALIZED filesystem casing — so a test that
        # passed a value live Format-Volume would reject (e.g. 'ext4') fails here too, closing the
        # divergence. Runs BEFORE the state write, mirroring the real backend's pre-cmdlet validation.
        $fs = & $ValidateFmt $fs $label
        $state.VHDs[$path] = @{
            Path         = $path
            SizeBytes    = $size
            Differencing = $false
            ParentPath   = $null
            Label        = $label
            FileSystem   = $fs
        }
    }.GetNewClosure()

    # Host-populate / host-read a single file INSIDE a VHDX. The real backend Mounts the
    # VHDX (rw to write / -ReadOnly to read) and writes/reads a file on its formatted volume; the
    # fake models that volume's file table as a per-VHDX 'Files' sub-hashtable on the $state.VHDs
    # record (keyed by inner path -> content string). The 'Files' bucket is created lazily — the
    # flat VHD records NewVHD/NewOutputVhdx write carry no 'Files' field, so initialize it on first
    # write. WriteVhdxFile onto a never-created VHD is a caller bug (the real Mount-VHD would throw
    # on a missing path), so the fake throws too; ReadVhdxFile of a missing inner file returns $null
    # (mirrors the real backend's Test-Path miss).
    $b.WriteVhdxFile = {
        param([System.Collections.IDictionary] $P)
        $path = & $AssertArg $P 'Path' 'WriteVhdxFile'
        $inner = & $AssertArg $P 'InnerPath' 'WriteVhdxFile'
        $content = & $AssertArg $P 'Content' 'WriteVhdxFile'
        if (-not $state.VHDs.ContainsKey($path)) { throw "WriteVhdxFile: VHD '$path' does not exist (create it first)." }
        if (-not $state.VHDs[$path].ContainsKey('Files')) { $state.VHDs[$path]['Files'] = @{} }
        $state.VHDs[$path]['Files'][$inner] = $content
        # Log the host write (with Content) so a test can prove what was written onto a disk even AFTER
        # teardown deletes the disk from the store (CallLog persists across RemoveVM/RemoveVHD) — mirrors
        # the ReadVhdxFile/RemoveHardDiskDrive logging precedent. Fake-only bookkeeping; not a contract op.
        $state.CallLog.Add(@{ Op = 'WriteVhdxFile'; Path = $path; InnerPath = $inner; Content = $content })
    }.GetNewClosure()

    $b.ReadVhdxFile = {
        param([System.Collections.IDictionary] $P)
        $path = & $AssertArg $P 'Path' 'ReadVhdxFile'
        $inner = & $AssertArg $P 'InnerPath' 'ReadVhdxFile'
        if (-not $state.VHDs.ContainsKey($path)) { throw "ReadVhdxFile: VHD '$path' does not exist." }
        # Log the host read so a test can prove detach (RemoveHardDiskDrive) precedes it.
        $state.CallLog.Add(@{ Op = 'ReadVhdxFile'; Path = $path; InnerPath = $inner })
        if ($state.VHDs[$path].ContainsKey('Files') -and $state.VHDs[$path]['Files'].ContainsKey($inner)) {
            return $state.VHDs[$path]['Files'][$inner]
        }
        return $null
    }.GetNewClosure()

    # USER-SPACE raw region read (fake): return the recorded outbox-region bytes, modeling the live
    # divergence axes honestly (D-A) so the mock cannot pass where the live qemu-img read would fail.
    #
    # ZERO-DISK MODEL + REAL-DISK CAVEAT + SELF-DELIMITING CONTRACT (MUST-FIX 3):
    #   (a) The fake models a ZERO-INITIALIZED raw disk with the outbox at disk byte OFFSET 0 — every byte
    #       outside the recorded OutboxRegion reads as zero (AXIS 4, the zero-padded FIXED-disk tail).
    #   (b) The REAL OUTPUT disk is NOT guaranteed zero outside the outbox region THIS phase: the live read
    #       target is the EXISTING NTFS-formatted output disk (D-B), whose low offsets carry a boot sector /
    #       MFT / prior-run residue, NOT zeros — until the dedicated FIXED raw outbox disk lands (Phase 2/4).
    #   (c) THEREFORE the consumer MUST SELF-DELIMIT — the outbox is length-prefixed (its header carries
    #       entry_count + payload_total_len), so the seam reads the 24-byte header then EXACTLY
    #       24 + entry_count*104 + payload_total_len bytes from offset 0 and NEVER reads arbitrary / low
    #       offsets expecting zeros. The zero-pad tail below stays — it correctly models the FUTURE FIXED
    #       raw disk; a future seam test must NOT lean on it for the present NTFS-formatted disk.
    $b.ReadVhdxRawRegion = {
        param([System.Collections.IDictionary] $P)
        $path   = & $AssertArg $P 'Path'   'ReadVhdxRawRegion'
        $offset = [int64](& $AssertArg $P 'Offset' 'ReadVhdxRawRegion')
        $length = [int64](& $AssertArg $P 'Length' 'ReadVhdxRawRegion')
        # M-c: bounds FIRST (matches the real impl's bounds-before-existence order) so a double-fault input
        # (missing path AND a negative offset) reports the bounds problem first.
        if ($offset -lt 0 -or $length -lt 0) { throw "ReadVhdxRawRegion: Offset/Length must be non-negative (got Offset=$offset, Length=$length)." }
        # M-d: the same 2GB single-read ceiling the real impl guards — [byte[]]::new($length) / [int][Math]::Min
        # only accept Int32, so a >2GB value throws an opaque CLR exception. Fail closed with a clear message.
        if ($length -gt [int]::MaxValue -or $offset -gt [int]::MaxValue) {
            throw "ReadVhdxRawRegion: Offset/Length exceeds the supported 2GB single-read limit ($offset/$length) — failing closed."
        }
        if (-not $state.VHDs.ContainsKey($path)) { throw "ReadVhdxRawRegion: VHD '$path' does not exist." }
        # AXIS 1 — detach/file-lock ordering: qemu-img opens the VHDX with a shared read; that open is only
        # blocked while the Hyper-V worker process (vmwp.exe) holds the file lock — i.e. ONLY while the
        # holding VM is Running/Saved/Paused. An Off-but-attached disk (the builder's post-power-off,
        # pre-detach window reachable via -SimulateSelfPowerOff) carries NO live worker handle and IS
        # qemu-readable, so the real returns its bytes; gate the throw on the holder's runtime State to
        # match. A live (Running/Saved/Paused) holder hits a sharing violation -> $LockRetry -> *locked*
        # (the real NEVER emits *still attached*); the message carries `locked` so a consumer can branch
        # on the single *locked* substring both factories and the real share.
        foreach ($vmRec in $state.VMs.Values) {
            if ((@($vmRec.HardDrives) -contains $path) -and ([string]$vmRec.State -in @('Running','Saved','Paused'))) {
                throw "ReadVhdxRawRegion: VHDX '$path' is attached to a live VM '$($vmRec.Name)' (State=$($vmRec.State)); the VHDX is still locked — detach (and ensure the VM is Off) before the host raw read. Failing closed."
            }
        }
        $rec = $state.VHDs[$path]
        # RC8 (MUST-FIX 1, FAKE) — model the detach SETTLE-LAG the real read tolerates via its internal
        # lock-retry. Seed a per-disk countdown from -SimulateDetachSettleLag on the FIRST read, then "retry
        # it away" via the SAME increment-then-compare arithmetic the real $script:SbInvokeWithLockRetry uses
        # ($attempt++ then `-ge $MaxAttempts`). $LOCK_RETRY_BUDGET (5) MATCHES the real's MaxAttempts default,
        # but the TOLERANCE is MaxAttempts-1 = 4: a lag of <=4 transient lock-failures decrements to 0 and the
        # read proceeds (bytes returned); a lag of >=5 throws the SAME *still locked* message the real helper
        # throws on its 5th attempt. (The earlier check-before-decrement form tolerated <=5 / threw at >=6 —
        # one off from the real, so the fake returned bytes at lag=5 where the real fails closed.)
        $LOCK_RETRY_BUDGET = 5   # == the real's MaxAttempts default; TOLERANCE is MaxAttempts-1 = 4
        if (-not $rec.ContainsKey('_settleRemaining')) { $rec['_settleRemaining'] = [int]$detachSettleLag }
        $attempts = 0
        while ([int]$rec['_settleRemaining'] -gt 0) {
            $attempts++
            if ($attempts -ge $LOCK_RETRY_BUDGET) {
                throw "ReadVhdxRawRegion: the VHDX '$path' is still locked after $LOCK_RETRY_BUDGET attempts — the VHDX handle may not have been released after detach (settle-lag did not clear). Failing closed."
            }
            $rec['_settleRemaining'] = [int]$rec['_settleRemaining'] - 1
        }
        # Log so a test can prove DETACH (RemoveHardDiskDrive) precedes the read (survives RemoveVM).
        $state.CallLog.Add(@{ Op = 'ReadVhdxRawRegion'; Path = $path; Offset = $offset; Length = $length })
        # AXIS 2 — .avhdx identity trap (RC7): only the BASE OutboxRegion is host-readable; a blob stuck in
        # the checkpoint child layer reads as zeros.
        $region = if ($rec.ContainsKey('OutboxRegion')) { [byte[]]$rec['OutboxRegion'] } else { [byte[]]::new(0) }
        # AXIS 4 — honest FIXED-disk tail: full-size disk, an over-read past the written payload is zeros.
        $buf = [byte[]]::new($length)
        if ($offset -lt $region.Length) {
            $avail = [int][Math]::Min($length, [int64]$region.Length - $offset)
            if ($avail -gt 0) { [System.Array]::Copy($region, [int]$offset, $buf, 0, $avail) }
        }
        return ,$buf
    }.GetNewClosure()

    # USER-SPACE whole-image hash (fake): SHA-256 of the recorded deps bytes, modeling the axes that
    # apply to a streaming FILE hash (D-3) — detach/lock ordering, the RC8 settle-lag, and determinism.
    # NO qemu/.avhdx/zero-pad (those are ReadVhdxRawRegion's region-read concerns). FIDELITY NOTE: the
    # settle-lag is modeled as a SEPARATE per-method countdown (_hashSettleRemaining) for test isolation;
    # the real lag is a per-HANDLE property that the first read after a detach absorbs — disclosed so the
    # ULTRACODE gate can judge the representation gap.
    # REPRESENTATION GAP (whole-file vs content blob) — INTENTIONAL, UNMODELED: the REAL hashes the WHOLE
    # .vhdx file (header / BAT / footer / parent-locator / free-space) via OpenRead->SHA256; this fake
    # hashes ONLY the recorded deps CONTENT blob (DepsImageRegion). Therefore the fake CANNOT model a
    # container/footer/parent-locator-only substitution — e.g. the canonical VHDX-swap attack of rewriting
    # the footer so a fixed disk becomes a differencing disk pointing at an attacker-controlled parent,
    # which changes the REAL whole-file hash but NOT this fake's content-only hash. This container-tamper
    # class is DELIBERATELY left unmodeled in the mock (building container-byte fake machinery is deferred
    # to Phase 3, when a consumer is wired) and MUST be covered by a live Phase-6 test before
    # verify-before-attach is trusted in production.
    $b.GetVhdxImageHash = {
        param([System.Collections.IDictionary] $P)
        $path = & $AssertArg $P 'Path' 'GetVhdxImageHash'
        if (-not $state.VHDs.ContainsKey($path)) {
            throw "GetVhdxImageHash: VHDX '$path' does not exist (cannot hash a missing artifact). Failing closed."
        }
        # AXIS 1 — detach/file-lock ordering: the real opens with [System.IO.File]::OpenRead (FileShare.Read);
        # that open is only blocked while the Hyper-V worker process (vmwp.exe) holds the file lock — i.e.
        # ONLY while the holding VM is Running/Saved/Paused. An Off-but-attached disk (the builder's
        # post-power-off, pre-detach window reachable via -SimulateSelfPowerOff) carries NO live worker handle
        # and IS OpenRead-able, so the real returns its hash; gate the throw on the holder's runtime State to
        # match. A live (Running/Saved/Paused) holder hits a sharing violation -> $LockRetry -> *locked* (the
        # real NEVER emits *still attached*); the message carries `locked` so a consumer can branch on the
        # single *locked* substring both factories and the real share.
        foreach ($vmRec in $state.VMs.Values) {
            if ((@($vmRec.HardDrives) -contains $path) -and ([string]$vmRec.State -in @('Running','Saved','Paused'))) {
                throw "GetVhdxImageHash: VHDX '$path' is attached to a live VM '$($vmRec.Name)' (State=$($vmRec.State)); the VHDX is still locked — detach (and ensure the VM is Off) before the host hash. Failing closed."
            }
        }
        $rec = $state.VHDs[$path]
        # AXIS 2 — RC8 detach settle-lag: same bounded tolerance the real $LockRetry gives, via the SAME
        # increment-then-compare arithmetic the real $script:SbInvokeWithLockRetry uses ($attempt++ then
        # `-ge $MaxAttempts`). $LOCK_RETRY_BUDGET (5) MATCHES the real's MaxAttempts default, but the
        # TOLERANCE is MaxAttempts-1 = 4: a lag of <=4 transient lock-failures rides out (hash returned); a
        # lag of >=5 throws the same *still locked* fail-closed shape the real helper throws on its 5th
        # attempt (Context='GetVhdxImageHash'). (The earlier check-before-decrement form tolerated <=5 / threw
        # at >=6 — one off from the real, so the fake returned a hash at lag=5 where the real fails closed.)
        $LOCK_RETRY_BUDGET = 5   # == the real's MaxAttempts default; TOLERANCE is MaxAttempts-1 = 4
        if (-not $rec.ContainsKey('_hashSettleRemaining')) { $rec['_hashSettleRemaining'] = [int]$detachSettleLag }
        $attempts = 0
        while ([int]$rec['_hashSettleRemaining'] -gt 0) {
            $attempts++
            if ($attempts -ge $LOCK_RETRY_BUDGET) {
                throw "GetVhdxImageHash: the VHDX '$path' is still locked after $LOCK_RETRY_BUDGET attempts — the VHDX handle may not have been released after detach (settle-lag did not clear). Failing closed."
            }
            $rec['_hashSettleRemaining'] = [int]$rec['_hashSettleRemaining'] - 1
        }
        $state.CallLog.Add(@{ Op = 'GetVhdxImageHash'; Path = $path })
        # AXIS 3 — determinism: SHA-256 of the recorded deps bytes (stand-in for the file content). Same
        # bytes -> same hash; different bytes -> different hash (tamper-sensitive). An Off-but-attached read
        # of a disk with NO recorded blob (the FIX-2 path) hashes an EMPTY image — model the real, which
        # OpenReads and SHA-256s whatever (possibly tiny) file is there. NOTE: re-cast to [byte[]] HERE (not
        # only inside the if/else) because a PowerShell if-expression unrolls an EMPTY byte[] to $null, and
        # SHA256.ComputeHash($null) is an ambiguous overload (byte[] vs Stream) — fail-loud-but-wrong.
        $bytes = if ($rec.ContainsKey('DepsImageRegion')) { [byte[]]$rec['DepsImageRegion'] } else { [byte[]]::new(0) }
        if ($null -eq $bytes) { $bytes = [byte[]]::new(0) }   # the empty-blob if-branch unrolls to $null
        [byte[]]$bytes = $bytes                                # re-pin the static type so the overload binds
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $digest = $sha.ComputeHash($bytes) } finally { $sha.Dispose() }
        return [System.BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
    }.GetNewClosure()

    $b.GetVHDInfo = {
        param([System.Collections.IDictionary] $P)
        $path = & $AssertArg $P 'Path' 'GetVHDInfo'
        if (-not $state.VHDs.ContainsKey($path)) { return $null }
        # Surface the formatted-disk fields (Label/FileSystem) alongside the base VHD info. A plain
        # NewVHD record carries no Label/FileSystem; default those to $null so existing GetVHDInfo
        # tests still pass while a NewOutputVhdx-created disk reports its volume metadata.
        $rec = $state.VHDs[$path]
        return @{
            Path         = $rec['Path']
            SizeBytes    = $rec['SizeBytes']
            Differencing = $rec['Differencing']
            ParentPath   = $rec['ParentPath']
            Label        = if ($rec.Contains('Label'))      { $rec['Label'] }      else { $null }
            FileSystem   = if ($rec.Contains('FileSystem')) { $rec['FileSystem'] } else { $null }
        }
    }.GetNewClosure()

    $b.RemoveVHD = {
        param([System.Collections.IDictionary] $P)
        # Drop the in-memory VHD record (the fake's analogue of deleting the
        # detached .vhdx file on disk). Idempotent — removing an unknown path is a no-op,
        # mirroring the real backend's Test-Path guard. Detaching from a VM is a separate
        # step (RemoveHardDiskDrive); this only forgets the disk record.
        $path = & $AssertArg $P 'Path' 'RemoveVHD'
        if ($state.VHDs.ContainsKey($path)) { $state.VHDs.Remove($path) | Out-Null }
    }.GetNewClosure()

    $b.AddHardDiskDrive = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $requireVM (& $GetArg $P 'VMName') 'AddHardDiskDrive'
        $path = & $AssertArg $P 'Path' 'AddHardDiskDrive'
        # Real Add-VMHardDiskDrive requires the .vhdx file to exist on disk; mirror that
        # by demanding the VHD was created via NewVHD first. Without this the fake would
        # attach a phantom disk and the consumers' disk tests would pass against a non-existent file.
        if (-not $state.VHDs.ContainsKey($path)) {
            throw "HyperVBackend(fake).AddHardDiskDrive: VHD '$path' does not exist (create it with NewVHD first); real Add-VMHardDiskDrive requires the file to exist."
        }
        $vm.HardDrives.Add($path)
    }.GetNewClosure()

    $b.RemoveHardDiskDrive = {
        param([System.Collections.IDictionary] $P)
        $vmName = & $GetArg $P 'VMName'
        $vm   = & $requireVM $vmName 'RemoveHardDiskDrive'
        $path = & $AssertArg $P 'Path' 'RemoveHardDiskDrive'
        # Log the detach so a test can prove it precedes the host read (ReadVhdxFile) — and survives
        # RemoveVM (teardown), since the per-VM record is gone after a full Invoke-Voidseal run.
        $state.CallLog.Add(@{ Op = 'RemoveHardDiskDrive'; Path = $path; VMName = [string]$vmName })
        # SimulateDetachError: model a transient real-Hyper-V detach failure (throw AFTER logging, so the
        # test can still see the attempt). Exercises the orchestrator's detach try/catch.
        if ($detachThrows) {
            throw "HyperVBackend(fake).RemoveHardDiskDrive: simulated detach failure for '$path' on '$vmName' (SimulateDetachError) — a transient Remove-VMHardDiskDrive failure right after force-stop."
        }
        # Detach only — the VHD record in $state.VHDs is untouched (disk file stays on disk).
        $kept = [System.Collections.Generic.List[object]]::new()
        foreach ($d in $vm.HardDrives) { if ($d -ne $path) { $kept.Add($d) } }
        $vm.HardDrives = $kept
    }.GetNewClosure()

    $b.SetDvdDrive = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $requireVM (& $GetArg $P 'VMName') 'SetDvdDrive'
        $vm.DvdDrive = (& $AssertArg $P 'Path' 'SetDvdDrive')
    }.GetNewClosure()

    $b.RemoveDvdDrive = {
        param([System.Collections.IDictionary] $P)
        $vm = & $requireVM (& $GetArg $P 'VMName') 'RemoveDvdDrive'
        $vm.DvdDrive = $null
    }.GetNewClosure()

    $b.GetDvdDrives = {
        param([System.Collections.IDictionary] $P)
        $vm = & $requireVM (& $GetArg $P 'VMName') 'GetDvdDrives'
        # The fake models a single DVD slot as the scalar .DvdDrive; expose it as a 0/1-element
        # COLLECTION so the fake models attach/detach exactly as the real Get-VMDvdDrive read does
        # (Where-Object { $_ } drops the $null = empty-slot case). Unary-comma wrap keeps a single
        # path an array for an unwrapped caller's `.Count` (parity with GetNetworkAdapter).
        return ,@($vm.DvdDrive | Where-Object { $_ })
    }.GetNewClosure()

    # ---- switch / network ----
    $b.NewSwitch = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'NewSwitch'
        $type = & $GetArg $P 'SwitchType' 'Internal'
        if (@('Internal', 'Private', 'External') -notcontains $type) {
            throw "HyperVBackend(fake).NewSwitch: SwitchType '$type' must be Internal, Private, or External."
        }
        $state.Switches[$name] = @{ Name = $name; SwitchType = $type }
    }.GetNewClosure()

    $b.GetSwitch = {
        param([System.Collections.IDictionary] $P)
        $name = & $AssertArg $P 'Name' 'GetSwitch'
        if ($state.Switches.ContainsKey($name)) { return $state.Switches[$name] }
        return $null
    }.GetNewClosure()

    $b.RemoveSwitch = {
        param([System.Collections.IDictionary] $P)
        # Drop the in-memory switch record (the fake's analogue of Remove-VMSwitch).
        # Idempotent — removing an unknown name is a no-op, mirroring the real backend's Get guard.
        $name = & $AssertArg $P 'Name' 'RemoveSwitch'
        if ($state.Switches.ContainsKey($name)) { $state.Switches.Remove($name) | Out-Null }
    }.GetNewClosure()

    $b.ConnectNetworkAdapter = {
        param([System.Collections.IDictionary] $P)
        $vm = & $requireVM (& $GetArg $P 'VMName') 'ConnectNetworkAdapter'
        $sw = & $AssertArg $P 'SwitchName' 'ConnectNetworkAdapter'
        # Real Connect-VMNetworkAdapter errors when the named switch does not exist; mirror
        # that by demanding the switch was created via NewSwitch first. Without this the fake
        # would bind a NIC to a phantom switch and network-isolation checks go false-green.
        if (-not $state.Switches.ContainsKey($sw)) {
            throw "HyperVBackend(fake).ConnectNetworkAdapter: switch '$sw' does not exist (create it with NewSwitch first); real Connect-VMNetworkAdapter errors on an unknown switch."
        }
        $vm.NetworkAdapters.Add(@{ SwitchName = $sw; Name = 'Network Adapter' })
    }.GetNewClosure()

    $b.RemoveNetworkAdapter = {
        param([System.Collections.IDictionary] $P)
        # SEAL: strip every NIC.
        $vm = & $requireVM (& $GetArg $P 'VMName') 'RemoveNetworkAdapter'
        $vm.NetworkAdapters = [System.Collections.Generic.List[object]]::new()
    }.GetNewClosure()

    $b.GetNetworkAdapter = {
        param([System.Collections.IDictionary] $P)
        $vm = & $requireVM (& $GetArg $P 'VMName') 'GetNetworkAdapter'
        # Unary-comma wrap: a bare @(...) return unrolls to a single bare hashtable when the
        # VM has exactly one NIC (and to $null when empty), so an unwrapped caller's `.Count`
        # would read the hashtable's key-count (or fail on $null). `,@(...)` keeps it an array.
        return ,@($vm.NetworkAdapters)
    }.GetNewClosure()

    # ---- checkpoint ----
    $b.Checkpoint = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $requireVM (& $GetArg $P 'VMName') 'Checkpoint'
        $snap = & $AssertArg $P 'SnapshotName' 'Checkpoint'
        # Capture an independent deep copy of the VM's current state.
        $vm.Checkpoints.Add(@{ Name = $snap; Snapshot = (& $CopyVM $vm) })
    }.GetNewClosure()

    $b.RestoreCheckpoint = {
        param([System.Collections.IDictionary] $P)
        $name = & $GetArg $P 'VMName'
        $vm   = & $requireVM $name 'RestoreCheckpoint'
        $snap = & $AssertArg $P 'SnapshotName' 'RestoreCheckpoint'
        $cp = $null
        foreach ($c in $vm.Checkpoints) { if ($c.Name -eq $snap) { $cp = $c } }
        if ($null -eq $cp) {
            throw "HyperVBackend(fake).RestoreCheckpoint: VM '$name' has no checkpoint named '$snap'."
        }
        # Roll the live record back to the captured copy, but PRESERVE the checkpoint
        # list (Hyper-V keeps checkpoints across a restore).
        $restored = & $CopyVM $cp.Snapshot
        $restored.Checkpoints = $vm.Checkpoints
        $state.VMs[$name] = $restored
    }.GetNewClosure()

    $b.GetCheckpoint = {
        param([System.Collections.IDictionary] $P)
        $vm = & $requireVM (& $GetArg $P 'VMName') 'GetCheckpoint'
        # Unary-comma wrap (see GetNetworkAdapter): keep a single-element / empty result an
        # array so an unwrapped caller's `.Count` is the checkpoint count, not a key-count.
        return ,@($vm.Checkpoints | ForEach-Object { @{ Name = $_.Name } })
    }.GetNewClosure()

    $b.RemoveCheckpoint = {
        param([System.Collections.IDictionary] $P)
        $vm   = & $requireVM (& $GetArg $P 'VMName') 'RemoveCheckpoint'
        $snap = & $AssertArg $P 'SnapshotName' 'RemoveCheckpoint'
        $kept = [System.Collections.Generic.List[object]]::new()
        foreach ($c in $vm.Checkpoints) { if ($c.Name -ne $snap) { $kept.Add($c) } }
        $vm.Checkpoints = $kept
    }.GetNewClosure()

    # TEST-ONLY introspection seam (NOT a backend method): expose the cross-cutting CALL LOG as a
    # NON-scriptblock key so the interface-parity test (which compares only scriptblock-valued keys)
    # ignores it and the real backend stays free of it. A test reads $backend.FakeCallLog to prove
    # call ordering (e.g. detach precedes the host read) AFTER a full Invoke-Voidseal run, when the
    # per-VM HardDrives record is already gone (the VM was torn down).
    $b.FakeCallLog = $state.CallLog

    return $b
}
