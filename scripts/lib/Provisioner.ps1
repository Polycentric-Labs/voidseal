<#
.SYNOPSIS
    Voidseal — Provisioner + Reaper.

.DESCRIPTION
    Builds a risk-tiered sandbox VM from a NORMALIZED profile (the output of
    Import-TierProfile / Import-WorkloadProfile) and tears it down again. EVERYTHING
    touches Hyper-V through the backend abstraction (HyperVBackend.ps1) — this file
    NEVER calls a raw `New-VM` / `Set-VM*` / `Checkpoint-VM` / `*VMSwitch` / etc. cmdlet.
    That single seam is what lets the whole thing unit-test against the in-memory fake.

    Dot-source this file (after HyperVBackend.ps1 + ProfileLoader.ps1) to get:

        New-SandboxVM       -Profile <hashtable> -Name <vmname> [-Backend]
        Checkpoint-Sandbox  -Name <vmname> -SnapshotName <name> [-Backend]
        Restore-Sandbox     -Name <vmname> -SnapshotName <name> [-Backend]
        Remove-Sandbox      -Name <vmname> [-DeleteDisks] [-Descriptor] [-Backend]

    INJECTION: every public function takes `-Backend <hashtable>` defaulting to
    `(New-RealHyperVBackend)`. Production passes nothing (real Hyper-V). Tests pass
    `-Backend (New-FakeHyperVBackend)` and assert against the fake's in-memory state.

    FAIL-CLOSED: New-SandboxVM runs the backend's TestAvailable() preflight first; if
    Hyper-V is unreachable / this process is not elevated, it throws a clear, actionable
    message BEFORE creating anything (no half-built VM). A host free-RAM gate follows it (see
    -HostMemoryMarginBytes): the guest's memory plus a margin must fit in the host's free physical
    memory, and an unreadable host is refused, before anything is created.

    PROVISIONING ORDER (mirrors real Hyper-V dependencies so the fake's fidelity guards
    are satisfied — switch/VHD must exist before they're referenced):
        preflight -> idempotency check -> NewVHD (system disk) -> NewVM (Gen2, NoVHD)
        -> SetMemory -> SetProcessor (+nested virt, +optional CPU caps) -> SetFirmware (SecureBoot template)
        -> SetComPort (COM1, Linux mgmt) -> NewSwitch + ConnectNetworkAdapter (IsolatedInternalSwitch VMs only)
        -> AddHardDiskDrive (attach system disk).
    The VM is left POWERED OFF — the Sealer runs before first boot.

    MID-PROVISION ROLLBACK: steps 1-8 run inside a try/catch (AFTER preflight + idempotency).
    Created artifacts are tracked as-we-go (the VM once NewVM succeeds, each switch WE created,
    the disks in $createdDisks). If ANY step throws, the catch best-effort tears down exactly
    what was created (VM -> its disks -> switches), then RETHROWS the original error. So a
    failed provision leaves NO orphaned VM/disk/switch and the idempotency guard does not wedge
    a retry of the same name. (NewVM passes NoVHD=$true so real Hyper-V doesn't auto-create a
    boot VHD — the provisioner attaches its own system disk at step 8; the fake ignores NoVHD.)

    RETURNS a sandbox descriptor (PSCustomObject) the later tasks consume — see
    New-SandboxDescriptor below for the shape.

    BACKEND ADDENDA:
      * RemoveVHD @{ Path } — added to the backend (manifest + both factories + tests). The Reaper's
        -DeleteDisks step needs to delete the detached .vhdx the provisioner created; RemoveVM
        deliberately leaves disks. Real backend = Remove-Item on the file (a filesystem op,
        not a Hyper-V cmdlet); fake = drops its in-memory record so the -DeleteDisks contract
        is unit-testable. Both idempotent. This keeps disk deletion routed through the backend
        seam instead of the Provisioner reaching for a raw cmdlet.
      * RemoveSwitch @{ Name } — added to the backend (manifest + both factories + tests). The mid-
        provision rollback (above) deletes any vSwitch the provision created so a failed
        provision leaves no orphaned switch. Real backend = Remove-VMSwitch -Force (guarded by
        a Get so it's idempotent); fake = drops its in-memory record. (Also usable by the Sealer.)
        Teardown uses it as well: Remove-Sandbox removes the switches the descriptor records in
        CreatedSwitches, so a COMPLETED run leaves no per-VM switch behind either.
    NIC POLICY (2026-10-03):
      * Get-SealNicPolicy (SealPolicy.ps1, dot-sourced below) is the single predicate for whether a VM
        keeps a NIC, shared with Lock-Sandbox and Assert-Sealed. New-SandboxVM records the profile's Network label on the descriptor so all
        three compute the same answer. Only a Tier-1 non-processor gets a switch and a connected NIC.
    AUTOMATIC CHECKPOINTS (RC7 — gap CLOSED 2026-06-25):
      * Hyper-V defaults `AutomaticCheckpointsEnabled=ON`, which pins a differencing AVHDX per disk at
        VM start: the guest writes its result into the .avhdx while the host reads the empty BASE .vhdx,
        so every result read came back empty (a disposable sandbox also does not want checkpoints leaking
        state across runs). The backend now has `SetAutomaticCheckpoints @{ VMName; Enabled }` (real =
        `Set-VM -AutomaticCheckpointsEnabled`; fake flips the recorded flag), and provisioning CALLS it
        (Enabled=$false) right after NewVM — the descriptor's `AutomaticCheckpointsEnabled=$false` field
        now reflects the ACTUALLY-APPLIED posture, not just recorded intent.
#>

Set-StrictMode -Version Latest

# The NIC policy predicate shared with Lock-Sandbox and Assert-Sealed (see SealPolicy.ps1).
. (Join-Path $PSScriptRoot 'SealPolicy.ps1')
# HostProxy egress: the per-VM address plan, its collision check, and teardown (see HostEgress.ps1).
. (Join-Path $PSScriptRoot 'HostEgress.ps1')

# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------

# The stable fail-closed prefix the backend uses (HyperVBackend.ps1
# $script:HyperVUnavailablePrefix). Re-declared here so this file is usable even
# when dot-sourced standalone; callers/tests match on the substring, not this var.
$script:ProvisionUnavailableMessage =
    'Hyper-V unavailable or insufficient privilege (need elevation / Hyper-V Administrators group)'

<#
.SYNOPSIS
    Read a named field off a backend-returned VM record, regardless of backend shape.
.DESCRIPTION
    The FAKE backend returns a [hashtable] (fields are keys); the REAL backend returns a
    Microsoft.HyperV.PowerShell.VirtualMachine object (fields are properties). A hashtable
    has no .State property and a PSObject has no .Contains() method, so a single accessor
    must branch on type. Returns $Default if the field is absent/null on either shape.
#>
function Get-VMField {
    [CmdletBinding()]
    param(
        [AllowNull()] $VM,
        [Parameter(Mandatory)] [string] $Name,
        $Default = $null
    )
    if ($null -eq $VM) { return $Default }
    if ($VM -is [System.Collections.IDictionary]) {
        if ($VM.Contains($Name) -and $null -ne $VM[$Name]) { return $VM[$Name] }
        return $Default
    }
    # PSObject / real VM object: probe the property bag.
    $prop = $VM.PSObject.Properties[$Name]
    if ($null -ne $prop -and $null -ne $prop.Value) { return $prop.Value }
    return $Default
}

<#
.SYNOPSIS
    Return $true if a file carries the NTFS SPARSE attribute. Pure host-FS check (no Hyper-V).
.DESCRIPTION
    A qemu-img-converted parent disk is often SPARSE, and Hyper-V REFUSES to create a differencing
    child off a sparse parent with a raw `0xC03A001A: ... must not be sparse` error (this bit a live
    run). Detect the sparse attribute up front via the file's NTFS attributes so the Provisioner can
    fail closed with an actionable message BEFORE the differencing NewVHD call hits that opaque error.

    Pure preflight: no Hyper-V call is needed to detect sparseness — it is a host filesystem attribute.
    Split into its own (mockable) function so the sparse branch is unit-testable even on a host/CI where
    a real sparse file cannot be fabricated. StrictMode-safe; a non-existent path is the CALLER's concern
    (the preflight guard handles file-not-found with its own clear message before calling this).
#>
function Test-IsSparseFile {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Path)

    $attrs = [System.IO.File]::GetAttributes($Path)
    return (($attrs -band [System.IO.FileAttributes]::SparseFile) -eq [System.IO.FileAttributes]::SparseFile)
}

<#
.SYNOPSIS
    Pure host-FS free-space preflight (no Hyper-V call). Refuses fail-closed BEFORE any disk
    creation when the volume hosting a VHDX cannot hold the required budget + headroom.
.DESCRIPTION
    Finding I6b: the engine had ZERO host-free-space preflight — a guest fork-bomb/fill can
    balloon a dynamic VHDX toward its max, exhausting host disk, with nothing gating it.
    Measures the volume HOSTING -Path (not necessarily C:) via `Get-Volume -FilePath`, so it
    is correct regardless of which drive the sandbox storage root lives on. Split into its own
    (mockable) function — like Test-IsSparseFile — so it is unit-testable without needing a
    real near-full volume: tests `Mock Get-Volume { ... }`.

    -Path need not exist yet (the caller invokes this BEFORE the disk is created); only the
    volume it resolves onto must exist. An unresolvable volume (bad/disconnected drive letter)
    is itself fail-closed: Get-Volume's own error propagates via -ErrorAction Stop rather than
    being swallowed, since silently skipping the check on an unresolvable volume would be a
    fail-OPEN containment hole.
#>
function Test-HostFreeSpace {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [long]   $RequiredBytes,
        [long] $HeadroomBytes = 1GB,  # fixed safety margin above the summed disk budgets
        [hashtable] $Backend           # optional: query free space through the backend seam
    )
    # Reading free space is a HOST query, so it goes through the backend seam when the caller
    # has one. That is what keeps a mock-backed run independent of the machine it runs on: the
    # fake reports a configurable figure instead of whatever the real volume happens to have.
    # Without a Backend (a direct call) we fall back to Get-Volume, so callers and tests that
    # exercise this function on its own are unaffected.
    if ($Backend) {
        $free = [long](& $Backend.GetVolumeFreeSpace @{ Path = $Path })
    } else {
        $vol  = Get-Volume -FilePath $Path -ErrorAction Stop  # maps the .vhdx path to its volume
        $free = [long]$vol.SizeRemaining
    }
    $need = $RequiredBytes + $HeadroomBytes
    if ($free -lt $need) {
        throw ("Test-HostFreeSpace: insufficient host free space on the volume hosting '$Path' — " +
               "need $need bytes (budget $RequiredBytes + headroom $HeadroomBytes) but only $free free. " +
               "Free up space or choose another storage root. Failing closed BEFORE disk creation.")
    }
    return $true
}

<#
.SYNOPSIS
    Parse a human memory string ('4GB', '512MB', '2 GB') OR a raw byte count into bytes.
.DESCRIPTION
    Tier profiles store Memory as a string ('4GB'); PowerShell's own 4GB literals are
    [long] bytes. Accept both. Throws on an unparseable value (fail-closed) so a typo'd
    profile can't silently provision a 0-byte VM.
#>
function ConvertTo-Bytes {
    [CmdletBinding()]
    [OutputType([long])]
    param([Parameter(Mandatory)] [AllowNull()] $Value)

    if ($null -eq $Value) {
        throw "ConvertTo-Bytes: memory/size value is null."
    }
    # Already numeric (e.g. a 4GB literal from a profile that used one, or a plain int).
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
        return [long]$Value
    }

    $s = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($s)) {
        throw "ConvertTo-Bytes: memory/size value is blank."
    }

    # <number><unit?>  — unit in KB/MB/GB/TB (binary, 1024-based, matching PS literals).
    $m = [regex]::Match($s, '^(?<num>\d+(?:\.\d+)?)\s*(?<unit>KB|MB|GB|TB|B)?$', 'IgnoreCase')
    if (-not $m.Success) {
        throw "ConvertTo-Bytes: cannot parse memory/size value '$Value' (expected e.g. '4GB', '512MB', or a byte count)."
    }

    $num  = [double]$m.Groups['num'].Value
    $unit = $m.Groups['unit'].Value.ToUpperInvariant()
    $mult = switch ($unit) {
        'KB'    { 1KB }
        'MB'    { 1MB }
        'GB'    { 1GB }
        'TB'    { 1TB }
        default { 1 }     # bare number or 'B' -> bytes
    }
    return [long]($num * $mult)
}

<#
.SYNOPSIS
    Resolve the BASE directory that holds every sandbox's folder (host-side).
.DESCRIPTION
    Precedence (E2): an explicit -StorageRoot beats the VOIDSEAL_STORAGE_ROOT environment variable,
    which beats the default of %ProgramData%\Voidseal\sandboxes (a temp-dir fallback on a non-Windows
    test/dev host). A blank or whitespace value counts as unset and falls through to the next source.

    A chosen root must be an ABSOLUTE LOCAL path. A relative path, a drive-relative path (C:dir), a
    rooted path with no drive (\dir) and any UNC, extended or device path (\\server\share, \\?\C:\dir,
    \\.\C:\dir) is refused, fail closed, with a message naming which source supplied it. The guard keeps
    a typo from landing a VM's disks relative to whatever the working directory happens to be, and keeps
    the system and data disks off a network share. Nothing is created here: the fake backend never
    touches the filesystem and the real NewVHD creates the files.
#>
function Resolve-SandboxStorageBase {
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $StorageRoot)

    $candidate = $null
    $source    = $null
    if (-not [string]::IsNullOrWhiteSpace($StorageRoot)) {
        $candidate = $StorageRoot.Trim(); $source = '-StorageRoot'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:VOIDSEAL_STORAGE_ROOT)) {
        $candidate = $env:VOIDSEAL_STORAGE_ROOT.Trim(); $source = 'the VOIDSEAL_STORAGE_ROOT environment variable'
    }

    if ($null -ne $candidate) {
        if (($candidate -match '^(\\\\|//)') -or -not [System.IO.Path]::IsPathFullyQualified($candidate)) {
            throw ("Sandbox storage root: $source value '$candidate' is not an absolute local path " +
                   "(for example 'D:\VoidsealSandboxes'). Relative, drive-relative, UNC, extended and device " +
                   "paths are refused. Failing closed BEFORE anything is created.")
        }
        return $candidate
    }

    if ($env:ProgramData -and -not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        return (Join-Path $env:ProgramData 'Voidseal\sandboxes')
    }
    return (Join-Path ([System.IO.Path]::GetTempPath()) 'Voidseal\sandboxes')
}

<#
.SYNOPSIS
    Compute one sandbox's storage folder, <base>\<vmName> (host-side). Disks + the COM1 pipe live here.
.DESCRIPTION
    The base comes from Resolve-SandboxStorageBase: -StorageRoot, then VOIDSEAL_STORAGE_ROOT, then
    %ProgramData%\Voidseal\sandboxes. The folder is always <base>\<vmName>.
#>
function Get-SandboxStorageRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [string] $StorageRoot
    )
    return (Join-Path (Resolve-SandboxStorageBase -StorageRoot $StorageRoot) $Name)
}

<#
.SYNOPSIS
    Build the standard sandbox-descriptor object the Provisioner returns + the Reaper
    (and later the Sealer / Runner) consume. ONE definition so the shape never drifts.
#>
function New-SandboxDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $Name,
        [Parameter(Mandatory)] [int]      $Tier,
        [int]      $Generation = 2,
        [string]   $GuestImage,
        [string]   $SecureBootTemplate,
        [string]   $ManagementChannel,
        [string]   $ComPipePath,
        [string]   $SwitchName,
        [string]   $SwitchType,
        [string]   $Network = $null,               # the profile's Network posture label; with Tier it decides the NIC policy (Get-SealNicPolicy)
        [string]   $DiskPath,                      # the primary / system disk
        [string[]] $DiskPaths   = @(),             # all attached disks
        [string[]] $CreatedDisks = @(),            # disks THIS provision created (Remove -DeleteDisks targets these)
        [string[]] $CreatedSwitches = @(),         # switches THIS provision created (Remove-Sandbox reaps these, never a pre-existing one)
        [string]   $InputDiskPath  = $null,        # optional host-side INPUT disk handed to the guest
        [string]   $OutputDiskPath = $null,        # optional host-side OUTPUT disk collected from the guest
        [string]   $SeedDiskPath   = $null,        # optional host-side CIDATA seed data disk (RC6: disk-mode cloud-init seed that survives the seal)
        [long]     $MemoryStartupBytes = 0,
        [int]      $ProcessorCount = 0,
        [bool]     $NestedVirt = $false,
        [string]   $State = 'Off',
        [bool]     $AutomaticCheckpointsEnabled = $false,
        [string]   $WorkloadDiskStatus       = $null,   # I2b: non-$null only on a HOST-side workload-disk write failure (e.g. 'DiskFull')
        [string]   $WorkloadDiskStatusReason = $null,    # I2b: human-readable detail paired with WorkloadDiskStatus
        [string]   $EgressMode = $null,            # the profile's EgressMode, recorded so the seal and teardown know it
        [System.Collections.IDictionary] $Egress = $null   # HostProxy only: the address plan (HostEgress.ps1 Get-EgressAddressPlan)
    )
    return [pscustomobject]@{
        Name                         = $Name
        Tier                         = $Tier
        Generation                   = $Generation
        GuestImage                   = $GuestImage
        SecureBootTemplate           = $SecureBootTemplate
        ManagementChannel            = $ManagementChannel
        ComPipePath                  = $ComPipePath
        SwitchName                   = $SwitchName
        SwitchType                   = $SwitchType
        Network                      = $Network
        DiskPath                     = $DiskPath
        DiskPaths                    = @($DiskPaths)
        CreatedDisks                 = @($CreatedDisks)
        CreatedSwitches              = @($CreatedSwitches)
        InputDiskPath                = $InputDiskPath
        OutputDiskPath               = $OutputDiskPath
        SeedDiskPath                 = $SeedDiskPath
        MemoryStartupBytes           = $MemoryStartupBytes
        ProcessorCount               = $ProcessorCount
        NestedVirt                   = $NestedVirt
        State                        = $State
        # The applied automatic-checkpoints posture (RC7 — see the file header). New-SandboxVM now
        # calls the backend's SetAutomaticCheckpoints (Enabled=$false) at provision time, so this field
        # records the state actually applied to the VM, not just intent.
        AutomaticCheckpointsEnabled  = $AutomaticCheckpointsEnabled
        # I2b ENOSPC sentinel: New-WorkloadDisks sets these on a classified HOST-side disk-full write
        # during Inputs population (distinct from a generic propagated throw). $null/$null in the
        # ordinary (non-full) case — every existing caller is unaffected.
        WorkloadDiskStatus           = $WorkloadDiskStatus
        WorkloadDiskStatusReason     = $WorkloadDiskStatusReason
        # Host egress (EgressMode='HostProxy', HostEgress.ps1). Egress is the address plan New-SandboxVM
        # checked; the next four record what was actually created on the host, each the moment it exists,
        # so Assert-Sealed can read them back and Remove-Sandbox removes exactly them (like CreatedSwitches).
        EgressMode                   = $EgressMode
        Egress                       = $Egress
        EgressGatewayAddress         = $null
        EgressFirewallRules          = @()
        EgressAcls                   = @()
        EgressProxy                  = $null
    }
}

# Get-SealNicPolicy lives in SealPolicy.ps1 (dot-sourced at the top of this file).

# --------------------------------------------------------------------------
# Public: New-SandboxVM  (the Provisioner)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Provision a sandbox VM from a normalized tier/workload profile. Returns a descriptor.
.PARAMETER Profile
    A normalized profile hashtable (Import-TierProfile / Import-WorkloadProfile output):
    Tier, Substrate, GuestImage, Memory, Cpu, NestedVirt, SecureBootTemplate,
    ManagementChannel, Network, etc.
.PARAMETER Name
    The VM name (also the sandbox id + storage subdir). Must start with a letter or digit and contain only
    letters, digits, '.', '_' and '-', 64 characters at most: Get-VM -Name and Get-VMSwitch -Name treat
    * ? [ ] as wildcards, and the name also becomes a folder, a pipe name and firewall rule names.
.PARAMETER ParentDiskPath
    (Optional) A base/golden image .vhdx. When supplied, the system disk is a DIFFERENCING
    disk off this parent (fast, copy-on-write). When omitted, a fresh dynamic disk is created.
    PREFLIGHT (fail-closed, pure host-FS): a supplied parent must EXIST and must NOT be SPARSE —
    Hyper-V refuses a differencing child off a sparse parent (0xC03A001A). A sparse parent throws an
    actionable message naming the `fsutil sparse setflag <path> 0` fix BEFORE any artifact is created.
.PARAMETER SystemDiskSizeBytes
    (Optional) Size of a fresh system disk when no ParentDiskPath is given. Default 40GB.
.PARAMETER StorageRoot
    (Optional) the base directory under which this VM's folder (<root>\<name>) and every disk the
    provision creates live. Beats the VOIDSEAL_STORAGE_ROOT environment variable, which beats the
    %ProgramData%\Voidseal\sandboxes default. Must be an absolute local path (Resolve-SandboxStorageBase
    refuses anything else, before any backend call). Teardown never recomputes it: Remove-Sandbox deletes
    only the paths the descriptor recorded.
.PARAMETER HostMemoryMarginBytes
    (Optional) headroom the HOST must keep free on top of the guest's memory. Before creating anything,
    New-SandboxVM reads the host's free physical memory through the backend's GetHostMemory and refuses
    (fail closed) when FreeBytes < the guest's startup memory + this margin. It also refuses when the read
    throws or returns nothing usable: an unreadable host is not assumed to have room. Default 2GB.
.PARAMETER Backend
    The Hyper-V backend. Defaults to the real one; tests inject the fake.
#>
function New-SandboxVM {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Profile,
        [Parameter(Mandatory)] [AllowEmptyString()] [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')] [string] $Name,
        [string] $ParentDiskPath,
        [long]   $SystemDiskSizeBytes = 40GB,
        [string] $StorageRoot,
        [ValidateRange(0, [long]::MaxValue)] [long] $HostMemoryMarginBytes = 2GB,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    # --- input validation (fail-closed before any backend call) -----------
    if ($null -eq $Profile) {
        throw "New-SandboxVM: -Profile is null. Pass an Import-TierProfile / Import-WorkloadProfile result."
    }
    if (-not ($Profile -is [System.Collections.IDictionary])) {
        throw "New-SandboxVM: -Profile must be a hashtable (the normalized profile from the loader)."
    }
    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw "New-SandboxVM: -Name is blank. A sandbox VM needs a non-empty name."
    }
    # E2: resolve (and validate) the storage root up front so a bad root fails closed before ANY backend
    # call. PowerShell variable names are case-insensitive, so the per-VM folder is $vmStorageDir, not
    # $storageRoot (which would alias the -StorageRoot parameter).
    $vmStorageDir = Join-Path (Resolve-SandboxStorageBase -StorageRoot $StorageRoot) $Name

    # --- preflight: is Hyper-V usable? (fail-closed) ----------------------
    $probe = & $Backend.TestAvailable @{}
    if (-not $probe.Available) {
        $reason = if ($probe.ContainsKey('Reason') -and $probe.Reason) { $probe.Reason } else { '(no reason reported)' }
        throw ("New-SandboxVM: cannot provision '$Name' — $script:ProvisionUnavailableMessage. Backend reports: $reason")
    }

    # --- idempotency: refuse to clobber an existing VM of this name -------
    $existing = & $Backend.GetVM @{ Name = $Name }
    if ($null -ne $existing) {
        throw "New-SandboxVM: a VM named '$Name' already exists. Remove it first (Remove-Sandbox -Name '$Name') or choose another name."
    }

    # --- pull + normalize profile fields ----------------------------------
    $tier = [int]$Profile['Tier']
    $generation = 2     # all sandbox VMs are Gen2 (UEFI SecureBoot)

    $memoryBytes = ConvertTo-Bytes $Profile['Memory']
    $cpuCount    = [int]$Profile['Cpu']

    $guestImage  = if ($Profile.ContainsKey('GuestImage')) { [string]$Profile['GuestImage'] } else { $null }
    $secureTmpl  = if ($Profile.ContainsKey('SecureBootTemplate')) { [string]$Profile['SecureBootTemplate'] } else { $null }
    $mgmtChannel = if ($Profile.ContainsKey('ManagementChannel')) { [string]$Profile['ManagementChannel'] } else { $null }

    # The Network posture label decides, with the tier, whether this VM keeps a NIC at all
    # (Get-SealNicPolicy). It is recorded on the descriptor so Lock-Sandbox and Assert-Sealed enforce
    # the SAME decision this provision makes. Before 2026-10-03 it was never recorded, which left the
    # seal gate's processor check unable to fire in production.
    $network   = if ($Profile.ContainsKey('Network')) { [string]$Profile['Network'] } else { $null }
    $nicPolicy = Get-SealNicPolicy -Tier $tier -Network $network
    $egressMode = if ($Profile.ContainsKey('EgressMode')) { [string]$Profile['EgressMode'] } else { $null }

    $nestedVirt = $false
    if ($Profile.ContainsKey('NestedVirt') -and $null -ne $Profile['NestedVirt']) {
        $nestedVirt = [bool]$Profile['NestedVirt']
    }

    # Optional CPU caps (E1). Absent means Hyper-V's defaults, so they reach SetProcessor only when set.
    $cpuMaxPercent  = $null
    $cpuRelWeight   = $null
    if ($Profile.ContainsKey('CpuMaximumPercent') -and $null -ne $Profile['CpuMaximumPercent']) { $cpuMaxPercent = [int]$Profile['CpuMaximumPercent'] }
    if ($Profile.ContainsKey('CpuRelativeWeight') -and $null -ne $Profile['CpuRelativeWeight']) { $cpuRelWeight  = [int]$Profile['CpuRelativeWeight'] }

    # --- host free-RAM gate (E1; fail-closed, BEFORE anything is created) -------------------
    # A guest whose startup memory the host cannot actually supply either fails to start or starves the
    # host, and with the memory now profile-sized a workload can ask for a lot. Read the host's free
    # physical memory through the backend seam and refuse unless it covers the guest plus the margin.
    # A read that throws, returns nothing, or returns a figure that is not a non-negative number is a
    # REFUSAL, never a pass: an unreadable host is not assumed to have room. The message names both
    # numbers so the operator can see which side to change (host load, profile Memory or the margin).
    $hostMem = $null
    try { $hostMem = & $Backend.GetHostMemory @{} }
    catch {
        throw ("New-SandboxVM: cannot read host memory ($($_.Exception.Message)); refusing to provision " +
               "'$Name' because free RAM could not be verified. Failing closed BEFORE anything is created.")
    }
    $freeRaw = Get-VMField -VM $hostMem -Name 'FreeBytes'
    $freeOk  = ($freeRaw -is [int] -or $freeRaw -is [long] -or $freeRaw -is [uint32] -or $freeRaw -is [uint64] -or $freeRaw -is [double]) -and ([double]$freeRaw -ge 0)
    if (-not $freeOk) {
        throw ("New-SandboxVM: the host memory read returned no usable FreeBytes (got '$freeRaw'); refusing to " +
               "provision '$Name' because free RAM could not be verified. Failing closed BEFORE anything is created.")
    }
    $hostFreeBytes = [long]$freeRaw
    $requiredRam   = $memoryBytes + $HostMemoryMarginBytes
    if ($hostFreeBytes -lt $requiredRam) {
        throw ("New-SandboxVM: refusing to provision '$Name': host free memory is $hostFreeBytes bytes but the " +
               "guest needs $memoryBytes bytes plus a $HostMemoryMarginBytes byte margin ($requiredRam bytes in all). " +
               "Free host memory, lower the profile's Memory, or lower -HostMemoryMarginBytes. " +
               "Failing closed BEFORE anything is created.")
    }

    # --- sparse-parent preflight (fail-closed; pure host-FS, BEFORE any creation) ---------
    # When a ParentDiskPath is supplied the system disk will be a DIFFERENCING child off it. Hyper-V
    # REFUSES to create a differencing child from a SPARSE parent with an opaque raw error
    # (`0xC03A001A: ... must not be sparse`) — a qemu-img-converted golden disk is commonly sparse, and
    # this bit a live run. Detect it up front from the file's NTFS attribute (no Hyper-V call needed) and
    # fail closed with an ACTIONABLE message naming the fix. Only checked when a parent is supplied AND
    # exists; a missing parent gets its own clear message (the differencing NewVHD would otherwise fail
    # opaquely on the absent file).
    if (-not [string]::IsNullOrWhiteSpace($ParentDiskPath)) {
        if (-not (Test-Path -LiteralPath $ParentDiskPath -PathType Leaf)) {
            throw ("New-SandboxVM: -ParentDiskPath '$ParentDiskPath' does not exist (cannot create a " +
                   "differencing system disk from a missing parent). Fail closed.")
        }
        if (Test-IsSparseFile -Path $ParentDiskPath) {
            throw ("New-SandboxVM: -ParentDiskPath '$ParentDiskPath' is a SPARSE file; Hyper-V cannot create " +
                   "a differencing child from it (0xC03A001A: the parent virtual disk must not be sparse). " +
                   "Clear the sparse flag first: ``fsutil sparse setflag '$ParentDiskPath' 0`` (then optionally " +
                   "re-convert via qemu-img with -o subformat=dynamic, or Convert-VHD). Fail closed.")
        }
    }

    # Storage layout (record strings — the FS isn't touched here; the real NewVHD creates the file).
    $systemDisk  = Join-Path $vmStorageDir ("{0}-system.vhdx" -f $Name)
    $comPipe     = "\\.\pipe\{0}-com1" -f $Name

    # --- host-free-space preflight (I6b; fail-closed; pure host-FS, BEFORE any creation) --
    # A guest fork-bomb/fill can balloon a dynamic VHDX toward its max with nothing gating host
    # disk exhaustion. Budget = the system disk's worst-case size: for a DIFFERENCING child, its
    # PARENT's on-disk size is the conservative bound (the child grows toward the parent's data,
    # and a bad/sparse parent was already rejected above so the parent's Length is a real number
    # here); for a fresh disk, the full requested $SystemDiskSizeBytes (a dynamic disk's worst
    # case at CREATE time, since currentFileSize≈0). Measures the volume hosting $vmStorageDir,
    # the resolved sandbox storage folder every provision uses (-StorageRoot, the
    # VOIDSEAL_STORAGE_ROOT variable, or the ProgramData default), so a relocated root is the volume
    # that gets checked. The read goes through the backend seam, so a mock-backed run never depends
    # on a fake VM name resolving to a real drive.
    $requiredBytes = if (-not [string]::IsNullOrWhiteSpace($ParentDiskPath)) {
        (Get-Item -LiteralPath $ParentDiskPath).Length
    }
    else {
        $SystemDiskSizeBytes
    }
    $null = Test-HostFreeSpace -Path $vmStorageDir -RequiredBytes $requiredBytes -Backend $Backend

    # --- HostProxy address plan + collision check (fail-closed, BEFORE any creation) ----------------
    # A VM that keeps a NIC and declares EgressMode='HostProxy' gets a deterministic /30 from its name
    # (HostEgress.ps1). Any host address or NAT network overlapping it, or a host that cannot be read,
    # refuses the provision here, before anything exists. The plan rides the descriptor: the seed takes
    # the guest's static address from it, Lock-Sandbox installs the host side from it.
    $egressPlan = $null
    if ($Profile['Substrate'] -eq 'HyperV-Gen2' -and $nicPolicy -eq 'IsolatedInternalSwitch' -and $egressMode -eq 'HostProxy') {
        $egressPlan = Get-EgressAddressPlan -VMName $Name -SwitchName ("{0}-int" -f $Name)
        Assert-EgressAddressFree -Plan $egressPlan -Backend $Backend -Context 'New-SandboxVM'
    }

    # --- artifact tracking for mid-provision ROLLBACK ---------------------
    # If ANY creation step below throws, the catch best-effort tears down EXACTLY what was
    # created so far (no orphaned VM/disk/switch) and rethrows the original error. Without
    # this, a half-built VM is orphaned AND the "already exists" idempotency guard wedges a
    # retry of the same name. Track as-we-go so cleanup never touches a not-yet-created thing.
    $createdDisks    = [System.Collections.Generic.List[string]]::new()
    $createdSwitches = [System.Collections.Generic.List[string]]::new()
    $vmCreated       = $false

    $switchName = $null
    $switchType = $null

    try {
        # --- 1. system disk: differencing off a parent, else a fresh dynamic disk ---
        # OUTPUT-STREAM DISCIPLINE (a real-backend bug found during live debugging): the REAL backend methods emit Hyper-V
        # objects to the output stream (real New-VHD/New-VM/Set-VM*/Add-*/New-VMSwitch/Connect-*
        # all return a record). Any such emission NOT captured here would be collected as part of
        # THIS function's return value, turning the lone descriptor into an ARRAY @(<stray>, ...,
        # <descriptor>). That made Import-SandboxAsset get element [0] (a raw VM object with no
        # .Name → "descriptor has no VM Name") and teardown crash on a missing .CreatedDisks. So
        # EVERY effect-only backend call below is routed to `$null = ...` (the fake's quiet
        # hashtables are unaffected — suppression is transparent to it). New-SandboxVM MUST return
        # EXACTLY the descriptor (asserted at the end + by tests/ProvisionerReturnContract.Tests.ps1).
        if (-not [string]::IsNullOrWhiteSpace($ParentDiskPath)) {
            $null = & $Backend.NewVHD @{ Path = $systemDisk; Differencing = $true; ParentPath = $ParentDiskPath }
        }
        else {
            $null = & $Backend.NewVHD @{ Path = $systemDisk; SizeBytes = $SystemDiskSizeBytes; Dynamic = $true }
        }
        $createdDisks.Add($systemDisk)

        # --- 2. the VM (Gen2) ---------------------------------------------
        # NoVHD=$true: New-VM must NOT auto-create a blank boot VHD (real Hyper-V otherwise
        # emits a diskless-VM warning and/or makes a disk we don't want). We attach our own
        # system disk in step 8. (The fake ignores NoVHD; the real backend honors it.)
        $null = & $Backend.NewVM @{ Name = $Name; Generation = $generation; MemoryStartupBytes = $memoryBytes; Path = $vmStorageDir; NoVHD = $true }
        $vmCreated = $true

        # --- 2a. disable automatic checkpoints (RC7) ----------------------
        # RC7 (2026-06-25 live): Hyper-V defaults AutomaticCheckpointsEnabled=ON, so each disk gets a
        # differencing .avhdx at VM start and the guest's writes land in the .avhdx while the host reads
        # the empty BASE .vhdx (every result read came back empty). The descriptor has long RECORDED the
        # intent (AutomaticCheckpointsEnabled=$false) but no backend method applied it; now it does. A
        # disposable sandbox never wants automatic checkpoints (they pin a differencing AVHDX and leak
        # state across runs), so this is unconditionally $false — the same value the descriptor records.
        $autoCheckpoints = $false
        $null = & $Backend.SetAutomaticCheckpoints @{ VMName = $Name; Enabled = $autoCheckpoints }

        # --- 3. memory (fixed startup; dynamic disabled for a deterministic sandbox) ---
        $null = & $Backend.SetMemory @{ VMName = $Name; StartupBytes = $memoryBytes; DynamicMemoryEnabled = $false }

        # --- 4. processor (+ expose virt extensions only when NestedVirt) -
        $procArgs = @{ VMName = $Name; Count = $cpuCount }
        if ($nestedVirt) { $procArgs.ExposeVirtualizationExtensions = $true }
        if ($null -ne $cpuMaxPercent) { $procArgs.Maximum        = $cpuMaxPercent }   # E1: only when the profile sets it
        if ($null -ne $cpuRelWeight)  { $procArgs.RelativeWeight = $cpuRelWeight }
        $null = & $Backend.SetProcessor $procArgs

        # --- 5. firmware: SecureBoot ON with the EFFECTIVE Secure Boot template -------
        # RC1 (2026-06-24 live): Voidseal only provisions Linux (Debian) Gen2 guests. If a profile OMITS
        # (or blank-sets) SecureBootTemplate, we MUST NOT fall through to Hyper-V's MicrosoftWindows
        # default — that template rejects Debian's MS-UEFI-CA-signed shim/grub and the guest never boots
        # (it sits "Running" at firmware until the idle timeout force-stops it). So default the template
        # to the Linux CA here, and record the EFFECTIVE (defaulted) template on the descriptor.
        if ([string]::IsNullOrWhiteSpace($secureTmpl)) { $secureTmpl = 'MicrosoftUEFICertificateAuthority' }
        $fwArgs = @{ VMName = $Name; EnableSecureBoot = $true; SecureBootTemplate = $secureTmpl }
        $null = & $Backend.SetFirmware $fwArgs

        # --- 6. COM1 named pipe — the Linux management channel ------------
        # Tier profiles for Linux guests declare ManagementChannel='Com1Serial' (PS Direct is
        # Windows-guest-only). Wire COM1 to a host named pipe so the Runner can drive the
        # serial console. We wire it whenever the channel is Com1Serial (or unset on a VM tier,
        # which still benefits from a serial console for a headless Linux guest).
        if ($null -eq $mgmtChannel -or $mgmtChannel -eq 'Com1Serial') {
            $null = & $Backend.SetComPort @{ VMName = $Name; Number = 1; Path = $comPipe }
        }

        # --- 7. network: switch + NIC ONLY for a VM that keeps one ---------
        # Get-SealNicPolicy is the single predicate, shared with Lock-Sandbox and Assert-Sealed. Only an
        # IsolatedInternalSwitch VM (Tier 1, non-processor) on the Hyper-V substrate gets an Internal
        # vSwitch and a connected NIC. A NoAdapter VM (Tier 0, Tier >= 2, any processor) gets NO switch:
        # the default adapter real New-VM creates stays unconnected until Lock-Sandbox removes it.
        # Create the switch FIRST (the backend rejects connecting a NIC to a non-existent switch, as
        # real Hyper-V does). A switch of that name that already exists is REFUSED, not reused (until
        # 2026-10-16 the provision connected to it): another run or something outside the tool owns it,
        # and the gate's isolation checks assume the switch is the one this provision built. The throw
        # lands in the rollback below, which removes the VM and leaves the foreign switch alone (it was
        # never added to $createdSwitches).
        if ($Profile['Substrate'] -eq 'HyperV-Gen2' -and $nicPolicy -eq 'IsolatedInternalSwitch') {
            $switchType = 'Internal'
            $switchName = "{0}-int" -f $Name
            if ($null -ne (& $Backend.GetSwitch @{ Name = $switchName })) {
                throw ("New-SandboxVM: a vSwitch named '$switchName' already exists; refusing to reuse it. Another run or " +
                       "something outside the tool owns it, and a switch this provision did not build cannot be assumed " +
                       "isolated. Remove it (Remove-VMSwitch -Name '$switchName') or choose another sandbox name. Fail closed.")
            }
            $null = & $Backend.NewSwitch @{ Name = $switchName; SwitchType = $switchType }
            $createdSwitches.Add($switchName)   # the switch this provision built; rollback and teardown reap exactly these
            $null = & $Backend.ConnectNetworkAdapter @{ VMName = $Name; SwitchName = $switchName }
        }

        # --- 8. attach the system disk ------------------------------------
        $null = & $Backend.AddHardDiskDrive @{ VMName = $Name; Path = $systemDisk }

        # --- read back authoritative state for the descriptor -------------
        $vm    = & $Backend.GetVM @{ Name = $Name }
        $state = [string](Get-VMField -VM $vm -Name 'State' -Default 'Off')

        $descriptor = New-SandboxDescriptor `
            -Name               $Name `
            -Tier               $tier `
            -Generation         $generation `
            -GuestImage         $guestImage `
            -SecureBootTemplate $secureTmpl `
            -ManagementChannel  $mgmtChannel `
            -ComPipePath        $comPipe `
            -SwitchName         $switchName `
            -SwitchType         $switchType `
            -Network            $network `
            -DiskPath           $systemDisk `
            -DiskPaths          @($systemDisk) `
            -CreatedDisks       @($createdDisks) `
            -CreatedSwitches    @($createdSwitches) `
            -MemoryStartupBytes $memoryBytes `
            -ProcessorCount     $cpuCount `
            -NestedVirt         $nestedVirt `
            -State              $state `
            -AutomaticCheckpointsEnabled $autoCheckpoints `
            -EgressMode         $egressMode `
            -Egress             $egressPlan

        # BELT-AND-BRACES (a real-backend bug found during live debugging): guarantee this function emits EXACTLY the
        # descriptor and nothing else. If a future edit reintroduces an uncaptured backend emission
        # above, $descriptor would be an array here — fail closed with a clear message rather than
        # silently returning a polluted array the orchestrator then mis-reads as element [0]. (A
        # PSCustomObject is not [IList], so the lone-descriptor happy path passes straight through.)
        if ($descriptor -is [System.Collections.IList]) {
            throw ("New-SandboxVM: INTERNAL — provision of '$Name' produced $(@($descriptor).Count) " +
                   "output objects instead of one descriptor (an effect-only backend call leaked into " +
                   "the return stream). This is the output-stream-pollution class of bug; suppress the " +
                   "offending '& `$Backend.<Method>' with '`$null = ...'. Fail closed.")
        }
        return $descriptor
    }
    catch {
        # Mid-provision failure: best-effort roll back EVERYTHING this call created, in
        # reverse-ish dependency order (VM first so its disks detach, then disks, then the
        # switches). Each step is defensive (its own try/catch) so one cleanup failure can't
        # mask the real error — which we RETHROW unchanged at the end so the caller sees the
        # original cause, not a teardown artifact.
        $original = $_

        if ($vmCreated) {
            # Remove-Sandbox stops a running VM, unregisters it, and (no -DeleteDisks here)
            # leaves the disks for the explicit disk pass below. Swallow any teardown error.
            try { Remove-Sandbox -Name $Name -Backend $Backend }
            catch { Write-Warning "New-SandboxVM rollback: failed to remove VM '$Name': $($_.Exception.Message)" }
        }

        # Delete every disk THIS provision created (routes through the backend's RemoveVHD;
        # idempotent + best-effort per disk).
        if ($createdDisks.Count -gt 0) {
            try { Remove-SandboxDisks -Disks @($createdDisks) -Backend $Backend }
            catch { Write-Warning "New-SandboxVM rollback: failed to delete created disks: $($_.Exception.Message)" }
        }

        # Remove every switch THIS provision created (a pre-existing switch of the same name is refused
        # before anything is built, and is never tracked here). RemoveSwitch is idempotent + best-effort.
        foreach ($sw in @($createdSwitches)) {
            try { $null = & $Backend.RemoveSwitch @{ Name = $sw } }
            catch { Write-Warning "New-SandboxVM rollback: failed to remove switch '$sw': $($_.Exception.Message)" }
        }

        throw $original
    }
}

# --------------------------------------------------------------------------
# Public: Checkpoint-Sandbox / Restore-Sandbox  (the Reaper — snapshot side)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Take a named checkpoint of a sandbox VM (the golden-image / pre-run snapshot).
#>
function Checkpoint-Sandbox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $SnapshotName,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    # The backend's Checkpoint already errors clearly on a missing VM (fake: "no such VM").
    # Effect-only: suppress so the real backend's emission can't leak as this function's return.
    $null = & $Backend.Checkpoint @{ VMName = $Name; SnapshotName = $SnapshotName }
}

<#
.SYNOPSIS
    Restore a sandbox VM to a previously-taken checkpoint (SnapshotRevert lifecycle).
#>
function Restore-Sandbox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $SnapshotName,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    # Effect-only: suppress so the real backend's emission can't leak as this function's return.
    $null = & $Backend.RestoreCheckpoint @{ VMName = $Name; SnapshotName = $SnapshotName }
}

# --------------------------------------------------------------------------
# Public: Remove-Sandbox  (the Reaper — teardown side)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Tear down a sandbox VM: stop it if running, unregister it, and (only with
    -DeleteDisks) explicitly delete the VHD files the provisioner created.
.DESCRIPTION
    IDEMPOTENT: removing a VM that does not exist is a clean no-op (a Write-Warning,
    not a throw) so repeated/abandoned teardowns never crash a pipeline.

    The backend's RemoveVM mirrors Hyper-V's Remove-VM: it UNREGISTERS the VM but LEAVES
    its VHDX files on disk. Disk deletion is THIS function's explicit, opt-in step:
      - default: leave the disks (safe — they can be re-attached / inspected).
      - -DeleteDisks: explicitly delete the created disks AFTER the VM is gone.

    -DeleteDisks targets the disks recorded on the sandbox descriptor's CreatedDisks if a
    -Descriptor is supplied; otherwise it falls back to this VM's currently-attached disks
    (read from the VM before removal) so a caller without the descriptor can still clean up.

    HOST EGRESS: with a -Descriptor that records HostProxy objects (EgressProxy, EgressAcls,
    EgressFirewallRules, EgressGatewayAddress), they are removed after the VM is stopped and before it is
    unregistered (Remove-SandboxEgress, HostEgress.ps1). Only recorded objects are touched. Anything that
    cannot be removed stays recorded, the rest of teardown still runs, and Remove-Sandbox then THROWS
    naming what is left, so the orchestrator's TeardownStatus reports it.

    SWITCHES: with a -Descriptor, the per-VM switches recorded on its CreatedSwitches are removed
    after the VM is gone, whether or not -DeleteDisks is set (a disk can be worth keeping for
    inspection; a switch whose only VM is gone serves nothing). Only switches New-SandboxVM itself
    created are listed there (it refuses a pre-existing switch of its name rather than reuse it), so a
    switch another run or the operator owns is never reaped. Without a -Descriptor no switch is
    touched, because ownership cannot be established from a name alone.
.PARAMETER Name
    The VM name.
.PARAMETER DeleteDisks
    Also delete the VHD files (the explicit cleanup step RemoveVM does NOT do).
.PARAMETER Descriptor
    (Optional) The New-SandboxVM descriptor; its CreatedDisks list is the authoritative
    set of disks to delete under -DeleteDisks, and its CreatedSwitches list is the set of
    switches to remove.
.PARAMETER Backend
    The Hyper-V backend.
#>
function Remove-Sandbox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [switch] $DeleteDisks,
        [pscustomobject] $Descriptor,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    # The switches this sandbox owns (see SWITCHES above). Read through PSObject.Properties so a
    # descriptor built without the field (by hand, or before it existed) yields none rather than a
    # StrictMode property-not-found throw in the middle of teardown.
    $switchesToRemove = @()
    if ($null -ne $Descriptor) {
        $csProp = $Descriptor.PSObject.Properties['CreatedSwitches']
        if ($null -ne $csProp -and $null -ne $csProp.Value) { $switchesToRemove = @($csProp.Value) }
    }

    $vm = & $Backend.GetVM @{ Name = $Name }
    if ($null -eq $vm) {
        # Idempotent no-op. If asked to delete disks for a VM that no longer exists, still
        # honor the descriptor's disk list (the VM may already be gone but disks may linger).
        Write-Warning "Remove-Sandbox: no VM named '$Name' exists; nothing to remove (no-op)."
        if ($DeleteDisks -and $null -ne $Descriptor) {
            Remove-SandboxDisks -Disks @($Descriptor.CreatedDisks) -Backend $Backend
        }
        # Host egress objects the descriptor still records (an earlier teardown may have stopped part way).
        $egressLeft = @(Remove-SandboxEgress -Descriptor $Descriptor -Backend $Backend)
        # Likewise the switch: an earlier teardown may have removed the VM and stopped before it.
        Remove-SandboxSwitches -Switches $switchesToRemove -Backend $Backend
        if ($egressLeft.Count -gt 0) {
            throw "Remove-Sandbox: host egress teardown for '$Name' could not remove: $($egressLeft -join '; ')"
        }
        return
    }

    # Determine which disks to delete BEFORE we unregister the VM (its HardDrives vanish with it).
    $disksToDelete = @()
    if ($DeleteDisks) {
        if ($null -ne $Descriptor -and @($Descriptor.CreatedDisks).Count -gt 0) {
            # Preferred + authoritative: the descriptor's CreatedDisks (plain path strings).
            $disksToDelete = @($Descriptor.CreatedDisks)
        }
        else {
            # Fallback (no descriptor kept): delete whatever is attached. The fake records
            # HardDrives as path STRINGS; the real backend as HardDiskDrive objects with a
            # .Path — normalize both to strings.
            $hd = Get-VMField -VM $vm -Name 'HardDrives' -Default @()
            $disksToDelete = @($hd | ForEach-Object {
                if ($_ -is [string]) { $_ }
                elseif ($null -ne $_ -and $null -ne $_.PSObject.Properties['Path']) { [string]$_.Path }
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
    }

    # Stop the VM first if it's running (Remove-VM on a running VM is an error / surprise).
    # Effect-only calls are suppressed ($null = ...) so a real-backend emission can't leak.
    $state = [string](Get-VMField -VM $vm -Name 'State' -Default 'Off')
    if ($state -eq 'Running') {
        $null = & $Backend.StopVM @{ Name = $Name; Force = $true }
    }

    # HostProxy egress (HostEgress.ps1): with the VM stopped, stop its proxy and remove exactly the port
    # ACL entries, firewall rules and gateway address the descriptor records, while the VM still exists
    # (its ACLs are settings of its adapter). A failure is collected, the rest of teardown still runs,
    # and the throw at the end puts it on the report rather than hiding it in a warning.
    $egressLeft = @(Remove-SandboxEgress -Descriptor $Descriptor -Backend $Backend)

    # Unregister the VM. This LEAVES the VHDX files (per the backend contract).
    $null = & $Backend.RemoveVM @{ Name = $Name; Force = $true }

    # Explicit, opt-in disk deletion — the step RemoveVM intentionally does NOT do.
    if ($DeleteDisks -and @($disksToDelete).Count -gt 0) {
        Remove-SandboxDisks -Disks @($disksToDelete) -Backend $Backend
    }

    # The per-VM switch goes last, once the VM and its NIC are gone, so nothing is bound to it.
    Remove-SandboxSwitches -Switches $switchesToRemove -Backend $Backend

    if ($egressLeft.Count -gt 0) {
        throw "Remove-Sandbox: host egress teardown for '$Name' could not remove: $($egressLeft -join '; ')"
    }
}

<#
.SYNOPSIS
    Remove a set of vSwitches through the backend's RemoveSwitch method. Idempotent per switch.
.DESCRIPTION
    The teardown counterpart of the mid-provision rollback's switch cleanup, and best-effort in the
    same way as Remove-SandboxDisks: one switch that fails to go is a warning, not an abort of the
    rest of teardown. RemoveSwitch is idempotent on both backends (an absent switch is a no-op).
    The caller passes only switches the provision created (the descriptor's CreatedSwitches).
#>
function Remove-SandboxSwitches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Switches,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    foreach ($sw in @($Switches)) {
        if ([string]::IsNullOrWhiteSpace($sw)) { continue }
        try {
            $null = & $Backend.RemoveSwitch @{ Name = $sw }
        }
        catch {
            Write-Warning "Remove-SandboxSwitches: failed to remove switch '$sw': $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Delete a set of VHD files through the backend's RemoveVHD method. Idempotent per disk.
.DESCRIPTION
    Goes through `$Backend.RemoveVHD @{ Path }` (a backend addendum — see this file's
    header). The real backend deletes the detached .vhdx file (a filesystem op, NOT a Hyper-V
    cmdlet); the fake drops its in-memory VHD record so unit tests can verify -DeleteDisks via
    GetVHDInfo. RemoveVHD is idempotent (absent path = no-op) on both backends. This function
    NEVER calls a raw cmdlet — disk deletion is routed through the seam like everything else.

    The caller (Remove-Sandbox) is responsible for having unregistered the VM first; once the
    VM is gone the disk is detached and safe to delete.
#>
function Remove-SandboxDisks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Disks,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    foreach ($disk in @($Disks)) {
        if ([string]::IsNullOrWhiteSpace($disk)) { continue }
        try {
            $null = & $Backend.RemoveVHD @{ Path = $disk }
        }
        catch {
            # Best-effort: a single un-deletable disk should not abort the rest of teardown.
            Write-Warning "Remove-SandboxDisks: failed to delete '$disk': $($_.Exception.Message)"
        }
    }
}
