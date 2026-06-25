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
        Remove-Sandbox      -Name <vmname> [-DeleteDisks] [-Backend]

    INJECTION: every public function takes `-Backend <hashtable>` defaulting to
    `(New-RealHyperVBackend)`. Production passes nothing (real Hyper-V). Tests pass
    `-Backend (New-FakeHyperVBackend)` and assert against the fake's in-memory state.

    FAIL-CLOSED: New-SandboxVM runs the backend's TestAvailable() preflight first; if
    Hyper-V is unreachable / this process is not elevated, it throws a clear, actionable
    message BEFORE creating anything (no half-built VM).

    PROVISIONING ORDER (mirrors real Hyper-V dependencies so the fake's fidelity guards
    are satisfied — switch/VHD must exist before they're referenced):
        preflight -> idempotency check -> NewVHD (system disk) -> NewVM (Gen2, NoVHD)
        -> SetMemory -> SetProcessor (+nested virt) -> SetFirmware (SecureBoot template)
        -> SetComPort (COM1, Linux mgmt) -> NewSwitch + ConnectNetworkAdapter (VM tiers)
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
    Compute the default sandbox storage root (host-side). Disks + the COM1 pipe live here.
.DESCRIPTION
    Defaults to %ProgramData%\Voidseal\sandboxes\<vmName> on Windows, with a temp-dir
    fallback for the non-Windows test/dev host (the fake backend never touches the FS, so
    these are just record strings the descriptor carries — no directory is created here).
#>
function Get-SandboxStorageRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Name)

    $base = $null
    if ($env:ProgramData -and -not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        $base = Join-Path $env:ProgramData 'Voidseal\sandboxes'
    }
    else {
        $base = Join-Path ([System.IO.Path]::GetTempPath()) 'Voidseal\sandboxes'
    }
    return (Join-Path $base $Name)
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
        [string]   $DiskPath,                      # the primary / system disk
        [string[]] $DiskPaths   = @(),             # all attached disks
        [string[]] $CreatedDisks = @(),            # disks THIS provision created (Remove -DeleteDisks targets these)
        [string]   $InputDiskPath  = $null,        # optional host-side INPUT disk handed to the guest
        [string]   $OutputDiskPath = $null,        # optional host-side OUTPUT disk collected from the guest
        [string]   $SeedDiskPath   = $null,        # optional host-side CIDATA seed data disk (RC6: disk-mode cloud-init seed that survives the seal)
        [long]     $MemoryStartupBytes = 0,
        [int]      $ProcessorCount = 0,
        [bool]     $NestedVirt = $false,
        [string]   $State = 'Off',
        [bool]     $AutomaticCheckpointsEnabled = $false
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
        DiskPath                     = $DiskPath
        DiskPaths                    = @($DiskPaths)
        CreatedDisks                 = @($CreatedDisks)
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
    }
}

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
    The VM name (also the sandbox id + storage subdir).
.PARAMETER ParentDiskPath
    (Optional) A base/golden image .vhdx. When supplied, the system disk is a DIFFERENCING
    disk off this parent (fast, copy-on-write). When omitted, a fresh dynamic disk is created.
    PREFLIGHT (fail-closed, pure host-FS): a supplied parent must EXIST and must NOT be SPARSE —
    Hyper-V refuses a differencing child off a sparse parent (0xC03A001A). A sparse parent throws an
    actionable message naming the `fsutil sparse setflag <path> 0` fix BEFORE any artifact is created.
.PARAMETER SystemDiskSizeBytes
    (Optional) Size of a fresh system disk when no ParentDiskPath is given. Default 40GB.
.PARAMETER Backend
    The Hyper-V backend. Defaults to the real one; tests inject the fake.
#>
function New-SandboxVM {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Profile,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Name,
        [string] $ParentDiskPath,
        [long]   $SystemDiskSizeBytes = 40GB,
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

    $nestedVirt = $false
    if ($Profile.ContainsKey('NestedVirt') -and $null -ne $Profile['NestedVirt']) {
        $nestedVirt = [bool]$Profile['NestedVirt']
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
    $storageRoot = Get-SandboxStorageRoot -Name $Name
    $systemDisk  = Join-Path $storageRoot ("{0}-system.vhdx" -f $Name)
    $comPipe     = "\\.\pipe\{0}-com1" -f $Name

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
        $null = & $Backend.NewVM @{ Name = $Name; Generation = $generation; MemoryStartupBytes = $memoryBytes; Path = $storageRoot; NoVHD = $true }
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

        # --- 7. network: VM-tier switch + NIC -----------------------------
        # v1 scope is Tier 0/1. Tier 1 (Substrate=HyperV-Gen2, Network=Internal+Allowlist)
        # gets an Internal vSwitch + a connected NIC. (Tier 0 is a container substrate handled
        # outside Hyper-V; a future no-NIC VM tier would skip this block.) Create the switch
        # FIRST (the backend rejects connecting a NIC to a non-existent switch — real-HV parity).
        if ($Profile['Substrate'] -eq 'HyperV-Gen2') {
            $switchType = 'Internal'
            $switchName = "{0}-int" -f $Name
            if ($null -eq (& $Backend.GetSwitch @{ Name = $switchName })) {
                $null = & $Backend.NewSwitch @{ Name = $switchName; SwitchType = $switchType }
                $createdSwitches.Add($switchName)   # only track switches WE created (don't reap a pre-existing one)
            }
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
            -DiskPath           $systemDisk `
            -DiskPaths          @($systemDisk) `
            -CreatedDisks       @($createdDisks) `
            -MemoryStartupBytes $memoryBytes `
            -ProcessorCount     $cpuCount `
            -NestedVirt         $nestedVirt `
            -State              $state `
            -AutomaticCheckpointsEnabled $autoCheckpoints

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

        # Remove every switch THIS provision created (a pre-existing switch was NOT tracked,
        # so a shared switch is never reaped). RemoveSwitch is idempotent + best-effort.
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
.PARAMETER Name
    The VM name.
.PARAMETER DeleteDisks
    Also delete the VHD files (the explicit cleanup step RemoveVM does NOT do).
.PARAMETER Descriptor
    (Optional) The New-SandboxVM descriptor; its CreatedDisks list is the authoritative
    set of disks to delete under -DeleteDisks.
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

    $vm = & $Backend.GetVM @{ Name = $Name }
    if ($null -eq $vm) {
        # Idempotent no-op. If asked to delete disks for a VM that no longer exists, still
        # honor the descriptor's disk list (the VM may already be gone but disks may linger).
        Write-Warning "Remove-Sandbox: no VM named '$Name' exists; nothing to remove (no-op)."
        if ($DeleteDisks -and $null -ne $Descriptor) {
            Remove-SandboxDisks -Disks @($Descriptor.CreatedDisks) -Backend $Backend
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

    # Unregister the VM. This LEAVES the VHDX files (per the backend contract).
    $null = & $Backend.RemoveVM @{ Name = $Name; Force = $true }

    # Explicit, opt-in disk deletion — the step RemoveVM intentionally does NOT do.
    if ($DeleteDisks -and @($disksToDelete).Count -gt 0) {
        Remove-SandboxDisks -Disks @($disksToDelete) -Backend $Backend
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
