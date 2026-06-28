<#
.SYNOPSIS
    Voidseal — Importer + Sealer + Assert-Sealed.

.DESCRIPTION
    The import-then-seal ritual + the host-verified seal gate — the security heart of the
    deployer. EVERYTHING touches Hyper-V through the backend abstraction
    (HyperVBackend.ps1); this file NEVER calls a raw `Set-VM*` / `*VMDvdDrive` /
    `*VMHardDiskDrive` / `*VMNetworkAdapter` / `*VMIntegrationService` cmdlet. That single
    seam is what lets the whole thing unit-test against the in-memory fake.

    Dot-source this file (after HyperVBackend.ps1 + ProfileLoader.ps1 + Provisioner.ps1) to get:

        Import-SandboxAsset   -Descriptor <d> -Source <path> -As <Iso|TransferVhd> [-ExpectedSha256] [-Backend]
        Dismount-SandboxAsset -Descriptor <d> -Path <vhdx> [-Backend]      # scripted transfer-VHD detach
        Test-AssetIntegrity   -Path <path> -ExpectedSha256 <hex>           # host-side hash verify
        Lock-Sandbox          -Descriptor <d> [-Backend]                   # cut to the tier's isolation
        Assert-Sealed         -Descriptor <d> [-Backend]                   # host-verified seal GATE

    INJECTION: every backend-touching function takes `-Backend <hashtable>` defaulting to
    `(New-RealHyperVBackend)`. Production passes nothing (real Hyper-V). Tests pass
    `-Backend (New-FakeHyperVBackend)` and assert against the fake's in-memory state.

    THE ONE-WAY IMPORT:
      * ISO          — read-only into the guest (`SetDvdDrive`); inherently one-way; hashed
                       pre-attach. The Sealer detaches it (it is import-only).
      * TransferVhd  — `AddHardDiskDrive` the transfer disk; the caller copies inside the guest;
                       then a SCRIPTED `RemoveHardDiskDrive` DETACH. Transfer media is NOT
                       inherently one-way — the detach MUST be part of the seal. Detach removes
                       the attachment only; the VHDX FILE stays on disk (it is not the boot disk).

    THE SEAL (Lock-Sandbox; "Re-connection prevention"):
      Lock-Sandbox handles VM-CONFIG isolation:
        1. detach every import-only medium (ISO DVD + transfer VHDs recorded on the descriptor),
        2. for a no-NIC tier (Tier >= 2) `RemoveNetworkAdapter` (remove, not disconnect),
        3. turn OFF every host<->guest channel (clipboard / shares / guest-services /
           enhanced-session) via the backend's SetHostChannel,
        4. mark the descriptor State='Sealed'.
      It does NOT power the VM on (the seal runs before first boot) and it does NOT touch the
      egress allowlist — Tier-1 net-restriction is the in-guest nftables/allowlist concern,
      not this function's job. Tier-1 keeps its NIC; Tier >= 2 has it removed.

    THE GATE (Assert-Sealed; SCHEMA.md invariant 6 — the runtime pre-seal gate):
      Verifies the seal FROM THE HOST via backend Get* calls — the guest's own view is NEVER
      trusted. FAILS CLOSED:
        * preflight TestAvailable: if the host can't be queried, REFUSE to certify (an inability
          to check is never a pass).
        * the VM must exist (a missing VM cannot be certified).
        * Tier >= 2: GetNetworkAdapter MUST be empty (no NIC / live egress route).
        * ANY tier: no import DVD attached; no transfer/import medium recorded on the descriptor
          still attached.
        * a secret-SHAPED attached disk path (Test-IsSecretPath) is REFUSED at any tier.
        * a Tier >= 2 attached disk that is NOT the recorded system disk is treated as a residual
          secret/transfer volume and REFUSED (the STRUCTURAL, authoritative no-net guarantee —
          invariant 6's "attached secret volume", Tier-3 scope; does not depend on the path being
          secret-shaped or recorded as import media).
        * ANY tier (BEST-EFFORT backstop): an attached disk that is NOT an EXPECTED disk (the
          recorded system disk + the descriptor's CreatedDisks/DiskPaths) is refused as a residual.
          This extends residual-disk detection to Tier-1 too, but is only as complete as the
          descriptor's recorded disk set — at Tier-1 it is a best-effort backstop layered on the
          name-shape (Test-IsSecretPath) + descriptor import/transfer-denylist checks above; the
          STRUCTURAL no-net guarantee remains the Tier>=2 rule.
        * all four host channels MUST be off.
        * POSITIVE COM1-liveness (serial-managed guests only): for a Com1Serial / ComPipePath-bearing
          descriptor, COM1 MUST still be attached after sealing — the seal must never collaterally
          sever the Runner's serial command channel (the only no-NIC management path for a Linux guest).
          A non-serial / container-ish tier is skipped.
      Throws a clear, named message on the first violation; returns $true only when every check
      passes. A deliberately-not-sealed VM MUST fail.

    BACKEND ADDENDA:
      * SetHostChannel @{ VMName; Channel; Enabled } and GetHostChannels @{ VMName } — the seam the
        seal turns OFF and the gate host-verifies, so the Sealer never reaches for a raw Set-VM /
        *-VMIntegrationService cmdlet.

    LINUX-GUEST SEAL MODEL (the channels split into TWO classes):
      * GuestServices = the ONE REAL autonomous host<->guest data channel (Copy-VMFile / 'Guest
        Service Interface'). The real backend maps it to Enable/Disable-VMIntegrationService and its
        GET reads the real .Enabled FAIL-CLOSED. Assert-Sealed hard-fails if it is ON. The seal+gate
        treat this as the authoritative channel and DO NOT weaken it.
      * Clipboard / Shares / EnhancedSession = ESM facets, OFF BY CONSTRUCTION for a Linux guest.
        There is no per-VM "ESM off" toggle and ESM clipboard/drive-redirection needs Windows-guest
        components a stock Linux cloud image structurally lacks (and is interactive-only, never an
        autonomous exfil path). The seal still closes the interactive KVM surface best-effort via
        Disable-VMConsoleSupport (belt-and-braces; confirmed not to break COM1 serial); the GET
        reports them off (it does NOT read the WMI ConsoleMode — a live diagnostic proved that
        property never flips with Disable-VMConsoleSupport, so the old ConsoleMode-keyed read kept the
        facets ON forever and the seal could never certify a real Linux VM). The fake records each
        channel independently and so mirrors this contract (disable -> reads off). See HyperVBackend.ps1.
#>

Set-StrictMode -Version Latest

# --------------------------------------------------------------------------
# Shared constants
# --------------------------------------------------------------------------

# The host<->guest channels the seal turns OFF and the gate host-verifies. Mirrors
# $script:HostChannelNames in HyperVBackend.ps1 and the tier-profile HostChannels keys
# (SCHEMA.md). Re-declared here so this file is usable when dot-sourced standalone.
$script:SealHostChannels = @('Clipboard', 'Shares', 'GuestServices', 'EnhancedSession')

# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Read a field off a sandbox descriptor (PSCustomObject) with a default. StrictMode-safe.
.DESCRIPTION
    The Sealer adds fields to the descriptor as-we-go (ImportedMedia, TransferDisks). A descriptor
    built by New-SandboxDescriptor will not have them yet, so reads must tolerate
    absence. Branches on hashtable vs PSObject like the Provisioner's Get-VMField.
#>
function Get-DescriptorField {
    [CmdletBinding()]
    param([AllowNull()] $Descriptor, [Parameter(Mandatory)] [string] $Name, $Default = $null)
    if ($null -eq $Descriptor) { return $Default }
    if ($Descriptor -is [System.Collections.IDictionary]) {
        if ($Descriptor.Contains($Name) -and $null -ne $Descriptor[$Name]) { return $Descriptor[$Name] }
        return $Default
    }
    $prop = $Descriptor.PSObject.Properties[$Name]
    if ($null -ne $prop -and $null -ne $prop.Value) { return $prop.Value }
    return $Default
}

<#
.SYNOPSIS
    Append a value to a descriptor list-field (creating the NoteProperty if absent), de-duped.
.DESCRIPTION
    Tracks import media on the descriptor so the Sealer knows what to detach. The descriptor
    is a PSCustomObject; a missing field is added via Add-Member as a [string[]].
#>
function Add-DescriptorListItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Descriptor,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Value
    )
    $current = @(Get-DescriptorField -Descriptor $Descriptor -Name $Name -Default @())
    if ($current -notcontains $Value) { $current = @($current) + @($Value) }

    if ($Descriptor -is [System.Collections.IDictionary]) {
        $Descriptor[$Name] = @($current)
        return
    }
    if ($null -ne $Descriptor.PSObject.Properties[$Name]) {
        $Descriptor.$Name = @($current)
    }
    else {
        Add-Member -InputObject $Descriptor -MemberType NoteProperty -Name $Name -Value @($current) -Force
    }
}

<#
.SYNOPSIS
    Set a descriptor scalar field (creating the NoteProperty if absent).
#>
function Set-DescriptorField {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Descriptor, [Parameter(Mandatory)] [string] $Name, $Value)
    if ($Descriptor -is [System.Collections.IDictionary]) { $Descriptor[$Name] = $Value; return }
    if ($null -ne $Descriptor.PSObject.Properties[$Name]) { $Descriptor.$Name = $Value }
    else { Add-Member -InputObject $Descriptor -MemberType NoteProperty -Name $Name -Value $Value -Force }
}

<#
.SYNOPSIS
    Canonicalize a path STRING for form-insensitive comparison (Hardening 2). Pure-string; safe.
.DESCRIPTION
    The expected-disk set vs. the host-truth attached paths are compared OrdinalIgnoreCase. Two
    forms of the SAME path (trailing slash, relative '.'/'..', a '\\?\' prefix, an 8.3 short name)
    would otherwise exact-string-compare as DIFFERENT and a legitimately-recorded data disk under a
    differing form would be wrongly REFUSED — an AVAILABILITY bug (it fails CLOSED, so it is not a
    security hole, but it spuriously rejects a valid seal). We canonicalize BOTH sides before the
    set-membership test so equivalent forms match.

    Uses ONLY [System.IO.Path]::GetFullPath — a PURE-STRING resolver of relative segments / '.' /
    '..' / trailing separators that does NOT require the file to EXIST (unlike Resolve-Path, which
    throws on a non-existent path, or GetFullPath's filesystem-touching cousins). Then trims a single
    trailing slash so 'C:\x\' and 'C:\x' unify. Wrapped in try/catch: if GetFullPath ever throws
    (e.g. an invalid-character path), we FALL BACK to the original string — normalization must NEVER
    crash the security gate. A blank/whitespace input is returned unchanged.

    This does NOT weaken the gate: an UNRECORDED disk's canonical form is still not in the expected
    set, so it is still refused (the canonical-vs-canonical compare is exactly as strict as the old
    exact compare for genuinely-different paths — it only unifies forms that resolve to the SAME path).
#>
function Get-CanonicalDiskPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    try {
        # Pure-string full-path resolution (no existence requirement); then drop a trailing separator.
        $full = [System.IO.Path]::GetFullPath($Path)
        return $full.TrimEnd('\', '/')
    }
    catch {
        # Never let canonicalization crash the gate — fall back to the original string.
        return $Path
    }
}

<#
.SYNOPSIS
    Normalize the backend's VM HardDrives field to a flat [string[]] of disk paths.
.DESCRIPTION
    The FAKE records HardDrives as path STRINGS; the REAL backend as HardDiskDrive objects
    with a .Path. This accessor handles both (mirrors Remove-Sandbox's normalization).
#>
function Get-AttachedDiskPath {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] $VM)
    $hd = Get-VMField -VM $VM -Name 'HardDrives' -Default @()
    return @($hd | ForEach-Object {
        if ($_ -is [string]) { $_ }
        elseif ($null -ne $_ -and $null -ne $_.PSObject.Properties['Path']) { [string]$_.Path }
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

<#
.SYNOPSIS
    Read the VM's attached DVD/ISO media paths from HOST TRUTH via the backend's GetDvdDrives.
.DESCRIPTION
    This MUST NOT read the DVD off the GetVM object's `DvdDrive`
    field. A real Get-VM object has NO DvdDrive property — real Hyper-V exposes DVD state as the
    DVDDrives COLLECTION, read via Get-VMDvdDrive (wrapped by the backend's GetDvdDrives). The old
    `Get-VMField -Name DvdDrive` read returned $null on real Hyper-V (property absent), so the seal
    never detached the seed DVD and the gate never saw a still-attached import DVD — a fake≠real
    hole on the security seam (the fake carried the scalar the code looked for). Reading through
    the backend's GetDvdDrives is the host-truth authority on BOTH backends.

    Returns ALL attached DVD media paths (a [string[]]; empty when none). Callers asking "is any
    import DVD attached" check `.Count` / `@(...)`; the single-import-slot callers take the first.
.PARAMETER VMName
    The VM whose DVD media to read.
.PARAMETER Backend
    The Hyper-V backend — DVD state is read through its GetDvdDrives (host truth).
#>
function Get-AttachedDvdPath {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $VMName,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    # Read the collection DIRECTLY (the backend's GetDvdDrives preserves array semantics via its
    # unary-comma return); never re-wrap in @() that would re-unroll a single element. Normalize
    # each entry to a non-blank string path.
    $dvds = & $Backend.GetDvdDrives @{ VMName = $VMName }
    return @($dvds | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

# --------------------------------------------------------------------------
# Public: Test-AssetIntegrity (host-side hash verification of import inputs)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Verify a host-side asset file's SHA-256 against an expected digest. Throws on mismatch.
.DESCRIPTION
    Host-side input verification for the import ritual (e.g. the ISO build inputs, a transfer
    VHDX staged on the host). The IN-GUEST verify (after transfer, with pre-provisioned pinned
    tools + publisher keys) is the guest's job and is NOT this function — here we only confirm
    the host-side input is what we expect before we attach it. Fails closed: a missing file or
    a digest mismatch THROWS; a match returns $true. Comparison is case-insensitive hex.
.PARAMETER Path
    The host-side file to hash.
.PARAMETER ExpectedSha256
    The expected SHA-256 hex digest (case-insensitive).
#>
function Test-AssetIntegrity {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ExpectedSha256
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        throw "Test-AssetIntegrity: -ExpectedSha256 is blank; cannot verify '$Path' against nothing."
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Test-AssetIntegrity: asset not found at '$Path' (cannot verify a missing file — fail closed)."
    }

    # Get-FileHash returns an upper-case hex digest. Compare case-insensitively so a caller's
    # lower-case expected digest still verifies.
    $actual   = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    $expected = $ExpectedSha256.Trim()
    if ($actual.ToUpperInvariant() -ne $expected.ToUpperInvariant()) {
        throw ("Test-AssetIntegrity: SHA-256 mismatch for '$Path'. Expected '$expected' but got '$actual'. " +
               "The asset is not what was expected — refusing (fail closed).")
    }
    return $true
}

# --------------------------------------------------------------------------
# Public: Import-SandboxAsset (one-way asset injection on the PRE-seal state)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Inject an asset into a still-networked, pre-seal sandbox VM as a read-only ISO or a
    transfer VHD. Records the medium on the descriptor so Lock-Sandbox detaches it.
.DESCRIPTION
    Import happens BEFORE the seal (the VM is still on its provisioning switch). Two modes:
      -As Iso          attach a read-only ISO via SetDvdDrive (inherently one-way to the guest).
      -As TransferVhd  AddHardDiskDrive a transfer VHD (the caller copies inside the guest); the
                       VHDX must already exist on the host. The detach is NOT done here — it is a
                       scripted seal step (Dismount-SandboxAsset, also run by Lock-Sandbox).
    When -ExpectedSha256 is supplied, the host-side source is hash-verified BEFORE attaching
    (a mismatch refuses the import and attaches nothing). The asset path is recorded on the
    descriptor's ImportedMedia (and TransferDisks for transfer VHDs) so the seal knows what to
    detach and the gate knows what must be gone.
.PARAMETER Descriptor
    The New-SandboxVM descriptor (consumed + updated).
.PARAMETER Source
    Host-side path to the ISO or transfer VHDX.
.PARAMETER As
    'Iso' (read-only DVD) or 'TransferVhd' (attached hard disk, scripted detach at seal).
.PARAMETER ExpectedSha256
    (Optional) verify the host-side source hash before attaching.
.PARAMETER Backend
    The Hyper-V backend. Defaults to the real one; tests inject the fake.
#>
function Import-SandboxAsset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Descriptor,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Source,
        [Parameter(Mandatory)] [ValidateSet('Iso', 'TransferVhd')] [string] $As,
        [string] $ExpectedSha256,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    if ($null -eq $Descriptor) {
        throw "Import-SandboxAsset: -Descriptor is null. Pass a New-SandboxVM descriptor."
    }
    $vmName = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'Name')
    if ([string]::IsNullOrWhiteSpace($vmName)) {
        throw "Import-SandboxAsset: descriptor has no VM Name."
    }
    if ([string]::IsNullOrWhiteSpace($Source)) {
        throw "Import-SandboxAsset: -Source is blank."
    }

    # Optional host-side integrity gate (refuse to attach a tampered/wrong asset).
    if ($PSBoundParameters.ContainsKey('ExpectedSha256') -and -not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        [void](Test-AssetIntegrity -Path $Source -ExpectedSha256 $ExpectedSha256)
    }

    switch ($As) {
        'Iso' {
            if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
                throw "Import-SandboxAsset: ISO source not found at '$Source' (fail closed before attaching)."
            }
            # Effect-only backend call: suppress with `$null = ...` so the REAL backend's stream
            # emission (real Set-VMDvdDrive / Add-VMHardDiskDrive return a record) can't leak into
            # this function's output — the output-stream-pollution class of bug.
            $null = & $Backend.SetDvdDrive @{ VMName = $vmName; Path = $Source }
            Add-DescriptorListItem -Descriptor $Descriptor -Name 'ImportedMedia' -Value $Source
        }
        'TransferVhd' {
            # The fake (and real Add-VMHardDiskDrive) require the VHDX to exist; a missing
            # transfer disk is a clear caller error surfaced by the backend. We attach only;
            # the caller copies data inside the guest, then the seal detaches (scripted).
            $null = & $Backend.AddHardDiskDrive @{ VMName = $vmName; Path = $Source }
            Add-DescriptorListItem -Descriptor $Descriptor -Name 'ImportedMedia' -Value $Source
            Add-DescriptorListItem -Descriptor $Descriptor -Name 'TransferDisks' -Value $Source
        }
    }
}

# --------------------------------------------------------------------------
# Public: Add-SandboxSeed (attach the cloud-init NoCloud CIDATA seed ISO)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Attach the cloud-init NoCloud SEED ISO (a CIDATA-labelled .iso) as a READ-ONLY DVD so the guest
    configures itself on FIRST BOOT (serial-getty autologin on ttyS0 = the Runner's command channel;
    run-user; packages). Records it on the descriptor so the seal ejects it + the gate verifies it.
.DESCRIPTION
    The SeedIso is the BOOT-CONFIG disc — distinct from StageAssets (workload payload). It must be
    present at the VERY FIRST boot (before the seal powers nothing on — the seal runs pre-boot — so it
    is attached at provision/STAGE, then the Runner powers the sealed VM on with the seed having been
    consumed by cloud-init on that first boot). It is IMPORT-ONLY: it rides the same one-way ISO import
    path as Import-SandboxAsset -As Iso, so it lands on the descriptor's ImportedMedia and the existing
    seal (Lock-Sandbox detaches the live DVD) + gate (Assert-Sealed refuses any attached import DVD)
    treat it correctly — the seed is EJECTED as part of the seal and a STILL-attached seed post-seal
    fails the gate. We additionally record the path under the descriptor's SeedIso field for audit /
    so the seal+gate know the seed by name.

    DVD-SLOT NOTE: the backend models a SINGLE DVD slot (the VM record's DvdDrive scalar). The seed
    is the disc in that slot at first boot. A StageAssets ISO that must COEXIST with the seed cannot
    share the one DVD slot and must be a transfer-VHD for a real coexistence run — the orchestrator
    gives the SEED the boot DVD slot (attaching it AFTER any StageAssets ISO so the seed occupies the
    slot at boot) and warns when both ISOs are present.

    A $null / blank -SeedIso is a documented NO-OP (so the orchestrator can call this unconditionally;
    a profile without a SeedIso changes nothing). Optional -ExpectedSha256 hash-verifies the host-side
    seed before attach (a mismatch refuses + attaches nothing) — same gate as Import-SandboxAsset.
.PARAMETER Descriptor
    The New-SandboxVM descriptor (consumed + updated: ImportedMedia + SeedIso).
.PARAMETER SeedIso
    Host-side path to the CIDATA NoCloud seed .iso. $null/blank = no-op.
.PARAMETER ExpectedSha256
    (Optional) verify the host-side seed hash before attaching.
.PARAMETER Backend
    The Hyper-V backend. Defaults to the real one; tests inject the fake.
#>
function Add-SandboxSeed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Descriptor,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $SeedIso,
        [string] $ExpectedSha256,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    if ($null -eq $Descriptor) {
        throw "Add-SandboxSeed: -Descriptor is null. Pass a New-SandboxVM descriptor."
    }
    # A blank/absent seed is a deliberate NO-OP — a profile without a SeedIso changes nothing.
    if ([string]::IsNullOrWhiteSpace($SeedIso)) { return }

    $importArgs = @{ Descriptor = $Descriptor; Source = $SeedIso; As = 'Iso'; Backend = $Backend }
    if ($PSBoundParameters.ContainsKey('ExpectedSha256') -and -not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        $importArgs.ExpectedSha256 = $ExpectedSha256
    }
    # Reuse the one-way ISO import: attaches read-only via SetDvdDrive + records on ImportedMedia so
    # the existing seal detaches it and Assert-Sealed verifies no import DVD remains. The seed is the
    # boot-config disc in the single DVD slot at first boot.
    Import-SandboxAsset @importArgs

    # Record the seed by name on the descriptor (audit + the seal/gate know it as the seed).
    Set-DescriptorField -Descriptor $Descriptor -Name 'SeedIso' -Value $SeedIso
}

# --------------------------------------------------------------------------
# Public: Dismount-SandboxAsset (scripted transfer-VHD detach — a seal step)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Detach a transfer VHD from a sandbox VM (the explicit, scripted detach the seal requires).
.DESCRIPTION
    Transfer media is NOT inherently one-way: the guest can mount it read-write. The detach
    (`RemoveHardDiskDrive`) MUST be enforced as part of the seal. This removes the ATTACHMENT
    only — the VHDX file is left on disk (it carried data INTO the guest; deleting it is a
    separate, optional cleanup, and it is never the system disk). Idempotent: detaching a disk
    that is not attached is a no-op on the fake backend.
.PARAMETER Descriptor
    The sandbox descriptor (its Name identifies the VM; TransferDisks is updated).
.PARAMETER Path
    The transfer VHDX path to detach.
.PARAMETER Backend
    The Hyper-V backend.
#>
function Dismount-SandboxAsset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Descriptor,
        [Parameter(Mandatory)] [string] $Path,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    if ($null -eq $Descriptor) { throw "Dismount-SandboxAsset: -Descriptor is null." }
    $vmName = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'Name')
    if ([string]::IsNullOrWhiteSpace($vmName)) { throw "Dismount-SandboxAsset: descriptor has no VM Name." }

    # Effect-only: suppress so the real backend's emission can't leak as this function's output.
    $null = & $Backend.RemoveHardDiskDrive @{ VMName = $vmName; Path = $Path }

    # Forget it as a transfer disk (it is now detached). Leave ImportedMedia history intact for audit.
    $remaining = @(Get-DescriptorField -Descriptor $Descriptor -Name 'TransferDisks' -Default @() |
                   Where-Object { $_ -ne $Path })
    Set-DescriptorField -Descriptor $Descriptor -Name 'TransferDisks' -Value @($remaining)
}

# --------------------------------------------------------------------------
# Public: Lock-Sandbox (the Sealer — cut to the tier's required isolation)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Seal a sandbox VM to its tier's required isolation: detach import media, (Tier>=2) remove
    the NIC, turn off all host channels, and mark the descriptor Sealed. Runs before first boot.
.DESCRIPTION
    Handles VM-CONFIG isolation only ("Re-connection prevention"):
      1. detach every import-only ISO/DVD (the imported media recorded on the descriptor, plus
         a defensive detach of whatever DVD the host actually shows attached),
      2. detach every transfer VHD recorded on the descriptor (scripted — NOT inherently one-way),
      3. for a no-NIC tier (Tier >= 2): RemoveNetworkAdapter (remove, not disconnect),
      4. turn OFF every host<->guest channel (clipboard / shares / guest-services / enhanced-session),
      5. set the descriptor State = 'Sealed'.
    It does NOT power the VM on, and does NOT manage the egress allowlist — Tier-1 net-restriction
    is the in-guest nftables/allowlist concern, not this function's job. Tier-1 KEEPS its
    NIC; only Tier >= 2 is no-NIC. Generic over the tier so a future no-NIC profile seals correctly.
.PARAMETER Descriptor
    The New-SandboxVM descriptor (consumed + updated; its Tier drives the NIC decision).
.PARAMETER Backend
    The Hyper-V backend.
#>
function Lock-Sandbox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Descriptor,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    if ($null -eq $Descriptor) {
        throw "Lock-Sandbox: -Descriptor is null. Pass a New-SandboxVM descriptor."
    }
    $vmName = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'Name')
    if ([string]::IsNullOrWhiteSpace($vmName)) {
        throw "Lock-Sandbox: descriptor has no VM Name."
    }
    $tier = [int](Get-DescriptorField -Descriptor $Descriptor -Name 'Tier' -Default 0)

    # Preflight: the seal mutates VM config; if the host can't be reached, fail closed BEFORE
    # claiming a half-seal. (Mirrors the Provisioner's preflight discipline.)
    $probe = & $Backend.TestAvailable @{}
    if (-not $probe.Available) {
        $reason = if ($probe.ContainsKey('Reason') -and $probe.Reason) { $probe.Reason } else { '(no reason reported)' }
        throw "Lock-Sandbox: cannot seal '$vmName' — Hyper-V unavailable or insufficient privilege. Backend reports: $reason"
    }

    # --- 1. detach the system's currently-attached import DVD (if any) ----
    # This ejects EITHER a StageAssets import ISO OR the cloud-init NoCloud SEED ISO — both ride
    # the single DVD slot as import-only media; the seed is the boot-config disc consumed by cloud-init
    # on the guest's first boot and is ejected here as part of the seal (Assert-Sealed then verifies no
    # import DVD remains, so a still-attached seed fails the gate — the seed opens no hole).
    #
    # The attached-DVD read MUST come from HOST TRUTH via the backend's
    # GetDvdDrives — NOT off the GetVM object's `DvdDrive` field. A real Get-VM object has no DvdDrive
    # property (DVD state is the DVDDrives collection / Get-VMDvdDrive); the old scalar read returned
    # $null on real Hyper-V, so RemoveDvdDrive was NEVER called and the seed survived the seal. We now
    # (a) read host truth and RemoveDvdDrive for EACH attached DVD, AND (b) belt-and-braces detach the
    # seed/import media RECORDED on the descriptor (ImportedMedia) regardless of the read — RemoveDvd-
    # Drive is idempotent on both backends — so the detach does not depend solely on the host read.
    # (The host-truth read remains the gate's authority in Assert-Sealed.)
    $vm = & $Backend.GetVM @{ Name = $vmName }
    if ($null -eq $vm) {
        throw "Lock-Sandbox: no VM named '$vmName' on the backend; nothing to seal."
    }
    $attachedDvds = @(Get-AttachedDvdPath -VMName $vmName -Backend $Backend)
    # Belt-and-braces: the import media this provision RECORDED. RemoveDvdDrive clears the (single)
    # DVD slot, so a single call detaches everything; we drive it from the union of host-truth +
    # recorded media so an unread-but-recorded seed is still ejected on every backend.
    $importedMedia = @(Get-DescriptorField -Descriptor $Descriptor -Name 'ImportedMedia' -Default @())
    # Effect-only backend calls in the seal are suppressed ($null = ...) so a REAL-backend stream
    # emission can't leak into Lock-Sandbox's output (output-stream-pollution class).
    if ($attachedDvds.Count -gt 0 -or $importedMedia.Count -gt 0) {
        $null = & $Backend.RemoveDvdDrive @{ VMName = $vmName }
    }

    # --- 2. detach every transfer VHD the import recorded (scripted detach) ----
    foreach ($disk in @(Get-DescriptorField -Descriptor $Descriptor -Name 'TransferDisks' -Default @())) {
        if ([string]::IsNullOrWhiteSpace($disk)) { continue }
        Dismount-SandboxAsset -Descriptor $Descriptor -Path $disk -Backend $Backend
    }

    # --- 3. no-NIC tiers (Tier >= 2): remove the NIC entirely -------------
    # Tier-1 is net-RESTRICTED, not no-net — its NIC stays (egress is the in-guest
    # nftables/allowlist concern, not the seal). Generic over the tier.
    if ($tier -ge 2) {
        $null = & $Backend.RemoveNetworkAdapter @{ VMName = $vmName }
    }

    # --- 4. turn OFF every host<->guest channel ---------------------------
    foreach ($channel in $script:SealHostChannels) {
        $null = & $Backend.SetHostChannel @{ VMName = $vmName; Channel = $channel; Enabled = $false }
    }

    # --- 5. record the seal on the descriptor (do NOT power on) -----------
    Set-DescriptorField -Descriptor $Descriptor -Name 'State' -Value 'Sealed'
}

# --------------------------------------------------------------------------
# Public: Assert-Sealed (THE GATE — host-verified, fail-closed)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Host-verified seal gate. Throws (refuses to certify) if a VM is not properly sealed for its
    tier; returns $true only when every host-side check passes. Implements SCHEMA.md invariant 6.
.DESCRIPTION
    The security heart of the deployer. Verifies the seal FROM THE HOST via backend Get* calls —
    the guest's own view is NEVER authoritative. FAILS CLOSED at every step:

      * preflight TestAvailable — if the host can't be queried, REFUSE (inability to check is
        never a pass).
      * the VM must exist on the backend (a missing VM cannot be certified).
      * Tier >= 2: GetNetworkAdapter MUST be empty (no NIC = no live egress route). A Tier-1 VM
        legitimately keeps its NIC, so the NIC check is tier-gated; the media + channel checks
        apply to every tier.
      * no import DVD/ISO attached (a live read-only-but-present host<->guest medium).
      * no transfer/import VHD recorded on the descriptor still attached.
      * a secret-SHAPED attached disk path (Test-IsSecretPath) is refused at ANY tier.
      * Tier >= 2 STRUCTURAL invariant-6 check: the only hard disks that may be attached are the
        recorded system disk and the descriptor's RECORDED workload data disks (InputDiskPath/
        OutputDiskPath, plus the RC6 CIDATA SeedDiskPath — all attached before the seal, expected to
        remain); ANY other attached volume is treated as a residual secret/transfer volume and refused
        (catches an attached secret volume even if its path isn't secret-shaped). An UNRECORDED data disk is still refused, so this is
        the AUTHORITATIVE no-net guarantee (Tier-3 scope per SCHEMA invariant-6).
      * ANY tier BEST-EFFORT backstop: an attached disk that is NOT an EXPECTED disk (recorded
        system disk + the descriptor's CreatedDisks/DiskPaths + the recorded data disks) is
        refused as a residual. Extends residual-disk detection to Tier-1 (where the strict structural
        rule above does not run), but is only as complete as the descriptor's recorded disk set — so
        at Tier-1 it layers on the name-shape + import/transfer-denylist checks rather than replacing
        the structural rule. A RECORDED data disk is expected; an UNRECORDED attached disk is refused.
      * every host channel (clipboard / shares / guest-services / enhanced-session) MUST be off.
      * POSITIVE COM1-liveness (serial-managed guests only): COM1 MUST still be attached after sealing
        so the seal cannot have severed the Runner's serial command channel. Read from host truth via
        the backend's GetComPort. Skipped for a non-serial tier (no ComPipePath, not Com1Serial).

    Throws a clear, named message on the FIRST violation. Returns $true when sealed.
.PARAMETER Descriptor
    The sandbox descriptor (Name, Tier, DiskPath, and the import-media lists drive the checks).
.PARAMETER Backend
    The Hyper-V backend.
#>
function Assert-Sealed {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Descriptor,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    if ($null -eq $Descriptor) {
        throw "Assert-Sealed: -Descriptor is null. Pass a New-SandboxVM descriptor."
    }
    $vmName = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'Name')
    if ([string]::IsNullOrWhiteSpace($vmName)) {
        throw "Assert-Sealed: descriptor has no VM Name; cannot verify a seal."
    }
    $tier = [int](Get-DescriptorField -Descriptor $Descriptor -Name 'Tier' -Default 0)
    # A processor profile carries Network='None' on the descriptor. It is structurally
    # no-NIC — the same guarantee as Tier>=2 — even when the tier integer is 0 or 1.
    # Read it once and propagate to the NIC check and error messaging below.
    $network     = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'Network')
    $isProcessor = ($network -eq 'None')

    # --- FAIL CLOSED: if the host can't be queried, do NOT certify --------
    # An inability to perform the host-side check is never a pass — that is the whole point of
    # a host-verified gate. TestAvailable never throws; we read its verdict.
    $probe = & $Backend.TestAvailable @{}
    if (-not $probe.Available) {
        $reason = if ($probe.ContainsKey('Reason') -and $probe.Reason) { $probe.Reason } else { '(no reason reported)' }
        throw ("Assert-Sealed: REFUSING to certify '$vmName' SEALED — the host cannot verify the seal " +
               "(Hyper-V unavailable / insufficient privilege). Fail closed. Backend reports: $reason")
    }

    # --- the VM must exist (a missing VM cannot be certified) -------------
    $vm = & $Backend.GetVM @{ Name = $vmName }
    if ($null -eq $vm) {
        throw "Assert-Sealed: REFUSING to certify — no VM named '$vmName' exists on the host. Fail closed."
    }

    # --- Tier >= 2 OR processor (Network='None'): NO NIC (host-verified; guest view irrelevant) ---
    # A processor (Network='None') is structurally no-NIC at any tier — exactly the same
    # guarantee as Tier>=2. We reuse the same GetNetworkAdapter call (D2: no new method)
    # and branch the error message so the reason is unambiguous in the operator log.
    # Read the collection DIRECTLY (the backend preserves array semantics; never re-wrap).
    if ($tier -ge 2 -or $isProcessor) {
        $nics = & $Backend.GetNetworkAdapter @{ VMName = $vmName }
        if ($nics.Count -ne 0) {
            if ($isProcessor -and $tier -lt 2) {
                # Processor case: the no-NIC guarantee comes from Network='None', not the tier.
                throw ("Assert-Sealed: REFUSING to certify processor VM '$vmName' SEALED — $($nics.Count) " +
                       "network adapter(s) still attached. A processor (Network='None') MUST have NO NIC " +
                       "(structurally no-net even at Tier-$tier). Fail closed.")
            }
            throw ("Assert-Sealed: REFUSING to certify Tier-$tier VM '$vmName' SEALED — $($nics.Count) network " +
                   "adapter(s) still attached. A Tier>=2 VM MUST have NO NIC (no live egress route). Fail closed.")
        }
    }

    # --- NO import DVD/ISO attached (any tier) ----------------------------
    # Read DVD state from HOST TRUTH via the backend's GetDvdDrives,
    # NOT off the GetVM object (a real Get-VM object has no DvdDrive property — the old scalar read
    # returned $null on real Hyper-V, so a still-attached seed/import DVD PASSED the gate). Fail if
    # ANY DVD media is still attached.
    $dvds = @(Get-AttachedDvdPath -VMName $vmName -Backend $Backend)
    if ($dvds.Count -gt 0) {
        throw ("Assert-Sealed: REFUSING to certify '$vmName' SEALED — an import DVD/ISO is still attached " +
               "('$($dvds -join ''', ''')'). Import-only media must be detached as part of the seal. Fail closed.")
    }

    # --- attached-disk checks --------------------------------------------
    $attached    = @(Get-AttachedDiskPath -VM $vm)
    $systemDisk  = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'DiskPath')
    $transferSet = @(Get-DescriptorField -Descriptor $Descriptor -Name 'TransferDisks' -Default @())
    $importSet   = @(Get-DescriptorField -Descriptor $Descriptor -Name 'ImportedMedia' -Default @())

    # The set of disks the descriptor records as LEGITIMATELY persistent (i.e. expected to remain
    # attached through the seal): the system disk + every disk this provision CREATED + every disk
    # recorded as attached at provision time. Used by the ALL-TIER backend-truth backstop (d):
    # any ACTUALLY-attached disk that is NOT one of these is a residual (a leftover transfer/secret
    # or otherwise unexpected volume). Compared case-insensitively — Windows paths are case-folding,
    # so a case-variant residual must not bypass the check. (Import/transfer media are intentionally
    # NOT "expected": they must be detached by the seal, and a still-attached one is caught by (a).)
    $createdDisks = @(Get-DescriptorField -Descriptor $Descriptor -Name 'CreatedDisks' -Default @())
    $diskPaths    = @(Get-DescriptorField -Descriptor $Descriptor -Name 'DiskPaths'    -Default @())
    # The workload INPUT/OUTPUT data disks are attached to the VM BEFORE the seal and
    # are recorded on the descriptor (InputDiskPath/OutputDiskPath, default $null). A RECORDED data
    # disk is EXPECTED to remain attached through the seal — it is the deployer's own host-formatted
    # data volume, NOT a residual. Add the recorded data disks to the expected set so the all-tier
    # backstop (d) below does not refuse them. Guarded so an absent/$null field is skipped (a
    # descriptor without these fields, or one that recorded no data disk, contributes nothing — and
    # an UNRECORDED attached disk is therefore still refused). They join the SAME OrdinalIgnoreCase
    # HashSet so they are compared exactly like the system/created disks (case-folding Windows paths).
    $inputDisk  = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'InputDiskPath')
    $outputDisk = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'OutputDiskPath')
    # RC6: the disk-mode cloud-init seed rides a recorded CIDATA DATA DISK (SeedDiskPath) instead of an
    # ejected DVD — the seal ejects DVDs, so the seed would never survive to the guest's only boot. The
    # seed disk is attached BEFORE the seal and recorded on the descriptor, so it is EXPECTED to remain
    # attached through the seal exactly like INPUT/OUTPUT — NOT a residual. It joins the recorded-data-
    # disk set (Tier>=2 structural rule (c)) and the expected set (all-tier backstop (d)) below. As with
    # input/output, an UNRECORDED disk is still refused, and a secret-SHAPED SeedDiskPath is still caught
    # by the secret check (b) BEFORE these allowances — recording cannot launder a secret.
    $seedDisk   = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'SeedDiskPath')
    # Task 1.3: the processor-profile DEPS disk (DepsDiskPath) is a pre-provisioned dependency
    # payload attached BEFORE the seal and recorded on the descriptor. It is EXPECTED to remain
    # attached through the seal exactly like INPUT/OUTPUT/SeedDiskPath — NOT a residual. It joins
    # both the expected set (all-tier backstop (d)) and the recorded-data-disk set (Tier>=2
    # structural rule (c)). The secret check (b) still runs FIRST so a secret-SHAPED DepsDiskPath
    # is caught before these allowances — recording cannot launder a secret. An UNRECORDED attached
    # disk is still refused; the no-net structural guarantee is intact.
    # NOTE: Hyper-V cannot host-enforce a read-only VHDX (no -ReadOnly on Add-VMHardDiskDrive and
    # host-file-read-only is undefined), so there is NO read-only check and NO new backend method.
    # The DEPS disk is attached normally; the recorded DepsDiskPath is simply ACCEPTED (not refused
    # as a residual), exactly like INPUT/OUTPUT. (D3 correction — 2026-06-28.)
    $depsDisk   = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'DepsDiskPath')
    # HARDENING 2 (path canonicalization): the set-membership compares below (the structural rule (c)
    # and the all-tier backstop (d)) test a host-truth attached path against these recorded sets with
    # an exact OrdinalIgnoreCase string compare. A recorded path and the attached path that differ
    # only by FORM (trailing slash, relative '.'/'..', '\\?\' prefix, 8.3 short name) would compare as
    # DIFFERENT and a legitimately-recorded data disk under a differing form would be wrongly REFUSED
    # (fails CLOSED — an availability bug, not a security hole). We CANONICALIZE every expected-set
    # entry (Get-CanonicalDiskPath: pure-string GetFullPath + trailing-slash trim, try/catch fallback)
    # and canonicalize each attached path the same way before the compare, so equivalent forms match.
    # This does NOT weaken the gate: an UNRECORDED disk's canonical form is still absent from the set,
    # so it is still refused (a genuinely-different path canonicalizes to a genuinely-different string).
    $expectedDisks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in (@($systemDisk) + $createdDisks + $diskPaths + @($inputDisk) + @($outputDisk) + @($seedDisk) + @($depsDisk))) {
        if (-not [string]::IsNullOrWhiteSpace([string]$e)) { [void]$expectedDisks.Add((Get-CanonicalDiskPath ([string]$e))) }
    }
    # The recorded data disks, as a set, used by the Tier>=2 STRUCTURAL rule (c) to allow them too
    # (they are expected, not residual). Same OrdinalIgnoreCase + canonicalization as the expected set.
    # RC6: the CIDATA seed disk (SeedDiskPath) is a recorded data disk too — it must be allowed by the
    # Tier>=2 structural rule alongside INPUT/OUTPUT (an UNRECORDED disk is still refused; see (c)).
    # Task 1.3: the DEPS disk (DepsDiskPath) joins the same recorded-data-disk set for the structural
    # rule, mirroring the SeedDiskPath addition (an UNRECORDED disk is still refused by rule (c)).
    $recordedDataDisks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in (@($inputDisk) + @($outputDisk) + @($seedDisk) + @($depsDisk))) {
        if (-not [string]::IsNullOrWhiteSpace([string]$e)) { [void]$recordedDataDisks.Add((Get-CanonicalDiskPath ([string]$e))) }
    }
    # The system disk in canonical form, for the structural rule (c)'s system-disk compare.
    $systemDiskCanon = Get-CanonicalDiskPath $systemDisk

    # Fail closed if a Tier>=2 descriptor has no recorded system disk: the structural
    # "only the system disk may be attached" invariant-6 check below CANNOT run without
    # knowing which disk is legitimate, and certifying a no-net tier without that check
    # would be a fail-OPEN hole. A real New-SandboxVM descriptor always records DiskPath.
    if ($tier -ge 2 -and [string]::IsNullOrWhiteSpace($systemDisk)) {
        throw ("Assert-Sealed: REFUSING to certify Tier-$tier VM '$vmName' SEALED — the descriptor records " +
               "no system disk (DiskPath), so the 'only the system disk may be attached' check cannot be " +
               "performed. Fail closed.")
    }

    foreach ($disk in $attached) {
        if ([string]::IsNullOrWhiteSpace($disk)) { continue }

        # HARDENING 2: the host-truth attached path in CANONICAL form, for the form-insensitive
        # set-membership compares (c)/(d). Branches (a) and (b) deliberately run on the RAW $disk:
        # (a) compares against the descriptor's recorded import/transfer media (same-form lists), and
        # (b) is a name-shape match whose secret leaf is preserved by canonicalization anyway — running
        # it on the raw path keeps the original (already-correct, test-locked) behavior unchanged.
        $diskCanon = Get-CanonicalDiskPath $disk

        # (a) a transfer/import medium still attached (any tier) — must have been detached.
        if ($transferSet -contains $disk -or $importSet -contains $disk) {
            throw ("Assert-Sealed: REFUSING to certify '$vmName' SEALED — import/transfer medium '$disk' is " +
                   "still attached. Transfer media is NOT one-way; the seal MUST detach it. Fail closed.")
        }

        # (b) a SECRET-SHAPED attached volume (any tier) — invariant 6's "attached secret volume".
        # Reuses the ProfileLoader's single-source-of-truth secret-path matcher (dot-sourced).
        # IMPORTANT: this runs BEFORE the recorded-disk allowances (c)/(d), so recording a secret-
        # shaped path as InputDiskPath/OutputDiskPath CANNOT launder it past this check.
        if ((Get-Command Test-IsSecretPath -ErrorAction SilentlyContinue) -and (Test-IsSecretPath -Path $disk)) {
            throw ("Assert-Sealed: REFUSING to certify '$vmName' SEALED — a secret-shaped volume '$disk' is " +
                   "attached. No secret volume may be present in a sealed sandbox (SCHEMA invariant 6). Fail closed.")
        }

        # (c) Tier >= 2 STRUCTURAL check: the only attached disks may be the recorded system disk
        # and the descriptor's RECORDED workload data disks (InputDiskPath/OutputDiskPath + the RC6
        # CIDATA SeedDiskPath). ANY other attached volume is a residual secret/transfer disk — refuse
        # (this is the invariant-6
        # "attached secret volume" guard that does not rely on the path being secret-shaped or
        # recorded as import media). The data disks are attached before the seal and are recorded
        # on the descriptor, so they are EXPECTED here too — but an UNRECORDED disk is still refused,
        # so the no-net structural guarantee is intact (recording a data disk does not open the door
        # to arbitrary residual volumes). The recorded-data-disk set is compared OrdinalIgnoreCase,
        # matching the system-disk `-ne` (case-insensitive) comparison for case-folding Windows paths.
        # Compared in CANONICAL form (Hardening 2) so a recorded data disk under a differing-but-
        # equivalent path form is matched (and a genuinely-unrecorded disk is still refused).
        if ($tier -ge 2 -and -not [string]::IsNullOrWhiteSpace($systemDisk) -and
            $diskCanon -ne $systemDiskCanon -and -not $recordedDataDisks.Contains($diskCanon)) {
            throw ("Assert-Sealed: REFUSING to certify Tier-$tier VM '$vmName' SEALED — an unexpected volume " +
                   "'$disk' is attached (only the system disk '$systemDisk' and the descriptor's recorded data " +
                   "disks are allowed). Treated as a residual secret/transfer volume. Fail closed.")
        }

        # (d) ALL-TIER best-effort backend-truth backstop: an ACTUALLY-attached disk that is not an
        # EXPECTED disk (system disk + the descriptor's CreatedDisks/DiskPaths) is a residual and is
        # refused — at EVERY tier, including Tier-1 (where (c)'s strict single-disk rule does not
        # apply). This closes the Tier-1 gap the review caught: a residual that is neither secret-
        # shaped by name (b) nor recorded as import media (a) would otherwise slip through at Tier-1.
        # It is BEST-EFFORT — it can only catch disks the descriptor did not record as legitimate;
        # the authoritative no-net structural guarantee remains (c) at Tier>=2. We only apply it when
        # the expected set is known (a real New-SandboxVM descriptor always records DiskPath), so a
        # descriptor with no recorded disks at all does not produce spurious refusals.
        # Compared in CANONICAL form (Hardening 2): a recorded disk under an equivalent-but-differing
        # form matches; a genuinely-unrecorded disk's canonical form is still absent => still refused.
        if ($expectedDisks.Count -gt 0 -and -not $expectedDisks.Contains($diskCanon)) {
            throw ("Assert-Sealed: REFUSING to certify '$vmName' SEALED — an unexpected residual disk '$disk' " +
                   "is attached. Only the expected disks (the system disk and the descriptor's recorded " +
                   "created disks) may remain attached in a sealed sandbox; a disk the descriptor did not " +
                   "record as legitimate is treated as a residual transfer/secret volume. Fail closed.")
        }
    }

    # --- every host channel MUST be off (host-verified) -------------------
    $channels = & $Backend.GetHostChannels @{ VMName = $vmName }
    foreach ($channel in $script:SealHostChannels) {
        $on = $false
        if ($channels -is [System.Collections.IDictionary] -and $channels.Contains($channel)) {
            $on = [bool]$channels[$channel]
        }
        else {
            # The channel state could not be read — fail closed (cannot verify => cannot certify).
            throw ("Assert-Sealed: REFUSING to certify '$vmName' SEALED — could not read host-channel " +
                   "'$channel' state from the host. Fail closed.")
        }
        if ($on) {
            throw ("Assert-Sealed: REFUSING to certify '$vmName' SEALED — host channel '$channel' is still ON. " +
                   "All host<->guest channels (clipboard / shares / guest-services / enhanced-session) MUST be " +
                   "off in a sealed sandbox. Fail closed.")
        }
    }

    # --- POSITIVE post-seal COM1-liveness assertion (serial-managed guests only) ----------
    # The seal closes host<->guest channels, removes NICs (Tier>=2), and ejects media. None of that
    # may COLLATERALLY sever the Runner's COM1 serial command channel — the ONLY no-NIC management
    # path for a Linux guest (PowerShell Direct is Windows-guest-only). A live run confirmed the seal
    # (Disable-VMConsoleSupport for the ESM facets) does NOT break COM1, but inference is not host
    # truth: we ASSERT it. Only for a SERIAL-MANAGED guest — ManagementChannel='Com1Serial' OR a
    # ComPipePath recorded on the descriptor. A container-ish / non-serial tier (no ComPipePath, not
    # Com1Serial) is SKIPPED so this never spuriously fails a VM that legitimately has no COM1 channel.
    $mgmtChannel = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'ManagementChannel')
    $comPipePath = [string](Get-DescriptorField -Descriptor $Descriptor -Name 'ComPipePath')
    $serialManaged = ($mgmtChannel -eq 'Com1Serial') -or (-not [string]::IsNullOrWhiteSpace($comPipePath))
    if ($serialManaged) {
        # Read COM1 back from HOST TRUTH via the backend's GetComPort (the Sealer must NOT reach for a
        # raw Get-VMComPort). A $null record OR a blank path means the serial command channel is gone.
        $com1 = & $Backend.GetComPort @{ VMName = $vmName; Number = 1 }
        $com1Path = if ($com1 -is [System.Collections.IDictionary] -and $com1.Contains('Path')) { [string]$com1['Path'] } else { '' }
        if ($null -eq $com1 -or [string]::IsNullOrWhiteSpace($com1Path)) {
            throw ("Assert-Sealed: REFUSING to certify '$vmName' SEALED — the COM1 serial command channel is no " +
                   "longer attached after sealing (the host reports no live COM1 pipe). The seal must NEVER sever " +
                   "the Runner's command channel (COM1 is the only no-NIC management path for a Linux guest). " +
                   "Fail closed.")
        }
    }

    return $true
}
