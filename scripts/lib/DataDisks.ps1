<#
.SYNOPSIS
    Voidseal: verify-before-attach for pre-built disks (the DEPS disk and operator data disks).

.DESCRIPTION
    A pre-built disk is a VHDX the host did not create for this run: the builder's deps.vhdx, or a
    data disk the operator built from a directory with scripts/New-VoidsealDataDisk.ps1. Before the
    orchestrator attaches one, it has to prove the file is the one whose whole-image SHA-256 was
    recorded when it was built. Assert-DiskImageVerified is that proof, shared by both callers so the
    checks cannot drift apart:

      1. GetVHDInfo must read the disk (an unreadable or missing VHDX is refused).
      2. The disk must not be differencing and must carry no parent path (a differencing child takes
         blocks from a parent the host never hashed).
      3. An expected hash must be supplied (an unverified disk is never attached).
      4. GetVhdxImageHash (user space, never Mount-VHD) must equal the expected hash, compared as
         case-insensitive hex.

    The function returns the verified hash in lowercase. Attaching and recording stay with the
    caller, because the DEPS disk and the data disks record different descriptor fields, and data
    disks are all verified before any of them is attached.

    Dot-sourced by scripts/Invoke-Voidseal.ps1. Every Hyper-V touch goes through the backend.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Verify a pre-built VHDX before it is attached: readable, not differencing, hash present and equal.
.PARAMETER VMName
    The run's VM name (used in messages only).
.PARAMETER Path
    The host path of the VHDX to verify.
.PARAMETER ExpectedHash
    The whole-image SHA-256 recorded when the disk was built. Blank or null is refused.
.PARAMETER DiskLabel
    How messages name the disk, for example 'DEPS disk' or "data disk 'corpus'".
.PARAMETER DiskKind
    The noun used in the explanatory half of a message, for example 'dependency disk' or 'data disk'.
.PARAMETER MissingHashMessage
    The full refusal message for a missing expected hash (the caller knows where the hash should
    have come from, so it writes this one).
.PARAMETER HashOrigin
    Who recorded the expected hash, used in the mismatch message ('builder-recorded' by default).
.PARAMETER Backend
    The Hyper-V backend (real or fake).
.OUTPUTS
    [string] the verified lowercase hex SHA-256.
#>
function Assert-DiskImageVerified {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $VMName,
        [Parameter(Mandatory)] [string] $Path,
        [AllowNull()] [AllowEmptyString()] [string] $ExpectedHash,
        [Parameter(Mandatory)] [string] $DiskLabel,
        [Parameter(Mandatory)] [string] $DiskKind,
        [Parameter(Mandatory)] [string] $MissingHashMessage,
        [string] $HashOrigin = 'builder-recorded',
        [Parameter(Mandatory)] [hashtable] $Backend
    )

    # I1, STRUCTURE BEFORE HASH: a container swap can rewrite a fixed disk's footer and parent
    # locator so it becomes a DIFFERENCING disk pointing at a parent the attacker controls (which
    # supplies the real blocks at attach time). Refuse any differencing or parent-bearing disk before
    # trusting it. The whole-image hash alone does not model an attacker who controls child and parent.
    $info = & $Backend.GetVHDInfo @{ Path = $Path }
    if ($null -eq $info) {
        throw ("Invoke-Voidseal: '$VMName' $DiskLabel ('$Path') is unreadable via GetVHDInfo (missing, or not " +
               "a VHDX the host can read): refusing to attach an unverifiable $DiskKind. Failing closed.")
    }
    if ([bool]$info.Differencing -or -not [string]::IsNullOrWhiteSpace([string]$info.ParentPath)) {
        throw ("Invoke-Voidseal: '$VMName' $DiskLabel ('$Path') is a DIFFERENCING disk (Differencing=$($info.Differencing), " +
               "ParentPath='$($info.ParentPath)'). A $DiskKind MUST be a self-contained fixed/dynamic VHDX: a " +
               "differencing child pulls blocks from an external parent the host cannot verify. Refusing to attach; failing closed.")
    }

    # VERIFY BEFORE ATTACH: tamper evidence for the hand-off (the disk is byte-identical to what was
    # built), not a claim about where its contents came from. The hash is taken in user space while
    # the disk is still detached, so the host kernel never parses its bytes.
    if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
        throw $MissingHashMessage
    }
    $expected = $ExpectedHash.Trim().ToLowerInvariant()
    $actual   = ([string](& $Backend.GetVhdxImageHash @{ Path = $Path })).Trim().ToLowerInvariant()
    if ($actual -ne $expected) {
        throw ("Invoke-Voidseal: '$VMName' $DiskLabel integrity check FAILED: '$Path' hashes to '$actual' but the " +
               "expected ($HashOrigin) hash is '$expected'. The $DiskKind was tampered with or substituted; " +
               "refusing to attach. Failing closed.")
    }
    return $actual
}
