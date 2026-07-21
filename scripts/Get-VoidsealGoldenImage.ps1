<#
.SYNOPSIS
    Fetch, verify, and convert the pinned Debian genericcloud image into the golden `.vhdx`
    that `Invoke-Voidseal -ParentDiskPath` consumes — voidseal's most manual first-run step,
    turned into one command (Firecracker's "fetch a known-good rootfs" onboarding analog).

.DESCRIPTION
    Downloads a PINNED Debian 12 `genericcloud` amd64 qcow2, verifies it against a pinned
    SHA-512, and `qemu-img`-converts it to a golden VHDX. Read-mostly, unprivileged, fail-closed;
    it never touches Hyper-V (unlike a live run) — mirror of `Test-VoidsealPrereqs.ps1`.

    TRUST ROOT — pinned SHA-512 (honest framing, no overclaim):
      Debian cloud images are UNSIGNED — the serial directory ships `SHA512SUMS` but NO
      `SHA512SUMS.sign` (unlike Debian CD/ISO images, which are GPG-signed). So the root of
      trust is the SHA-512 Debian published for the pinned serial, which was fetched over
      TLS from cloud.debian.org and baked in below with provenance. Every download is verified
      against it and REFUSED on mismatch.

      This gives tamper-EVIDENCE of the download (a corrupted transfer, or a compromised
      mirror/CDN swapping the image at download time, is caught by the frozen pin). It is NOT
      a signature and does NOT attest that Debian's own infra was clean when the pin was
      sourced. That residual is acceptable here because the golden image feeds a HOST-VERIFIED
      SEALED sandbox: at Tier 0 the guest has no NIC and the seal is certified from the host
      BEFORE the guest runs, so a worst-case bad base image (which the pin already prevents) is
      structurally contained. The image is not the trust boundary; the seal is. (If signature-
      backed provenance is ever required, Ubuntu cloud images ARE GPG-signed — a guest-image-
      contract change, not this helper.)

    NECESSARY BUT NOT SUFFICIENT: a verified golden disk is the starting artifact; a live run
    still needs elevation + a CVE-floored host (see `Test-VoidsealPrereqs.ps1` / operator-runbook §0).

.PARAMETER OutputPath
    Where to write the golden `.vhdx`. Default: the path the runbook/live-smoke-test examples use.

.PARAMETER WorkDir
    Scratch directory for the qcow2 download. Default: `$env:TEMP\voidseal-golden`.

.PARAMETER Plan
    Dry-run: print the pinned URL, expected SHA-512, and the steps; download NOTHING; exit 0.

.PARAMETER Force
    Re-download + reconvert even if the output `.vhdx` already exists.

.PARAMETER KeepDownload
    Keep the verified qcow2 in `-WorkDir` after a successful convert (default: delete it).

.PARAMETER DotSourceOnly
    Internal: define the functions (and dot-source the engine for the qemu helpers) and return
    WITHOUT running the orchestrator, so Pester can dot-source this file to unit-test the logic.

.EXAMPLE
    pwsh scripts/Get-VoidsealGoldenImage.ps1 -Plan
    # Preview the pinned image + expected SHA-512 + steps without downloading anything.

.EXAMPLE
    pwsh scripts/Get-VoidsealGoldenImage.ps1 -OutputPath C:\sandbox\golden\debian-12-cloud.vhdx
    # Download -> verify -> convert into the golden parent disk, then run Test-VoidsealPrereqs.
#>
param(
    [string] $OutputPath = 'C:\sandbox\golden\debian-12-cloud.vhdx',
    [string] $WorkDir     = (Join-Path $env:TEMP 'voidseal-golden'),
    [switch] $Plan,
    [switch] $Force,
    [switch] $KeepDownload,
    [switch] $DotSourceOnly
)

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Pinned Debian genericcloud image (sourced + verified 2026-07-19 from Debian's
# published SHA512SUMS, fetched over TLS). Debian cloud images are UNSIGNED (no
# SHA512SUMS.sign) — the pinned SHA-512 below IS the root of trust. Never fabricated.
# Provenance: https://cloud.debian.org/images/cloud/bookworm/20260712-2537/SHA512SUMS
# Re-pin (a deliberate source edit) when Debian rotates this serial off the mirror.
# ---------------------------------------------------------------------------
$script:DebianRelease     = 'bookworm'
$script:DebianSerial      = '20260712-2537'
$script:DebianImageFile   = "debian-12-genericcloud-amd64-$script:DebianSerial.qcow2"  # serial embedded in name
$script:DebianBaseUrl     = "https://cloud.debian.org/images/cloud/$script:DebianRelease/$script:DebianSerial/"
$script:DebianImageSha512 = '6c2607f1846ee86040830c87d0b723f0967da3e884ea4673d9db4aa8eee13a4b7c663524bfa42082c16fc6919f3aa1bf425c004d07ff06c53a319ad0c42647bb'

# ---------------------------------------------------------------------------
# Pure logic (unit-tested offline)
# ---------------------------------------------------------------------------

function Resolve-GoldenImagePlan {
    <# Pure. Assemble the download/verify/convert plan from the pinned constants + params. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $OutputPath,
        [Parameter(Mandatory)] [string] $WorkDir
    )
    $shaShort = $script:DebianImageSha512.Substring(0, 16)
    [pscustomobject]@{
        Release        = $script:DebianRelease
        Serial         = $script:DebianSerial
        ImageFile      = $script:DebianImageFile
        Url            = $script:DebianBaseUrl + $script:DebianImageFile
        SumsUrl        = $script:DebianBaseUrl + 'SHA512SUMS'
        ExpectedSha512 = $script:DebianImageSha512
        OutputPath     = $OutputPath
        WorkDir        = $WorkDir
        QcowPath       = (Join-Path $WorkDir $script:DebianImageFile)
        Steps          = @(
            "Download $($script:DebianImageFile) (~300 MB) from cloud.debian.org into $WorkDir",
            "Verify its SHA-512 == $shaShort... against the pinned value (REFUSE on mismatch)",
            "qemu-img convert -f qcow2 -O vhdx (confined) -> $OutputPath (atomic)"
        )
    }
}

function Compare-Sha512 {
    <# Pure fail-closed gate. Ordinal, case-insensitive equality of two hex digests; empty/whitespace -> $false. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Expected,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Actual
    )
    if ([string]::IsNullOrWhiteSpace($Expected) -or [string]::IsNullOrWhiteSpace($Actual)) { return $false }
    return [string]::Equals($Expected.Trim(), $Actual.Trim(), [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-GoldenImagePresent {
    <# $true = skip (output present and no -Force). -Force always returns $false (rebuild). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $OutputPath,
        [switch] $Force
    )
    if ($Force) { return $false }
    return [bool](Test-Path -LiteralPath $OutputPath -PathType Leaf)
}

# ---------------------------------------------------------------------------
# Side effects (LIVE-ONLY: real network / hashing / qemu-img — operator-run,
# not exercised by the offline suite; the SEAMS are structurally test-asserted).
# ---------------------------------------------------------------------------

function Get-DebianImage {
    <# LIVE: download the pinned qcow2 into WorkDir. Returns the local path. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Plan)
    if (-not (Test-Path -LiteralPath $Plan.WorkDir)) {
        $null = New-Item -ItemType Directory -Path $Plan.WorkDir -Force
    }
    Write-Host "Downloading $($Plan.ImageFile) (~300 MB) from cloud.debian.org ..."
    # The progress renderer badly slows a large -OutFile download; silence it (function-scoped).
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $Plan.Url -OutFile $Plan.QcowPath
    } catch {
        throw ("Get-VoidsealGoldenImage: download failed for $($Plan.Url) — $($_.Exception.Message). " +
               "The pinned serial '$($Plan.Serial)' may have rotated off the mirror; re-pin from " +
               "$($Plan.SumsUrl) (see the script-header provenance). Failing closed.")
    }
    return $Plan.QcowPath
}

function Assert-ImageVerified {
    <# LIVE: hash the file and gate on the pinned SHA-512. Throws + deletes the download on mismatch. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Plan,
        [Parameter(Mandatory)] [string] $File
    )
    $actual = (Get-FileHash -LiteralPath $File -Algorithm SHA512).Hash
    if (-not (Compare-Sha512 -Expected $Plan.ExpectedSha512 -Actual $actual)) {
        Remove-Item -LiteralPath $File -Force -ErrorAction SilentlyContinue
        throw ("Get-VoidsealGoldenImage: SHA-512 mismatch for '$($Plan.ImageFile)' " +
               "(got $actual, pinned $($Plan.ExpectedSha512)) — refusing a substituted/corrupt image. " +
               "Deleted the download. Failing closed.")
    }
    Write-Host "SHA-512 verified against the pinned value ($($Plan.ExpectedSha512.Substring(0,16))...)."
}

function Clear-SparseFlag {
    <# LIVE (Windows): clear the NTFS sparse attribute on the produced VHDX. Hyper-V REFUSES to create a
       differencing child from a SPARSE parent (0xC03A001A: "the parent virtual disk must not be sparse"),
       and `qemu-img convert -O vhdx` writes a sparse file on NTFS. This is a LIVE-ONLY fix — surfaced on
       the first real provision (2026-07-19), invisible to the mock suite (a file's NTFS sparse flag is not
       something the fake backend models). Verify + fail-closed: if the flag can't be cleared, refuse rather
       than hand Hyper-V an unusable parent. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)
    $null = & fsutil.exe sparse setflag "$Path" 0 2>&1
    $q = (& fsutil.exe sparse queryflag "$Path" 2>&1) -join ' '
    if ($q -notmatch 'NOT set as sparse') {
        throw ("Get-VoidsealGoldenImage: could not clear the NTFS sparse flag on '$Path' — Hyper-V rejects a " +
               "sparse differencing parent (0xC03A001A). Clear it by hand (fsutil sparse setflag '$Path' 0) or " +
               "re-materialize with Convert-VHD -VHDType Dynamic. Failing closed.")
    }
}

function Convert-QcowToVhdx {
    <# LIVE: confined qemu-img convert qcow2 -> vhdx, atomic move into place, clear the sparse flag.
       Returns OutputPath. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $QcowPath,
        [Parameter(Mandatory)] [string] $OutputPath,
        [Parameter(Mandatory)] [string] $QemuPath
    )
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { $null = New-Item -ItemType Directory -Path $outDir -Force }
    # Temp beside the target (same volume) so the final Move-Item is an atomic rename — the host
    # never sees a half-written golden disk at $OutputPath.
    $tmp = "$OutputPath.partial-$PID"
    Write-Host "Converting qcow2 -> vhdx (confined qemu-img) ..."
    $null = Invoke-ConfinedQemu -QemuPath $QemuPath -Arguments @('convert', '-f', 'qcow2', '-O', 'vhdx', '--', $QcowPath, $tmp)
    if ($LASTEXITCODE -ne 0) {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw "Get-VoidsealGoldenImage: qemu-img convert failed (exit $LASTEXITCODE). Failing closed."
    }
    Move-Item -LiteralPath $tmp -Destination $OutputPath -Force
    # Hyper-V rejects a sparse differencing parent; qemu-img's output is sparse on NTFS (see Clear-SparseFlag).
    Clear-SparseFlag -Path $OutputPath
    return $OutputPath
}

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

function Get-VoidsealGoldenImage {
    [CmdletBinding()]
    param(
        # OutputPath/WorkDir defaults mirror the script param block (the canonical caller surface);
        # the entry below always passes them explicitly, so these apply only to direct programmatic calls.
        [string] $OutputPath = 'C:\sandbox\golden\debian-12-cloud.vhdx',
        [string] $WorkDir     = (Join-Path $env:TEMP 'voidseal-golden'),
        [switch] $Plan,
        [switch] $Force,
        [switch] $KeepDownload
    )
    $ErrorActionPreference = 'Stop'   # function-scoped: does not leak into a dot-sourcing test
    $p = Resolve-GoldenImagePlan -OutputPath $OutputPath -WorkDir $WorkDir

    if ($Plan) {
        Write-Host ''
        Write-Host 'Get-VoidsealGoldenImage -Plan (dry-run — nothing downloaded):'
        Write-Host "  Image   : $($p.ImageFile)"
        Write-Host "  URL     : $($p.Url)"
        Write-Host "  SHA-512 : $($p.ExpectedSha512)"
        Write-Host "  Output  : $($p.OutputPath)"
        Write-Host '  Steps   :'
        $p.Steps | ForEach-Object { Write-Host "    - $_" }
        Write-Host ''
        return $p
    }

    # qemu-img preflight — fail FAST (before a ~300 MB download) if it's missing / below floor.
    # Reuse the engine's resolver + floor/pin (captured at dot-source time from HyperVBackend.ps1).
    $qemu = Resolve-QemuImg -MinVersion $script:GoldenQemuMinVer -PinnedSha256 $script:GoldenQemuPin

    if (Test-GoldenImagePresent -OutputPath $OutputPath -Force:$Force) {
        Write-Host "Golden image already present: $OutputPath  (use -Force to rebuild). Nothing to do."
        return $OutputPath
    }

    $qcow = Get-DebianImage -Plan $p
    Assert-ImageVerified -Plan $p -File $qcow
    $out = Convert-QcowToVhdx -QcowPath $qcow -OutputPath $OutputPath -QemuPath $qemu
    if (-not $KeepDownload) { Remove-Item -LiteralPath $qcow -Force -ErrorAction SilentlyContinue }

    Write-Host ''
    Write-Host "Golden image ready: $out"
    Write-Host "Next: pwsh scripts/Test-VoidsealPrereqs.ps1 -ParentDiskPath `"$out`""
    Write-Host "Then: Invoke-Voidseal -Tier 0 -Profile firefox -ParentDiskPath `"$out`" ..."
    return $out
}

# ---------------------------------------------------------------------------
# Entry — dot-source the engine for Resolve-QemuImg + Invoke-ConfinedQemu, capture
# its qemu floor/pin (single source of truth), then run (unless test dot-sourcing).
# ---------------------------------------------------------------------------
. "$PSScriptRoot/lib/HyperVBackend.ps1"
$script:GoldenQemuMinVer = $script:QemuImgMinVersion      # reuse the engine's floor (8.2.0), no duplication
$script:GoldenQemuPin    = $script:QemuImgPinnedSha256    # $null by default (version-floor only)

if ($DotSourceOnly) { return }

$result = Get-VoidsealGoldenImage -OutputPath $OutputPath -WorkDir $WorkDir -Plan:$Plan -Force:$Force -KeepDownload:$KeepDownload
# -Plan already printed the human-readable plan; don't also dump the plan object to stdout.
if (-not $Plan) { $result }
