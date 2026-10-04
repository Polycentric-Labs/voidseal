<#
.SYNOPSIS
    Build a pre-built data disk (an exFAT VHDX) from a host directory and print its whole-image
    SHA-256, ready to declare in a workload's DataDisks.

.DESCRIPTION
    A data disk carries bulk read-only input into a sealed guest: a corpus of sample text files,
    Python wheels for `pip install --no-index --find-links /mnt/data/<name>`, or model weights. The
    guest mounts it read-only at /mnt/data/<name> by its volume label (VSD + the upper-cased name).
    Invoke-Voidseal attaches it only after re-hashing it and matching the hash printed here.

    Steps (all fail-closed, in this order, before anything is created):
      1. The name must match ^[a-z0-9]{1,8}$ (it becomes a guest directory and a volume label).
      2. The destination must be a local .vhdx path that does not exist yet, is not secret-shaped,
         and is not inside the source tree or under the sandbox storage root; its folder must exist.
      3. The source tree must contain NO secret-shaped path (invariant 1's patterns, the single
         source of truth in scripts/lib/ProfileLoader.ps1) and NO junction or symbolic link (a link
         could pull files from outside the tree into the disk).
      4. Size: -SizeBytes, or by default the content size (each file rounded up to a 128 KiB exFAT
         cluster) times 1.3 plus 64 MB, never below 64 MB, rounded up to whole MiB. The host volume
         must have that much free plus headroom.
    Then: create and format the VHDX (NewOutputVhdx, exFAT, label VSD<NAME>), copy the tree onto it
    (CopyDirectoryToVhdx), and hash the detached file (GetVhdxImageHash, user space). A failed copy
    removes the half-built VHDX.

    The secret check is a path-SHAPE lint, not a content scan: it stops the common accident (an .env
    or a key file left in the tree), not a caller who renames a credential.

    LIVE-ONLY: the real create, mount, robocopy and hash need an elevated session (Mount-VHD). The
    mock suite drives this script through the fake backend.

.PARAMETER SourceDir
    The host directory whose contents become the disk's root.
.PARAMETER Path
    The .vhdx file to create. Keep it outside the sandbox storage root.
.PARAMETER Name
    The data disk name (1 to 8 lowercase letters or digits).
.PARAMETER SizeBytes
    Optional virtual size. Must be at least 64 MB and at least the rounded content size.
.PARAMETER DotSourceOnly
    Internal: define the function and dot-source the engine, then return (for Pester).

.EXAMPLE
    pwsh scripts/New-VoidsealDataDisk.ps1 -SourceDir D:\vs\sample-corpus -Path D:\vs\disks\corpus.vhdx -Name corpus
    # Prints Name, Path, ImageHash and a DataDisks entry to paste into -Workload or a profile.
#>
param(
    [string] $SourceDir,
    [string] $Path,
    [string] $Name,
    [long]   $SizeBytes = 0,
    [switch] $DotSourceOnly
)

Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Build a data disk from a directory. See the script header for the full contract.
.PARAMETER Backend
    The Hyper-V backend. Defaults to the real one; tests inject the fake.
#>
function New-VoidsealDataDisk {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $SourceDir,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [long] $SizeBytes = 0,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    $clusterBytes = 128KB
    $minBytes     = 64MB

    # 1. Name (throws on anything outside ^[a-z0-9]{1,8}$).
    $label = Get-DataDiskLabel -Name $Name

    # 2. Destination.
    $why = Get-DataDiskPathProblem -Path $Path
    if ($null -ne $why) { throw "New-VoidsealDataDisk: -Path '$Path' is refused: $why. Failing closed." }
    $dest = [System.IO.Path]::GetFullPath($Path)
    if (Test-IsSecretPath -Path $dest) { throw "New-VoidsealDataDisk: -Path '$dest' is secret-shaped (invariant 1). Failing closed." }
    if (Test-Path -LiteralPath $dest) { throw "New-VoidsealDataDisk: '$dest' already exists; refusing to overwrite it. Remove it first or pick another path." }

    if ([string]::IsNullOrWhiteSpace($SourceDir) -or -not (Test-Path -LiteralPath $SourceDir -PathType Container)) {
        throw "New-VoidsealDataDisk: -SourceDir '$SourceDir' is not an existing directory. Failing closed."
    }
    $src = [System.IO.Path]::GetFullPath($SourceDir).TrimEnd('\', '/')
    $srcFinal  = Resolve-HostFinalPath -Path $src
    $destFinal = Resolve-HostFinalPath -Path $dest
    foreach ($pair in @(@($dest, $src), @($destFinal, $srcFinal))) {
        if (Test-PathUnderRoot -Candidate $pair[0] -Root $pair[1]) {
            throw "New-VoidsealDataDisk: -Path '$dest' is inside -SourceDir '$src'; the disk would try to copy itself. Failing closed."
        }
    }
    $storageBase = Split-Path -Parent (Get-SandboxStorageRoot -Name 'x')
    foreach ($root in @($storageBase, (Resolve-HostFinalPath -Path $storageBase)) | Select-Object -Unique) {
        foreach ($cand in @($dest, $destFinal)) {
            if (Test-PathUnderRoot -Candidate $cand -Root $root) {
                throw "New-VoidsealDataDisk: -Path '$dest' is under the sandbox storage root ('$root'); keep data disks outside it. Failing closed."
            }
        }
    }

    $destDir = Split-Path -Parent $dest
    if (-not (Test-Path -LiteralPath $destDir -PathType Container)) {
        throw "New-VoidsealDataDisk: the folder for -Path ('$destDir') does not exist. Create it first. Failing closed."
    }

    # 3. Source tree: no secret-shaped path, no link anywhere (the root included).
    $rootItem = Get-Item -LiteralPath $src -Force
    if (Test-IsSecretPath -Path $src) { throw "New-VoidsealDataDisk: -SourceDir '$src' is secret-shaped (invariant 1). Failing closed." }
    if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "New-VoidsealDataDisk: -SourceDir '$src' is itself a junction or symbolic link. Point at the real directory. Failing closed."
    }
    $items = @(Get-ChildItem -LiteralPath $src -Recurse -Force -ErrorAction Stop)
    $secret = [System.Collections.Generic.List[string]]::new()
    $links  = [System.Collections.Generic.List[string]]::new()
    $contentBytes = [long]0
    $fileCount = 0
    foreach ($it in $items) {
        $rel = $it.FullName.Substring($src.Length).TrimStart('\', '/')
        if ($it.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { $links.Add($rel); continue }
        if (Test-IsSecretPath -Path $it.FullName) { $secret.Add($rel) }
        if (-not $it.PSIsContainer) {
            $fileCount++
            $contentBytes += [long]([math]::Ceiling([double]$it.Length / $clusterBytes)) * $clusterBytes
        }
    }
    if ($secret.Count -gt 0) {
        throw ("Invariant 1 (secret-file refusal): -SourceDir '$src' contains $($secret.Count) secret-shaped path(s): " +
               "$(($secret | Select-Object -First 10) -join ', '). Remove them from the tree; a data disk must never " +
               "carry a credential into a sandbox. NOTE: this is a path-SHAPE lint, not a content scan. Failing closed.")
    }
    if ($links.Count -gt 0) {
        throw ("New-VoidsealDataDisk: -SourceDir '$src' contains $($links.Count) junction(s) or symbolic link(s): " +
               "$(($links | Select-Object -First 10) -join ', '). A link can pull files from outside the tree; copy the " +
               "real files in instead. Failing closed.")
    }

    # 4. Size.
    $auto = [long]([math]::Ceiling($contentBytes * 1.3)) + $minBytes
    if ($SizeBytes -gt 0) {
        if ($SizeBytes -lt $minBytes -or $SizeBytes -lt $contentBytes) {
            throw ("New-VoidsealDataDisk: -SizeBytes $SizeBytes is too small; it must be at least 64 MB and at least the " +
                   "content size rounded to clusters ($contentBytes bytes). Omit it to use the default ($auto). Failing closed.")
        }
        $size = $SizeBytes
    }
    else { $size = [math]::Max($auto, $minBytes) }
    $size = [long]([math]::Ceiling($size / [double]1MB)) * 1MB
    $null = Test-HostFreeSpace -Path $dest -RequiredBytes $size -Backend $Backend

    # Create + format, copy, hash. A failed copy removes the half-built disk.
    $null = & $Backend.NewOutputVhdx @{ Path = $dest; Label = $label; FileSystem = 'exFAT'; SizeBytes = $size }
    try {
        $null = & $Backend.CopyDirectoryToVhdx @{ Path = $dest; SourceDir = $src }
    }
    catch {
        $copyErr = $_
        try { $null = & $Backend.RemoveVHD @{ Path = $dest } }
        catch { Write-Warning "New-VoidsealDataDisk: could not remove the half-built '$dest': $($_.Exception.Message)" }
        throw $copyErr
    }
    $hash = ([string](& $Backend.GetVhdxImageHash @{ Path = $dest })).Trim().ToLowerInvariant()
    if ($hash -notmatch '^[0-9a-f]{64}$') {
        throw "New-VoidsealDataDisk: the image hash of '$dest' came back malformed ('$hash'). Failing closed."
    }

    return [pscustomobject]@{
        Name         = $Name
        Path         = $dest
        ImageHash    = $hash
        Label        = $label
        SizeBytes    = $size
        FileCount    = $fileCount
        ContentBytes = $contentBytes
        Declaration  = "@{ Name = '$Name'; Path = '$dest'; ImageHash = '$hash' }"
    }
}

# ---------------------------------------------------------------------------
# Entry: dot-source the engine pieces this script uses, then run (unless test dot-sourcing).
# ---------------------------------------------------------------------------
. "$PSScriptRoot/lib/HyperVBackend.ps1"
. "$PSScriptRoot/lib/ProfileLoader.ps1"
. "$PSScriptRoot/lib/Provisioner.ps1"
. "$PSScriptRoot/lib/DataDisks.ps1"

if ($DotSourceOnly) { return }

$result = New-VoidsealDataDisk -SourceDir $SourceDir -Path $Path -Name $Name -SizeBytes $SizeBytes
Write-Host ''
Write-Host "Data disk ready: $($result.Path)"
Write-Host "  Label     : $($result.Label) (mounts read-only at /mnt/data/$($result.Name))"
Write-Host "  ImageHash : $($result.ImageHash)"
Write-Host "  Declare it: DataDisks = @( $($result.Declaration) )"
$result
