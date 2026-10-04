<#
.SYNOPSIS
    Voidseal: verified per-run working copies of pre-built disks (the DEPS disk and operator data disks).

.DESCRIPTION
    A pre-built disk is a VHDX the host did not create for this run: the builder's deps.vhdx, or a
    data disk the operator built from a directory with scripts/New-VoidsealDataDisk.ps1. The run never
    attaches that ORIGINAL. Hyper-V attaches every VHDX read-write and may update the file's metadata
    even when the guest only reads, which would change its whole-image hash and make the next run
    refuse it; a guest with root could also write to it. So each run attaches a WORKING COPY instead,
    made in the run's own sandbox folder and deleted at teardown with the run's other disks.

    New-VerifiedDiskCopy is the one path both callers use, so the checks cannot drift apart:

      1. GetVHDInfo must read the ORIGINAL, and it must not be differencing or carry a parent path
         (a differencing child takes blocks from a parent the host never hashed).
      2. An expected hash must be supplied (an unverified disk is never attached).
      3. CopyVhdxFile copies the original into the run folder (it refuses to overwrite a file that
         already exists there), and the copy joins CreatedDisks so teardown deletes it.
      4. The COPY passes the same structure check, and its GetVhdxImageHash (user space, never
         Mount-VHD) must equal the expected hash, compared as case-insensitive hex. Hashing the copy
         rather than the original means the bytes the guest gets are the bytes that were verified.

    The function returns the verified hash in lowercase. Attaching and recording stay with the
    caller, because the DEPS disk and the data disks record different descriptor fields, and data
    disks are all verified before any of them is attached.

    Dot-sourced by scripts/Invoke-Voidseal.ps1. Every Hyper-V touch goes through the backend.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Refuse a VHDX the host cannot read, or one that is differencing or names a parent.
.OUTPUTS
    The GetVHDInfo record.
#>
function Assert-DiskStructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $VMName,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $DiskLabel,
        [Parameter(Mandatory)] [string] $DiskKind,
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
    return $info
}

<#
.SYNOPSIS
    Verify a VHDX before it is attached: readable, not differencing, hash present and equal.
.PARAMETER VMName
    The run's VM name (used in messages only).
.PARAMETER Path
    The host path of the VHDX to verify (the working copy, when called by New-VerifiedDiskCopy).
.PARAMETER SourcePath
    Optional: the original this file was copied from, named in the mismatch message.
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
        [string] $SourcePath,
        [AllowNull()] [AllowEmptyString()] [string] $ExpectedHash,
        [Parameter(Mandatory)] [string] $DiskLabel,
        [Parameter(Mandatory)] [string] $DiskKind,
        [Parameter(Mandatory)] [string] $MissingHashMessage,
        [string] $HashOrigin = 'builder-recorded',
        [Parameter(Mandatory)] [hashtable] $Backend
    )

    $null = Assert-DiskStructure -VMName $VMName -Path $Path -DiskLabel $DiskLabel -DiskKind $DiskKind -Backend $Backend

    # VERIFY BEFORE ATTACH: tamper evidence for the hand-off (the disk is byte-identical to what was
    # built), not a claim about where its contents came from. The hash is taken in user space while
    # the disk is still detached, so the host kernel never parses its bytes.
    if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
        throw $MissingHashMessage
    }
    $expected = $ExpectedHash.Trim().ToLowerInvariant()
    $actual   = ([string](& $Backend.GetVhdxImageHash @{ Path = $Path })).Trim().ToLowerInvariant()
    if ($actual -ne $expected) {
        $what = if ([string]::IsNullOrWhiteSpace($SourcePath)) { "'$Path'" } else { "'$Path' (the working copy of '$SourcePath')" }
        throw ("Invoke-Voidseal: '$VMName' $DiskLabel integrity check FAILED: $what hashes to '$actual' but the " +
               "expected ($HashOrigin) hash is '$expected'. The $DiskKind was tampered with or substituted; " +
               "refusing to attach. Failing closed.")
    }
    return $actual
}

<#
.SYNOPSIS
    Make and verify this run's working copy of a pre-built disk. See the file header for the steps.
.PARAMETER Path
    The ORIGINAL pre-built VHDX (never attached).
.PARAMETER CopyPath
    Where the working copy goes: inside the run's own sandbox folder.
.PARAMETER Descriptor
    The run descriptor; the copy is appended to its CreatedDisks once it exists, so teardown deletes it.
.OUTPUTS
    [string] the verified lowercase hex SHA-256 of the copy (equal to the expected hash).
#>
function New-VerifiedDiskCopy {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $VMName,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $CopyPath,
        [AllowNull()] [AllowEmptyString()] [string] $ExpectedHash,
        [Parameter(Mandatory)] [string] $DiskLabel,
        [Parameter(Mandatory)] [string] $DiskKind,
        [Parameter(Mandatory)] [string] $MissingHashMessage,
        [string] $HashOrigin = 'builder-recorded',
        [Parameter(Mandatory)] $Descriptor,
        [Parameter(Mandatory)] [hashtable] $Backend
    )

    # 1-2: the original's structure and the presence of a hash, before spending time on a copy.
    $null = Assert-DiskStructure -VMName $VMName -Path $Path -DiskLabel $DiskLabel -DiskKind $DiskKind -Backend $Backend
    if ([string]::IsNullOrWhiteSpace($ExpectedHash)) {
        throw $MissingHashMessage
    }

    # 3: copy, then record. Recording only after the copy exists keeps teardown from ever deleting a
    # file this run did not create (CopyVhdxFile refuses to overwrite an existing destination).
    $null = & $Backend.CopyVhdxFile @{ Path = $Path; Destination = $CopyPath }
    $created = @(@($Descriptor.CreatedDisks) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($created -notcontains $CopyPath) { $created = @($created) + @($CopyPath) }
    $Descriptor.CreatedDisks = @($created)

    # 4: the copy is what the guest gets, so the copy is what gets verified.
    return (Assert-DiskImageVerified -VMName $VMName -Path $CopyPath -SourcePath $Path -ExpectedHash $ExpectedHash `
                -DiskLabel $DiskLabel -DiskKind $DiskKind -MissingHashMessage $MissingHashMessage `
                -HashOrigin $HashOrigin -Backend $Backend)
}

<#
.SYNOPSIS
    Resolve the run's effective DataDisks declaration: a -Workload value replaces the profile's.
.DESCRIPTION
    The workload value wins whenever the key is PRESENT, even as an empty array, so a caller can
    run a profile that declares data disks without any. Returns the validated, normalized list
    (ConvertTo-DataDiskList) as an array; empty when nothing is declared.
#>
function Resolve-DataDiskDeclaration {
    [CmdletBinding()]
    param([AllowNull()] $Workload, [Parameter(Mandatory)] [hashtable] $Profile, [string] $Context = 'Invoke-Voidseal')

    $decl = $null
    $source = 'profile'
    $present = $false
    if ($Workload -is [System.Collections.IDictionary]) { $present = $Workload.Contains('DataDisks') }
    elseif ($null -ne $Workload) { $present = $null -ne $Workload.PSObject.Properties['DataDisks'] }
    if ($present) {
        $decl = if ($Workload -is [System.Collections.IDictionary]) { $Workload['DataDisks'] } else { $Workload.DataDisks }
        $source = '-Workload'
    }
    elseif ($Profile.ContainsKey('DataDisks')) {
        $decl = $Profile['DataDisks']
    }
    # Unrolled; callers wrap the call in @() (an empty declaration yields no output at all).
    ConvertTo-DataDiskList -Value $decl -Context "$Context DataDisks ($source)"
}

<#
.SYNOPSIS
    Resolve a host path through any junctions and symbolic links on it (best effort, existing parts only).
.DESCRIPTION
    Walks the path one segment at a time; when an existing segment is a junction or symbolic link,
    substitutes its target and starts again (at most 32 substitutions, then fails closed). Segments
    that do not exist are kept as written. Returns the canonical result without a trailing separator.
    Used so that a data disk path cannot reach the sandbox storage root, the DEPS disk or the golden
    parent through a link that only a lexical compare would miss.
#>
function Resolve-HostFinalPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)

    $full = [System.IO.Path]::GetFullPath($Path)
    for ($hop = 0; $hop -lt 32; $hop++) {
        $root  = [System.IO.Path]::GetPathRoot($full)
        $parts = @($full.Substring($root.Length).Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries))
        $cur = $root
        $swapped = $false
        for ($i = 0; $i -lt $parts.Count; $i++) {
            $cur = [System.IO.Path]::Combine($cur, $parts[$i])
            $item = Get-Item -LiteralPath $cur -Force -ErrorAction SilentlyContinue
            if ($null -eq $item) { break }
            $linkType = [string]$item.LinkType
            if ($linkType -eq 'Junction' -or $linkType -eq 'SymbolicLink') {
                $target = [string](@($item.Target)[0])
                if ([string]::IsNullOrWhiteSpace($target)) { break }
                if ($target.StartsWith('\\?\') -or $target.StartsWith('\??\')) { $target = $target.Substring(4) }
                if (-not [System.IO.Path]::IsPathRooted($target)) {
                    $target = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($cur), $target)
                }
                $rest = if ($i + 1 -lt $parts.Count) { $parts[($i + 1)..($parts.Count - 1)] -join '\' } else { '' }
                $next = if ($rest) { [System.IO.Path]::Combine($target, $rest) } else { $target }
                $full = [System.IO.Path]::GetFullPath($next)
                $swapped = $true
                break
            }
        }
        if (-not $swapped) { return $full.TrimEnd('\', '/') }
    }
    throw "Resolve-HostFinalPath: '$Path' passes through more than 32 links; refusing to resolve it. Failing closed."
}

# True when $Candidate equals $Root or lies under it (both canonical, case-insensitive).
function Test-PathUnderRoot {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Candidate, [Parameter(Mandatory)] [string] $Root)
    $c = $Candidate.TrimEnd('\', '/')
    $r = $Root.TrimEnd('\', '/')
    if ($c.Equals($r, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $c.StartsWith($r + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

<#
.SYNOPSIS
    Refuse any data disk path that could alias a disk the run owns or depends on (fail-closed).
.DESCRIPTION
    A data disk is attached read-write at the Hyper-V level (Hyper-V cannot attach a VHDX
    read-only), so its path must never name something the guest must not be able to write:
      * anything under the sandbox storage root (every run's system, INPUT, OUTPUT and CIDATA disks
        live there; the run's own disks are created there later, so they are covered too);
      * the DEPS disk;
      * the golden parent of the differencing system disk (-ParentDiskPath).
    Both the lexical canonical path and the link-resolved path (Resolve-HostFinalPath) are compared,
    for the data disk and for each protected location. A data disk file with more than one hard link
    is refused too: a second name could be any of the above, and the host cannot cheaply tell which.
.PARAMETER DataDisks
    The normalized list from ConvertTo-DataDiskList.
.PARAMETER StorageRoot
    The sandbox storage root (the parent of every per-VM folder).
.PARAMETER DepsDiskPath
    The run's DEPS disk path, if any.
.PARAMETER ParentDiskPath
    The run's golden parent disk, if any.
#>
function Assert-DataDiskPathsIsolated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $DataDisks,
        [Parameter(Mandatory)] [string] $StorageRoot,
        [AllowNull()] [AllowEmptyString()] [string] $DepsDiskPath,
        [AllowNull()] [AllowEmptyString()] [string] $ParentDiskPath
    )

    $forms = {
        param([string] $p)
        $lex = [System.IO.Path]::GetFullPath($p).TrimEnd('\', '/')
        $fin = Resolve-HostFinalPath -Path $p
        return @(@($lex, $fin) | Select-Object -Unique)
    }
    $rootForms = @(& $forms $StorageRoot)
    $protected = [System.Collections.Generic.List[object]]::new()
    if (-not [string]::IsNullOrWhiteSpace($DepsDiskPath)) {
        $protected.Add(@{ What = 'the DEPS disk'; Forms = @(& $forms $DepsDiskPath) })
    }
    if (-not [string]::IsNullOrWhiteSpace($ParentDiskPath)) {
        $protected.Add(@{ What = 'the golden parent disk (-ParentDiskPath)'; Forms = @(& $forms $ParentDiskPath) })
    }

    foreach ($dd in $DataDisks) {
        $name = [string]$dd['Name']
        $path = [string]$dd['Path']
        foreach ($f in @(& $forms $path)) {
            foreach ($r in $rootForms) {
                if (Test-PathUnderRoot -Candidate $f -Root $r) {
                    throw ("Invoke-Voidseal: data disk '$name' ('$path') resolves under the sandbox storage root ('$r'), " +
                           "where run disks live. A data disk must live outside it. Failing closed.")
                }
            }
            foreach ($pr in $protected) {
                foreach ($pf in $pr.Forms) {
                    if ($f.Equals([string]$pf, [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw ("Invoke-Voidseal: data disk '$name' ('$path') is $($pr.What) ('$pf'). A data disk must " +
                               "never alias a disk the run already uses. Failing closed.")
                    }
                }
            }
        }
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and [string]$item.LinkType -eq 'HardLink') {
            throw ("Invoke-Voidseal: data disk '$name' ('$path') has more than one hard link, so another name for the " +
                   "same file could be a run disk, the DEPS disk or the golden parent. Copy it to a file of its own. " +
                   "Failing closed.")
        }
    }
}

<#
.SYNOPSIS
    Re-hash every recorded data disk's ORIGINAL after the run and report whether any of them changed.
.DESCRIPTION
    Called after teardown. The guest only ever saw a working copy, which teardown deletes, so a guest
    write cannot reach the original or the next run; it is not tracked. What this catches is the
    original changing on the HOST while the run was going (or being unreadable afterwards), so the
    operator knows the file on disk is no longer the one that was verified for this run. Each recorded
    entry gets PostRunImageHash (the original's new hash, or $null when it could not be read) and
    Changed. A mismatch, or a hash that cannot be taken at all, counts as changed and writes a warning
    naming the disk; it never fails a run that otherwise succeeded. Returns $null when no data disk was
    recorded (nothing to check), else $true or $false.
.PARAMETER Descriptor
    The run descriptor (its DataDisks list, as recorded at attach time).
.PARAMETER VMName
    The run's VM name (messages only).
.PARAMETER Backend
    The Hyper-V backend; the hash goes through GetVhdxImageHash (user space, never Mount-VHD).
#>
function Test-DataDiskChanged {
    [CmdletBinding()]
    param([AllowNull()] $Descriptor, [Parameter(Mandatory)] [string] $VMName, [Parameter(Mandatory)] [hashtable] $Backend)

    $entries = @(Get-DescriptorField -Descriptor $Descriptor -Name 'DataDisks' -Default @())
    if ($entries.Count -eq 0) { return $null }
    $anyChanged = $false
    foreach ($e in $entries) {
        $post = $null
        $why  = $null
        $original = [string]$e.SourcePath
        try   { $post = ([string](& $Backend.GetVhdxImageHash @{ Path = $original })).Trim().ToLowerInvariant() }
        catch { $why = $_.Exception.Message }
        $same = (-not [string]::IsNullOrWhiteSpace($post)) -and ($post -eq ([string]$e.ImageHash).ToLowerInvariant())
        Add-Member -InputObject $e -MemberType NoteProperty -Name 'PostRunImageHash' -Value $post -Force
        Add-Member -InputObject $e -MemberType NoteProperty -Name 'Changed' -Value (-not $same) -Force
        if (-not $same) {
            $anyChanged = $true
            $detail = if ($null -ne $why) { "could not be re-hashed ($why)" } else { "now hashes to '$post', not the recorded '$($e.ImageHash)'" }
            Write-Warning ("Invoke-Voidseal: '$VMName' data disk '$($e.Name)' original ('$original') $detail. Something on " +
                           "the host changed it during the run; treat it as changed and rebuild it with " +
                           "New-VoidsealDataDisk.ps1 (or restore it) before another run relies on it.")
        }
    }
    return $anyChanged
}
