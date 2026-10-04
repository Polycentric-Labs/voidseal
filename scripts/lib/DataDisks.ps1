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
    Re-hash every recorded data disk after the run and report whether any of them changed.
.DESCRIPTION
    Called once the VM is gone (after teardown), so every data disk is detached and no guest can be
    writing to it. Each recorded entry gets PostRunImageHash (the new hash, or $null when it could not
    be read) and Changed. A mismatch, or a hash that cannot be taken at all, counts as changed and
    writes a warning naming the disk: the data disk is an input, so this never fails a run that
    otherwise succeeded, but the report must say the operator's file is no longer the one recorded.
    Returns $null when no data disk was recorded (nothing to check), else $true or $false.
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
        try   { $post = ([string](& $Backend.GetVhdxImageHash @{ Path = [string]$e.Path })).Trim().ToLowerInvariant() }
        catch { $why = $_.Exception.Message }
        $same = (-not [string]::IsNullOrWhiteSpace($post)) -and ($post -eq ([string]$e.ImageHash).ToLowerInvariant())
        Add-Member -InputObject $e -MemberType NoteProperty -Name 'PostRunImageHash' -Value $post -Force
        Add-Member -InputObject $e -MemberType NoteProperty -Name 'Changed' -Value (-not $same) -Force
        if (-not $same) {
            $anyChanged = $true
            $detail = if ($null -ne $why) { "could not be re-hashed ($why)" } else { "now hashes to '$post', not the recorded '$($e.ImageHash)'" }
            Write-Warning ("Invoke-Voidseal: '$VMName' data disk '$($e.Name)' ('$($e.Path)') $detail. Treat it as changed: " +
                           "rebuild it with New-VoidsealDataDisk.ps1 (or restore it) before another run relies on it.")
        }
    }
    return $anyChanged
}
