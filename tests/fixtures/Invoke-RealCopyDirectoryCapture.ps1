<#
.SYNOPSIS
    Out-of-process capture harness for the REAL backend's CopyDirectoryToVhdx body.

.DESCRIPTION
    Same pattern as Invoke-RealBackendCapture.ps1: the real backend's methods are closures that
    resolve their commands against the session state where HyperVBackend.ps1 was dot-sourced, so a
    Pester Mock in the test scope never reaches them. This script defines recording stubs for
    Mount-VHD, Get-Disk, Get-Partition, Add-PartitionAccessPath, Dismount-VHD and robocopy at its own
    top-level scope, dot-sources the lib into that same scope, then drives the REAL method. Nothing
    touches Hyper-V, storage or the file system beyond a temp source directory this script creates.

.PARAMETER LibPath
    Absolute path to scripts/lib/HyperVBackend.ps1.

.OUTPUTS
    One JSON line: { Ok; Fail; NoSource; Root } where each scenario carries
      err       the thrown message, or null
      robocopy  the argument list robocopy received (null if it never ran)
      mounted   the path Mount-VHD received (null if it never ran)
      dismounts how many times Dismount-VHD ran
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $LibPath)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:robocopyArgs = $null
$script:robocopyRc   = 1
$script:mounted      = $null
$script:dismounts    = 0

function Mount-VHD {
    [CmdletBinding()]
    param([string] $Path, [switch] $Passthru)
    $script:mounted = $Path
    return [pscustomobject]@{ Path = $Path }
}

function Get-Disk {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)] $InputObject)
    process { return [pscustomobject]@{ Number = 7 } }
}

function Get-Partition {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)] $InputObject, [int] $DiskNumber, [int] $PartitionNumber)
    process { return [pscustomobject]@{ Type = 'Basic'; DriveLetter = 'Q'; DiskNumber = 7; PartitionNumber = 2 } }
}

function Add-PartitionAccessPath {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)] $InputObject, [switch] $AssignDriveLetter)
    process { }
}

function Dismount-VHD {
    [CmdletBinding()]
    param([string] $Path)
    $script:dismounts++
}

function robocopy {
    $script:robocopyArgs = @($args | ForEach-Object { [string]$_ })
    $global:LASTEXITCODE = $script:robocopyRc
    'stub robocopy output'
}

. $LibPath
$b = New-RealHyperVBackend

$src = Join-Path ([System.IO.Path]::GetTempPath()) ("vs-copycap-{0}" -f ([guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path (Join-Path $src 'sub dir') -Force | Out-Null
Set-Content -LiteralPath (Join-Path $src 'sub dir\a.txt') -Value 'sample' -Encoding utf8

function Invoke-Scenario {
    param([string] $Source, [int] $Rc)
    $script:robocopyArgs = $null; $script:robocopyRc = $Rc; $script:mounted = $null; $script:dismounts = 0
    $err = $null
    try { $null = & $b.CopyDirectoryToVhdx @{ Path = 'C:\vs\data\corpus.vhdx'; SourceDir = $Source } }
    catch { $err = $_.Exception.Message }
    return [ordered]@{ err = $err; robocopy = $script:robocopyArgs; mounted = $script:mounted; dismounts = $script:dismounts }
}

try {
    $out = [ordered]@{
        Ok       = Invoke-Scenario -Source ($src + '\') -Rc 1
        Fail     = Invoke-Scenario -Source $src -Rc 8
        NoSource = Invoke-Scenario -Source (Join-Path $src 'missing') -Rc 0
        Root     = $src
    }
    $out | ConvertTo-Json -Depth 6 -Compress
}
finally {
    Remove-Item -LiteralPath $src -Recurse -Force -ErrorAction SilentlyContinue
}
