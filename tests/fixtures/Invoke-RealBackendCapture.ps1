<#
.SYNOPSIS
    Out-of-process capture harness for the REAL HyperVBackend method param-building logic.

.DESCRIPTION
    THE behavioral regression harness for a real-backend NewVHD bug found during live debugging (a differencing
    NewVHD call threw "required argument 'SizeBytes' is missing" because the real backend
    read its $P-derived args INSIDE the `& $InvokeOp { ... }` block — a cross-frame read that
    misfired). See tests/HyperVBackend.Tests.ps1 'Real backend — builds the right cmdlet
    params' for the full root-cause note.

    WHY A CHILD PROCESS: the real backend's methods are .GetNewClosure() scriptblocks that
    resolve their Hyper-V cmdlets (New-VHD / New-VM / New-VMSwitch / Set-VMProcessor / ...)
    against the SESSION STATE captured when New-RealHyperVBackend ran (the scope the lib was
    dot-sourced into). A shadow stub / Pester Mock installed in a TEST scope is NOT on that
    closure's command-resolution path, so it can't intercept the cmdlet (verified: both a
    Describe-scope `function New-VHD` and `Mock New-VHD` are bypassed and the real cmdlet runs,
    hitting the permission wall on a non-elevated host). The ONLY reliable interception is to
    define the shadow stub AND dot-source the lib in the SAME top-level script scope — which is
    exactly what THIS script does. The parent Pester test runs it in a child `pwsh` and asserts
    on the emitted JSON, so the REAL method body's param-building executes with NO live Hyper-V
    and NO elevation. This is the test that WOULD have caught the live bug (the in-process mock
    suite structurally could not — hence the mock tests stayed green while the real path was broken).

.PARAMETER LibPath
    Absolute path to scripts/lib/HyperVBackend.ps1.

.OUTPUTS
    A single-line JSON object on stdout:
      {
        "NewVHD_Diff":   { "err": <string|null>, "cap": { Path; SizeBytesGiven; SizeBytes; Differencing; ParentPath; Dynamic; Fixed } },
        "NewVHD_Fresh":  { ... },
        "NewVHD_Fixed":  { ... },
        "NewVM":         { "err": ...; "cap": { Name; GenerationGiven; Generation; MemoryGiven; MemoryStartupBytes; SwitchName; NoVHD } },
        "NewSwitch_Ext": { "err": ...; "cap": { Name; SwitchType; NetAdapterGiven; NetAdapterName } },
        "NewSwitch_Int": { ... },
        "SetProcessor":  { "err": ...; "cap": { VMName; CountGiven; Count; ExposeGiven; Expose } }
      }
    Each 'err' is $null on success or the thrown message; 'cap' is what the shadowed cmdlet recorded.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $LibPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Recording shadow stubs (defined at TOP-LEVEL script scope, BEFORE the dot-source, so the
#     backend closures capture THIS scope and resolve their cmdlet calls to these stubs). -------
$script:capNewVHD    = $null
$script:capNewVM     = $null
$script:capNewSwitch = $null
$script:capSetProc   = $null

function New-VHD {
    [CmdletBinding()]
    param([string] $Path, [long] $SizeBytes, [switch] $Differencing,
          [string] $ParentPath, [switch] $Dynamic, [switch] $Fixed)
    $script:capNewVHD = [ordered]@{
        Path           = $Path
        SizeBytesGiven = $PSBoundParameters.ContainsKey('SizeBytes')
        SizeBytes      = [long]$SizeBytes
        Differencing   = [bool]$Differencing
        ParentPath     = $ParentPath
        Dynamic        = [bool]$Dynamic
        Fixed          = [bool]$Fixed
    }
    return @{ Path = $Path }
}

function New-VM {
    [CmdletBinding()]
    param([string] $Name, [int] $Generation, [long] $MemoryStartupBytes,
          [string] $Path, [string] $SwitchName, [switch] $NoVHD)
    $script:capNewVM = [ordered]@{
        Name               = $Name
        GenerationGiven    = $PSBoundParameters.ContainsKey('Generation')
        Generation         = $Generation
        MemoryGiven        = $PSBoundParameters.ContainsKey('MemoryStartupBytes')
        MemoryStartupBytes = [long]$MemoryStartupBytes
        SwitchName         = $SwitchName
        NoVHD              = [bool]$NoVHD
    }
    return @{ Name = $Name }
}

function New-VMSwitch {
    [CmdletBinding()]
    param([string] $Name, [string] $SwitchType, [string] $NetAdapterName)
    $script:capNewSwitch = [ordered]@{
        Name            = $Name
        SwitchType      = $SwitchType
        SwitchTypeGiven = $PSBoundParameters.ContainsKey('SwitchType')
        NetAdapterName  = $NetAdapterName
        NetAdapterGiven = $PSBoundParameters.ContainsKey('NetAdapterName')
    }
    return @{ Name = $Name }
}

function Set-VMProcessor {
    [CmdletBinding()]
    param([string] $VMName, [int] $Count, [bool] $ExposeVirtualizationExtensions)
    $script:capSetProc = [ordered]@{
        VMName      = $VMName
        CountGiven  = $PSBoundParameters.ContainsKey('Count')
        Count       = $Count
        ExposeGiven = $PSBoundParameters.ContainsKey('ExposeVirtualizationExtensions')
        Expose      = [bool]$ExposeVirtualizationExtensions
    }
}

# Dot-source the lib INTO THIS top-level scope (so closures capture the stubs above).
. $LibPath
$b = New-RealHyperVBackend

# Helper: run one call, return @{ err = <msg|$null>; cap = <recorded capture> }.
# NB: the shadowed cmdlets return a value (New-VHD/New-VM/New-VMSwitch emit a record); route it
# to $null so ONLY the @{err;cap} hashtable lands on this function's output stream (otherwise the
# caller gets a 2-element array and the JSON nests as [returnValue, {err,cap}]).
function Invoke-Capture {
    param([scriptblock] $Call, [string] $CapVarName)
    Set-Variable -Name $CapVarName -Scope script -Value $null
    $err = $null
    try { & $Call | Out-Null } catch { $err = $_.Exception.Message }
    return @{ err = $err; cap = (Get-Variable -Name $CapVarName -Scope script -ValueOnly) }
}

$out = [ordered]@{
    NewVHD_Diff   = Invoke-Capture { & $b.NewVHD @{ Path = 'C:\sandbox\child.vhdx'; Differencing = $true; ParentPath = 'C:\sandbox\golden\debian-12-cloud.vhdx' } } 'capNewVHD'
    NewVHD_Fresh  = Invoke-Capture { & $b.NewVHD @{ Path = 'C:\sandbox\fresh.vhdx'; SizeBytes = 42949672960; Dynamic = $true } } 'capNewVHD'
    NewVHD_Fixed  = Invoke-Capture { & $b.NewVHD @{ Path = 'C:\sandbox\fixed.vhdx'; SizeBytes = 21474836480; Dynamic = $false } } 'capNewVHD'
    NewVM         = Invoke-Capture { & $b.NewVM @{ Name = 'vm1'; Generation = 2; MemoryStartupBytes = 4294967296; SwitchName = 'sw0'; NoVHD = $true } } 'capNewVM'
    NewSwitch_Ext = Invoke-Capture { & $b.NewSwitch @{ Name = 'extsw'; SwitchType = 'External'; NetAdapterName = 'Ethernet0' } } 'capNewSwitch'
    NewSwitch_Int = Invoke-Capture { & $b.NewSwitch @{ Name = 'intsw'; SwitchType = 'Internal' } } 'capNewSwitch'
    SetProcessor  = Invoke-Capture { & $b.SetProcessor @{ VMName = 'vm1'; Count = 2; ExposeVirtualizationExtensions = $true } } 'capSetProc'
}

$out | ConvertTo-Json -Depth 6 -Compress
