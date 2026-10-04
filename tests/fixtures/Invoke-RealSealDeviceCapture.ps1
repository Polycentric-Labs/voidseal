<#
.SYNOPSIS
    Out-of-process capture harness that EXECUTES the real backend's seal-device methods against
    recording stub cmdlets: RemoveNetworkAdapter, ConnectNetworkAdapter, GetGpuPartitionAdapters and
    GetAssignableDevices.

.DESCRIPTION
    The real backend's methods are .GetNewClosure() scriptblocks that resolve their Hyper-V cmdlets
    against the session state captured when New-RealHyperVBackend ran, so a Pester Mock or a
    test-scope shadow function cannot intercept them (Invoke-RealBackendCapture.ps1 carries the full
    note). This script defines the stubs and dot-sources the lib in the SAME top-level scope, so the
    REAL method bodies run against the stubs with no live Hyper-V and no elevation. The parent Pester
    test runs it in a child pwsh and asserts on the single JSON line it prints.

    RemoveNetworkAdapter is the seal operation for every NoAdapter VM and has never run live. Its
    scenarios prove the body enumerates the adapters, pipes each one to Remove-VMNetworkAdapter, never
    names the VM on the removal, and does nothing when the VM has no adapter.

    ConnectNetworkAdapter probes for an adapter, connects by VM name when one exists, and adds one
    only when the VM has none. Real New-VM always leaves one adapter, so production takes the connect
    branch. Both branches run here.

    GetGpuPartitionAdapters and GetAssignableDevices are the read-only passthrough checks behind the
    seal gate. Each scenario calls the real body with 0, 1 or 2 stub devices and does NOT wrap the
    result in @(), exactly like Assert-Sealed, so a single device that unrolled to a bare object across
    the call boundaries would show as isArray = false. Each stub records the -VMName it received so
    the tests can assert the body queries the VM it was asked about. A throwing stub proves a failing cmdlet reaches
    the caller as a throw, which the gate turns into a refusal.

.PARAMETER LibPath
    Absolute path to scripts/lib/HyperVBackend.ps1.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $LibPath)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Recording stubs (top-level script scope, defined BEFORE the dot-source so the closures resolve
#     their cmdlet calls to these) --------------------------------------------------------------
$script:stubNics    = @()
$script:capGetNicVM = $null
$script:capRemove   = [System.Collections.Generic.List[object]]::new()

function Get-VMNetworkAdapter {
    [CmdletBinding()]
    param([string[]] $VMName)
    $script:capGetNicVM = $VMName
    foreach ($n in $script:stubNics) { $n }
}

function Remove-VMNetworkAdapter {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] $VMNetworkAdapter,
        [string[]] $VMName,
        [string] $Name
    )
    process {
        $script:capRemove.Add([ordered]@{
            AdapterId   = if ($null -ne $VMNetworkAdapter) { [string]$VMNetworkAdapter.Id } else { $null }
            VMNameGiven = $PSBoundParameters.ContainsKey('VMName')
        })
    }
}

$script:capConnect = [System.Collections.Generic.List[object]]::new()
$script:capAdd     = [System.Collections.Generic.List[object]]::new()

function Connect-VMNetworkAdapter {
    [CmdletBinding()]
    param([string[]] $VMName, [string] $SwitchName, [string[]] $Name)
    $script:capConnect.Add([ordered]@{ VMName = (@($VMName) -join ','); SwitchName = $SwitchName })
}

function Add-VMNetworkAdapter {
    [CmdletBinding()]
    param([string[]] $VMName, [string] $SwitchName)
    $script:capAdd.Add([ordered]@{ VMName = (@($VMName) -join ','); SwitchName = $SwitchName })
}

$script:stubGpu      = @()
$script:stubDda      = @()
$script:stubGpuThrow = $false
$script:capReadVM    = $null

function Get-VMGpuPartitionAdapter {
    [CmdletBinding()]
    param([string[]] $VMName)
    $script:capReadVM = $VMName
    if ($script:stubGpuThrow) { throw 'stub: simulated Get-VMGpuPartitionAdapter failure' }
    foreach ($g in $script:stubGpu) { $g }
}

function Get-VMAssignableDevice {
    [CmdletBinding()]
    param([string[]] $VMName)
    $script:capReadVM = $VMName
    foreach ($d in $script:stubDda) { $d }
}

. $LibPath
$b = New-RealHyperVBackend

function New-StubAdapter {
    param([string] $Id)
    [pscustomobject]@{ Id = $Id; Name = 'Network Adapter'; SwitchName = $null }
}

# Run the real RemoveNetworkAdapter with the given stub adapters; report the error, which VM the
# enumeration asked for, every adapter the removal received, and whether any removal named the VM.
function Invoke-RemoveScenario {
    param([object[]] $Adapters)
    $script:stubNics    = $Adapters
    $script:capGetNicVM = $null
    $script:capRemove   = [System.Collections.Generic.List[object]]::new()
    $err = $null
    try { & $b.RemoveNetworkAdapter @{ VMName = 'vm1' } | Out-Null } catch { $err = $_.Exception.Message }
    return [ordered]@{
        err          = $err
        enumeratedVM = (@($script:capGetNicVM) -join ',')
        removed      = @($script:capRemove | ForEach-Object { $_.AdapterId })
        anyByVMName  = [bool](@($script:capRemove | Where-Object { $_.VMNameGiven }).Count)
    }
}

# Run the real ConnectNetworkAdapter with the given stub adapters; report which branch it took.
function Invoke-ConnectScenario {
    param([object[]] $Adapters)
    $script:stubNics   = $Adapters
    $script:capConnect = [System.Collections.Generic.List[object]]::new()
    $script:capAdd     = [System.Collections.Generic.List[object]]::new()
    $err = $null
    try { & $b.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw0' } | Out-Null } catch { $err = $_.Exception.Message }
    return [ordered]@{
        err       = $err
        connected = @($script:capConnect | ForEach-Object { "$($_.VMName)>$($_.SwitchName)" })
        added     = @($script:capAdd     | ForEach-Object { "$($_.VMName)>$($_.SwitchName)" })
    }
}

# Run one real passthrough read with the given stub items. The caller does NOT wrap the result in
# @(), exactly like Assert-Sealed, so 'isArray' proves the comma-wrap survived both & boundaries.
# 'queriedVM' is the -VMName the stub cmdlet received, proving the body asks about the VM it was given.
function Invoke-ReadScenario {
    param([string] $Method, [object[]] $Items, [switch] $Throw)
    $script:stubGpu      = @()
    $script:stubDda      = @()
    $script:stubGpuThrow = $Throw.IsPresent
    $script:capReadVM    = $null
    if ($Method -eq 'GetGpuPartitionAdapters') { $script:stubGpu = $Items } else { $script:stubDda = $Items }
    $err = $null; $r = $null
    try { $r = & $b.$Method @{ VMName = 'vm1' } } catch { $err = $_.Exception.Message }
    return [ordered]@{
        err       = $err
        queriedVM = (@($script:capReadVM) -join ',')
        isArray   = ($r -is [array])
        count     = if ($r -is [array]) { $r.Count } else { -1 }
    }
}

$out = [ordered]@{
    Remove_None = Invoke-RemoveScenario -Adapters @()
    Remove_One  = Invoke-RemoveScenario -Adapters @((New-StubAdapter 'nic-0'))
    Remove_Two  = Invoke-RemoveScenario -Adapters @((New-StubAdapter 'nic-0'), (New-StubAdapter 'nic-1'))
    Connect_Default = Invoke-ConnectScenario -Adapters @((New-StubAdapter 'nic-0'))
    Connect_None    = Invoke-ConnectScenario -Adapters @()
    Gpu_None  = Invoke-ReadScenario -Method 'GetGpuPartitionAdapters' -Items @()
    Gpu_One   = Invoke-ReadScenario -Method 'GetGpuPartitionAdapters' -Items @([pscustomobject]@{ Id = 'gpu-p-0' })
    Gpu_Two   = Invoke-ReadScenario -Method 'GetGpuPartitionAdapters' -Items @([pscustomobject]@{ Id = 'gpu-p-0' }, [pscustomobject]@{ Id = 'gpu-p-1' })
    Gpu_Throw = Invoke-ReadScenario -Method 'GetGpuPartitionAdapters' -Items @() -Throw
    Dda_None  = Invoke-ReadScenario -Method 'GetAssignableDevices' -Items @()
    Dda_One   = Invoke-ReadScenario -Method 'GetAssignableDevices' -Items @([pscustomobject]@{ LocationPath = 'PCIROOT(0)#PCI(0300)' })
}

$out | ConvertTo-Json -Depth 6 -Compress
