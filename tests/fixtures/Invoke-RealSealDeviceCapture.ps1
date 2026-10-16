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
$script:stubNicFail = $false
$script:capGetNicVM = $null
$script:capRemove   = [System.Collections.Generic.List[object]]::new()

# The OnOffState enum the real adapter object carries for MacAddressSpoofing, DhcpGuard and RouterGuard.
enum StubOnOff { Off = 0; On = 1 }

function Get-VMNetworkAdapter {
    [CmdletBinding()]
    param([string[]] $VMName)
    $script:capGetNicVM = $VMName
    if ($script:stubNicFail) { throw 'stub: simulated Get-VMNetworkAdapter failure' }
    foreach ($n in $script:stubNics) { $n }
}

# Set-VMNetworkAdapter stub for SetNetworkAdapterGuards: records the parameters it received.
$script:capSetNic = $null
function Set-VMNetworkAdapter {
    [CmdletBinding()]
    param([string[]] $VMName, [string] $MacAddressSpoofing, [string] $DhcpGuard, [string] $RouterGuard)
    $script:capSetNic = [ordered]@{ VMName = (@($VMName) -join ','); MacAddressSpoofing = $MacAddressSpoofing; DhcpGuard = $DhcpGuard; RouterGuard = $RouterGuard }
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

# Get-VMComPort stub for GetComPort (the COM1 liveness read and the COM2 refusal). It reports a failure
# the way a real cmdlet does, as a NON-terminating error, so -ErrorAction decides whether the caller sees
# it: under SilentlyContinue the read would come back empty, which is exactly the fail-open the real body
# must not have.
$script:stubComPorts  = @{}
$script:stubComFail   = $false
$script:capComRead    = $null
function Get-VMComPort {
    [CmdletBinding()]
    param([string[]] $VMName, [int] $Number)
    $script:capComRead = "$(@($VMName) -join ',')#$Number"
    if ($script:stubComFail) {
        $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new('stub: simulated Get-VMComPort failure'),
            'StubComPortFailure', [System.Management.Automation.ErrorCategory]::ReadError, $Number))
        return
    }
    [pscustomobject]@{ Number = $Number; Path = [string]$script:stubComPorts[$Number] }
}

# Get-VM stub for GetAutomaticCheckpoints: returns $script:stubVMs (zero, one or two objects), or reports a
# non-terminating error like a real cmdlet when $script:stubVMFail. The bare availability probe other
# methods make (no -Name) returns nothing.
$script:stubVMs    = @()
$script:stubVMFail = $false
function Get-VM {
    [CmdletBinding()]
    param([string[]] $Name)
    if (-not $PSBoundParameters.ContainsKey('Name')) { return }
    if ($script:stubVMFail) {
        $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new('stub: simulated Get-VM failure'),
            'StubGetVMFailure', [System.Management.Automation.ErrorCategory]::ReadError, $Name))
        return
    }
    foreach ($v in $script:stubVMs) { $v }
}

# Get-VMSnapshot stub for GetCheckpoint (the checkpoint refusal).
$script:stubSnaps    = @()
$script:stubSnapFail = $false
function Get-VMSnapshot {
    [CmdletBinding()]
    param([string[]] $VMName, [string] $Name)
    if ($script:stubSnapFail) {
        $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new('stub: simulated Get-VMSnapshot failure'),
            'StubSnapshotFailure', [System.Management.Automation.ErrorCategory]::ReadError, $VMName))
        return
    }
    foreach ($s in $script:stubSnaps) { $s }
}

. $LibPath
$b = New-RealHyperVBackend

function New-StubAdapter {
    param([string] $Id, [switch] $Guarded, [switch] $NoRouterGuard)
    $nic = [ordered]@{ Id = $Id; Name = 'Network Adapter'; SwitchName = $null }
    if ($Guarded) {
        $nic.MacAddressSpoofing = [StubOnOff]::Off
        $nic.DhcpGuard          = [StubOnOff]::On
        if (-not $NoRouterGuard) { $nic.RouterGuard = [StubOnOff]::On }
    }
    [pscustomobject]$nic
}

# Run the real SetNetworkAdapterGuards; report the error and what Set-VMNetworkAdapter received.
function Invoke-GuardSetScenario {
    param([string] $Spoof, [string] $Dhcp, [string] $Router)
    $script:capSetNic = $null
    $err = $null
    try { & $b.SetNetworkAdapterGuards @{ VMName = 'vm1'; MacAddressSpoofing = $Spoof; DhcpGuard = $Dhcp; RouterGuard = $Router } | Out-Null }
    catch { $err = $_.Exception.Message }
    return [ordered]@{ err = $err; called = ($null -ne $script:capSetNic); call = $script:capSetNic }
}

# Run the real GetNetworkAdapterGuards against the given stub adapters; report the record (and its value
# types) or the error.
function Invoke-GuardGetScenario {
    param([object[]] $Adapters, [switch] $Fail)
    $script:stubNics    = $Adapters
    $script:stubNicFail = $Fail.IsPresent
    $script:capGetNicVM = $null
    $err = $null; $r = $null
    try { $r = & $b.GetNetworkAdapterGuards @{ VMName = 'vm1' } } catch { $err = $_.Exception.Message }
    $script:stubNicFail = $false
    $types = $null
    if ($r -is [System.Collections.IDictionary]) {
        $types = @('MacAddressSpoofing', 'DhcpGuard', 'RouterGuard' | ForEach-Object { $r[$_].GetType().Name }) -join ','
    }
    return [ordered]@{ err = $err; queriedVM = (@($script:capGetNicVM) -join ','); result = $r; types = $types }
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

# Run the real GetComPort for one port number with the given stub paths; report the record or the error.
function Invoke-ComScenario {
    param([int] $Number, [hashtable] $Paths = @{}, [switch] $Fail)
    $script:stubComPorts = $Paths
    $script:stubComFail  = $Fail.IsPresent
    $script:capComRead   = $null
    $err = $null; $r = $null
    try { $r = & $b.GetComPort @{ VMName = 'vm1'; Number = $Number } } catch { $err = $_.Exception.Message }
    $script:stubComFail = $false
    return [ordered]@{
        err     = $err
        read    = $script:capComRead
        isNull  = ($null -eq $r)
        number  = if ($r -is [System.Collections.IDictionary]) { $r['Number'] } else { $null }
        path    = if ($r -is [System.Collections.IDictionary]) { $r['Path'] } else { $null }
    }
}

# Run the real GetAutomaticCheckpoints against the given stub VMs; report the value, its type, or the error.
function Invoke-AutoCpScenario {
    param([object[]] $VMs, [switch] $Fail)
    $script:stubVMs = $VMs; $script:stubVMFail = $Fail.IsPresent
    $err = $null; $r = $null
    try { $r = & $b.GetAutomaticCheckpoints @{ VMName = 'vm1' } } catch { $err = $_.Exception.Message }
    $script:stubVMFail = $false
    return [ordered]@{ err = $err; value = $r; isBool = ($r -is [bool]) }
}

# Run the real GetCheckpoint against the given stub snapshots; report array shape and count, or the error.
function Invoke-CpListScenario {
    param([object[]] $Snaps, [switch] $Fail)
    $script:stubSnaps = $Snaps; $script:stubSnapFail = $Fail.IsPresent
    $err = $null; $r = $null
    try { $r = & $b.GetCheckpoint @{ VMName = 'vm1' } } catch { $err = $_.Exception.Message }
    $script:stubSnapFail = $false
    return [ordered]@{ err = $err; isArray = ($r -is [array]); count = if ($r -is [array]) { $r.Count } else { -1 } }
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
    Guards_Set       = Invoke-GuardSetScenario -Spoof 'Off' -Dhcp 'On' -Router 'On'
    Guards_SetBad    = Invoke-GuardSetScenario -Spoof 'Off' -Dhcp 'On' -Router 'Maybe'
    Guards_GetOne    = Invoke-GuardGetScenario -Adapters @((New-StubAdapter 'nic-0' -Guarded))
    Guards_GetNone   = Invoke-GuardGetScenario -Adapters @()
    Guards_GetTwo    = Invoke-GuardGetScenario -Adapters @((New-StubAdapter 'nic-0' -Guarded), (New-StubAdapter 'nic-1' -Guarded))
    Guards_GetNoProp = Invoke-GuardGetScenario -Adapters @((New-StubAdapter 'nic-0' -Guarded -NoRouterGuard))
    Guards_GetFail   = Invoke-GuardGetScenario -Adapters @() -Fail
    Dda_None  = Invoke-ReadScenario -Method 'GetAssignableDevices' -Items @()
    Dda_One   = Invoke-ReadScenario -Method 'GetAssignableDevices' -Items @([pscustomobject]@{ LocationPath = 'PCIROOT(0)#PCI(0300)' })
    Com2_Empty = Invoke-ComScenario -Number 2 -Paths @{ 1 = '\\.\pipe\vm1-com1'; 2 = '' }
    Com2_Path  = Invoke-ComScenario -Number 2 -Paths @{ 1 = '\\.\pipe\vm1-com1'; 2 = '\\.\pipe\extra' }
    Com2_Fail  = Invoke-ComScenario -Number 2 -Fail
    Com1_Path  = Invoke-ComScenario -Number 1 -Paths @{ 1 = '\\.\pipe\vm1-com1' }
    AutoCp_Off     = Invoke-AutoCpScenario -VMs @([pscustomobject]@{ Name = 'vm1'; AutomaticCheckpointsEnabled = $false })
    AutoCp_On      = Invoke-AutoCpScenario -VMs @([pscustomobject]@{ Name = 'vm1'; AutomaticCheckpointsEnabled = $true })
    AutoCp_NoProp  = Invoke-AutoCpScenario -VMs @([pscustomobject]@{ Name = 'vm1' })
    AutoCp_String  = Invoke-AutoCpScenario -VMs @([pscustomobject]@{ Name = 'vm1'; AutomaticCheckpointsEnabled = 'False' })
    AutoCp_NoVM    = Invoke-AutoCpScenario -VMs @()
    AutoCp_TwoVMs  = Invoke-AutoCpScenario -VMs @([pscustomobject]@{ Name = 'vm1'; AutomaticCheckpointsEnabled = $false }, [pscustomobject]@{ Name = 'vm1'; AutomaticCheckpointsEnabled = $false })
    AutoCp_Fail    = Invoke-AutoCpScenario -VMs @() -Fail
    CpList_None    = Invoke-CpListScenario -Snaps @()
    CpList_One     = Invoke-CpListScenario -Snaps @([pscustomobject]@{ Name = 'cp-0' })
    CpList_Fail    = Invoke-CpListScenario -Snaps @() -Fail
}

$out | ConvertTo-Json -Depth 6 -Compress
