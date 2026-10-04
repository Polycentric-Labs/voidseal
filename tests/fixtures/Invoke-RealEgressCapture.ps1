<#
.SYNOPSIS
    Out-of-process capture harness that EXECUTES the real backend's host-egress methods (EgressMode
    'HostProxy') against recording stub cmdlets, and the real proxy start/stop against a stub child
    process.

.DESCRIPTION
    The real backend's methods are .GetNewClosure() scriptblocks that resolve their cmdlets against the
    session state captured when New-RealHyperVBackend ran, so a Pester Mock cannot intercept them
    (Invoke-RealBackendCapture.ps1 carries the full note). This script defines the stubs and dot-sources
    the lib in the SAME top-level scope, so the REAL bodies run against the stubs with no live host
    network change, no Hyper-V and no elevation. The parent Pester test (tests/EgressBackend.Tests.ps1)
    runs it in a child pwsh and asserts on the single JSON line it prints.

    The stubs model the real objects' awkward parts on purpose: the firewall rule's Enabled, Action and
    Direction are enums (Enabled's 'False' member is truthy under a [bool] cast, the CIM trap), an
    unset address or port reads back as 'Any', a missing rule is an ObjectNotFound error, an unreadable
    one is a ReadError, and every cmdlet reports failure as a NON-terminating error so -ErrorAction
    decides whether the caller sees it.

    StartEgressProxy and StopEgressProxy run no cmdlet, so they run for real here: the harness starts
    tests/fixtures/egress_proxy_stub.py (which opens no socket) with the given Python and drives the
    ready, early-exit, never-ready, wrong-pid, stop, kill and PID-reuse paths.

.PARAMETER LibPath
    Absolute path to scripts/lib/HyperVBackend.ps1.
.PARAMETER PythonExe
    The host Python used to run the stub child process.
.PARAMETER WorkDir
    A scratch directory for the ready and stop files.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $LibPath,
    [Parameter(Mandatory)] [string] $PythonExe,
    [Parameter(Mandatory)] [string] $WorkDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

enum StubEnabled   { True = 1; False = 2 }
enum StubFwAction  { NotConfigured = 0; Allow = 2; Block = 4 }
enum StubDirection { Inbound = 1; Outbound = 2 }
enum StubAclAction { Allow = 1; Deny = 2 }

function Write-StubError {
    param($Cmdlet, [string] $Message, [System.Management.Automation.ErrorCategory] $Category, $Target)
    $Cmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
        [System.InvalidOperationException]::new($Message), 'StubFailure', $Category, $Target))
}

# --- Recording stubs (defined BEFORE the dot-source so the closures resolve to these) ---------------
$script:cap = [ordered]@{}
$script:stubIPs = @()
$script:stubIPFail = $false
function Get-NetIPAddress {
    [CmdletBinding()]
    param([string] $AddressFamily, [string[]] $InterfaceAlias, [string[]] $IPAddress)
    $script:cap['GetIP_Family'] = $AddressFamily
    if ($script:stubIPFail) { Write-StubError $PSCmdlet 'stub: Get-NetIPAddress failed' 'ReadError' $null; return }
    foreach ($a in $script:stubIPs) { $a }
}
function New-NetIPAddress {
    [CmdletBinding()]
    param([string] $InterfaceAlias, [string] $IPAddress, [byte] $PrefixLength, [string] $AddressFamily, [string] $PolicyStore)
    $script:cap['NewIP'] = [ordered]@{ InterfaceAlias = $InterfaceAlias; IPAddress = $IPAddress; PrefixLength = [int]$PrefixLength
                                       AddressFamily = $AddressFamily; PolicyStore = $PolicyStore }
    [pscustomobject]@{ IPAddress = $IPAddress }    # the real cmdlet emits the new address objects
}
function Remove-NetIPAddress {
    [CmdletBinding(SupportsShouldProcess)]
    param([string] $InterfaceAlias, [string] $IPAddress)
    $script:cap['RemoveIP'] = "$InterfaceAlias|$IPAddress"
}

$script:stubRules = @{}
$script:stubRuleReadFail = $false
function New-NetFirewallRule {
    [CmdletBinding()]
    param([string] $Name, [string] $DisplayName, [string] $Group, [string] $Direction, [string] $Action, [string] $Protocol,
          [string[]] $LocalAddress, [string[]] $RemoteAddress, [string[]] $LocalPort, [string[]] $InterfaceAlias,
          [string] $Profile, [string] $Enabled)
    $rec = [ordered]@{}
    foreach ($k in $PSBoundParameters.Keys) { $rec[$k] = $PSBoundParameters[$k] }
    $script:cap['NewRule_' + $Name] = $rec
    [pscustomobject]@{ Name = $Name }
}
function Get-NetFirewallRule {
    [CmdletBinding()]
    param([string[]] $Name)
    if ($script:stubRuleReadFail) { Write-StubError $PSCmdlet 'stub: firewall service unreadable' 'ReadError' $Name; return }
    $n = @($Name)[0]
    if (-not $script:stubRules.ContainsKey($n)) {
        Write-StubError $PSCmdlet "No MSFT_NetFirewallRule objects found with property 'Name' equal to '$n'." 'ObjectNotFound' $n
        return
    }
    foreach ($r in @($script:stubRules[$n])) { $r.Rule }
}
function Get-NetFirewallPortFilter      { [CmdletBinding()] param($AssociatedNetFirewallRule) $script:stubRules[$AssociatedNetFirewallRule.Name].Port }
function Get-NetFirewallAddressFilter   { [CmdletBinding()] param($AssociatedNetFirewallRule) $script:stubRules[$AssociatedNetFirewallRule.Name].Address }
function Get-NetFirewallInterfaceFilter { [CmdletBinding()] param($AssociatedNetFirewallRule) $script:stubRules[$AssociatedNetFirewallRule.Name].Iface }
function Remove-NetFirewallRule {
    [CmdletBinding()]
    param([string[]] $Name)
    $script:cap['RemoveRule'] = @($Name) -join ','
}

$script:stubAcls = @()
$script:stubAclFail = $false
$script:stubVMPresent = $true
function Add-VMNetworkAdapterExtendedAcl {
    [CmdletBinding()]
    param([string[]] $VMName, [string] $Action, [string] $Direction, [int] $Weight, [string] $Protocol,
          [string] $LocalIPAddress, [string] $RemoteIPAddress, [string] $RemotePort, [bool] $Stateful)
    $rec = [ordered]@{}
    foreach ($k in $PSBoundParameters.Keys) { $rec[$k] = if ($PSBoundParameters[$k] -is [array]) { @($PSBoundParameters[$k]) -join ',' } else { $PSBoundParameters[$k] } }
    $script:cap['AddAcl_' + $Direction + '_' + $Weight] = $rec
}
function Get-VMNetworkAdapterExtendedAcl {
    [CmdletBinding()]
    param([string[]] $VMName)
    $script:cap['GetAcl_VM'] = @($VMName) -join ','
    if ($script:stubAclFail) { Write-StubError $PSCmdlet 'stub: ACL read failed' 'ReadError' $VMName; return }
    foreach ($a in $script:stubAcls) { $a }
}
function Remove-VMNetworkAdapterExtendedAcl {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)] $VMNetworkAdapterExtendedAcl)
    process { $script:cap['RemovedAcls'] = @(@($script:cap['RemovedAcls']) | Where-Object { $_ }) + "$($VMNetworkAdapterExtendedAcl.Direction)/$($VMNetworkAdapterExtendedAcl.Weight)" }
}
function Get-VM {
    [CmdletBinding()]
    param([string[]] $Name)
    if (-not $PSBoundParameters.ContainsKey('Name')) { return }
    if ($script:stubVMPresent) { [pscustomobject]@{ Name = @($Name)[0] } }
}

$script:stubNats = @()
$script:stubNatFail = $false
function Get-NetNat {
    [CmdletBinding()]
    param()
    if ($script:stubNatFail) { Write-StubError $PSCmdlet 'stub: WinNAT unreadable' 'ReadError' $null; return }
    foreach ($n in $script:stubNats) { $n }
}

. $LibPath
$b = New-RealHyperVBackend

function Invoke-Capture {
    param([scriptblock] $Body)
    $script:cap = [ordered]@{}
    $err = $null; $r = $null
    try { $r = & $Body } catch { $err = $_.Exception.Message }
    return @{ err = $err; result = $r; cap = $script:cap }
}

$out = [ordered]@{}

# ---- GetHostIPAddresses -------------------------------------------------------------------------------
$script:stubIPs = @(
    [pscustomobject]@{ IPAddress = '192.168.1.20'; PrefixLength = [byte]24; InterfaceAlias = 'Ethernet' },
    [pscustomobject]@{ IPAddress = '10.231.0.1';  PrefixLength = [byte]30; InterfaceAlias = 'vEthernet (sbx-int)' })
$c = Invoke-Capture { & $b.GetHostIPAddresses @{} }
$out.IP_Two = [ordered]@{ err = $c.err; family = $c.cap['GetIP_Family']; isArray = ($c.result -is [array]); count = @($c.result).Count
                          second = if ($c.result -is [array] -and $c.result.Count -eq 2) { $c.result[1] } else { $null }
                          prefixType = if ($c.result -is [array] -and $c.result.Count -eq 2) { $c.result[1].PrefixLength.GetType().Name } else { $null } }
$script:stubIPs = @([pscustomobject]@{ IPAddress = '192.168.1.20'; PrefixLength = [byte]24; InterfaceAlias = 'Ethernet' })
$c = Invoke-Capture { & $b.GetHostIPAddresses @{} }
$out.IP_One = [ordered]@{ err = $c.err; isArray = ($c.result -is [array]); count = @($c.result).Count }
$script:stubIPFail = $true
$c = Invoke-Capture { & $b.GetHostIPAddresses @{} }
$out.IP_Fail = [ordered]@{ err = $c.err }
$script:stubIPFail = $false

# ---- Add / Remove the gateway address ----------------------------------------------------------------
$c = Invoke-Capture { & $b.AddSwitchHostIPAddress @{ SwitchName = 'sbx-int'; IPAddress = '10.231.0.1'; PrefixLength = 30 } }
$out.AddIP = [ordered]@{ err = $c.err; leaked = ($null -ne $c.result); call = $c.cap['NewIP'] }
$script:stubIPs = @([pscustomobject]@{ IPAddress = '10.231.0.1'; PrefixLength = [byte]30; InterfaceAlias = 'vEthernet (sbx-int)' })
$c = Invoke-Capture { & $b.RemoveSwitchHostIPAddress @{ SwitchName = 'sbx-int'; IPAddress = '10.231.0.1' } }
$out.RemoveIP_Present = [ordered]@{ err = $c.err; removed = $c.cap['RemoveIP'] }
$script:stubIPs = @()
$c = Invoke-Capture { & $b.RemoveSwitchHostIPAddress @{ SwitchName = 'sbx-int'; IPAddress = '10.231.0.1' } }
$out.RemoveIP_Absent = [ordered]@{ err = $c.err; removed = $c.cap['RemoveIP'] }

# ---- firewall rules ---------------------------------------------------------------------------------
$c = Invoke-Capture { & $b.NewHostFirewallRule @{ Name = 'Voidseal-sbx-allow-proxy'; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'
                                                   LocalAddress = @('10.231.0.1'); LocalPort = @('13128'); RemoteAddress = @('10.231.0.2')
                                                   InterfaceAlias = 'vEthernet (sbx-int)' } }
$out.NewRule_Allow = [ordered]@{ err = $c.err; leaked = ($null -ne $c.result); call = $c.cap['NewRule_Voidseal-sbx-allow-proxy'] }
$c = Invoke-Capture { & $b.NewHostFirewallRule @{ Name = 'Voidseal-sbx-block-udp'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'
                                                   LocalAddress = @('Any'); LocalPort = @('Any'); RemoteAddress = @('Any')
                                                   InterfaceAlias = 'vEthernet (sbx-int)' } }
$out.NewRule_AnyFilters = [ordered]@{ err = $c.err; keys = @($c.cap['NewRule_Voidseal-sbx-block-udp'].Keys) }

$script:stubRules['Voidseal-sbx-allow-proxy'] = @{
    Rule    = [pscustomobject]@{ Name = 'Voidseal-sbx-allow-proxy'; Enabled = [StubEnabled]::False; Direction = [StubDirection]::Inbound; Action = [StubFwAction]::Allow }
    Port    = [pscustomobject]@{ Protocol = 'TCP'; LocalPort = '13128' }
    Address = [pscustomobject]@{ LocalAddress = '10.231.0.1'; RemoteAddress = '10.231.0.2' }
    Iface   = [pscustomobject]@{ InterfaceAlias = 'vEthernet (sbx-int)' }
}
$script:stubRules['Voidseal-sbx-block-tcp'] = @{
    Rule    = [pscustomobject]@{ Name = 'Voidseal-sbx-block-tcp'; Enabled = [StubEnabled]::True; Direction = [StubDirection]::Inbound; Action = [StubFwAction]::Block }
    Port    = [pscustomobject]@{ Protocol = 'TCP'; LocalPort = @('1-13127', '13129-65535') }
    Address = [pscustomobject]@{ LocalAddress = 'Any'; RemoteAddress = 'Any' }
    Iface   = [pscustomobject]@{ InterfaceAlias = @('vEthernet (sbx-int)') }
}
$c = Invoke-Capture { & $b.GetHostFirewallRule @{ Name = 'Voidseal-sbx-allow-proxy' } }
$out.GetRule_DisabledAllow = [ordered]@{ err = $c.err; rule = $c.result; enabledType = if ($c.result) { $c.result.Enabled.GetType().Name } else { $null } }
$c = Invoke-Capture { & $b.GetHostFirewallRule @{ Name = 'Voidseal-sbx-block-tcp' } }
$out.GetRule_Block = [ordered]@{ err = $c.err; rule = $c.result }
$c = Invoke-Capture { & $b.GetHostFirewallRule @{ Name = 'Voidseal-sbx-missing' } }
$out.GetRule_Missing = [ordered]@{ err = $c.err; isNull = ($null -eq $c.result) }
$script:stubRuleReadFail = $true
$c = Invoke-Capture { & $b.GetHostFirewallRule @{ Name = 'Voidseal-sbx-allow-proxy' } }
$out.GetRule_Fail = [ordered]@{ err = $c.err }
$c = Invoke-Capture { & $b.RemoveHostFirewallRule @{ Name = 'Voidseal-sbx-allow-proxy' } }
$out.RemoveRule_Fail = [ordered]@{ err = $c.err; removed = $c.cap['RemoveRule'] }
$script:stubRuleReadFail = $false
$c = Invoke-Capture { & $b.RemoveHostFirewallRule @{ Name = 'Voidseal-sbx-allow-proxy' } }
$out.RemoveRule_Present = [ordered]@{ err = $c.err; removed = $c.cap['RemoveRule'] }
$c = Invoke-Capture { & $b.RemoveHostFirewallRule @{ Name = 'Voidseal-sbx-missing' } }
$out.RemoveRule_Missing = [ordered]@{ err = $c.err; removed = $c.cap['RemoveRule'] }

# ---- port ACLs -----------------------------------------------------------------------------------------
$c = Invoke-Capture { & $b.AddNetworkAdapterAcl @{ VMName = 'sbx'; Action = 'Allow'; Direction = 'Outbound'; Weight = 100; Protocol = 'TCP'
                                                    LocalIPAddress = '10.231.0.2'; RemoteIPAddress = '10.231.0.1'; RemotePort = '13128'; Stateful = $true } }
$out.AddAcl_Allow = [ordered]@{ err = $c.err; leaked = ($null -ne $c.result); call = $c.cap['AddAcl_Outbound_100'] }
$c = Invoke-Capture { & $b.AddNetworkAdapterAcl @{ VMName = 'sbx'; Action = 'Deny'; Direction = 'Inbound'; Weight = 1; Protocol = 'Any'
                                                    LocalIPAddress = 'Any'; RemoteIPAddress = 'Any'; RemotePort = 'Any'; Stateful = $false } }
$out.AddAcl_DenyAll = [ordered]@{ err = $c.err; call = $c.cap['AddAcl_Inbound_1'] }

$script:stubAcls = @(
    [pscustomobject]@{ Action = [StubAclAction]::Deny; Direction = [StubDirection]::Inbound; Weight = 1; Protocol = ''; LocalIPAddress = ''; RemoteIPAddress = 'ANY'; RemotePort = $null; Stateful = $false })
$c = Invoke-Capture { & $b.GetNetworkAdapterAcls @{ VMName = 'sbx' } }
$out.GetAcls_One = [ordered]@{ err = $c.err; vm = $c.cap['GetAcl_VM']; isArray = ($c.result -is [array]); count = @($c.result).Count
                               first = if ($c.result -is [array] -and $c.result.Count -ge 1) { $c.result[0] } else { $null } }
$script:stubAcls = @(
    [pscustomobject]@{ Action = [StubAclAction]::Allow; Direction = [StubDirection]::Outbound; Weight = 100; Protocol = 'TCP'; LocalIPAddress = '10.231.0.2'; RemoteIPAddress = '10.231.0.1'; RemotePort = '13128'; Stateful = $true },
    [pscustomobject]@{ Action = [StubAclAction]::Deny; Direction = [StubDirection]::Outbound; Weight = 1; Protocol = ''; LocalIPAddress = ''; RemoteIPAddress = ''; RemotePort = ''; Stateful = $false })
$c = Invoke-Capture { & $b.GetNetworkAdapterAcls @{ VMName = 'sbx' } }
$out.GetAcls_Two = [ordered]@{ err = $c.err; count = @($c.result).Count; first = if ($c.result -is [array]) { $c.result[0] } else { $null } }
$script:stubAclFail = $true
$c = Invoke-Capture { & $b.GetNetworkAdapterAcls @{ VMName = 'sbx' } }
$out.GetAcls_Fail = [ordered]@{ err = $c.err }
$script:stubAclFail = $false
$c = Invoke-Capture { & $b.RemoveNetworkAdapterAcl @{ VMName = 'sbx'; Action = 'Deny'; Direction = 'Outbound'; Weight = 1 } }
$out.RemoveAcl_Match = [ordered]@{ err = $c.err; removed = @($c.cap['RemovedAcls'] | Where-Object { $_ }) }
$script:stubVMPresent = $false
$c = Invoke-Capture { & $b.RemoveNetworkAdapterAcl @{ VMName = 'sbx'; Action = 'Deny'; Direction = 'Outbound'; Weight = 1 } }
$out.RemoveAcl_NoVM = [ordered]@{ err = $c.err; read = $c.cap['GetAcl_VM']; removed = @($c.cap['RemovedAcls'] | Where-Object { $_ }) }
$script:stubVMPresent = $true

# ---- NAT ---------------------------------------------------------------------------------------------
$script:stubNats = @()
$c = Invoke-Capture { & $b.GetNetNats @{} }
$out.Nat_None = [ordered]@{ err = $c.err; isArray = ($c.result -is [array]); count = @($c.result).Count }
$script:stubNats = @([pscustomobject]@{ Name = 'DockerNAT'; InternalIPInterfaceAddressPrefix = '10.231.0.0/24' })
$c = Invoke-Capture { & $b.GetNetNats @{} }
$out.Nat_One = [ordered]@{ err = $c.err; isArray = ($c.result -is [array]); count = @($c.result).Count; first = if ($c.result -is [array]) { $c.result[0] } else { $null } }
$script:stubNatFail = $true
$c = Invoke-Capture { & $b.GetNetNats @{} }
$out.Nat_Fail = [ordered]@{ err = $c.err }
$script:stubNatFail = $false

# ---- the proxy process (a real child: the stub script, which opens no socket) -----------------------
$stubScript = Join-Path $PSScriptRoot 'egress_proxy_stub.py'
function Invoke-Start {
    param([string[]] $Extra, [double] $Timeout = 15)
    $ready = Join-Path $WorkDir ("ready-{0}.json" -f [guid]::NewGuid().ToString('N'))
    $stop  = Join-Path $WorkDir ("stop-{0}" -f [guid]::NewGuid().ToString('N'))
    $argv = @('--listen-host', '10.231.0.1', '--ready-file', $ready, '--stop-file', $stop, '--allow', 'api.example.com') + $Extra
    $err = $null; $r = $null
    try { $r = & $b.StartEgressProxy @{ PythonExe = $PythonExe; ScriptPath = $stubScript; Arguments = $argv; ReadyFile = $ready; ReadyTimeoutSeconds = $Timeout } }
    catch { $err = $_.Exception.Message }
    return @{ err = $err; result = $r; stop = $stop }
}
function Test-Alive { param([int] $Id) try { $null = [System.Diagnostics.Process]::GetProcessById($Id); return $true } catch { return $false } }

$s = Invoke-Start
$procId = if ($s.result) { [int]$s.result.ProcessId } else { 0 }
$out.Start_Ok = [ordered]@{ err = $s.err; hasPid = ($procId -gt 0); alive = ($procId -gt 0 -and (Test-Alive $procId))
                            commandLine = if ($s.result) { $s.result.CommandLine } else { $null }
                            startTime = if ($s.result) { $s.result.StartTime } else { $null } }
if ($procId -gt 0) {
    $wrong = & $b.StopEgressProxy @{ ProcessId = $procId; StartTime = '2001-01-01T00:00:00.0000000Z'; StopFile = $s.stop; TimeoutSeconds = 5 }
    $out.Stop_WrongStartTime = [ordered]@{ result = $wrong; stillAlive = (Test-Alive $procId); stopFileWritten = (Test-Path -LiteralPath $s.stop) }
    $good = & $b.StopEgressProxy @{ ProcessId = $procId; StartTime = $s.result.StartTime; StopFile = $s.stop; TimeoutSeconds = 15 }
    Start-Sleep -Milliseconds 200
    $out.Stop_Ok = [ordered]@{ result = $good; alive = (Test-Alive $procId) }
    $again = & $b.StopEgressProxy @{ ProcessId = $procId; StartTime = $s.result.StartTime; StopFile = $s.stop; TimeoutSeconds = 5 }
    $out.Stop_Again = [ordered]@{ result = $again }
}
$s = Invoke-Start -Extra @('--ignore-stop')
if ($s.result) {
    $k = & $b.StopEgressProxy @{ ProcessId = [int]$s.result.ProcessId; StartTime = $s.result.StartTime; StopFile = $s.stop; TimeoutSeconds = 1 }
    Start-Sleep -Milliseconds 200
    $out.Stop_Kill = [ordered]@{ result = $k; alive = (Test-Alive ([int]$s.result.ProcessId)) }
}
else { $out.Stop_Kill = [ordered]@{ startErr = $s.err } }
$s = Invoke-Start -Extra @('--exit-early')
$out.Start_ExitEarly = [ordered]@{ err = $s.err; result = $s.result }
$s = Invoke-Start -Extra @('--never-ready') -Timeout 1.5
$out.Start_NeverReady = [ordered]@{ err = $s.err; result = $s.result }
$s = Invoke-Start -Extra @('--wrong-pid')
$out.Start_WrongPid = [ordered]@{ err = $s.err; result = $s.result }
$err = $null
try { $null = & $b.StartEgressProxy @{ PythonExe = $PythonExe; ScriptPath = (Join-Path $WorkDir 'no-such-proxy.py'); Arguments = @(); ReadyFile = (Join-Path $WorkDir 'r.json') } }
catch { $err = $_.Exception.Message }
$out.Start_NoScript = [ordered]@{ err = $err }

$out | ConvertTo-Json -Depth 8 -Compress
