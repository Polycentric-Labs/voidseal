<#
.SYNOPSIS
    Voidseal host egress for EgressMode 'HostProxy': addressing, host enforcement, the proxy, teardown
    and the seal-gate checks.

.DESCRIPTION
    A Tier-1 VM whose profile sets EgressMode='HostProxy' reaches the outside world through exactly one
    door: an HTTPS CONNECT allowlist proxy the HOST runs (scripts/egress/voidseal_egress_proxy.py), bound
    to a gateway address on the VM's own Internal switch. There is no NAT, no route and no resolver for
    the guest. Three host controls close everything else, each through the backend seam:

      * the gateway address on "vEthernet (<switch>)" (AddSwitchHostIPAddress), so the host answers on
        the VM's /30 and nowhere else on it;
      * host firewall rules scoped to that interface (NewHostFirewallRule): allow inbound TCP to the
        proxy port on the gateway from the guest address only, block every other inbound path from the
        switch. Windows Firewall lets a Block rule beat any Allow, so the blocks are shaped around the
        one allowed tuple rather than as a blanket "block all";
      * an extended port ACL on the VM's adapter (AddNetworkAdapterAcl): deny all in and out, allow
        (stateful) TCP from the guest address to the gateway's proxy port. It runs at the vSwitch port,
        before the host stack sees a packet, so a guest must defeat two independent controls.

    The firewall rules are a control only while Windows Firewall is enforcing them, so the seal gate also
    reads the firewall profiles (GetHostFirewallProfiles: every profile enabled, default inbound action
    Block) and the gateway interface's IP forwarding (GetNetIPInterfaceForwarding: off for both families,
    so the host cannot route between the VM subnet and its other interfaces). Until 2026-10-16 neither was
    read, and "two independent controls" held only by assumption.

    ADDRESSING. Each VM gets a deterministic /30 inside 10.231.0.0/16: the slot is the first two bytes
    of SHA-256(lowercase VM name) modulo 16384. Gateway = network + 1, guest = network + 2. Before
    anything is created the plan is checked against every IPv4 address the host already has and every
    NAT network; any overlap is a refusal (fail closed), never a silent pick of another slot, so the
    address a VM gets is always the one its name implies.

    ORDER (Invoke-Voidseal): New-SandboxVM computes and checks the plan and records it on the descriptor;
    the seed carries the guest's static address; Lock-Sandbox installs the gateway address, firewall
    rules and ACL (Install-SandboxEgressNetwork) and records each one as it is created; Assert-Sealed
    reads them back (Assert-SandboxEgressSealed); only then does the orchestrator start the proxy
    (Start-SandboxEgressProxy) and the VM. Remove-Sandbox removes exactly what the descriptor records
    (Remove-SandboxEgress), mirroring CreatedSwitches.

    Pure functions plus backend calls; no raw cmdlet. Safe to dot-source more than once.
#>

Set-StrictMode -Version Latest

$script:EgressRangeBase          = '10.231.0.0'
$script:EgressRangePrefixLength  = 16
$script:EgressSubnetPrefixLength = 30
$script:EgressProxyPort          = 13128
$script:EgressProxyScript        = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\egress\voidseal_egress_proxy.py'))

# --------------------------------------------------------------------------
# descriptor access (hashtable or PSCustomObject; StrictMode-safe)
# --------------------------------------------------------------------------
function Get-EgressDescriptorField {
    [CmdletBinding()]
    param([AllowNull()] $Descriptor, [Parameter(Mandatory)] [string] $Name, $Default = $null)
    if ($null -eq $Descriptor) { return $Default }
    if ($Descriptor -is [System.Collections.IDictionary]) {
        if ($Descriptor.Contains($Name) -and $null -ne $Descriptor[$Name]) { return $Descriptor[$Name] }
        return $Default
    }
    $prop = $Descriptor.PSObject.Properties[$Name]
    if ($null -ne $prop -and $null -ne $prop.Value) { return $prop.Value }
    return $Default
}

function Set-EgressDescriptorField {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Descriptor, [Parameter(Mandatory)] [string] $Name, [AllowNull()] $Value)
    if ($Descriptor -is [System.Collections.IDictionary]) { $Descriptor[$Name] = $Value; return }
    if ($null -ne $Descriptor.PSObject.Properties[$Name]) { $Descriptor.$Name = $Value }
    else { Add-Member -InputObject $Descriptor -MemberType NoteProperty -Name $Name -Value $Value -Force }
}

<#
.SYNOPSIS
    $true when a descriptor records a HostProxy VM that keeps a NIC (the only case with host egress).
#>
function Test-SandboxUsesHostProxy {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Descriptor)
    return ([string](Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressMode') -eq 'HostProxy') -and
           ($null -ne (Get-EgressDescriptorField -Descriptor $Descriptor -Name 'Egress'))
}

# --------------------------------------------------------------------------
# IPv4 arithmetic
# --------------------------------------------------------------------------
function ConvertTo-EgressUInt32 {
    [CmdletBinding()]
    [OutputType([uint32])]
    param([Parameter(Mandatory)] [string] $Address)
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $Address -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        throw "HostEgress: '$Address' is not a dotted IPv4 address."
    }
    $bytes = $parsed.GetAddressBytes()
    return [uint32]([uint64]$bytes[0] * 16777216 + [uint64]$bytes[1] * 65536 + [uint64]$bytes[2] * 256 + [uint64]$bytes[3])
}

function ConvertFrom-EgressUInt32 {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [uint64] $Value)
    if ($Value -gt 4294967295) { throw "HostEgress: $Value is beyond the IPv4 range." }
    $v = [uint64]$Value
    return '{0}.{1}.{2}.{3}' -f [uint64][math]::Floor($v / 16777216), ([uint64][math]::Floor($v / 65536) % 256), ([uint64][math]::Floor($v / 256) % 256), ($v % 256)
}

<#
.SYNOPSIS
    The [first, last] address range of an IPv4 prefix, as uint32 values.
#>
function Get-EgressPrefixRange {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Address, [Parameter(Mandatory)] [int] $PrefixLength)
    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) { throw "HostEgress: prefix length $PrefixLength is out of range." }
    $value = [uint64](ConvertTo-EgressUInt32 -Address $Address)
    $size  = [uint64]1 -shl (32 - $PrefixLength)
    $first = [uint64]([math]::Floor($value / $size)) * $size
    return @{ First = $first; Last = ($first + $size - 1) }
}

<#
.SYNOPSIS
    $true when two IPv4 prefixes share any address.
#>
function Test-EgressPrefixOverlap {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $AddressA, [Parameter(Mandatory)] [int] $PrefixA,
        [Parameter(Mandatory)] [string] $AddressB, [Parameter(Mandatory)] [int] $PrefixB
    )
    $a = Get-EgressPrefixRange -Address $AddressA -PrefixLength $PrefixA
    $b = Get-EgressPrefixRange -Address $AddressB -PrefixLength $PrefixB
    return ($a.First -le $b.Last) -and ($b.First -le $a.Last)
}

# --------------------------------------------------------------------------
# the plan and the enforcement specs (pure)
# --------------------------------------------------------------------------
<#
.SYNOPSIS
    The deterministic HostProxy addressing plan for a VM: its /30, gateway, guest, proxy port, names.
#>
function Get-EgressAddressPlan {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $VMName, [Parameter(Mandatory)] [string] $SwitchName)
    if ([string]::IsNullOrWhiteSpace($VMName) -or [string]::IsNullOrWhiteSpace($SwitchName)) {
        throw 'Get-EgressAddressPlan: VMName and SwitchName are required.'
    }
    $hash  = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($VMName.ToLowerInvariant()))
    $slots = [int][math]::Pow(2, $script:EgressSubnetPrefixLength - $script:EgressRangePrefixLength)
    $slot  = ((([int]$hash[0]) -shl 8) -bor [int]$hash[1]) % $slots
    $base  = ConvertTo-EgressUInt32 -Address $script:EgressRangeBase
    $size  = [uint32][math]::Pow(2, 32 - $script:EgressSubnetPrefixLength)
    $net   = [uint64]$base + [uint64]$slot * [uint64]$size
    $netText = ConvertFrom-EgressUInt32 -Value $net
    return @{
        VMName         = $VMName
        SwitchName     = $SwitchName
        InterfaceAlias = "vEthernet ($SwitchName)"
        Slot           = $slot
        NetworkAddress = $netText
        PrefixLength   = $script:EgressSubnetPrefixLength
        Subnet         = "$netText/$($script:EgressSubnetPrefixLength)"
        GatewayIP      = ConvertFrom-EgressUInt32 -Value ($net + 1)
        GuestIP        = ConvertFrom-EgressUInt32 -Value ($net + 2)
        ProxyPort      = $script:EgressProxyPort
        RulePrefix     = "Voidseal-egress-$VMName-"
    }
}

function Get-EgressPlanField {
    param($Plan, [string] $Name)
    if ($null -eq $Plan) { return $null }
    if ($Plan -is [System.Collections.IDictionary]) { if ($Plan.Contains($Name)) { return $Plan[$Name] } return $null }
    $p = $Plan.PSObject.Properties[$Name]
    if ($null -ne $p) { return $p.Value }
    return $null
}

<#
.SYNOPSIS
    The host firewall rules a HostProxy VM needs, as specs (Name, Direction, Action, Protocol, filters).
.DESCRIPTION
    Windows Firewall applies a Block rule over any Allow rule, so "allow the proxy, block the rest" is
    built as one Allow plus Blocks that cover everything EXCEPT the allowed tuple:
      allow-proxy        TCP to gateway:port from the guest address
      block-tcp-ports    TCP to every other local port
      block-proxy-others TCP to the proxy port from any address but the guest's
      block-udp          all UDP
      block-icmp         ICMPv4 and ICMPv6
      block-other-local  every protocol to any local address but the gateway (IPv4 ranges around it,
                         and all of IPv6)
    All are inbound and scoped to the VM switch's vEthernet interface. What is left (a protocol other
    than TCP, UDP or ICMP sent to the gateway address itself) meets the default inbound Block and the
    port ACL's deny; docs/threat-model.md records it.
#>
function Get-EgressFirewallRuleSpec {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Plan)
    $gw     = [string](Get-EgressPlanField $Plan 'GatewayIP')
    $guest  = [string](Get-EgressPlanField $Plan 'GuestIP')
    $port   = [int](Get-EgressPlanField $Plan 'ProxyPort')
    $alias  = [string](Get-EgressPlanField $Plan 'InterfaceAlias')
    $prefix = [string](Get-EgressPlanField $Plan 'RulePrefix')
    $gwN    = ConvertTo-EgressUInt32 -Address $gw
    $guestN = ConvertTo-EgressUInt32 -Address $guest
    $aroundGw    = @(('0.0.0.0-' + (ConvertFrom-EgressUInt32 ([uint64]$gwN - 1))), ((ConvertFrom-EgressUInt32 ([uint64]$gwN + 1)) + '-255.255.255.255'))
    $aroundGuest = @(('0.0.0.0-' + (ConvertFrom-EgressUInt32 ([uint64]$guestN - 1))), ((ConvertFrom-EgressUInt32 ([uint64]$guestN + 1)) + '-255.255.255.255'))
    $any = @('Any')
    $spec = {
        param($Suffix, $Action, $Protocol, $LocalAddress, $LocalPort, $RemoteAddress)
        [ordered]@{
            Name = "$prefix$Suffix"; Direction = 'Inbound'; Action = $Action; Protocol = $Protocol
            LocalAddress = [string[]]@($LocalAddress); LocalPort = [string[]]@($LocalPort)
            RemoteAddress = [string[]]@($RemoteAddress); InterfaceAlias = $alias
        }
    }
    return @(
        (& $spec 'allow-proxy'        'Allow' 'TCP'    @($gw) @("$port") @($guest))
        (& $spec 'block-tcp-ports'    'Block' 'TCP'    $any   @("1-$($port - 1)", "$($port + 1)-65535") $any)
        (& $spec 'block-proxy-others' 'Block' 'TCP'    $any   @("$port") $aroundGuest)
        (& $spec 'block-udp'          'Block' 'UDP'    $any   $any $any)
        (& $spec 'block-icmp4'        'Block' 'ICMPv4' $any   $any $any)
        (& $spec 'block-icmp6'        'Block' 'ICMPv6' $any   $any $any)
        (& $spec 'block-other-local'  'Block' 'Any'    (@($aroundGw) + @('::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')) $any $any)
    )
}

<#
.SYNOPSIS
    The extended port ACL entries a HostProxy VM's adapter needs (weights: deny 1, allow 100).
#>
function Get-EgressAclSpec {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Plan)
    $gw    = [string](Get-EgressPlanField $Plan 'GatewayIP')
    $guest = [string](Get-EgressPlanField $Plan 'GuestIP')
    $port  = [int](Get-EgressPlanField $Plan 'ProxyPort')
    return @(
        [ordered]@{ Action = 'Deny';  Direction = 'Outbound'; Weight = 1;   Protocol = 'Any'; LocalIPAddress = 'Any';  RemoteIPAddress = 'Any'; RemotePort = 'Any';   Stateful = $false }
        [ordered]@{ Action = 'Deny';  Direction = 'Inbound';  Weight = 1;   Protocol = 'Any'; LocalIPAddress = 'Any';  RemoteIPAddress = 'Any'; RemotePort = 'Any';   Stateful = $false }
        [ordered]@{ Action = 'Allow'; Direction = 'Outbound'; Weight = 100; Protocol = 'TCP'; LocalIPAddress = $guest; RemoteIPAddress = $gw;   RemotePort = "$port"; Stateful = $true }
    )
}

<#
.SYNOPSIS
    The proxy's allowlist from the run's merged EgressAllowlist.
.DESCRIPTION
    The loader's allowlist syntax is Squid's: a leading dot ('.example.com') means the domain AND its
    subdomains. The proxy names subdomains only with an explicit '*.' rule, so '.example.com' becomes
    both 'example.com' and '*.example.com'. Every other entry passes through. Duplicates (any case) go.
#>
function ConvertTo-EgressProxyAllowlist {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Allowlist)
    $out  = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($raw in @($Allowlist)) {
        $e = ([string]$raw).Trim()
        if ([string]::IsNullOrWhiteSpace($e)) { continue }
        $entries = if ($e.StartsWith('.')) { @($e.Substring(1), ('*' + $e)) } else { @($e) }
        foreach ($x in $entries) { if ($seen.Add($x)) { $out.Add($x) } }
    }
    return ,[string[]]$out.ToArray()
}

<#
.SYNOPSIS
    The proxy's command-line arguments (after the script path) for a plan and a run.
#>
function Get-EgressProxyArguments {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] $Plan,
        [Parameter(Mandatory)] [string[]] $Allowlist,
        [Parameter(Mandatory)] [string] $LogPath,
        [Parameter(Mandatory)] [string] $StopFile,
        [Parameter(Mandatory)] [string] $ReadyFile,
        [Parameter(Mandatory)] [int] $MaxLifetimeSeconds,
        [int] $ParentPid = $PID
    )
    $argv = [System.Collections.Generic.List[string]]::new()
    foreach ($pair in @(
            @('--listen-host', [string](Get-EgressPlanField $Plan 'GatewayIP')),
            @('--listen-port', [string](Get-EgressPlanField $Plan 'ProxyPort')),
            @('--log', $LogPath), @('--stop-file', $StopFile), @('--ready-file', $ReadyFile),
            @('--max-lifetime-seconds', [string]$MaxLifetimeSeconds), @('--parent-pid', [string]$ParentPid))) {
        $argv.Add($pair[0]); $argv.Add($pair[1])
    }
    foreach ($a in $Allowlist) { $argv.Add('--allow'); $argv.Add($a) }
    return ,[string[]]$argv.ToArray()
}

# --------------------------------------------------------------------------
# host checks
# --------------------------------------------------------------------------
<#
.SYNOPSIS
    Why the plan's /30 is not free, or $null when it is: a host address or a NAT network overlaps it.
.DESCRIPTION
    Reads GetHostIPAddresses and GetNetNats. A read that throws, returns no collection, or reports a
    value that cannot be parsed yields a reason too: an address that cannot be checked is not assumed
    to be free. -IgnoreInterfaceAlias skips addresses on that interface (the seal gate checks after the
    gateway address is in place on the VM's own switch).
#>
function Get-EgressAddressConflict {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Plan, [Parameter(Mandatory)] [hashtable] $Backend, [string] $IgnoreInterfaceAlias)
    $subnetAddr = [string](Get-EgressPlanField $Plan 'NetworkAddress')
    $subnetLen  = [int](Get-EgressPlanField $Plan 'PrefixLength')
    $subnet     = [string](Get-EgressPlanField $Plan 'Subnet')

    $ips = $null
    try { $ips = & $Backend.GetHostIPAddresses @{} }
    catch { return "the host's IPv4 addresses could not be read ($($_.Exception.Message)), so the egress subnet $subnet cannot be checked for a collision" }
    if ($null -eq $ips) { return "the host's IPv4 address read returned no collection, so the egress subnet $subnet cannot be checked for a collision" }
    foreach ($ip in $ips) {
        $alias = [string](Get-EgressPlanField $ip 'InterfaceAlias')
        if (-not [string]::IsNullOrWhiteSpace($IgnoreInterfaceAlias) -and $alias -eq $IgnoreInterfaceAlias) { continue }
        $addr = [string](Get-EgressPlanField $ip 'IPAddress')
        $len  = [int](Get-EgressPlanField $ip 'PrefixLength')
        $overlap = $false
        try { $overlap = Test-EgressPrefixOverlap -AddressA $subnetAddr -PrefixA $subnetLen -AddressB $addr -PrefixB $len }
        catch { return "the host reports an address that cannot be parsed ('$addr/$len' on '$alias')" }
        if ($overlap) {
            return ("the egress subnet $subnet collides with host address $addr/$len on '$alias' (the subnet follows the " +
                    "sandbox name; rename the sandbox or free the range rather than expecting another subnet to be picked)")
        }
    }

    $nats = $null
    try { $nats = & $Backend.GetNetNats @{} }
    catch { return "the host's NAT networks could not be read ($($_.Exception.Message)), so no NAT can be proven absent from $subnet" }
    if ($null -eq $nats) { return "the host's NAT read returned no collection, so no NAT can be proven absent from $subnet" }
    foreach ($nat in $nats) {
        $prefixText = [string](Get-EgressPlanField $nat 'InternalIPInterfaceAddressPrefix')
        $name       = [string](Get-EgressPlanField $nat 'Name')
        $parts = $prefixText.Split('/')
        $overlap = $false
        try {
            if ($parts.Count -ne 2) { throw 'no prefix length' }
            $overlap = Test-EgressPrefixOverlap -AddressA $subnetAddr -PrefixA $subnetLen -AddressB $parts[0] -PrefixB ([int]$parts[1])
        }
        catch { return "NAT network '$name' has a prefix that cannot be parsed ('$prefixText'), so it cannot be proven not to cover $subnet" }
        if ($overlap) { return "NAT network '$name' ($prefixText) covers the egress subnet $subnet; a HostProxy VM must have no NAT route" }
    }
    return $null
}

<#
.SYNOPSIS
    Throw "<Context>: refusing '<vm>' because <reason>. Fail closed." when Get-EgressAddressConflict finds one.
#>
function Assert-EgressAddressFree {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Plan, [Parameter(Mandatory)] [hashtable] $Backend, [string] $Context = 'HostEgress')
    $why = Get-EgressAddressConflict -Plan $Plan -Backend $Backend
    if ($null -ne $why) {
        throw "${Context}: refusing '$(Get-EgressPlanField $Plan 'VMName')' because $why. Fail closed."
    }
}

<#
.SYNOPSIS
    Throw when a firewall rule this VM's install would create already exists on the host.
.DESCRIPTION
    A crashed run can leave its rules behind. Install would then fail part way through, after the gateway
    address was added, and rollback has no record of rules it did not create. So the install asks first
    (GetHostFirewallRuleNames, by the plan's RulePrefix) and refuses before it creates anything. Only the
    seven names the install would create count: another VM's rule whose name merely starts with this
    prefix ('sbx-a' and 'sbx-a-b') is not a clash. A read that fails is a refusal too. The message names
    the rules and the command that removes them.
#>
function Assert-EgressRulesAbsent {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Plan, [Parameter(Mandatory)] [hashtable] $Backend, [string] $Context = 'HostEgress')
    $vm     = [string](Get-EgressPlanField $Plan 'VMName')
    $prefix = [string](Get-EgressPlanField $Plan 'RulePrefix')
    $expected = @(Get-EgressFirewallRuleSpec -Plan $Plan | ForEach-Object { [string]$_.Name })
    $existing = $null
    try { $existing = & $Backend.GetHostFirewallRuleNames @{ NamePrefix = $prefix } }
    catch { throw "${Context}: refusing '$vm' because the existing firewall rules could not be read ($($_.Exception.Message)). Fail closed." }
    $clash = @($existing | Where-Object { $null -ne $_ -and $expected -contains [string]$_ } | ForEach-Object { [string]$_ } | Sort-Object)
    if ($clash.Count -eq 0) { return }
    $quoted = ($clash | ForEach-Object { "'$_'" }) -join ','
    throw ("${Context}: refusing '$vm' because $($clash.Count) firewall rule(s) named '${prefix}*' already exist on the host " +
           "(a crashed run leaves them behind): $($clash -join ', '). Remove them with: " +
           "Remove-NetFirewallRule -Name $quoted -PolicyStore ActiveStore. Fail closed.")
}

# --------------------------------------------------------------------------
# install, proxy, teardown
# --------------------------------------------------------------------------
<#
.SYNOPSIS
    Install the host enforcement for a HostProxy VM: gateway address, firewall rules, port ACL.
.DESCRIPTION
    Re-checks the plan's subnet first (the host may have changed since provisioning). Each object is
    recorded on the descriptor the moment it exists (EgressGatewayAddress, EgressFirewallRules,
    EgressAcls), so teardown can always find it. If any step throws, everything this call created is
    removed again in reverse order, the records of what was removed are cleared, and the original error
    is rethrown with a note; anything that could not be removed stays recorded for teardown.
.PARAMETER Descriptor
    A New-SandboxVM descriptor with EgressMode='HostProxy' and an Egress plan.
#>
function Install-SandboxEgressNetwork {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Descriptor, [Parameter(Mandatory)] [hashtable] $Backend)
    $vm   = [string](Get-EgressDescriptorField -Descriptor $Descriptor -Name 'Name')
    $plan = Get-EgressDescriptorField -Descriptor $Descriptor -Name 'Egress'
    if (-not (Test-SandboxUsesHostProxy -Descriptor $Descriptor)) {
        throw "Install-SandboxEgressNetwork: '$vm' does not record EgressMode='HostProxy' with an Egress plan. Fail closed."
    }
    $sw = [string](Get-EgressDescriptorField -Descriptor $Descriptor -Name 'SwitchName')
    if ([string]::IsNullOrWhiteSpace($sw) -or $sw -ne [string](Get-EgressPlanField $plan 'SwitchName')) {
        throw "Install-SandboxEgressNetwork: '$vm' records switch '$sw' but its egress plan names '$(Get-EgressPlanField $plan 'SwitchName')'. Fail closed."
    }
    Assert-EgressAddressFree -Plan $plan -Backend $Backend -Context 'Install-SandboxEgressNetwork'
    Assert-EgressRulesAbsent -Plan $plan -Backend $Backend -Context 'Install-SandboxEgressNetwork'

    Set-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressFirewallRules' -Value @()
    Set-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressAcls' -Value @()
    try {
        $null = & $Backend.AddSwitchHostIPAddress @{ SwitchName = $sw; IPAddress = [string](Get-EgressPlanField $plan 'GatewayIP'); PrefixLength = [int](Get-EgressPlanField $plan 'PrefixLength') }
        Set-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressGatewayAddress' -Value ([string](Get-EgressPlanField $plan 'GatewayIP'))

        foreach ($rule in (Get-EgressFirewallRuleSpec -Plan $plan)) {
            $null = & $Backend.NewHostFirewallRule @{
                Name = $rule.Name; Direction = $rule.Direction; Action = $rule.Action; Protocol = $rule.Protocol
                LocalAddress = $rule.LocalAddress; LocalPort = $rule.LocalPort; RemoteAddress = $rule.RemoteAddress
                InterfaceAlias = $rule.InterfaceAlias
            }
            $recorded = @(Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressFirewallRules' -Default @())
            Set-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressFirewallRules' -Value (@($recorded) + @($rule))
        }

        foreach ($acl in (Get-EgressAclSpec -Plan $plan)) {
            $aclArgs = @{ VMName = $vm }
            foreach ($k in $acl.Keys) { $aclArgs[$k] = $acl[$k] }
            $null = & $Backend.AddNetworkAdapterAcl $aclArgs
            $recorded = @(Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressAcls' -Default @())
            Set-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressAcls' -Value (@($recorded) + @($acl))
        }
    }
    catch {
        $original = $_.Exception.Message
        $left = @(Remove-SandboxEgress -Descriptor $Descriptor -Backend $Backend)
        $note = if ($left.Count -eq 0) { 'everything it had created was removed' }
                else { "rollback could not remove $($left.Count) object(s), still recorded for teardown: $($left -join '; ')" }
        throw "Install-SandboxEgressNetwork: installing host egress for '$vm' failed ($original); $note. Fail closed."
    }
}

<#
.SYNOPSIS
    Start the HostProxy proxy for a sealed VM and record it on the descriptor (EgressProxy).
.DESCRIPTION
    Called after Assert-Sealed certifies and before the VM starts. The proxy listens on the gateway
    address only, enforces the run's merged allowlist (ConvertTo-EgressProxyAllowlist), logs one JSON
    line per connection to -LogPath, exits on its stop file, on -MaxLifetimeSeconds, or when this
    PowerShell process exits. An empty allowlist, a missing plan, or a proxy that does not report ready
    is a throw.
#>
function Start-SandboxEgressProxy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Descriptor,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Allowlist,
        [Parameter(Mandatory)] [string] $RunDirectory,
        [Parameter(Mandatory)] [int] $MaxLifetimeSeconds,
        [Parameter(Mandatory)] [string] $PythonExe,
        [Parameter(Mandatory)] [hashtable] $Backend,
        [double] $ReadyTimeoutSeconds = 30
    )
    $vm = [string](Get-EgressDescriptorField -Descriptor $Descriptor -Name 'Name')
    if (-not (Test-SandboxUsesHostProxy -Descriptor $Descriptor)) {
        throw "Start-SandboxEgressProxy: '$vm' does not record EgressMode='HostProxy' with an Egress plan. Fail closed."
    }
    if ($null -ne (Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressProxy')) {
        throw "Start-SandboxEgressProxy: '$vm' already records a running egress proxy. Fail closed."
    }
    $proxyAllow = ConvertTo-EgressProxyAllowlist -Allowlist $Allowlist
    if ($proxyAllow.Count -eq 0) {
        throw "Start-SandboxEgressProxy: '$vm' has an empty EgressAllowlist; a HostProxy run must allow at least one name. Fail closed."
    }
    $plan = Get-EgressDescriptorField -Descriptor $Descriptor -Name 'Egress'
    $null = New-Item -ItemType Directory -Path $RunDirectory -Force
    $log   = Join-Path $RunDirectory 'egress-proxy.log'
    $stop  = Join-Path $RunDirectory 'egress-proxy.stop'
    $ready = Join-Path $RunDirectory 'egress-proxy.ready.json'
    if (Test-Path -LiteralPath $stop) { Remove-Item -LiteralPath $stop -Force }
    $argv = Get-EgressProxyArguments -Plan $plan -Allowlist $proxyAllow -LogPath $log -StopFile $stop -ReadyFile $ready -MaxLifetimeSeconds $MaxLifetimeSeconds
    $started = & $Backend.StartEgressProxy @{
        PythonExe = $PythonExe; ScriptPath = $script:EgressProxyScript; Arguments = $argv
        ReadyFile = $ready; ReadyTimeoutSeconds = $ReadyTimeoutSeconds
    }
    if ($null -eq $started -or $null -eq (Get-EgressPlanField $started 'ProcessId')) {
        throw "Start-SandboxEgressProxy: the backend reported no process for the egress proxy of '$vm'. Fail closed."
    }
    Set-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressProxy' -Value ([ordered]@{
        ProcessId   = [int](Get-EgressPlanField $started 'ProcessId')
        StartTime   = [string](Get-EgressPlanField $started 'StartTime')
        CommandLine = [string](Get-EgressPlanField $started 'CommandLine')
        LogPath     = $log
        StopFile    = $stop
        ReadyFile   = $ready
        Allowlist   = $proxyAllow
    })
}

<#
.SYNOPSIS
    Remove exactly the host egress objects the descriptor records. Returns what could not be removed.
.DESCRIPTION
    Order: stop the proxy (closes the door first), remove the port ACL entries (a VM that is already
    gone took them with it), the firewall rules, then the gateway address. Each removal is attempted
    even when an earlier one failed; a record is cleared only when its removal succeeded, so a failure
    stays visible on the descriptor. Emits one message per failure (nothing when everything went);
    collect it with @(...).
    Never touches an object it did not record, so a rule or address this run did not create is safe.
#>
function Remove-SandboxEgress {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] $Descriptor, [Parameter(Mandatory)] [hashtable] $Backend)
    $failures = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Descriptor) { return }
    $vm = [string](Get-EgressDescriptorField -Descriptor $Descriptor -Name 'Name')

    $proxy = Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressProxy'
    if ($null -ne $proxy) {
        try {
            $null = & $Backend.StopEgressProxy @{
                ProcessId = [int](Get-EgressPlanField $proxy 'ProcessId'); StartTime = [string](Get-EgressPlanField $proxy 'StartTime')
                StopFile = [string](Get-EgressPlanField $proxy 'StopFile'); TimeoutSeconds = 10
            }
            Set-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressProxy' -Value $null
        }
        catch { $failures.Add("egress proxy pid $(Get-EgressPlanField $proxy 'ProcessId'): $($_.Exception.Message)") }
    }

    $keptAcls = [System.Collections.Generic.List[object]]::new()
    foreach ($acl in @(Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressAcls' -Default @())) {
        try {
            $null = & $Backend.RemoveNetworkAdapterAcl @{ VMName = $vm; Action = [string](Get-EgressPlanField $acl 'Action'); Direction = [string](Get-EgressPlanField $acl 'Direction'); Weight = [int](Get-EgressPlanField $acl 'Weight') }
        }
        catch { $keptAcls.Add($acl); $failures.Add("port ACL $(Get-EgressPlanField $acl 'Direction')/$(Get-EgressPlanField $acl 'Action')/$(Get-EgressPlanField $acl 'Weight'): $($_.Exception.Message)") }
    }
    Set-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressAcls' -Value $keptAcls.ToArray()

    $keptRules = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in @(Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressFirewallRules' -Default @())) {
        $name = [string](Get-EgressPlanField $rule 'Name')
        try { $null = & $Backend.RemoveHostFirewallRule @{ Name = $name } }
        catch { $keptRules.Add($rule); $failures.Add("firewall rule '$name': $($_.Exception.Message)") }
    }
    Set-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressFirewallRules' -Value $keptRules.ToArray()

    $gw = [string](Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressGatewayAddress')
    if (-not [string]::IsNullOrWhiteSpace($gw)) {
        $plan = Get-EgressDescriptorField -Descriptor $Descriptor -Name 'Egress'
        $sw = [string](Get-EgressPlanField $plan 'SwitchName')
        if ([string]::IsNullOrWhiteSpace($sw)) { $sw = [string](Get-EgressDescriptorField -Descriptor $Descriptor -Name 'SwitchName') }
        try {
            $null = & $Backend.RemoveSwitchHostIPAddress @{ SwitchName = $sw; IPAddress = $gw }
            Set-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressGatewayAddress' -Value $null
        }
        catch { $failures.Add("gateway address $gw on 'vEthernet ($sw)': $($_.Exception.Message)") }
    }
    # Unrolled on purpose: callers collect with @(...), so an empty result is an empty array.
    return $failures.ToArray()
}

# --------------------------------------------------------------------------
# the seal gate (called from Assert-Sealed for a Tier-1 VM that keeps its NIC)
# --------------------------------------------------------------------------
function ConvertTo-EgressCompareKey {
    param($Value)
    $items = @(@($Value) | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ -ne '' })
    if ($items.Count -eq 0) { $items = @('any') }
    return ((@($items) | Sort-Object) -join ',')
}

# The firewall readback cannot compare address and port lists as text: how Windows renders a single
# address, a range, a prefix, an IPv6 address or the order of a list is not something the mock can show.
# These functions parse each entry to a numeric range, merge the ranges and return one canonical key, so
# two renderings of the same set compare equal and two different sets do not. Anything they cannot
# parse exactly (a keyword such as LocalSubnet or RPC, a malformed address, a reversed range, an IPv6
# scope id) THROWS, and the gate turns that into a refusal: an entry that cannot be read is never
# assumed to be the recorded one.

<#
.SYNOPSIS
    Parse one IPv4 or IPv6 address to @{ Family; Bits; Value } with Value a BigInteger. Throws if not exact.
.DESCRIPTION
    IPv4 must be a strict dotted quad (no short forms, no leading zeros). IPv6 may be compressed, expanded,
    in any case, or carry an embedded IPv4 tail; a scope id ('%12') or any other text is refused.
#>
function ConvertTo-EgressIpNumber {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text)
    $t = $Text.Trim()
    $ipv4 = '^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$'
    $family = $null; $bytes = $null
    if ($t -match $ipv4) {
        $family = 'v4'; $bytes = [System.Net.IPAddress]::Parse($t).GetAddressBytes()
    }
    elseif ($t.Contains(':') -and $t -notmatch '[%/\s]') {
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($t, [ref]$ip) -and $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $family = 'v6'; $bytes = $ip.GetAddressBytes()
        }
    }
    if ($null -eq $family) { throw "HostEgress: '$t' is not an IPv4 or IPv6 address the gate can read." }
    $value = [System.Numerics.BigInteger]::Zero
    foreach ($byte in $bytes) { $value = ($value * 256) + [int]$byte }
    return @{ Family = $family; Bits = ($bytes.Length * 8); Value = $value }
}

<#
.SYNOPSIS
    Parse one address entry (address, a-b range, a/len prefix, a/mask) to @{ Family; First; Last }.
#>
function ConvertTo-EgressAddressRange {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Item)
    if ($Item.Contains('/')) {
        $parts = $Item.Split('/')
        if ($parts.Count -ne 2) { throw "HostEgress: '$Item' is not an address prefix the gate can read." }
        $base = ConvertTo-EgressIpNumber -Text $parts[0]
        $lenText = $parts[1].Trim()
        $len = -1
        if ($lenText -match '^\d{1,3}$') { $len = [int]$lenText }
        elseif ($base.Family -eq 'v4' -and $lenText -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $mask = (ConvertTo-EgressIpNumber -Text $lenText).Value
            $ones = [System.Numerics.BigInteger]::Pow(2, 32) - 1
            for ($l = 0; $l -le 32; $l++) {
                if ($mask -eq ($ones - ([System.Numerics.BigInteger]::Pow(2, 32 - $l) - 1))) { $len = $l; break }
            }
        }
        if ($len -lt 0 -or $len -gt $base.Bits) { throw "HostEgress: '$Item' has a prefix length or mask the gate can not read." }
        $size  = [System.Numerics.BigInteger]::Pow(2, $base.Bits - $len)
        $first = [System.Numerics.BigInteger]::Divide($base.Value, $size) * $size
        return @{ Family = $base.Family; First = $first; Last = ($first + $size - 1) }
    }
    if ($Item.Contains('-')) {
        $parts = $Item.Split('-')
        if ($parts.Count -ne 2) { throw "HostEgress: '$Item' is not an address range the gate can read." }
        $a = ConvertTo-EgressIpNumber -Text $parts[0]
        $b = ConvertTo-EgressIpNumber -Text $parts[1]
        if ($a.Family -ne $b.Family) { throw "HostEgress: '$Item' mixes IPv4 and IPv6." }
        if ($a.Value -gt $b.Value)   { throw "HostEgress: '$Item' is a reversed range." }
        return @{ Family = $a.Family; First = $a.Value; Last = $b.Value }
    }
    $one = ConvertTo-EgressIpNumber -Text $Item
    return @{ Family = $one.Family; First = $one.Value; Last = $one.Value }
}

# Sort ranges by First and merge any that overlap or touch. Input: @{ First; Last } records (BigInteger).
function Merge-EgressRanges {
    param([object[]] $Ranges)
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Ranges)) { $list.Add($r) }
    $list.Sort([System.Comparison[object]]{ param($x, $y) [System.Numerics.BigInteger]::Compare($x.First, $y.First) })
    $merged = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $list) {
        if ($merged.Count -gt 0 -and $r.First -le ($merged[$merged.Count - 1].Last + 1)) {
            if ($r.Last -gt $merged[$merged.Count - 1].Last) { $merged[$merged.Count - 1].Last = $r.Last }
        }
        else { $merged.Add(@{ First = $r.First; Last = $r.Last }) }
    }
    return ,$merged.ToArray()
}

# Split a list value into trimmed non-blank entries; a renderer may join entries with commas.
function Get-EgressListItems {
    param($Value)
    $items = [System.Collections.Generic.List[string]]::new()
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        foreach ($piece in ([string]$v).Split(',')) { $t = $piece.Trim(); if ($t -ne '') { $items.Add($t) } }
    }
    return ,$items.ToArray()
}

<#
.SYNOPSIS
    One canonical key for a firewall address list: 'any', or the merged IPv4 and IPv6 ranges it covers.
.DESCRIPTION
    Nothing, a blank, 'Any', 'ANY' and '*' are the one set 'any' (which is NOT the same key as a list that
    happens to cover every address). Single addresses, a-b ranges, a/len prefixes, a/mask prefixes and
    IPv6 in any form are read to numeric ranges; order, repeats and how the set is split do not matter.
    Throws on anything it cannot read exactly.
#>
function ConvertTo-EgressAddressKey {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)
    $items = Get-EgressListItems -Value $Value
    if ($items.Count -eq 0) { return 'any' }
    $anyCount = @($items | Where-Object { $_ -ieq 'any' -or $_ -eq '*' }).Count
    if ($anyCount -gt 0) {
        if ($items.Count -eq 1) { return 'any' }
        throw "HostEgress: an address list mixes 'Any' with other entries ($($items -join ', '))."
    }
    $byFamily = @{ v4 = [System.Collections.Generic.List[object]]::new(); v6 = [System.Collections.Generic.List[object]]::new() }
    foreach ($item in $items) {
        $r = ConvertTo-EgressAddressRange -Item $item
        $byFamily[$r.Family].Add(@{ First = $r.First; Last = $r.Last })
    }
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($fam in @('v4', 'v6')) {
        if ($byFamily[$fam].Count -eq 0) { continue }
        $merged = Merge-EgressRanges -Ranges $byFamily[$fam].ToArray()
        $parts.Add("$fam=" + ((@($merged) | ForEach-Object { '{0}-{1}' -f $_.First, $_.Last }) -join ','))
    }
    return ($parts -join ';')
}

<#
.SYNOPSIS
    One canonical key for a firewall port list: 'any', or the merged port ranges it covers (0 to 65535).
.DESCRIPTION
    A port keyword such as RPC, a value outside 0..65535 and a reversed range throw.
#>
function ConvertTo-EgressPortKey {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)
    $items = Get-EgressListItems -Value $Value
    if ($items.Count -eq 0) { return 'any' }
    $anyCount = @($items | Where-Object { $_ -ieq 'any' -or $_ -eq '*' }).Count
    if ($anyCount -gt 0) {
        if ($items.Count -eq 1) { return 'any' }
        throw "HostEgress: a port list mixes 'Any' with other entries ($($items -join ', '))."
    }
    $ranges = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $items) {
        if ($item -notmatch '^(\d{1,5})(?:-(\d{1,5}))?$') { throw "HostEgress: '$item' is not a port or port range the gate can read." }
        $lo = [System.Numerics.BigInteger]::Parse($Matches[1])
        $hi = if ($Matches[2]) { [System.Numerics.BigInteger]::Parse($Matches[2]) } else { $lo }
        if ($lo -gt 65535 -or $hi -gt 65535 -or $lo -gt $hi) { throw "HostEgress: '$item' is outside 0..65535 or reversed." }
        $ranges.Add(@{ First = $lo; Last = $hi })
    }
    $merged = Merge-EgressRanges -Ranges $ranges.ToArray()
    return 'p=' + ((@($merged) | ForEach-Object { '{0}-{1}' -f $_.First, $_.Last }) -join ',')
}

<#
.SYNOPSIS
    Seal-gate checks for a HostProxy VM. Throws a named refusal; returns nothing when all hold.
.DESCRIPTION
    1. the descriptor records a plan on this VM's own switch, and the recorded firewall rules and ACL
       entries are exactly what the plan requires (a short or altered record is refused, so an install
       bug cannot certify weaker enforcement);
    2. the gateway address is on "vEthernet (<switch>)" with the plan's prefix, no other host address
       overlaps the subnet, and no NAT network covers it (Get-EgressAddressConflict);
    3. every recorded firewall rule exists, is enabled and matches its record field for field (addresses
       and ports as parsed sets, so another rendering of the same set passes; an entry the parser cannot
       read exactly is a refusal);
    4. the VM's adapter carries exactly the recorded ACL entries, no more and no fewer;
    5. Windows Firewall is enforcing on all three profiles (Domain, Private, Public), each with default
       inbound action exactly Block, so the rules in 3 are in force whatever profile the interface lands in;
    6. IP forwarding on "vEthernet (<switch>)" reads Disabled for IPv4 and IPv6, so the host cannot route
       between the VM subnet and its other interfaces around the proxy.
    Every read that throws or returns no collection is a refusal.
#>
function Assert-SandboxEgressSealed {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Descriptor, [Parameter(Mandatory)] [hashtable] $Backend)
    $vm   = [string](Get-EgressDescriptorField -Descriptor $Descriptor -Name 'Name')
    $head = "Assert-Sealed: REFUSING to certify Tier-1 HostProxy VM '$vm' SEALED because"
    $plan = Get-EgressDescriptorField -Descriptor $Descriptor -Name 'Egress'
    if ($null -eq $plan) {
        throw "$head the descriptor records EgressMode='HostProxy' but no egress plan. Fail closed."
    }
    $sw = [string](Get-EgressDescriptorField -Descriptor $Descriptor -Name 'SwitchName')
    if ([string](Get-EgressPlanField $plan 'SwitchName') -ne $sw -or [string](Get-EgressPlanField $plan 'VMName') -ne $vm) {
        throw "$head its egress plan was made for VM '$(Get-EgressPlanField $plan 'VMName')' on switch '$(Get-EgressPlanField $plan 'SwitchName')', not this VM on '$sw'. Fail closed."
    }
    $expectedPlan = Get-EgressAddressPlan -VMName $vm -SwitchName $sw
    foreach ($k in @('Subnet', 'GatewayIP', 'GuestIP', 'ProxyPort', 'InterfaceAlias', 'RulePrefix')) {
        if ([string](Get-EgressPlanField $plan $k) -ne [string]$expectedPlan[$k]) {
            throw "$head its recorded egress plan field '$k' ('$(Get-EgressPlanField $plan $k)') differs from the address plan for its name ('$($expectedPlan[$k])'). Fail closed."
        }
    }

    # 1. the records are the full required set
    $wantRules = @(Get-EgressFirewallRuleSpec -Plan $plan)
    $gotRules  = @(Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressFirewallRules' -Default @())
    # Addresses and ports compare as parsed sets (ConvertTo-EgressAddressKey / ConvertTo-EgressPortKey), not
    # as text; an entry that cannot be parsed throws, and each caller turns that into a named refusal.
    $ruleKey = { param($r) ('{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f (Get-EgressPlanField $r 'Name'), (Get-EgressPlanField $r 'Direction'), (Get-EgressPlanField $r 'Action'),
                 (Get-EgressPlanField $r 'Protocol'), (ConvertTo-EgressAddressKey (Get-EgressPlanField $r 'LocalAddress')), (ConvertTo-EgressPortKey (Get-EgressPlanField $r 'LocalPort')),
                 (ConvertTo-EgressAddressKey (Get-EgressPlanField $r 'RemoteAddress')), (ConvertTo-EgressCompareKey (Get-EgressPlanField $r 'InterfaceAlias'))).ToLowerInvariant() }
    $wantKeys = $null; $gotKeys = $null
    try {
        $wantKeys = @($wantRules | ForEach-Object { & $ruleKey $_ } | Sort-Object)
        $gotKeys  = @($gotRules  | ForEach-Object { & $ruleKey $_ } | Sort-Object)
    }
    catch { throw "$head a recorded host firewall rule has an address or port the gate cannot interpret ($($_.Exception.Message)). Fail closed." }
    if (($wantKeys -join "`n") -ne ($gotKeys -join "`n")) {
        throw "$head the descriptor records $($gotRules.Count) host firewall rule(s) that are not the $($wantRules.Count) its egress plan requires. Fail closed."
    }
    $wantAcls = @(Get-EgressAclSpec -Plan $plan)
    $gotAcls  = @(Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressAcls' -Default @())
    $aclKey = { param($a) ('{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f (Get-EgressPlanField $a 'Action'), (Get-EgressPlanField $a 'Direction'), [int](Get-EgressPlanField $a 'Weight'),
                (ConvertTo-EgressCompareKey (Get-EgressPlanField $a 'Protocol')), (ConvertTo-EgressCompareKey (Get-EgressPlanField $a 'LocalIPAddress')),
                (ConvertTo-EgressCompareKey (Get-EgressPlanField $a 'RemoteIPAddress')), (ConvertTo-EgressCompareKey (Get-EgressPlanField $a 'RemotePort')),
                [bool](Get-EgressPlanField $a 'Stateful')).ToLowerInvariant() }
    $wantAclKeys = @($wantAcls | ForEach-Object { & $aclKey $_ } | Sort-Object)
    if (($wantAclKeys -join "`n") -ne (@($gotAcls | ForEach-Object { & $aclKey $_ } | Sort-Object) -join "`n")) {
        throw "$head the descriptor records $($gotAcls.Count) port ACL entr(ies) that are not the $($wantAcls.Count) its egress plan requires. Fail closed."
    }
    $gw = [string](Get-EgressDescriptorField -Descriptor $Descriptor -Name 'EgressGatewayAddress')
    if ($gw -ne [string](Get-EgressPlanField $plan 'GatewayIP')) {
        throw "$head the descriptor does not record the gateway address $(Get-EgressPlanField $plan 'GatewayIP') as installed. Fail closed."
    }

    # 2. the gateway address is on the VM's switch, and nothing else on the host overlaps the subnet
    $ips = $null
    try { $ips = & $Backend.GetHostIPAddresses @{} }
    catch { throw "$head the host's IPv4 addresses could not be read ($($_.Exception.Message)). Fail closed." }
    if ($null -eq $ips) { throw "$head the host's IPv4 address read returned no collection. Fail closed." }
    $alias = [string](Get-EgressPlanField $plan 'InterfaceAlias')
    $onSwitch = @($ips | Where-Object { [string](Get-EgressPlanField $_ 'InterfaceAlias') -eq $alias -and [string](Get-EgressPlanField $_ 'IPAddress') -eq $gw -and [int](Get-EgressPlanField $_ 'PrefixLength') -eq [int](Get-EgressPlanField $plan 'PrefixLength') })
    if ($onSwitch.Count -ne 1) {
        throw "$head the gateway address $gw/$(Get-EgressPlanField $plan 'PrefixLength') is not on '$alias'. Fail closed."
    }
    $why = Get-EgressAddressConflict -Plan $plan -Backend $Backend -IgnoreInterfaceAlias $alias
    if ($null -ne $why) { throw "$head $why. Fail closed." }

    # 3. every recorded firewall rule is on the host as recorded
    foreach ($rule in $gotRules) {
        $name = [string](Get-EgressPlanField $rule 'Name')
        $host_ = $null
        try { $host_ = & $Backend.GetHostFirewallRule @{ Name = $name } }
        catch { throw "$head host firewall rule '$name' could not be read ($($_.Exception.Message)). Fail closed." }
        if ($null -eq $host_) { throw "$head host firewall rule '$name' is missing. Fail closed." }
        if (-not [bool](Get-EgressPlanField $host_ 'Enabled')) { throw "$head host firewall rule '$name' is disabled. Fail closed." }
        $hostKey = $null
        try { $hostKey = & $ruleKey $host_ }
        catch { throw "$head host firewall rule '$name' reports an address or port the gate cannot interpret ($($_.Exception.Message)). Fail closed." }
        if ($hostKey -ne (& $ruleKey $rule)) {
            throw "$head host firewall rule '$name' differs from its record (direction, action, protocol, addresses, ports or interface). Fail closed."
        }
    }

    # 4. the adapter carries exactly the recorded ACL entries
    $acls = $null
    try { $acls = & $Backend.GetNetworkAdapterAcls @{ VMName = $vm } }
    catch { throw "$head its port ACL could not be read ($($_.Exception.Message)). Fail closed." }
    if ($null -eq $acls) { throw "$head its port ACL read returned no collection. Fail closed." }
    $hostAclKeys = @($acls | ForEach-Object { & $aclKey $_ } | Sort-Object)
    if (($hostAclKeys -join "`n") -ne ($wantAclKeys -join "`n")) {
        throw "$head its network adapter carries $($hostAclKeys.Count) port ACL entr(ies), not exactly the $($wantAclKeys.Count) recorded. Fail closed."
    }

    # 5. Windows Firewall is enforcing on every profile, with Block as the default inbound action
    # The rules checked in 3 are controls only while the firewall is on. All three profiles are required
    # because the gate does not read which profile the vEthernet interface landed in (usually Public, but
    # a domain-joined host can differ). A profile that is off, that defaults to Allow, that is missing,
    # or that cannot be read refuses by name.
    $profiles = $null
    try { $profiles = & $Backend.GetHostFirewallProfiles @{} }
    catch { throw "$head the host firewall profiles could not be read ($($_.Exception.Message)). Fail closed." }
    if ($null -eq $profiles) { throw "$head the host firewall profile read returned no collection. Fail closed." }
    foreach ($profileName in @('Domain', 'Private', 'Public')) {
        $found = @($profiles | Where-Object { [string](Get-EgressPlanField $_ 'Name') -eq $profileName })
        if ($found.Count -ne 1) {
            throw "$head the host reports $($found.Count) firewall profile(s) named '$profileName', not exactly one. Fail closed."
        }
        $enabled = Get-EgressPlanField $found[0] 'Enabled'
        if ($enabled -isnot [bool] -or -not $enabled) {
            throw "$head Windows Firewall is not enabled on the '$profileName' profile. Fail closed."
        }
        $inbound = [string](Get-EgressPlanField $found[0] 'DefaultInboundAction')
        if ($inbound -cne 'Block') {
            throw "$head the '$profileName' firewall profile's default inbound action is '$inbound', not Block. Fail closed."
        }
    }

    # 6. the gateway interface forwards nothing
    # IP forwarding on "vEthernet (<switch>)" would let the host route between the VM subnet and its other
    # interfaces, around the proxy. Both families must read exactly Disabled; a family the host does not
    # report ('Missing'), any other value, and a failed read refuse.
    $forwarding = $null
    try { $forwarding = & $Backend.GetNetIPInterfaceForwarding @{ InterfaceAlias = $alias } }
    catch { throw "$head IP forwarding on '$alias' could not be read ($($_.Exception.Message)). Fail closed." }
    if ($null -eq $forwarding) { throw "$head the IP forwarding read for '$alias' returned nothing. Fail closed." }
    foreach ($family in @('IPv4', 'IPv6')) {
        $value = [string](Get-EgressPlanField $forwarding $family)
        if ($value -cne 'Disabled') {
            $shown = if ([string]::IsNullOrWhiteSpace($value)) { '(unreadable)' } else { $value }
            throw "$head $family forwarding on '$alias' is '$shown', not Disabled. Fail closed."
        }
    }
}
