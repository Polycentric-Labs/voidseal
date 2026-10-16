#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for the host-egress backend methods (EgressMode 'HostProxy') in
    scripts/lib/HyperVBackend.ps1: the fake's behavior, and the REAL bodies run out of process against
    recording stub cmdlets (tests/fixtures/Invoke-RealEgressCapture.ps1). No host network object is
    created, no Hyper-V cmdlet runs, nothing is elevated. The proxy start and stop run a stub Python
    child that opens no socket.
#>

BeforeAll {
    $script:SkillRoot = Split-Path -Parent $PSScriptRoot
    $script:LibPath   = Join-Path $script:SkillRoot 'scripts/lib/HyperVBackend.ps1'
    . $script:LibPath
    . (Join-Path $script:SkillRoot 'scripts/lib/PythonResolver.ps1')
    $script:ProxyScript = Join-Path $script:SkillRoot 'scripts/egress/voidseal_egress_proxy.py'

    function New-EgressFakeVM {
        param([hashtable] $Backend, [string] $Name = 'vm1', [string] $Switch = 'vm1-int', [string] $SwitchType = 'Internal')
        & $Backend.NewSwitch @{ Name = $Switch; SwitchType = $SwitchType }
        & $Backend.NewVM @{ Name = $Name; Generation = 2 }
        & $Backend.ConnectNetworkAdapter @{ VMName = $Name; SwitchName = $Switch }
    }
}

Describe 'Host egress backend methods: the manifest' {
    It 'documents every host egress method with its arg keys' {
        $m = Get-HyperVBackendMethodManifest
        $m['GetHostIPAddresses']        | Should -BeNullOrEmpty
        $m['GetNetNats']                | Should -BeNullOrEmpty
        $m['AddSwitchHostIPAddress']    | Should -Be @('SwitchName', 'IPAddress', 'PrefixLength')
        $m['RemoveSwitchHostIPAddress'] | Should -Be @('SwitchName', 'IPAddress')
        $m['NewHostFirewallRule']       | Should -Be @('Name', 'Direction', 'Action', 'Protocol', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'InterfaceAlias')
        $m['GetHostFirewallRule']       | Should -Be @('Name')
        $m['RemoveHostFirewallRule']    | Should -Be @('Name')
        $m['GetHostFirewallRuleNames']  | Should -Be @('NamePrefix')
        $m['AddNetworkAdapterAcl']      | Should -Be @('VMName', 'Action', 'Direction', 'Weight', 'Protocol', 'LocalIPAddress', 'RemoteIPAddress', 'RemotePort', 'Stateful')
        $m['GetNetworkAdapterAcls']     | Should -Be @('VMName')
        $m['RemoveNetworkAdapterAcl']   | Should -Be @('VMName', 'Action', 'Direction', 'Weight')
        $m['StartEgressProxy']          | Should -Be @('PythonExe', 'ScriptPath', 'Arguments', 'ReadyFile', 'ReadyTimeoutSeconds')
        $m['StopEgressProxy']           | Should -Be @('ProcessId', 'StartTime', 'StopFile', 'TimeoutSeconds')
        $m['GetHostFirewallProfiles']   | Should -BeNullOrEmpty
        $m['GetNetIPInterfaceForwarding'] | Should -Be @('InterfaceAlias')
    }
}

Describe 'Host egress backend methods: the fake' {

    BeforeEach { $script:B = New-FakeHyperVBackend }

    It 'GetHostIPAddresses reports the seeded LAN address as an array, even for one entry' {
        $ips = & $script:B.GetHostIPAddresses @{}
        $ips -is [array] | Should -BeTrue
        $ips.Count | Should -Be 1
        $ips[0].IPAddress | Should -Be '192.168.1.20'
    }

    It 'AddSwitchHostIPAddress puts the address on the switch''s vEthernet adapter, and RemoveSwitch takes it away' {
        New-EgressFakeVM -Backend $script:B
        & $script:B.AddSwitchHostIPAddress @{ SwitchName = 'vm1-int'; IPAddress = '10.231.0.1'; PrefixLength = 30 }
        $ips = & $script:B.GetHostIPAddresses @{}
        $rec = $ips | Where-Object { $_.IPAddress -eq '10.231.0.1' }
        $rec.InterfaceAlias | Should -Be 'vEthernet (vm1-int)'
        $rec.PrefixLength   | Should -Be 30
        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        & $script:B.RemoveSwitch @{ Name = 'vm1-int' }
        $ips = & $script:B.GetHostIPAddresses @{}
        @($ips | Where-Object { $_.IPAddress -eq '10.231.0.1' }).Count | Should -Be 0
    }

    It 'AddSwitchHostIPAddress refuses an unknown switch, a Private switch and a duplicate address' {
        { & $script:B.AddSwitchHostIPAddress @{ SwitchName = 'nope'; IPAddress = '10.231.0.1'; PrefixLength = 30 } } | Should -Throw '*no switch*'
        & $script:B.NewSwitch @{ Name = 'priv'; SwitchType = 'Private' }
        { & $script:B.AddSwitchHostIPAddress @{ SwitchName = 'priv'; IPAddress = '10.231.0.1'; PrefixLength = 30 } } | Should -Throw '*Private*'
        & $script:B.NewSwitch @{ Name = 'a-int'; SwitchType = 'Internal' }
        { & $script:B.AddSwitchHostIPAddress @{ SwitchName = 'a-int'; IPAddress = '192.168.1.20'; PrefixLength = 30 } } | Should -Throw '*already has address*'
    }

    It 'RemoveSwitchHostIPAddress is idempotent' {
        New-EgressFakeVM -Backend $script:B
        & $script:B.AddSwitchHostIPAddress @{ SwitchName = 'vm1-int'; IPAddress = '10.231.0.1'; PrefixLength = 30 }
        & $script:B.RemoveSwitchHostIPAddress @{ SwitchName = 'vm1-int'; IPAddress = '10.231.0.1' }
        { & $script:B.RemoveSwitchHostIPAddress @{ SwitchName = 'vm1-int'; IPAddress = '10.231.0.1' } } | Should -Not -Throw
        (& $script:B.GetHostIPAddresses @{}).Count | Should -Be 1
    }

    It 'NewHostFirewallRule records a rule GetHostFirewallRule reads back with Any for unset filters' {
        New-EgressFakeVM -Backend $script:B
        & $script:B.NewHostFirewallRule @{ Name = 'r1'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; InterfaceAlias = 'vEthernet (vm1-int)' }
        $r = & $script:B.GetHostFirewallRule @{ Name = 'r1' }
        $r.Enabled | Should -BeTrue
        $r.Action  | Should -Be 'Block'
        @($r.LocalPort)     | Should -Be @('Any')
        @($r.RemoteAddress) | Should -Be @('Any')
        @($r.InterfaceAlias) | Should -Be @('vEthernet (vm1-int)')
    }

    It 'NewHostFirewallRule refuses a duplicate Name, an unknown interface and a port filter without TCP or UDP' {
        New-EgressFakeVM -Backend $script:B
        $base = @{ Name = 'r1'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; InterfaceAlias = 'vEthernet (vm1-int)' }
        & $script:B.NewHostFirewallRule $base
        { & $script:B.NewHostFirewallRule $base } | Should -Throw '*already exists*'
        { & $script:B.NewHostFirewallRule @{ Name = 'r2'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; InterfaceAlias = 'vEthernet (other)' } } | Should -Throw '*no host interface*'
        { & $script:B.NewHostFirewallRule @{ Name = 'r3'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'ICMPv4'; LocalPort = @('80'); InterfaceAlias = 'vEthernet (vm1-int)' } } | Should -Throw '*TCP or UDP*'
    }

    It 'GetHostFirewallRule returns a copy: editing what was read does not change the host' {
        New-EgressFakeVM -Backend $script:B
        & $script:B.NewHostFirewallRule @{ Name = 'r1'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; InterfaceAlias = 'vEthernet (vm1-int)' }
        $r = & $script:B.GetHostFirewallRule @{ Name = 'r1' }
        $r.Action = 'Allow'
        (& $script:B.GetHostFirewallRule @{ Name = 'r1' }).Action | Should -Be 'Block'
    }

    It 'GetHostFirewallRuleNames lists the rule names that start with the prefix (any case) as an array' {
        New-EgressFakeVM -Backend $script:B
        foreach ($n in @('Voidseal-egress-vm1-allow-proxy', 'Voidseal-egress-vm1-block-udp', 'Voidseal-egress-vm12-allow-proxy', 'Other-rule')) {
            & $script:B.NewHostFirewallRule @{ Name = $n; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; InterfaceAlias = 'vEthernet (vm1-int)' }
        }
        $names = & $script:B.GetHostFirewallRuleNames @{ NamePrefix = 'voidseal-EGRESS-vm1-' }
        $names -is [array] | Should -BeTrue
        @($names | Sort-Object) | Should -Be @('Voidseal-egress-vm1-allow-proxy', 'Voidseal-egress-vm1-block-udp')
        $none = & $script:B.GetHostFirewallRuleNames @{ NamePrefix = 'Voidseal-egress-nobody-' }
        $none -is [array] | Should -BeTrue
        $none.Count | Should -Be 0
    }

    It 'GetHostFirewallRuleNames requires NamePrefix and honors SimulateEgressMethodError' {
        { & $script:B.GetHostFirewallRuleNames @{} } | Should -Throw
        $b = New-FakeHyperVBackend -SimulateEgressMethodError @('GetHostFirewallRuleNames')
        { & $b.GetHostFirewallRuleNames @{ NamePrefix = 'x' } } | Should -Throw '*SimulateEgressMethodError*'
    }

    It 'GetHostFirewallRule returns null for a missing rule and RemoveHostFirewallRule is idempotent' {
        & $script:B.GetHostFirewallRule @{ Name = 'nope' } | Should -BeNullOrEmpty
        { & $script:B.RemoveHostFirewallRule @{ Name = 'nope' } } | Should -Not -Throw
    }

    It 'AddNetworkAdapterAcl needs an adapter, refuses a duplicate weight, and the ACLs go with the adapter' {
        New-EgressFakeVM -Backend $script:B
        & $script:B.AddNetworkAdapterAcl @{ VMName = 'vm1'; Action = 'Deny'; Direction = 'Outbound'; Weight = 1 }
        { & $script:B.AddNetworkAdapterAcl @{ VMName = 'vm1'; Action = 'Allow'; Direction = 'Outbound'; Weight = 1 } } | Should -Throw '*weight 1*'
        $acls = & $script:B.GetNetworkAdapterAcls @{ VMName = 'vm1' }
        $acls -is [array] | Should -BeTrue
        $acls.Count | Should -Be 1
        $acls[0].RemoteIPAddress | Should -Be 'Any'
        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        (& $script:B.GetNetworkAdapterAcls @{ VMName = 'vm1' }).Count | Should -Be 0
        { & $script:B.AddNetworkAdapterAcl @{ VMName = 'vm1'; Action = 'Deny'; Direction = 'Outbound'; Weight = 1 } } | Should -Throw '*no network adapter*'
    }

    It 'RemoveNetworkAdapterAcl removes only the matching entry and is a no-op for a VM that is gone' {
        New-EgressFakeVM -Backend $script:B
        & $script:B.AddNetworkAdapterAcl @{ VMName = 'vm1'; Action = 'Deny'; Direction = 'Outbound'; Weight = 1 }
        & $script:B.AddNetworkAdapterAcl @{ VMName = 'vm1'; Action = 'Deny'; Direction = 'Inbound'; Weight = 1 }
        & $script:B.RemoveNetworkAdapterAcl @{ VMName = 'vm1'; Action = 'Deny'; Direction = 'Outbound'; Weight = 1 }
        $left = & $script:B.GetNetworkAdapterAcls @{ VMName = 'vm1' }
        $left.Count | Should -Be 1
        $left[0].Direction | Should -Be 'Inbound'
        { & $script:B.RemoveNetworkAdapterAcl @{ VMName = 'gone'; Action = 'Deny'; Direction = 'Inbound'; Weight = 1 } } | Should -Not -Throw
    }

    It 'GetNetNats reports the simulated NAT networks' {
        $b = New-FakeHyperVBackend -SimulateNetNat @(@{ Name = 'n1'; InternalIPInterfaceAddressPrefix = '172.20.0.0/16' })
        $n = & $b.GetNetNats @{}
        $n -is [array] | Should -BeTrue
        $n[0].InternalIPInterfaceAddressPrefix | Should -Be '172.20.0.0/16'
        (& $script:B.GetNetNats @{}).Count | Should -Be 0
    }

    It 'StartEgressProxy records a running process without starting Python, and StopEgressProxy stops exactly it' {
        $r = & $script:B.StartEgressProxy @{ PythonExe = 'C:\py\python.exe'; ScriptPath = $script:ProxyScript; Arguments = @('--listen-host', '10.231.0.1', $null); ReadyFile = 'C:\x\ready.json' }
        $r.ProcessId | Should -BeGreaterThan 0
        $r.CommandLine | Should -Be ('"C:\py\python.exe" "' + $script:ProxyScript + '" "--listen-host" "10.231.0.1"')
        $script:B.FakeEgressProcesses[$r.ProcessId].Running | Should -BeTrue
        (& $script:B.StopEgressProxy @{ ProcessId = $r.ProcessId; StartTime = 'not-it' }).AlreadyGone | Should -BeTrue
        $script:B.FakeEgressProcesses[$r.ProcessId].Running | Should -BeTrue -Because 'a start-time mismatch means the id is not ours'
        (& $script:B.StopEgressProxy @{ ProcessId = $r.ProcessId; StartTime = $r.StartTime }).AlreadyGone | Should -BeFalse
        $script:B.FakeEgressProcesses[$r.ProcessId].Running | Should -BeFalse
        (& $script:B.StopEgressProxy @{ ProcessId = $r.ProcessId; StartTime = $r.StartTime }).AlreadyGone | Should -BeTrue
    }

    It '-SimulateEgressProxyUnkillable makes StopEgressProxy report Stopped=$false with Killed=$true and leaves the process running' {
        $b = New-FakeHyperVBackend -SimulateEgressProxyUnkillable
        $r = & $b.StartEgressProxy @{ PythonExe = 'C:\py\python.exe'; ScriptPath = $script:ProxyScript; Arguments = @(); ReadyFile = 'C:\x\ready.json' }
        $s = & $b.StopEgressProxy @{ ProcessId = $r.ProcessId; StartTime = $r.StartTime; StopFile = 'C:\x\stop'; TimeoutSeconds = 1 }
        $s.Stopped     | Should -BeOfType [bool]
        $s.Stopped     | Should -BeFalse
        $s.Killed      | Should -BeTrue
        $s.AlreadyGone | Should -BeFalse
        $b.FakeEgressProcesses[$r.ProcessId].Running | Should -BeTrue -Because 'the process survived the kill'
        (& $script:B.StopEgressProxy @{ ProcessId = 1; StartTime = 'x' }).Stopped | Should -BeTrue -Because 'an unknown pid is already gone, which is a stopped state'
    }

    It 'StartEgressProxy refuses a proxy script that does not exist, like the real body' {
        { & $script:B.StartEgressProxy @{ PythonExe = 'py'; ScriptPath = 'C:\nope\proxy.py'; ReadyFile = 'C:\x\r.json' } } | Should -Throw '*does not exist*'
    }

    It 'SimulateEgressMethodError makes the named method throw' {
        $b = New-FakeHyperVBackend -SimulateEgressMethodError @('GetNetNats', 'NewHostFirewallRule')
        { & $b.GetNetNats @{} } | Should -Throw '*SimulateEgressMethodError*'
        { & $b.NewHostFirewallRule @{ Name = 'r'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; InterfaceAlias = 'x' } } | Should -Throw '*SimulateEgressMethodError*'
        { & $b.GetHostIPAddresses @{} } | Should -Not -Throw
    }

    It 'GetHostFirewallProfiles reports Domain, Private and Public enabled with Block by default, as an array of copies' {
        $p = & $script:B.GetHostFirewallProfiles @{}
        $p -is [array] | Should -BeTrue
        @($p | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('Domain', 'Private', 'Public')
        foreach ($row in $p) {
            $row.Enabled | Should -BeOfType [bool]
            $row.Enabled | Should -BeTrue
            $row.DefaultInboundAction | Should -Be 'Block'
        }
        $p[0].Enabled = $false
        (& $script:B.GetHostFirewallProfiles @{} | Where-Object { $_.Name -eq $p[0].Name }).Enabled | Should -BeTrue -Because 'a read hands out copies'
    }

    It '-SimulateFirewallProfile overrides one profile (disabled, Allow, or removed) and refuses an unknown profile name' {
        $b = New-FakeHyperVBackend -SimulateFirewallProfile @(@{ Name = 'Public'; Enabled = $false }, @{ Name = 'Private'; DefaultInboundAction = 'Allow' })
        $p = & $b.GetHostFirewallProfiles @{}
        ($p | Where-Object { $_.Name -eq 'Public' }).Enabled | Should -BeFalse
        ($p | Where-Object { $_.Name -eq 'Private' }).DefaultInboundAction | Should -Be 'Allow'
        ($p | Where-Object { $_.Name -eq 'Domain' }).Enabled | Should -BeTrue -Because 'the untouched profile keeps its default'
        $b2 = New-FakeHyperVBackend -SimulateFirewallProfile @(@{ Name = 'Domain'; Remove = $true })
        @((& $b2.GetHostFirewallProfiles @{}) | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('Private', 'Public')
        { New-FakeHyperVBackend -SimulateFirewallProfile @(@{ Name = 'Guest'; Enabled = $false }) } | Should -Throw '*unknown profile*Guest*'
        { & (New-FakeHyperVBackend -SimulateEgressMethodError @('GetHostFirewallProfiles')).GetHostFirewallProfiles @{} } | Should -Throw '*SimulateEgressMethodError*'
    }

    It 'GetNetIPInterfaceForwarding reads Disabled for both families on a switch''s vEthernet interface, and throws for an alias the host does not have' {
        New-EgressFakeVM -Backend $script:B
        $f = & $script:B.GetNetIPInterfaceForwarding @{ InterfaceAlias = 'vEthernet (vm1-int)' }
        $f.IPv4 | Should -Be 'Disabled'
        $f.IPv6 | Should -Be 'Disabled'
        (& $script:B.GetNetIPInterfaceForwarding @{ InterfaceAlias = 'Ethernet' }).IPv4 | Should -Be 'Disabled' -Because 'the seeded LAN interface exists too'
        { & $script:B.GetNetIPInterfaceForwarding @{ InterfaceAlias = 'vEthernet (nope-int)' } } | Should -Throw "*no host interface 'vEthernet (nope-int)'*"
        { & $script:B.GetNetIPInterfaceForwarding @{} } | Should -Throw '*InterfaceAlias*'
    }

    It '-SimulateNetIPInterfaceForwarding sets a family''s value (Enabled or Missing) and -SimulateEgressMethodError makes the read throw' {
        $b = New-FakeHyperVBackend -SimulateNetIPInterfaceForwarding @{ IPv4 = 'Enabled' }
        New-EgressFakeVM -Backend $b
        $f = & $b.GetNetIPInterfaceForwarding @{ InterfaceAlias = 'vEthernet (vm1-int)' }
        $f.IPv4 | Should -Be 'Enabled'
        $f.IPv6 | Should -Be 'Disabled'
        $b2 = New-FakeHyperVBackend -SimulateNetIPInterfaceForwarding @{ IPv6 = 'Missing' }
        New-EgressFakeVM -Backend $b2
        (& $b2.GetNetIPInterfaceForwarding @{ InterfaceAlias = 'vEthernet (vm1-int)' }).IPv6 | Should -Be 'Missing'
        $b3 = New-FakeHyperVBackend -SimulateEgressMethodError @('GetNetIPInterfaceForwarding')
        New-EgressFakeVM -Backend $b3
        { & $b3.GetNetIPInterfaceForwarding @{ InterfaceAlias = 'vEthernet (vm1-int)' } } | Should -Throw '*SimulateEgressMethodError*'
    }
}

Describe 'Host egress backend methods: the REAL bodies, executed out of process against stub cmdlets' {

    BeforeAll {
        $harness = Join-Path $PSScriptRoot 'fixtures/Invoke-RealEgressCapture.ps1'
        $work = Join-Path ([System.IO.Path]::GetTempPath()) ("vs-egcap-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $work -Force
        $pwsh = (Get-Process -Id $PID).Path
        if ([string]::IsNullOrWhiteSpace($pwsh)) { $pwsh = 'pwsh' }
        $raw = & $pwsh -NoProfile -File $harness -LibPath $script:LibPath -PythonExe (Resolve-PythonExe) -WorkDir $work 2>&1
        $rawText = ($raw | Out-String).Trim()
        $jsonLine = ($rawText -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
        $jsonLine | Should -Not -BeNullOrEmpty -Because "the harness must emit JSON; got: $rawText"
        $script:Cap = $jsonLine | ConvertFrom-Json
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'GetHostIPAddresses asks for IPv4 and returns plain records as an array, even for one address' {
        $script:Cap.IP_Two.err | Should -BeNullOrEmpty
        $script:Cap.IP_Two.family | Should -Be 'IPv4'
        $script:Cap.IP_Two.isArray | Should -BeTrue
        $script:Cap.IP_Two.count | Should -Be 2
        $script:Cap.IP_Two.second.InterfaceAlias | Should -Be 'vEthernet (sbx-int)'
        $script:Cap.IP_Two.prefixType | Should -Be 'Int32' -Because 'the real PrefixLength is a byte; the record normalizes it'
        $script:Cap.IP_One.isArray | Should -BeTrue
        $script:Cap.IP_One.count | Should -Be 1
    }

    It 'GetHostIPAddresses, GetHostFirewallRule, GetNetworkAdapterAcls and GetNetNats THROW when the cmdlet reports a failure' {
        $script:Cap.IP_Fail.err      | Should -Match 'Get-NetIPAddress failed'
        $script:Cap.GetRule_Fail.err | Should -Match 'firewall service unreadable'
        $script:Cap.GetAcls_Fail.err | Should -Match 'ACL read failed'
        $script:Cap.Nat_Fail.err     | Should -Match 'WinNAT unreadable'
    }

    It 'AddSwitchHostIPAddress targets "vEthernet (switch)" in the active store, and emits nothing' {
        $c = $script:Cap.AddIP
        $c.err | Should -BeNullOrEmpty
        $c.leaked | Should -BeFalse
        $c.call.InterfaceAlias | Should -Be 'vEthernet (sbx-int)'
        $c.call.IPAddress      | Should -Be '10.231.0.1'
        $c.call.PrefixLength   | Should -Be 30
        $c.call.AddressFamily  | Should -Be 'IPv4'
        $c.call.PolicyStore    | Should -Be 'ActiveStore'
    }

    It 'RemoveSwitchHostIPAddress removes a present address and does nothing for an absent one' {
        $script:Cap.RemoveIP_Present.removed | Should -Be 'vEthernet (sbx-int)|10.231.0.1'
        $script:Cap.RemoveIP_Absent.removed  | Should -BeNullOrEmpty
        $script:Cap.RemoveIP_Absent.err      | Should -BeNullOrEmpty
    }

    It 'NewHostFirewallRule passes every filter, applies to every profile and enables the rule' {
        $c = $script:Cap.NewRule_Allow.call
        $script:Cap.NewRule_Allow.leaked | Should -BeFalse
        $c.Name | Should -Be 'Voidseal-sbx-allow-proxy'
        $c.Direction | Should -Be 'Inbound'
        $c.Action | Should -Be 'Allow'
        $c.Protocol | Should -Be 'TCP'
        @($c.LocalAddress) | Should -Be @('10.231.0.1')
        @($c.LocalPort) | Should -Be @('13128')
        @($c.RemoteAddress) | Should -Be @('10.231.0.2')
        @($c.InterfaceAlias) | Should -Be @('vEthernet (sbx-int)')
        $c.Profile | Should -Be 'Any'
        $c.Enabled | Should -Be 'True'
    }

    It 'creates, reads and removes firewall rules in the ACTIVE store, like the gateway address, so a crash cannot leave them past a reboot' {
        $script:Cap.NewRule_Allow.call.PolicyStore | Should -Be 'ActiveStore'
        $script:Cap.GetRule_Block.store            | Should -Be 'ActiveStore'
        $script:Cap.RemoveRule_Present.readStore   | Should -Be 'ActiveStore'
        $script:Cap.RemoveRule_Present.store       | Should -Be 'ActiveStore'
    }

    It 'GetHostFirewallRuleNames lists the voidseal group in the active store, filtered by prefix, as an array' {
        $l = $script:Cap.ListRules
        $l.err | Should -BeNullOrEmpty
        $l.isArray | Should -BeTrue
        @($l.names | Sort-Object) | Should -Be @('Voidseal-sbx-allow-proxy', 'Voidseal-sbx-block-tcp') -Because 'Voidseal-sbx2-* shares the text but not the prefix'
        $l.group | Should -Be 'Voidseal egress'
        $l.store | Should -Be 'ActiveStore'
        $script:Cap.ListRules_Case.count | Should -Be 2 -Because 'rule names compare without regard to case'
        $script:Cap.ListRules_None.count | Should -Be 0
        $script:Cap.ListRules_None.isArray | Should -BeTrue
    }

    It 'GetHostFirewallRuleNames reads a group with no rules as an empty array, and THROWS when the firewall cannot be read' {
        $script:Cap.ListRules_NoGroup.err | Should -BeNullOrEmpty
        $script:Cap.ListRules_NoGroup.count | Should -Be 0
        $script:Cap.ListRules_NoGroup.isArray | Should -BeTrue
        $script:Cap.ListRules_Fail.err | Should -Match 'firewall service unreadable'
    }

    It 'NewHostFirewallRule leaves an Any filter off the call instead of passing the word Any' {
        $keys = @($script:Cap.NewRule_AnyFilters.keys)
        $keys | Should -Not -Contain 'LocalAddress'
        $keys | Should -Not -Contain 'RemoteAddress'
        $keys | Should -Not -Contain 'LocalPort'
    }

    It 'GetHostFirewallRule reads a disabled rule as Enabled = false (the CIM enum trap) and normalizes every filter' {
        $r = $script:Cap.GetRule_DisabledAllow
        $r.err | Should -BeNullOrEmpty
        $r.enabledType | Should -Be 'Boolean'
        $r.rule.Enabled | Should -BeFalse -Because 'the real Enabled enum''s False member casts to $true under [bool]'
        $r.rule.Action | Should -Be 'Allow'
        $r.rule.Direction | Should -Be 'Inbound'
        @($r.rule.RemoteAddress) | Should -Be @('10.231.0.2')
        $b = $script:Cap.GetRule_Block.rule
        $b.Enabled | Should -BeTrue
        @($b.LocalPort) | Should -Be @('1-13127', '13129-65535')
        @($b.RemoteAddress) | Should -Be @('Any')
        @($b.InterfaceAlias) | Should -Be @('vEthernet (sbx-int)')
    }

    It 'GetHostFirewallRule returns null for a missing rule; RemoveHostFirewallRule removes a present one only' {
        $script:Cap.GetRule_Missing.err | Should -BeNullOrEmpty
        $script:Cap.GetRule_Missing.isNull | Should -BeTrue
        $script:Cap.RemoveRule_Present.removed | Should -Be 'Voidseal-sbx-allow-proxy'
        $script:Cap.RemoveRule_Missing.removed | Should -BeNullOrEmpty
        $script:Cap.RemoveRule_Missing.err | Should -BeNullOrEmpty
        $script:Cap.RemoveRule_Fail.err | Should -Match 'unreadable' -Because 'a removal that cannot read the rule must not report success'
        $script:Cap.RemoveRule_Fail.removed | Should -BeNullOrEmpty
    }

    It 'AddNetworkAdapterAcl passes the full allow tuple with Stateful, and only Action/Direction/Weight for a deny-all' {
        $a = $script:Cap.AddAcl_Allow.call
        $script:Cap.AddAcl_Allow.leaked | Should -BeFalse
        $a.VMName | Should -Be 'sbx'
        $a.Action | Should -Be 'Allow'
        $a.Direction | Should -Be 'Outbound'
        $a.Weight | Should -Be 100
        $a.Protocol | Should -Be 'TCP'
        $a.LocalIPAddress | Should -Be '10.231.0.2'
        $a.RemoteIPAddress | Should -Be '10.231.0.1'
        $a.RemotePort | Should -Be '13128'
        $a.Stateful | Should -BeTrue
        $d = $script:Cap.AddAcl_DenyAll.call
        @($d.PSObject.Properties.Name | Where-Object { $_ -ne 'ErrorAction' } | Sort-Object) | Should -Be @('Action', 'Direction', 'VMName', 'Weight')
    }

    It 'GetNetworkAdapterAcls returns an array of normalized records (enum to text, blank and ANY to Any)' {
        $g = $script:Cap.GetAcls_One
        $g.vm | Should -Be 'sbx'
        $g.isArray | Should -BeTrue
        $g.count | Should -Be 1
        $g.first.Action | Should -Be 'Deny'
        $g.first.Direction | Should -Be 'Inbound'
        $g.first.Protocol | Should -Be 'Any'
        $g.first.RemoteIPAddress | Should -Be 'Any'
        $g.first.RemotePort | Should -Be 'Any'
        $g.first.Stateful | Should -BeFalse
        $script:Cap.GetAcls_Two.first.Stateful | Should -BeTrue
        $script:Cap.GetAcls_Two.first.RemotePort | Should -Be '13128'
    }

    It 'RemoveNetworkAdapterAcl pipes only the matching entry, and does nothing for a VM that is gone' {
        @($script:Cap.RemoveAcl_Match.removed) | Should -Be @('Outbound/1')
        $script:Cap.RemoveAcl_NoVM.err | Should -BeNullOrEmpty
        $script:Cap.RemoveAcl_NoVM.read | Should -BeNullOrEmpty -Because 'no ACL read is attempted for a VM that no longer exists'
        @($script:Cap.RemoveAcl_NoVM.removed).Count | Should -Be 0
    }

    It 'GetNetNats returns an array for zero and one NAT networks' {
        $script:Cap.Nat_None.isArray | Should -BeTrue
        $script:Cap.Nat_None.count | Should -Be 0
        $script:Cap.Nat_One.isArray | Should -BeTrue
        $script:Cap.Nat_One.first.InternalIPInterfaceAddressPrefix | Should -Be '10.231.0.0/24'
    }

    It 'GetHostFirewallProfiles reads the active store and maps each profile to a plain record with a real [bool] Enabled' {
        $c = $script:Cap.Profiles_AllOn
        $c.err | Should -BeNullOrEmpty
        $c.store | Should -Be 'ActiveStore'
        $c.isArray | Should -BeTrue
        $c.count | Should -Be 3
        @($c.rows | ForEach-Object { $_.Name }) | Should -Be @('Domain', 'Private', 'Public')
        foreach ($row in $c.rows) {
            $row.EnabledType | Should -Be 'Boolean' -Because 'the GpoBoolean enum must be compared as text, never cast'
            $row.Enabled | Should -BeTrue
            $row.InboundType | Should -Be 'String'
            $row.DefaultInboundAction | Should -Be 'Block'
        }
    }

    It 'GetHostFirewallProfiles reports a disabled profile as Enabled $false (not the truthy enum) and passes Allow through as text' {
        $rows = $script:Cap.Profiles_Mixed.rows
        $script:Cap.Profiles_Mixed.err | Should -BeNullOrEmpty
        ($rows | Where-Object { $_.Name -eq 'Private' }).Enabled | Should -BeFalse -Because 'the enum False member is truthy under [bool]; the real body compares the text'
        ($rows | Where-Object { $_.Name -eq 'Public' }).DefaultInboundAction | Should -Be 'Allow'
        ($rows | Where-Object { $_.Name -eq 'Domain' }).Enabled | Should -BeTrue
    }

    It 'GetHostFirewallProfiles keeps a single profile an array, and THROWS when the cmdlet reports a failure' {
        $script:Cap.Profiles_One.isArray | Should -BeTrue
        $script:Cap.Profiles_One.count | Should -Be 1
        $script:Cap.Profiles_Fail.err | Should -Match 'firewall profiles unreadable'
    }

    It 'GetNetIPInterfaceForwarding asks for the alias in the active store and maps both families to Disabled when their rows read Disabled' {
        $c = $script:Cap.Fwd_Disabled
        $c.err | Should -BeNullOrEmpty
        $c.alias | Should -Be 'vEthernet (sbx-int)'
        $c.store | Should -Be 'ActiveStore'
        $c.result.IPv4 | Should -Be 'Disabled'
        $c.result.IPv6 | Should -Be 'Disabled'
    }

    It 'GetNetIPInterfaceForwarding reports an enabled family as Enabled, a family with no row as Missing, and one enabled row among two as Enabled' {
        $script:Cap.Fwd_V4On.result.IPv4 | Should -Be 'Enabled'
        $script:Cap.Fwd_V4On.result.IPv6 | Should -Be 'Disabled'
        $script:Cap.Fwd_NoV6.result.IPv4 | Should -Be 'Disabled'
        $script:Cap.Fwd_NoV6.result.IPv6 | Should -Be 'Missing' -Because 'a family the host does not report cannot be assumed off'
        $script:Cap.Fwd_TwoV4Rows.result.IPv4 | Should -Be 'Enabled' -Because 'one forwarding row is enough to route around the proxy'
    }

    It 'GetNetIPInterfaceForwarding THROWS for an alias the host does not know and when the cmdlet reports a failure' {
        $script:Cap.Fwd_UnknownAlias.err | Should -Match 'No MSFT_NetIPInterface objects found'
        $script:Cap.Fwd_UnknownAlias.isNull | Should -BeTrue
        $script:Cap.Fwd_Fail.err | Should -Match 'IP interface unreadable'
    }

    It 'StartEgressProxy starts a real child, waits for its ready file and records a quoted command line without null arguments' {
        $s = $script:Cap.Start_Ok
        $s.err | Should -BeNullOrEmpty
        $s.hasPid | Should -BeTrue
        $s.alive | Should -BeTrue
        $s.commandLine | Should -Match '"--allow" "api\.example\.com"$' -Because 'a null argument must be dropped, not passed as an empty string'
        $s.startTime | Should -Not -BeNullOrEmpty
        { [datetime]$s.startTime } | Should -Not -Throw -Because 'the recorded start time is a round-trip timestamp'
    }

    It 'StopEgressProxy leaves a process alone when the start time does not match (PID reuse), then stops ours via the stop file' {
        $script:Cap.Stop_WrongStartTime.result.AlreadyGone | Should -BeTrue
        $script:Cap.Stop_WrongStartTime.stillAlive | Should -BeTrue
        $script:Cap.Stop_WrongStartTime.stopFileWritten | Should -BeFalse
        $script:Cap.Stop_Ok.result.Killed | Should -BeFalse
        $script:Cap.Stop_Ok.alive | Should -BeFalse
        $script:Cap.Stop_Again.result.AlreadyGone | Should -BeTrue
    }

    It 'StopEgressProxy kills a proxy that ignores the stop file, and reports Stopped=$true only because the kill ended it' {
        $script:Cap.Stop_Kill.result.Killed | Should -BeTrue
        $script:Cap.Stop_Kill.result.Stopped | Should -BeTrue
        $script:Cap.Stop_Kill.alive | Should -BeFalse
    }

    It 'the REAL StopEgressProxy derives Stopped from the post-kill WaitForExit instead of asserting $true (AST-pinned; an unkillable process cannot be driven here)' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:LibPath, [ref]$tokens, [ref]$errors)
        $assign = $ast.FindAll({
            param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                      $n.Left.Extent.Text -eq '$b.StopEgressProxy' -and
                      $n.Right.Extent.Text -match 'GetProcessById'
        }, $true) | Select-Object -First 1
        $assign | Should -Not -BeNullOrEmpty -Because 'the real factory must define StopEgressProxy'
        # The post-kill WaitForExit result must be captured into a plain variable other than $null (the
        # outer `$b.StopEgressProxy = {...}` assignment is excluded: its Left is a member expression).
        $captured = @($assign.FindAll({
            param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                      $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                      $n.Left.Extent.Text -ne '$null' -and
                      $n.Right.Extent.Text -match 'WaitForExit\(5000\)'
        }, $true))
        $captured.Count | Should -Be 1 -Because 'the result of the post-kill wait decides Stopped'
        $stoppedVar = $captured[0].Left.Extent.Text
        # And the final return's Stopped field reads that variable, not a constant.
        $returns = @($assign.FindAll({ param($n) $n -is [System.Management.Automation.Language.ReturnStatementAst] }, $true) |
            Where-Object { $_.Extent.Text -match 'AlreadyGone = \$false' })
        $returns.Count | Should -Be 1
        $returns[0].Extent.Text | Should -Match ('Stopped = \[bool\]' + [regex]::Escape($stoppedVar))
    }

    It 'StartEgressProxy THROWS for an early exit, a ready timeout, a ready file naming another pid and a missing script' {
        $script:Cap.Start_ExitEarly.err  | Should -Match 'exited with code 4 before it was listening'
        $script:Cap.Start_NeverReady.err | Should -Match 'did not report ready within 1\.5 seconds; it was killed'
        $script:Cap.Start_WrongPid.err   | Should -Match 'ready file names pid'
        $script:Cap.Start_NoScript.err   | Should -Match 'does not exist'
    }
}
