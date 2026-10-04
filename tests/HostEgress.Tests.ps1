#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for EgressMode 'HostProxy' (scripts/lib/HostEgress.ps1) and its wiring: the address
    plan and collision check, the firewall and ACL specs, install with rollback, the proxy start, the
    seal gate's refusals, teardown, and the orchestrator order (seal gate, then proxy, then VM start).
    Everything runs against the fake backend: no host network object, no VM, no Python process.
#>

BeforeAll {
    $script:SkillRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:SkillRoot 'scripts/Invoke-Voidseal.ps1')
    $script:TierDir = Join-Path $script:SkillRoot 'tier-profiles'

    # A Tier-1 profile with EgressMode='HostProxy' and a synthetic allowlist, independent of what the
    # shipped tier file says.
    $script:T1HP = Import-TierProfile -Path (Join-Path $script:TierDir 'tier1.psd1')
    $script:T1HP['EgressMode']      = 'HostProxy'
    $script:T1HP['EgressAllowlist'] = @('api.example.com', '.files.example.org')

    $script:TmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vs-hostegress-{0}" -f ([guid]::NewGuid().ToString('N')))
    $null = New-Item -ItemType Directory -Path $script:TmpRoot -Force

    function script:New-HPVM {
        param([hashtable] $Backend, [string] $Name = 'sbx-hp')
        New-SandboxVM -Profile $script:T1HP -Name $Name -StorageRoot $script:TmpRoot -Backend $Backend
    }
    function script:New-SealedHPVM {
        param([hashtable] $Backend, [string] $Name = 'sbx-hp')
        $d = script:New-HPVM -Backend $Backend -Name $Name
        Lock-Sandbox -Descriptor $d -Backend $Backend
        $d
    }
    # The test seam for a Serial run: a workload with an entrypoint and a result file.
    function script:New-HPWorkload {
        $res = Join-Path $script:TmpRoot ("res-{0}.txt" -f ([guid]::NewGuid().ToString('N')))
        Set-Content -LiteralPath $res -Value 'artifact' -NoNewline -Encoding utf8
        @{ Entrypoint = 'bash run.sh'; ResultPath = $res }
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:TmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'HostEgress: the shipped profiles' {

    It 'tier1 ships EgressMode HostProxy, and ralph inherits it with the merged allowlist the proxy enforces' {
        (Import-TierProfile -Path (Join-Path $script:TierDir 'tier1.psd1'))['EgressMode'] | Should -Be 'HostProxy'
        $ralph = Import-WorkloadProfile -Path (Join-Path $script:SkillRoot 'profiles/ralph.psd1') -TierProfileDir $script:TierDir
        $ralph['EgressMode'] | Should -Be 'HostProxy'
        $allow = ConvertTo-EgressProxyAllowlist -Allowlist $ralph['EgressAllowlist']
        @($allow) | Should -Contain 'api.anthropic.com'
        @($allow) | Should -Contain 'claude.ai' -Because 'the workload ExtraAllowlist is merged in'
    }

    It 'the builder keeps SquidSniProxy' {
        $builder = Import-WorkloadProfile -Path (Join-Path $script:SkillRoot 'profiles/builder.psd1') -TierProfileDir $script:TierDir
        $builder['EgressMode'] | Should -Be 'SquidSniProxy'
    }
}

Describe 'HostEgress: the address plan' {

    It 'is deterministic per name, a /30 inside 10.231.0.0/16, gateway .1 and guest .2 of it' {
        $a = Get-EgressAddressPlan -VMName 'sbx-1-abc' -SwitchName 'sbx-1-abc-int'
        $b = Get-EgressAddressPlan -VMName 'sbx-1-abc' -SwitchName 'sbx-1-abc-int'
        $a.Subnet | Should -Be $b.Subnet
        $a.PrefixLength | Should -Be 30
        $a.Subnet | Should -Match '^10\.231\.\d{1,3}\.\d{1,3}/30$'
        $net = ConvertTo-EgressUInt32 -Address $a.NetworkAddress
        ($net % 4) | Should -Be 0
        (ConvertTo-EgressUInt32 -Address $a.GatewayIP) | Should -Be ($net + 1)
        (ConvertTo-EgressUInt32 -Address $a.GuestIP)   | Should -Be ($net + 2)
        $a.InterfaceAlias | Should -Be 'vEthernet (sbx-1-abc-int)'
        $a.ProxyPort | Should -Be 13128
        $a.RulePrefix | Should -Be 'Voidseal-egress-sbx-1-abc-'
    }

    It 'ignores the case of the name and differs between names' {
        (Get-EgressAddressPlan -VMName 'SBX-A' -SwitchName 's').Subnet | Should -Be (Get-EgressAddressPlan -VMName 'sbx-a' -SwitchName 's').Subnet
        $subnets = @(1..40 | ForEach-Object { (Get-EgressAddressPlan -VMName "sbx-$_" -SwitchName 's').Subnet } | Sort-Object -Unique)
        $subnets.Count | Should -BeGreaterThan 35
    }

    It 'overlap test is exact at prefix boundaries' {
        Test-EgressPrefixOverlap -AddressA '10.231.0.4' -PrefixA 30 -AddressB '10.231.0.7' -PrefixB 32 | Should -BeTrue
        Test-EgressPrefixOverlap -AddressA '10.231.0.4' -PrefixA 30 -AddressB '10.231.0.8' -PrefixB 32 | Should -BeFalse
        Test-EgressPrefixOverlap -AddressA '10.231.0.4' -PrefixA 30 -AddressB '10.0.0.1'   -PrefixB 8  | Should -BeTrue
        Test-EgressPrefixOverlap -AddressA '10.231.0.4' -PrefixA 30 -AddressB '0.0.0.0'    -PrefixB 0  | Should -BeTrue
        Test-EgressPrefixOverlap -AddressA '10.231.0.4' -PrefixA 30 -AddressB '192.168.1.20' -PrefixB 24 | Should -BeFalse
    }
}

Describe 'HostEgress: the address collision check' {

    BeforeAll { $script:Plan = Get-EgressAddressPlan -VMName 'sbx-c' -SwitchName 'sbx-c-int' }

    It 'passes on a host with only an unrelated LAN address and no NAT' {
        Get-EgressAddressConflict -Plan $script:Plan -Backend (New-FakeHyperVBackend) | Should -BeNullOrEmpty
    }

    It 'names a host address whose prefix covers the subnet' {
        $b = New-FakeHyperVBackend -SimulateHostIPAddresses @(@{ IPAddress = '10.0.5.1'; PrefixLength = 8; InterfaceAlias = 'VPN' })
        Get-EgressAddressConflict -Plan $script:Plan -Backend $b | Should -BeLike "the egress subnet $($script:Plan.Subnet) collides with host address 10.0.5.1/8 on 'VPN'*"
    }

    It 'names a NAT network covering the subnet' {
        $b = New-FakeHyperVBackend -SimulateNetNat @(@{ Name = 'ContainerNAT'; InternalIPInterfaceAddressPrefix = '10.231.0.0/16' })
        Get-EgressAddressConflict -Plan $script:Plan -Backend $b | Should -Be "NAT network 'ContainerNAT' (10.231.0.0/16) covers the egress subnet $($script:Plan.Subnet); a HostProxy VM must have no NAT route"
    }

    It 'ignores a NAT network elsewhere' {
        $b = New-FakeHyperVBackend -SimulateNetNat @(@{ Name = 'Other'; InternalIPInterfaceAddressPrefix = '172.20.0.0/16' })
        Get-EgressAddressConflict -Plan $script:Plan -Backend $b | Should -BeNullOrEmpty
    }

    It 'treats an unreadable address list, an unreadable NAT list and an unparsable NAT prefix as conflicts' {
        Get-EgressAddressConflict -Plan $script:Plan -Backend (New-FakeHyperVBackend -SimulateEgressMethodError @('GetHostIPAddresses')) |
            Should -BeLike "the host's IPv4 addresses could not be read (*), so the egress subnet $($script:Plan.Subnet) cannot be checked for a collision"
        Get-EgressAddressConflict -Plan $script:Plan -Backend (New-FakeHyperVBackend -SimulateEgressMethodError @('GetNetNats')) |
            Should -BeLike "the host's NAT networks could not be read (*), so no NAT can be proven absent from $($script:Plan.Subnet)"
        Get-EgressAddressConflict -Plan $script:Plan -Backend (New-FakeHyperVBackend -SimulateNetNat @(@{ Name = 'Odd'; InternalIPInterfaceAddressPrefix = 'garbage' })) |
            Should -Be "NAT network 'Odd' has a prefix that cannot be parsed ('garbage'), so it cannot be proven not to cover $($script:Plan.Subnet)"
    }
}

Describe 'HostEgress: the firewall and port ACL specs' {

    BeforeAll {
        $script:P = Get-EgressAddressPlan -VMName 'sbx-s' -SwitchName 'sbx-s-int'
        $script:Rules = @(Get-EgressFirewallRuleSpec -Plan $script:P)
        $script:Acls  = @(Get-EgressAclSpec -Plan $script:P)
    }

    It 'has one Allow, for TCP to gateway:proxy-port from the guest only, on the VM switch interface' {
        $allow = @($script:Rules | Where-Object { $_.Action -eq 'Allow' })
        $allow.Count | Should -Be 1
        $allow[0].Protocol | Should -Be 'TCP'
        @($allow[0].LocalAddress) | Should -Be @($script:P.GatewayIP)
        @($allow[0].LocalPort) | Should -Be @('13128')
        @($allow[0].RemoteAddress) | Should -Be @($script:P.GuestIP)
        foreach ($r in $script:Rules) {
            $r.Direction | Should -Be 'Inbound'
            $r.InterfaceAlias | Should -Be $script:P.InterfaceAlias
            $r.Name | Should -BeLike "$($script:P.RulePrefix)*"
        }
    }

    It 'blocks every other TCP port, the proxy port from any other address, UDP, ICMP and other local addresses' {
        $byName = @{}; foreach ($r in $script:Rules) { $byName[$r.Name.Substring($script:P.RulePrefix.Length)] = $r }
        @($byName['block-tcp-ports'].LocalPort) | Should -Be @('1-13127', '13129-65535')
        @($byName['block-proxy-others'].LocalPort) | Should -Be @('13128')
        $guest = ConvertTo-EgressUInt32 $script:P.GuestIP
        @($byName['block-proxy-others'].RemoteAddress) | Should -Be @(('0.0.0.0-' + (ConvertFrom-EgressUInt32 ($guest - 1))), ((ConvertFrom-EgressUInt32 ($guest + 1)) + '-255.255.255.255'))
        $byName['block-udp'].Protocol | Should -Be 'UDP'
        $byName['block-icmp4'].Protocol | Should -Be 'ICMPv4'
        $byName['block-icmp6'].Protocol | Should -Be 'ICMPv6'
        $byName['block-other-local'].Protocol | Should -Be 'Any'
        $gw = ConvertTo-EgressUInt32 $script:P.GatewayIP
        @($byName['block-other-local'].LocalAddress) | Should -Contain ('0.0.0.0-' + (ConvertFrom-EgressUInt32 ($gw - 1)))
        @($byName['block-other-local'].LocalAddress) | Should -Contain ('::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
        @($script:Rules | Where-Object { $_.Action -eq 'Block' }).Count | Should -Be 6
    }

    It 'no Block rule matches the allowed tuple (a Windows Block beats any Allow)' {
        $gw = ConvertTo-EgressUInt32 $script:P.GatewayIP; $guest = ConvertTo-EgressUInt32 $script:P.GuestIP
        $inRanges = {
            param([string[]] $Ranges, [uint64] $Value, [scriptblock] $Parse)
            foreach ($r in $Ranges) {
                if ($r -eq 'Any') { return $true }
                if ($r.Contains(':')) { continue }
                $lo, $hi = if ($r.Contains('-')) { $r.Split('-') } else { $r, $r }
                if ($Value -ge (& $Parse $lo) -and $Value -le (& $Parse $hi)) { return $true }
            }
            return $false
        }
        $ipParse = { param($t) [uint64](ConvertTo-EgressUInt32 $t) }
        $portParse = { param($t) [uint64]$t }
        foreach ($r in @($script:Rules | Where-Object { $_.Action -eq 'Block' })) {
            $protoHits = $r.Protocol -in @('TCP', 'Any')
            $hit = $protoHits -and (& $inRanges $r.LocalAddress $gw $ipParse) -and (& $inRanges $r.LocalPort 13128 $portParse) -and (& $inRanges $r.RemoteAddress $guest $ipParse)
            $hit | Should -BeFalse -Because "Block rule $($r.Name) would also block the guest's proxy connection"
        }
    }

    It 'port ACL: deny all both ways at weight 1, allow stateful TCP guest to gateway:proxy at weight 100' {
        $script:Acls.Count | Should -Be 3
        $deny = @($script:Acls | Where-Object { $_.Action -eq 'Deny' })
        @($deny | ForEach-Object { $_.Direction } | Sort-Object) | Should -Be @('Inbound', 'Outbound')
        foreach ($d in $deny) { $d.Weight | Should -Be 1; $d.RemoteIPAddress | Should -Be 'Any' }
        $allow = @($script:Acls | Where-Object { $_.Action -eq 'Allow' })[0]
        $allow.Direction | Should -Be 'Outbound'
        $allow.Weight | Should -Be 100
        $allow.Protocol | Should -Be 'TCP'
        $allow.LocalIPAddress | Should -Be $script:P.GuestIP
        $allow.RemoteIPAddress | Should -Be $script:P.GatewayIP
        $allow.RemotePort | Should -Be '13128'
        $allow.Stateful | Should -BeTrue
    }
}

Describe 'HostEgress: the proxy allowlist and arguments' {

    It 'turns a leading-dot entry into the domain and an explicit suffix rule, and drops case-insensitive duplicates' {
        $out = ConvertTo-EgressProxyAllowlist -Allowlist @('api.example.com', '.files.example.org', 'API.example.com', '')
        @($out) | Should -Be @('api.example.com', 'files.example.org', '*.files.example.org')
    }

    It 'binds the gateway address, never an unspecified one, and passes every allowlist entry' {
        $p = Get-EgressAddressPlan -VMName 'sbx-a' -SwitchName 'sbx-a-int'
        $argv = Get-EgressProxyArguments -Plan $p -Allowlist @('api.example.com', '*.x.example.org') -LogPath 'C:\r\l.log' -StopFile 'C:\r\s' -ReadyFile 'C:\r\r.json' -MaxLifetimeSeconds 1500 -ParentPid 4242
        $i = [array]::IndexOf($argv, '--listen-host'); $argv[$i + 1] | Should -Be $p.GatewayIP
        $i = [array]::IndexOf($argv, '--listen-port'); $argv[$i + 1] | Should -Be '13128'
        $i = [array]::IndexOf($argv, '--max-lifetime-seconds'); $argv[$i + 1] | Should -Be '1500'
        $i = [array]::IndexOf($argv, '--parent-pid'); $argv[$i + 1] | Should -Be '4242'
        ($argv -join ' ') | Should -BeLike '*--allow api.example.com --allow `*.x.example.org*'
        $argv | Should -Not -Contain '0.0.0.0'
    }
}

Describe 'HostEgress: provisioning records the plan and refuses a collision before creating anything' {

    It 'a Tier-1 HostProxy VM records EgressMode and the plan for its own switch' {
        $b = New-FakeHyperVBackend
        $d = script:New-HPVM -Backend $b -Name 'sbx-hp-prov'
        $d.EgressMode | Should -Be 'HostProxy'
        $d.Egress.SwitchName | Should -Be 'sbx-hp-prov-int'
        $d.Egress.Subnet | Should -Be (Get-EgressAddressPlan -VMName 'sbx-hp-prov' -SwitchName 'sbx-hp-prov-int').Subnet
        $d.EgressGatewayAddress | Should -BeNullOrEmpty -Because 'nothing is installed on the host until the seal'
    }

    It 'an InGuestSquid Tier-1 VM and a Tier-0 VM get no plan' {
        $b = New-FakeHyperVBackend
        $sq = $script:T1HP.Clone(); $sq['EgressMode'] = 'InGuestSquid'
        (New-SandboxVM -Profile $sq -Name 'sbx-sq' -StorageRoot $script:TmpRoot -Backend $b).Egress | Should -BeNullOrEmpty
        $t0 = Import-TierProfile -Path (Join-Path $script:TierDir 'tier0.psd1')
        $d0 = New-SandboxVM -Profile $t0 -Name 'sbx-t0' -StorageRoot $script:TmpRoot -Backend $b
        $d0.EgressMode | Should -Be 'HostProxy'
        $d0.Egress | Should -BeNullOrEmpty -Because 'a Tier-0 VM is sealed with no adapter, so it has no egress to plan'
    }

    It 'refuses with a named message, and creates nothing, when a NAT covers the subnet' {
        $b = New-FakeHyperVBackend -SimulateNetNat @(@{ Name = 'WideNAT'; InternalIPInterfaceAddressPrefix = '10.231.0.0/16' })
        $plan = Get-EgressAddressPlan -VMName 'sbx-hp-nat' -SwitchName 'sbx-hp-nat-int'
        { script:New-HPVM -Backend $b -Name 'sbx-hp-nat' } |
            Should -Throw "New-SandboxVM: refusing 'sbx-hp-nat' because NAT network 'WideNAT' (10.231.0.0/16) covers the egress subnet $($plan.Subnet); a HostProxy VM must have no NAT route. Fail closed."
        & $b.GetVM @{ Name = 'sbx-hp-nat' } | Should -BeNullOrEmpty
        & $b.GetSwitch @{ Name = 'sbx-hp-nat-int' } | Should -BeNullOrEmpty
    }

    It 'refuses when the host addresses cannot be read' {
        $b = New-FakeHyperVBackend -SimulateEgressMethodError @('GetHostIPAddresses')
        { script:New-HPVM -Backend $b -Name 'sbx-hp-unread' } | Should -Throw "New-SandboxVM: refusing 'sbx-hp-unread' because the host's IPv4 addresses could not be read*Fail closed."
        & $b.GetVM @{ Name = 'sbx-hp-unread' } | Should -BeNullOrEmpty
    }
}

Describe 'HostEgress: Lock-Sandbox installs, records and rolls back' {

    It 'installs the gateway address, the seven rules and the three ACL entries, and records each' {
        $b = New-FakeHyperVBackend
        $d = script:New-SealedHPVM -Backend $b -Name 'sbx-hp-inst'
        $d.EgressGatewayAddress | Should -Be $d.Egress.GatewayIP
        @($d.EgressFirewallRules).Count | Should -Be 7
        @($d.EgressAcls).Count | Should -Be 3
        $ips = & $b.GetHostIPAddresses @{}
        @($ips | Where-Object { $_.IPAddress -eq $d.Egress.GatewayIP -and $_.InterfaceAlias -eq 'vEthernet (sbx-hp-inst-int)' }).Count | Should -Be 1
        foreach ($r in $d.EgressFirewallRules) { & $b.GetHostFirewallRule @{ Name = $r.Name } | Should -Not -BeNullOrEmpty }
        (& $b.GetNetworkAdapterAcls @{ VMName = 'sbx-hp-inst' }).Count | Should -Be 3
        @($b.FakeCallLog | Where-Object { $_.Op -eq 'StartEgressProxy' }).Count | Should -Be 0 -Because 'the proxy starts only after the gate, in the orchestrator'
    }

    It 'a failure part way rolls back everything it created and says so' {
        $b = New-FakeHyperVBackend -SimulateEgressMethodError @('AddNetworkAdapterAcl')
        $d = script:New-HPVM -Backend $b -Name 'sbx-hp-rb'
        { Lock-Sandbox -Descriptor $d -Backend $b } | Should -Throw "Install-SandboxEgressNetwork: installing host egress for 'sbx-hp-rb' failed (*SimulateEgressMethodError*); everything it had created was removed. Fail closed."
        $d.EgressGatewayAddress | Should -BeNullOrEmpty
        @($d.EgressFirewallRules).Count | Should -Be 0
        @($b.FakeFirewallRules.Keys).Count | Should -Be 0
        $ips = & $b.GetHostIPAddresses @{}
        @($ips | Where-Object { $_.IPAddress -eq $d.Egress.GatewayIP }).Count | Should -Be 0
    }

    It 'a rollback that cannot remove something keeps it recorded for teardown and names it' {
        $b = New-FakeHyperVBackend -SimulateEgressMethodError @('AddNetworkAdapterAcl', 'RemoveHostFirewallRule')
        $d = script:New-HPVM -Backend $b -Name 'sbx-hp-rb2'
        { Lock-Sandbox -Descriptor $d -Backend $b } | Should -Throw "*rollback could not remove 7 object(s), still recorded for teardown*"
        @($d.EgressFirewallRules).Count | Should -Be 7
        $d.EgressGatewayAddress | Should -BeNullOrEmpty -Because 'the address removal itself worked'
    }

    It 're-checks the subnet at the seal: a NAT that appeared after provisioning stops the install' {
        $b = New-FakeHyperVBackend
        $d = script:New-HPVM -Backend $b -Name 'sbx-hp-late'
        $b2 = $b.Clone()
        $b2.GetNetNats = { param($P) return ,@(@{ Name = 'LateNAT'; InternalIPInterfaceAddressPrefix = '10.231.0.0/16' }) }
        { Lock-Sandbox -Descriptor $d -Backend $b2 } | Should -Throw "Install-SandboxEgressNetwork: refusing 'sbx-hp-late' because NAT network 'LateNAT'*Fail closed."
        $d.EgressGatewayAddress | Should -BeNullOrEmpty
    }
}

Describe 'HostEgress: leftover rules from a crashed run stop the install before anything is created' {

    It 'refuses, naming the rules and the cleanup command, and creates no address, rule or ACL' {
        $b = New-FakeHyperVBackend
        $d = script:New-HPVM -Backend $b -Name 'sbx-hp-stale'
        & $b.NewHostFirewallRule @{ Name = 'Voidseal-egress-sbx-hp-stale-block-udp'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; InterfaceAlias = 'vEthernet (sbx-hp-stale-int)' }
        $err = $null
        try { Lock-Sandbox -Descriptor $d -Backend $b } catch { $err = $_.Exception.Message }
        $err | Should -Match "^Install-SandboxEgressNetwork: refusing 'sbx-hp-stale' because 1 firewall rule\(s\) named 'Voidseal-egress-sbx-hp-stale-\*' already exist"
        $err | Should -Match "Remove-NetFirewallRule -Name 'Voidseal-egress-sbx-hp-stale-block-udp' -PolicyStore ActiveStore"
        $err | Should -Match 'Fail closed\.$'
        @($b.FakeCallLog | Where-Object { $_.Op -in @('AddSwitchHostIPAddress', 'AddNetworkAdapterAcl') }).Count | Should -Be 0
        @($b.FakeFirewallRules.Keys).Count | Should -Be 1 -Because 'only the leftover rule exists; none of the seven was created'
        $d.EgressGatewayAddress | Should -BeNullOrEmpty
        @($d.EgressFirewallRules).Count | Should -Be 0
        @($d.EgressAcls).Count | Should -Be 0
    }

    It 'names every leftover rule, whatever its case' {
        $b = New-FakeHyperVBackend
        $d = script:New-HPVM -Backend $b -Name 'sbx-hp-stale2'
        foreach ($n in @('Voidseal-egress-sbx-hp-stale2-allow-proxy', 'VOIDSEAL-EGRESS-SBX-HP-STALE2-BLOCK-ICMP4')) {
            & $b.NewHostFirewallRule @{ Name = $n; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; InterfaceAlias = 'vEthernet (sbx-hp-stale2-int)' }
        }
        { Lock-Sandbox -Descriptor $d -Backend $b } | Should -Throw "*2 firewall rule(s)*Voidseal-egress-sbx-hp-stale2-allow-proxy*VOIDSEAL-EGRESS-SBX-HP-STALE2-BLOCK-ICMP4*"
    }

    It 'a rule of another VM whose name merely starts with this VM''s prefix is not a clash' {
        $b = New-FakeHyperVBackend
        $d = script:New-HPVM -Backend $b -Name 'sbx-hp-st'
        & $b.NewHostFirewallRule @{ Name = 'Voidseal-egress-sbx-hp-st-x-allow-proxy'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; InterfaceAlias = 'vEthernet (sbx-hp-st-int)' }
        { Lock-Sandbox -Descriptor $d -Backend $b } | Should -Not -Throw
        @($d.EgressFirewallRules).Count | Should -Be 7
    }

    It 'refuses, and creates nothing, when the existing rules cannot be read' {
        $b = New-FakeHyperVBackend -SimulateEgressMethodError @('GetHostFirewallRuleNames')
        $d = script:New-HPVM -Backend $b -Name 'sbx-hp-stale3'
        { Lock-Sandbox -Descriptor $d -Backend $b } | Should -Throw "Install-SandboxEgressNetwork: refusing 'sbx-hp-stale3' because the existing firewall rules could not be read (*SimulateEgressMethodError*). Fail closed."
        @($b.FakeCallLog | Where-Object { $_.Op -eq 'AddSwitchHostIPAddress' }).Count | Should -Be 0
        @($b.FakeFirewallRules.Keys).Count | Should -Be 0
    }

    It 'a clean host installs as before' {
        $b = New-FakeHyperVBackend
        $d = script:New-SealedHPVM -Backend $b -Name 'sbx-hp-clean'
        @($d.EgressFirewallRules).Count | Should -Be 7
    }
}

Describe 'HostEgress: Assert-Sealed refusals for a Tier-1 HostProxy VM (each message pinned)' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        $script:D = script:New-SealedHPVM -Backend $script:B -Name 'sbx-g'
        $script:Head = "Assert-Sealed: REFUSING to certify Tier-1 HostProxy VM 'sbx-g' SEALED because"
    }

    It 'certifies the untouched install' {
        Assert-Sealed -Descriptor $script:D -Backend $script:B | Should -BeTrue
    }

    It 'refuses a descriptor that records HostProxy but no plan' {
        $script:D.Egress = $null
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) the descriptor records EgressMode='HostProxy' but no egress plan. Fail closed."
    }

    It 'refuses a plan made for another VM or switch' {
        $script:D.Egress = Get-EgressAddressPlan -VMName 'sbx-other' -SwitchName 'sbx-other-int'
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) its egress plan was made for VM 'sbx-other' on switch 'sbx-other-int', not this VM on 'sbx-g-int'. Fail closed."
    }

    It 'refuses a plan whose addresses do not follow from its name' {
        $script:D.Egress.GatewayIP = '10.231.255.253'
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) its recorded egress plan field 'GatewayIP' ('10.231.255.253') differs from the address plan for its name (*). Fail closed."
    }

    It 'refuses a short firewall-rule record' {
        $script:D.EgressFirewallRules = @($script:D.EgressFirewallRules | Select-Object -First 6)
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) the descriptor records 6 host firewall rule(s) that are not the 7 its egress plan requires. Fail closed."
    }

    It 'refuses a short ACL record' {
        $script:D.EgressAcls = @($script:D.EgressAcls | Select-Object -First 2)
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) the descriptor records 2 port ACL entr(ies) that are not the 3 its egress plan requires. Fail closed."
    }

    It 'refuses when the gateway address is not recorded as installed' {
        $script:D.EgressGatewayAddress = $null
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) the descriptor does not record the gateway address $($script:D.Egress.GatewayIP) as installed. Fail closed."
    }

    It 'refuses when the gateway address is gone from the switch' {
        & $script:B.RemoveSwitchHostIPAddress @{ SwitchName = 'sbx-g-int'; IPAddress = $script:D.Egress.GatewayIP }
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) the gateway address $($script:D.Egress.GatewayIP)/30 is not on 'vEthernet (sbx-g-int)'. Fail closed."
    }

    It 'refuses when the host addresses cannot be read' {
        $b2 = $script:B.Clone(); $b2.GetHostIPAddresses = { param($P) throw 'stub: unreadable' }
        { Assert-Sealed -Descriptor $script:D -Backend $b2 } | Should -Throw "$($script:Head) the host's IPv4 addresses could not be read (stub: unreadable). Fail closed."
    }

    It 'refuses when another host interface overlaps the subnet' {
        $b2 = $script:B.Clone()
        $real = $script:B.GetHostIPAddresses
        $b2.GetHostIPAddresses = { param($P) $l = [System.Collections.Generic.List[object]]::new(); foreach ($x in (& $real @{})) { $l.Add($x) }; $l.Add(@{ IPAddress = '10.231.0.9'; PrefixLength = 16; InterfaceAlias = 'Rogue' }); return ,$l.ToArray() }.GetNewClosure()
        { Assert-Sealed -Descriptor $script:D -Backend $b2 } | Should -Throw "$($script:Head) the egress subnet $($script:D.Egress.Subnet) collides with host address 10.231.0.9/16 on 'Rogue'*. Fail closed."
    }

    It 'refuses when a NAT covers the subnet' {
        $b2 = $script:B.Clone(); $b2.GetNetNats = { param($P) return ,@(@{ Name = 'SneakyNAT'; InternalIPInterfaceAddressPrefix = '10.231.0.0/16' }) }
        { Assert-Sealed -Descriptor $script:D -Backend $b2 } | Should -Throw "$($script:Head) NAT network 'SneakyNAT' (10.231.0.0/16) covers the egress subnet $($script:D.Egress.Subnet); a HostProxy VM must have no NAT route. Fail closed."
    }

    It 'refuses when the NAT list cannot be read' {
        $b2 = $script:B.Clone(); $b2.GetNetNats = { param($P) throw 'stub: winnat down' }
        { Assert-Sealed -Descriptor $script:D -Backend $b2 } | Should -Throw "$($script:Head) the host's NAT networks could not be read (stub: winnat down), so no NAT can be proven absent from $($script:D.Egress.Subnet). Fail closed."
    }

    It 'refuses a missing firewall rule' {
        $name = $script:D.EgressFirewallRules[3].Name
        & $script:B.RemoveHostFirewallRule @{ Name = $name }
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) host firewall rule '$name' is missing. Fail closed."
    }

    It 'refuses a disabled firewall rule' {
        $name = $script:D.EgressFirewallRules[0].Name
        $script:B.FakeFirewallRules[$name].Enabled = $false
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) host firewall rule '$name' is disabled. Fail closed."
    }

    It 'refuses a firewall rule edited outside the tool' {
        $name = $script:D.EgressFirewallRules[0].Name
        $script:B.FakeFirewallRules[$name].RemoteAddress = [string[]]@('Any')
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) host firewall rule '$name' differs from its record (direction, action, protocol, addresses, ports or interface). Fail closed."
    }

    It 'refuses when a firewall rule cannot be read' {
        $b2 = $script:B.Clone(); $b2.GetHostFirewallRule = { param($P) throw 'stub: firewall service down' }
        $name = $script:D.EgressFirewallRules[0].Name
        { Assert-Sealed -Descriptor $script:D -Backend $b2 } | Should -Throw "$($script:Head) host firewall rule '$name' could not be read (stub: firewall service down). Fail closed."
    }

    It 'refuses an extra port ACL entry (an added Allow would widen the port)' {
        & $script:B.AddNetworkAdapterAcl @{ VMName = 'sbx-g'; Action = 'Allow'; Direction = 'Outbound'; Weight = 200 }
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) its network adapter carries 4 port ACL entr(ies), not exactly the 3 recorded. Fail closed."
    }

    It 'refuses a missing port ACL entry' {
        & $script:B.RemoveNetworkAdapterAcl @{ VMName = 'sbx-g'; Action = 'Deny'; Direction = 'Inbound'; Weight = 1 }
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "$($script:Head) its network adapter carries 2 port ACL entr(ies), not exactly the 3 recorded. Fail closed."
    }

    It 'refuses when the port ACL cannot be read, or the read returns no collection' {
        $b2 = $script:B.Clone(); $b2.GetNetworkAdapterAcls = { param($P) throw 'stub: acl read' }
        { Assert-Sealed -Descriptor $script:D -Backend $b2 } | Should -Throw "$($script:Head) its port ACL could not be read (stub: acl read). Fail closed."
        $b3 = $script:B.Clone(); $b3.GetNetworkAdapterAcls = { param($P) $null }
        { Assert-Sealed -Descriptor $script:D -Backend $b3 } | Should -Throw "$($script:Head) its port ACL read returned no collection. Fail closed."
    }

    It 'still applies the switch checks first (the egress checks are added, not instead)' {
        & $script:B.NewSwitch @{ Name = 'other-int'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'sbx-g'; SwitchName = 'other-int' }
        { Assert-Sealed -Descriptor $script:D -Backend $script:B } | Should -Throw "*its NIC is on switch 'other-int', not this VM's own recorded switch 'sbx-g-int'*"
    }

    It 'an InGuestSquid Tier-1 VM is not held to the HostProxy checks' {
        $b = New-FakeHyperVBackend
        $sq = $script:T1HP.Clone(); $sq['EgressMode'] = 'InGuestSquid'
        $d = New-SandboxVM -Profile $sq -Name 'sbx-sq2' -StorageRoot $script:TmpRoot -Backend $b
        Lock-Sandbox -Descriptor $d -Backend $b
        Assert-Sealed -Descriptor $d -Backend $b | Should -BeTrue
        @($b.FakeCallLog | Where-Object { $_.Op -eq 'AddSwitchHostIPAddress' }).Count | Should -Be 0
    }
}

Describe 'HostEgress: teardown removes exactly what was recorded' {

    It 'Remove-Sandbox stops the proxy, then removes the ACL entries, rules and address, and the switch' {
        $b = New-FakeHyperVBackend
        $d = script:New-SealedHPVM -Backend $b -Name 'sbx-td'
        Start-SandboxEgressProxy -Descriptor $d -Allowlist @('api.example.com') -RunDirectory (Join-Path $script:TmpRoot 'run-td') -MaxLifetimeSeconds 600 -PythonExe 'C:\py\python.exe' -Backend $b
        $procId = $d.EgressProxy.ProcessId
        # A rule this run did NOT create, on the same interface, must survive.
        & $b.NewHostFirewallRule @{ Name = 'Operator-own-rule'; Direction = 'Inbound'; Action = 'Block'; Protocol = 'UDP'; InterfaceAlias = 'vEthernet (sbx-td-int)' }
        Remove-Sandbox -Name 'sbx-td' -DeleteDisks -Descriptor $d -Backend $b
        $b.FakeEgressProcesses[$procId].Running | Should -BeFalse
        @($b.FakeFirewallRules.Keys) | Should -Be @('Operator-own-rule')
        $ips = & $b.GetHostIPAddresses @{}
        @($ips | Where-Object { $_.IPAddress -eq $d.Egress.GatewayIP }).Count | Should -Be 0
        & $b.GetSwitch @{ Name = 'sbx-td-int' } | Should -BeNullOrEmpty
        $d.EgressProxy | Should -BeNullOrEmpty
        @($d.EgressFirewallRules).Count | Should -Be 0
        @($d.EgressAcls).Count | Should -Be 0
        $d.EgressGatewayAddress | Should -BeNullOrEmpty
        $order = @($b.FakeCallLog | Where-Object { $_.Op -in @('StopEgressProxy', 'RemoveNetworkAdapterAcl', 'RemoveHostFirewallRule', 'RemoveSwitchHostIPAddress') } | ForEach-Object { $_.Op } | Select-Object -Unique)
        $order | Should -Be @('StopEgressProxy', 'RemoveNetworkAdapterAcl', 'RemoveHostFirewallRule', 'RemoveSwitchHostIPAddress')
    }

    It 'a removal that fails still runs the rest of teardown, keeps the record, and Remove-Sandbox throws naming it' {
        $b = New-FakeHyperVBackend
        $d = script:New-SealedHPVM -Backend $b -Name 'sbx-td2'
        $b2 = $b.Clone(); $b2.RemoveSwitchHostIPAddress = { param($P) throw 'stub: address stuck' }
        { Remove-Sandbox -Name 'sbx-td2' -DeleteDisks -Descriptor $d -Backend $b2 } | Should -Throw "Remove-Sandbox: host egress teardown for 'sbx-td2' could not remove: gateway address $($d.Egress.GatewayIP) on 'vEthernet (sbx-td2-int)': stub: address stuck"
        & $b.GetVM @{ Name = 'sbx-td2' } | Should -BeNullOrEmpty -Because 'the VM is still removed'
        @($d.EgressFirewallRules).Count | Should -Be 0
        $d.EgressGatewayAddress | Should -Be $d.Egress.GatewayIP -Because 'what could not be removed stays recorded'
    }
}

Describe 'HostEgress: Start-SandboxEgressProxy' {

    It 'refuses a descriptor without HostProxy, a second start and an empty allowlist' {
        $b = New-FakeHyperVBackend
        $d = script:New-SealedHPVM -Backend $b -Name 'sbx-px'
        $run = Join-Path $script:TmpRoot 'run-px'
        { Start-SandboxEgressProxy -Descriptor $d -Allowlist @() -RunDirectory $run -MaxLifetimeSeconds 60 -PythonExe 'py' -Backend $b } |
            Should -Throw "Start-SandboxEgressProxy: 'sbx-px' has an empty EgressAllowlist; a HostProxy run must allow at least one name. Fail closed."
        Start-SandboxEgressProxy -Descriptor $d -Allowlist @('api.example.com') -RunDirectory $run -MaxLifetimeSeconds 60 -PythonExe 'py' -Backend $b
        { Start-SandboxEgressProxy -Descriptor $d -Allowlist @('api.example.com') -RunDirectory $run -MaxLifetimeSeconds 60 -PythonExe 'py' -Backend $b } |
            Should -Throw "Start-SandboxEgressProxy: 'sbx-px' already records a running egress proxy. Fail closed."
        $plain = [pscustomobject]@{ Name = 'x'; EgressMode = 'InGuestSquid'; Egress = $null }
        { Start-SandboxEgressProxy -Descriptor $plain -Allowlist @('a.example.com') -RunDirectory $run -MaxLifetimeSeconds 60 -PythonExe 'py' -Backend $b } |
            Should -Throw "Start-SandboxEgressProxy: 'x' does not record EgressMode='HostProxy' with an Egress plan. Fail closed."
    }

    It 'records pid, start time, command line and the run-folder log, and launches the repo proxy script' {
        $b = New-FakeHyperVBackend
        $d = script:New-SealedHPVM -Backend $b -Name 'sbx-px2'
        $run = Join-Path $script:TmpRoot 'run-px2'
        Start-SandboxEgressProxy -Descriptor $d -Allowlist @('api.example.com', '.files.example.org') -RunDirectory $run -MaxLifetimeSeconds 60 -PythonExe 'C:\py\python.exe' -Backend $b
        $d.EgressProxy.ProcessId | Should -BeGreaterThan 0
        $d.EgressProxy.StartTime | Should -Not -BeNullOrEmpty
        $d.EgressProxy.LogPath | Should -Be (Join-Path $run 'egress-proxy.log')
        $d.EgressProxy.CommandLine | Should -BeLike '"C:\py\python.exe" "*voidseal_egress_proxy.py" "--listen-host" "10.231.*'
        $d.EgressProxy.CommandLine | Should -BeLike '*"--allow" "files.example.org" "--allow" "`*.files.example.org"*'
        @($d.EgressProxy.Allowlist) | Should -Be @('api.example.com', 'files.example.org', '*.files.example.org')
    }

    It 'a backend start failure throws and records nothing' {
        $b = New-FakeHyperVBackend -SimulateEgressMethodError @('StartEgressProxy')
        $d = script:New-SealedHPVM -Backend $b -Name 'sbx-px3'
        { Start-SandboxEgressProxy -Descriptor $d -Allowlist @('api.example.com') -RunDirectory (Join-Path $script:TmpRoot 'run-px3') -MaxLifetimeSeconds 60 -PythonExe 'py' -Backend $b } | Should -Throw '*SimulateEgressMethodError*'
        $d.EgressProxy | Should -BeNullOrEmpty
    }
}

Describe 'HostEgress: Invoke-Voidseal runs the gate, then the proxy, then the guest, and cleans up' {

    It 'a Serial HostProxy run: seal gate, proxy start, VM start, in that order; proxy stopped and objects gone after' {
        $b = New-FakeHyperVBackend
        $art = Join-Path $script:TmpRoot ("art-{0}" -f ([guid]::NewGuid().ToString('N')))
        $report = Invoke-Voidseal -Tier 1 -Profile $script:T1HP -Workload (script:New-HPWorkload) -Name 'sbx-orch' -ArtifactRoot $art -Backend $b
        $report.Error | Should -BeNullOrEmpty
        $report.SealVerdict | Should -BeTrue
        @($report.States) | Should -Contain 'DESTROYED'
        $report.EgressProxyLog | Should -Be (Join-Path $art 'egress-proxy.log')
        $ops = @($b.FakeCallLog | ForEach-Object { $_.Op })
        $iAcl   = [array]::IndexOf($ops, 'AddNetworkAdapterAcl')
        $iProxy = [array]::IndexOf($ops, 'StartEgressProxy')
        $iStart = [array]::IndexOf($ops, 'StartVM')
        $iStop  = [array]::IndexOf($ops, 'StopEgressProxy')
        $iAcl   | Should -BeGreaterOrEqual 0
        $iProxy | Should -BeGreaterThan $iAcl
        $iStart | Should -BeGreaterThan $iProxy -Because 'the guest must never boot before its proxy is listening'
        $iStop  | Should -BeGreaterThan $iStart
        @($b.FakeFirewallRules.Keys).Count | Should -Be 0
        @($b.FakeEgressProcesses.Values | Where-Object { $_.Running }).Count | Should -Be 0
        $report.TeardownStatus | Should -BeLike 'OK*'
    }

    It 'the seed carries the static address, the proxy settings and a network-config with no route or resolver' {
        $b = New-FakeHyperVBackend
        $report = Invoke-Voidseal -Tier 1 -Profile $script:T1HP -Workload (script:New-HPWorkload) -Name 'sbx-orch-seed' `
            -ArtifactRoot (Join-Path $script:TmpRoot ("art-{0}" -f ([guid]::NewGuid().ToString('N')))) -Backend $b
        $seed = [string]$report.Descriptor.SeedDiskPath
        $writes = @($b.FakeCallLog | Where-Object { $_.Op -eq 'WriteVhdxFile' -and $_.Path -eq $seed })
        @($writes | ForEach-Object { $_.InnerPath } | Sort-Object) | Should -Be @('meta-data', 'network-config', 'user-data')
        $plan = Get-EgressAddressPlan -VMName 'sbx-orch-seed' -SwitchName 'sbx-orch-seed-int'
        $nc = [string]($writes | Where-Object { $_.InnerPath -eq 'network-config' }).Content
        $nc | Should -Match ([regex]::Escape("- $($plan.GuestIP)/30"))
        $nc | Should -Not -Match 'gateway|routes|nameservers'
        $ud = [string]($writes | Where-Object { $_.InnerPath -eq 'user-data' }).Content
        $ud | Should -Match ([regex]::Escape("HTTPS_PROXY=http://$($plan.GatewayIP):13128"))
    }

    It 'a seal-gate refusal never starts the proxy or the VM, and teardown removes what Lock-Sandbox installed' {
        $b = New-FakeHyperVBackend -SimulateChannelReadError
        $report = Invoke-Voidseal -Tier 1 -Profile $script:T1HP -Workload (script:New-HPWorkload) -Name 'sbx-orch-gate' `
            -ArtifactRoot (Join-Path $script:TmpRoot ("art-{0}" -f ([guid]::NewGuid().ToString('N')))) -Backend $b
        $report.SealVerdict | Should -BeFalse
        @($b.FakeCallLog | Where-Object { $_.Op -in @('StartEgressProxy', 'StartVM') }).Count | Should -Be 0
        @($b.FakeFirewallRules.Keys).Count | Should -Be 0
        $ips = & $b.GetHostIPAddresses @{}
        @($ips | Where-Object { $_.IPAddress -like '10.231.*' }).Count | Should -Be 0
    }

    It 'a proxy that fails to start aborts before the VM starts, and the run still tears down' {
        $b = New-FakeHyperVBackend -SimulateEgressMethodError @('StartEgressProxy')
        $report = Invoke-Voidseal -Tier 1 -Profile $script:T1HP -Workload (script:New-HPWorkload) -Name 'sbx-orch-px' `
            -ArtifactRoot (Join-Path $script:TmpRoot ("art-{0}" -f ([guid]::NewGuid().ToString('N')))) -Backend $b
        $report.Error | Should -BeLike '*StartEgressProxy*'
        @($b.FakeCallLog | Where-Object { $_.Op -eq 'StartVM' }).Count | Should -Be 0
        & $b.GetVM @{ Name = 'sbx-orch-px' } | Should -BeNullOrEmpty
        @($b.FakeFirewallRules.Keys).Count | Should -Be 0
    }

    It 'a teardown that cannot remove a host object is reported on TeardownStatus' {
        $b = New-FakeHyperVBackend -SimulateEgressMethodError @('RemoveHostFirewallRule')
        $report = Invoke-Voidseal -Tier 1 -Profile $script:T1HP -Workload (script:New-HPWorkload) -Name 'sbx-orch-td' `
            -ArtifactRoot (Join-Path $script:TmpRoot ("art-{0}" -f ([guid]::NewGuid().ToString('N')))) -Backend $b
        $report.TeardownStatus | Should -BeLike "FAILED: Remove-Sandbox: host egress teardown for 'sbx-orch-td' could not remove: firewall rule*"
    }

    It 'a Serial run with no entrypoint never boots, so no proxy is started' {
        $b = New-FakeHyperVBackend
        $report = Invoke-Voidseal -Tier 1 -Profile $script:T1HP -Name 'sbx-orch-noep' `
            -ArtifactRoot (Join-Path $script:TmpRoot ("art-{0}" -f ([guid]::NewGuid().ToString('N')))) -Backend $b
        $report.SealVerdict | Should -BeTrue
        @($b.FakeCallLog | Where-Object { $_.Op -eq 'StartEgressProxy' }).Count | Should -Be 0
        $report.EgressProxyLog | Should -BeNullOrEmpty
    }
}
