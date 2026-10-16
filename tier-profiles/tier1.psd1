@{
    # Voidseal — Tier 1 isolation contract (net-restricted Hyper-V VM).
    # Declarative; consumed by the profile loader (Import-TierProfile).
    Tier            = 1
    Description     = 'Network-restricted Hyper-V Gen2 VM. Egress is host-enforced: the guest has no route, NAT or resolver and reaches only a host CONNECT allowlist proxy on its own switch, behind host firewall rules and a port ACL that the seal gate verifies. An in-guest default-DROP is defense in depth. Default: no credentials. For agent loops (Ralph), organizers and similar maintenance tasks.'
    Substrate       = 'HyperV-Gen2'
    Network         = 'Internal+Allowlist'      # per-VM Internal vSwitch; the host holds the gateway address of the VM's /30
    # EgressMode (2026-10-03): 'HostProxy', the host-enforced design (scripts/lib/HostEgress.ps1).
    # The VM gets a deterministic /30 from its name; the host puts the gateway address on the VM's
    # switch, adds firewall rules on that interface and a port ACL on the VM's NIC that leave one door
    # open (TCP to the proxy port on the gateway, from the guest's address), and runs
    # scripts/egress/voidseal_egress_proxy.py there, which tunnels only CONNECT host:443 for names on
    # the merged EgressAllowlist, resolving them itself and refusing private answers. No NAT, no route,
    # no resolver in the guest. Assert-Sealed reads the host objects back before the proxy and the VM
    # start. Mock-green only: the first elevated run is the first live exercise
    # (docs/phase-6-live-runbook.md section 2). 'InGuestSquid' (the in-guest Squid + iptables layer,
    # defense in depth and NOT a boundary) still works for a tier file that sets it.
    EgressMode      = 'HostProxy'                # credential-FREE. Phase-1B: 'HostEnvoy' (deferred)
    EgressAllowlist = @(
        'api.anthropic.com',
        'registry.npmjs.org',
        'github.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com', 'codeload.github.com',
        'pypi.org', 'files.pythonhosted.org'
    )
    # DECLARATIVE ONLY: no code reads this array. HostProxy blocks these by construction anyway: the
    # host proxy tunnels TCP CONNECT to port 443 only, and the host firewall and port ACL drop all UDP.
    BlockProtocols  = @('QUIC', 'UDP/443', 'DoH', 'DoT')
    Credentials     = 'ScopedOnDemand'           # default none; a scoped token only when the task needs a live API
    GuestImage      = 'debian-12-cloud'          # Debian 12 cloud image .vhdx + cloud-init NoCloud
    SecureBootTemplate = 'MicrosoftUEFICertificateAuthority'   # verified for Debian Gen2
    Memory          = '4GB'
    Cpu             = 4
    NestedVirt      = $false                      # bare-VM agent runtime — no nested Docker needed
    ManagementChannel = 'Com1Serial'              # PowerShell Direct is Windows-guest-only; Linux = COM1 serial + cloud-init
    HostChannels    = @{ Clipboard = $false; Shares = $false; GuestServices = $false; EnhancedSession = $false }
    Capture         = @{ Mode = 'HostSide+ProxyLog'; Otlp = $true }   # ProxyLog = the host proxy's per-connection JSON log in the run folder
    Extraction      = 'HostReadResultDir'         # Tier 1 isn't running presumed-hostile code
    Lifecycle       = 'SnapshotRevert'
    Controls        = @('NonRoot', 'ReadOnlyCodeMount', 'SecretFileExclusion', 'DeferTrust', 'SymlinkGuard', 'NativeBubblewrap')
}
