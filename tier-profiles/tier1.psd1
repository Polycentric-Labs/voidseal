@{
    # Voidseal — Tier 1 isolation contract (net-restricted Hyper-V VM).
    # Declarative; consumed by the profile loader (Import-TierProfile).
    Tier            = 1
    Description     = 'Network-restricted Hyper-V Gen2 VM. Egress = in-guest iptables default-DROP + transparent Squid domain-ACL (defense-in-depth, NOT a boundary; the host-verified boundary is Phase-6). Default: no credentials. For agent loops (Ralph), organizers, Immich steady-state.'
    Substrate       = 'HyperV-Gen2'
    Network         = 'Internal+Allowlist'      # Internal vSwitch + static host IP; in-guest egress is defense-in-depth only — the host-side boundary is Phase-6
    # HONESTY (2026-07-18): EgressMode names the real mechanism this tier ships as — in-guest
    # iptables default-DROP + transparent Squid dstdomain ACL over EgressAllowlist, ported from
    # the builder's proven mechanism (SeedBuilder.ps1) — replacing the fabricated/schema-only
    # 'NftablesAllowlist' (design-invalidated by Pass-5, 2026-06-28: static nftables/ipset
    # allowlists don't survive CDN IP rotation). NOT YET WIRED into New-CidataUserData's serial
    # seed (that lands next); until then this still validates schema-only, same posture as
    # before. Even once wired, this is NOT a boundary — a compromised/root guest can disable it —
    # the host-verified boundary is Phase-6 (host-side NAT/Squid/default-DROP).
    EgressMode      = 'InGuestSquid'             # v1 credential-FREE. Phase-1B: 'HostEnvoy' (deferred)
    EgressAllowlist = @(
        'api.anthropic.com',
        'registry.npmjs.org',
        'github.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com', 'codeload.github.com',
        'pypi.org', 'files.pythonhosted.org'
    )
    BlockProtocols  = @('QUIC', 'UDP/443', 'DoH', 'DoT')   # force plaintext-resolvable egress through the allowlist
    Credentials     = 'ScopedOnDemand'           # default none; a scoped token only when the task needs a live API
    GuestImage      = 'debian-12-cloud'          # Debian 12 cloud image .vhdx + cloud-init NoCloud
    SecureBootTemplate = 'MicrosoftUEFICertificateAuthority'   # verified for Debian Gen2
    Memory          = '4GB'
    Cpu             = 4
    NestedVirt      = $false                      # bare-VM agent runtime — no nested Docker needed
    ManagementChannel = 'Com1Serial'              # PowerShell Direct is Windows-guest-only; Linux = COM1 serial + cloud-init
    HostChannels    = @{ Clipboard = $false; Shares = $false; GuestServices = $false; EnhancedSession = $false }
    Capture         = @{ Mode = 'HostSide+ProxyLog'; Otlp = $true }
    Extraction      = 'HostReadResultDir'         # Tier 1 isn't running presumed-hostile code
    Lifecycle       = 'SnapshotRevert'
    Controls        = @('NonRoot', 'ReadOnlyCodeMount', 'SecretFileExclusion', 'DeferTrust', 'SymlinkGuard', 'NativeBubblewrap')
}
