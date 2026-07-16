@{
    # Voidseal — Tier 1 isolation contract (net-restricted Hyper-V VM).
    # Declarative; consumed by the profile loader (Import-TierProfile).
    Tier            = 1
    Description     = 'Network-restricted Hyper-V Gen2 VM. Egress = credential-free in-guest nftables allowlist. Default: no credentials. For agent loops (Ralph), organizers, Immich steady-state.'
    Substrate       = 'HyperV-Gen2'
    Network         = 'Internal+Allowlist'      # Internal vSwitch + static host IP + in-guest nftables
    # HONESTY (2026-07-15): declarative only — validated for schema shape by ProfileLoader,
    # NOT enforced by any code path today (the ralph/Serial CIDATA seed ships zero
    # firewall/nftables content). The mechanism itself is design-invalidated for CDN-fronted
    # hosts (Pass-5, 2026-06-28: static nftables/ipset allowlists don't survive CDN IP
    # rotation); the replacement direction is a Squid-based in-guest redirect and/or
    # host-side enforcement — see docs/tier-reference.md's Egress note.
    EgressMode      = 'NftablesAllowlist'        # v1 credential-FREE. Phase-1B: 'HostEnvoy' (deferred)
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
