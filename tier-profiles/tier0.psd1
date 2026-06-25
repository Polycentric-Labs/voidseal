@{
    # Voidseal — Tier 0 isolation contract (container / lightweight, network OK).
    # For trusted productivity workloads (e.g. the Firefox organizer proof on a profile COPY).
    Tier            = 0
    Description     = 'Container / lightweight sandbox, network allowed via host proxy. Trusted dev + productivity. Operates on copies, never live host data without explicit per-task authorization.'
    Substrate       = 'Container'                 # Docker/devcontainer; docker sbx / @anthropic-ai/sandbox-runtime optional for untrusted code
    Network         = 'HostProxyAllowlist'
    EgressMode      = 'HostProxy'                 # credential-free; host firewall / proxy allowlist
    EgressAllowlist = @()                          # default offline; the only Tier-0 net step is an opt-in dead-link check (escalates to Tier 1)
    Credentials     = 'None'
    GuestImage      = 'debian-12-slim'             # container base
    # RC1 (2026-06-24 live): Tier-0 today provisions a real Debian Gen2 VM (the container substrate is
    # still aspirational), so it MUST carry the Linux Secure Boot template — an omitted/Windows-default
    # template makes Hyper-V reject Debian's MS-UEFI-CA-signed shim/grub and the guest never boots.
    SecureBootTemplate = 'MicrosoftUEFICertificateAuthority'   # verified for Debian Gen2 (matches tier1)
    Memory          = '2GB'
    Cpu             = 2
    HostChannels    = @{ Clipboard = $false; Shares = 'ReadOnlyInput'; GuestServices = $false }
    Capture         = @{ Mode = 'ProxyLog'; Otlp = $false }
    Extraction      = 'HostReadResultDir'          # host reads the emitted artifact (e.g. the Netscape-HTML bookmark export)
    Lifecycle       = 'Ephemeral'                  # --rm per task
    Controls        = @('NonRoot', 'ReadOnlyCodeMount', 'SecretFileExclusion', 'DeferTrust', 'SymlinkGuard')
}
