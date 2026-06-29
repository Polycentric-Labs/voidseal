@{
    # =====================================================================
    # Voidseal — Tier-1 net-restricted BUILDER workload profile (Phase 2).
    # Layers onto tier1.psd1; the loader RE-VALIDATES all invariants + the
    # builder rule (SquidSniProxy => DepsSpec + derived-per-fetcher allowlist
    # completeness). Runs a DepsSpec in a net-restricted VM and emits a
    # hash-verified deps.vhdx. ZERO personal data — the safest first live Tier-1.
    # =====================================================================
    BaseTier = 1
    Name     = 'builder'

    # Disk-mode: reuse the PROVEN firefox CIDATA disk path. The dep-fetch runner (2.2) rides the
    # INPUT disk, fetches per DepsSpec over the Squid SNI egress, writes deps onto the OUTPUT disk
    # (-> deps.vhdx) + a per-file manifest, and self-powers-off; the host (2.4) reads + hashes it.
    WorkloadMode = 'Disk'
    Inputs       = @{}

    # The builder egress: transparent Squid SNI proxy (Pass-5: nftables CANNOT runtime-FQDN-filter —
    # it resolves name->IP once at rule-load and CDN rotation then drops the connection). This is the
    # FIRST live Tier-1 egress in the project; the allowlist is load-bearing. Guarded workload override
    # (D-1): the loader accepts EgressMode here ONLY because it is exactly 'SquidSniProxy'.
    EgressMode = 'SquidSniProxy'

    # Union the apt + HF hosts tier1 lacks (tier1 already carries pypi/files.pythonhosted/github/
    # codeload/objects.githubusercontent). '.hf.co' is a domain-suffix entry covering the rotating
    # LFS/Xet hosts (the Squid domain-ACL model); the explicit cdn-lfs/cas-bridge anchors document the
    # representative hosts the completeness check requires. Re-confirm the exact rotating LFS set at fire.
    ExtraAllowlist = @(
        'deb.debian.org', 'security.debian.org',
        'huggingface.co', 'cdn-lfs.huggingface.co', 'cas-bridge.xethub.hf.co', '.hf.co'
    )

    # MVFR DepsSpec (Pass-5 §B) — minimal-viable-first-run isolates network/firewall failures from
    # dependency-resolution complexity. pip urllib3 (pure-Python, no manylinux complexity), apt jq
    # (tiny, no complex maintainer scripts), HF tiny-random-gpt2 (few-MB CI model). Expand to the 5a
    # stack (Tika/spaCy/Presidio/datasketch) only AFTER the live round-trip is green. NO Github fetcher
    # for MVFR (jq comes from apt) -> github hosts are NOT required by the derived-per-fetcher check.
    # >>> RE-CONFIRM the exact HF id 'hf-internal-testing/tiny-random-gpt2' at fire (Phase 6). <<<
    DepsSpec = @{
        Pip = @{
            Packages      = @('urllib3')
            Platform      = 'manylinux2014_x86_64'   # cross-target the AIR-GAPPED processor, not the builder
            OnlyBinary    = $true                    # pip --only-binary=:all:
            RequireHashes = $true                    # pip --require-hashes (abort if any transitive dep lacks a hash)
        }
        Apt         = @{ Packages = @('jq') }
        HuggingFace = @{ Models   = @('hf-internal-testing/tiny-random-gpt2') }
    }

    # Disk-mode entrypoint — the dep-fetch runner the seed injects (2.2 finalizes the exact call +
    # the deps-spec.json the runner reads). Reads the DepsSpec, fetches over the Squid egress, stages
    # deps + a per-file SHA-256 manifest under /mnt/out (-> the OUTPUT disk -> deps.vhdx).
    Entrypoint = 'python3 /mnt/in/fetch_deps.py --spec /mnt/in/deps-spec.json --out /mnt/out'

    # The cloud-init NoCloud CIDATA seed (2.2 builds the builder variant with the Squid proxy +
    # dep-fetch runner). Attached read-only at provision; ejected by the seal. Not secret-shaped.
    SeedIso = 'C:\sandbox\assets\cidata-seed.iso'
}
