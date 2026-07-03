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
    #
    # I3 (fetch_deps.py hardening): RequireHashes now REJECTS at build_commands()-time unless paired
    # with a RequirementsFile — the old "--require-hashes appended after bare package names" wiring
    # was a NO-OP (pip only enforces hashes when EVERY resolved requirement carries one, which only a
    # requirements file can do). RequirementsFile is a `pip-compile --generate-hashes` LOCKFILE minted
    # by the operator/build step (documented in docs/operator-runbook.md) — fetch_deps.py never
    # generates hashes itself, it only consumes a pre-hashed lockfile. The file need not exist on disk
    # for --plan / build_commands (pure, no execution, no file I/O on the reqfile path); the operator
    # supplies the real requirements.txt alongside the deps-spec.json at Phase 6 fire time.
    # HuggingFace.Revision pins the exact commit SHA so the fetch is an immutable snapshot, not
    # "whatever main currently resolves to". The value below is the REAL current main-branch commit
    # SHA of hf-internal-testing/tiny-random-gpt2 as of 2026-07-02 (confirmed live via
    # https://huggingface.co/api/models/hf-internal-testing/tiny-random-gpt2 -> "sha" field) —
    # >>> RE-CONFIRM it has not moved at fire (Phase 6); HF orgs can force-push a ref. <<<
    DepsSpec = @{
        Pip = @{
            Packages          = @('urllib3')          # informational only when RequirementsFile is set (see fetch_deps.py)
            Platform          = 'manylinux2014_x86_64' # cross-target the AIR-GAPPED processor, not the builder
            OnlyBinary        = $true                  # pip --only-binary=:all:
            RequireHashes     = $true                  # pip --require-hashes -- REQUIRES RequirementsFile (see above)
            RequirementsFile  = 'requirements.txt'      # pip-compile --generate-hashes lockfile, operator-supplied at fire
        }
        Apt         = @{ Packages = @('jq') }
        HuggingFace = @{
            Models   = @('hf-internal-testing/tiny-random-gpt2')
            Revision = '71034c5d8bde858ff824298bdedc65515b97d2b9'   # full 40-char commit SHA, confirmed live (see above)
        }
    }

    # Disk-mode entrypoint — the dep-fetch runner the seed injects (2.2 finalizes the exact call +
    # the deps-spec.json the runner reads). Reads the DepsSpec, fetches over the Squid egress, stages
    # deps + a per-file SHA-256 manifest under /mnt/out (-> the OUTPUT disk -> deps.vhdx).
    Entrypoint = 'python3 /mnt/in/fetch_deps.py --spec /mnt/in/deps-spec.json --out /mnt/out'

    # The cloud-init NoCloud CIDATA seed path. ci-2 NOTE: this is UNUSED in the disk-mode/builder path —
    # the builder is WorkloadMode='Disk', and New-WorkloadSeedDisk (Workload.ps1) builds the seed CONTENT
    # in-line onto a recorded CIDATA *data disk* ('<name>-cidata.vhdx' under the storage root, RC6) that
    # survives the seal; it never reads this SeedIso file. SeedIso is consumed ONLY by the serial/DVD path
    # (New-CidataSeed -Destination default + Add-SandboxSeed). Kept (not dropped) because the loader still
    # carries the key (mirrors firefox.psd1, which also declares it for disk-mode) and it documents the
    # canonical seed path; it is harmless in disk mode. Not secret-shaped.
    SeedIso = 'C:\sandbox\assets\cidata-seed.iso'
}
