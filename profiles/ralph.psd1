@{
    # =====================================================================
    # Voidseal — Ralph autonomous-loop workload profile (Tier 1).
    # Example workload. Layers the Ralph loop shape over tier1.psd1
    # (net-restricted Hyper-V Gen2 Debian VM). Loaded by Import-WorkloadProfile,
    # which merges this onto tier1 and re-validates ALL loader invariants.
    # =====================================================================
    #
    # WHAT IT RUNS (verified via `gh api repos/frankbria/ralph-claude-code`):
    #   frankbria/ralph-claude-code is BASH, not an npm package, and has NO git tags /
    #   GitHub releases -> we PIN A COMMIT SHA (see StageAssets below), never a tag.
    #   Entrypoint is `bash ralph_loop.sh` at the repo root (it sources lib/*.sh).
    #   The loop drives the `claude` CLI headless:
    #       claude -p "<prompt>" --output-format json --allowedTools "<list>" --resume <id>
    #   It REQUIRES the `claude` CLI >= 2.0.76 + `jq` on the guest PATH, and it
    #   DELIBERATELY does NOT pass --dangerously-skip-permissions (tool sandboxing is
    #   via --allowedTools). The VM is the real trust boundary; --allowedTools is
    #   defense-in-depth, not the containment. Ralph state lives in `.ralph/` in the
    #   target repo (PROMPT.md, logs/, status.json). Loop config via env in the guest
    #   (MAX_CALLS_PER_HOUR, CLAUDE_TIMEOUT_MINUTES, etc.), set on the Entrypoint command
    #   line because the engine-built seed does not set them; not here.
    #
    # RUNTIME: Claude Code runs on the BARE Debian VM — NO nested
    #   devcontainer. The VM boundary replaces the privileged-devcontainer-for-bwrap
    #   reason; native bubblewrap (tier1 control 'NativeBubblewrap') + an unprivileged
    #   run-user provide in-guest defense-in-depth.

    BaseTier   = 1
    Name       = 'ralph'

    # ------------------------------------------------------------------
    # Packages: DECLARED, NOT INSTALLED. This lists what Ralph needs in the guest,
    # but no engine code reads the field, so nothing installs from it. The Serial
    # seed hard-codes its own apt install (ca-certificates and bubblewrap) and does
    # not read this list either. Under tier1's HostProxy egress that install goes
    # through the host proxy and only succeeds if a Debian mirror is on the
    # allowlist, which it is not by default, so git, jq, bubblewrap and the claude
    # CLI must already be in the golden image before a live ralph run.
    # Ralph itself is bash; the runtime deps are git (clone the pinned repo),
    # jq (the loop pipes `claude --output-format json` through jq), ca-certificates
    # (TLS to api.anthropic.com), and bubblewrap (the native-bwrap defense-in-depth
    # the tier-1 control names). The `claude` CLI (>= 2.0.76) comes from Anthropic's
    # official installer, not apt, so its entry is a named prerequisite rather
    # than a package name.
    # ------------------------------------------------------------------
    Packages   = @(
        'git',
        'jq',
        'ca-certificates',
        'bubblewrap',
        'claude-cli>=2.0.76'        # the Anthropic Claude Code CLI (installed in staging; Ralph needs >= 2.0.76)
    )

    # ------------------------------------------------------------------
    # Entrypoint — the Runner delivers this over the COM1 serial seam to the
    # sealed Debian guest (PowerShell Direct is Windows-guest-only). It runs
    # the loop from /opt/ralph/ralph-claude-code, which nothing in Voidseal puts
    # there today: the StageAssets ISO below never reaches the guest. A live run
    # needs the pinned repo already in the golden image at that path.
    # `bash ralph_loop.sh` is the verified invocation (NOT npm, NOT a binary).
    # ------------------------------------------------------------------
    Entrypoint = 'bash /opt/ralph/ralph-claude-code/ralph_loop.sh'

    # ------------------------------------------------------------------
    # ExtraAllowlist: FQDNs unioned onto tier1's EgressAllowlist. The merged list is
    # exactly what the host proxy enforces (EgressMode='HostProxy', inherited from
    # tier1; a workload may not set it). tier1's list already
    # carries api.anthropic.com, registry.npmjs.org, github.com + the GitHub raw/
    # codeload hosts, pypi.org, files.pythonhosted.org, all that the clone +
    # cloud-Claude calls need). The two hosts below are the Claude Code CLI
    # installer/auto-update origins. NB the loop's normal API traffic is
    # api.anthropic.com (already in tier1).
    #
    # These hosts are NOT install-time only. The seal runs before the guest's only
    # boot (see StageAssets below), so there is no still-open pre-seal window in
    # which a CLI install could run, and Import-WorkloadProfile unions this list
    # into the run's EgressAllowlist with no time limit. Both hosts stay reachable
    # for the whole sealed run. storage.googleapis.com is the wider of the two: it
    # admits any public bucket, not just the CLI release artifacts.
    # ------------------------------------------------------------------
    ExtraAllowlist = @(
        'claude.ai',          # Claude Code CLI installer / auth origin
        'storage.googleapis.com'   # CLI release artifact CDN; admits ANY public bucket, reachable for the whole sealed run
    )

    # ------------------------------------------------------------------
    # StageAssets: does NOT reach the guest. Invoke-Voidseal attaches the KEY (a host
    # file) as a read-only ISO before the seal, and the seal ejects it before the
    # guest's only boot; nothing in the guest mounts it either. The file must still
    # exist, or the STAGED import fails closed. The VALUE is a free-text pin note
    # (no hash is checked). Ralph has NO tags, so the note pins a COMMIT SHA.
    #
    # >>> PIN THE SHA before a live run <<<  Replace <PIN-COMMIT-SHA> with the
    # exact frankbria/ralph-claude-code commit you vendored (e.g. the `main` HEAD
    # you verified), and put the repo at that SHA into the golden image at
    # /opt/ralph/ralph-claude-code: that is the path the Entrypoint runs, and this
    # ISO cannot deliver it. The key below is a PLACEHOLDER host path; it is NOT
    # secret-shaped, so the loader accepts it.
    # ------------------------------------------------------------------
    StageAssets = @{
        'C:\sandbox\assets\ralph-claude-code.iso' = 'frankbria/ralph-claude-code @ <PIN-COMMIT-SHA> (bash; NO tags exist -> pin a SHA, never a tag). Pin note only: this ISO is ejected before the guest boots and is never mounted at /opt/ralph.'
    }

    # ------------------------------------------------------------------
    # Mounts — DECLARED, NOT WIRED (Gap 2): no code path attaches a host-guest bind mount, so
    # these entries move no files. They are kept because the loader still screens their source keys
    # and because they document the intended shape. The loader REFUSES any secret-shaped source
    # (.env*, *.pem, *.key, credentials*.json, .credentials.json, id_rsa*, ~/.ssh,
    # ~/.aws/credentials, anything under a `.secrets/` dir, etc.).
    #
    # THE CLAUDE OAUTH TOKEN (read-only file bind-mount pattern):
    #   Ralph's `claude` CLI authenticates with an OAuth token. Per a strict
    #   secret-handling protocol it is delivered as a FILE, mounted READ-ONLY into
    #   the guest — NEVER passed via `-e`, NEVER embedded in this profile, NEVER
    #   echoed through a shell.
    #
    #   IMPORTANT — why this path is shaped the way it is:
    #   Claude Code's real token store is `~/.claude/.credentials.json`, and the
    #   loader's secret-refusal list INCLUDES `.credentials.json` (and any
    #   `.secrets/` dir). So you must NOT mount the live credentials file directly —
    #   the loader would (correctly) refuse it. Instead, you do a one-time
    #   FILE-TO-FILE copy of just the token into a dedicated, NON-secret-shaped
    #   path with a `.token` extension (`.token` is not on the refusal list), e.g.:
    #
    #       # You run this yourself; the value never transits the agent's context:
    #       Copy-Item "$env:USERPROFILE\.claude\.credentials.json" `
    #                 "C:\sandbox\agent-cred\agent.token"
    #
    #   The mount KEY below points at THAT copied token file. IMPORTANT: nothing attaches it.
    #   Mounts are declared and secret-path-screened but NOT wired into the guest (no component
    #   attaches a host-guest bind mount; see docs/live-smoke-test.md Gap 2), so the ':ro' suffix
    #   records intent only and the token does NOT reach the guest through this block. No other
    #   channel carries it today either: a StageAssets ISO is ejected by the seal before the guest's
    #   only boot, and the engine builds the CIDATA seed from the profile. Until a token-delivery
    #   channel is wired, a live ralph run cannot authenticate. Rotate the token after any session
    #   that touched it.
    #
    #   This passes Import-WorkloadProfile because the SOURCE path is not
    #   secret-shaped (a `.token` leaf in a `claude-oauth` dir — neither the leaf
    #   globs nor the `.secrets`/`.ssh` dir rules nor the .aws/.kube/.docker pair
    #   rules match it). The token's VALUE is never present in this file.
    # ------------------------------------------------------------------
    Mounts = @{
        'C:\sandbox\agent-cred\agent.token' = '/home/sandbox/.claude/.credentials.json:ro'
        'C:\sandbox\ralph-workdir'          = '/home/sandbox/work'
    }

    # ------------------------------------------------------------------
    # SeedIso: NOT READ by Invoke-Voidseal. For every run with an entrypoint the engine builds
    # ralph's cloud-init seed itself, from the resolved profile, on a small CIDATA data disk that
    # survives the seal (New-WorkloadSeedDisk): serial-getty AUTOLOGIN on ttyS0 (the COM1 console
    # the Runner drives; Linux management is serial, not PS Direct), the unprivileged run-user,
    # the seed's own hard-coded packages (not the Packages list above, which nothing reads), and,
    # because tier1's EgressMode is 'HostProxy', a network-config with one static address in the
    # VM's /30 (no route, no resolver), HTTPS_PROXY pointing at the host proxy on the gateway, apt's
    # proxy setting, and an in-guest default-DROP that allows only the proxy port (defense in depth;
    # the host enforces). That lockdown is applied on the guest's single boot, before any apt step.
    # Autologin does not depend on it: the seed restarts serial-getty before any apt step. No seed
    # would mean no serial console, and the Runner's InvokeGuestCommand would time out. A seed DVD
    # cannot work: the seal ejects every DVD before the guest's only boot (RC6). This path only names
    # where New-CidataSeed writes an ISO if you build one by hand. Not secret-shaped.
    # ------------------------------------------------------------------
    SeedIso = 'C:\sandbox\assets\cidata-seed.iso'
}
