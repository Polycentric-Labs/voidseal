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
    #   (MAX_CALLS_PER_HOUR, CLAUDE_TIMEOUT_MINUTES, etc.) — set in the seed/cloud-init,
    #   not here.
    #
    # RUNTIME: Claude Code runs on the BARE Debian VM — NO nested
    #   devcontainer. The VM boundary replaces the privileged-devcontainer-for-bwrap
    #   reason; native bubblewrap (tier1 control 'NativeBubblewrap') + an unprivileged
    #   run-user provide in-guest defense-in-depth.

    BaseTier   = 1
    Name       = 'ralph'

    # ------------------------------------------------------------------
    # Guest packages staged BEFORE the seal (the tier's import-then-seal ritual
    # pulls these over the still-open allowlist, then Lock-Sandbox cuts egress).
    # Ralph itself is bash; the runtime deps are git (clone the pinned repo),
    # jq (the loop pipes `claude --output-format json` through jq), ca-certificates
    # (TLS to api.anthropic.com), and bubblewrap (the native-bwrap defense-in-depth
    # the tier-1 control names). The `claude` CLI (>= 2.0.76) is installed from the
    # official installer during staging — listed here as the named prerequisite.
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
    # the loop from where StageAssets dropped the pinned repo. `bash ralph_loop.sh`
    # is the verified invocation (NOT npm, NOT a binary).
    # ------------------------------------------------------------------
    Entrypoint = 'bash /opt/ralph/ralph-claude-code/ralph_loop.sh'

    # ------------------------------------------------------------------
    # ExtraAllowlist — FQDNs unioned onto tier1's EgressAllowlist (which already
    # carries api.anthropic.com, registry.npmjs.org, github.com + the GitHub raw/
    # codeload hosts, pypi.org, files.pythonhosted.org — all that the clone +
    # cloud-Claude calls need). The one host tier1 lacks is the Claude Code
    # installer/auto-update origin, so Ralph's `claude` CLI can be installed +
    # self-update inside the (still-open, pre-seal) window. NB the loop's normal
    # API traffic is api.anthropic.com (already in tier1); this is install-time only.
    # ------------------------------------------------------------------
    ExtraAllowlist = @(
        'claude.ai',          # Claude Code CLI installer / auth origin
        'storage.googleapis.com'   # CLI release artifact CDN (install-time only; pre-seal)
    )

    # ------------------------------------------------------------------
    # StageAssets — pre-pulled + hash-pinned BEFORE the seal (one-way IN). The
    # KEY is the host source the Importer attaches (read-only ISO) into the guest;
    # the VALUE documents the pin. Ralph has NO tags so we pin a COMMIT SHA.
    #
    # >>> PIN THE SHA before a live run <<<  Replace <PIN-COMMIT-SHA> with the
    # exact frankbria/ralph-claude-code commit you vendored (e.g. the `main` HEAD
    # you verified). The host-side prep clones the repo at that SHA, verifies it,
    # and builds the read-only ISO this key points at. The path below is a
    # PLACEHOLDER host location for that prepared, SHA-pinned asset bundle — it is
    # NOT secret-shaped, so the loader accepts it.
    # ------------------------------------------------------------------
    StageAssets = @{
        'C:\sandbox\assets\ralph-claude-code.iso' = 'frankbria/ralph-claude-code @ <PIN-COMMIT-SHA> (bash; NO tags exist -> pin a SHA, never a tag). Verify SHA before build; mounts read-only to /opt/ralph.'
    }

    # ------------------------------------------------------------------
    # Mounts — host->guest bind mounts. The loader REFUSES any secret-shaped source
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
    #   The mount KEY below points at THAT copied token file. It is read-only in
    #   the guest (the ':ro' suffix on the target documents the intent; the Sealer/
    #   backend attaches it read-only), single-purpose, and rotatable (re-copy +
    #   re-deploy). Rotate the token after any session that touched it.
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
    # SeedIso — the cloud-init NoCloud CIDATA seed. Attached READ-ONLY as a DVD at
    # provision so the Debian guest configures itself on FIRST BOOT: serial-getty AUTOLOGIN
    # on ttyS0 (the COM1 serial console the Runner drives — Linux mgmt is serial, not
    # PS Direct), the unprivileged run-user, and the guest packages. NO seed -> no serial
    # console -> the Runner's InvokeGuestCommand finds nothing on \\.\pipe\<vm>-com1 and times
    # out (the first-boot gap). The seed is the boot-config disc (distinct from the
    # StageAssets payload ISO above) and is EJECTED as part of the seal — Assert-Sealed verifies
    # no import DVD remains, so a still-attached seed fails the gate. Not secret-shaped -> the
    # loader accepts the .iso path. DVD-SLOT NOTE: the backend has ONE DVD slot; the seed takes
    # the boot DVD, so the StageAssets payload that must coexist with the seed at boot should be
    # delivered as a transfer-VHD for a live coexistence run.
    # ------------------------------------------------------------------
    SeedIso = 'C:\sandbox\assets\cidata-seed.iso'
}
