@{
    # =====================================================================
    # Voidseal — SKELETON workload profile (Tier 0, offline, Serial mode).
    # Copy this file to profiles/<your-task-name>.psd1 and edit every line
    # marked "# <-- EDIT". It is deliberately the MINIMAL valid shape — see
    # docs/authoring-a-workload-profile.md for the full field contract, the
    # two-layer (tier + workload) model, and a worked walkthrough.
    #
    # This skeleton is SYNTHETIC (no real task wired up) and Tier-0/offline:
    # it loads clean through Import-WorkloadProfile and inherits tier0.psd1
    # unchanged (host-proxy egress mode, default-empty allowlist — no network
    # unless YOU add one via ExtraAllowlist below).
    #
    # HONESTY NOTE: this Serial-mode shape has NOT been live-run. Only the
    # firefox example's Disk-mode Tier-0 shape has a proven live round-trip
    # (see docs/live-smoke-test.md). If you want the fastest path to
    # something ALREADY live-validated, copy+strip profiles/firefox.psd1
    # instead (see the "scaffold from existing" note in the authoring guide).
    # =====================================================================

    # --- REQUIRED (the loader's WorkloadRequiredKeys) ---------------------

    BaseTier   = 0                        # <-- EDIT: 0-3. Which tier-profiles/tierN.psd1 to inherit.
                                           #     0 = lightweight/offline. Only raise this if your task
                                           #     genuinely needs the isolation THAT tier buys you (see
                                           #     the field contract's tier-profile table for what each
                                           #     tier structurally enforces).

    Name       = 'example-skeleton'       # <-- EDIT: profile id. Convention: matches this filename
                                           #     (minus .psd1) — e.g. Name='my-task' for my-task.psd1.

    Entrypoint = 'echo "REPLACE-ME: see docs/authoring-a-workload-profile.md"'
                                           # <-- EDIT: the command the Runner delivers into the guest
                                           #     over the COM1 serial seam (Serial mode — the default
                                           #     when WorkloadMode is omitted, as here). Serial mode has
                                           #     no automatic INPUT/OUTPUT data disks — get your files
                                           #     in/out via Mounts below (or bake them into the golden
                                           #     image / a StageAssets ISO).

    # --- OPTIONAL, shown here because almost every real task needs them --

    # Packages — extra guest packages staged BEFORE the seal (over the still-open
    # pre-seal allowlist window). Leave @() if the golden image already has what
    # your Entrypoint needs.
    Packages = @()                        # <-- EDIT: e.g. @('python3') if your Entrypoint needs it.

    # Mounts — host->guest bind mounts. Use these to get your task's input in and
    # its output back out under Serial mode (this tier's Extraction='HostReadResultDir' —
    # the host just reads whatever your Entrypoint wrote here after the run). The
    # loader REFUSES any secret-shaped SOURCE (.env*, *.pem, *.key, credentials*.json,
    # id_rsa*, ~/.ssh, ~/.aws/credentials, ~/.kube/config, ~/.docker/config.json,
    # .npmrc, .pypirc, *-service-account.json, anything under a .secrets/ dir) — point
    # at a COPY of your real data, never a live secret store or a live personal-data
    # directory (see the authoring guide's DATA-ACCESS discussion).
    Mounts = @{
        'C:\sandbox\example-input'  = '/mnt/task/in:ro'   # <-- EDIT: your host input dir (read-only copy)
        'C:\sandbox\example-output' = '/mnt/task/out'     # <-- EDIT: your host output dir (read-write)
    }

    # ExtraAllowlist — FQDNs unioned onto tier0's EgressAllowlist (which defaults to
    # @() — Tier 0 is offline by default). Leave this EMPTY to stay offline. Only add
    # hosts your task actually calls out to (each entry is validated: a bare hostname
    # or a '.sub.domain' suffix, no whitespace/quotes/newlines).
    ExtraAllowlist = @()                   # <-- EDIT only if your task needs specific network egress.

    # SeedIso — a cloud-init NoCloud CIDATA seed ISO, attached read-only as a DVD at
    # provision so the guest configures itself on FIRST BOOT (serial-getty autologin
    # on ttyS0 — required for Serial-mode Entrypoint delivery to find anything
    # listening; without it, first boot has no serial console and delivery times
    # out). Ejected as part of the seal. Point this at the SAME seed recipe the
    # shipped profiles use (guest-images/debian-12-cloud.md) — you do not normally
    # need a bespoke seed per profile.
    SeedIso = 'C:\sandbox\assets\cidata-seed.iso'   # <-- EDIT if your seed lives elsewhere.
}
