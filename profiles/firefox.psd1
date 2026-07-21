@{
    # =====================================================================
    # Voidseal — Firefox bookmark-organizer workload profile (Tier 0).
    # Example workload. Layers the organizer shape over tier0.psd1
    # (container / lightweight, host-proxy egress, ephemeral). Loaded by
    # Import-WorkloadProfile, which merges this onto tier0 and re-validates ALL
    # loader invariants. Proves the FULL lifecycle with ZERO egress-proxy
    # dependency — the cleanest end-to-end exercise of the core engine.
    # =====================================================================
    #
    # WHAT IT DOES:
    #   Organizes Firefox bookmarks by operating on a COPY of profile files, NEVER
    #   the live profile, and NEVER mutating anything in place. Pipeline:
    #     1. take a COPY of `places.sqlite` (+ its `-wal`/`-shm` sidecars) read while
    #        Firefox is CLOSED, opened read-only/immutable; and/or decompress the
    #        latest `bookmarkbackups/*.jsonlz4` (mozlz4: 8-byte magic `mozLz40\0`
    #        then a raw LZ4 block -> `pip install lz4`, `lz4.block.decompress`);
    #     2. dedupe + frecency-rank + auto-folder; one OPT-IN dead-link check is the
    #        lone reason this could ever bump to Tier 1 (Tier 0 default is offline);
    #     3. EMIT an importable Netscape-HTML file (first line exactly
    #        `<!DOCTYPE NETSCAPE-Bookmark-file-1>`) that you can import via
    #        Firefox Library -> Import Bookmarks from HTML.
    #   Reads ONLY bookmark sources (places.sqlite, bookmarkbackups/, optionally
    #   sessionstore.jsonlz4). It MUST NEVER touch `logins.json`, `key4.db`, or
    #   `cookies.sqlite` — those are credential/session stores and are out of scope.
    #
    # !!! DATA-ACCESS RULE (BINDING) !!!
    #   This profile DEFAULTS TO SYNTHETIC / SAMPLE bookmark data. Reading your
    #   REAL Firefox profile (bookmarks/history/places.sqlite/etc.) requires EXPLICIT,
    #   PER-TASK authorization and is NEVER the default. "Personal-only this round"
    #   is NOT standing read-authorization. In the Disk model the input source is the
    #   INPUT data disk (InputFiles -> Inputs -> guest /mnt/in), which defaults to a
    #   SAMPLE/synthetic 'sample-bookmarks.json'; to run against real data, the operator must
    #   first authorize it per-task AND point the InputFiles 'sample-bookmarks.json'
    #   source at a COPY of the real profile's bookmark export (Firefox closed), never
    #   the live profile dir. (The legacy Mounts source is superseded — see Mounts below.)

    BaseTier   = 0
    Name       = 'firefox'

    # ------------------------------------------------------------------
    # WorkloadMode — 'Disk': the guest runs its boot workload off the SEED, writes its
    # result + an exit-code sentinel onto the OUTPUT data disk, and self-powers-off; the host
    # then detaches the data disks and reads + classifies the result (Read-WorkloadResult). The
    # default ('Serial') delivers an entrypoint over the COM1 serial seam — firefox uses Disk.
    #
    # Inputs (innerName -> CONTENT) seed the INPUT data disk: New-WorkloadDisks writes each entry
    # onto the host-formatted INPUT-labelled volume via WriteVhdxFile, and the guest mounts that
    # volume read-only at /mnt/in. The Disk-model inputs are (a) the organizer script and (b) the
    # sample bookmark profile — both ride the INPUT disk; the Entrypoint below reads them from
    # /mnt/in and writes the Netscape-HTML to /run/staging/result.html, which the in-guest producer
    # packs into the outbox (OutboxOutput below; result.html stays the result inner-name).
    #
    # Inputs stays EMPTY here because a .psd1 is static data and inlining a whole Python file as a
    # here-string would be unreadable + brittle. INSTEAD the inputs are populated AT LIVE-RUN TIME
    # from the host files by the live-acceptance step. See InputFiles below for the
    # host source paths, and guest-images/debian-12-cloud.md §2a + the operator runbook for the
    # 3-line populate snippet (read each host file -> build an Inputs hashtable -> pass it through
    # -Workload / a profile override so New-WorkloadDisks writes them onto the INPUT disk). An empty
    # Inputs is also exactly what the mock e2e needs (input disk created with no files).
    # ------------------------------------------------------------------
    WorkloadMode = 'Disk'
    Inputs       = @{}

    # ------------------------------------------------------------------
    # OutboxOutput (C1.4) — firefox converges onto the SAME user-space outbox transport a
    # PROCESSOR uses (Workload.ps1's Raw-OUTPUT predicate; Invoke-Voidseal.ps1's post-detach outbox
    # read), but WITHOUT a ScreenConfig — so it is transport-only, NEVER screened (LOCKED design,
    # Allen 2026-07-01). Effect: the OUTPUT data disk is created Raw (no filesystem — NewOutputVhdx
    # FileSystem='Raw'); the host NEVER Mount-VHDs it. Instead, post-detach, the host reads the outbox
    # in user-space (ReadVhdxRawRegion -> read_outbox.py — never mounts untrusted guest data) and, for
    # a transport-only profile like this one, materializes the sole candidate (result.html) verbatim
    # to Destination as ExtractedArtifact — no sensitivity-gate partition (Released/Held stay $null;
    # that partition is a PROCESSOR-only concept). The in-guest seed runner that packs the outbox is
    # guest/run_disk_workload.py --transport-only (delivered below via InputFiles, same mechanism as
    # the organizer script itself), which writes a well-formed placeholder verdicts.json ([]) so the
    # SAME container format (guest/outbox.py) the host read path expects parses cleanly.
    # ------------------------------------------------------------------
    OutboxOutput = $true

    # ------------------------------------------------------------------
    # InputFiles (Disk-mode, live-acceptance) — innerName -> host FILE PATH. This is DOC-ONLY
    # metadata: New-WorkloadDisks consumes `Inputs` (innerName -> CONTENT), NOT this map, so the
    # live-acceptance step reads each of these host files and folds them into `Inputs` before the
    # deploy (do NOT add a new loader path — just populate Inputs from these). The organizer script
    # + the sample profile both land on the INPUT disk and mount read-only at /mnt/in in the guest.
    #
    # C1.4: run_disk_workload.py + outbox.py ride the SAME INPUT disk, delivered the SAME way — the
    # seed's OutboxOutput disk-mode runner (SeedBuilder.ps1 CidataOutboxDiskRunnerTemplate) invokes
    # `python3 /mnt/in/run_disk_workload.py --transport-only` after the Entrypoint populates staging,
    # and run_disk_workload.py imports `outbox` off its OWN directory (sys.path.insert(0, HERE)) — so
    # outbox.py must land alongside it at /mnt/in, not just organize_bookmarks.py's own dependencies.
    # ------------------------------------------------------------------
    InputFiles = @{
        'organize_bookmarks.py' = 'C:\sandbox\organizer-src\organize_bookmarks.py'
        'sample-bookmarks.json' = 'C:\sandbox\firefox-sample-profile\sample-bookmarks.json'
        'run_disk_workload.py'  = 'C:\sandbox\organizer-src\run_disk_workload.py'
        'outbox.py'             = 'C:\sandbox\organizer-src\outbox.py'
    }

    # ------------------------------------------------------------------
    # Guest packages — Tier 0 is a lightweight Debian container. The organizer is
    # Python (sqlite3 stdlib for the places.sqlite read; `lz4` for mozlz4 backups).
    # No browser is installed — we never launch Firefox, we read a closed COPY.
    # ------------------------------------------------------------------
    Packages   = @(
        'python3',
        'python3-lz4'     # mozlz4 (*.jsonlz4) decompression for bookmarkbackups
    )

    # ------------------------------------------------------------------
    # Entrypoint (Disk model) — the organizer script + the sample profile both ride the INPUT
    # data disk (mounted read-only at /mnt/in); the result is written into the in-guest STAGING dir
    #
    # C1.4 CORRECTION (live 2026-07-21) — OutboxOutput=$true means the OUTPUT disk is RAW and is
    # NEVER mounted. SeedBuilder's CidataOutboxDiskRunnerTemplate creates only /mnt/in + /run/staging,
    # runs this Entrypoint INTO /run/staging, then hands staging to run_disk_workload.py, which packs
    # the outbox and writes it to the raw OUTPUT device. This string previously targeted the exFAT-era
    # /mnt/out/result.html. The organizer auto-creates its --out parent, but the runner executes the
    # entrypoint as the NON-ROOT sandbox user and /mnt is root-owned, so creating /mnt/out was denied
    # -> the organizer aborted (rc=1), staging stayed EMPTY,
    # and the outbox shipped carrying only its placeholder verdicts.json -> the host read failed with
    # "transport-only outbox has no 'result.html' candidate". C1.4 converged the transport but never
    # moved the Entrypoint, and Profiles.Tests.ps1 asserted the stale path, keeping the suite green.
    # The inner-name MUST be result.html - that is what the host outbox read extracts as this
    # transport-only profile's artifact (ResultInnerName). The seed builder injects this string in
    # place of __ENTRYPOINT__ in the OutboxOutput runner. `--out /run/staging/result.html` is the
    # SOLE writer of result.html: the script writes the Netscape-HTML there itself, and the runner
    # does NOT also redirect stdout into it (that double-write - shell `>` plus the script's --out on
    # the same path - is undefined-order and could 0-byte/corrupt the file; the runner sends
    # stdout/stderr to separate /run/{stdout.log,stderr.txt}, which die with the guest at poweroff).
    # Operates on the read-only input copy at /mnt/in; emits to /run/staging. NEVER mutates the input.
    # (Superseded: first the serial/container-era /opt/organizer + /work/out/bookmarks.html form,
    # then the exFAT /mnt/out/result.html form that the OutboxOutput transport replaced.)
    # ------------------------------------------------------------------
    Entrypoint = 'python3 /mnt/in/organize_bookmarks.py --profile /mnt/in --out /run/staging/result.html'

    # ------------------------------------------------------------------
    # ExtraAllowlist — DELIBERATELY EMPTY. The Tier-0 default is offline (tier0's
    # EgressAllowlist is @()); the bookmark organize/dedupe/frecency steps need NO
    # network. The single optional dead-link check is the lone net bump and, if ever
    # enabled, ESCALATES the workload to Tier 1 (where the allowlist lives) — it is
    # NOT granted here. Keeping this empty is what lets this workload validate the engine
    # with zero egress-proxy dependency.
    # ------------------------------------------------------------------
    ExtraAllowlist = @()

    # ------------------------------------------------------------------
    # Mounts (SUPERSEDED for Disk mode — SERIAL/CONTAINER-ERA, kept for shape/history).
    # In the DISK model these bind mounts NO LONGER deliver inputs/collect output: inputs
    # arrive on the INPUT data disk (guest /mnt/in) and the result lands on the OUTPUT data disk
    # (guest /run/staging/result.html, packed into the outbox) — see WorkloadMode/Inputs/InputFiles/Entrypoint above. These
    # entries are retained only because the loader still secret-screens them (regression guard)
    # and to document the pre-Disk mechanism; the Disk-mode runner does not consult them.
    #
    # The loader REFUSES secret-shaped sources. None of these are secret-shaped (no
    # .env/.key/credentials*/.secrets-dir etc.), so Import-WorkloadProfile accepts them. Note we
    # reference a profile COPY dir, NOT `logins.json`/`key4.db`/`cookies.sqlite` — never mounted.
    # Per the DATA-ACCESS rule the source defaults to a SAMPLE/synthetic dir; running on real data
    # is per-task-authorized and points at a COPY of a closed profile, never the live dir.
    # ------------------------------------------------------------------
    Mounts = @{
        'C:\sandbox\firefox-sample-profile' = '/mnt/firefox-profile:ro'
        'C:\sandbox\firefox-organizer-out'  = '/work/out'
    }

    # StageAssets: REMOVED 2026-06-25 (post-live-acceptance tidy). In Disk mode the organizer rides the
    # INPUT data disk (Inputs -> /mnt/in/organize_bookmarks.py), so the superseded firefox-organizer.iso
    # DVD was being imported-then-ejected-by-the-seal for nothing. The loader's secret-screen regression
    # coverage lives in the ProfileLoader tests (synthetic profiles), not in a profile carrying a
    # placeholder StageAssets. Pre-Disk staging history is in git.

    # ------------------------------------------------------------------
    # SeedIso — STILL APPLIES in Disk mode. The cloud-init NoCloud CIDATA seed is attached
    # READ-ONLY as a DVD at provision so the guest configures itself on FIRST BOOT. For a Disk-mode
    # profile the seed carries the DISK-MODE WORKLOAD RUNNER (guest-images/debian-12-cloud.md §2a):
    # the systemd oneshot that mounts LABEL=INPUT ro + LABEL=OUTPUT rw, runs the Entrypoint (injected
    # in place of __ENTRYPOINT__), writes result.html + result.exitcode, umounts, and self-powers-off.
    # It is the boot-config disc — distinct from the INPUT/OUTPUT data disks (workload payload + result)
    # — and is EJECTED as part of the seal (Assert-Sealed verifies no import DVD remains). Not
    # secret-shaped -> the loader accepts the .iso path. DVD-SLOT NOTE: the backend has ONE DVD slot;
    # the seed takes the boot DVD, so the inputs ride a SCSI DATA DISK (not a second DVD), avoiding the
    # single-DVD-slot conflict the serial-era StageAssets ISO would have had.
    # ------------------------------------------------------------------
    SeedIso = 'C:\sandbox\assets\cidata-seed.iso'
}
