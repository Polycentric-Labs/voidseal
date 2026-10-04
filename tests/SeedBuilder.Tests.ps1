#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for the CIDATA seed BUILDER (scripts/lib/SeedBuilder.ps1).

.DESCRIPTION
    The live smoke test (live-smoke-test.md §4A) needs a CIDATA NoCloud seed ISO that carries the
    DISK-MODE workload runner (guest-images/debian-12-cloud.md §2a) with the profile's `Entrypoint`
    substituted for `__ENTRYPOINT__`. Before this builder there was NO code that produced that seed —
    the on-disk seed was the OLD serial-getty seed, so a disk-mode run would boot to an idle login,
    never run the workload, and the host would classify `Failed` (no sentinel). This builder closes
    that gap.

    DESIGN (mirrors the engine's backend-injection discipline):
      * New-CidataUserData  — PURE string builder. Disk-mode profile -> the §2a runner with
        __ENTRYPOINT__ substituted; Serial-mode (default) -> the §2 serial-getty autologin baseline.
        Fail-closed on an unsafe entrypoint (a single quote or a newline would break the runner's
        `sh -c '__ENTRYPOINT__'`).
      * New-CidataMetaData  — PURE string builder (instance-id + local-hostname).
      * Write-Iso9660Image  — the REAL IMAPI2 (built-in Windows COM) ISO writer; verified by a gated
        round-trip test (skipped where IMAPI2 is unavailable).
      * New-CidataSeed      — orchestrates: assemble meta-data + user-data into a staging dir, then
        hand it to an INJECTABLE ISO writer (default = the real IMAPI2 writer; tests inject a fake
        that records what it was asked to write). This keeps the substitution logic unit-testable
        with no IMAPI dependency, exactly as the Hyper-V backend is faked.

    TDD: written FIRST; drives scripts/lib/SeedBuilder.ps1 + its dot-source into the orchestrator.
#>

BeforeAll {
    $script:SkillRoot       = Split-Path -Parent $PSScriptRoot
    $script:OrchPath        = Join-Path $script:SkillRoot 'scripts/Invoke-Voidseal.ps1'
    $script:SeedBuilderPath = Join-Path $script:SkillRoot 'scripts/lib/SeedBuilder.ps1'

    Test-Path $script:OrchPath | Should -BeTrue -Because 'the orchestrator must exist'

    # The orchestrator dot-sources the whole engine; once SeedBuilder is wired in, dot-sourcing the
    # orchestrator makes New-CidataSeed / New-CidataUserData / New-CidataMetaData available.
    . $script:OrchPath

    # The exact firefox disk-mode entrypoint (profiles/firefox.psd1) — the live-acceptance string.
    $script:FfEntrypoint = 'python3 /mnt/in/organize_bookmarks.py --profile /mnt/in --out /mnt/out/result.html'

    # A minimal DISK-mode profile (firefox shape) and a SERIAL-mode profile (ralph shape).
    $script:DiskProfile = @{
        Tier         = 0
        Name         = 'firefox'
        WorkloadMode = 'Disk'
        Entrypoint   = $script:FfEntrypoint
        SeedIso      = (Join-Path ([System.IO.Path]::GetTempPath()) ("vmdep-seedb-{0}.iso" -f ([guid]::NewGuid().ToString('N'))))
    }
    $script:SerialProfile = @{
        Tier         = 1
        Name         = 'ralph'
        WorkloadMode = 'Serial'
        Entrypoint   = 'bash /opt/ralph/ralph-claude-code/ralph_loop.sh'
    }

    # A fake ISO writer (the backend-injection analogue): records its last call + drops a stub file so
    # the orchestration is exercised end to end with NO IMAPI dependency.
    $script:NewFakeIsoWriter = {
        $rec = [pscustomobject]@{ Called = $false; SourceDir = $null; VolumeLabel = $null; Destination = $null; StagedFiles = @(); UserData = $null; MetaData = $null }
        $writer = {
            param($Spec)   # NB: do NOT name this $Args — it collides with the automatic $args and won't bind.
            $rec.Called      = $true
            $rec.SourceDir   = [string]$Spec.SourceDir
            $rec.VolumeLabel = [string]$Spec.VolumeLabel
            $rec.Destination = [string]$Spec.Destination
            $rec.StagedFiles = @(Get-ChildItem -LiteralPath $Spec.SourceDir -File | Select-Object -ExpandProperty Name)
            # Snapshot the staged content NOW — New-CidataSeed deletes its staging dir after the writer returns.
            $udPath = Join-Path $Spec.SourceDir 'user-data'
            $mdPath = Join-Path $Spec.SourceDir 'meta-data'
            if (Test-Path -LiteralPath $udPath) { $rec.UserData = Get-Content -LiteralPath $udPath -Raw }
            if (Test-Path -LiteralPath $mdPath) { $rec.MetaData = Get-Content -LiteralPath $mdPath -Raw }
            Set-Content -LiteralPath $Spec.Destination -Value 'fake-iso-bytes' -NoNewline -Encoding ascii
        }.GetNewClosure()
        return @{ Record = $rec; Writer = $writer }
    }

    # Is the real IMAPI2 COM writer available on this host? (Gates the round-trip test.)
    $script:ImapiAvailable = $false
    try { $null = New-Object -ComObject IMAPI2FS.MsftFileSystemImage; $script:ImapiAvailable = $true } catch { $script:ImapiAvailable = $false }

    $script:TmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vmdep-seedb-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $script:TmpRoot -Force | Out-Null
}

AfterAll {
    if ($script:TmpRoot -and (Test-Path -LiteralPath $script:TmpRoot)) {
        Remove-Item -LiteralPath $script:TmpRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'New-CidataUserData — disk-mode runner' {

    It 'emits #cloud-config as the first line' {
        $ud = New-CidataUserData -Profile $script:DiskProfile
        ($ud -split "`n")[0].Trim() | Should -Be '#cloud-config' -Because 'cloud-init requires the literal header on line 1'
    }

    It 'carries the disk-mode runner contract markers' {
        $ud = New-CidataUserData -Profile $script:DiskProfile
        foreach ($m in @('/usr/local/sbin/vmdep-workload','LABEL=INPUT','LABEL=OUTPUT','/mnt/in','/mnt/out/result.exitcode','runuser -u sandbox','poweroff')) {
            $ud | Should -BeLike "*$m*" -Because "the §2a disk-mode runner must contain '$m'"
        }
    }

    It 'disables networking (sealed/offline guest)' {
        New-CidataUserData -Profile $script:DiskProfile | Should -BeLike '*network: {config: disabled}*'
    }

    It 'RC2: creates the non-root sandbox user (the golden image has none; the disk seed must)' {
        $ud = New-CidataUserData -Profile $script:DiskProfile
        $ud | Should -BeLike '*name: sandbox*' -Because 'RC2: the disk-mode seed must create the sandbox user so runuser -u sandbox works'
        $ud | Should -BeLike '*lock_passwd: true*' -Because 'the sandbox user must have no password login (matches the serial baseline)'
    }

    It 'RC4: OUTPUT mount is ROBUST — falls back to a plain mount when the uid/gid mount fails' {
        $ud = New-CidataUserData -Profile $script:DiskProfile
        # The serial probe proved a plain `mount LABEL=OUTPUT /mnt/out` works where `mount -o uid=,gid=`
        # failed; the runner must try uid/gid first then fall back to plain mount.
        $ud | Should -BeLike '*|| mount LABEL=OUTPUT*' -Because 'RC4: a uid/gid OUTPUT mount must fall back to a plain mount so OUTPUT always mounts'
    }

    # The INPUT fallback is covered for every Disk runner by the read-only Describe below.

    It 'RC3: the seed still carries the wait-online mask directive (INEFFECTIVE for this boot — see below)' {
        # HONESTY (corrected 2026-07-21): this asserts only that the directive is PRESENT. It does NOT
        # assert the mask works, because live capture proves it does not and cannot: `bootcmd` runs in
        # the cloud-init.service stage, which is ordered After=systemd-networkd-wait-online.service, so
        # it cannot execute until that unit has already burned its full 120s timeout — and a sandbox VM
        # boots exactly ONCE, so a mask that only affects a later boot never applies. The unit still
        # costs ~120s of every boot; the real fix is masking it in the GOLDEN IMAGE (not done).
        # The old test name claimed the wait was "removed", which was never true.
        $ud = New-CidataUserData -Profile $script:DiskProfile
        $ud | Should -BeLike '*systemd-networkd-wait-online*' -Because 'the directive is still shipped (harmless, self-documenting)'
        $ud | Should -Match '(?i)mask' -Because 'it is a mask directive, whatever its (nil) effect on the current boot'
    }

    It 'substitutes the profile Entrypoint for __ENTRYPOINT__ (and leaves no token behind)' {
        $ud = New-CidataUserData -Profile $script:DiskProfile
        $ud | Should -BeLike "*$($script:FfEntrypoint)*" -Because 'the runner runs the profile entrypoint'
        $ud | Should -Not -BeLike '*__ENTRYPOINT__*' -Because 'an unsubstituted token means the guest runs literally nothing'
    }

    It 'starts the oneshot runner --no-block from runcmd' {
        New-CidataUserData -Profile $script:DiskProfile | Should -BeLike '*--no-block*vmdep-workload.service*'
    }

    It 'FAILS CLOSED on an entrypoint containing a single quote (would break sh -c ''...'')' {
        $bad = $script:DiskProfile.Clone(); $bad['Entrypoint'] = "python3 -c 'print(1)'"
        { New-CidataUserData -Profile $bad } | Should -Throw -Because 'a single quote escapes the runner sh -c wrapper — refuse it'
    }

    It 'FAILS CLOSED on a multi-line entrypoint (would break the single sh -c line)' {
        $bad = $script:DiskProfile.Clone(); $bad['Entrypoint'] = "echo a`necho b"
        { New-CidataUserData -Profile $bad } | Should -Throw -Because 'a newline breaks the single-line runner invocation'
    }

    It 'FAILS CLOSED on a blank entrypoint for a disk profile' {
        $bad = $script:DiskProfile.Clone(); $bad['Entrypoint'] = '   '
        { New-CidataUserData -Profile $bad } | Should -Throw -Because 'a disk runner with no command cannot produce a result'
    }
}

Describe 'New-CidataUserData: INPUT stays read-only on every mount arm of every Disk runner' {
    # Hyper-V cannot attach a data disk read-only (D3), so the guest's `ro` mount option is the only
    # read-only control INPUT has. RC4 (2026-06-24 live) gave the uid/gid INPUT mount a fallback arm
    # for kernels that reject those options, but the arm was a bare `mount LABEL=INPUT`, which mounts
    # read-write. All three Disk runners carried it, and the test this replaces pinned the bare form.
    # The fallback stays (RC4's reason still holds); what changes is that every arm must pass `ro`.
    BeforeAll {
        # Each `mount` command (a line split at || && ;) that targets LABEL=INPUT, skipping comment
        # lines. `mountpoint` never matches because the pattern needs whitespace right after `mount`.
        function script:Get-InputMountCommand {
            param([string] $UserData)
            foreach ($line in ($UserData -split "`r?`n")) {
                if ($line.TrimStart().StartsWith('#')) { continue }
                foreach ($seg in ($line -split '\|\||&&|;')) {
                    if ($seg -match '^\s*mount\s.*\bLABEL=INPUT\b') { $seg.Trim() }
                }
            }
        }
    }

    It '<Runner>: every mount of LABEL=INPUT passes ro, the RC4 fallback arm included' -ForEach @(
        @{ Runner = 'exFAT disk runner';  SeedProfile = @{ WorkloadMode = 'Disk'; Entrypoint = 'python3 /mnt/in/job.py --out /mnt/out/result.html' } }
        @{ Runner = 'outbox disk runner'; SeedProfile = @{ WorkloadMode = 'Disk'; OutboxOutput = $true; Entrypoint = 'python3 /mnt/in/job.py --out /run/staging/result.html' } }
        @{ Runner = 'builder runner';     SeedProfile = @{ WorkloadMode = 'Disk'; EgressMode = 'SquidSniProxy'; Entrypoint = 'python3 /mnt/in/fetch_deps.py --out /mnt/out'; EgressAllowlist = @('pypi.org') } }
    ) {
        $ud     = New-CidataUserData -Profile $SeedProfile
        $mounts = @(Get-InputMountCommand -UserData $ud)
        $mounts.Count | Should -BeGreaterOrEqual 2 -Because 'RC4: the uid/gid INPUT mount keeps a fallback arm (a plain mount worked live where the uid/gid form failed)'
        foreach ($m in $mounts) {
            $optMatch = [regex]::Match($m, '\s-o\s+(\S+)')
            $optMatch.Success | Should -BeTrue -Because "'$m' passes no option list, so it would mount INPUT read-write"
            $opts = $optMatch.Groups[1].Value -split ','
            $opts | Should -Contain 'ro' -Because "'$m' must mount INPUT read-only; the host cannot enforce that from its side (D3)"
            $opts | Should -Not -Contain 'rw' -Because "'$m' must not ask for a writable INPUT mount"
        }
    }
}

Describe 'New-CidataUserData — OutboxOutput disk runner (C1.3, firefox transport-only outbox)' {
    BeforeAll {
        # The OutboxOutput convergence entrypoint shape: writes result.html into the STAGING dir
        # (/run/staging), NOT onto a mounted /mnt/out (there is none — OUTPUT is Raw). This fixture
        # now MATCHES the shipped firefox.psd1 Entrypoint: C1.4 converged the transport but left that
        # string on the exFAT-era /mnt/out/result.html, which aborted the organizer live (rc=1, empty
        # staging) until it was corrected 2026-07-21. Profiles.Tests.ps1 pins the shipped string.
        $script:OutboxEntrypoint = 'python3 /mnt/in/organize_bookmarks.py --profile /mnt/in --out /run/staging/result.html'

        # A firefox-shaped OutboxOutput Disk profile: WorkloadMode='Disk' + OutboxOutput=$true, no
        # ScreenConfig (the C1.1/C1.2 predicate for a transport-only, non-processor outbox profile).
        # The entrypoint runs into a STAGING dir (not directly onto a mounted exFAT OUTPUT) — the
        # shared outbox producer (run_disk_workload.py --transport-only) packs staging -> raw OUTPUT.
        $script:OutboxProfile = @{
            Tier         = 0
            Name         = 'firefox'
            WorkloadMode = 'Disk'
            OutboxOutput = $true
            Entrypoint   = $script:OutboxEntrypoint
            SeedIso      = (Join-Path ([System.IO.Path]::GetTempPath()) ("vmdep-seedb-outbox-{0}.iso" -f ([guid]::NewGuid().ToString('N'))))
        }
    }

    It 'references run_disk_workload.py as the outbox producer' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        $ud | Should -BeLike '*run_disk_workload.py*' -Because 'an OutboxOutput profile packs its result via the shared outbox-producer template, not a direct exFAT write'
    }

    It 'invokes the producer in --transport-only mode (firefox: transport rides the outbox, never screened)' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        $ud | Should -BeLike '*run_disk_workload.py*--transport-only*' -Because 'LOCKED design: firefox is transport-only — the shared producer must skip the screener'
    }

    It 'does NOT format/mount an exFAT OUTPUT for the result (no LABEL=OUTPUT mount, no result.html exFAT write)' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        $ud | Should -Not -BeLike '*LABEL=OUTPUT*' -Because 'OUTPUT is a Raw disk for an OutboxOutput profile — there is no filesystem to mount by label'
        $ud | Should -Not -BeLike '*mkfs*' -Because 'the guest never formats OUTPUT — it is host-pre-formatted Raw (New-WorkloadDisks, C1.1)'
    }

    It 'still mounts INPUT read-only by label (the entrypoint reads its inputs from /mnt/in, unchanged)' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        $ud | Should -BeLike '*LABEL=INPUT*' -Because 'the entrypoint still reads its inputs off the host-formatted exFAT INPUT disk'
        $ud | Should -BeLike '*/mnt/in*'
    }

    It 'runs the entrypoint into a staging dir, not directly onto a mounted OUTPUT' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        $ud | Should -BeLike '*staging*' -Because 'the producer packs a STAGING dir (run_disk_workload --staging) into the outbox, mirroring the processor producer shape'
        # Precise structural check (not a loose comment-prose match): no ACTUAL `mount ... OUTPUT`
        # invocation anywhere in the emitted user-data — only the (separately asserted) absence of
        # LABEL=OUTPUT / mkfs covers the mount-by-label case; this additionally rules out any
        # `mount /dev/...` call naming OUTPUT directly.
        $mountLines = ($ud -split "`r?`n") | Where-Object { $_ -match '^\s*(mount|mountpoint)\b' }
        ($mountLines -join "`n") | Should -Not -Match 'OUTPUT' -Because 'no mount/mountpoint invocation may reference OUTPUT — it is a raw disk with nothing to mount'
    }

    It 'substitutes the profile Entrypoint for __ENTRYPOINT__ (and leaves no token behind)' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        $ud | Should -BeLike "*$($script:OutboxEntrypoint)*" -Because 'the runner still runs the profile entrypoint (into staging)'
        $ud | Should -Not -BeLike '*__ENTRYPOINT__*' -Because 'an unsubstituted token means the guest runs literally nothing'
    }

    It 'still self-powers-off after the producer runs' {
        New-CidataUserData -Profile $script:OutboxProfile | Should -BeLike '*poweroff*'
    }

    It 'FAILS CLOSED on an OutboxOutput entrypoint containing a single quote (same sh -c guard)' {
        $bad = $script:OutboxProfile.Clone(); $bad['Entrypoint'] = "python3 -c 'print(1)'"
        { New-CidataUserData -Profile $bad } | Should -Throw -Because 'a single quote escapes the runner sh -c wrapper — refuse it, same as the non-outbox disk runner'
    }

    It 'FAILS CLOSED on a blank OutboxOutput entrypoint' {
        $bad = $script:OutboxProfile.Clone(); $bad['Entrypoint'] = '   '
        { New-CidataUserData -Profile $bad } | Should -Throw -Because 'an outbox runner with no command cannot produce a result'
    }

    # --- serial diagnostics (live-debug observability; structural facts ONLY) --------------------
    # The OutboxOutput raw-device path is LIVE-ONLY-unproven (D4-D): its first live test failed the
    # outbox read and the runner was SILENT (every fail-closed branch is a bare `poweroff; exit 0`,
    # and the producer's stdout/stderr die with the ephemeral rootfs). These assert the runner now
    # narrates each decision point to the serial console (ttyS0 -> host COM1 pipe) so a live capture
    # pins the failing branch. STRUCTURAL ONLY: device nodes, mount y/n, candidate list, count,
    # producer rc, staging COUNT, the 8-byte container magic — NEVER candidate file bytes (the
    # processor shares this runner; serial must not become a screener-bypass release channel).
    It 'emits structural [voidseal-diag] serial markers (the silent runner gave the live run zero signal)' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        $ud | Should -Match '\[voidseal-diag\]' -Because 'a fail-closed poweroff must narrate WHY to the serial console, not vanish silently'
    }

    It 'narrates the raw-device identification (candidate list + chosen device) — the exact step under live debug' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        # Match the diag CALL site, not a bare shell var: OUT_CANDIDATES/OUTPUT_DEV already exist in
        # the runner and -BeLike/-Match are case-insensitive, so assert the runner actually ECHOES them.
        $ud | Should -Match 'diag "out_candidates' -Because 'the capture must SEE which block devices remained after excluding root+INPUT'
        $ud | Should -Match 'diag "output_dev'      -Because 'and which device the runner chose to write the outbox to'
    }

    It 'echoes a distinct ABORT reason before each fail-closed poweroff' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        $ud | Should -Match 'diag "ABORT' -Because 'each `poweroff; exit 0` guard must first echo its branch so the serial capture pins the cause'
    }

    It 'reports the outbox producer exit code (separates a pre-producer device-ID abort from a producer/raw-write failure)' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        $ud | Should -Match 'diag "producer_rc' -Because 'if the producer ran, its rc distinguishes a raw-device WRITE failure from a silent device-ID abort before it'
    }

    It 'diag markers are STRUCTURAL only — no candidate staging CONTENT is echoed to the console (shared runner: no screener-bypass side channel)' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        # Filter the diag CALL SITES (`diag "..."`), which is where the echoed content is actually
        # composed — NOT lines containing the literal 'voidseal-diag' (only the diag() DEFINITION
        # carries that, so filtering on it would inspect one line and miss every call site).
        $diagLines = @(($ud -split "`r?`n") | Where-Object { $_ -match 'diag "' })
        $diagLines.Count | Should -BeGreaterThan 5 -Because 'every decision point (mount, exclusions, enumeration, candidates, chosen device, entrypoint, producer, magic) must be narrated'
        # A diag line must never dump staging file BYTES to the console (that is the guest->host
        # payload the screener governs). Reading the OUTPUT device's own 8-byte magic (dd if=OUTPUT_DEV)
        # or LISTING/COUNTING staging names is structural and allowed; catting staging file bytes is not.
        # Per-line: flag any diag line that BOTH names /run/staging AND uses a byte-dump tool.
        $leaky = @($diagLines | Where-Object { $_ -match '/run/staging' -and $_ -match '\b(cat|head|tail|od|xxd|hexdump|dd|strings)\b' })
        $leaky | Should -BeNullOrEmpty -Because 'the release boundary: serial narrates structure (device nodes/counts/rc/magic), never staged payload bytes'
    }

    # --- raw-OUTPUT identification (root cause of the 2026-07-20 live abort) ---------------------
    # LIVE: the runner excluded only root + INPUT, but RC6 had added the FAT32 CIDATA seed as a 4th
    # disk, so two candidates always remained (OUTPUT + seed) and EVERY OutboxOutput run fail-closed
    # aborted with no outbox written. A DEPS disk would reproduce it on the processor path. The fix
    # selects the OUTPUT disk by its DEFINING property (raw: no partitions, no filesystem signature).
    It 'identifies the raw OUTPUT disk POSITIVELY (no partitions + no filesystem signature)' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        $ud | Should -Match 'blkid -p'                    -Because 'low-level PROBE mode tests the device for a filesystem signature now, rather than trusting the blkid cache'
        $ud | Should -Match 'has partitions'              -Because 'a partitioned disk (root/INPUT/CIDATA/DEPS) is not the raw OUTPUT disk'
        $ud | Should -Match 'has a filesystem signature'  -Because 'a formatted disk is not the raw OUTPUT disk'
    }

    It 'does NOT identify OUTPUT by an exclusion list of known labels (the RC6 CIDATA seed disk broke that live)' {
        $ud = New-CidataUserData -Profile $script:OutboxProfile
        # `LABEL=INPUT` must still appear (the INPUT *mount*, asserted above) — this pins that the
        # OUTPUT *identification* no longer hinges on resolving INPUT's label to subtract it, which
        # silently left the seed disk as a second candidate.
        $ud | Should -Not -Match 'blkid -L INPUT' -Because 'an exclusion list must be kept in sync with every disk we attach; the raw-ness test does not'
        $ud | Should -BeLike '*LABEL=INPUT*'      -Because 'the INPUT disk is still MOUNTED by label — only the OUTPUT identification changed'
    }

    # --- PREDICATE-DRIFT regression (found 2026-07-21) -------------------------------------------
    # Workload.ps1 makes the OUTPUT disk Raw for `isProcessor -OR- wantsOutbox`, but this seed builder
    # keyed on `wantsOutbox` ALONE. A PROCESSOR without OutboxOutput therefore got a RAW OUTPUT disk
    # AND the exFAT runner, which would `mount LABEL=OUTPUT` against a disk with no filesystem, fail,
    # and hit the silent poweroff guard -> no outbox -> "header missing/!magic". Exactly the bug class
    # that produced the 2026-07-20 disk-ID defect and the C1.4 entrypoint defect: two copies of one
    # truth drifting apart. Both now read the SINGLE shared Test-UsesOutboxTransport predicate.
    It 'a PROCESSOR (Network=None + ScreenConfig, NO OutboxOutput key) ALSO gets the OutboxOutput runner' {
        $proc = @{
            Tier         = 0
            Name         = 'proc-predicate'
            WorkloadMode = 'Disk'
            Network      = 'None'
            ScreenConfig = @{ mode = 'aggressive' }
            Entrypoint   = 'python3 /mnt/in/proc.py --out /run/staging/result.html'
            SeedIso      = (Join-Path ([System.IO.Path]::GetTempPath()) ("vmdep-proc-{0}.iso" -f ([guid]::NewGuid().ToString('N'))))
        }
        $ud = New-CidataUserData -Profile $proc
        $ud | Should -BeLike '*run_disk_workload.py*' -Because 'a processor releases through the SAME user-space outbox as an OutboxOutput profile — its OUTPUT disk is Raw'
        $ud | Should -Not -BeLike '*LABEL=OUTPUT*'    -Because 'a Raw OUTPUT disk has no filesystem to mount; the exFAT runner would fail closed and write nothing'
    }

    # --- in-guest screening (decided 2026-10-03) ---------------------------------------------------
    # The outbox runner used to hard-code --transport-only. That is right for a transport-only profile
    # like firefox and wrong for a PROCESSOR: its outbox shipped a placeholder verdicts.json ([]), and
    # the host gate refuses every staged file that has no verdict, so no processor run could release
    # anything. A processor now runs the screener in the guest, in the mode its ScreenConfig names.
    It 'a PROCESSOR seed runs the screener in the guest: --mode from ScreenConfig, never --transport-only' {
        $proc = @{ Tier = 0; Name = 'proc-mode'; WorkloadMode = 'Disk'; Network = 'None'
                   ScreenConfig = @{ mode = 'moderate' }; Entrypoint = 'python3 /mnt/in/proc.py --out /run/staging/result.html' }
        $line = @((New-CidataUserData -Profile $proc) -split "`r?`n" | Where-Object { $_ -match '^\s*python3\s+/mnt/in/run_disk_workload\.py\s' })
        $line.Count | Should -Be 1
        $line[0] | Should -Match '\s--mode\s+moderate(\s|$)' -Because 'the in-guest screener runs in the mode the processor''s ScreenConfig names'
        $line[0] | Should -Not -Match '--transport-only' -Because 'a processor''s outbox must carry real verdicts, or the host gate refuses every staged file'
    }

    It 'a PROCESSOR with no ScreenConfig.mode screens in aggressive mode (the same default the host gate uses)' {
        $proc = @{ Tier = 0; Name = 'proc-default'; WorkloadMode = 'Disk'; Network = 'None'
                   ScreenConfig = @{}; Entrypoint = 'python3 /mnt/in/proc.py --out /run/staging/result.html' }
        (New-CidataUserData -Profile $proc) | Should -Match 'run_disk_workload\.py[^\r\n]*\s--mode\s+aggressive(\s|$)'
    }

    It 'REFUSES a processor ScreenConfig.mode other than aggressive or moderate (the value lands on a shell line)' {
        $proc = @{ Tier = 0; Name = 'proc-badmode'; WorkloadMode = 'Disk'; Network = 'None'
                   ScreenConfig = @{ mode = 'aggressive; poweroff' }; Entrypoint = 'python3 /mnt/in/proc.py --out /run/staging/result.html' }
        { New-CidataUserData -Profile $proc } | Should -Throw -ExpectedMessage '*mode*' -Because 'only the two screener modes may reach the runner''s shell line'
    }

    It 'a transport-only OutboxOutput seed still skips the screener (no --mode)' {
        $line = @((New-CidataUserData -Profile $script:OutboxProfile) -split "`r?`n" | Where-Object { $_ -match '^\s*python3\s+/mnt/in/run_disk_workload\.py\s' })
        $line[0] | Should -Match '--transport-only'
        $line[0] | Should -Not -Match '\s--mode\s' -Because 'a transport-only profile is never screened (LOCKED design for firefox)'
    }

    It 'FAILS CLOSED when an outbox-transport entrypoint writes to /mnt/out (there is no such mount)' {
        # The live 2026-07-21 defect in profile form: the outbox runner creates only /mnt/in and
        # /run/staging, so an entrypoint aimed at /mnt/out cannot work — and fails in the worst way
        # (rc=1, empty staging, a VALID but empty outbox), which reads as a transport fault.
        $bad = $script:OutboxProfile.Clone()
        $bad['Entrypoint'] = 'python3 /mnt/in/organize_bookmarks.py --profile /mnt/in --out /mnt/out/result.html'
        { New-CidataUserData -Profile $bad } | Should -Throw -Because 'refuse at seed-build time rather than ship a runner whose entrypoint cannot write its result'
    }

    It 'a plain (non-OutboxOutput) Disk profile is UNCHANGED — still the direct exFAT result.html runner' {
        # Regression guard: C1.3 must not touch the existing non-outbox Disk-mode runner (a legacy
        # profile with WorkloadMode='Disk' and no OutboxOutput key keeps the old exFAT contract).
        $ud = New-CidataUserData -Profile $script:DiskProfile
        $ud | Should -BeLike '*LABEL=OUTPUT*'
        $ud | Should -BeLike '*/mnt/out/result.html*'
        $ud | Should -Not -BeLike '*run_disk_workload.py*'
    }
}

Describe 'New-CidataUserData — serial-mode baseline (no regression for ralph)' {

    It 'emits the serial-getty autologin baseline, NOT the disk-mode runner' {
        $ud = New-CidataUserData -Profile $script:SerialProfile
        ($ud -split "`n")[0].Trim() | Should -Be '#cloud-config'
        $ud | Should -BeLike '*serial-getty@ttyS0*'  -Because 'serial mode brings up the COM1 command channel'
        $ud | Should -BeLike '*--autologin sandbox*' -Because 'the serial client does not authenticate (G4)'
        $ud | Should -Not -BeLike '*vmdep-workload*'  -Because 'serial mode must not embed the disk-mode runner'
    }

    It 'defaults to serial when WorkloadMode is absent' {
        $p = @{ Tier = 1; Name = 'nomode'; Entrypoint = 'bash run.sh' }
        New-CidataUserData -Profile $p | Should -BeLike '*serial-getty@ttyS0*'
    }
}

Describe 'New-CidataUserData — serial + InGuestSquid egress' {
    BeforeAll {
        # ralph-shaped Serial profile opting into the in-guest egress control (EG-2, Option A):
        # WorkloadMode='Serial' (unchanged — ralph keeps its ttyS0 command channel) + EgressMode=
        # 'InGuestSquid' + a representative merged EgressAllowlist (tier1 base + a stand-in for
        # ExtraAllowlist domains).
        $script:SerialEgressProfile = $script:SerialProfile.Clone()
        $script:SerialEgressProfile['EgressMode']      = 'InGuestSquid'
        $script:SerialEgressProfile['EgressAllowlist'] = @('api.anthropic.com', 'github.com', 'claude.ai', 'storage.googleapis.com')
    }

    It 'emits BOTH the serial-getty command channel AND the Squid egress fragment' {
        $ud = New-CidataUserData -Profile $script:SerialEgressProfile
        $ud | Should -BeLike '*serial-getty@ttyS0*' -Because 'ralph keeps its ttyS0 command channel even with in-guest egress'
        $ud | Should -BeLike '*squid.conf*'         -Because 'InGuestSquid must ship the transparent Squid domain-ACL'
        $ud | Should -Match 'http_access deny all'  -Because 'default-deny is the whole point of the domain-ACL'
    }

    It 'templates every merged allowlist domain into the Squid dstdomain ACL' {
        $ud = New-CidataUserData -Profile $script:SerialEgressProfile
        # Assert the domains land on the `acl allowed_domains dstdomain` line specifically (not merely
        # somewhere in the seed) — so a future template edit that echoed a domain elsewhere can't make
        # a missing-from-the-ACL regression pass silently.
        $dstdomainLine = ($ud -split "`r?`n") | Where-Object { $_.Trim() -match '^acl allowed_domains dstdomain\b' }
        $dstdomainLine | Should -Not -BeNullOrEmpty -Because 'the seed must carry the dstdomain ACL line'
        foreach ($d in $script:SerialEgressProfile.EgressAllowlist) {
            $dstdomainLine | Should -BeLike "*$d*" -Because "the dstdomain ACL line must carry allowlist domain '$d'"
        }
    }

    It 'carries the iptables default-DROP + IPv6-disable + transparent-proxy REDIRECT shape' {
        $ud = New-CidataUserData -Profile $script:SerialEgressProfile
        $ud | Should -Match 'iptables -P OUTPUT DROP'      -Because 'default-DROP OUTPUT is the egress-lockdown control'
        $ud | Should -Match 'disable_ipv6'                 -Because 'IPv6 must be disabled — the lockdown is otherwise IPv4-only'
        $ud | Should -Match 'REDIRECT --to-port 3129'      -Because 'HTTP must be transparently redirected to Squid'
        $ud | Should -Match 'REDIRECT --to-port 3130'      -Because 'HTTPS must be transparently redirected to Squid'
    }

    It 'fully substitutes __SQUID_ALLOWLIST_ACL__ (no unsubstituted token remains)' {
        $ud = New-CidataUserData -Profile $script:SerialEgressProfile
        $ud | Should -Not -BeLike '*__SQUID_ALLOWLIST_ACL__*' -Because 'an unsubstituted placeholder means the ACL is malformed/empty'
    }

    It 'FAILS CLOSED on InGuestSquid with an empty EgressAllowlist' {
        $bad = $script:SerialEgressProfile.Clone(); $bad['EgressAllowlist'] = @()
        { New-CidataUserData -Profile $bad } | Should -Throw -Because 'InGuestSquid with nothing to allow must refuse, not silently ship a useless/broken ACL'
    }

    It 'FAILS CLOSED on a Disk-mode profile declaring EgressMode=InGuestSquid (that combo is undefined)' {
        $bad = $script:DiskProfile.Clone(); $bad['EgressMode'] = 'InGuestSquid'
        { New-CidataUserData -Profile $bad } | Should -Throw -Because 'InGuestSquid is the SERIAL-seed in-guest egress; a Disk-mode egress profile must declare SquidSniProxy (the builder egress, which carries its DepsSpec rule) instead of silently falling through to the plain disk runner with no egress content'
    }

    It 'REGRESSION: a plain serial profile (no InGuestSquid) still emits the bare baseline only' {
        # The existing 'serial-mode baseline (no regression for ralph)' Describe covers the core
        # baseline assertions; this adds the explicit negative checks for the egress fragment so a
        # future change to the dispatch cannot silently leak the egress fragment onto every serial
        # profile regardless of EgressMode.
        $ud = New-CidataUserData -Profile $script:SerialProfile
        $ud | Should -BeLike '*serial-getty@ttyS0*' -Because 'the bare serial baseline must still bring up the command channel'
        $ud | Should -Not -BeLike '*squid.conf*'    -Because 'a plain serial profile must not get the egress fragment'
        $ud | Should -Not -Match 'OUTPUT DROP'      -Because 'a plain serial profile must not get the iptables lockdown'
    }
}

Describe 'New-CidataMetaData' {
    It 'emits instance-id and local-hostname' {
        $md = New-CidataMetaData
        $md | Should -BeLike '*instance-id:*'
        $md | Should -BeLike '*local-hostname:*'
    }
}

Describe 'New-CidataSeed — assembles meta-data + user-data and drives the (injected) ISO writer' {

    It 'calls the ISO writer with the CIDATA volume label' {
        $fake = & $script:NewFakeIsoWriter
        $dest = Join-Path $script:TmpRoot ("seed-{0}.iso" -f ([guid]::NewGuid().ToString('N')))
        New-CidataSeed -Profile $script:DiskProfile -Destination $dest -IsoWriter $fake.Writer | Out-Null
        $fake.Record.Called      | Should -BeTrue
        $fake.Record.VolumeLabel | Should -Be 'CIDATA' -Because 'NoCloud requires the volume label exactly CIDATA'
    }

    It 'stages BOTH meta-data and user-data into the writer source dir' {
        $fake = & $script:NewFakeIsoWriter
        $dest = Join-Path $script:TmpRoot ("seed-{0}.iso" -f ([guid]::NewGuid().ToString('N')))
        New-CidataSeed -Profile $script:DiskProfile -Destination $dest -IsoWriter $fake.Writer | Out-Null
        $fake.Record.StagedFiles | Should -Contain 'meta-data'
        $fake.Record.StagedFiles | Should -Contain 'user-data'
    }

    It 'the staged user-data is the disk-mode runner with the entrypoint substituted' {
        $fake = & $script:NewFakeIsoWriter
        $dest = Join-Path $script:TmpRoot ("seed-{0}.iso" -f ([guid]::NewGuid().ToString('N')))
        New-CidataSeed -Profile $script:DiskProfile -Destination $dest -IsoWriter $fake.Writer | Out-Null
        $ud = $fake.Record.UserData   # snapshotted by the fake writer (the staging dir is cleaned up post-write)
        $ud | Should -BeLike '*vmdep-workload*'
        $ud | Should -BeLike "*$($script:FfEntrypoint)*"
        $ud | Should -Not -BeLike '*__ENTRYPOINT__*'
    }

    It 'returns the destination ISO path' {
        $fake = & $script:NewFakeIsoWriter
        $dest = Join-Path $script:TmpRoot ("seed-{0}.iso" -f ([guid]::NewGuid().ToString('N')))
        (New-CidataSeed -Profile $script:DiskProfile -Destination $dest -IsoWriter $fake.Writer) | Should -Be $dest
    }

    It 'defaults the destination to the profile SeedIso when -Destination is omitted' {
        $fake = & $script:NewFakeIsoWriter
        New-CidataSeed -Profile $script:DiskProfile -IsoWriter $fake.Writer | Out-Null
        $fake.Record.Destination | Should -Be ([string]$script:DiskProfile['SeedIso'])
    }

    It 'propagates the fail-closed entrypoint check (a bad entrypoint never reaches the ISO writer)' {
        $fake = & $script:NewFakeIsoWriter
        $bad  = $script:DiskProfile.Clone(); $bad['Entrypoint'] = "x'y"
        $dest = Join-Path $script:TmpRoot ("seed-bad-{0}.iso" -f ([guid]::NewGuid().ToString('N')))
        { New-CidataSeed -Profile $bad -Destination $dest -IsoWriter $fake.Writer } | Should -Throw
        $fake.Record.Called | Should -BeFalse -Because 'an unsafe entrypoint must be rejected before any ISO is written'
    }
}

Describe 'Builder CIDATA seed — Squid SNI egress (Phase 2.2)' {
    BeforeAll {
        $script:builderProfile = @{
            WorkloadMode = 'Disk'; EgressMode = 'SquidSniProxy'
            Entrypoint = 'python3 /mnt/in/fetch_deps.py --spec /mnt/in/deps-spec.json --out /mnt/out'
            EgressAllowlist = @('pypi.org','files.pythonhosted.org','deb.debian.org','security.debian.org','huggingface.co','.hf.co')
        }
    }
    It 'Disk + SquidSniProxy selects the builder seed and templates every allowlist domain into the Squid dstdomain ACL (default-deny)' {
        $ud = New-CidataUserData -Profile $script:builderProfile
        $ud | Should -Match 'https_port 3130 intercept ssl-bump'
        foreach ($d in $script:builderProfile.EgressAllowlist) { $ud | Should -BeLike "*$d*" }
        $ud | Should -Match 'http_access deny all'
        $ud | Should -Match ([regex]::Escape($script:builderProfile.Entrypoint))
        $ud | Should -Not -Match '__SQUID_ALLOWLIST_ACL__'   # placeholder fully substituted
        $ud | Should -Not -Match '__ENTRYPOINT__'
    }
    It 'a Disk profile WITHOUT SquidSniProxy still gets the OFFLINE disk seed (network disabled, no squid)' {
        $ud = New-CidataUserData -Profile @{ WorkloadMode = 'Disk'; Entrypoint = 'python3 /mnt/in/x.py' }
        $ud | Should -Match 'network: \{config: disabled\}'
        $ud | Should -Not -Match '(?i)squid'
    }
    It 'a SquidSniProxy builder profile with an EMPTY allowlist is refused (fail-closed)' {
        { New-CidataUserData -Profile @{ WorkloadMode='Disk'; EgressMode='SquidSniProxy'; Entrypoint='python3 x'; EgressAllowlist=@() } } |
            Should -Throw -ExpectedMessage '*allowlist*'
    }
    It 'a builder entrypoint containing a single quote is refused (same sh -c guard as the offline runner)' {
        { New-CidataUserData -Profile @{ WorkloadMode='Disk'; EgressMode='SquidSniProxy'; Entrypoint="python3 'x'"; EgressAllowlist=@('pypi.org') } } |
            Should -Throw
    }
    It 'SEC-2: builder egress is DEFAULT-DROP + a minimal allow-list (BlockProtocols enforced by construction)' {
        $ud = New-CidataUserData -Profile $script:builderProfile
        # Default-drop egress policy + the minimal allow-list (loopback, established, DNS 53, TCP 80/443).
        $ud | Should -Match 'iptables -P OUTPUT DROP'
        $ud | Should -Match 'iptables -A OUTPUT -o lo -j ACCEPT'
        $ud | Should -Match 'ESTABLISHED,RELATED -j ACCEPT'
        $ud | Should -Match 'iptables -A OUTPUT -p udp --dport 53 -j ACCEPT'
        $ud | Should -Match 'iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT'
        $ud | Should -Match 'iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT'
        $ud | Should -Match 'iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT'

        # --- SEC-2 / Named-Risk-2 hardening: STRUCTURAL allow-list assertion -------------------------
        # The two guards this replaces (`Should -Not -Match 'udp --dport 443'` / `'dport 853'`) are
        # literal-string matches: a differently-worded hole (e.g. `-m multiport --dports 443,853`)
        # matches NEITHER string and would pass the old test vacuously. Instead, extract every
        # `iptables -A OUTPUT ... -j ACCEPT` rule the seed actually emits and assert the SET is
        # exactly the intended minimal allow-list — 6 rules, nothing else. A 7th rule, a reworded
        # rule, a multiport rule, or any extra/renamed port/proto opens the count or the set and
        # fails this test, regardless of how the hole is spelled.
        # TABLE-AGNOSTIC anchor (whole-branch-review Fix C): iptables accepts an optional explicit
        # `-t <table>` token before the chain op (e.g. `iptables -t filter -A OUTPUT ...`) — `filter`
        # is the implicit default table, so `-t filter -A OUTPUT ... -j ACCEPT` is FUNCTIONALLY
        # IDENTICAL to the un-qualified spelling this seed emits. The prior anchor
        # ('^\s*iptables\s+-A\s+OUTPUT\b...') required the un-qualified spelling immediately after
        # `iptables`, so a `-t filter`-qualified rule (e.g. a QUIC/UDP-443 hole spelled
        # `iptables -t filter -A OUTPUT -p udp --dport 443 -j ACCEPT`) matched NEITHER this
        # extraction NOR the udp/443 belt-and-braces guard below — an evasion that passed this test
        # GREEN while opening a real hole. The optional `(\s+-t\s+\S+)?` group closes that gap; it is
        # non-capturing on the table name itself (any table spelling is still caught), so a `-t nat`
        # rule (the REDIRECTs, which end in `-j REDIRECT`, not `-j ACCEPT`) is correctly excluded by
        # the trailing `-j\s+ACCEPT\s*$` the same as before.
        $acceptRuleAnchor = '^\s*iptables(\s+-t\s+\S+)?\s+-A\s+OUTPUT\b.*-j\s+ACCEPT\s*$'
        $outputLines  = $ud -split "`r?`n"
        $acceptRules  = $outputLines | Where-Object { $_ -match $acceptRuleAnchor } | ForEach-Object { $_.Trim() }

        $acceptRules.Count | Should -Be 6 -Because 'the builder OUTPUT allow-list must contain EXACTLY the 6 intended rules (lo, established/related, dns udp/tcp, http, https) — any extra ACCEPT rule (a 7th rule, a widened/renamed port, a multiport rule, or a -t-table-qualified duplicate) must fail this test even if it does not match the literal strings "udp --dport 443" or "dport 853"'

        # Per-expected-rule presence within the extracted set (order-independent).
        $expectedRules = @(
            'iptables -A OUTPUT -o lo -j ACCEPT'
            'iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT'
            'iptables -A OUTPUT -p udp --dport 53 -j ACCEPT'
            'iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT'
            'iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT'
            'iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT'
        )
        foreach ($rule in $expectedRules) {
            $acceptRules | Should -Contain $rule -Because "the minimal allow-list must contain '$rule'"
        }
        # And the reverse: every extracted rule must be one of the expected 6 (closes the set both ways —
        # count-equality alone would not catch a rule that REPLACES an expected one with a different hole
        # while another expected rule is duplicated).
        foreach ($rule in $acceptRules) {
            $expectedRules | Should -Contain $rule -Because "found an OUTPUT ACCEPT rule not in the intended minimal allow-list: '$rule' — this is exactly the drift SEC-2 guards against"
        }

        # Structural port/proto extraction: for every ACCEPT rule that carries a proto+dport, assert the
        # (proto, dport) set is exactly {(udp,53), (tcp,53), (tcp,80), (tcp,443)}. This is a second,
        # independent lens on the same rules (parsed rather than string-compared) so a rule that is
        # byte-identical to an expected one except for a transposed proto/port still gets caught.
        $portRulePattern = '-p\s+(?<proto>udp|tcp)\s+--dport\s+(?<port>\d+)\s+-j\s+ACCEPT'
        $portRules = @()
        foreach ($rule in $acceptRules) {
            if ($rule -match $portRulePattern) {
                $portRules += [pscustomobject]@{ Proto = $Matches['proto']; Port = $Matches['port'] }
            }
        }
        $portRules.Count | Should -Be 4 -Because 'exactly 4 of the 6 ACCEPT rules carry an explicit proto+dport (dns udp/tcp, http, https); lo and established/related do not'
        $portSet = $portRules | ForEach-Object { "$($_.Proto):$($_.Port)" } | Sort-Object -Unique
        ($portSet -join ',') | Should -Be 'tcp:443,tcp:53,tcp:80,udp:53' -Because 'the (proto,port) set of every dport-bearing ACCEPT rule must be EXACTLY {udp/53, tcp/53, tcp/80, tcp/443} — no udp/443 (QUIC), no port 853 (DoT), no additional port under any proto'

        # --- Belt-and-braces (defense in depth; the set-equality above is the primary guard) -----------
        # BlockProtocols enforced BY CONSTRUCTION: no rule anywhere opens QUIC/UDP-443 or DoT/853, and no
        # ACCEPT rule combines udp with 443 in any form (covers e.g. a stray `-m multiport --dports 443,853`
        # that the structural extraction above wouldn't even classify as a plain port rule). Scoped to
        # non-comment lines only — the seed's own honesty comment legitimately DISCUSSES "DoT/853" in prose
        # to explain why it's dropped, so a raw whole-`$ud` substring match would false-positive on that
        # comment; a real rule/directive line never starts with '#'.
        $nonCommentLines = $outputLines | Where-Object { $_.Trim() -notmatch '^#' -and $_.Trim() -ne '' }
        ($nonCommentLines | Where-Object { $_ -match '853' }) |
            Should -BeNullOrEmpty -Because 'DoT (853) must never appear in any non-comment (rule/config) line of the builder seed'
        # Table-agnostic here too (mirrors the extraction anchor above): 'iptables\s+-A\s+OUTPUT'
        # alone does NOT match a `-t <table>`-qualified rule (e.g. `iptables -t filter -A OUTPUT -p
        # udp --dport 443 -j ACCEPT`), which is functionally identical to the un-qualified spelling
        # since 'filter' is the implicit default table. Without the optional -t group this belt-and-
        # braces guard silently no-ops against exactly that spelling of a QUIC/UDP-443 hole.
        ($outputLines | Where-Object { $_ -match 'iptables(\s+-t\s+\S+)?\s+-A\s+OUTPUT' -and $_ -match '-j\s+ACCEPT' -and $_ -match 'udp' -and $_ -match '443' }) |
            Should -BeNullOrEmpty -Because 'no OUTPUT ACCEPT rule may combine udp with port 443 (QUIC/HTTP-3), in any spelling (plain --dport, -m multiport --dports, or -t filter -A ...)'

        # The transparent-proxy REDIRECTs still gatekeep 80/443 to Squid.
        $ud | Should -Match 'REDIRECT --to-port 3129'
        $ud | Should -Match 'REDIRECT --to-port 3130'
    }

    It 'SEC-2 (MINOR): the Squid ACL http_access ordering is deny-all-last, with no shadowing allow-all above it' {
        # The iptables allow-list above is the primary control, but Squid's OWN domain ACL
        # (acl allowed_domains dstdomain ... / http_access allow allowed_domains / http_access deny
        # all) is the actual per-FQDN fetch gate. Ordering matters for squid.conf: http_access rules
        # are evaluated FIRST-MATCH-WINS, so an `http_access allow all` (or any unconditional allow)
        # ABOVE the `deny all` would shadow it and defeat the domain restriction even though `deny
        # all` still appears later in the file. Assert structurally: extract every ordered
        # `http_access` line from the seed and check (a) the LAST one is exactly `deny all`, and (b)
        # no EARLIER line is an unconditional allow (i.e. `http_access allow all` or a bare
        # `http_access allow` with no ACL name).
        $ud = New-CidataUserData -Profile $script:builderProfile
        $outputLines = $ud -split "`r?`n"

        $httpAccessLines = $outputLines | Where-Object { $_.Trim() -match '^http_access\b' } | ForEach-Object { $_.Trim() }
        $httpAccessLines.Count | Should -BeGreaterOrEqual 2 -Because 'the seed must carry at least an allow (scoped to allowed_domains) and a final deny'

        $httpAccessLines[-1] | Should -Be 'http_access deny all' -Because 'the LAST http_access rule must be the unconditional deny — Squid is first-match-wins, so anything reachable after an allow-all would still be reachable if deny-all is not last'

        $earlierLines = $httpAccessLines[0..($httpAccessLines.Count - 2)]
        $shadowingAllowAll = $earlierLines | Where-Object { $_ -match '^http_access\s+allow\s+all\s*$' -or $_ -match '^http_access\s+allow\s*$' }
        $shadowingAllowAll | Should -BeNullOrEmpty -Because 'an unconditional allow ABOVE the final deny would shadow it (first-match-wins) and defeat the allowed_domains restriction regardless of what the deny line says'
    }

    It 'SEC-2/C3: IPv6 is disabled pre-network (bootcmd) AND ip6tables default-DROPs, closing the IPv4-only egress bypass' {
        $ud = New-CidataUserData -Profile $script:builderProfile
        $outputLines = $ud -split "`r?`n"

        # --- Primary: IPv6 disabled via sysctl, applied EARLY (bootcmd runs before network-config) ---
        $ud | Should -Match 'net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1' -Because 'SLAAC/DHCPv6 must never bring up a usable IPv6 route on the builder'
        $ud | Should -Match 'net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1' -Because 'new interfaces must also come up with IPv6 disabled'

        $bootcmdIdx = ($outputLines | Select-String -Pattern '^bootcmd:' -SimpleMatch:$false | Select-Object -First 1).LineNumber
        $bootcmdIdx | Should -Not -BeNullOrEmpty -Because 'the builder seed must have a bootcmd: section (runs before network-config, unlike runcmd)'
        # bootcmd is a YAML list; find the next top-level (non-indented, non-comment, non-blank) key after
        # it to bound the section, then assert a sysctl invocation disabling ipv6 appears inside that bound.
        $afterBootcmd = $outputLines[$bootcmdIdx..($outputLines.Count - 1)]
        $nextTopLevelOffset = ($afterBootcmd | Select-Object -Skip 1 | Select-String -Pattern '^[A-Za-z_][A-Za-z0-9_]*:' | Select-Object -First 1).LineNumber
        if ($nextTopLevelOffset) { $bootcmdSection = $afterBootcmd[0..$nextTopLevelOffset] } else { $bootcmdSection = $afterBootcmd }
        ($bootcmdSection -join "`n") | Should -Match 'sysctl' -Because 'IPv6 must be disabled inside bootcmd (pre-network), not only via a dropped-in sysctl.d file that a later stage applies'
        ($bootcmdSection -join "`n") | Should -Match 'disable_ipv6' -Because 'the bootcmd sysctl invocation must reference disable_ipv6, not some unrelated sysctl'

        # --- Belt-and-braces: ip6tables default-DROP, guarded so a missing binary cannot abort the script ---
        $ud | Should -Match 'ip6tables -P OUTPUT DROP' -Because 'IPv6 egress must default-DROP even if disable_ipv6 somehow fails to take effect'
        $ud | Should -Match 'ip6tables -A OUTPUT -o lo -j ACCEPT'
        $ud | Should -Match 'ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT'
        $ud | Should -Match 'command -v ip6tables' -Because 'a missing ip6tables binary must not abort the set +e egress-lockdown script; guard the whole ip6tables block'

        # --- No IPv6 egress ACCEPT is ever opened for 53/80/443 — IPv6 stays fully dropped ---
        $ip6Lines = $outputLines | Where-Object { $_ -match 'ip6tables' }
        ($ip6Lines | Where-Object { $_ -match '-A\s+OUTPUT' -and $_ -match '-j\s+ACCEPT' -and $_ -match '--dport\s+(53|80|443)\b' }) |
            Should -BeNullOrEmpty -Because 'the builder fetch is IPv4-only through Squid; no ip6tables rule may ACCEPT egress on 53/80/443'
    }

    It 'the OFFLINE (non-builder) disk seed is unaffected by the IPv6 lockdown (network is disabled entirely, no iptables/ip6tables at all)' {
        $ud = New-CidataUserData -Profile @{ WorkloadMode = 'Disk'; Entrypoint = 'python3 /mnt/in/x.py' }
        $ud | Should -Not -Match '(?i)ip6tables'
        $ud | Should -Not -Match '(?i)disable_ipv6'
        $ud | Should -Match 'network: \{config: disabled\}'
    }

    # --- serial diagnostics (Phase-6 live-debug observability; structural facts ONLY) -------------
    # The builder runner had ZERO serial markers, while the OutboxOutput runner's diag lines are what
    # pinned BOTH Tier-0 live root causes (D4-D). Phase 6 is the project's FIRST live egress: a failed
    # fetch must be attributable to squid-down vs REDIRECT-not-applied vs mount-failure vs the fetch
    # itself. Invoke-BuilderVM now reads the exit-code file and manifest off the OUTPUT disk for its
    # verdict (Success or FetchFailed), but teardown then DELETES that disk, so the serial console is
    # the second source and the only one that says where the guest stopped. Same
    # discipline as the outbox runner: STRUCTURAL ONLY — liveness, rc values, file COUNTS, manifest
    # presence; never fetched-artifact bytes.
    It 'emits structural [voidseal-diag] serial markers (the silent-runner class already cost two live debug rounds)' {
        $ud = New-CidataUserData -Profile $script:builderProfile
        $ud | Should -Match '\[voidseal-diag\]' -Because 'a fail-closed poweroff must narrate WHY to the serial console, not vanish silently'
    }

    It 'narrates the egress bring-up: squid liveness + per-REDIRECT rc (the first layer a failed live fetch must rule out)' {
        $ud = New-CidataUserData -Profile $script:builderProfile
        $ud | Should -Match 'diag "squid_active='   -Because 'a dead Squid turns every fetch into an opaque connection failure; its liveness must be on serial before the entrypoint runs'
        $ud | Should -Match 'diag "egress_lockdown' -Because 'the lockdown/REDIRECT application must be narrated so a no-egress failure is attributable to THIS layer, not guessed'
        $ud | Should -Match 'redirect80_rc='        -Because 'an unapplied 80-REDIRECT silently bypasses the Squid ACL for HTTP — its rc must be visible'
        $ud | Should -Match 'redirect443_rc='       -Because 'an unapplied 443-REDIRECT silently bypasses the Squid ACL for HTTPS — its rc must be visible'
        $ud | Should -Match 'diag "ip6_lockdown'    -Because 'the IPv6 belt-and-braces outcome (applied vs no-binary skip) must be visible live'
    }

    It 'narrates mounts, entrypoint rc, per-fetcher artifact counts, and manifest presence (the host verdict is the exit code and manifest; serial says where the guest stopped)' {
        $ud = New-CidataUserData -Profile $script:builderProfile
        $ud | Should -Match 'diag "input_mounted='  -Because 'a failed INPUT mount means the runner + DepsSpec never reached the guest'
        $ud | Should -Match 'diag "output_mounted=' -Because 'a failed OUTPUT mount means nothing can be staged — and which owner it mounted under decides who may write'
        $ud | Should -Match 'diag "entrypoint_rc='  -Because 'fetch_deps.py exits 2 on any failed fetcher; the host reads that rc as the verdict, and serial says where it came from'
        $ud | Should -Match 'fetched pip='          -Because 'a per-fetcher artifact COUNT attributes an empty deps disk to the fetcher that produced nothing'
        $ud | Should -Match 'apt='                  -Because 'apt artifacts land under /mnt/out/apt — its count must be narrated separately'
        $ud | Should -Match 'hf='                   -Because 'HF artifacts land under /mnt/out/hf — its count must be narrated separately'
        $ud | Should -Match 'manifest_present='     -Because 'write_manifest only runs after ALL fetchers succeed; its presence is the single yes/no of a fully-green fetch'
    }

    It 'echoes a DISTINCT ABORT reason before each of the two fail-closed poweroffs (no-OUTPUT vs no-INPUT+rc70)' {
        $ud = New-CidataUserData -Profile $script:builderProfile
        $ud | Should -Match 'diag "ABORT output-not-mounted' -Because 'the no-OUTPUT branch powers off with NOTHING written anywhere; only serial can say why'
        $ud | Should -Match 'diag "ABORT input-not-mounted'  -Because 'the no-INPUT branch writes the rc70 sentinel, which the host reads as a failed verdict; serial must name the branch'
    }

    It 'builder diag markers are STRUCTURAL only — no fetched-artifact bytes on the serial console (same contract as the outbox runner)' {
        $ud = New-CidataUserData -Profile $script:builderProfile
        $diagLines = @(($ud -split "`r?`n") | Where-Object { $_ -match 'diag "' })
        $diagLines.Count | Should -BeGreaterThan 6 -Because 'every decision point (squid, lockdown/redirects, ip6, both mounts, entrypoint, fetch counts, manifest, poweroff) must be narrated'
        # A diag line must never dump dependency-payload bytes to the console: counts/presence/rc are
        # structural and allowed; catting fetched files is not. (The builder carries zero personal data —
        # this is contract-consistency with the shared outbox runner, and it keeps the serial capture a
        # control-flow record rather than a payload mirror.)
        $leaky = @($diagLines | Where-Object { $_ -match '/mnt/out' -and $_ -match '\b(cat|head|tail|od|xxd|hexdump|dd|strings)\b' })
        $leaky | Should -BeNullOrEmpty -Because 'serial narrates structure (liveness/rc/counts/presence), never dependency payload bytes'
    }
}

Describe 'Write-Iso9660Image — REAL IMAPI2 round-trip (gated on IMAPI availability)' {

    It 'builds an ISO whose volume label is CIDATA and whose staged file content is present' {
        # -Skip is evaluated at DISCOVERY (before BeforeAll runs), so gate in-body instead.
        if (-not $script:ImapiAvailable) { Set-ItResult -Skipped -Because 'IMAPI2 COM is unavailable on this host'; return }
        $src = Join-Path $script:TmpRoot ("imapi-src-{0}" -f ([guid]::NewGuid().ToString('N')))
        New-Item -ItemType Directory -Path $src -Force | Out-Null
        $marker = 'voidseal-imapi-roundtrip-marker-vmdep-workload'
        Set-Content -LiteralPath (Join-Path $src 'user-data') -Value $marker -NoNewline -Encoding ascii
        Set-Content -LiteralPath (Join-Path $src 'meta-data') -Value 'instance-id: x' -NoNewline -Encoding ascii
        $dest = Join-Path $script:TmpRoot ("imapi-{0}.iso" -f ([guid]::NewGuid().ToString('N')))

        Write-Iso9660Image -SourceDir $src -VolumeLabel 'CIDATA' -Destination $dest

        Test-Path -LiteralPath $dest | Should -BeTrue -Because 'the writer must produce the ISO file'
        $bytes = [System.IO.File]::ReadAllBytes($dest)
        # ISO9660 Primary Volume Descriptor: sector 16 (offset 0x8000); Volume Identifier at +40, 32 bytes ASCII.
        $volId = [System.Text.Encoding]::ASCII.GetString($bytes, (16 * 2048) + 40, 32).Trim()
        $volId | Should -Be 'CIDATA' -Because 'cloud-init NoCloud matches the volume label exactly'
        ([System.Text.Encoding]::ASCII.GetString($bytes)) | Should -BeLike "*$marker*" -Because 'the user-data content must round-trip into the image'
    }
}

# ===========================================================================
#  Serial templates carry the same structural [voidseal-diag] markers as the disk runners (E7)
# ===========================================================================
Describe 'New-CidataUserData - the serial baseline and serial egress seeds narrate structure on the serial console (E7)' {

    BeforeAll {
        $script:DiagLineShape = 'diag() { echo "[voidseal-diag] $*" > /dev/console 2>/dev/null; }'
        $script:SerialUd = New-CidataUserData -Profile $script:SerialProfile
        $egress = $script:SerialProfile.Clone()
        $egress['EgressMode']      = 'InGuestSquid'
        $egress['EgressAllowlist'] = @('api.example.com', '.example.org')
        $script:SerialEgressUd = New-CidataUserData -Profile $egress

        # The content block of one write_files entry, dedented (same extraction the data-disk tests use).
        function script:Get-SeedFile {
            param([string] $UserData, [string] $Path)
            $lines = $UserData -split "`n"
            $start = [array]::IndexOf($lines, "  - path: $Path")
            $start | Should -BeGreaterOrEqual 0 -Because "the seed must write $Path"
            $body = [System.Collections.Generic.List[string]]::new()
            for ($i = $start + 3; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^  - path: ' -or $lines[$i] -match '^  #' -or $lines[$i] -match '^\S') { break }
                $body.Add(($lines[$i] -replace '^      ', ''))
            }
            return ($body -join "`n")
        }
        # The runcmd entries after the 'runcmd:' key.
        function script:Get-RunCmd {
            param([string] $UserData)
            $lines = $UserData -split "`n"
            $at = [array]::IndexOf($lines, 'runcmd:')
            $at | Should -BeGreaterOrEqual 0
            $out = [System.Collections.Generic.List[string]]::new()
            for ($i = $at + 1; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^  - ') { $out.Add($lines[$i].Trim()) } elseif ($lines[$i] -match '^\S') { break }
            }
            return @($out)
        }
        $script:Diag = @{
            Serial = (script:Get-SeedFile $script:SerialUd '/usr/local/sbin/voidseal-serial-diag')
            Egress = (script:Get-SeedFile $script:SerialEgressUd '/usr/local/sbin/voidseal-serial-diag')
            Lock   = (script:Get-SeedFile $script:SerialEgressUd '/usr/local/sbin/voidseal-egress-lockdown')
        }

        $script:PosixSh2 = $null
        if ($IsWindows) {
            foreach ($git in @(Get-Command git -CommandType Application -All -ErrorAction SilentlyContinue)) {
                $dir = Split-Path -Parent $git.Source
                for ($up = 0; $up -lt 3 -and -not $script:PosixSh2 -and $dir; $up++) {
                    $dir = Split-Path -Parent $dir
                    foreach ($c in 'usr\bin\dash.exe', 'usr\bin\sh.exe') {
                        $cand = Join-Path $dir $c
                        if (Test-Path -LiteralPath $cand) { $script:PosixSh2 = $cand; break }
                    }
                }
                if ($script:PosixSh2) { break }
            }
        }
        else {
            $sh = Get-Command dash, sh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sh) { $script:PosixSh2 = $sh.Source }
        }
    }

    It 'both seeds write the diag script and run it as the last runcmd entry' -ForEach @(
        @{ Seed = 'baseline'; Var = 'SerialUd' }, @{ Seed = 'egress'; Var = 'SerialEgressUd' }
    ) {
        $ud = Get-Variable -Scope Script -Name $Var -ValueOnly
        $ud | Should -BeLike '*- path: /usr/local/sbin/voidseal-serial-diag*'
        $cmds = @(script:Get-RunCmd $ud)
        $cmds[-1] | Should -Be '- [ /usr/local/sbin/voidseal-serial-diag ]' -Because 'it runs after the installs, so it reports what they left'
    }

    It 'uses the same diag helper shape as the outbox and builder runners, and the same marker prefix' {
        $builder = New-CidataUserData -Profile (Import-WorkloadProfile -Path (Join-Path $script:SkillRoot 'profiles/builder.psd1') -TierProfileDir (Join-Path $script:SkillRoot 'tier-profiles'))
        $builder.Contains($script:DiagLineShape)             | Should -BeTrue -Because 'the builder runner is the reference shape'
        $script:Diag.Serial.Contains($script:DiagLineShape) | Should -BeTrue
        $script:Diag.Egress.Contains($script:DiagLineShape) | Should -BeTrue
        $script:Diag.Lock.Contains($script:DiagLineShape)   | Should -BeTrue
    }

    It 'the baseline script narrates device, mount, user, serial-getty and package facts' {
        foreach ($marker in 'serial-seed start', 'block_devices=', 'device_mounts=', 'cidata_labeled=', 'sandbox_user=',
                            'serial_getty_active=', 'autologin_dropin=', 'grub_ttyS0_lines=', 'cmdline_ttyS0=', 'bwrap_present=',
                            'ca_certificates=', 'failed_units=', 'serial-seed done') {
            $script:Diag.Serial | Should -BeLike "*diag `"*$marker*" -Because "the baseline must narrate $marker"
        }
    }

    It 'the egress seed adds the squid, unit, IPv6 and OUTPUT-policy facts, and its lockdown script narrates its own run' {
        foreach ($marker in 'squid_present=', 'squid_active=', 'egress_unit_enabled=', 'ipv6_disabled=', 'output_policy=') {
            $script:Diag.Egress | Should -BeLike "*diag `"*$marker*" -Because "the egress seed must narrate $marker"
        }
        $script:Diag.Lock | Should -Match 'diag "squid_active='
        $script:Diag.Lock | Should -Match 'diag "egress_lockdown=v4-applied redirect80_rc=\$r80 redirect443_rc=\$r443"'
        $script:Diag.Lock | Should -Match 'diag "ip6_lockdown=applied"'
        $script:Diag.Lock | Should -Match 'diag "ip6_lockdown=skipped'
        $script:Diag.Lock | Should -Match 'r80=\$\?' -Because 'each REDIRECT rc is captured right after its rule'
    }

    It 'the markers are structural only: no content tools, and only fixed system paths are read' -ForEach @(
        @{ Which = 'Serial' }, @{ Which = 'Egress' }, @{ Which = 'Lock' }
    ) {
        $diagLines = @(($script:Diag[$Which] -split "`n") | Where-Object { $_ -match '^\s*diag "' })
        $diagLines.Count | Should -BeGreaterThan 1
        foreach ($l in $diagLines) {
            $l | Should -Not -Match '\b(ls|find|head|tail|od|xxd|hexdump|strings|dd|journalctl|dmesg|tee)\b' -Because "'$l' would put names or bytes on the console"
            $l | Should -Not -Match '/mnt|/run/staging|/home|/workspace|/tmp|/var'
            # cat may only read the one kernel flag; any other absolute path must be a known fixed one.
            foreach ($m in [regex]::Matches($l, '\bcat\s+(\S+)')) { $m.Groups[1].Value | Should -Be '/proc/sys/net/ipv6/conf/all/disable_ipv6' }
            $allowed = @('/proc/mounts', '/proc/cmdline', '/boot/grub/grub.cfg', '/proc/sys/net/ipv6/conf/all/disable_ipv6',
                         '/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf', '/dev/null', '/dev/console', '/dev/')
            foreach ($m in [regex]::Matches($l, "(?<![\w<])/[A-Za-z][\w@./-]*")) {
                $path = $m.Value.TrimEnd('"', ')', '.')
                ($allowed | Where-Object { $path -eq $_ -or ($_ -eq '/dev/' -and $path -eq '/dev/') }) | Should -Not -BeNullOrEmpty -Because "'$path' in '$l' is not a fixed system path"
            }
        }
    }

    It 'the diag scripts and the lockdown script parse as POSIX sh (sh -n)' -ForEach @(
        @{ Which = 'Serial' }, @{ Which = 'Egress' }, @{ Which = 'Lock' }
    ) {
        if (-not $script:PosixSh2) { Set-ItResult -Skipped -Because 'no POSIX sh (dash) available on this host'; return }
        $f = Join-Path $TestDrive "diag-$Which.sh"
        [System.IO.File]::WriteAllText($f, $script:Diag[$Which], [System.Text.UTF8Encoding]::new($false))
        $out = & $script:PosixSh2 -n $f 2>&1
        $LASTEXITCODE | Should -Be 0 -Because "sh -n reported: $out"
    }

    It 'a diag failure cannot change control flow: set +e, output to /dev/console, errors swallowed' {
        foreach ($w in 'Serial', 'Egress') {
            $script:Diag[$w] | Should -Match '(?m)^set \+e$'
            $script:Diag[$w] | Should -Not -Match '(?m)^\s*(exit|poweroff|reboot|shutdown)\b'
        }
    }

    It 'the bare baseline still carries no egress content, and the egress seed still carries the lockdown' {
        $script:SerialUd | Should -Not -BeLike '*squid_active*'
        $script:SerialUd | Should -Not -BeLike '*egress_lockdown*'
        $script:SerialEgressUd | Should -BeLike '*iptables -P OUTPUT DROP*'
    }
}

# ===========================================================================
#  Serial + HostProxy: the guest side of host-enforced egress (EgressMode='HostProxy')
# ===========================================================================
Describe 'New-CidataUserData and New-CidataNetworkConfig - Serial + HostProxy' {

    BeforeAll {
        $script:HPProfile = @{
            Tier = 1; Name = 'ralph'; WorkloadMode = 'Serial'; Network = 'Internal+Allowlist'; EgressMode = 'HostProxy'
            Entrypoint = 'bash /opt/ralph/ralph-claude-code/ralph_loop.sh'; EgressAllowlist = @('api.example.com', '.files.example.org')
        }
        $script:HPPlan = Get-EgressAddressPlan -VMName 'sbx-seed' -SwitchName 'sbx-seed-int'
        $script:HPUd = New-CidataUserData -Profile $script:HPProfile -Egress $script:HPPlan
        $script:HPNc = New-CidataNetworkConfig -Egress $script:HPPlan
        $script:HPProxy = "http://$($script:HPPlan.GatewayIP):13128"

        function script:Get-HPSeedFile {
            param([string] $UserData, [string] $Path)
            $lines = $UserData -split "`n"
            $start = [array]::IndexOf($lines, "  - path: $Path")
            $start | Should -BeGreaterOrEqual 0 -Because "the seed must write $Path"
            $i = $start + 1
            while ($i -lt $lines.Count -and $lines[$i] -notmatch '^    content: \|') { $i++ }
            $body = [System.Collections.Generic.List[string]]::new()
            for ($i = $i + 1; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^  - path: ' -or $lines[$i] -match '^  #' -or $lines[$i] -match '^\S') { break }
                $body.Add(($lines[$i] -replace '^      ', ''))
            }
            return ($body -join "`n").TrimEnd()
        }
        function script:Get-HPRunCmd {
            param([string] $UserData)
            $lines = $UserData -split "`n"
            $at = [array]::IndexOf($lines, 'runcmd:')
            $out = [System.Collections.Generic.List[string]]::new()
            for ($i = $at + 1; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^  - ') { $out.Add($lines[$i].Trim()) } elseif ($lines[$i] -match '^\S') { break }
            }
            return @($out)
        }
        $script:HPPosixSh = $null
        if ($IsWindows) {
            foreach ($git in @(Get-Command git -CommandType Application -All -ErrorAction SilentlyContinue)) {
                $dir = Split-Path -Parent $git.Source
                for ($up = 0; $up -lt 3 -and -not $script:HPPosixSh -and $dir; $up++) {
                    $dir = Split-Path -Parent $dir
                    foreach ($c in 'usr\bin\dash.exe', 'usr\bin\sh.exe') {
                        $cand = Join-Path $dir $c
                        if (Test-Path -LiteralPath $cand) { $script:HPPosixSh = $cand; break }
                    }
                }
                if ($script:HPPosixSh) { break }
            }
        }
        else {
            $sh = Get-Command dash, sh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sh) { $script:HPPosixSh = $sh.Source }
        }
    }

    It 'keeps the serial command channel and substitutes every token' {
        $script:HPUd | Should -Match '#cloud-config'
        $script:HPUd | Should -Match '--autologin sandbox'
        $script:HPUd | Should -Not -Match '__[A-Z_]+__' -Because 'an unsubstituted token would ship a broken seed'
        $script:HPUd | Should -Not -Match "`r"
    }

    It 'points every client at the host proxy, with NO_PROXY empty, in /etc/environment and a login profile script' {
        $envFile = script:Get-HPSeedFile $script:HPUd '/etc/environment'
        @($envFile -split "`n") | Should -Be @("HTTPS_PROXY=$($script:HPProxy)", "https_proxy=$($script:HPProxy)", 'NO_PROXY=', 'no_proxy=')
        $script:HPUd | Should -Match '(?m)^    append: true$' -Because '/etc/environment is appended to, not replaced'
        $prof = script:Get-HPSeedFile $script:HPUd '/etc/profile.d/voidseal-egress-proxy.sh'
        $prof | Should -Match ([regex]::Escape("export HTTPS_PROXY=$($script:HPProxy)"))
        $prof | Should -Match '(?m)^export NO_PROXY=$'
        $script:HPUd | Should -Not -Match 'HTTP_PROXY=' -Because 'there is no plain-HTTP proxying'
    }

    It 'configures apt for the proxy and moves the Debian sources to https' {
        $apt = script:Get-HPSeedFile $script:HPUd '/etc/apt/apt.conf.d/99voidseal-proxy'
        $apt | Should -Match ([regex]::Escape("Acquire::https::Proxy `"$($script:HPProxy)/`";"))
        $cmds = script:Get-HPRunCmd $script:HPUd
        ($cmds -join "`n") | Should -Match 'http://deb\.debian\.org#https://deb\.debian\.org'
    }

    It 'the in-guest default-DROP allows only TCP to the gateway proxy port (nftables, with an iptables fallback)' {
        $lock = script:Get-HPSeedFile $script:HPUd '/usr/local/sbin/voidseal-egress-lockdown'
        $lock | Should -Match 'policy drop;'
        $lock | Should -Match ([regex]::Escape("ip daddr $($script:HPPlan.GatewayIP) tcp dport 13128 accept"))
        $lock | Should -Match ([regex]::Escape("iptables -A OUTPUT -p tcp -d $($script:HPPlan.GatewayIP) --dport 13128 -j ACCEPT"))
        $lock | Should -Match 'iptables -P OUTPUT DROP'
        $lock | Should -Not -Match 'dport 53|dport 80\b|dport 443|REDIRECT' -Because 'no DNS and no direct web egress in HostProxy mode'
    }

    It 'applies the lockdown in runcmd before any apt step, and runs the diag script last' {
        $cmds = script:Get-HPRunCmd $script:HPUd
        $iLock = [array]::IndexOf($cmds, '- systemctl enable --now voidseal-egress.service')
        $iApt  = [array]::IndexOf($cmds, '- [ apt-get, update ]')
        $iLock | Should -BeGreaterOrEqual 0
        $iLock | Should -BeLessThan $iApt
        $cmds[-1] | Should -Be '- [ /usr/local/sbin/voidseal-serial-diag ]'
        $script:HPUd | Should -Match 'Before=network-pre\.target'
    }

    It 'the diag script narrates the egress facts structurally' {
        $diag = script:Get-HPSeedFile $script:HPUd '/usr/local/sbin/voidseal-serial-diag'
        foreach ($m in 'egress_mode=hostproxy', 'guest_addr=', 'default_routes=', 'nameservers=', 'proxy_env=', 'egress_unit_enabled=', 'proxy_reachable=') {
            $diag | Should -BeLike "*$m*"
        }
        $diag | Should -Match '(?m)^set \+e$'
    }

    It 'the lockdown and diag scripts parse as POSIX sh (sh -n)' -ForEach @(
        @{ Path = '/usr/local/sbin/voidseal-egress-lockdown' }, @{ Path = '/usr/local/sbin/voidseal-serial-diag' }
    ) {
        if (-not $script:HPPosixSh) { Set-ItResult -Skipped -Because 'no POSIX sh (dash) available on this host'; return }
        $f = Join-Path $TestDrive ("hp-" + (Split-Path -Leaf $Path) + '.sh')
        [System.IO.File]::WriteAllText($f, (script:Get-HPSeedFile $script:HPUd $Path) + "`n", [System.Text.UTF8Encoding]::new($false))
        $out = & $script:HPPosixSh -n $f 2>&1
        $LASTEXITCODE | Should -Be 0 -Because "sh -n reported: $out"
    }

    It 'the user-data and network-config parse as YAML (when PyYAML is available)' {
        $py = $null
        try { $py = Resolve-PythonExe } catch { $py = $null }
        if (-not $py) { Set-ItResult -Skipped -Because 'no host Python'; return }
        & $py -c 'import yaml' 2>$null
        if ($LASTEXITCODE -ne 0) { Set-ItResult -Skipped -Because 'PyYAML is not installed'; return }
        $toJson = 'import sys,yaml,json; print(json.dumps(yaml.safe_load(open(sys.argv[1],encoding="utf-8"))))'
        $parsed = @{}
        foreach ($doc in @(@{ Name = 'ud'; Text = $script:HPUd }, @{ Name = 'nc'; Text = $script:HPNc })) {
            $f = Join-Path $TestDrive "hp-$($doc.Name).yaml"
            [System.IO.File]::WriteAllText($f, $doc.Text, [System.Text.UTF8Encoding]::new($false))
            $out = & $py -c $toJson $f 2>&1
            $LASTEXITCODE | Should -Be 0 -Because "YAML parse of $($doc.Name) reported: $out"
            $parsed[$doc.Name] = ($out | Out-String) | ConvertFrom-Json
        }
        $nc = $parsed['nc']
        $nc.version | Should -Be 2
        @($nc.ethernets.eth0.addresses) | Should -Be @("$($script:HPPlan.GuestIP)/30")
        $nc.ethernets.eth0.dhcp4 | Should -BeFalse
        $nc.ethernets.eth0.PSObject.Properties.Name | Should -Not -Contain 'routes'
        $nc.ethernets.eth0.PSObject.Properties.Name | Should -Not -Contain 'gateway4'
        $nc.ethernets.eth0.PSObject.Properties.Name | Should -Not -Contain 'nameservers'
        @($parsed['ud'].write_files | Where-Object { $_.path -eq '/etc/environment' })[0].append | Should -BeTrue
    }

    It 'the network-config is one static address with DHCP off and no route or resolver' {
        $script:HPNc | Should -Match '(?m)^version: 2$'
        $script:HPNc | Should -Match ([regex]::Escape("      - $($script:HPPlan.GuestIP)/30"))
        $script:HPNc | Should -Match 'dhcp4: false'
        $script:HPNc | Should -Not -Match 'gateway|routes|nameservers|via'
    }

    It 'FAILS CLOSED without a plan, with a malformed plan, or with an empty allowlist' {
        { New-CidataUserData -Profile $script:HPProfile } | Should -Throw "New-CidataUserData: a Serial+HostProxy seed needs the VM's egress address plan (-Egress, from the descriptor); none was given. Fail closed."
        $bad = @{} + $script:HPPlan; $bad['GatewayIP'] = "10.231.0.1'; reboot; '"
        { New-CidataUserData -Profile $script:HPProfile -Egress $bad } | Should -Throw 'New-CidataUserData: the egress address plan is malformed*'
        $far = @{} + $script:HPPlan; $far['GuestIP'] = '192.168.7.2'
        { New-CidataNetworkConfig -Egress $far } | Should -Throw "New-CidataUserData: the egress plan's gateway * and guest 192.168.7.2 are not two addresses in one /30. Fail closed."
        $empty = $script:HPProfile.Clone(); $empty['EgressAllowlist'] = @()
        { New-CidataUserData -Profile $empty -Egress $script:HPPlan } | Should -Throw 'New-CidataUserData: a Serial+HostProxy profile must have a non-empty EgressAllowlist (fail-closed).'
    }

    It 'FAILS CLOSED for a Disk-mode Tier-1 HostProxy profile (no Disk runner uses the host proxy)' {
        $disk = $script:HPProfile.Clone(); $disk['WorkloadMode'] = 'Disk'; $disk['Entrypoint'] = 'python3 /mnt/in/x.py'
        { New-CidataUserData -Profile $disk -Egress $script:HPPlan } | Should -Throw "New-CidataUserData: 'HostProxy' is wired for SERIAL-mode Tier-1 seeds*"
    }

    It 'a Tier-0 HostProxy profile (sealed with no adapter) keeps the offline seed' {
        $t0 = @{ Tier = 0; Name = 't0'; WorkloadMode = 'Serial'; Network = 'HostProxyAllowlist'; EgressMode = 'HostProxy'; EgressAllowlist = @() }
        New-CidataUserData -Profile $t0 | Should -Not -Match 'HTTPS_PROXY|voidseal-egress'
        $disk0 = $script:DiskProfile.Clone(); $disk0['EgressMode'] = 'HostProxy'
        New-CidataUserData -Profile $disk0 | Should -Not -Match 'HTTPS_PROXY'
    }
}
