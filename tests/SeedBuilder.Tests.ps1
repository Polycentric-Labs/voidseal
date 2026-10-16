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
        @{ Runner = 'builder runner';     SeedProfile = @{ Tier = 1; Network = 'Internal+Allowlist'; EgressMode = 'HostProxy'; WorkloadMode = 'Disk'; DepsSpec = @{ Pip = @{ Packages = @('urllib3') } }; Entrypoint = 'python3 /mnt/in/fetch_deps.py --out /mnt/out'; EgressAllowlist = @('pypi.org', 'files.pythonhosted.org') } }
    ) {
        # The builder seed needs the VM's address plan (it rides the host proxy); the offline runners do not.
        $udArgs = @{ Profile = $SeedProfile }
        if ($SeedProfile.ContainsKey('DepsSpec')) { $udArgs.Egress = Get-EgressAddressPlan -VMName 'sbx-ro' -SwitchName 'sbx-ro-int' }
        $ud     = New-CidataUserData @udArgs
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

    # The entrypoint's exit code used to go only to a console diagnostic, so a failed workload reached the
    # host as a missing result file. The runner now passes the code it captured to the producer, which
    # records it in the outbox. Both outbox profile shapes share the runner, so both are checked.
    It 'the outbox runner passes the entrypoint exit code to the producer (transport-only and processor)' {
        $proc = @{ Tier = 0; Name = 'proc-rc'; WorkloadMode = 'Disk'; Network = 'None'
                   ScreenConfig = @{ mode = 'aggressive' }; Entrypoint = 'python3 /mnt/in/proc.py --out /run/staging/result.html' }
        foreach ($prof in @($script:OutboxProfile, $proc)) {
            $lines    = @((New-CidataUserData -Profile $prof) -split "`r?`n")
            $producer = @($lines | Where-Object { $_ -match '^\s*python3\s+/mnt/in/run_disk_workload\.py\s' })
            $producer.Count | Should -Be 1
            $producer[0] | Should -Match '\s--workload-rc\s+"\$erc"(\s|$)' -Because 'the producer records the code the runner captured'
            $capture = @(0..($lines.Count - 1) | Where-Object { $lines[$_] -match '^\s*erc=\$\?\s*$' })
            $capture.Count | Should -Be 1 -Because 'the code is captured exactly once'
            $lines[$capture[0] - 1].Trim() | Should -Be 'fi' -Because 'it is captured straight after the entrypoint ran, before any other command can overwrite $?'
            $producerIdx = [array]::IndexOf($lines, $producer[0])
            $producerIdx | Should -BeGreaterThan $capture[0] -Because 'the code exists before the producer is called'
        }
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

Describe 'Builder CIDATA seed: the dep fetch rides the host proxy (no in-guest proxy, no redirect rules)' {
    BeforeAll {
        # The builder is the kept-NIC HostProxy shape with a DepsSpec; its seed needs the VM's address plan.
        $script:builderProfile = @{
            Tier = 1; Network = 'Internal+Allowlist'; EgressMode = 'HostProxy'; WorkloadMode = 'Disk'
            DepsSpec = @{ Pip = @{ Packages = @('urllib3') }; Apt = @{ Packages = @('jq') }; HuggingFace = @{ Models = @('org/model') } }
            Entrypoint = 'python3 /mnt/in/fetch_deps.py --spec /mnt/in/deps-spec.json --out /mnt/out'
            EgressAllowlist = @('pypi.org','files.pythonhosted.org','deb.debian.org','security.debian.org','huggingface.co','.hf.co')
        }
        $script:builderPlan  = Get-EgressAddressPlan -VMName 'sbx-bld-seed' -SwitchName 'sbx-bld-seed-int'
        $script:builderProxy = "http://$($script:builderPlan.GatewayIP):13128"
        $script:builderUd    = New-CidataUserData -Profile $script:builderProfile -Egress $script:builderPlan

        # The content block of one write_files entry, dedented.
        function script:Get-BuilderSeedFile {
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
        function script:Get-BuilderRunCmd {
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
    }
    It 'DepsSpec selects the builder runner; the seed carries no in-guest proxy, no redirect rules and no unsubstituted token' {
        $script:builderUd | Should -Match 'vmdep-builder'
        $script:builderUd | Should -Match ([regex]::Escape($script:builderProfile.Entrypoint))
        $script:builderUd | Should -Not -Match '(?i)squid'
        $script:builderUd | Should -Not -Match 'REDIRECT|intercept|ssl-bump|dstdomain|--to-port'
        $script:builderUd | Should -Not -Match '__[A-Z_]+__' -Because 'every token is substituted'
        $script:builderUd | Should -Not -Match 'network: \{config: disabled\}' -Because 'the builder keeps its NIC; the seed network-config gives it its static address'
        $script:builderUd | Should -Match '(?m)^# network: applied from the seed network-config'
    }
    It 'points every fetcher at the host proxy: the proxy environment (both spellings, both schemes), the login profile and the apt setting' {
        $env = script:Get-BuilderSeedFile $script:builderUd '/etc/environment'
        @($env -split "`n") | Should -Be @("http_proxy=$($script:builderProxy)", "https_proxy=$($script:builderProxy)", "HTTP_PROXY=$($script:builderProxy)", "HTTPS_PROXY=$($script:builderProxy)", 'no_proxy=localhost,127.0.0.1', 'NO_PROXY=localhost,127.0.0.1')
        $prof = script:Get-BuilderSeedFile $script:builderUd '/etc/profile.d/voidseal-egress-proxy.sh'
        $prof | Should -Match ([regex]::Escape("export https_proxy=$($script:builderProxy)"))
        $prof | Should -Match ([regex]::Escape("export HTTPS_PROXY=$($script:builderProxy)"))
        $apt = script:Get-BuilderSeedFile $script:builderUd '/etc/apt/apt.conf.d/99voidseal-proxy'
        $apt | Should -Match ([regex]::Escape("Acquire::http::Proxy `"$($script:builderProxy)/`";"))
        $apt | Should -Match ([regex]::Escape("Acquire::https::Proxy `"$($script:builderProxy)/`";"))
    }
    It 'the runner exports the proxy settings after the verdict disk is chosen and before the entrypoint runs (a oneshot unit reads no login profile)' {
        $runner = script:Get-BuilderSeedFile $script:builderUd '/usr/local/sbin/vmdep-builder'
        $lines  = $runner -split "`n"
        $export = [array]::IndexOf($lines, '. /etc/profile.d/voidseal-egress-proxy.sh')
        $pick   = [array]::IndexOf($lines, 'VERDICT_DEV="/dev/$1"')
        $run    = @(0..($lines.Count - 1) | Where-Object { $lines[$_] -like "*runuser -u sandbox -- /bin/sh -c '*" })[0]
        $export | Should -BeGreaterThan 0
        $pick   | Should -BeLessThan $export -Because 'a run that cannot report a verdict stops before anything else'
        $export | Should -BeLessThan $run -Because 'the fetchers inherit the environment the runner exports'
    }
    It 'the in-guest lockdown is the shared HostProxy block: default-DROP allowing only TCP to the gateway proxy port, nft first, iptables fallback, no DNS or direct web egress, identical to the Serial seed' {
        $lock = script:Get-BuilderSeedFile $script:builderUd '/usr/local/sbin/voidseal-egress-lockdown'
        $lock | Should -Match 'policy drop;'
        $lock | Should -Match ([regex]::Escape("ip daddr $($script:builderPlan.GatewayIP) tcp dport 13128 accept"))
        $lock | Should -Match ([regex]::Escape("iptables -A OUTPUT -p tcp -d $($script:builderPlan.GatewayIP) --dport 13128 -j ACCEPT"))
        $lock | Should -Match 'iptables -P OUTPUT DROP'
        $lock | Should -Not -Match 'dport 53|dport 80\b|dport 443|REDIRECT' -Because 'no DNS and no direct web egress: the proxy resolves and dials'
        $serial = New-CidataUserData -Profile @{ Tier = 1; Network = 'Internal+Allowlist'; EgressMode = 'HostProxy'; WorkloadMode = 'Serial'; EgressAllowlist = @('pypi.org'); Entrypoint = 'bash run.sh' } -Egress $script:builderPlan
        (script:Get-BuilderSeedFile $serial '/usr/local/sbin/voidseal-egress-lockdown') | Should -Be $lock -Because 'one lockdown block, carried by every HostProxy seed'
    }
    It 'IPv6 is disabled in bootcmd and persisted through sysctl.d; the Debian sources move to https there too, before the package stage' {
        $script:builderUd | Should -Match "(?m)^  - \[ sysctl, -w, 'net\.ipv6\.conf\.all\.disable_ipv6=1' \]"
        $script:builderUd | Should -Match "(?m)^  - \[ sysctl, -w, 'net\.ipv6\.conf\.default\.disable_ipv6=1' \]"
        (script:Get-BuilderSeedFile $script:builderUd '/etc/sysctl.d/99-voidseal-noipv6.conf') | Should -Match 'net\.ipv6\.conf\.all\.disable_ipv6 = 1'
        $lines = $script:builderUd -split "`n"
        $boot  = [array]::IndexOf($lines, 'bootcmd:')
        $files = [array]::IndexOf($lines, 'write_files:')
        $sed   = @(0..($lines.Count - 1) | Where-Object { $lines[$_] -match 'http://deb\.debian\.org#https://deb\.debian\.org' })[0]
        $boot | Should -BeGreaterOrEqual 0
        $sed  | Should -BeGreaterThan $boot
        $sed  | Should -BeLessThan $files -Because 'the sources move inside bootcmd, before the package stage can read them'
    }
    It 'nftables is installed through the proxy in the package stage, and runcmd applies the lockdown before the builder unit starts' {
        $script:builderUd | Should -Match "(?m)^packages:\n  - nftables"
        $cmds   = script:Get-BuilderRunCmd $script:builderUd
        $iLock  = [array]::IndexOf($cmds, '- [ systemctl, enable, --now, voidseal-egress.service ]')
        $iStart = [array]::IndexOf($cmds, '- [ systemctl, start, --no-block, vmdep-builder.service ]')
        $iLock  | Should -BeGreaterOrEqual 0
        $iStart | Should -BeGreaterThan $iLock
        $cmds | Should -Not -Contain '- [ apt-get, install, -y, squid, iptables ]'
        $script:builderUd | Should -Match 'After=network-online\.target voidseal-egress\.service'
    }
    It 'emits structural [voidseal-diag] serial markers (the silent-runner class already cost two live debug rounds)' {
        $script:builderUd | Should -Match '\[voidseal-diag\]' -Because 'a fail-closed poweroff must narrate WHY to the serial console, not vanish silently'
    }
    It 'narrates the egress bring-up: the proxy address, routes and resolver counts, the IPv6 flag, the lockdown unit, nft presence and a TCP connect to the proxy' {
        foreach ($m in 'diag "egress_mode=hostproxy proxy=', 'default_routes=', 'nameservers=', 'ipv6_disabled=', 'diag "egress_unit_enabled=', 'nft_present=', 'proxy_reachable=') {
            $script:builderUd | Should -BeLike "*$m*" -Because "a failed live fetch must be attributable from $m"
        }
        $script:builderUd | Should -Match ([regex]::Escape("/dev/tcp/$($script:builderPlan.GatewayIP)/13128"))
    }
    It 'narrates mounts, entrypoint rc, per-fetcher artifact counts, and manifest presence (the host verdict is the exit code and manifest; serial says where the guest stopped)' {
        $script:builderUd | Should -Match 'diag "input_mounted='  -Because 'a failed INPUT mount means the runner + DepsSpec never reached the guest'
        $script:builderUd | Should -Match 'diag "output_mounted=' -Because 'a failed OUTPUT mount means nothing can be staged, and which owner it mounted under decides who may write'
        $script:builderUd | Should -Match 'diag "entrypoint_rc='  -Because 'fetch_deps.py exits 2 on any failed fetcher; the host reads that rc as the verdict, and serial says where it came from'
        $script:builderUd | Should -Match 'fetched pip='          -Because 'a per-fetcher artifact COUNT attributes an empty deps disk to the fetcher that produced nothing'
        $script:builderUd | Should -Match 'apt='                  -Because 'apt artifacts land under /mnt/out/apt; its count must be narrated separately'
        $script:builderUd | Should -Match 'hf='                   -Because 'HF artifacts land under /mnt/out/hf; its count must be narrated separately'
        $script:builderUd | Should -Match 'manifest_present='     -Because 'write_manifest only runs after ALL fetchers succeed; its presence is the single yes/no of a fully-green fetch'
    }
    It 'echoes a DISTINCT ABORT reason before each of the fail-closed poweroffs (no-OUTPUT, no-INPUT, no single raw verdict disk)' {
        $script:builderUd | Should -Match 'diag "ABORT output-not-mounted' -Because 'the no-OUTPUT branch powers off before any verdict can be packed; only serial can say why'
        $script:builderUd | Should -Match 'diag "ABORT input-not-mounted'  -Because 'the no-INPUT branch has no producer to pack a verdict with, so the host reads a missing verdict; serial must name the branch'
        $script:builderUd | Should -Match 'diag "ABORT verdict-candidates-not-1' -Because 'the raw verdict disk could not be told apart from the others'
    }
    It 'builder diag markers are STRUCTURAL only: no fetched-artifact bytes on the serial console (same contract as the outbox runner)' {
        $diagLines = @(($script:builderUd -split "`r?`n") | Where-Object { $_ -match 'diag "' })
        $diagLines.Count | Should -BeGreaterThan 6 -Because 'every decision point (mounts, verdict disk, proxy, entrypoint, fetch counts, manifest, poweroff) must be narrated'
        $leaky = @($diagLines | Where-Object { $_ -match '/mnt/out' -and $_ -match '\b(cat|head|tail|od|xxd|hexdump|dd|strings)\b' })
        $leaky | Should -BeNullOrEmpty -Because 'serial narrates structure (liveness/rc/counts/presence), never dependency payload bytes'
    }
    It 'the OFFLINE (non-builder) disk seed is unaffected: network disabled, no proxy files, no lockdown, no package stage' {
        $ud = New-CidataUserData -Profile @{ WorkloadMode = 'Disk'; Entrypoint = 'python3 /mnt/in/x.py' }
        $ud | Should -Match 'network: \{config: disabled\}'
        $ud | Should -Not -Match '(?i)squid|nftables|disable_ipv6|HTTPS_PROXY|voidseal-egress'
        $ud | Should -Not -Match '__[A-Z_]+__'
    }
    It 'a builder profile with an EMPTY allowlist is refused (fail-closed)' {
        $empty = $script:builderProfile.Clone(); $empty['EgressAllowlist'] = @()
        { New-CidataUserData -Profile $empty -Egress $script:builderPlan } | Should -Throw -ExpectedMessage '*allowlist*'
    }
    It 'a builder entrypoint containing a single quote is refused (same sh -c guard as the other runners)' {
        $quoted = $script:builderProfile.Clone(); $quoted['Entrypoint'] = "python3 'x'"
        { New-CidataUserData -Profile $quoted -Egress $script:builderPlan } | Should -Throw
    }
    It 'a builder profile that does not keep a NIC (Tier 0, or a processor) is refused: it fetches over the host proxy or not at all' {
        $t0 = $script:builderProfile.Clone(); $t0['Tier'] = 0
        { New-CidataUserData -Profile $t0 -Egress $script:builderPlan } | Should -Throw "New-CidataUserData: a builder profile (DepsSpec) fetches over the host proxy, so it must be a Tier-1 'Internal+Allowlist' profile with EgressMode='HostProxy'; this one is Tier 0, Network='Internal+Allowlist', EgressMode='HostProxy'. Fail closed."
        $proc = $script:builderProfile.Clone(); $proc['Network'] = 'None'; $proc['EgressMode'] = 'None'
        { New-CidataUserData -Profile $proc -Egress $script:builderPlan } | Should -Throw '*builder profile (DepsSpec) fetches over the host proxy*'
    }
    It 'a builder seed without the address plan is refused' {
        { New-CidataUserData -Profile $script:builderProfile } | Should -Throw "New-CidataUserData: a HostProxy seed (a VM that keeps its NIC) needs the VM's egress address plan (-Egress, from the descriptor); none was given. Fail closed."
    }
    It 'the user-data parses as YAML with the proxy files, the package stage and the bootcmd (when PyYAML is available)' {
        $py = $null
        try { $py = Resolve-PythonExe } catch { $py = $null }
        if (-not $py) { Set-ItResult -Skipped -Because 'no host Python'; return }
        & $py -c 'import yaml' 2>$null
        if ($LASTEXITCODE -ne 0) { Set-ItResult -Skipped -Because 'PyYAML is not installed'; return }
        $f = Join-Path $TestDrive 'builder-ud.yaml'
        [System.IO.File]::WriteAllText($f, $script:builderUd, [System.Text.UTF8Encoding]::new($false))
        $out = & $py -c 'import sys,yaml,json; print(json.dumps(yaml.safe_load(open(sys.argv[1],encoding="utf-8"))))' $f 2>&1
        $LASTEXITCODE | Should -Be 0 -Because "YAML parse reported: $out"
        $doc = ($out | Out-String) | ConvertFrom-Json
        @($doc.packages) | Should -Be @('nftables')
        @($doc.write_files | ForEach-Object { $_.path }) | Should -Contain '/etc/apt/apt.conf.d/99voidseal-proxy'
        @($doc.write_files | ForEach-Object { $_.path }) | Should -Contain '/usr/local/sbin/voidseal-egress-lockdown'
        @($doc.bootcmd).Count | Should -Be 3
        $doc.PSObject.Properties.Name | Should -Not -Contain 'network'
    }
}

Describe 'Builder runner - the verdict goes to a raw verdict disk, packed with the shared outbox producer' {

    BeforeAll {
        $script:BvProfile = @{
            Tier = 1; Network = 'Internal+Allowlist'; EgressMode = 'HostProxy'; WorkloadMode = 'Disk'
            DepsSpec = @{ Pip = @{ Packages = @('urllib3') } }
            Entrypoint = 'python3 /mnt/in/fetch_deps.py --spec /mnt/in/deps-spec.json --out /mnt/out'
            EgressAllowlist = @('pypi.org', 'files.pythonhosted.org')
        }
        $script:BvUd = New-CidataUserData -Profile $script:BvProfile -Egress (Get-EgressAddressPlan -VMName 'sbx-bv' -SwitchName 'sbx-bv-int')

        # The content block of the builder runner script embedded in the user-data, dedented.
        $lines = $script:BvUd -split "`n"
        $start = [array]::IndexOf($lines, '  - path: /usr/local/sbin/vmdep-builder')
        $start | Should -BeGreaterOrEqual 0
        $body = [System.Collections.Generic.List[string]]::new()
        for ($i = $start + 3; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^  - path: ' -or $lines[$i] -match '^\S') { break }
            $body.Add(($lines[$i] -replace '^      ', ''))
        }
        $script:BvRunner = ($body -join "`n")

        # A POSIX sh for `-n` checks and for running extracted blocks. On Windows use Git for Windows' dash
        # (never the WSL launcher); its sibling tools (basename, xargs, tr, ...) live in the same folder.
        $script:BvSh = $null
        if ($IsWindows) {
            foreach ($git in @(Get-Command git -CommandType Application -All -ErrorAction SilentlyContinue)) {
                $dir = Split-Path -Parent $git.Source
                for ($up = 0; $up -lt 3 -and -not $script:BvSh -and $dir; $up++) {
                    $dir = Split-Path -Parent $dir
                    foreach ($c in 'usr\bin\dash.exe', 'usr\bin\sh.exe') {
                        $cand = Join-Path $dir $c
                        if (Test-Path -LiteralPath $cand) { $script:BvSh = $cand; break }
                    }
                }
                if ($script:BvSh) { break }
            }
        }
        else {
            $sh = Get-Command dash, sh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sh) { $script:BvSh = $sh.Source }
        }

        # Run $Script under the POSIX sh with its sibling tools on PATH; returns @{ Out; Code }.
        function script:Invoke-BvSh {
            param([string] $Script)
            $f = Join-Path ([System.IO.Path]::GetTempPath()) ('vs-bv-{0}.sh' -f [guid]::NewGuid().ToString('N'))
            [System.IO.File]::WriteAllText($f, $Script, [System.Text.UTF8Encoding]::new($false))
            $savedPath = $env:PATH
            try {
                $env:PATH = "$(Split-Path -Parent $script:BvSh)$([System.IO.Path]::PathSeparator)$env:PATH"
                $out = & $script:BvSh $f 2>&1
                return @{ Out = @($out | ForEach-Object { [string]$_ }); Code = $LASTEXITCODE }
            }
            finally { $env:PATH = $savedPath; Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        }

        # The runner's raw-disk selection block (root disk lookup through the chosen device), with /sys/block
        # pointed at a fake tree and the Linux-only tools shimmed. Each disk is @{ Name; Partitions = n;
        # Signature = bool }; the root disk is the first one.
        function script:Invoke-VerdictSelection {
            param([object[]] $Disks)
            $m = [regex]::Match($script:BvRunner, '(?ms)^ROOT_SRC=.*?^diag "verdict_dev=[^\n]*$')
            $m.Success | Should -BeTrue -Because 'the selection block must be findable'
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('vs-sel-{0}' -f [guid]::NewGuid().ToString('N'))
            $sys = Join-Path $tmp 'sysblock'; $sig = Join-Path $tmp 'sig'
            New-Item -ItemType Directory -Path $sys, $sig -Force | Out-Null
            try {
                foreach ($d in $Disks) {
                    New-Item -ItemType Directory -Path (Join-Path $sys $d.Name) -Force | Out-Null
                    for ($p = 1; $p -le [int]$d.Partitions; $p++) { New-Item -ItemType Directory -Path (Join-Path $sys "$($d.Name)/$($d.Name)$p") -Force | Out-Null }
                    if ($d.Signature) { Set-Content -LiteralPath (Join-Path $sig $d.Name) -Value 'sig' }
                }
                $root = $Disks[0].Name
                $block = $m.Value.Replace('/sys/block', '$SYSBLOCK')
                $harness = @(
                    'set +e'
                    ('SYSBLOCK="{0}"' -f ($sys -replace '\\', '/'))
                    ('SIGDIR="{0}"' -f ($sig -replace '\\', '/'))
                    'diag() { echo "diag: $*"; }'
                    ('findmnt() { echo /dev/' + $root + '1; }')
                    ('lsblk() { echo ' + $root + '; }')
                    'blkid() { for a in "$@"; do :; done; [ -f "$SIGDIR/$(basename "$a")" ]; }'
                    'sync() { :; }'
                    'umount() { :; }'
                    'poweroff() { echo POWEROFF; }'
                    $block
                    'echo "CHOSEN=$VERDICT_DEV"'
                ) -join "`n"
                $res = script:Invoke-BvSh -Script $harness
                $text = $res.Out -join "`n"
                return @{ Text = $text; Chosen = ([regex]::Match($text, '(?m)^CHOSEN=(.*)$').Groups[1].Value); PoweredOff = ($text -match '(?m)^POWEROFF$') }
            }
            finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'packs the exit code and the manifest with the shared producer, in transport-only mode, onto the raw device' {
        $script:BvRunner | Should -Match 'python3 /mnt/in/run_disk_workload\.py --staging /run/vstaging --verdicts /run/vverdicts\.json --out "\$VERDICT_DEV" --transport-only'
        $script:BvRunner | Should -Match ([regex]::Escape('printf ''%s'' "$rc" > /run/vstaging/result.exitcode'))
        $script:BvRunner | Should -Match ([regex]::Escape('cp /mnt/out/deps-manifest.json /run/vstaging/deps-manifest.json'))
    }

    It 'no longer writes any verdict onto the exFAT deps disk (the host never reads that disk)' {
        $script:BvRunner | Should -Not -Match '/mnt/out/result\.exitcode'
        $script:BvRunner | Should -Not -Match 'rc70'
    }

    It 'identifies the raw verdict disk POSITIVELY: no partitions and no filesystem signature, never by an exclusion list' {
        $script:BvRunner | Should -Match 'blkid -p'
        $script:BvRunner | Should -Match 'has partitions'
        $script:BvRunner | Should -Match 'has a filesystem signature'
        $script:BvRunner | Should -Not -Match 'blkid -L INPUT' -Because 'an exclusion list must track every disk we attach; the raw-ness test does not'
        $script:BvRunner | Should -Not -Match 'blkid -L OUTPUT'
    }

    It 'chooses the verdict disk and aborts on anything but exactly one candidate, BEFORE the entrypoint runs' {
        $script:BvRunner | Should -Match 'if \[ "\$#" -ne 1 \]; then diag "ABORT verdict-candidates-not-1'
        $pick = $script:BvRunner.IndexOf('VERDICT_DEV="/dev/$1"')
        $run  = $script:BvRunner.IndexOf("runuser -u sandbox -- /bin/sh -c '")
        $pick | Should -BeGreaterThan 0
        $pick | Should -BeLessThan $run -Because 'a run that cannot report a verdict must stop before a long fetch, not after it'
        $abort = ($script:BvRunner -split "`n" | Where-Object { $_ -match 'ABORT verdict-candidates-not-1' } | Select-Object -First 1)
        $abort | Should -Match 'poweroff; exit 0'
    }

    It 'narrates the selection and the pack: candidates, chosen device, producer rc and the container magic, structurally' {
        foreach ($marker in 'diag "verdict_candidates=', 'diag "verdict_dev=', 'diag "verdict_producer_rc=', 'diag "verdict_head=', 'diag "ABORT verdict-candidates-not-1') {
            $script:BvRunner | Should -BeLike "*$marker*" -Because "the live capture needs $marker"
        }
        $diagLines = @(($script:BvRunner -split "`n") | Where-Object { $_ -match 'diag "' })
        @($diagLines | Where-Object { $_ -match '/run/vstaging' -and $_ -match '\b(cat|head|tail|od|xxd|hexdump|strings)\b' }).Count | Should -Be 0 -Because 'serial narrates structure, never staged bytes'
    }

    It 'the whole runner still parses as POSIX sh (sh -n)' {
        if (-not $script:BvSh) { Set-ItResult -Skipped -Because 'no POSIX sh (dash) available on this host'; return }
        $f = Join-Path ([System.IO.Path]::GetTempPath()) ('vs-bv-n-{0}.sh' -f [guid]::NewGuid().ToString('N'))
        try {
            [System.IO.File]::WriteAllText($f, $script:BvRunner, [System.Text.UTF8Encoding]::new($false))
            $out = & $script:BvSh -n $f 2>&1
            $LASTEXITCODE | Should -Be 0 -Because "sh -n reported: $out"
        }
        finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }

    It 'selection, run for real under sh: the only raw disk is chosen, never the deps, INPUT, CIDATA or root disk' {
        if (-not $script:BvSh) { Set-ItResult -Skipped -Because 'no POSIX sh (dash) available on this host'; return }
        $r = script:Invoke-VerdictSelection -Disks @(
            @{ Name = 'sda'; Partitions = 2; Signature = $true },    # root
            @{ Name = 'sdb'; Partitions = 1; Signature = $true },    # INPUT (exFAT on a GPT partition)
            @{ Name = 'sdc'; Partitions = 1; Signature = $true },    # OUTPUT / deps (exFAT on a GPT partition)
            @{ Name = 'sdd'; Partitions = 1; Signature = $true },    # CIDATA seed (FAT32)
            @{ Name = 'sde'; Partitions = 0; Signature = $false })   # the raw verdict disk
        $r.Chosen | Should -Be '/dev/sde'
        $r.PoweredOff | Should -BeFalse
        $r.Text | Should -Match 'skip sdb \(has partitions\)'
        $r.Text | Should -Match 'skip sdc \(has partitions\)'
    }

    It 'selection: a whole disk with a filesystem signature but no partition table is skipped, not mistaken for raw' {
        if (-not $script:BvSh) { Set-ItResult -Skipped -Because 'no POSIX sh (dash) available on this host'; return }
        $r = script:Invoke-VerdictSelection -Disks @(
            @{ Name = 'sda'; Partitions = 1; Signature = $true },
            @{ Name = 'sdb'; Partitions = 0; Signature = $true },    # superfloppy-style deps disk
            @{ Name = 'sdc'; Partitions = 0; Signature = $false })
        $r.Chosen | Should -Be '/dev/sdc'
        $r.Text | Should -Match 'skip sdb \(has a filesystem signature\)'
    }

    It 'selection: no raw disk, or two raw disks, powers off with no device chosen (fail closed)' -ForEach @(
        @{ Case = 'none'; Disks = @(@{ Name = 'sda'; Partitions = 1; Signature = $true }, @{ Name = 'sdb'; Partitions = 1; Signature = $true }) }
        @{ Case = 'two';  Disks = @(@{ Name = 'sda'; Partitions = 1; Signature = $true }, @{ Name = 'sdb'; Partitions = 0; Signature = $false }, @{ Name = 'sdc'; Partitions = 0; Signature = $false }) }
    ) {
        if (-not $script:BvSh) { Set-ItResult -Skipped -Because 'no POSIX sh (dash) available on this host'; return }
        $r = script:Invoke-VerdictSelection -Disks $Disks
        $r.PoweredOff | Should -BeTrue
        $r.Text | Should -Match 'ABORT verdict-candidates-not-1'
        $r.Text | Should -Not -Match '(?m)^CHOSEN='
    }

    It 'the pack block, run for real under sh with the real producer, writes a container the host reader accepts: exit code and manifest, nothing else' -ForEach @(
        @{ Case = 'with manifest'; Rc = '0'; Manifest = '{"files":[]}'; Want = @('deps-manifest.json', 'result.exitcode', 'verdicts.json') }
        @{ Case = 'no manifest';   Rc = '2'; Manifest = $null;          Want = @('result.exitcode', 'verdicts.json') }
    ) {
        if (-not $script:BvSh) { Set-ItResult -Skipped -Because 'no POSIX sh (dash) available on this host'; return }
        $m = [regex]::Match($script:BvRunner, '(?ms)^printf .%s. "\$rc" > /run/vstaging/result\.exitcode.*?^diag "verdict_producer_rc=[^\n]*$')
        $m.Success | Should -BeTrue
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('vs-pack-{0}' -f [guid]::NewGuid().ToString('N'))
        $outDir = Join-Path $tmp 'out'; $stage = Join-Path $tmp 'vstaging'
        New-Item -ItemType Directory -Path $outDir, $stage -Force | Out-Null
        try {
            if ($null -ne $Manifest) { [System.IO.File]::WriteAllText((Join-Path $outDir 'deps-manifest.json'), $Manifest, [System.Text.UTF8Encoding]::new($false)) }
            $fwd = { param($p) $p -replace '\\', '/' }
            $block = $m.Value.
                Replace('/mnt/in/run_disk_workload.py', '"$PRODUCER"').
                Replace('/mnt/out/', ((& $fwd $outDir) + '/')).
                Replace('/run/vstaging', (& $fwd $stage)).
                Replace('/run/vverdicts.json', ((& $fwd $tmp) + '/vv.json')).
                Replace('/run/vproducer.err', ((& $fwd $tmp) + '/vp.err'))
            $device = (& $fwd $tmp) + '/verdict.raw'
            $harness = @(
                'set +e'
                ('PRODUCER="{0}"' -f (& $fwd (Join-Path $script:SkillRoot 'guest/run_disk_workload.py')))
                ('VERDICT_DEV="{0}"' -f $device)
                ('rc={0}' -f $Rc)
                'diag() { echo "diag: $*"; }'
                ('python3() {{ "{0}" "$@"; }}' -f (& $fwd (Resolve-PythonExe)))
                $block
            ) -join "`n"
            $res = script:Invoke-BvSh -Script $harness
            ($res.Out -join "`n") | Should -Match 'verdict_producer_rc=0'
            Test-Path -LiteralPath $device | Should -BeTrue

            # Feed it to the host's own reader and list what came out.
            $dest = Join-Path $tmp 'gate'
            $py = Resolve-PythonExe
            $null = & $py (Join-Path $script:SkillRoot 'host/read_outbox.py') --blob $device --out $dest
            $LASTEXITCODE | Should -Be 0
            $got = @(Get-ChildItem -LiteralPath $dest -Recurse -File | ForEach-Object { $_.Name } | Sort-Object)
            $got | Should -Be @($Want | Sort-Object)
            [System.IO.File]::ReadAllText((Join-Path $dest 'staging/result.exitcode')) | Should -BeExactly $Rc
            if ($null -ne $Manifest) { [System.IO.File]::ReadAllText((Join-Path $dest 'staging/deps-manifest.json')) | Should -BeExactly $Manifest }
        }
        finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
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
#  The Serial baseline carries the same structural [voidseal-diag] markers as the disk runners (E7)
# ===========================================================================
Describe 'New-CidataUserData - the serial baseline seed narrates structure on the serial console (E7)' {

    BeforeAll {
        $script:DiagLineShape = 'diag() { echo "[voidseal-diag] $*" > /dev/console 2>/dev/null; }'
        $script:SerialUd = New-CidataUserData -Profile $script:SerialProfile

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
        $script:Diag = @{ Serial = (script:Get-SeedFile $script:SerialUd '/usr/local/sbin/voidseal-serial-diag') }

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

    It 'the baseline seed writes the diag script and runs it as the last runcmd entry' {
        $script:SerialUd | Should -BeLike '*- path: /usr/local/sbin/voidseal-serial-diag*'
        $cmds = @(script:Get-RunCmd $script:SerialUd)
        $cmds[-1] | Should -Be '- [ /usr/local/sbin/voidseal-serial-diag ]' -Because 'it runs after the installs, so it reports what they left'
    }

    It 'uses the same diag helper shape as the outbox and builder runners, and the same marker prefix' {
        $builderProfile = Import-WorkloadProfile -Path (Join-Path $script:SkillRoot 'profiles/builder.psd1') -TierProfileDir (Join-Path $script:SkillRoot 'tier-profiles')
        $builder = New-CidataUserData -Profile $builderProfile -Egress (Get-EgressAddressPlan -VMName 'sbx-e7' -SwitchName 'sbx-e7-int')
        $builder.Contains($script:DiagLineShape)             | Should -BeTrue -Because 'the builder runner is the reference shape'
        $script:Diag.Serial.Contains($script:DiagLineShape) | Should -BeTrue
    }

    It 'the baseline script narrates device, mount, user, serial-getty and package facts' {
        foreach ($marker in 'serial-seed start', 'block_devices=', 'device_mounts=', 'cidata_labeled=', 'sandbox_user=',
                            'serial_getty_active=', 'autologin_dropin=', 'grub_ttyS0_lines=', 'cmdline_ttyS0=', 'bwrap_present=',
                            'ca_certificates=', 'failed_units=', 'serial-seed done') {
            $script:Diag.Serial | Should -BeLike "*diag `"*$marker*" -Because "the baseline must narrate $marker"
        }
    }

    It 'the markers are structural only: no content tools, and only fixed system paths are read' {
        $diagLines = @(($script:Diag.Serial -split "`n") | Where-Object { $_ -match '^\s*diag "' })
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

    It 'the diag script parses as POSIX sh (sh -n)' {
        if (-not $script:PosixSh2) { Set-ItResult -Skipped -Because 'no POSIX sh (dash) available on this host'; return }
        $f = Join-Path $TestDrive 'diag-Serial.sh'
        [System.IO.File]::WriteAllText($f, $script:Diag.Serial, [System.Text.UTF8Encoding]::new($false))
        $out = & $script:PosixSh2 -n $f 2>&1
        $LASTEXITCODE | Should -Be 0 -Because "sh -n reported: $out"
    }

    It 'a diag failure cannot change control flow: set +e, output to /dev/console, errors swallowed' {
        $script:Diag.Serial | Should -Match '(?m)^set \+e$'
        $script:Diag.Serial | Should -Not -Match '(?m)^\s*(exit|poweroff|reboot|shutdown)\b'
    }

    It 'the bare baseline carries no egress content' {
        $script:SerialUd | Should -Not -BeLike '*voidseal-egress-lockdown*'
        $script:SerialUd | Should -Not -BeLike '*egress_lockdown*'
        $script:SerialUd | Should -Not -BeLike '*HTTPS_PROXY*'
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
        { New-CidataUserData -Profile $script:HPProfile } | Should -Throw "New-CidataUserData: a HostProxy seed (a VM that keeps its NIC) needs the VM's egress address plan (-Egress, from the descriptor); none was given. Fail closed."
        $bad = @{} + $script:HPPlan; $bad['GatewayIP'] = "10.231.0.1'; reboot; '"
        { New-CidataUserData -Profile $script:HPProfile -Egress $bad } | Should -Throw 'New-CidataUserData: the egress address plan is malformed*'
        $far = @{} + $script:HPPlan; $far['GuestIP'] = '192.168.7.2'
        { New-CidataNetworkConfig -Egress $far } | Should -Throw "New-CidataUserData: the egress plan's gateway * and guest 192.168.7.2 are not two addresses in one /30. Fail closed."
        $empty = $script:HPProfile.Clone(); $empty['EgressAllowlist'] = @()
        { New-CidataUserData -Profile $empty -Egress $script:HPPlan } | Should -Throw 'New-CidataUserData: a Serial+HostProxy profile must have a non-empty EgressAllowlist (fail-closed).'
    }

    It 'a Disk-mode Tier-1 HostProxy profile gets the proxy settings and the same lockdown block (the Disk runners learned the proxy)' {
        $disk = $script:HPProfile.Clone(); $disk['WorkloadMode'] = 'Disk'; $disk['OutboxOutput'] = $true; $disk['Entrypoint'] = 'python3 /mnt/in/x.py --out /run/staging/result.html'
        $ud = New-CidataUserData -Profile $disk -Egress $script:HPPlan
        $ud | Should -Match ([regex]::Escape("https_proxy=$($script:HPProxy)"))
        (script:Get-HPSeedFile $ud '/usr/local/sbin/voidseal-egress-lockdown') | Should -Be (script:Get-HPSeedFile $script:HPUd '/usr/local/sbin/voidseal-egress-lockdown')
    }

    It 'a Tier-0 HostProxy profile (sealed with no adapter) keeps the offline seed' {
        $t0 = @{ Tier = 0; Name = 't0'; WorkloadMode = 'Serial'; Network = 'HostProxyAllowlist'; EgressMode = 'HostProxy'; EgressAllowlist = @() }
        New-CidataUserData -Profile $t0 | Should -Not -Match 'HTTPS_PROXY|voidseal-egress'
        $disk0 = $script:DiskProfile.Clone(); $disk0['EgressMode'] = 'HostProxy'
        New-CidataUserData -Profile $disk0 | Should -Not -Match 'HTTPS_PROXY'
    }
}

# ===========================================================================
#  Disk + HostProxy: the Disk runners learn the proxy (a kept NIC in Disk mode)
# ===========================================================================
Describe 'New-CidataUserData - Disk + HostProxy: the outbox and exFAT runners carry the proxy settings and the lockdown' {

    BeforeAll {
        $script:DhPlan   = Get-EgressAddressPlan -VMName 'sbx-dh' -SwitchName 'sbx-dh-int'
        $script:DhProxy  = "http://$($script:DhPlan.GatewayIP):13128"
        $script:DhOutbox = @{ Tier = 1; Name = 'hp-disk'; Network = 'Internal+Allowlist'; EgressMode = 'HostProxy'; WorkloadMode = 'Disk'; OutboxOutput = $true
                              EgressAllowlist = @('api.example.com'); Entrypoint = 'python3 /mnt/in/work.py --out /run/staging/result.html' }
        $script:DhExfat  = @{ Tier = 1; Name = 'hp-exfat'; Network = 'Internal+Allowlist'; EgressMode = 'HostProxy'; WorkloadMode = 'Disk'
                              EgressAllowlist = @('api.example.com'); Entrypoint = 'python3 /mnt/in/work.py --out /mnt/out/result.html' }
        $script:DhOutboxUd = New-CidataUserData -Profile $script:DhOutbox -Egress $script:DhPlan
        $script:DhExfatUd  = New-CidataUserData -Profile $script:DhExfat  -Egress $script:DhPlan
        $script:DhSerialUd = New-CidataUserData -Profile @{ Tier = 1; WorkloadMode = 'Serial'; Network = 'Internal+Allowlist'; EgressMode = 'HostProxy'; EgressAllowlist = @('api.example.com'); Entrypoint = 'bash run.sh' } -Egress $script:DhPlan

        function script:Get-DhSeedFile {
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
        function script:Get-DhRunCmd {
            param([string] $UserData)
            $lines = $UserData -split "`n"
            $at = [array]::IndexOf($lines, 'runcmd:')
            $out = [System.Collections.Generic.List[string]]::new()
            for ($i = $at + 1; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^  - ') { $out.Add($lines[$i].Trim()) } elseif ($lines[$i] -match '^\S') { break }
            }
            return @($out)
        }
        $script:DhPosixSh = $null
        if ($IsWindows) {
            foreach ($git in @(Get-Command git -CommandType Application -All -ErrorAction SilentlyContinue)) {
                $dir = Split-Path -Parent $git.Source
                for ($up = 0; $up -lt 3 -and -not $script:DhPosixSh -and $dir; $up++) {
                    $dir = Split-Path -Parent $dir
                    foreach ($c in 'usr\bin\dash.exe', 'usr\bin\sh.exe') {
                        $cand = Join-Path $dir $c
                        if (Test-Path -LiteralPath $cand) { $script:DhPosixSh = $cand; break }
                    }
                }
                if ($script:DhPosixSh) { break }
            }
        }
        else {
            $sh = Get-Command dash, sh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sh) { $script:DhPosixSh = $sh.Source }
        }
    }

    It '<Runner>: the network stays enabled, every token is substituted, and the proxy settings, apt setting and lockdown files are written' -ForEach @(
        @{ Runner = 'outbox'; Var = 'DhOutboxUd' }, @{ Runner = 'exFAT'; Var = 'DhExfatUd' }
    ) {
        $ud = Get-Variable -Scope Script -Name $Var -ValueOnly
        $ud | Should -Not -Match '__[A-Z_]+__' -Because 'an unsubstituted token would ship a broken seed'
        $ud | Should -Not -Match 'network: \{config: disabled\}' -Because 'the VM keeps its NIC; the seed network-config gives it its static address'
        $ud | Should -Match '(?m)^# network: applied from the seed network-config'
        foreach ($p in '/etc/environment', '/etc/profile.d/voidseal-egress-proxy.sh', '/etc/apt/apt.conf.d/99voidseal-proxy',
                       '/etc/sysctl.d/99-voidseal-noipv6.conf', '/usr/local/sbin/voidseal-egress-lockdown', '/etc/systemd/system/voidseal-egress.service') {
            $ud | Should -BeLike "*- path: $p*" -Because "the seed must write $p"
        }
        $env = script:Get-DhSeedFile $ud '/etc/environment'
        @($env -split "`n") | Should -Be @("http_proxy=$($script:DhProxy)", "https_proxy=$($script:DhProxy)", "HTTP_PROXY=$($script:DhProxy)", "HTTPS_PROXY=$($script:DhProxy)", 'no_proxy=localhost,127.0.0.1', 'NO_PROXY=localhost,127.0.0.1')
        $ud | Should -Match '(?m)^    append: true$' -Because '/etc/environment is appended to, not replaced'
        $apt = script:Get-DhSeedFile $ud '/etc/apt/apt.conf.d/99voidseal-proxy'
        $apt | Should -Match ([regex]::Escape("Acquire::http::Proxy `"$($script:DhProxy)/`";"))
        $apt | Should -Match ([regex]::Escape("Acquire::https::Proxy `"$($script:DhProxy)/`";"))
    }

    It '<Runner>: bootcmd disables IPv6 and moves the Debian sources to https, the package stage installs nftables, and runcmd applies the lockdown before the workload unit starts' -ForEach @(
        @{ Runner = 'outbox'; Var = 'DhOutboxUd' }, @{ Runner = 'exFAT'; Var = 'DhExfatUd' }
    ) {
        $ud = Get-Variable -Scope Script -Name $Var -ValueOnly
        $ud | Should -Match "(?m)^  - \[ sysctl, -w, 'net\.ipv6\.conf\.all\.disable_ipv6=1' \]"
        $ud | Should -Match 'http://deb\.debian\.org#https://deb\.debian\.org'
        $ud | Should -Match "(?m)^packages:\n  - nftables"
        $cmds   = script:Get-DhRunCmd $ud
        $iLock  = [array]::IndexOf($cmds, '- [ systemctl, enable, --now, voidseal-egress.service ]')
        $iStart = [array]::IndexOf($cmds, '- [ systemctl, start, --no-block, vmdep-workload.service ]')
        $iLock  | Should -BeGreaterOrEqual 0
        $iStart | Should -BeGreaterThan $iLock -Because 'the lockdown is in place before the workload runs'
        $ud | Should -Match 'Before=network-pre\.target' -Because 'the unit re-applies the lockdown on any later boot'
    }

    It 'the lockdown is the one shared block: identical in the outbox, exFAT and Serial HostProxy seeds, nft first with an iptables fallback, no DNS or direct web egress' {
        $a = script:Get-DhSeedFile $script:DhOutboxUd '/usr/local/sbin/voidseal-egress-lockdown'
        $b = script:Get-DhSeedFile $script:DhExfatUd  '/usr/local/sbin/voidseal-egress-lockdown'
        $c = script:Get-DhSeedFile $script:DhSerialUd '/usr/local/sbin/voidseal-egress-lockdown'
        $a | Should -Be $b
        $a | Should -Be $c
        $a | Should -Match 'policy drop;'
        $a | Should -Match ([regex]::Escape("ip daddr $($script:DhPlan.GatewayIP) tcp dport 13128 accept"))
        $a | Should -Match ([regex]::Escape("iptables -A OUTPUT -p tcp -d $($script:DhPlan.GatewayIP) --dport 13128 -j ACCEPT"))
        $a | Should -Match 'iptables -P OUTPUT DROP'
        $a | Should -Not -Match 'dport 53|dport 80\b|dport 443|REDIRECT' -Because 'no DNS and no direct web egress in HostProxy mode'
    }

    It 'the outbox runner exports the proxy before the entrypoint and narrates the egress facts; the exFAT runner (no diag) exports it alone' {
        $runner = script:Get-DhSeedFile $script:DhOutboxUd '/usr/local/sbin/vmdep-workload'
        $lines  = $runner -split "`n"
        $export = [array]::IndexOf($lines, '. /etc/profile.d/voidseal-egress-proxy.sh')
        $run    = @(0..($lines.Count - 1) | Where-Object { $lines[$_] -like "*runuser -u sandbox -- /bin/sh -c '*" })[0]
        $export | Should -BeGreaterThan 0
        $export | Should -BeLessThan $run -Because 'the entrypoint inherits the environment the runner exports'
        foreach ($m in 'egress_mode=hostproxy', 'proxy_reachable=', 'egress_unit_enabled=', 'nft_present=', 'ipv6_disabled=', 'default_routes=', 'nameservers=') {
            $runner | Should -BeLike "*$m*" -Because "a live run must be able to attribute a failed fetch from $m"
        }
        $ex = script:Get-DhSeedFile $script:DhExfatUd '/usr/local/sbin/vmdep-workload'
        $ex | Should -Match '(?m)^\. /etc/profile\.d/voidseal-egress-proxy\.sh$'
        $ex | Should -Not -Match 'diag' -Because 'the exFAT runner defines no diag()'
    }

    It 'the <Which> runner and the lockdown script parse as POSIX sh (sh -n)' -ForEach @(
        @{ Which = 'outbox'; Var = 'DhOutboxUd' }, @{ Which = 'exFAT'; Var = 'DhExfatUd' }
    ) {
        if (-not $script:DhPosixSh) { Set-ItResult -Skipped -Because 'no POSIX sh (dash) available on this host'; return }
        $ud = Get-Variable -Scope Script -Name $Var -ValueOnly
        foreach ($path in '/usr/local/sbin/vmdep-workload', '/usr/local/sbin/voidseal-egress-lockdown') {
            $f = Join-Path $TestDrive ("dh-$Which-" + (Split-Path -Leaf $path) + '.sh')
            [System.IO.File]::WriteAllText($f, (script:Get-DhSeedFile $ud $path) + "`n", [System.Text.UTF8Encoding]::new($false))
            $out = & $script:DhPosixSh -n $f 2>&1
            $LASTEXITCODE | Should -Be 0 -Because "sh -n on $path reported: $out"
        }
    }

    It 'the user-data parses as YAML with the proxy files, the package stage and the bootcmd (when PyYAML is available)' {
        $py = $null
        try { $py = Resolve-PythonExe } catch { $py = $null }
        if (-not $py) { Set-ItResult -Skipped -Because 'no host Python'; return }
        & $py -c 'import yaml' 2>$null
        if ($LASTEXITCODE -ne 0) { Set-ItResult -Skipped -Because 'PyYAML is not installed'; return }
        foreach ($doc in @(@{ Name = 'outbox'; Text = $script:DhOutboxUd }, @{ Name = 'exfat'; Text = $script:DhExfatUd })) {
            $f = Join-Path $TestDrive "dh-$($doc.Name).yaml"
            [System.IO.File]::WriteAllText($f, $doc.Text, [System.Text.UTF8Encoding]::new($false))
            $out = & $py -c 'import sys,yaml,json; print(json.dumps(yaml.safe_load(open(sys.argv[1],encoding="utf-8"))))' $f 2>&1
            $LASTEXITCODE | Should -Be 0 -Because "YAML parse of $($doc.Name) reported: $out"
            $parsed = ($out | Out-String) | ConvertFrom-Json
            @($parsed.packages) | Should -Be @('nftables')
            @($parsed.bootcmd).Count | Should -Be 4 -Because 'the wait-online mask, two sysctl entries and the sources move'
            @($parsed.write_files | ForEach-Object { $_.path }) | Should -Contain '/etc/profile.d/voidseal-egress-proxy.sh'
            $parsed.PSObject.Properties.Name | Should -Not -Contain 'network'
        }
    }

    It 'FAILS CLOSED without a plan or with an empty allowlist' {
        { New-CidataUserData -Profile $script:DhOutbox } | Should -Throw "New-CidataUserData: a HostProxy seed (a VM that keeps its NIC) needs the VM's egress address plan (-Egress, from the descriptor); none was given. Fail closed."
        $empty = $script:DhOutbox.Clone(); $empty['EgressAllowlist'] = @()
        { New-CidataUserData -Profile $empty -Egress $script:DhPlan } | Should -Throw 'New-CidataUserData: a Disk+HostProxy profile must have a non-empty EgressAllowlist (fail-closed).'
    }

    It 'a Disk profile with no NIC keeps the offline seed: network disabled, every token a comment, no proxy or lockdown content' {
        $noNic = @(
            @{ Tier = 0; WorkloadMode = 'Disk'; OutboxOutput = $true; EgressMode = 'HostProxy'; Entrypoint = 'python3 /mnt/in/x.py --out /run/staging/result.html' }
            @{ Tier = 1; Network = 'None'; EgressMode = 'None'; WorkloadMode = 'Disk'; ScreenConfig = @{ mode = 'aggressive' }; Entrypoint = 'python3 /mnt/in/x.py --out /run/staging/result.html' }
            @{ Tier = 0; WorkloadMode = 'Disk'; Entrypoint = 'python3 /mnt/in/x.py --out /mnt/out/result.html' }
        )
        foreach ($p in $noNic) {
            $ud = New-CidataUserData -Profile $p
            $ud | Should -Match 'network: \{config: disabled\}'
            $ud | Should -Not -Match '__[A-Z_]+__'
            $ud | Should -Not -Match 'HTTPS_PROXY|voidseal-egress|nftables|disable_ipv6'
            $ud | Should -Match '\(no network adapter' -Because 'each HostProxy token resolves to a comment that says why nothing is there'
        }
    }
}
