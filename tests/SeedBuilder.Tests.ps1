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

    It 'RC4: INPUT mount also has a plain-mount fallback' {
        New-CidataUserData -Profile $script:DiskProfile | Should -BeLike '*|| mount LABEL=INPUT*' -Because 'RC4: the read-only INPUT mount must also fall back to a plain mount'
    }

    It 'RC3: masks systemd-networkd-wait-online (network is disabled — the ~47s wait is dead time)' {
        $ud = New-CidataUserData -Profile $script:DiskProfile
        $ud | Should -BeLike '*systemd-networkd-wait-online*' -Because 'RC3: the runner must reference the wait-online service to disable/mask it'
        $ud | Should -Match '(?i)mask' -Because 'RC3: the boot delay is removed by masking systemd-networkd-wait-online.service'
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
        $outputLines  = $ud -split "`r?`n"
        $acceptRules  = $outputLines | Where-Object { $_ -match '^\s*iptables\s+-A\s+OUTPUT\b.*-j\s+ACCEPT\s*$' } | ForEach-Object { $_.Trim() }

        $acceptRules.Count | Should -Be 6 -Because 'the builder OUTPUT allow-list must contain EXACTLY the 6 intended rules (lo, established/related, dns udp/tcp, http, https) — any extra ACCEPT rule (a 7th rule, a widened/renamed port, a multiport rule) must fail this test even if it does not match the literal strings "udp --dport 443" or "dport 853"'

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
        ($outputLines | Where-Object { $_ -match 'iptables\s+-A\s+OUTPUT' -and $_ -match '-j\s+ACCEPT' -and $_ -match 'udp' -and $_ -match '443' }) |
            Should -BeNullOrEmpty -Because 'no OUTPUT ACCEPT rule may combine udp with port 443 (QUIC/HTTP-3), in any spelling (plain --dport or -m multiport --dports)'

        # The transparent-proxy REDIRECTs still gatekeep 80/443 to Squid.
        $ud | Should -Match 'REDIRECT --to-port 3129'
        $ud | Should -Match 'REDIRECT --to-port 3130'
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
