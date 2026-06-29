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
