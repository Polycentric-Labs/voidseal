#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for the two v1 workload profiles:
    profiles/ralph.psd1 (Tier 1) + profiles/firefox.psd1 (Tier 0).

.DESCRIPTION
    Contract under test: both shipped workload profiles MUST load cleanly through the
    REAL loader (Import-WorkloadProfile, resolving against tier-profiles/), merge to the
    expected shape, and survive every loader invariant — in particular:
      * Ralph's Claude OAuth token mount must NOT trip the secret-file refusal (invariant 1).
        The token is delivered as a `.token` FILE in a non-secret-shaped path (a one-time
        file-to-file copy of the real credentials), mounted read-only — modeled so it passes.
      * Firefox stays Tier-0 / offline (empty merged allowlist) and never mounts a secret-
        shaped source (and, per the DATA-ACCESS rule, defaults to a SAMPLE profile copy).
    Also pins the negative guard: the live `~/.claude/.credentials.json` path WOULD be
    refused (it matches `.credentials.json`), which is exactly why the profile references
    a copied `.token` file instead — locking the documented pattern as a regression guard.
#>

BeforeAll {
    $script:SkillRoot   = Split-Path -Parent $PSScriptRoot
    $script:LibPath     = Join-Path $script:SkillRoot 'scripts/lib/ProfileLoader.ps1'
    $script:TierDir     = Join-Path $script:SkillRoot 'tier-profiles'
    $script:ProfileDir  = Join-Path $script:SkillRoot 'profiles'
    $script:RalphPath   = Join-Path $script:ProfileDir 'ralph.psd1'
    $script:FirefoxPath = Join-Path $script:ProfileDir 'firefox.psd1'
    $script:SkeletonPath = Join-Path $script:ProfileDir 'example-skeleton.psd1'

    Test-Path $script:LibPath     | Should -BeTrue -Because 'the loader must exist to test profiles through it'
    Test-Path $script:RalphPath   | Should -BeTrue -Because 'the ralph profile must exist'
    Test-Path $script:FirefoxPath | Should -BeTrue -Because 'the firefox profile must exist'
    Test-Path $script:SkeletonPath | Should -BeTrue -Because 'the onboarding skeleton profile must exist'
    . $script:LibPath
}

Describe 'profiles/ralph.psd1 — loads + merges through Import-WorkloadProfile (Tier 1)' {

    BeforeAll {
        $script:Ralph = Import-WorkloadProfile -Path $script:RalphPath -TierProfileDir $script:TierDir
    }

    It 'loads without throwing and is a hashtable' {
        $script:Ralph | Should -Not -BeNullOrEmpty
        $script:Ralph | Should -BeOfType [System.Collections.IDictionary]
    }

    It 'resolves to BaseTier 1 (the merged Tier is 1, HyperV-Gen2)' {
        $script:Ralph.Tier      | Should -Be 1
        $script:Ralph.BaseTier  | Should -Be 1
        $script:Ralph.Substrate | Should -Be 'HyperV-Gen2'
        $script:Ralph.Name      | Should -Be 'ralph'
    }

    It 'has the verified bash entrypoint (bash ralph_loop.sh, NOT npm / a binary)' {
        $script:Ralph.Entrypoint | Should -Match 'bash\b'
        $script:Ralph.Entrypoint | Should -Match 'ralph_loop\.sh'
        $script:Ralph.Entrypoint | Should -Not -Match 'npm'
    }

    It 'inherits the Linux Com1Serial management channel from tier1' {
        $script:Ralph.ManagementChannel | Should -Be 'Com1Serial'
    }

    It 'stages git + jq + the claude CLI prereqs for the loop' {
        @($script:Ralph.Packages) | Should -Contain 'git'
        @($script:Ralph.Packages) | Should -Contain 'jq'
        # the claude CLI prerequisite is declared (>= 2.0.76)
        @($script:Ralph.Packages) -join ',' | Should -Match 'claude'
    }

    It 'unions ExtraAllowlist onto tier1 and keeps api.anthropic.com (the loop calls cloud Claude)' {
        @($script:Ralph.EgressAllowlist) | Should -Contain 'api.anthropic.com'   # inherited from tier1
        @($script:Ralph.EgressAllowlist) | Should -Contain 'github.com'          # inherited from tier1 (clone)
        @($script:Ralph.EgressAllowlist).Count | Should -BeGreaterThan 8 -Because 'tier1 has 8 FQDNs; ralph adds install-time origins'
    }

    It 'pins the upstream by COMMIT SHA in StageAssets (Ralph has NO tags)' {
        $script:Ralph.ContainsKey('StageAssets') | Should -BeTrue
        $stageText = (@($script:Ralph.StageAssets.Values) -join ' ')
        $stageText | Should -Match '(?i)sha'  -Because 'Ralph has no tags -> the pin must be a commit SHA'
        $stageText | Should -Match 'frankbria/ralph-claude-code'
    }

    # ----- THE KEY ASSERTION: the OAuth token mount is ALLOWED (not secret-refused) -----
    It 'declares the Claude OAuth token as a read-only FILE mount that PASSES the secret-file refusal' {
        $script:Ralph.ContainsKey('Mounts') | Should -BeTrue
        $tokenKey = @($script:Ralph.Mounts.Keys) | Where-Object { $_ -match '\.token$' }
        $tokenKey | Should -Not -BeNullOrEmpty -Because 'the token is delivered as a .token FILE (read-only bind-mount)'
        # The source path must NOT be secret-shaped (that is the whole point — a .token leaf
        # in a non-.secrets dir slips neither the leaf globs nor the dir rules).
        Test-IsSecretPath -Path ([string]$tokenKey) | Should -BeFalse -Because 'a token FILE in a non-secret-shaped path is an allowed mount'
        # And it is mounted read-only (':ro' documents the intent on the guest target).
        [string]$script:Ralph.Mounts[$tokenKey] | Should -Match ':ro' -Because 'the token must be mounted READ-ONLY'
    }

    It 'embeds NO secret VALUE anywhere in the profile (only a token FILE PATH, never a token)' {
        $raw = Get-Content -LiteralPath $script:RalphPath -Raw
        # No bearer/sk-/oauth-token-shaped literals. (The word "token" as prose is fine; an
        # actual token value would look like sk-ant-... / a long base64-ish secret.)
        $raw | Should -Not -Match 'sk-ant-'           -Because 'no Anthropic key literal may be embedded'
        $raw | Should -Not -Match 'Bearer\s+[A-Za-z0-9]' -Because 'no Bearer token literal may be embedded'
    }
}

Describe 'profiles/firefox.psd1 — loads + merges through Import-WorkloadProfile (Tier 0)' {

    BeforeAll {
        $script:Firefox = Import-WorkloadProfile -Path $script:FirefoxPath -TierProfileDir $script:TierDir
    }

    It 'loads without throwing and is a hashtable' {
        $script:Firefox | Should -Not -BeNullOrEmpty
        $script:Firefox | Should -BeOfType [System.Collections.IDictionary]
    }

    It 'resolves to BaseTier 0 (Container, the lightweight tier)' {
        $script:Firefox.Tier      | Should -Be 0
        $script:Firefox.BaseTier  | Should -Be 0
        $script:Firefox.Substrate | Should -Be 'Container'
        $script:Firefox.Name      | Should -Be 'firefox'
    }

    It 'stays OFFLINE: the merged EgressAllowlist is empty (Tier-0 default, zero egress-proxy dependency)' {
        @($script:Firefox.EgressAllowlist).Count | Should -Be 0 -Because 'the organizer needs no network; the dead-link check escalates to Tier 1 instead'
    }

    It 'is a Disk-mode profile whose entrypoint matches the engine contract (/mnt/in -> /mnt/out/result.html)' {
        # Disk model: inputs ride the INPUT disk (guest /mnt/in), the result lands on the OUTPUT
        # disk at the engine default inner-name result.html (Read-WorkloadResult -ResultInnerName).
        # The OLD serial/container-era form (/opt/organizer + /mnt/firefox-profile + bookmarks.html)
        # is superseded — asserting result.html here keeps profile + runner + engine consistent.
        $script:Firefox.WorkloadMode | Should -Be 'Disk' -Because 'firefox runs via the disk-passing model'
        $script:Firefox.Entrypoint   | Should -Match 'organize'
        $script:Firefox.Entrypoint   | Should -Match '/mnt/in'  -Because 'inputs arrive on the INPUT disk mounted at /mnt/in'
        $script:Firefox.Entrypoint   | Should -Match '/mnt/out/result\.html' -Because 'the result inner-name MUST be result.html (the engine default)'
        $script:Firefox.Entrypoint   | Should -Not -Match 'bookmarks\.html' -Because 'bookmarks.html was the serial/container-era inner name; the engine default is result.html'
    }

    It 'extraction is the trusting Tier-0/1 host-read (HostReadResultDir, not the cold-VHDX sink)' {
        $script:Firefox.Extraction | Should -Be 'HostReadResultDir'
    }

    It 'never mounts a credential/session store and mounts no secret-shaped source' {
        @($script:Firefox.Mounts.Keys) | ForEach-Object {
            Test-IsSecretPath -Path ([string]$_) | Should -BeFalse -Because "mount source '$_' must not be secret-shaped"
            # Belt-and-braces: it must not mount the named credential/session stores.
            [string]$_ | Should -Not -Match '(?i)(logins\.json|key4\.db|cookies\.sqlite)'
        }
    }

    It 'documents the SYNTHETIC-data default + the per-task authorization gate (DATA-ACCESS rule)' {
        $raw = Get-Content -LiteralPath $script:FirefoxPath -Raw
        $raw | Should -Match '(?i)synthetic'  -Because 'the profile must state synthetic/sample data is the default'
        $raw | Should -Match '(?i)(per-task|authoriz)' -Because 'reading real profile data must require explicit per-task authorization'
    }

    # ----- C1.4: firefox opts into the user-space outbox transport (Raw OUTPUT, no host Mount-VHD) -----
    It 'opts into OutboxOutput=$true (Raw OUTPUT + user-space outbox read, C1.1/C1.2 transport path)' {
        $script:Firefox.ContainsKey('OutboxOutput') | Should -BeTrue -Because 'firefox converges onto the shared outbox transport (C1.4)'
        $script:Firefox.OutboxOutput | Should -BeTrue
    }

    It 'regression: OutboxOutput does not disturb WorkloadMode/Tier/Network/EgressAllowlist' {
        $script:Firefox.WorkloadMode | Should -Be 'Disk' -Because 'C1.4 is transport-only; the disk-passing model is unchanged'
        $script:Firefox.Tier         | Should -Be 0
        $script:Firefox.BaseTier     | Should -Be 0
        @($script:Firefox.EgressAllowlist).Count | Should -Be 0 -Because 'firefox stays offline; OutboxOutput is a transport change, not a network change'
    }

    It 'is transport-only: NOT a processor (no ScreenConfig, Network unforced to None)' {
        $script:Firefox.ContainsKey('ScreenConfig') | Should -BeFalse -Because 'firefox is transport-only (LOCKED design) — never screened, so it must not carry a processor ScreenConfig'
    }

    It 'delivers run_disk_workload.py (the shared outbox producer) + its outbox.py dependency via the INPUT disk' {
        # C1.3 handoff: run_disk_workload.py is the shared in-guest outbox-producer template, delivered
        # the SAME way as organize_bookmarks.py — via InputFiles (raw .psd1 doc-only metadata; the
        # live-acceptance step folds these host paths into Inputs before deploy — see the InputFiles
        # header comment in firefox.psd1 and Invoke-Voidseal.ps1's processor-gate wiring). It imports outbox.py from its
        # own directory (sys.path.insert(0, HERE)), so outbox.py must ride alongside it on the INPUT disk too.
        $raw = Import-PowerShellDataFile -LiteralPath $script:FirefoxPath
        $raw.InputFiles.ContainsKey('run_disk_workload.py') | Should -BeTrue -Because 'the seed runner invokes python3 /mnt/in/run_disk_workload.py (SeedBuilder.ps1 CidataOutboxDiskRunnerTemplate)'
        $raw.InputFiles.ContainsKey('outbox.py') | Should -BeTrue -Because 'run_disk_workload.py imports outbox from its own directory — it must ride the INPUT disk alongside it'
        [string]$raw.InputFiles['run_disk_workload.py'] | Should -Match '(?i)run_disk_workload\.py$'
        [string]$raw.InputFiles['outbox.py'] | Should -Match '(?i)outbox\.py$'
    }
}

Describe 'profiles/example-skeleton.psd1 — the onboarding skeleton loads clean (docs/authoring-a-workload-profile.md)' {

    BeforeAll {
        $script:Skeleton = Import-WorkloadProfile -Path $script:SkeletonPath -TierProfileDir $script:TierDir
    }

    It 'loads without throwing and is a hashtable' {
        $script:Skeleton | Should -Not -BeNullOrEmpty
        $script:Skeleton | Should -BeOfType [System.Collections.IDictionary]
    }

    It 'resolves to BaseTier 0 (Container, the lightweight/offline tier)' {
        $script:Skeleton.Tier      | Should -Be 0
        $script:Skeleton.BaseTier  | Should -Be 0
        $script:Skeleton.Substrate | Should -Be 'Container'
        $script:Skeleton.Name      | Should -Be 'example-skeleton'
    }

    It 'stays OFFLINE: the merged EgressAllowlist is empty (no ExtraAllowlist declared beyond @())' {
        @($script:Skeleton.EgressAllowlist).Count | Should -Be 0 -Because 'the skeleton is a minimal offline example — no network by default'
    }

    It 'is a Serial-mode profile (WorkloadMode omitted -> not layered onto the merge)' {
        $script:Skeleton.ContainsKey('WorkloadMode') | Should -BeFalse -Because 'the skeleton omits WorkloadMode, so it inherits the engine default (Serial)'
    }

    It 'declares no secret-shaped Mounts source' {
        @($script:Skeleton.Mounts.Keys) | ForEach-Object {
            Test-IsSecretPath -Path ([string]$_) | Should -BeFalse -Because "mount source '$_' must not be secret-shaped"
        }
    }

    It 'is heavily commented with copy-editor EDIT markers' {
        $raw = Get-Content -LiteralPath $script:SkeletonPath -Raw
        (Select-String -InputObject $raw -Pattern '<-- EDIT' -AllMatches).Matches.Count | Should -BeGreaterThan 3 -Because 'every field a newcomer edits should carry an EDIT marker'
    }
}

Describe 'Negative guard — the live credentials path WOULD be refused (why we copy to a .token)' {

    It 'rejects mounting the live ~/.claude/.credentials.json directly (invariant 1)' {
        # This pins the reason the ralph profile copies the token to a .token file: the live
        # credentials store IS secret-shaped (.credentials.json) and the loader refuses it.
        Test-IsSecretPath -Path 'C:\Users\testuser\.claude\.credentials.json' |
            Should -BeTrue -Because '.credentials.json is on the secret-refusal list — mount a copied .token instead'
    }

    It 'a workload that mounts the live credentials file fails Import-WorkloadProfile' {
        $evil = @{
            BaseTier   = 1
            Name       = 'evil-token-mount'
            Entrypoint = 'bash ralph_loop.sh'
            Mounts     = @{ 'C:\Users\testuser\.claude\.credentials.json' = '/home/sandbox/.claude/.credentials.json:ro' }
        }
        $tmp = Join-Path $TestDrive 'evil-token-mount.psd1'
        # Render the fixture .psd1 (single-quote the path key so it parses).
        $body = @(
            '@{'
            "    BaseTier   = 1"
            "    Name       = 'evil-token-mount'"
            "    Entrypoint = 'bash ralph_loop.sh'"
            "    Mounts     = @{ 'C:\Users\testuser\.claude\.credentials.json' = '/home/sandbox/.claude/.credentials.json:ro' }"
            '}'
        ) -join [Environment]::NewLine
        Set-Content -LiteralPath $tmp -Value $body -Encoding UTF8
        { Import-WorkloadProfile -Path $tmp -TierProfileDir $script:TierDir } |
            Should -Throw -ExpectedMessage '*secret*'
    }
}
