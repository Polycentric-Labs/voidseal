#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for scripts/lib/ProfileLoader.ps1 (the tier/workload profile loader).

    Contract under test: tier-profiles/SCHEMA.md (the build contract) +
    the two real example profiles tier0.psd1 / tier1.psd1 which MUST load clean.

    TDD: these are written first; they drive the loader implementation.
    Violating fixtures are written to $TestDrive (never committed to tier-profiles/).
#>

BeforeAll {
    # Resolve the skill root from this test file's location: <root>/tests/ -> <root>
    $script:SkillRoot   = Split-Path -Parent $PSScriptRoot
    $script:LibPath     = Join-Path $script:SkillRoot 'scripts/lib/ProfileLoader.ps1'
    $script:TierDir     = Join-Path $script:SkillRoot 'tier-profiles'
    $script:Tier0Path   = Join-Path $script:TierDir 'tier0.psd1'
    $script:Tier1Path   = Join-Path $script:TierDir 'tier1.psd1'

    Test-Path $script:LibPath | Should -BeTrue -Because 'the loader script must exist to be tested'
    . $script:LibPath

    # --- helpers ----------------------------------------------------------

    # Render a hashtable literal into .psd1 text. Supports nested hashtables,
    # arrays, ints, bools, and strings. Good enough for fixtures.
    function script:ConvertTo-Psd1Text {
        param([Parameter(Mandatory)] $Value, [int] $Indent = 0)
        $pad = '    ' * $Indent
        if ($Value -is [System.Collections.IDictionary]) {
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine('@{')
            foreach ($k in $Value.Keys) {
                $inner = script:ConvertTo-Psd1Text -Value $Value[$k] -Indent ($Indent + 1)
                # Keys that are not bare identifiers (e.g. Windows/POSIX paths used
                # as Mounts sources) must be single-quoted so Import-PowerShellDataFile
                # parses them. A bare key like `C:\proj\.env` is a parse error otherwise.
                $keyText = if ($k -match '^[A-Za-z_][A-Za-z0-9_]*$') { "$k" }
                           else { "'" + ([string]$k -replace "'", "''") + "'" }
                [void]$sb.AppendLine(('    ' * ($Indent + 1)) + "$keyText = $inner")
            }
            [void]$sb.Append($pad + '}')
            return $sb.ToString()
        }
        elseif ($Value -is [bool]) {
            return $(if ($Value) { '$true' } else { '$false' })
        }
        elseif ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
            return "$Value"
        }
        elseif ($Value -is [string]) {
            return "'" + ($Value -replace "'", "''") + "'"
        }
        elseif ($Value -is [System.Collections.IEnumerable]) {
            $items = @($Value | ForEach-Object { script:ConvertTo-Psd1Text -Value $_ -Indent 0 })
            if ($items.Count -eq 0) { return '@()' }
            return '@(' + ($items -join ', ') + ')'
        }
        else {
            return "'" + [string]$Value + "'"
        }
    }

    function script:New-Psd1File {
        param([Parameter(Mandatory)] [hashtable] $Data, [string] $Name)
        if (-not $Name) { $Name = [System.IO.Path]::GetRandomFileName().Replace('.', '') + '.psd1' }
        $path = Join-Path $TestDrive $Name
        $text = script:ConvertTo-Psd1Text -Value $Data
        Set-Content -LiteralPath $path -Value $text -Encoding UTF8
        return $path
    }

    # A known-good Tier-1 (HyperV) hashtable we can mutate per fixture.
    function script:Get-ValidTier1Hashtable {
        return @{
            Tier               = 1
            Description        = 'fixture tier 1'
            Substrate          = 'HyperV-Gen2'
            Network            = 'Internal+Allowlist'
            EgressMode         = 'NftablesAllowlist'
            EgressAllowlist    = @('api.anthropic.com', 'github.com')
            BlockProtocols     = @('QUIC')
            Credentials        = 'ScopedOnDemand'
            GuestImage         = 'debian-12-cloud'
            SecureBootTemplate = 'MicrosoftUEFICertificateAuthority'
            Memory             = '4GB'
            Cpu                = 4
            NestedVirt         = $false
            ManagementChannel  = 'Com1Serial'
            HostChannels       = @{ Clipboard = $false; Shares = $false; GuestServices = $false; EnhancedSession = $false }
            Capture            = @{ Mode = 'HostSide+ProxyLog'; Otlp = $true }
            Extraction         = 'HostReadResultDir'
            Lifecycle          = 'SnapshotRevert'
            Controls           = @('NonRoot', 'SecretFileExclusion')
        }
    }

    # A known-good Tier-2 (HyperV, starved) hashtable.
    function script:Get-ValidTier2Hashtable {
        return @{
            Tier              = 2
            Description       = 'fixture tier 2 (starved)'
            Substrate         = 'HyperV-Gen2'
            Network           = 'Isolated'
            EgressMode        = 'None'
            EgressAllowlist   = @()
            Credentials       = 'None'
            GuestImage        = 'debian-12-cloud'
            Memory            = '4GB'
            Cpu               = 4
            ManagementChannel = 'Com1Serial'
            HostChannels      = @{ Clipboard = $false; Shares = $false; GuestServices = $false; EnhancedSession = $false }
            Capture           = @{ Mode = 'HostSide'; Otlp = $true }
            Extraction        = 'ColdVHDX-Quarantine-CDR'
            Lifecycle         = 'CreateDestroy'
            Controls          = @('NonRoot')
        }
    }
}

Describe 'Import-TierProfile — real example profiles' {

    It 'loads tier0.psd1 without error and returns the expected normalized shape' {
        $p = Import-TierProfile -Path $script:Tier0Path
        $p                     | Should -Not -BeNullOrEmpty
        $p.Tier                | Should -Be 0
        $p.Substrate           | Should -Be 'Container'
        $p.EgressMode          | Should -Be 'HostProxy'
        $p.Credentials         | Should -Be 'None'
        # empty allowlist normalizes to an array (count 0), never $null
        @($p.EgressAllowlist).Count | Should -Be 0
        $p.HostChannels        | Should -BeOfType [System.Collections.IDictionary]
        $p.HostChannels.Shares | Should -Be 'ReadOnlyInput'   # string on a container tier is allowed
        $p.ContainsKey('ManagementChannel') | Should -BeFalse # container tier has no mgmt channel
    }

    It 'loads tier1.psd1 without error and returns the expected normalized shape' {
        $p = Import-TierProfile -Path $script:Tier1Path
        $p                       | Should -Not -BeNullOrEmpty
        $p.Tier                  | Should -Be 1
        $p.Substrate             | Should -Be 'HyperV-Gen2'
        $p.EgressMode            | Should -Be 'NftablesAllowlist'
        $p.ManagementChannel     | Should -Be 'Com1Serial'
        @($p.EgressAllowlist)    | Should -Contain 'api.anthropic.com'
        @($p.EgressAllowlist).Count | Should -BeGreaterThan 1
        # all HostChannels booleans are $false on a VM tier
        foreach ($v in $p.HostChannels.Values) {
            if ($v -is [bool]) { $v | Should -BeFalse }
        }
    }
}

Describe 'Import-TierProfile — basic schema validation (invariant 6)' {

    It 'throws when a required key is missing' {
        $h = script:Get-ValidTier1Hashtable
        $h.Remove('Extraction')
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*Extraction*'
    }

    It 'throws when Tier is out of the 0..3 range' {
        $h = script:Get-ValidTier1Hashtable
        $h.Tier = 5
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*Tier*'
    }

    It 'throws when an enum field is outside its allowed set (EgressMode)' {
        $h = script:Get-ValidTier1Hashtable
        $h.EgressMode = 'WideOpen'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*EgressMode*'
    }

    It 'throws when an enum field is outside its allowed set (Substrate)' {
        $h = script:Get-ValidTier1Hashtable
        $h.Substrate = 'Xen'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*Substrate*'
    }

    It 'throws when the file does not exist' {
        { Import-TierProfile -Path (Join-Path $TestDrive 'does-not-exist.psd1') } | Should -Throw
    }
}

Describe 'SecureBootTemplate enum gate (optional; validated when present)' {
    # SecureBootTemplate feeds Set-VMFirmware -SecureBootTemplate <string>. An invalid value is a real-
    # Hyper-V reject the FAKE silently accepts (the fake≠real bug class the live debug loop surfaced), so
    # the loader fails closed BEFORE provisioning. Absent/empty is allowed (= the provisioner omits the
    # param = Hyper-V default; neither shipped tier sets it on a container tier).

    It 'REJECTS a profile with an invalid SecureBootTemplate value' {
        $h = script:Get-ValidTier1Hashtable
        $h.SecureBootTemplate = 'Bogus'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } |
            Should -Throw -ExpectedMessage '*SecureBootTemplate*' -Because 'an invalid SecureBootTemplate is a real Set-VMFirmware reject; the loader must fail closed'
    }

    It 'ACCEPTS each documented SecureBootTemplate value' {
        foreach ($tmpl in @('MicrosoftWindows', 'MicrosoftUEFICertificateAuthority', 'OpenSourceShieldedVM')) {
            $h = script:Get-ValidTier1Hashtable
            $h.SecureBootTemplate = $tmpl
            $path = script:New-Psd1File -Data $h -Name ("sbt-$tmpl.psd1")
            { Import-TierProfile -Path $path } |
                Should -Not -Throw -Because "'$tmpl' is a documented SecureBootTemplate value and must load"
            (Import-TierProfile -Path $path).SecureBootTemplate | Should -Be $tmpl
        }
    }

    It 'ACCEPTS a profile that OMITS SecureBootTemplate entirely (absent = Hyper-V default)' {
        $h = script:Get-ValidTier1Hashtable
        $h.Remove('SecureBootTemplate')
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } |
            Should -Not -Throw -Because 'SecureBootTemplate is optional; absent means the provisioner omits the param'
    }

    It 'ACCEPTS a profile with an EMPTY-string SecureBootTemplate (treated as absent)' {
        $h = script:Get-ValidTier1Hashtable
        $h.SecureBootTemplate = ''
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } |
            Should -Not -Throw -Because 'an empty SecureBootTemplate is treated as absent (= Hyper-V default), not an invalid enum value'
    }

    It 'a workload REJECTS an invalid SecureBootTemplate inherited from its base tier (merged re-validation)' {
        # The merged workload re-runs Assert-TierProfileValid, so a bad SecureBootTemplate on the base
        # tier is caught at the workload layer too (not just the bare tier load).
        $h = script:Get-ValidTier1Hashtable
        $h.SecureBootTemplate = 'NotAValidTemplate'
        $tierPath = script:New-Psd1File -Data $h -Name 'tier1.psd1'
        $tierDir  = Split-Path -Parent $tierPath
        $wl = @{ BaseTier = 1; Name = 'bad-sbt-wl'; Entrypoint = 'true' }
        $wlPath = script:New-Psd1File -Data $wl -Name 'bad-sbt-workload.psd1'
        { Import-WorkloadProfile -Path $wlPath -TierProfileDir $tierDir } |
            Should -Throw -ExpectedMessage '*SecureBootTemplate*' -Because 'the merged workload re-validation must also reject an invalid SecureBootTemplate'
    }

    It 'tier1.psd1 (which sets MicrosoftUEFICertificateAuthority) still loads' {
        # Regression guard: the shipped tier1 profile sets a valid SecureBootTemplate and must keep loading.
        { Import-TierProfile -Path $script:Tier1Path } | Should -Not -Throw
        (Import-TierProfile -Path $script:Tier1Path).SecureBootTemplate | Should -Be 'MicrosoftUEFICertificateAuthority'
    }
}

Describe 'Invariant 1 — secret-file mount refusal' {

    # Each of these source paths is secret-shaped and MUST be refused.
    $secretCases = @(
        @{ Src = 'C:\proj\.env';                         Label = '.env' }
        @{ Src = 'C:\proj\.env.production';              Label = '.env.*' }
        @{ Src = 'C:\proj\config\app.env';               Label = '*.env' }
        @{ Src = 'C:\certs\server.pem';                  Label = '*.pem' }
        @{ Src = 'C:\certs\server.key';                  Label = '*.key' }
        @{ Src = 'C:\certs\bundle.p12';                  Label = '*.p12' }
        @{ Src = 'C:\certs\bundle.pfx';                  Label = '*.pfx' }
        @{ Src = 'C:\Users\testuser\.ssh\id_rsa';           Label = 'id_rsa* + .ssh' }
        @{ Src = 'C:\proj\id_rsa.pub';                   Label = 'id_rsa*' }
        @{ Src = 'C:\proj\credentials.json';             Label = 'credentials*.json' }
        @{ Src = 'C:\proj\credentials-prod.json';        Label = 'credentials*.json' }
        @{ Src = 'C:\proj\.credentials.json';            Label = '.credentials.json' }
        @{ Src = 'C:\Users\testuser\.aws\credentials';      Label = '.aws\credentials' }
        @{ Src = 'C:\Users\testuser\.kube\config';          Label = '.kube\config' }
        @{ Src = 'C:\Users\testuser\.docker\config.json';   Label = '.docker\config.json' }
        @{ Src = 'C:\proj\.npmrc';                       Label = '.npmrc' }
        @{ Src = 'C:\proj\.pypirc';                      Label = '.pypirc' }
        @{ Src = 'C:\proj\gcp-service-account.json';     Label = '*-service-account.json' }
        @{ Src = 'C:\Users\testuser\.secrets\openrouter.env'; Label = '.secrets dir' }
        @{ Src = 'C:\Users\testuser\.secrets\token';        Label = '.secrets dir (no ext)' }
        # forward-slash variants must be caught too
        @{ Src = '/home/testuser/.ssh/id_ed25519';       Label = '.ssh (posix)' }
        @{ Src = '/home/testuser/.secrets/x';            Label = '.secrets (posix)' }
        @{ Src = '/home/testuser/.aws/credentials';      Label = '.aws/credentials (posix)' }
    )

    It 'rejects secret-shaped mount source <Label> (<Src>)' -ForEach $secretCases {
        $h = script:Get-ValidTier1Hashtable
        $h.Mounts = @{ $Src = '/mnt/in' }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } |
            Should -Throw -ExpectedMessage '*secret*'
    }

    It 'rejects a secret source regardless of letter case' {
        $h = script:Get-ValidTier1Hashtable
        $h.Mounts = @{ 'C:\Proj\.ENV.PRODUCTION' = '/mnt/in' }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*secret*'
    }

    It 'allows a benign mount source (no secret shape)' {
        $h = script:Get-ValidTier1Hashtable
        $h.Mounts = @{ 'C:\proj\input-data' = '/mnt/in' }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Not -Throw
    }
}

Describe 'Invariant 1 — Windows leaf-equivalence bypass refusal' {

    # Windows treats these LEAF forms as equivalent to the real secret file:
    #   - trailing dots / spaces are stripped by the Win32 path layer
    #     ("server.pem." opens "server.pem"; ".env " opens ".env")
    #   - an NTFS Alternate Data Stream suffix (":stream" / "::$DATA") resolves
    #     to the same base file ("server.key:hidden" reads "server.key")
    # An attacker-controlled workload Mounts key in any of these forms must be
    # REFUSED — the un-normalized leaf must not slip past the glob/EndsWith rules.
    $bypassCases = @(
        @{ Src = 'C:\proj\server.pem.';        Label = 'trailing dot (*.pem)' }
        @{ Src = 'C:\proj\server.pem...';      Label = 'multiple trailing dots (*.pem)' }
        @{ Src = 'C:\proj\.env ';              Label = 'trailing space (.env)' }
        @{ Src = 'C:\certs\server.key ';       Label = 'trailing space (*.key)' }
        @{ Src = 'C:\certs\server.key:hidden'; Label = 'NTFS ADS named stream (*.key)' }
        @{ Src = 'C:\proj\.env::$DATA';        Label = 'NTFS ADS ::$DATA (.env)' }
        # combinations + posix-separator forms must also be caught
        @{ Src = 'C:\proj\server.pem. ';       Label = 'trailing dot+space (*.pem)' }
        @{ Src = 'C:\certs\server.key:hidden.';Label = 'ADS + trailing dot (*.key)' }
        @{ Src = '/home/testuser/.env ';       Label = 'trailing space, posix sep (.env)' }
    )

    It 'rejects Windows-equivalent secret leaf <Label> (<Src>)' -ForEach $bypassCases {
        $h = script:Get-ValidTier1Hashtable
        $h.Mounts = @{ $Src = '/mnt/in' }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*secret*'
    }

    # Re-assert the benign-allow set survives the leaf normalization (no over-block).
    # id_rsa.pub is DELIBERATELY blocked (SCHEMA.md §1 'id_rsa*'); it is NOT in this
    # allow-set — see the dedicated test below that pins its intentional rejection.
    $benignCases = @(
        @{ Src = 'C:\proj\environment.md'; Label = 'environment.md (not *.env)' }
        @{ Src = 'C:\proj\keynote.txt';    Label = 'keynote.txt (not *.key)' }
        @{ Src = 'C:\proj\.secretstuff';   Label = '.secretstuff (not a .secrets dir, not .env)' }
        @{ Src = 'C:\proj\readme.pem.md';  Label = 'readme.pem.md (.md leaf, not *.pem)' }
        @{ Src = 'C:\proj\input-data';     Label = 'plain input dir' }
    )

    It 'still allows benign leaf <Label> (<Src>) after normalization' -ForEach $benignCases {
        $h = script:Get-ValidTier1Hashtable
        $h.Mounts = @{ $Src = '/mnt/in' }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Not -Throw
    }

    It 'still rejects id_rsa.pub (intentional: SCHEMA.md §1 id_rsa* — public key blocked by design)' {
        # Locks the deliberate behavior: id_rsa* refuses id_rsa.pub too. Changing
        # this would silently relax the contract, so it is pinned as a regression guard.
        $h = script:Get-ValidTier1Hashtable
        $h.Mounts = @{ 'C:\proj\id_rsa.pub' = '/mnt/in' }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*secret*'
    }
}

Describe 'Secret-pattern single source of truth' {

    # The matcher, the throw message, and these tests must all derive from ONE
    # set of arrays so the list cannot drift. These assert the hoisted arrays
    # exist (populated by dot-sourcing the lib in BeforeAll) and cover the
    # SCHEMA.md §1 contract — if a future edit drops a pattern, this fails.
    It 'exposes $script:SecretLeafGlobs and $script:SecretDirSegments as the canonical lists' {
        $script:SecretLeafGlobs    | Should -Not -BeNullOrEmpty -Because 'the leaf glob list is the single source of truth'
        $script:SecretDirSegments  | Should -Not -BeNullOrEmpty -Because 'the dir-segment list is the single source of truth'
    }

    It 'the leaf-glob list still covers every SCHEMA.md §1 leaf pattern' {
        # Canonical leaf patterns from tier-profiles/SCHEMA.md §1 (the human-readable doc).
        $schemaLeafPatterns = @(
            '.env', '.env.*', '*.env', '*.pem', '*.key', '*.p12', '*.pfx',
            'id_rsa*', 'credentials*.json', '.credentials.json',
            '.npmrc', '.pypirc', '*-service-account.json'
        )
        foreach ($pat in $schemaLeafPatterns) {
            $script:SecretLeafGlobs | Should -Contain $pat -Because "SCHEMA.md §1 lists '$pat' as a refused leaf"
        }
    }

    It 'the dir-segment list still covers the SCHEMA.md §1 directory rules' {
        # .secrets / .ssh are bare-segment rules; .aws|.kube|.docker are pair rules.
        $script:SecretDirSegments | Should -Contain '.secrets'
        $script:SecretDirSegments | Should -Contain '.ssh'
    }
}

Describe 'Invariant 2 — Tier >= 2 starvation' {

    It 'throws if Tier 2 has Credentials other than None' {
        $h = script:Get-ValidTier2Hashtable
        $h.Credentials = 'ScopedOnDemand'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*Credentials*'
    }

    It 'throws if Tier 2 has EgressMode other than None' {
        $h = script:Get-ValidTier2Hashtable
        $h.EgressMode = 'NftablesAllowlist'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*Egress*'
    }

    It 'throws if Tier 2 has a non-empty EgressAllowlist' {
        $h = script:Get-ValidTier2Hashtable
        $h.EgressAllowlist = @('github.com')
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*Egress*'
    }

    It 'accepts a properly-starved Tier 2 profile' {
        $h = script:Get-ValidTier2Hashtable
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Not -Throw
    }
}

Describe 'Invariant 3 — Extraction by tier' {

    It 'throws if Tier 2 Extraction is not ColdVHDX-Quarantine-CDR' {
        $h = script:Get-ValidTier2Hashtable
        $h.Extraction = 'HostReadResultDir'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*Extraction*'
    }

    It 'accepts Tier 1 with HostReadResultDir (rule only binds Tier >= 2)' {
        $h = script:Get-ValidTier1Hashtable
        $h.Extraction = 'HostReadResultDir'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Not -Throw
    }
}

Describe 'Invariant 4 — VM-tier HostChannels must be all-false' {

    It 'throws if a HyperV-Gen2 tier has a true HostChannel boolean' {
        $h = script:Get-ValidTier1Hashtable
        $h.HostChannels = @{ Clipboard = $true; Shares = $false; GuestServices = $false }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*HostChannel*'
    }

    It 'allows a container tier (Tier 0) to have a non-bool Shares string' {
        # tier0.psd1 already exercises this; assert directly it does not throw on invariant 4.
        { Import-TierProfile -Path $script:Tier0Path } | Should -Not -Throw
    }
}

Describe 'Invariant 5 — Linux guests use Com1Serial' {

    $linuxImages = @('debian-12-cloud', 'ubuntu-22.04', 'alpine-3.19', 'fedora-40', 'remnux-7', 'some-linux-build')

    It 'throws if Linux image <_> uses PSDirect' -ForEach $linuxImages {
        $h = script:Get-ValidTier1Hashtable
        $h.GuestImage = $_
        $h.ManagementChannel = 'PSDirect'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*Com1Serial*'
    }

    It 'allows a Windows guest to use PSDirect' {
        $h = script:Get-ValidTier1Hashtable
        $h.GuestImage = 'windows-11-eval'
        $h.ManagementChannel = 'PSDirect'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Not -Throw
    }

    It 'skips the rule entirely when ManagementChannel key is absent (container tier 0)' {
        { Import-TierProfile -Path $script:Tier0Path } | Should -Not -Throw
    }
}

Describe 'Import-WorkloadProfile — merge + re-validation' {

    It 'unions ExtraAllowlist onto the base tier EgressAllowlist (deduped)' {
        $wl = @{
            BaseTier       = 1
            Name           = 'merge-test'
            Entrypoint     = '/usr/local/bin/run.sh'
            ExtraAllowlist = @('example.com', 'github.com')   # github.com already in tier1 -> deduped
        }
        $wlPath = script:New-Psd1File -Data $wl -Name 'merge-test.psd1'
        $merged = Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir

        $merged.Tier               | Should -Be 1
        $merged.Name               | Should -Be 'merge-test'
        $merged.Entrypoint         | Should -Be '/usr/local/bin/run.sh'
        @($merged.EgressAllowlist) | Should -Contain 'example.com'
        @($merged.EgressAllowlist) | Should -Contain 'api.anthropic.com'   # inherited from tier1
        # github.com appears exactly once (union deduped)
        @(@($merged.EgressAllowlist) | Where-Object { $_ -eq 'github.com' }).Count | Should -Be 1
    }

    It 'layers Packages / Mounts / Entrypoint / StageAssets onto the tier' {
        $wl = @{
            BaseTier   = 1
            Name       = 'layer-test'
            Packages   = @('git', 'ripgrep')
            Mounts     = @{ 'C:\proj\code' = '/mnt/code' }
            Entrypoint = '/bin/agent'
            StageAssets = @{ model = 'sha256:abc' }
        }
        $wlPath = script:New-Psd1File -Data $wl -Name 'layer-test.psd1'
        $merged = Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir

        @($merged.Packages) | Should -Contain 'ripgrep'
        $merged.Mounts['C:\proj\code'] | Should -Be '/mnt/code'
        $merged.Entrypoint  | Should -Be '/bin/agent'
        $merged.StageAssets['model'] | Should -Be 'sha256:abc'
    }

    It 'rejects a workload whose Mount source is secret-shaped (invariant 1 on merged result)' {
        $wl = @{
            BaseTier   = 1
            Name       = 'evil-mount'
            Entrypoint = '/bin/run'
            Mounts     = @{ 'C:\Users\testuser\.secrets\openrouter.env' = '/mnt/in' }
        }
        $wlPath = script:New-Psd1File -Data $wl -Name 'evil-mount.psd1'
        { Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir } |
            Should -Throw -ExpectedMessage '*secret*'
    }

    It 'throws when BaseTier resolves to no tier file' {
        $wl = @{ BaseTier = 9; Name = 'no-tier'; Entrypoint = '/bin/x' }
        $wlPath = script:New-Psd1File -Data $wl -Name 'no-tier.psd1'
        { Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir } |
            Should -Throw -ExpectedMessage '*tier*'
    }

    It 'throws when a required workload key is missing (BaseTier)' {
        $wl = @{ Name = 'no-basetier'; Entrypoint = '/bin/x' }
        $wlPath = script:New-Psd1File -Data $wl -Name 'no-basetier.psd1'
        { Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir } |
            Should -Throw -ExpectedMessage '*BaseTier*'
    }

    It 'a workload that pushes a Tier-2 base into a non-empty allowlist is rejected (starvation re-check)' {
        # We need a tier2 file in a scratch tier dir for this; build one.
        $scratchTierDir = Join-Path $TestDrive 'scratch-tiers'
        New-Item -ItemType Directory -Path $scratchTierDir -Force | Out-Null
        $t2 = script:Get-ValidTier2Hashtable
        $t2Text = script:ConvertTo-Psd1Text -Value $t2
        Set-Content -LiteralPath (Join-Path $scratchTierDir 'tier2.psd1') -Value $t2Text -Encoding UTF8

        $wl = @{
            BaseTier       = 2
            Name           = 'starve-break'
            Entrypoint     = '/bin/x'
            ExtraAllowlist = @('exfil.example.com')   # would break Tier-2 starvation
        }
        $wlPath = script:New-Psd1File -Data $wl -Name 'starve-break.psd1'
        { Import-WorkloadProfile -Path $wlPath -TierProfileDir $scratchTierDir } |
            Should -Throw -ExpectedMessage '*Egress*'
    }
}
