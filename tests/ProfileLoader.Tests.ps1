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
            EgressMode         = 'HostProxy'
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
        # Every declared channel must be falsey. Lock-Sandbox turns all four OFF from its own
        # hardcoded list without reading this profile, so a truthy value here advertises a channel
        # that never exists in a sealed guest. tier0 previously declared Shares='ReadOnlyInput',
        # a truthy string; it was inert and misleading, and is now $false.
        $p.HostChannels.Shares          | Should -BeFalse
        $p.HostChannels.Clipboard       | Should -BeFalse
        $p.HostChannels.GuestServices   | Should -BeFalse
        $p.HostChannels.EnhancedSession | Should -BeFalse
        $p.ContainsKey('ManagementChannel') | Should -BeFalse # container tier has no mgmt channel
        # Tier-0 today provisions a real Debian Gen2 VM, so it MUST carry the Linux Secure Boot
        # template (an omitted/Windows-default template rejects Debian's MS-UEFI-CA-signed bootloader).
        $p.SecureBootTemplate  | Should -Be 'MicrosoftUEFICertificateAuthority' -Because 'a Linux Gen2 guest needs the MS-UEFI-CA template, not the Windows default'
    }

    It 'loads tier1.psd1 without error and returns the expected normalized shape' {
        $p = Import-TierProfile -Path $script:Tier1Path
        $p                       | Should -Not -BeNullOrEmpty
        $p.Tier                  | Should -Be 1
        $p.Substrate             | Should -Be 'HyperV-Gen2'
        $p.EgressMode            | Should -Be 'HostProxy'
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

    It 'REJECTS the retired NftablesAllowlist EgressMode (fabricated/never-implemented; pins the retirement)' {
        # NftablesAllowlist was schema-only and design-invalidated (a static nftables rule set cannot
        # follow CDN-fronted hosts whose addresses rotate). Nothing should be able to silently
        # re-introduce the fabricated value via an unknown enum member.
        $h = script:Get-ValidTier1Hashtable
        $h.EgressMode = 'NftablesAllowlist'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*EgressMode*'
    }

    It 'REJECTS the retired in-guest modes <Mode> (one egress model remains: HostProxy for a kept NIC, None otherwise)' -ForEach @(
        @{ Mode = 'InGuestSquid' }, @{ Mode = 'SquidSniProxy' }, @{ Mode = 'HostEnvoy' }
    ) {
        # These modes put the egress filter inside the guest, where a root guest could remove it, and
        # left the kept NIC with no host-side restriction. They are gone from the enum; pin that.
        $h = script:Get-ValidTier1Hashtable
        $h.EgressMode = $Mode
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage "*EgressMode*'$Mode'*not one of the allowed values*"
        @($script:Enum_EgressMode) | Should -Be @('HostProxy', 'None')
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

    It 'tier0.psd1 (which sets MicrosoftUEFICertificateAuthority for its Linux Gen2 guest) still loads' {
        # RC1 regression guard: tier0 now also declares the Linux Secure Boot template and must load through the enum gate.
        { Import-TierProfile -Path $script:Tier0Path } | Should -Not -Throw
        (Import-TierProfile -Path $script:Tier0Path).SecureBootTemplate | Should -Be 'MicrosoftUEFICertificateAuthority'
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

Describe 'Invariant 1: StageAssets secret refusal (regression - the live delivery field)' {

    # REGRESSION GUARD. Invariant 1 originally screened ONLY Mounts, which the Provisioner/Runner
    # never wire into the guest (docs/live-smoke-test.md Gap 2). StageAssets is the field the
    # orchestrator actually imports (Invoke-Voidseal -> Import-SandboxAsset), and it was unscreened,
    # so a secret-shaped path could be staged into a guest and still pass the seal gate. Both fields
    # are screened now. These cases fail if that ever regresses.

    $stageSecretCases = @(
        @{ Src = 'C:\Users\testuser\.secrets\anthropic.env'; Label = '.secrets dir (the original escape)' }
        @{ Src = 'C:\proj\.env';                             Label = '.env' }
        @{ Src = 'C:\certs\server.key';                      Label = '*.key' }
        @{ Src = 'C:\Users\testuser\.aws\credentials';       Label = '.aws-credentials' }
        @{ Src = '/home/testuser/.ssh/id_rsa';               Label = '.ssh (posix)' }
    )

    It 'rejects secret-shaped StageAssets source <Label> (<Src>) on a tier profile' -ForEach $stageSecretCases {
        $h = script:Get-ValidTier1Hashtable
        $h.StageAssets = @{ $Src = 'pinned asset' }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*secret*'
    }

    It 'rejects a secret-shaped StageAssets source on the MERGED workload (the path the orchestrator imports)' {
        $wl = @{
            BaseTier    = 1
            Name        = 'evil-stage'
            Entrypoint  = '/bin/run'
            StageAssets = @{ 'C:\Users\testuser\.secrets\anthropic.env' = 'pinned asset' }
        }
        $wlPath = script:New-Psd1File -Data $wl -Name 'evil-stage.psd1'
        { Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir } |
            Should -Throw -ExpectedMessage '*secret*'
    }

    It 'names StageAssets (not Mounts) in the refusal so the operator can find the offending field' {
        $h = script:Get-ValidTier1Hashtable
        $h.StageAssets = @{ 'C:\proj\.env' = 'pinned asset' }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*StageAssets*'
    }

    It 'allows a benign StageAssets source (no secret shape)' {
        $h = script:Get-ValidTier1Hashtable
        $h.StageAssets = @{ 'C:\sandbox\assets\ralph-claude-code.iso' = 'pinned @ sha' }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Not -Throw
    }

    It 'refuses a StageAssets value that is not a hashtable (unscreenable shape fails closed)' {
        $h = script:Get-ValidTier1Hashtable
        $h.StageAssets = @('C:\sandbox\assets\thing.iso')
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*StageAssets*'
    }
}

Describe 'Invariant 1: broadened denylist coverage' {

    # Added after an external review demonstrated these common credential shapes were missed.
    $broadenedCases = @(
        @{ Src = 'C:\proj\id_ed25519';                      Label = 'id_ed25519 outside .ssh' }
        @{ Src = 'C:\proj\id_ecdsa';                        Label = 'id_ecdsa outside .ssh' }
        @{ Src = 'C:\Users\testuser\.netrc';                Label = 'dot-netrc' }
        @{ Src = 'C:\Users\testuser\_netrc';                Label = 'underscore-netrc (windows)' }
        @{ Src = 'C:\Users\testuser\.git-credentials';      Label = 'git-credentials' }
        @{ Src = 'C:\keys\release.jks';                     Label = 'jks' }
        @{ Src = 'C:\keys\debug.keystore';                  Label = 'keystore' }
        @{ Src = 'C:\keys\session.ppk';                     Label = 'ppk' }
        @{ Src = 'C:\vault\passwords.kdbx';                 Label = 'kdbx' }
        @{ Src = 'C:\Users\testuser\.pgpass';               Label = 'pgpass' }
        @{ Src = 'C:\Users\testuser\.my.cnf';               Label = 'my-cnf' }
        @{ Src = 'C:\infra\secrets.yaml';                   Label = 'secrets-yaml' }
        @{ Src = 'C:\infra\secrets.yml';                    Label = 'secrets-yml' }
        @{ Src = 'C:\infra\prod.tfvars';                    Label = 'tfvars' }
        @{ Src = 'C:\Users\testuser\.aws\config';           Label = 'aws-config' }
        @{ Src = 'C:\Users\testuser\.config\gh\hosts.yml';  Label = 'gh-hosts' }
        @{ Src = 'C:\Users\testuser\.gnupg\secring.gpg';    Label = 'gnupg dir' }
    )

    It 'Test-IsSecretPath flags <Label> (<Src>)' -ForEach $broadenedCases {
        Test-IsSecretPath -Path $Src | Should -BeTrue
    }

    It 'the loader refuses <Label> (<Src>) declared via StageAssets' -ForEach $broadenedCases {
        $h = script:Get-ValidTier1Hashtable
        $h.StageAssets = @{ $Src = 'pinned asset' }
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*secret*'
    }

    It 'still allows the ralph .token delivery path (documented, deliberately not secret-shaped)' {
        Test-IsSecretPath -Path 'C:\sandbox\agent-cred\agent.token' | Should -BeFalse
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

Describe 'Mounts: declared, not wired (the docs must say so while no engine code reads it)' {
    # The loader screens Mounts source keys (invariant 1 above) and layers the field onto the tier.
    # Nothing else reads it: no provisioner, runner or backend method attaches a host-guest bind
    # mount (docs/live-smoke-test.md Gap 2). The authoring guide and the skeleton profile once
    # presented Mounts as the way to move files in and out. These checks tie the docs to the code in
    # both directions: a new reader fails the scan, so the docs get revisited, and while there is
    # none, every place that introduces the field must say it is not wired.
    BeforeAll {
        # Each place a script names the Mounts key, as 'file:line'. Index reads ($p['Mounts']), member
        # reads ($p.Mounts), ContainsKey('Mounts') and literal keys all parse to a string constant
        # whose value is the bare key. Comments are not in the AST, and a here-string that mentions
        # mounts never equals the key. The match ignores case because profile hashtables do: $p.mounts
        # reads the same entry.
        function script:Find-MountsKeyReference {
            param([System.IO.FileInfo[]] $Files)
            foreach ($f in $Files) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                $ast.FindAll({ param($n)
                    $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -eq 'Mounts'
                }, $true) | ForEach-Object { '{0}:{1}' -f $f.Name, $_.Extent.StartLineNumber }
            }
        }
        $script:MountsScanFiles = @(Get-ChildItem -Path (Join-Path $script:SkillRoot 'scripts') -Recurse -Filter '*.ps1')
    }

    It 'the scan finds the loader''s own reads, so a clean result elsewhere means something' {
        $loader = @($script:MountsScanFiles | Where-Object Name -eq 'ProfileLoader.ps1')
        $loader.Count | Should -Be 1 -Because 'the loader is the one known reader'
        @(script:Find-MountsKeyReference -Files $loader) | Should -Not -BeNullOrEmpty -Because 'the loader screens and merges Mounts, so a working scan must see it there'
    }

    It 'the scan catches a reader written in any letter case (planted positive control)' {
        # Profile hashtables ignore case, so $p['mounts'] and $p.MOUNTS read the same entry as
        # $p['Mounts']. A case-sensitive match would let those readers evade the guard.
        $planted = Join-Path $TestDrive 'planted-mounts-reader.ps1'
        Set-Content -LiteralPath $planted -Encoding utf8 -Value @(
            '$a = $p[''mounts'']'
            '$b = $p.MOUNTS'
        )
        @(script:Find-MountsKeyReference -Files @(Get-Item -LiteralPath $planted)).Count | Should -Be 2
    }

    It 'no engine script outside the loader reads the Mounts key' {
        $engine = @($script:MountsScanFiles | Where-Object Name -ne 'ProfileLoader.ps1')
        $engine.Count | Should -BeGreaterThan 5 -Because 'the scan must actually cover the engine'
        @(script:Find-MountsKeyReference -Files $engine) | Should -BeNullOrEmpty -Because 'Mounts is unread outside the loader today; a reader means the docs that call it declared-only must change with it'
    }

    It '<File> says Mounts is not wired' -ForEach @(
        @{ File = 'tier-profiles/SCHEMA.md';              Intro = '^\|\s*`Mounts`\s*\|' }
        @{ File = 'docs/authoring-a-workload-profile.md'; Intro = '^\|\s*`Mounts`\s*\|' }
        @{ File = 'profiles/example-skeleton.psd1';       Intro = '^\s*#\s*Mounts\b' }
    ) {
        $intro = @(Get-Content -LiteralPath (Join-Path $script:SkillRoot $File) | Where-Object { $_ -match $Intro })
        $intro.Count | Should -Be 1 -Because "$File introduces the field in exactly one line (a table row, or the comment heading the key)"
        $intro[0] | Should -Match '(?i)not wired' -Because "$File must not promise a delivery the engine does not perform"
        $intro[0] | Should -Not -Match '(?i)delivery mechanism' -Because 'Mounts delivers nothing, in Serial mode or any other'
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
        $h.EgressMode = 'HostProxy'
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

Describe 'Packages: declared, not installed (the docs must say so while no engine code reads it)' {
    # The loader layers a workload's Packages onto its tier (tested above), and nothing else in the
    # engine reads the key: no seed, provisioner or runner installs from it. The schema and the
    # authoring guide used to say packages were "staged before the seal". These checks tie the docs
    # to the code in both directions: a new reader fails the first It, so the docs get revisited,
    # and while there is none, the docs must say the field installs nothing.
    BeforeAll {
        # Each place a script names the Packages key, as 'file:line'. Index reads ($p['Packages']),
        # member reads ($p.Packages) and quoted names all parse to a string constant whose value is
        # the bare key. Comments are not in the AST, and a here-string that merely mentions packages
        # never equals the key. The match ignores case because profile hashtables do: $p['packages']
        # reads the same entry, so a case-sensitive match would let such a reader evade the guard.
        function script:Find-PackagesKeyReference {
            param([System.IO.FileInfo[]] $Files)
            foreach ($f in $Files) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                $ast.FindAll({ param($n)
                    $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -eq 'Packages'
                }, $true) | ForEach-Object { '{0}:{1}' -f $f.Name, $_.Extent.StartLineNumber }
            }
        }
    }

    It 'the scan catches a reader written in any letter case (planted positive control)' {
        $planted = Join-Path $TestDrive 'planted-packages-reader.ps1'
        Set-Content -LiteralPath $planted -Encoding utf8 -Value @(
            '$a = $p[''packages'']'
            '$b = $p.PACKAGES'
        )
        @(script:Find-PackagesKeyReference -Files @(Get-Item -LiteralPath $planted)).Count | Should -Be 2
    }

    It 'no engine script outside the loader reads the Packages key' {
        $engineScripts = @(Get-ChildItem -Path (Join-Path $script:SkillRoot 'scripts') -Recurse -Filter '*.ps1' |
                           Where-Object { $_.Name -ne 'ProfileLoader.ps1' })
        $engineScripts.Count | Should -BeGreaterThan 5 -Because 'the scan must actually cover the engine'
        $readers = script:Find-PackagesKeyReference -Files $engineScripts
        @($readers) | Should -BeNullOrEmpty -Because 'Packages is unread today; a reader means the docs that call it declared-only must change with it'
    }

    It '<Doc> says Packages installs nothing' -ForEach @(
        @{ Doc = 'tier-profiles/SCHEMA.md' }
        @{ Doc = 'docs/authoring-a-workload-profile.md' }
    ) {
        $row = @(Get-Content -LiteralPath (Join-Path $script:SkillRoot $Doc) | Where-Object { $_ -match '^\|\s*`Packages`\s*\|' })
        $row.Count | Should -Be 1 -Because "$Doc documents the field in exactly one table row"
        $row[0] | Should -Match '(?i)not installed' -Because "$Doc must not claim an effect the engine does not have"
        $row[0] | Should -Not -Match '(?i)staged before' -Because 'nothing stages these packages, before the seal or after it'
    }
}

Describe 'Processor profile (Network=None) + DepsSpec/ScreenConfig' {
    BeforeAll {
        . "$PSScriptRoot/../scripts/lib/ProfileLoader.ps1"
        # New-ProcBase defined in BeforeAll so It blocks can find it (Pester 5 scoping).
        function script:New-ProcBase {
            @{ Tier=0; Description='p'; Substrate='HyperV-Gen2'; Network='None'; EgressMode='None';
               EgressAllowlist=@(); Credentials='None'; GuestImage='debian-12'; Memory=2GB; Cpu=2;
               HostChannels=@{Clipboard=$false;Shares=$false;GuestServices=$false;EnhancedSession=$false};
               Capture='HostReadResultDir'; Extraction='HostReadResultDir'; Lifecycle='CreateDestroy';
               Controls=@(); ManagementChannel='Com1Serial' }
        }
    }
    It 'accepts a processor profile with Network=None + ScreenConfig' {
        $p = script:New-ProcBase; $p.ScreenConfig=@{mode='aggressive';categories=@('financial')}
        { Assert-TierProfileValid -Profile $p -Context 'test' } | Should -Not -Throw
    }
    It 'REFUSES a Network=None profile that declares a DepsSpec (a builder keeps a NIC; a processor gets a built deps disk instead)' {
        $p = script:New-ProcBase; $p.DepsSpec=@{ Pip = @{ Packages = @('tika') } }; $p.ScreenConfig=@{mode='aggressive'}
        { Assert-TierProfileValid -Profile $p -Context 'test' } | Should -Throw -ExpectedMessage "*Builder rule (DepsSpec)*MUST be Tier 1 with Network='Internal+Allowlist'*"
    }
    It 'REFUSES a Network=None profile that declares egress (EgressMode != None)' {
        $p = script:New-ProcBase; $p.EgressMode='HostProxy'
        { Assert-TierProfileValid -Profile $p -Context 'test' } | Should -Throw
    }
    It 'REFUSES a Network=None profile with a non-empty EgressAllowlist' {
        $p = script:New-ProcBase; $p.EgressAllowlist=@('pypi.org')
        { Assert-TierProfileValid -Profile $p -Context 'test' } | Should -Throw
    }
    It 'defaults a processor ScreenConfig mode to aggressive when omitted' {
        $p = script:New-ProcBase; $p.ScreenConfig=@{categories=@('financial')}
        (Resolve-ScreenConfig -Profile $p).mode | Should -Be 'aggressive'
    }
    It 'returns categories as an ARRAY even for a single-element categories (no unroll)' {
        $p = @{ ScreenConfig = @{ mode='aggressive'; categories=@('financial') } }
        $r = Resolve-ScreenConfig -Profile $p
        ($r.categories -is [array]) | Should -BeTrue
        @($r.categories).Count      | Should -Be 1
        @($r.categories)[0]         | Should -Be 'financial'
    }
    It 'defaults BOTH mode and categories when ScreenConfig is absent entirely' {
        $r = Resolve-ScreenConfig -Profile @{}
        $r.mode                | Should -Be 'aggressive'
        ($r.categories -is [array]) | Should -BeTrue
        @($r.categories).Count | Should -Be 0
    }
}

Describe 'Kept-NIC rule: a VM that keeps a NIC must use EgressMode HostProxy' {
    # Get-SealNicPolicy decides which VM keeps a NIC (Tier 1 with Network 'Internal+Allowlist'). Before
    # this rule a kept-NIC profile could declare any mode and the gate certified it with no host-side
    # egress check at all; now the loader refuses the shape before anything is provisioned.
    It 'refuses a Tier-1 Internal+Allowlist profile set to None, naming HostProxy as the only option' {
        $h = script:Get-ValidTier1Hashtable; $h.EgressMode = 'None'; $h.EgressAllowlist = @()
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } |
            Should -Throw -ExpectedMessage "*Kept-NIC rule*keeps a network adapter*EgressMode='None'*MUST use EgressMode='HostProxy'*"
    }
    It 'refuses a Tier-1 Network label the seal policy does not recognize, at load rather than at provisioning' {
        $h = script:Get-ValidTier1Hashtable; $h.Network = 'Internal'
        $path = script:New-Psd1File -Data $h
        { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage "*Kept-NIC rule*cannot place*'Internal' is not recognized*"
    }
    It 'accepts the kept-NIC HostProxy shape, a Tier-1 processor set to None, and a Tier-0 profile set to None' {
        { Import-TierProfile -Path (script:New-Psd1File -Data (script:Get-ValidTier1Hashtable)) } | Should -Not -Throw
        $proc = script:Get-ValidTier1Hashtable; $proc.Network = 'None'; $proc.EgressMode = 'None'; $proc.EgressAllowlist = @()
        { Import-TierProfile -Path (script:New-Psd1File -Data $proc) } | Should -Not -Throw
        # A Tier-0 VM seals with no adapter whatever its label says, so either mode is accepted there.
        $t0 = script:Get-ValidTier1Hashtable; $t0.Tier = 0; $t0.EgressMode = 'None'; $t0.EgressAllowlist = @()
        { Import-TierProfile -Path (script:New-Psd1File -Data $t0) } | Should -Not -Throw
    }
    It 'the shipped tier1.psd1 is the kept-NIC HostProxy shape, and tier0.psd1 seals with no adapter' {
        $t1 = Import-TierProfile -Path "$PSScriptRoot/../tier-profiles/tier1.psd1"
        $t1['Network']    | Should -Be 'Internal+Allowlist'
        $t1['EgressMode'] | Should -Be 'HostProxy'
        Get-SealNicPolicy -Tier ([int]$t1['Tier']) -Network ([string]$t1['Network']) | Should -Be 'IsolatedInternalSwitch'
        $t0 = Import-TierProfile -Path "$PSScriptRoot/../tier-profiles/tier0.psd1"
        Get-SealNicPolicy -Tier ([int]$t0['Tier']) -Network ([string]$t0['Network']) | Should -Be 'NoAdapter'
    }
}

Describe 'Builder profile: DepsSpec selects the builder rule (the kept-NIC HostProxy shape + a derived-per-fetcher allowlist)' {
    It 'the real profiles/builder.psd1 loads green, inherits HostProxy from tier1, and is Tier-1 Internal+Allowlist' {
        $merged = Import-WorkloadProfile -Path "$PSScriptRoot/../profiles/builder.psd1" -TierProfileDir "$PSScriptRoot/../tier-profiles"
        $merged['EgressMode'] | Should -Be 'HostProxy'
        $merged['Tier']       | Should -Be 1
        $merged['Network']    | Should -Be 'Internal+Allowlist'
        $merged['DepsSpec'].Keys | Should -Contain 'Pip'
        # merged allowlist must cover apt + HF (unioned from ExtraAllowlist) and pip (from tier1)
        @($merged['EgressAllowlist']) | Should -Contain 'deb.debian.org'
        @($merged['EgressAllowlist']) | Should -Contain 'huggingface.co'
        (Import-PowerShellDataFile -LiteralPath "$PSScriptRoot/../profiles/builder.psd1").ContainsKey('EgressMode') |
            Should -BeFalse -Because 'EgressMode is tier-owned; the builder file inherits it rather than setting it'
    }
    It 'Test-AllowlistCoversHost: a domain-suffix entry covers a rotating subdomain' {
        Test-AllowlistCoversHost -Allowlist @('.hf.co') -HostName 'cas-bridge.xethub.hf.co' | Should -BeTrue
        Test-AllowlistCoversHost -Allowlist @('huggingface.co') -HostName 'cdn-lfs.huggingface.co' | Should -BeFalse
        Test-AllowlistCoversHost -Allowlist @('pypi.org') -HostName 'pypi.org' | Should -BeTrue
    }
    It 'SEC-1: an EgressAllowlist entry bearing a newline (proxy argument injection) is REFUSED fail-closed, naming the bad entry' {
        # Every allowlist entry becomes a --allow argument of the host proxy (Get-EgressProxyArguments);
        # a newline-bearing entry could reshape that argument list. The load-time charset check must
        # reject it before it ever reaches the proxy or the seed. Direct Assert-TierProfileValid on a
        # network-tier hashtable (a .psd1 cannot even carry a literal newline-in-a-string cleanly).
        $bad = @{
            Tier=1; Description='p'; Substrate='HyperV-Gen2'; Network='Internal+Allowlist'; EgressMode='HostProxy';
            EgressAllowlist=@("pypi.org`nhttp_access allow all"); Credentials='None'; GuestImage='debian-12'; Memory=2GB; Cpu=2;
            HostChannels=@{Clipboard=$false;Shares=$false;GuestServices=$false;EnhancedSession=$false};
            Capture='HostReadResultDir'; Extraction='HostReadResultDir'; Lifecycle='CreateDestroy';
            Controls=@(); ManagementChannel='Com1Serial'
        }
        { Assert-TierProfileValid -Profile $bad -Context 'sec1' } |
            Should -Throw -ExpectedMessage '*EgressAllowlist*invalid entry*'
    }
    It 'SEC-1: a clean hostname AND a leading-dot domain-suffix entry are ACCEPTED (the regex passes real allowlists)' {
        $ok = @{
            Tier=1; Description='p'; Substrate='HyperV-Gen2'; Network='Internal+Allowlist'; EgressMode='HostProxy';
            EgressAllowlist=@('cas-bridge.xethub.hf.co', '.hf.co', 'pypi.org'); Credentials='None'; GuestImage='debian-12'; Memory=2GB; Cpu=2;
            HostChannels=@{Clipboard=$false;Shares=$false;GuestServices=$false;EnhancedSession=$false};
            Capture='HostReadResultDir'; Extraction='HostReadResultDir'; Lifecycle='CreateDestroy';
            Controls=@(); ManagementChannel='Com1Serial'
        }
        { Assert-TierProfileValid -Profile $ok -Context 'sec1ok' } | Should -Not -Throw
    }
    It 'a workload file that sets EgressMode (to <Mode>) is REFUSED as a tier-owned key' -ForEach @(
        @{ Mode = 'HostProxy' }, @{ Mode = 'None' }, @{ Mode = 'SquidSniProxy' }
    ) {
        $wl = Join-Path $TestDrive "egress-$Mode.psd1"
        Set-Content -LiteralPath $wl -Encoding utf8 -Value "@{ BaseTier = 1; Name = 'bad'; Entrypoint = 'x'; EgressMode = '$Mode' }"
        { Import-WorkloadProfile -Path $wl -TierProfileDir "$PSScriptRoot/../tier-profiles" } |
            Should -Throw -ExpectedMessage "*unknown key 'EgressMode'*'EgressMode' is a tier-owned key*"
    }
    It 'a DepsSpec that is not a non-empty hashtable is REFUSED' {
        $wl = Join-Path $TestDrive 'empty-depsspec.psd1'
        Set-Content -LiteralPath $wl -Encoding utf8 -Value @'
@{ BaseTier = 1; Name = 'nd'; Entrypoint = 'x'; DepsSpec = @{};
   ExtraAllowlist = @('deb.debian.org','security.debian.org') }
'@
        { Import-WorkloadProfile -Path $wl -TierProfileDir "$PSScriptRoot/../tier-profiles" } |
            Should -Throw -ExpectedMessage '*Builder rule (DepsSpec)*MUST carry a non-empty DepsSpec*'
    }
    It 'a DepsSpec on a base tier that seals with no adapter (Tier 0) is REFUSED: a builder must be the kept-NIC HostProxy shape' {
        $wl = Join-Path $TestDrive 'tier0-depsspec.psd1'
        Set-Content -LiteralPath $wl -Encoding utf8 -Value @'
@{ BaseTier = 0; Name = 'bld0'; Entrypoint = 'x';
   ExtraAllowlist = @('pypi.org', 'files.pythonhosted.org');
   DepsSpec = @{ Pip = @{ Packages = @('urllib3') } } }
'@
        { Import-WorkloadProfile -Path $wl -TierProfileDir "$PSScriptRoot/../tier-profiles" } |
            Should -Throw -ExpectedMessage "*Builder rule (DepsSpec)*declares DepsSpec (a builder) but is Tier 0*MUST be Tier 1 with Network='Internal+Allowlist' and EgressMode='HostProxy'*"
    }
    It 'a declared fetcher with a MISSING required host is REFUSED (derived per-fetcher)' {
        $wl = Join-Path $TestDrive 'incomplete.psd1'
        Set-Content -LiteralPath $wl -Encoding utf8 -Value @'
@{ BaseTier = 1; Name = 'inc'; Entrypoint = 'x';
   ExtraAllowlist = @('deb.debian.org');                      # security.debian.org MISSING
   DepsSpec = @{ Apt = @{ Packages = @('jq') } } }
'@
        { Import-WorkloadProfile -Path $wl -TierProfileDir "$PSScriptRoot/../tier-profiles" } |
            Should -Throw -ExpectedMessage '*Builder rule (DepsSpec)*INCOMPLETE*security.debian.org*'
    }
    It 'an unknown fetcher name is REFUSED, naming the known ones' {
        $wl = Join-Path $TestDrive 'unknown-fetcher.psd1'
        Set-Content -LiteralPath $wl -Encoding utf8 -Value @'
@{ BaseTier = 1; Name = 'uf'; Entrypoint = 'x'; DepsSpec = @{ Cargo = @{ Crates = @('serde') } } }
'@
        { Import-WorkloadProfile -Path $wl -TierProfileDir "$PSScriptRoot/../tier-profiles" } |
            Should -Throw -ExpectedMessage "*Builder rule (DepsSpec)*unknown fetcher 'Cargo'*"
    }
    It 'a pip-ONLY DepsSpec is NOT forced to allowlist apt/HF hosts (derived per-fetcher)' {
        $wl = Join-Path $TestDrive 'pip-only.psd1'
        Set-Content -LiteralPath $wl -Encoding utf8 -Value @'
@{ BaseTier = 1; Name = 'pip'; Entrypoint = 'x';
   DepsSpec = @{ Pip = @{ Packages = @('urllib3') } } }   # pypi+pythonhosted already in tier1
'@
        $merged = Import-WorkloadProfile -Path $wl -TierProfileDir "$PSScriptRoot/../tier-profiles"
        $merged['EgressMode'] | Should -Be 'HostProxy' -Because 'a builder inherits the tier mode like any other workload'
    }
    It 'existing ralph/firefox profiles still load (neither sets EgressMode; both inherit their tier)' {
        { Import-WorkloadProfile -Path "$PSScriptRoot/../profiles/ralph.psd1"   -TierProfileDir "$PSScriptRoot/../tier-profiles" } | Should -Not -Throw
        { Import-WorkloadProfile -Path "$PSScriptRoot/../profiles/firefox.psd1" -TierProfileDir "$PSScriptRoot/../tier-profiles" } | Should -Not -Throw
    }
}

# ===========================================================================
# Test-UsesOutboxTransport — THE single predicate for "does this profile release
# its result through the user-space outbox (Raw OUTPUT) rather than a mounted exFAT
# OUTPUT?". Workload.ps1 (disk shape), SeedBuilder.ps1 (in-guest runner) and
# Invoke-Voidseal.ps1 (structural validator + read routing) ALL read this one
# function. They used to compute it independently and drifted: SeedBuilder keyed on
# OutboxOutput alone, so a PROCESSOR got a Raw OUTPUT disk AND the exFAT runner —
# the guest would mount a filesystem that isn't there and fail closed silently.
# ===========================================================================
Describe 'Test-UsesOutboxTransport — the single outbox predicate' {

    It 'is TRUE for a PROCESSOR (Network=None + ScreenConfig) even with NO OutboxOutput key' {
        $p = @{ Name='proc'; WorkloadMode='Disk'; Network='None'; ScreenConfig=@{ mode='aggressive' } }
        Test-UsesOutboxTransport -Profile $p | Should -BeTrue -Because 'a processor releases through the screener-governed outbox; its OUTPUT disk is Raw'
    }

    It 'is TRUE for an OutboxOutput profile (firefox) even with NO ScreenConfig' {
        $p = @{ Name='firefox'; WorkloadMode='Disk'; OutboxOutput=$true }
        Test-UsesOutboxTransport -Profile $p | Should -BeTrue -Because 'transport-only firefox opts into the same outbox transport'
    }

    It 'is FALSE for a legacy non-outbox Disk profile (keeps the direct exFAT result.html contract)' {
        $p = @{ Name='legacy'; WorkloadMode='Disk'; Network='Internal' }
        Test-UsesOutboxTransport -Profile $p | Should -BeFalse
    }

    It 'is FALSE when OutboxOutput is explicitly $false' {
        $p = @{ Name='off'; WorkloadMode='Disk'; OutboxOutput=$false }
        Test-UsesOutboxTransport -Profile $p | Should -BeFalse
    }

    It 'needs BOTH halves of the processor shape (Network=None alone is not a processor)' {
        $p = @{ Name='half'; WorkloadMode='Disk'; Network='None' }
        Test-UsesOutboxTransport -Profile $p | Should -BeFalse -Because 'a no-NIC profile without a ScreenConfig is not a processor'
    }

    It 'is FALSE for a null profile (fail-safe, no throw)' {
        Test-UsesOutboxTransport -Profile $null | Should -BeFalse
    }

    It 'accepts a pscustomobject profile as well as a hashtable (both shapes callers pass)' {
        $p = [pscustomobject]@{ Name='obj'; WorkloadMode='Disk'; OutboxOutput=$true }
        Test-UsesOutboxTransport -Profile $p | Should -BeTrue
    }

    It 'agrees with the SHIPPED firefox profile (which is OutboxOutput transport-only)' {
        $ff = Import-WorkloadProfile -Path "$PSScriptRoot/../profiles/firefox.psd1" -TierProfileDir "$PSScriptRoot/../tier-profiles"
        Test-UsesOutboxTransport -Profile $ff | Should -BeTrue
    }
}

# ===========================================================================
# Test-IsProcessorProfile: THE single predicate for "is this a processor?" (Network=None plus a
# ScreenConfig). Test-UsesOutboxTransport, SeedBuilder.ps1 (whether the seed screens in the guest)
# and Invoke-Voidseal.ps1 (the gate routing and the processor preflight) all read it. The seed that
# screens and the host that gates must agree on which profiles are processors, so the truth lives in
# one function instead of several hand-copied expressions.
# ===========================================================================
Describe 'Test-IsProcessorProfile: the single processor predicate' {

    It 'is TRUE for Network=None plus a ScreenConfig' {
        Test-IsProcessorProfile -Profile @{ Network = 'None'; ScreenConfig = @{ mode = 'aggressive' } } | Should -BeTrue
    }

    It 'needs BOTH halves (Network=None alone, or a ScreenConfig alone, is not a processor)' {
        Test-IsProcessorProfile -Profile @{ Network = 'None' } | Should -BeFalse
        Test-IsProcessorProfile -Profile @{ Network = 'Internal'; ScreenConfig = @{} } | Should -BeFalse
    }

    It 'is FALSE for a transport-only OutboxOutput profile (the firefox shape)' {
        Test-IsProcessorProfile -Profile @{ WorkloadMode = 'Disk'; OutboxOutput = $true } | Should -BeFalse
    }

    It 'accepts a pscustomobject as well as a hashtable, and is FALSE for $null (no throw)' {
        Test-IsProcessorProfile -Profile ([pscustomobject]@{ Network = 'None'; ScreenConfig = @{} }) | Should -BeTrue
        Test-IsProcessorProfile -Profile $null | Should -BeFalse
    }

    It 'every processor also uses the outbox transport (the two predicates agree)' {
        $p = @{ Network = 'None'; ScreenConfig = @{} }
        Test-IsProcessorProfile -Profile $p | Should -BeTrue
        Test-UsesOutboxTransport -Profile $p | Should -BeTrue -Because 'a processor releases through the outbox; if these disagreed, the seed and the host would route it differently'
    }
}

Describe 'Guest sizing keys: Memory / Cpu / CpuMaximumPercent / CpuRelativeWeight (E1)' {
    # Memory and Cpu were tier-only and unchecked ([int] casts at provision time). They are now bounded
    # at load for BOTH tier and merged workload profiles, and a workload may set them (they layer onto
    # the tier like Entrypoint). The two CPU cap keys are optional; absent means Hyper-V's defaults.

    Context 'tier profile bounds' {
        It 'ACCEPTS the Memory boundaries 512MB and 64GB (and the equivalent byte count)' {
            foreach ($mem in @('512MB', '64GB', '1024MB', '4 GB', 4GB)) {
                $h = script:Get-ValidTier1Hashtable
                $h.Memory = $mem
                $path = script:New-Psd1File -Data $h -Name ("mem-ok-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
                { Import-TierProfile -Path $path } | Should -Not -Throw -Because "Memory '$mem' is inside 512MB..64GB"
            }
        }

        It 'REJECTS Memory below 512MB, above 64GB, zero, unparseable or blank, naming the field' {
            foreach ($mem in @('511MB', '65GB', '128GB', '0', '0GB', 'lots', '')) {
                $h = script:Get-ValidTier1Hashtable
                $h.Memory = $mem
                $path = script:New-Psd1File -Data $h -Name ("mem-bad-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
                { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*Memory*' -Because "Memory '$mem' is outside 512MB..64GB or unparseable"
            }
        }

        It 'ACCEPTS Cpu 1 and 32, REJECTS 0, 33, a negative, a string and a fraction, naming the field' {
            foreach ($cpu in @(1, 32)) {
                $h = script:Get-ValidTier1Hashtable
                $h.Cpu = $cpu
                $path = script:New-Psd1File -Data $h -Name ("cpu-ok-$cpu.psd1")
                { Import-TierProfile -Path $path } | Should -Not -Throw
            }
            foreach ($cpu in @(0, 33, -2, '4', 2.5)) {
                $h = script:Get-ValidTier1Hashtable
                $h.Cpu = $cpu
                $path = script:New-Psd1File -Data $h -Name ("cpu-bad-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
                { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*Cpu*' -Because "Cpu '$cpu' is not an integer in 1..32"
            }
        }

        It 'ACCEPTS CpuMaximumPercent 1..100 and CpuRelativeWeight 1..10000, REJECTS outside values and non-integers' {
            foreach ($pair in @(@(1, 1), @(100, 10000), @(50, 250))) {
                $h = script:Get-ValidTier1Hashtable
                $h.CpuMaximumPercent = $pair[0]; $h.CpuRelativeWeight = $pair[1]
                $path = script:New-Psd1File -Data $h -Name ("cap-ok-{0}-{1}.psd1" -f $pair[0], $pair[1])
                $loaded = Import-TierProfile -Path $path
                $loaded.CpuMaximumPercent | Should -Be $pair[0]
                $loaded.CpuRelativeWeight | Should -Be $pair[1]
            }
            foreach ($bad in @(0, 101, -5, '50', 12.5, $true)) {
                $h = script:Get-ValidTier1Hashtable
                $h.CpuMaximumPercent = $bad
                $path = script:New-Psd1File -Data $h -Name ("capmax-bad-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
                { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*CpuMaximumPercent*' -Because "'$bad' is not an integer in 1..100"
            }
            foreach ($bad in @(0, 10001, -1, '100', 1.5, $false)) {
                $h = script:Get-ValidTier1Hashtable
                $h.CpuRelativeWeight = $bad
                $path = script:New-Psd1File -Data $h -Name ("capwgt-bad-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
                { Import-TierProfile -Path $path } | Should -Throw -ExpectedMessage '*CpuRelativeWeight*' -Because "'$bad' is not an integer in 1..10000"
            }
        }

        It 'treats absent cap keys as no cap (the shipped tiers carry neither)' {
            foreach ($tierPath in @($script:Tier0Path, $script:Tier1Path)) {
                $t = Import-TierProfile -Path $tierPath
                $t.ContainsKey('CpuMaximumPercent') | Should -BeFalse
                $t.ContainsKey('CpuRelativeWeight') | Should -BeFalse
            }
        }
    }

    Context 'workload layering' {
        It 'a workload Memory and Cpu REPLACE the tier values' {
            $wl = @{ BaseTier = 1; Name = 'sized'; Entrypoint = 'true'; Memory = '8GB'; Cpu = 6 }
            $wlPath = script:New-Psd1File -Data $wl -Name 'sized.psd1'
            $m = Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir
            $m.Memory | Should -Be '8GB'
            $m.Cpu    | Should -Be 6
        }

        It 'a workload that sets neither inherits the tier values' {
            $wl = @{ BaseTier = 1; Name = 'unsized'; Entrypoint = 'true' }
            $wlPath = script:New-Psd1File -Data $wl -Name 'unsized.psd1'
            $m = Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir
            $m.Memory | Should -Be '4GB'
            $m.Cpu    | Should -Be 4
        }

        It 'a workload cap overrides a tier cap, and an inherited tier cap survives when the workload is silent' {
            $scratch = Join-Path $TestDrive 'cap-tiers'
            New-Item -ItemType Directory -Path $scratch -Force | Out-Null
            $t = script:Get-ValidTier1Hashtable
            $t.CpuMaximumPercent = 80; $t.CpuRelativeWeight = 400
            Set-Content -LiteralPath (Join-Path $scratch 'tier1.psd1') -Value (script:ConvertTo-Psd1Text -Value $t) -Encoding UTF8

            $silent = script:New-Psd1File -Data @{ BaseTier = 1; Name = 'silent'; Entrypoint = 'true' } -Name 'silent-cap.psd1'
            $m = Import-WorkloadProfile -Path $silent -TierProfileDir $scratch
            $m.CpuMaximumPercent | Should -Be 80
            $m.CpuRelativeWeight | Should -Be 400

            $over = script:New-Psd1File -Data @{ BaseTier = 1; Name = 'over'; Entrypoint = 'true'; CpuMaximumPercent = 30 } -Name 'over-cap.psd1'
            $m2 = Import-WorkloadProfile -Path $over -TierProfileDir $scratch
            $m2.CpuMaximumPercent | Should -Be 30 -Because 'the workload wins'
            $m2.CpuRelativeWeight | Should -Be 400 -Because 'the workload did not set it, so the tier value stays'
        }

        It 'the same bounds apply to a workload value (merged re-validation)' {
            $cases = @(
                @{ Key = 'Memory';            Value = '65GB' },
                @{ Key = 'Memory';            Value = '256MB' },
                @{ Key = 'Cpu';               Value = 64 },
                @{ Key = 'CpuMaximumPercent'; Value = 150 },
                @{ Key = 'CpuRelativeWeight'; Value = 0 }
            )
            foreach ($c in $cases) {
                $wl = @{ BaseTier = 1; Name = 'oob'; Entrypoint = 'true' }
                $wl[$c.Key] = $c.Value
                $wlPath = script:New-Psd1File -Data $wl -Name ("oob-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
                { Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir } |
                    Should -Throw -ExpectedMessage "*$($c.Key)*" -Because "workload $($c.Key)=$($c.Value) is out of bounds"
            }
        }
    }
}

Describe 'WorkloadTimeoutSeconds profile key (E3)' {
    It 'layers a workload WorkloadTimeoutSeconds onto the merged profile' {
        $wl = @{ BaseTier = 1; Name = 'slow'; Entrypoint = 'true'; WorkloadTimeoutSeconds = 7200 }
        $wlPath = script:New-Psd1File -Data $wl -Name 'slow.psd1'
        (Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir).WorkloadTimeoutSeconds | Should -Be 7200
    }

    It 'is absent from the merged profile when the workload does not set it' {
        $wl = @{ BaseTier = 1; Name = 'quiet'; Entrypoint = 'true' }
        $wlPath = script:New-Psd1File -Data $wl -Name 'quiet.psd1'
        (Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir).ContainsKey('WorkloadTimeoutSeconds') | Should -BeFalse
    }

    It 'ACCEPTS the boundaries 60 and 86400' {
        foreach ($v in @(60, 86400)) {
            $wl = @{ BaseTier = 1; Name = "t$v"; Entrypoint = 'true'; WorkloadTimeoutSeconds = $v }
            $wlPath = script:New-Psd1File -Data $wl -Name "to-$v.psd1"
            { Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir } | Should -Not -Throw
        }
    }

    It 'REJECTS values outside 60..86400 and non-integers, naming the key' {
        foreach ($v in @(0, 59, 86401, -1, '600', 90.5, $true)) {
            $wl = @{ BaseTier = 1; Name = 'bad'; Entrypoint = 'true'; WorkloadTimeoutSeconds = $v }
            $wlPath = script:New-Psd1File -Data $wl -Name ("to-bad-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
            { Import-WorkloadProfile -Path $wlPath -TierProfileDir $script:TierDir } |
                Should -Throw -ExpectedMessage '*WorkloadTimeoutSeconds*' -Because "'$v' is not an integer in 60..86400"
        }
    }
}

Describe 'Unknown profile keys are refused (fail-closed)' {

    It 'refuses an unknown key in a workload profile, naming the key' {
        $wl = @{ BaseTier = 1; Name = 'typo'; Entrypoint = 'true'; Entrypont = 'oops' }
        $p = script:New-Psd1File -Data $wl -Name 'typo.psd1'
        { Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir } |
            Should -Throw -ExpectedMessage "*unknown key 'Entrypont'*"
    }

    It 'names every unknown key when there are several' {
        $wl = @{ BaseTier = 1; Name = 'many'; Entrypoint = 'true'; Alpha = 1; Beta = 2 }
        $p = script:New-Psd1File -Data $wl -Name 'many.psd1'
        { Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir } |
            Should -Throw -ExpectedMessage "*unknown keys*'Alpha'*'Beta'*"
    }

    It 'refuses an unknown key in a tier file' {
        $t = script:Get-ValidTier1Hashtable
        $t.Surprise = 'x'
        $p = script:New-Psd1File -Data $t -Name 'tier-surprise.psd1'
        { Import-TierProfile -Path $p } | Should -Throw -ExpectedMessage "*unknown key 'Surprise'*"
    }

    It 'matches key names case-insensitively, as the loader reads them' {
        $wl = @{ BASETIER = 1; name = 'cased'; entrypoint = 'true'; extraallowlist = @('example.com'); resultinnername = 'out.txt' }
        $p = script:New-Psd1File -Data $wl -Name 'cased.psd1'
        $m = Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir
        $m.Entrypoint | Should -Be 'true'
        @($m.EgressAllowlist) | Should -Contain 'example.com'
        $m.ResultInnerName | Should -Be 'out.txt'
    }

    It 'refuses a tier-owned key set from a workload and says where it belongs' {
        $wl = @{ BaseTier = 1; Name = 'weaken'; Entrypoint = 'true'; Credentials = 'None' }
        $p = script:New-Psd1File -Data $wl -Name 'weaken.psd1'
        { Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir } |
            Should -Throw -ExpectedMessage "*unknown key 'Credentials'*tier-owned*"
    }

    It 'checks the unknown key before the missing-key check, so a typo is named' {
        $wl = @{ BaseTier = 1; Name = 'typo2'; Entrypont = 'true' }
        $p = script:New-Psd1File -Data $wl -Name 'typo2.psd1'
        { Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir } |
            Should -Throw -ExpectedMessage "*unknown key 'Entrypont'*"
    }

    It 'Assert-KnownProfileKeys refuses an unknown key on a resolved profile hashtable' {
        $t = script:Get-ValidTier1Hashtable
        { Assert-KnownProfileKeys -Profile $t -Kind Resolved -Context 'fixture' } | Should -Not -Throw
        $t.ResultInnerNam = 'x'
        { Assert-KnownProfileKeys -Profile $t -Kind Resolved -Context 'fixture' } |
            Should -Throw -ExpectedMessage "*unknown key 'ResultInnerNam'*"
        # ExtraAllowlist is unioned away at merge time, so a RESOLVED profile never carries it.
        $u = script:Get-ValidTier1Hashtable
        $u.ExtraAllowlist = @('example.com')
        { Assert-KnownProfileKeys -Profile $u -Kind Resolved -Context 'fixture' } | Should -Throw -ExpectedMessage "*ExtraAllowlist*"
    }

    It 'every shipped tier and workload profile loads under the unknown-key rule' {
        foreach ($f in @(Get-ChildItem -LiteralPath $script:TierDir -Filter 'tier*.psd1')) {
            { Import-TierProfile -Path $f.FullName } | Should -Not -Throw -Because "tier-profiles/$($f.Name) ships with the repo"
        }
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $script:SkillRoot 'profiles') -Filter '*.psd1')) {
            { Import-WorkloadProfile -Path $f.FullName -TierProfileDir $script:TierDir } | Should -Not -Throw -Because "profiles/$($f.Name) ships with the repo"
        }
    }

    Context 'schema drift (SCHEMA.md and the loader list the same keys, table by table)' {
        BeforeAll {
            # Documented keys: every backticked identifier in the FIRST cell of a table row. The tier table
            # runs from its heading to the workload heading, the workload table from there to the
            # provision-time gate section. Each table is compared with ITS OWN loader list, in both
            # directions. The earlier union comparison let a key documented in the wrong table pass (the
            # tier-accepted WorkloadTimeoutSeconds was documented only as a workload key).
            $schemaText = Get-Content -LiteralPath (Join-Path $script:TierDir 'SCHEMA.md') -Raw
            $tierStart = $schemaText.IndexOf('## Tier-profile keys')
            $wlStart   = $schemaText.IndexOf('## Workload-profile keys')
            $end       = $schemaText.IndexOf('## Provision-time resource gate')
            $tierStart | Should -BeGreaterThan -1
            $wlStart   | Should -BeGreaterThan $tierStart
            $end       | Should -BeGreaterThan $wlStart
            function script:Get-DocumentedKeys {
                param([string] $Text)
                $keys = [System.Collections.Generic.List[string]]::new()
                foreach ($line in ($Text -split "`r?`n")) {
                    if ($line -notmatch '^\|\s*(?<cell>[^|]+?)\s*\|') { continue }
                    foreach ($m in [regex]::Matches($Matches['cell'], '`(?<k>[A-Za-z][A-Za-z0-9]*)`')) { $keys.Add($m.Groups['k'].Value) }
                }
                return @($keys | Sort-Object -Unique)
            }
            $script:DocumentedTierKeys     = @(script:Get-DocumentedKeys -Text $schemaText.Substring($tierStart, $wlStart - $tierStart))
            $script:DocumentedWorkloadKeys = @(script:Get-DocumentedKeys -Text $schemaText.Substring($wlStart, $end - $wlStart))
        }

        It 'parses a plausible number of documented keys from each table (the parser itself is sound)' {
            $script:DocumentedTierKeys     | Should -Contain 'EgressMode'
            $script:DocumentedTierKeys     | Should -Contain 'CpuMaximumPercent'
            $script:DocumentedWorkloadKeys | Should -Contain 'Entrypoint'
            $script:DocumentedWorkloadKeys | Should -Contain 'ResultInnerName'
            $script:DocumentedTierKeys.Count     | Should -BeGreaterThan 15
            $script:DocumentedWorkloadKeys.Count | Should -BeGreaterThan 20
        }

        It 'the tier table documents exactly the keys the loader accepts on a tier file (both directions)' {
            $tier = @((Get-ProfileSchemaKeys).Tier)
            @($script:DocumentedTierKeys | Where-Object { $tier -notcontains $_ }) |
                Should -BeNullOrEmpty -Because "the tier table documents keys the loader does not accept on a tier: $(@($script:DocumentedTierKeys | Where-Object { $tier -notcontains $_ }) -join ', ')"
            @($tier | Where-Object { $script:DocumentedTierKeys -notcontains $_ }) |
                Should -BeNullOrEmpty -Because "the loader accepts tier keys the tier table does not document: $(@($tier | Where-Object { $script:DocumentedTierKeys -notcontains $_ }) -join ', ')"
        }

        It 'the workload table documents exactly the keys the loader accepts in a workload file (both directions)' {
            $wl = @((Get-ProfileSchemaKeys).Workload)
            @($script:DocumentedWorkloadKeys | Where-Object { $wl -notcontains $_ }) |
                Should -BeNullOrEmpty -Because "the workload table documents keys the loader does not accept in a workload file: $(@($script:DocumentedWorkloadKeys | Where-Object { $wl -notcontains $_ }) -join ', ')"
            @($wl | Where-Object { $script:DocumentedWorkloadKeys -notcontains $_ }) |
                Should -BeNullOrEmpty -Because "the loader accepts workload keys the workload table does not document: $(@($wl | Where-Object { $script:DocumentedWorkloadKeys -notcontains $_ }) -join ', ')"
        }

        It 'EgressMode is a tier key only: not in the workload table, not accepted in a workload file' {
            $script:DocumentedTierKeys     | Should -Contain 'EgressMode'
            $script:DocumentedWorkloadKeys | Should -Not -Contain 'EgressMode'
            @((Get-ProfileSchemaKeys).Workload) | Should -Not -Contain 'EgressMode'
            @((Get-ProfileSchemaKeys).Resolved) | Should -Contain 'EgressMode' -Because 'a resolved profile carries the tier keys'
        }

        It 'the accepted lists come from the loader constants, not a second list' {
            $s = Get-ProfileSchemaKeys
            foreach ($k in $script:TierRequiredKeys)       { @($s.Tier) | Should -Contain $k }
            foreach ($k in $script:TierOptionalKeys)       { @($s.Tier) | Should -Contain $k }
            foreach ($k in $script:WorkloadLayeredKeys)    { @($s.Workload) | Should -Contain $k; @($s.Resolved) | Should -Contain $k }
            foreach ($k in $script:WorkloadMergeOnlyKeys)  { @($s.Workload) | Should -Contain $k; @($s.Resolved) | Should -Not -Contain $k }
        }
    }
}

Describe 'ResultInnerName is a layered workload key' {

    It 'layers a workload ResultInnerName onto the merged profile' {
        $wl = @{ BaseTier = 1; Name = 'named'; Entrypoint = 'true'; ResultInnerName = 'report.json' }
        $p = script:New-Psd1File -Data $wl -Name 'named.psd1'
        (Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir).ResultInnerName | Should -Be 'report.json'
    }

    It 'is absent from the merged profile when the workload does not set it' {
        $wl = @{ BaseTier = 1; Name = 'unnamed'; Entrypoint = 'true' }
        $p = script:New-Psd1File -Data $wl -Name 'unnamed.psd1'
        (Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir).ContainsKey('ResultInnerName') | Should -BeFalse
    }

    It 'refuses a name that is not a plain, non-reserved outbox file name' {
        foreach ($bad in @('..', '.', 'a/b.txt', 'a\b.txt', 'has space.txt', '', ('x' * 41), 'verdicts.json', 'Verdicts.JSON', 'workload.json')) {
            $wl = @{ BaseTier = 1; Name = 'badname'; Entrypoint = 'true'; ResultInnerName = $bad }
            $p = script:New-Psd1File -Data $wl -Name ("badname-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
            { Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir } |
                Should -Throw -ExpectedMessage '*ResultInnerName*' -Because "'$bad' is not an acceptable result name"
        }
    }

    It 'refuses a non-string ResultInnerName' {
        $wl = @{ BaseTier = 1; Name = 'intname'; Entrypoint = 'true'; ResultInnerName = 7 }
        $p = script:New-Psd1File -Data $wl -Name 'intname.psd1'
        { Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir } | Should -Throw -ExpectedMessage '*ResultInnerName*'
    }
}

Describe 'InputDiskSizeBytes, OutputDiskSizeBytes and DepsImageHash are schema keys' {

    It 'layers a workload InputDiskSizeBytes and OutputDiskSizeBytes onto the merged profile' {
        $wl = @{ BaseTier = 0; Name = 'sized'; Entrypoint = 'true'; InputDiskSizeBytes = 128MB; OutputDiskSizeBytes = 2GB }
        $p = script:New-Psd1File -Data $wl -Name 'sized.psd1'
        $m = Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir
        [long]$m.InputDiskSizeBytes  | Should -Be 128MB
        [long]$m.OutputDiskSizeBytes | Should -Be 2GB
    }

    It 'accepts the 64MB and 2TB bounds themselves' {
        foreach ($v in @(64MB, 2TB)) {
            $wl = @{ BaseTier = 0; Name = 'edge'; Entrypoint = 'true'; InputDiskSizeBytes = $v; OutputDiskSizeBytes = $v }
            $p = script:New-Psd1File -Data $wl -Name ("edge-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
            { Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir } | Should -Not -Throw -Because "$v bytes is inside 64MB..2TB"
        }
    }

    It 'refuses a disk size outside 64MB..2TB or that is not an integer, naming the key' {
        foreach ($key in @('InputDiskSizeBytes', 'OutputDiskSizeBytes')) {
            foreach ($bad in @(0, -1, (64MB - 1), (2TB + 1), 1.5, '1GB', $true)) {
                $wl = @{ BaseTier = 0; Name = 'badsize'; Entrypoint = 'true' }
                $wl[$key] = $bad
                $p = script:New-Psd1File -Data $wl -Name ("badsize-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
                { Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir } |
                    Should -Throw -ExpectedMessage "*field '$key' must be an integer in 64MB..2TB*" -Because "'$bad' is not an integer in 64MB..2TB"
            }
        }
    }

    It 'a bare tier file with a disk size key is accepted by the resolved-key list and bounds-checked' {
        $t = script:Get-ValidTier1Hashtable
        $t['InputDiskSizeBytes'] = 1GB
        { Assert-KnownProfileKeys -Profile $t -Kind Resolved -Context 'fixture' } | Should -Not -Throw
        { Assert-TierProfileValid -Profile $t -Context 'fixture' } | Should -Not -Throw
        $t['InputDiskSizeBytes'] = 1KB
        { Assert-TierProfileValid -Profile $t -Context 'fixture' } | Should -Throw -ExpectedMessage "*field 'InputDiskSizeBytes' must be an integer*"
    }

    It 'layers a workload DepsImageHash and accepts 64 hex characters in either case' {
        foreach ($h in @(('ab' * 32), ('AB' * 32), ('0123456789abcdefABCDEF' + ('0' * 42)))) {
            $wl = @{ BaseTier = 0; Name = 'hashed'; Entrypoint = 'true'; DepsImageHash = $h }
            $p = script:New-Psd1File -Data $wl -Name ("hashed-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
            (Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir).DepsImageHash | Should -Be $h
        }
    }

    It 'refuses a DepsImageHash that is not exactly 64 hex characters' {
        foreach ($bad in @('', 'abc', ('a' * 63), ('a' * 65), ('g' * 64), ('a' * 63 + ' '), ("`n" + ('a' * 64)), (('a' * 64) + "`n"), 7, $true)) {
            $wl = @{ BaseTier = 0; Name = 'badhash'; Entrypoint = 'true'; DepsImageHash = $bad }
            $p = script:New-Psd1File -Data $wl -Name ("badhash-{0}.psd1" -f ([guid]::NewGuid().ToString('N')))
            { Import-WorkloadProfile -Path $p -TierProfileDir $script:TierDir } |
                Should -Throw -ExpectedMessage "*field 'DepsImageHash' must be exactly 64 hex characters*" -Because "'$bad' is not 64 hex characters"
        }
    }

    It 'the new keys are on the layered list, so the unknown-key refusal accepts them' {
        foreach ($k in @('InputDiskSizeBytes', 'OutputDiskSizeBytes', 'DepsImageHash')) {
            $script:WorkloadLayeredKeys | Should -Contain $k
            @((Get-ProfileSchemaKeys).Resolved) | Should -Contain $k
        }
    }
}
