<#
.SYNOPSIS
    Voidseal — tier & workload profile loader + safety invariants.

.DESCRIPTION
    Dot-source this file to get two functions:

      Import-TierProfile    -Path <tierN.psd1>
      Import-WorkloadProfile -Path <workload.psd1> -TierProfileDir <dir>

    Both load a PowerShell data file (.psd1) via Import-PowerShellDataFile,
    validate it against tier-profiles/SCHEMA.md, and return a normalized
    [hashtable]. Any schema or safety-invariant violation THROWS with a
    message that names the violation (fail-closed).

    Enforced invariants (SCHEMA.md §"Loader invariants" 1-5 + basic schema 6):
      1. Secret-file mount refusal      (Assert-NoSecretMounts)
      2. Tier >= 2 starvation           (Credentials/EgressMode None, empty allowlist)
      3. Extraction by tier             (Tier >= 2 => ColdVHDX-Quarantine-CDR)
      4. VM-tier HostChannels all-false (HyperV-Gen2 => no $true channel)
      5. Linux guests => Com1Serial     (never PSDirect)
      6. Basic schema                   (required keys, Tier 0..3, enum membership)

    The runtime "pre-seal gate" (Assert-Sealed) is invariant #6 in SCHEMA.md's
    numbering and is built later — intentionally not implemented here.

    Pure validation: no Hyper-V calls, no filesystem reads of mount sources
    (paths are inspected as strings only — a secret file is NEVER opened/read).
#>

Set-StrictMode -Version Latest

# --------------------------------------------------------------------------
# Schema constants
# --------------------------------------------------------------------------

# Required keys for a tier profile (SCHEMA.md "Tier-profile keys", all required
# unless noted optional). Memory/Cpu both required.
$script:TierRequiredKeys = @(
    'Tier', 'Description', 'Substrate', 'Network', 'EgressMode', 'EgressAllowlist',
    'Credentials', 'GuestImage', 'Memory', 'Cpu', 'HostChannels', 'Capture',
    'Extraction', 'Lifecycle', 'Controls'
)

# Enum domains (SCHEMA.md type column).
$script:Enum_Substrate         = @('Container', 'HyperV-Gen2')
$script:Enum_EgressMode        = @('HostProxy', 'NftablesAllowlist', 'HostEnvoy', 'SquidSniProxy', 'None')
$script:Enum_Credentials       = @('None', 'ScopedOnDemand')
$script:Enum_ManagementChannel = @('Com1Serial', 'PSDirect')
$script:Enum_Extraction        = @('HostReadResultDir', 'ColdVHDX-Quarantine-CDR')
$script:Enum_Lifecycle         = @('Ephemeral', 'SnapshotRevert', 'CreateDestroy', 'DetonateWipe')
# The documented Hyper-V Set-VMFirmware -SecureBootTemplate values. OPTIONAL on a profile
# (neither shipped tier sets it on a container tier; absent = the provisioner omits the param
# = Hyper-V's default). When PRESENT and non-empty it MUST be one of these — an invalid value
# is a real Set-VMFirmware reject the fake would silently accept (the fake≠real bug class), so
# the loader fails closed here BEFORE provisioning ever reaches Hyper-V.
$script:Enum_SecureBootTemplate = @('MicrosoftWindows', 'MicrosoftUEFICertificateAuthority', 'OpenSourceShieldedVM')

# Builder (EgressMode='SquidSniProxy') derived-per-fetcher required hosts (Pass-5 §B). The
# completeness check requires, for EACH fetcher the DepsSpec declares, that the merged
# EgressAllowlist COVERS every representative host below (exact OR domain-suffix — the Squid
# domain-ACL model). Rotating CDN/LFS hostnames are covered by a suffix entry (e.g. '.hf.co').
$script:BuilderRequiredHostsByFetcher = @{
    Pip         = @('pypi.org', 'files.pythonhosted.org')
    Apt         = @('deb.debian.org', 'security.debian.org')
    HuggingFace = @('huggingface.co', 'cdn-lfs.huggingface.co', 'cas-bridge.xethub.hf.co')
    Github      = @('github.com', 'api.github.com', 'codeload.github.com',
                    'objects.githubusercontent.com', 'release-assets.githubusercontent.com')
}

# A Squid domain-ACL "covers" a host if:
#   - the entry is an exact match (e.g. 'pypi.org' covers 'pypi.org'), OR
#   - the entry starts with a leading dot (suffix entry) and the host ends with that suffix
#     (e.g. '.hf.co' covers 'cas-bridge.xethub.hf.co').
# An entry WITHOUT a leading dot covers ONLY itself; 'huggingface.co' does NOT cover
# 'cdn-lfs.huggingface.co' — that requires a '.huggingface.co' suffix entry.
function Test-AllowlistCoversHost {
    [OutputType([bool])]
    param([string[]] $Allowlist, [string] $HostName)
    $h = ([string]$HostName).ToLowerInvariant()
    foreach ($entry in @($Allowlist)) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        $raw = ([string]$entry).ToLowerInvariant()
        if ($raw.StartsWith('.')) {
            # Suffix entry: host must end with this suffix (e.g. '.hf.co' covers 'x.hf.co').
            $suffix = $raw.TrimStart('.')
            if ($h -eq $suffix -or $h.EndsWith('.' + $suffix)) { return $true }
        }
        else {
            # Exact entry: host must equal this exactly.
            if ($h -eq $raw) { return $true }
        }
    }
    return $false
}

# Required keys for a workload profile.
$script:WorkloadRequiredKeys = @('BaseTier', 'Name', 'Entrypoint')

# Linux guest-image detector (invariant 5).
$script:LinuxImageRegex = '(?i)(debian|ubuntu|alpine|fedora|remnux|linux)'

# --------------------------------------------------------------------------
# Secret-shaped path patterns — SINGLE SOURCE OF TRUTH (invariant 1).
# --------------------------------------------------------------------------
# Canonical human-readable list: tier-profiles/SCHEMA.md §1 ("Loader invariants").
# Keep these arrays IN SYNC with SCHEMA.md §1. Test-IsSecretPath AND the refusal
# throw message are both built from these — do not re-hardcode the list anywhere
# else (the matcher, the message, and the tests all derive from here so the
# exclusion set cannot drift). All entries are lowercase: matching case-folds the
# (already separator- and Windows-leaf-normalized) path before comparing.
#
# Leaf (filename) rules — PowerShell -like globs evaluated against the normalized
# final path segment. Bare names with no wildcard are exact-match globs.
$script:SecretLeafGlobs = @(
    '.env',                    # dotenv
    '.env.*',                  # .env.production, .env.local, ...
    '*.env',                   # app.env, prod.env, ...
    '*.pem',                   # PEM private keys / certs
    '*.key',                   # private keys
    '*.p12',                   # PKCS#12 bundles
    '*.pfx',                   # PFX bundles
    'id_rsa*',                 # id_rsa, id_rsa.pub (public key blocked by design), id_rsa_work, ...
    'credentials*.json',       # credentials.json, credentials-prod.json
    '.credentials.json',       # dotfile credentials
    '.npmrc',                  # npm auth token file
    '.pypirc',                 # PyPI upload creds
    '*-service-account.json'   # GCP service-account keys
)

# Directory-segment rules: any path segment EXACTLY equal to one of these makes
# the whole path secret-shaped (a .secrets/ or .ssh/ dir anywhere in the path).
$script:SecretDirSegments = @('.secrets', '.ssh')

# Adjacent directory/file pair rules: [parentSegment, childSegment]. Matches when
# 'parent' is immediately followed by 'child' (e.g. ~/.aws/credentials). Lowercase.
$script:SecretDirFilePairs = @(
    @('.aws',    'credentials'),
    @('.kube',   'config'),
    @('.docker', 'config.json')
)

# --------------------------------------------------------------------------
# Secret-shaped path detection (invariant 1)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Returns $true if a mount *source* path is secret-shaped and must be refused.
.DESCRIPTION
    Operates on the path STRING only — never opens the file. Case-insensitive.
    Normalizes both '/' and '\' to '\' so POSIX and Windows paths are caught.
#>
function Test-IsSecretPath {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    # Normalize separators to backslash; collapse runs; lowercase for matching.
    $norm = ($Path -replace '/', '\')
    $norm = ($norm -replace '\\+', '\')
    $lower = $norm.ToLowerInvariant()

    # All segments (for directory-based rules like \.ssh\ or .secrets). These are
    # NOT leaf-normalized — directory-segment rules match the on-disk dir name.
    # @() guards a single-segment path from unrolling to a scalar (StrictMode-safe .Count).
    $segments = @($lower -split '\\' | Where-Object { $_ -ne '' })

    # The final path segment (file or leaf dir name), then NORMALIZED for the
    # Windows-equivalence bypasses that resolve to the real secret file:
    #   - strip an NTFS Alternate Data Stream suffix  ("server.key:hidden" -> "server.key",
    #     ".env::$DATA" -> ".env"); a stream name opens the same base file.
    #   - strip trailing dots/spaces  ("server.pem." / ".env " -> "server.pem" / ".env");
    #     the Win32 path layer ignores them, so they reference the same file.
    # LEAF ONLY — the directory-segment rules above already ran on the raw segments.
    $leaf = ($lower -split '\\')[-1]
    $leaf = ($leaf -split ':')[0]      # strip NTFS ADS suffix (everything from the first ':')
    $leaf = $leaf.TrimEnd('. ')        # strip trailing dots/spaces (Windows ignores them)

    # --- directory / segment-based exclusions -----------------------------
    # Any path segment that IS a refused dir name (.secrets / .ssh) anywhere in the path.
    foreach ($seg in $script:SecretDirSegments) {
        if ($segments -contains $seg) { return $true }
    }
    # Adjacent parent/child pairs (~/.aws/credentials, ~/.kube/config, ~/.docker/config.json).
    for ($i = 0; $i -lt $segments.Count - 1; $i++) {
        foreach ($pair in $script:SecretDirFilePairs) {
            if ($segments[$i] -eq $pair[0] -and $segments[$i + 1] -eq $pair[1]) { return $true }
        }
    }

    # --- leaf (filename) glob-style exclusions ----------------------------
    # Every leaf rule is a -like glob in $script:SecretLeafGlobs (the single source
    # of truth); exact names like '.env' are wildcard-free globs that match exactly.
    foreach ($glob in $script:SecretLeafGlobs) {
        if ($leaf -like $glob) { return $true }
    }

    return $false
}

<#
.SYNOPSIS
    Invariant 1. Throws if any Mounts source path is secret-shaped.
.PARAMETER Mounts
    The (optional) Mounts hashtable: @{ <hostSource> = <guestTarget> }.
    KEYS are treated as the host source paths.
#>
function Assert-NoSecretMounts {
    [CmdletBinding()]
    param([AllowNull()] $Mounts, [string] $Context = 'profile')

    if ($null -eq $Mounts) { return }
    if (-not ($Mounts -is [System.Collections.IDictionary])) {
        throw "Invariant 1 (secret-file refusal): '$Context' Mounts must be a hashtable of host->guest paths."
    }
    # Build the human-readable pattern summary from the single source of truth so it
    # can never drift from what Test-IsSecretPath actually enforces (SCHEMA.md §1).
    $dirPairList = @($script:SecretDirFilePairs | ForEach-Object { "$($_[0])/$($_[1])" })
    $patternSummary = (@($script:SecretLeafGlobs) + @($script:SecretDirSegments | ForEach-Object { "$_/" }) + $dirPairList) -join ', '
    foreach ($src in @($Mounts.Keys)) {
        if (Test-IsSecretPath -Path ([string]$src)) {
            throw "Invariant 1 (secret-file refusal): '$Context' declares a secret-shaped mount source '$src'. Secret files ($patternSummary; trailing dots/spaces and NTFS ADS suffixes are normalized away) must never be mounted into a sandbox."
        }
    }
}

# --------------------------------------------------------------------------
# Shared validation (applied to a tier profile AND to a merged workload)
# --------------------------------------------------------------------------

function Assert-EnumMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Value,
        [Parameter(Mandatory)] [string[]] $Allowed,
        [Parameter(Mandatory)] [string] $Field,
        [string] $Context = 'profile'
    )
    if ($Allowed -cnotcontains $Value) {
        throw "Schema validation: '$Context' field '$Field' value '$Value' is not one of the allowed values: $($Allowed -join ', ')."
    }
}

<#
.SYNOPSIS
    Validates a (tier-shaped) profile hashtable against the schema + invariants 1-5.
    Used both for a bare tier profile and for the merged tier+workload result.
#>
function Assert-TierProfileValid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Profile,
        [string] $Context = 'profile'
    )

    # --- invariant 6 (basic schema): required keys -----------------------
    foreach ($key in $script:TierRequiredKeys) {
        if (-not $Profile.ContainsKey($key)) {
            throw "Schema validation: '$Context' is missing required key '$key'."
        }
    }

    # Tier int 0..3
    $tier = $Profile['Tier']
    if (-not (($tier -is [int]) -or ($tier -is [long]))) {
        throw "Schema validation: '$Context' field 'Tier' must be an integer (got '$tier')."
    }
    if ($tier -lt 0 -or $tier -gt 3) {
        throw "Schema validation: '$Context' field 'Tier' must be in range 0..3 (got $tier)."
    }

    # Enum membership.
    Assert-EnumMember -Value $Profile['Substrate']   -Allowed $script:Enum_Substrate   -Field 'Substrate'   -Context $Context
    Assert-EnumMember -Value $Profile['EgressMode']  -Allowed $script:Enum_EgressMode  -Field 'EgressMode'  -Context $Context
    Assert-EnumMember -Value $Profile['Credentials'] -Allowed $script:Enum_Credentials -Field 'Credentials' -Context $Context
    Assert-EnumMember -Value $Profile['Extraction']  -Allowed $script:Enum_Extraction  -Field 'Extraction'  -Context $Context
    Assert-EnumMember -Value $Profile['Lifecycle']   -Allowed $script:Enum_Lifecycle   -Field 'Lifecycle'   -Context $Context

    # EgressAllowlist must be an array (already normalized by caller, but re-check shape).
    $allowlist = @($Profile['EgressAllowlist'])

    # HostChannels must be a hashtable.
    if (-not ($Profile['HostChannels'] -is [System.Collections.IDictionary])) {
        throw "Schema validation: '$Context' field 'HostChannels' must be a hashtable."
    }

    # ManagementChannel is optional; if present it must be a valid enum value.
    $hasMgmt = $Profile.ContainsKey('ManagementChannel') -and ($null -ne $Profile['ManagementChannel'])
    if ($hasMgmt) {
        Assert-EnumMember -Value $Profile['ManagementChannel'] -Allowed $script:Enum_ManagementChannel -Field 'ManagementChannel' -Context $Context
    }

    # SecureBootTemplate is OPTIONAL; absent/empty = the provisioner omits the param (Hyper-V default).
    # When PRESENT and non-empty it MUST be one of the documented Set-VMFirmware values — an invalid
    # value is a real-Hyper-V reject the fake silently accepts (fake≠real), so fail closed at load.
    $hasSecureTmpl = $Profile.ContainsKey('SecureBootTemplate') -and
                     ($null -ne $Profile['SecureBootTemplate']) -and
                     (-not [string]::IsNullOrWhiteSpace([string]$Profile['SecureBootTemplate']))
    if ($hasSecureTmpl) {
        Assert-EnumMember -Value ([string]$Profile['SecureBootTemplate']) -Allowed $script:Enum_SecureBootTemplate -Field 'SecureBootTemplate' -Context $Context
    }

    # --- invariant 1: secret-file mount refusal --------------------------
    if ($Profile.ContainsKey('Mounts')) {
        Assert-NoSecretMounts -Mounts $Profile['Mounts'] -Context $Context
    }

    # --- invariant 2: Tier >= 2 starvation -------------------------------
    if ($tier -ge 2) {
        if ($Profile['Credentials'] -ne 'None') {
            throw "Invariant 2 (Tier>=2 starvation): '$Context' is Tier $tier but Credentials='$($Profile['Credentials'])'; Tier>=2 MUST set Credentials='None'."
        }
        if ($Profile['EgressMode'] -ne 'None') {
            throw "Invariant 2 (Tier>=2 starvation): '$Context' is Tier $tier but EgressMode='$($Profile['EgressMode'])'; Tier>=2 MUST set EgressMode='None'."
        }
        if ($allowlist.Count -ne 0) {
            throw "Invariant 2 (Tier>=2 starvation): '$Context' is Tier $tier but EgressAllowlist has $($allowlist.Count) entr$(if($allowlist.Count -eq 1){'y'}else{'ies'}); Tier>=2 MUST have an empty EgressAllowlist (@())."
        }
    }

    # --- invariant 3: Extraction by tier ---------------------------------
    if ($tier -ge 2 -and $Profile['Extraction'] -ne 'ColdVHDX-Quarantine-CDR') {
        throw "Invariant 3 (extraction by tier): '$Context' is Tier $tier but Extraction='$($Profile['Extraction'])'; Tier>=2 MUST use Extraction='ColdVHDX-Quarantine-CDR'."
    }

    # --- invariant 4: VM-tier HostChannels all-false ---------------------
    if ($Profile['Substrate'] -eq 'HyperV-Gen2') {
        foreach ($entry in $Profile['HostChannels'].GetEnumerator()) {
            if ($entry.Value -is [bool] -and $entry.Value -eq $true) {
                throw "Invariant 4 (VM-tier channels): '$Context' Substrate='HyperV-Gen2' but HostChannel '$($entry.Key)' is `$true; every boolean HostChannel on a HyperV-Gen2 tier MUST be `$false."
            }
        }
    }

    # --- invariant 5: Linux guests => Com1Serial -------------------------
    # Only binds when a ManagementChannel is declared (container tiers omit it).
    if ($hasMgmt -and ($Profile['GuestImage'] -match $script:LinuxImageRegex)) {
        if ($Profile['ManagementChannel'] -ne 'Com1Serial') {
            throw "Invariant 5 (Linux management): '$Context' GuestImage='$($Profile['GuestImage'])' is Linux but ManagementChannel='$($Profile['ManagementChannel'])'; a Linux guest MUST use ManagementChannel='Com1Serial' (PSDirect is Windows-guest-only)."
        }
    }

    # --- processor rule: Network='None' => EgressMode='None' + empty allowlist ------
    # A structurally no-NIC processor profile (Network='None') cannot simultaneously
    # request egress — there is no network interface to route traffic through. Enforced
    # as a fail-closed consistency check to catch accidental copy-paste from network-
    # capable profiles (the same mis-copy class that produced fake≠real divergences).
    if ($Profile['Network'] -eq 'None') {
        if ($Profile['EgressMode'] -ne 'None') {
            throw "Processor rule (Network=None): '$Context' sets Network='None' (no NIC) but EgressMode='$($Profile['EgressMode'])'; a no-network processor profile MUST set EgressMode='None'."
        }
        if ($allowlist.Count -ne 0) {
            throw "Processor rule (Network=None): '$Context' sets Network='None' (no NIC) but EgressAllowlist has $($allowlist.Count) entr$(if($allowlist.Count -eq 1){'y'}else{'ies'}); a no-network processor profile MUST have an empty EgressAllowlist (@())."
        }
    }

    # --- builder rule: EgressMode='SquidSniProxy' => DepsSpec present + derived-per-fetcher
    # allowlist completeness (D-1 guarded override + D-2 derived check, brainstorm 2026-06-29).
    # SquidSniProxy is the BUILDER egress (Pass-5: nftables can't runtime-FQDN-filter). A profile
    # selecting it MUST carry a non-empty DepsSpec, and its (merged) EgressAllowlist MUST COVER
    # every representative host for each fetcher the DepsSpec declares — else a live builder run
    # would reach an un-allowlisted host and stall. Fail closed at load, naming the gap.
    if ($Profile['EgressMode'] -eq 'SquidSniProxy') {
        if (-not $Profile.ContainsKey('DepsSpec') -or
            -not ($Profile['DepsSpec'] -is [System.Collections.IDictionary]) -or
            $Profile['DepsSpec'].Keys.Count -eq 0) {
            throw "Builder rule (SquidSniProxy): '$Context' sets EgressMode='SquidSniProxy' (the builder egress) but declares no DepsSpec; a builder profile MUST carry a non-empty DepsSpec hashtable."
        }
        $missing = [System.Collections.Generic.List[string]]::new()
        foreach ($fetcher in $Profile['DepsSpec'].Keys) {
            $fname = [string]$fetcher
            if (-not $script:BuilderRequiredHostsByFetcher.ContainsKey($fname)) {
                throw "Builder rule (SquidSniProxy): '$Context' DepsSpec declares unknown fetcher '$fname' (known: $($script:BuilderRequiredHostsByFetcher.Keys -join ', '))."
            }
            foreach ($reqHost in $script:BuilderRequiredHostsByFetcher[$fname]) {
                if (-not (Test-AllowlistCoversHost -Allowlist $allowlist -HostName $reqHost)) {
                    $missing.Add("$reqHost (fetcher '$fname')")
                }
            }
        }
        if ($missing.Count -gt 0) {
            throw "Builder rule (SquidSniProxy): '$Context' EgressAllowlist is INCOMPLETE for its DepsSpec — missing required host(s): $($missing -join '; '). Add them (or a covering domain suffix, e.g. '.hf.co') to the tier EgressAllowlist or the workload ExtraAllowlist."
        }
    }
}

# --------------------------------------------------------------------------
# Normalization helpers
# --------------------------------------------------------------------------

# Import-PowerShellDataFile returns a [hashtable]. An empty array literal @()
# in a .psd1 round-trips as @() (Count 0). We coerce allowlists to a clean
# [string[]] so downstream callers never see $null.
function ConvertTo-StringArray {
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

<#
.SYNOPSIS
    Returns the profile's ScreenConfig hashtable with missing defaults applied.
.DESCRIPTION
    Processor profiles carry an optional ScreenConfig key. When mode is absent
    or empty, defaults to 'aggressive'. When categories is absent, defaults to
    an empty array. StrictMode-safe: guards every key access with ContainsKey.
.PARAMETER Profile
    The (merged) profile hashtable.
.OUTPUTS
    [hashtable] with at least keys 'mode' and 'categories'.
#>
function Resolve-ScreenConfig {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [hashtable] $Profile)

    # Start from the profile's ScreenConfig when present; otherwise an empty table.
    $src = @{}
    if ($Profile.ContainsKey('ScreenConfig') -and ($null -ne $Profile['ScreenConfig']) -and
        ($Profile['ScreenConfig'] -is [System.Collections.IDictionary])) {
        foreach ($k in $Profile['ScreenConfig'].Keys) { $src[$k] = $Profile['ScreenConfig'][$k] }
    }

    # Apply defaults: mode defaults to 'aggressive'; categories defaults to @().
    if (-not $src.ContainsKey('mode') -or [string]::IsNullOrWhiteSpace([string]$src['mode'])) {
        $src['mode'] = 'aggressive'
    }
    if (-not $src.ContainsKey('categories') -or ($null -eq $src['categories'])) {
        $src['categories'] = @()
    }
    # Explicit array contract (StrictMode .Count safety): the RETURN always exposes
    # 'categories' as an array regardless of input shape. A hashtable value-copy already
    # preserves a 1-element array (it does NOT unroll like a function return), so this is
    # a harmless re-wrap today — it locks the contract against a future refactor that DID
    # introduce unrolling (single-element unrolling is the repo's documented #1 bug class).
    $src['categories'] = @($src['categories'])

    return $src
}

# --------------------------------------------------------------------------
# Public: Import-TierProfile
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Load + validate a tier profile (.psd1). Returns a normalized [hashtable].
.PARAMETER Path
    Path to a tierN.psd1 file.
#>
function Import-TierProfile {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Import-TierProfile: tier profile not found at path '$Path'."
    }

    try {
        $raw = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        throw "Import-TierProfile: failed to parse '$Path' as a PowerShell data file: $($_.Exception.Message)"
    }

    if (-not ($raw -is [System.Collections.IDictionary])) {
        throw "Import-TierProfile: '$Path' did not evaluate to a hashtable."
    }

    # Clone into a mutable hashtable + normalize the allowlist shape.
    # (Named $normalized, not $profile, to avoid shadowing the automatic $PROFILE.)
    $normalized = @{}
    foreach ($k in $raw.Keys) { $normalized[$k] = $raw[$k] }
    if ($normalized.ContainsKey('EgressAllowlist')) {
        # @() guards against single-element unrolling so the stored value is
        # always an array (Count works) even for a 1-FQDN allowlist.
        $normalized['EgressAllowlist'] = @(ConvertTo-StringArray $normalized['EgressAllowlist'])
    }

    $ctx = "tier profile '$([System.IO.Path]::GetFileName($Path))'"
    Assert-TierProfileValid -Profile $normalized -Context $ctx

    return $normalized
}

# --------------------------------------------------------------------------
# Public: Import-WorkloadProfile
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Load a workload profile, resolve its BaseTier to tier<N>.psd1, merge, and
    re-validate the merged result. Returns the merged [hashtable].
.DESCRIPTION
    Merge rules (SCHEMA.md "Workload-profile keys"):
      - ExtraAllowlist  UNIONS onto the tier's EgressAllowlist (deduped, case-insensitive).
      - Packages / Mounts / Entrypoint / StageAssets / Name / BaseTier layer onto the tier.
    The merged result is re-validated through Assert-TierProfileValid so a
    workload cannot smuggle in a secret mount or break Tier>=2 starvation.
.PARAMETER Path
    Path to the workload .psd1.
.PARAMETER TierProfileDir
    Directory holding tier0.psd1 .. tier3.psd1.
#>
function Import-WorkloadProfile {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $TierProfileDir
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Import-WorkloadProfile: workload profile not found at path '$Path'."
    }

    try {
        $raw = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        throw "Import-WorkloadProfile: failed to parse '$Path' as a PowerShell data file: $($_.Exception.Message)"
    }
    if (-not ($raw -is [System.Collections.IDictionary])) {
        throw "Import-WorkloadProfile: '$Path' did not evaluate to a hashtable."
    }

    $wlName = [System.IO.Path]::GetFileName($Path)

    # --- workload required keys (invariant 6 for the workload layer) ------
    foreach ($key in $script:WorkloadRequiredKeys) {
        if (-not $raw.ContainsKey($key)) {
            throw "Schema validation: workload '$wlName' is missing required key '$key'."
        }
    }

    $baseTier = $raw['BaseTier']
    if (-not (($baseTier -is [int]) -or ($baseTier -is [long]))) {
        throw "Schema validation: workload '$wlName' field 'BaseTier' must be an integer (got '$baseTier')."
    }

    # --- resolve BaseTier -> tier<N>.psd1 ---------------------------------
    $tierFile = Join-Path $TierProfileDir ("tier{0}.psd1" -f $baseTier)
    if (-not (Test-Path -LiteralPath $tierFile -PathType Leaf)) {
        throw "Import-WorkloadProfile: workload '$wlName' BaseTier=$baseTier resolves to no tier file (expected '$tierFile')."
    }

    # Load + validate the base tier first (fails closed on a bad tier file).
    $merged = Import-TierProfile -Path $tierFile

    # --- merge: union ExtraAllowlist onto EgressAllowlist (deduped) -------
    # NB: a single-element array returned from a function unrolls to a scalar at
    # the call site, so re-wrap with @() before touching .Count (StrictMode-safe).
    $baseAllow = @(ConvertTo-StringArray $merged['EgressAllowlist'])
    $extra     = @()
    if ($raw.ContainsKey('ExtraAllowlist')) { $extra = @(ConvertTo-StringArray $raw['ExtraAllowlist']) }

    if ($extra.Count -gt 0) {
        $seen   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $union  = [System.Collections.Generic.List[string]]::new()
        foreach ($fqdn in @($baseAllow) + @($extra)) {
            if ([string]::IsNullOrWhiteSpace($fqdn)) { continue }
            if ($seen.Add($fqdn)) { $union.Add($fqdn) }
        }
        $merged['EgressAllowlist'] = $union.ToArray()
    }
    else {
        $merged['EgressAllowlist'] = $baseAllow
    }

    # D-1 (guarded EgressMode override): a workload may override EgressMode ONLY to 'SquidSniProxy'
    # (the builder egress — strictly stricter than the tiers' nftables/proxy modes, so it can only
    # TIGHTEN egress, never weaken it). Any other workload-level EgressMode is refused: weakening
    # the isolation contract from the workload layer is forbidden (EgressMode is otherwise a tier
    # property). A workload that omits EgressMode inherits the tier's unchanged (ralph/firefox).
    if ($raw.ContainsKey('EgressMode') -and ([string]$raw['EgressMode'] -ne 'SquidSniProxy')) {
        throw "Import-WorkloadProfile: workload '$wlName' sets EgressMode='$($raw['EgressMode'])'; a workload may only override EgressMode to 'SquidSniProxy' (the builder egress). Other egress modes are tier-controlled."
    }

    # --- layer scalar/collection workload keys onto the tier --------------
    $merged['BaseTier'] = $baseTier
    $merged['Name']     = $raw['Name']

    # Disk-mode workload keys are layered too: WorkloadMode selects the disk-driven run path,
    # and Inputs / FileSystem / InputLabel / OutputLabel configure the INPUT/OUTPUT data disks that
    # New-WorkloadDisks creates. Without layering these, a 'Disk' workload profile (firefox.psd1)
    # would lose its mode + data-disk config in the merge and silently fall back to Serial.
    # DepsSpec / ScreenConfig / DepsDiskPath are processor-profile keys: DepsSpec carries the
    # dependency set the builder stages; ScreenConfig carries gate mode + categories;
    # DepsDiskPath carries the pre-built deps disk path (optional, resolved at runtime).
    foreach ($layerKey in @('Packages', 'Mounts', 'Entrypoint', 'StageAssets', 'SeedIso',
                            'WorkloadMode', 'Inputs', 'FileSystem', 'InputLabel', 'OutputLabel',
                            'EgressMode', 'DepsSpec', 'ScreenConfig', 'DepsDiskPath')) {
        if ($raw.ContainsKey($layerKey)) {
            $merged[$layerKey] = $raw[$layerKey]
        }
    }

    # --- re-validate the merged result (re-runs ALL invariants 1-6) ------
    $ctx = "merged workload '$wlName' (BaseTier $baseTier)"
    Assert-TierProfileValid -Profile $merged -Context $ctx

    return $merged
}
