<#
.SYNOPSIS
    Voidseal — Release Governor: host-side runs/day release rate cap (C2.6 backstop).

.DESCRIPTION
    Dot-source this file to get:

        Test-ReleaseAllowed -Profile <name> -LedgerPath <path> -Today <yyyy-MM-dd> -MaxReleasesPerDay <n>
        Register-Release    -Profile <name> -LedgerPath <path> -Today <yyyy-MM-dd>

    THE JOB (C2.6 — the third quantitative backstop behind the regenerator, after C2.4's
    schema/re-hash gates and C2.5's byte-budget): C2.4/C2.5 bound the leakage of a SINGLE run;
    C2.6 bounds AGGREGATE leakage across MANY runs (per-run bits x runs/interval). A host-side
    persistent JSON ledger, keyed by PROFILE NAME + UTC CALENDAR DAY, tracks how many times a
    profile's screener has RELEASED (see "RELEASE-EVENT SEMANTICS" below) today. Before a
    processor run's partition is allowed to write anything into released/, the caller (the gate,
    SensitivityGate.ps1) consults Test-ReleaseAllowed; over the cap -> the caller HOLDS
    EVERYTHING this run (heldReason='over-rate-cap') instead of releasing.

    RELEASE-EVENT SEMANTICS (decided + documented here, per the plan's requirement to pin the
    exact counting unit): the ledger counts RELEASE EVENTS, not individual released FILES and
    not gate INVOCATIONS. One Invoke-SensitivityGate run that ends with at least one file in
    .Released is ONE release event -> Register-Release is called ONCE for that run (never once
    per released file). A run whose .Released is empty (everything HELD — off-schema,
    hash-mismatch, over-byte-budget, not-SAFE, or itself over-rate-cap) is NOT a release event
    and MUST NOT increment the ledger — "the counter reflects releases, not attempts." This
    keeps the cap aligned with its stated purpose (aggregate leakage = per-run bit bound x
    number of runs that actually leaked something), independent of how many files a single
    run happened to bundle.

    THE LEDGER (host state, JSON, one entry point = -LedgerPath so tests / callers never touch
    global host state):
        {
          "<profile-name>": { "<yyyy-MM-dd>": <int count>, ... },
          ...
        }
    Per-profile, per-UTC-day (LOCKED design, plan Task C2.6 self-review fork #5): the cap is
    per-profile, not global, so an operator running multiple distinct processor profiles does
    not have one profile's volume starve another's budget. UTC is used throughout (never guest
    time, never host-local time) — the HOST-OBSERVED calendar day is the policy source per the
    threat model (a guest cannot influence what "today" means to the cap by lying about its
    clock, and host-local time would drift the reset boundary with the operator's timezone/DST).

    FAIL-CLOSED (Test-ReleaseAllowed):
      - Ledger file does not exist yet -> treated as a FRESH ledger (zero releases recorded for
        ANY profile/day) -> allowed under any cap >= 1. This is the only "absence is OK" case,
        and only because Register-Release deterministically CREATES the file on first use (see
        below) — so "missing" here always means "genuinely never released," not "state was lost."
      - Ledger file exists but cannot be parsed as JSON (corrupt), or an existing per-profile/
        per-day value is not a non-negative integer (malformed shape), or the path exists but
        cannot be read as a file (e.g. it is a directory) -> UNKNOWN state -> DENY. The caller
        cannot PROVE the profile is under-cap, so it must refuse to release — "cannot prove
        under-cap => refuse to release," never "assume zero and proceed."
      - A profile/day combination absent from an otherwise-valid ledger is genuinely zero
        releases for that combination (not a failure) -> allowed under any cap >= 1.

    FAIL-CLOSED (Register-Release):
      - The read-modify-write always re-reads the CURRENT on-disk ledger immediately before
        writing (no cached count), so back-to-back calls in the same process correctly
        accumulate rather than clobber each other.
      - A ledger that is present but corrupt/malformed is NOT silently overwritten with a fresh
        empty ledger (that would erase a real prior count and let the rate cap be bypassed by
        corrupting the file) — Register-Release THROWS instead, exactly like a missing-but-
        unwritable target directory throws. An increment that cannot be durably persisted must
        be a loud failure, never a silently-dropped one (a dropped increment would let a run
        release without ever counting against the cap).

    INJECTION: -LedgerPath is explicit (mirrors -ScreenerPath / -VerdictsPath in
    SensitivityGate.ps1) so tests point at a $TestDrive-scoped file and never touch real host
    state. -Today is an explicit 'yyyy-MM-dd' UTC-day STRING (never computed from the live wall
    clock inside this module) so tests are fully deterministic — a test can seed "yesterday" at
    the cap and assert "today" is unaffected without any wall-clock dependency or sleep. The
    orchestration caller (Invoke-Voidseal.ps1 / SensitivityGate.ps1's default wiring) is
    responsible for supplying the HOST's real `[datetime]::UtcNow.ToString('yyyy-MM-dd')` in
    production — never a guest-reported time (see module header above: host-observed time is
    the policy source per the threat model).

    Pure host-side file I/O: no Hyper-V calls, no Python dependency. This module is
    intentionally thin, mirroring SensitivityGate.ps1's own minimalism.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
    C2.6 — read the ledger and decide whether -Profile may release again on -Today.
.DESCRIPTION
    See the module header ("FAIL-CLOSED (Test-ReleaseAllowed)") for the exact decision table.
    Returns $true only when the ledger can be PROVEN to hold fewer than -MaxReleasesPerDay
    releases for -Profile on -Today (a missing ledger file, or a missing profile/day entry in
    an otherwise-valid ledger, both count as zero — everything else unreadable/malformed is a
    DENY, never an assumed zero).
#>
function Test-ReleaseAllowed {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Profile,
        [Parameter(Mandatory)] [string] $LedgerPath,
        [Parameter(Mandatory)] [string] $Today,
        [ValidateRange(1, [int]::MaxValue)] [int] $MaxReleasesPerDay = 5
    )

    $count = Get-LedgerCountOrFail -Profile $Profile -LedgerPath $LedgerPath -Today $Today
    # $null is the sentinel Get-LedgerCountOrFail returns for "could not prove the count" —
    # ANY unreadable/corrupt/malformed-shape ledger. Fail closed: DENY, never treat as zero.
    if ($null -eq $count) { return $false }

    return ($count -lt $MaxReleasesPerDay)
}

<#
.SYNOPSIS
    C2.6 — record ONE release event for -Profile on -Today (increment-by-one, create-if-absent).
.DESCRIPTION
    Call this EXACTLY ONCE per Invoke-SensitivityGate run whose .Released ended up non-empty —
    never per released file, never for a run that released nothing (including a run this same
    backstop just denied). See the module header's "RELEASE-EVENT SEMANTICS" section.
    Re-reads the ledger immediately before writing (no cached/stale count) so sequential calls
    accumulate correctly. Throws (never silently no-ops) if the ledger cannot be durably
    persisted afterward — a dropped increment would let a release go uncounted against the cap.
#>
function Register-Release {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Profile,
        [Parameter(Mandatory)] [string] $LedgerPath,
        [Parameter(Mandatory)] [string] $Today
    )

    $doc = Read-LedgerDocumentOrThrow -LedgerPath $LedgerPath

    # StrictMode-safe existence check: the indexer form (PSObject.Properties[<name>]) returns
    # $null for an absent property even when the object has ZERO properties, unlike
    # '.Properties.Name.Contains(...)', which throws under Set-StrictMode -Version Latest on a
    # property-less object (there is no '.Name' to enumerate). Mirrors the indexer idiom already
    # used elsewhere in this codebase (Runner.ps1/Sealer.ps1/SeedBuilder.ps1's Get-*Field
    # helpers) rather than introducing a second, StrictMode-fragile pattern.
    if ($null -eq $doc.PSObject.Properties[$Profile]) {
        $doc | Add-Member -NotePropertyName $Profile -NotePropertyValue ([pscustomobject]@{}) -Force
    }
    $profileNode = $doc.$Profile
    $dayProp = $profileNode.PSObject.Properties[$Today]
    $current = 0
    if ($null -ne $dayProp) { $current = [int]$dayProp.Value }
    if ($null -ne $dayProp) {
        $dayProp.Value = $current + 1
    } else {
        $profileNode | Add-Member -NotePropertyName $Today -NotePropertyValue ($current + 1) -Force
    }

    # -ErrorAction Stop: a directory that cannot be created, or a file that cannot be written
    # (e.g. its parent path is blocked by an existing FILE, not a directory — the "missing-but-
    # unwritable" case), must THROW rather than silently swallow the increment.
    $parent = Split-Path -Path $LedgerPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
    }
    $doc | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $LedgerPath -Encoding utf8 -ErrorAction Stop
}

# ---------------------------------------------------------------------------
# Internal helpers (not exported as "public API" by convention — mirrors SensitivityGate.ps1's
# Test-VerdictSchema being the one "internal but dot-sourceable" helper alongside its public
# Invoke-SensitivityGate entry point).
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
    Internal: parse -LedgerPath into a [pscustomobject] document, or throw if that is not
    durably possible (used by Register-Release, which must fail loudly rather than silently
    overwrite a corrupt ledger with a fresh empty one — see module header).
#>
function Read-LedgerDocumentOrThrow {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $LedgerPath)

    if (-not (Test-Path -LiteralPath $LedgerPath -PathType Leaf)) {
        # Genuinely absent (first use) -> a fresh empty document. (A path that EXISTS but is
        # not a Leaf — e.g. a directory — falls through to the Get-Content below and throws,
        # which is correct: that is an unreadable/blocked target, not "first use.")
        if (-not (Test-Path -LiteralPath $LedgerPath)) {
            return [pscustomobject]@{}
        }
    }

    # Raises a terminating error (Get-Content -ErrorAction Stop) on a directory / unreadable
    # path; ConvertFrom-Json -ErrorAction Stop raises on invalid JSON. Both propagate as a
    # THROW out of this function — callers that need fail-CLOSED-but-non-throwing (Test-
    # ReleaseAllowed) wrap this in try/catch (see Get-LedgerCountOrFail); Register-Release lets
    # it throw directly, since "cannot read the existing ledger to safely increment it" must be
    # a loud failure, never a silent fresh-ledger overwrite that would erase a real prior count.
    $raw = Get-Content -LiteralPath $LedgerPath -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return [pscustomobject]@{} }
    return (ConvertFrom-Json -InputObject $raw -ErrorAction Stop)
}

<#
.SYNOPSIS
    Internal: return -Profile's release count for -Today, or $null if the ledger cannot be
    trusted to prove that count (unreadable, corrupt JSON, or a malformed per-day value).
.DESCRIPTION
    $null is a deliberate sentinel distinct from 0 — Test-ReleaseAllowed treats $null as
    "DENY, cannot prove under-cap" and 0 as "genuinely zero releases so far today," per the
    module header's fail-closed decision table. Never conflate the two.
#>
function Get-LedgerCountOrFail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Profile,
        [Parameter(Mandatory)] [string] $LedgerPath,
        [Parameter(Mandatory)] [string] $Today
    )

    if (-not (Test-Path -LiteralPath $LedgerPath)) {
        # No ledger has ever been written -> zero releases recorded, for any profile/day.
        return 0
    }

    try {
        $doc = Read-LedgerDocumentOrThrow -LedgerPath $LedgerPath
    } catch {
        # Unreadable path (e.g. a directory) or invalid JSON -> cannot prove the count.
        return $null
    }

    $profileProp = $doc.PSObject.Properties[$Profile]
    if ($null -eq $profileProp) { return 0 }
    $profileNode = $profileProp.Value
    $dayProp = $null
    if ($null -ne $profileNode) { $dayProp = $profileNode.PSObject.Properties[$Today] }
    if ($null -eq $profileNode -or $null -eq $dayProp) {
        return 0
    }

    $raw = $dayProp.Value
    # A malformed shape (non-numeric, negative, or a nested object/array where a plain count is
    # expected) is untrustworthy -- fail closed rather than coerce/guess.
    $parsed = 0
    $isInt = [int]::TryParse([string]$raw, [ref]$parsed)
    if (-not $isInt -or $parsed -lt 0) { return $null }

    return $parsed
}
