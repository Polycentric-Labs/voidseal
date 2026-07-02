<#
.SYNOPSIS
    Voidseal — Sensitivity Gate: offline screener runner + artifact partitioner.

.DESCRIPTION
    Dot-source this file to get:

        # Run mode: execute the screener in-process and partition.
        Invoke-SensitivityGate -StagingDir <path> -OutputDir <path> [-Mode aggressive|moderate]
                               -ScreenerPath <path>

        # Consume mode: partition from a pre-existing verdicts file (in-guest-screen → host-partition).
        Invoke-SensitivityGate -StagingDir <path> -OutputDir <path> [-Mode aggressive|moderate]
                               -VerdictsPath <path>

    THE JOB:
      Run the offline Python screener (`guest/screener.py`) against a STAGING directory of
      candidate artifacts (Run mode), OR consume a verdicts.json produced in-guest (Consume mode),
      then PARTITION them into two output buckets:

          <OutputDir>/released/   — ONLY files the screener marked exactly 'SAFE'
          <OutputDir>/held/       — EVERYTHING else (HELD, ERROR, off-schema, or hash-mismatch)
          <OutputDir>/manifest/sensitivity-report.json  — HOST-REGENERATED partition record

    THE INVARIANT (released ⊆ SAFE):
      This is the non-negotiable security property of the gate. The only releasable verdict is
      the exact string 'SAFE'. HELD, ERROR, and any unrecognised verdict are HELD
      (fail-closed by construction). A belt-and-braces re-assertion throws immediately if the
      partition logic ever produces a violation — defence in depth against future code changes.

    C2.4 — REGENERATOR CORE (the load-bearing hardening on top of the base partition, gate side):
      an offline content screen cannot give an information-theoretic leakage bound against an
      adversarial producer that controls the released content (detection cannot bound leakage;
      regeneration can — see _dev/plans/2026-07-01-pre-phase6-hardening-plan.md, C2 header). So
      the host acts as a REGENERATOR, not a passive partitioner, on every Consume-mode verdict:
        1. Enum-schema validation (Test-VerdictSchema): a verdict with an unknown key (including
           a producer-supplied 'run_id' — never part of the schema), an out-of-enum verdict/
           error_code value, an off-vocabulary flag, or a malformed sha256 is UNTRUSTED -> HELD
           with heldReason='off-schema'. This confines the verdict channel to the fixed C2.1
           producer enum alphabet even against a malicious/buggy producer.
        2. Re-hash binding at release: immediately before copying a SAFE, schema-valid file into
           released/, the host re-hashes the STAGED bytes and releases ONLY if they match the
           verdict's own sha256; a mismatch -> HELD with heldReason='hash-mismatch' (closes the
           post-screen-swap / TOCTOU window between when the verdict was formed and when the gate
           runs).
        3. Host-generated run_id: a fresh GUID is minted per gate invocation and stamped on the
           regenerated report — NEVER a producer-supplied value (which would fail step 1 anyway).
        4. Regenerated released report: the report's 'released' array is built FRESH as
           [pscustomobject]@{name; sha256} for each released file — never the guest's raw verdict
           object — so a free-form value smuggled onto (or beside) a verdict has no path into the
           released surface. The consumed guest verdicts.json is still retained VERBATIM as an
           audit copy under manifest/verdicts.json (unchanged from pre-C2.4), and HELD entries in
           the report keep their full audit detail (including heldReason) — only the RELEASED
           section is regenerated to the minimal schema.
      All four are strictly-tightening: they can only narrow the releasable set relative to the
      pre-C2.4 partition, never widen it.

    C2.5 — RELEASED-BYTE BUDGET BACKSTOP (the second quantitative backstop behind the
    regenerator, layered strictly AFTER the C2.4 schema/re-hash gates on every Consume-mode
    verdict): the host caps what the SAFE partition may release on two axes —
    -MaxReleasedBytes (a per-artifact size cap; default 1 MiB / 1048576, a FORK for Allen,
    tunable at Phase 6) and -MaxReleasedFiles (a per-run releasable-file-count cap; default 16,
    also a FORK). A SAFE, schema-valid, hash-bound file that exceeds the size cap -> HELD with
    heldReason='over-byte-budget'; once a run has already released -MaxReleasedFiles files,
    every further candidate -> HELD with heldReason='over-file-budget' (fail-closed,
    hold-all-over-cap — there is no meaningful risk-priority ordering to pick a "least bad"
    excess file). Both caps are INCLUSIVE upper bounds (a file exactly AT the size cap, or
    exactly the Nth file AT the count cap, still releases). SACRED (tighten-only): this backstop
    can only move a would-have-released file to HELD — never the reverse; it never runs before,
    or in place of, the C2.4 schema/re-hash/regenerated-report gates.

    C2.6 — RUNS/DAY RELEASE RATE CAP BACKSTOP (the third quantitative backstop, an OPT-IN
    layer consulted ONCE per gate invocation, strictly BEFORE the per-file C2.4/C2.5 loop):
    where C2.4/C2.5 bound the leakage of a SINGLE run, C2.6 bounds AGGREGATE leakage across
    MANY runs of the same profile (per-run bit bound x runs/interval — see
    _dev/plans/2026-07-01-pre-phase6-hardening-plan.md, C2 header). Pass -RateLedgerPath (+
    -RateProfile, -RateToday, optionally -MaxReleasesPerDay) to enable it; omitting
    -RateLedgerPath skips the rate-cap check entirely (pre-C2.6 callers/tests are unaffected —
    this is an ADDITIVE backstop, never a mandatory global gate keyed on an implicit default
    path). When enabled, ReleaseGovernor.ps1's Test-ReleaseAllowed is consulted against a
    host-side JSON ledger keyed by -RateProfile + the UTC calendar day (-RateToday, injected —
    see ReleaseGovernor.ps1's header for why host-observed time, never guest time, is the
    policy source): if the profile is already AT or OVER -MaxReleasesPerDay releases for that
    day, this run's ENTIRE candidate set is routed to HELD with heldReason='over-rate-cap' —
    release NOTHING this run, before the C2.4 schema/re-hash gates even run per-file (fail-
    closed: an over-cap run must not leak a single byte, and a corrupt/unreadable ledger is
    treated identically to over-cap — Test-ReleaseAllowed's own fail-closed contract, see
    ReleaseGovernor.ps1). If the rate check passes (or is not enabled), the run proceeds through
    the normal C2.4/C2.5 gates; AFTER partitioning, if the rate cap was enabled AND this run's
    regenerated .Released ended up non-empty, EXACTLY ONE Register-Release call increments the
    ledger for -RateProfile/-RateToday — a "release event" is counted once per run that released
    something, never once per file and never for a run (including this run's own denial) that
    released nothing. SACRED (tighten-only): like C2.5, this backstop can only move a
    would-have-released run's files to HELD — it is layered strictly BEFORE the per-file gates
    (an over-cap run never even reaches the schema/re-hash/byte-budget checks), and it can never
    cause anything to release that the underlying per-file gates would not have already allowed.

    FAIL-CLOSED ON ERROR:
      Run mode: a non-zero screener exit code or a missing verdicts file means the screen did
      not complete → THROW, release nothing.
      Consume mode: a missing -VerdictsPath file → THROW, release nothing.
      In BOTH modes the file passes through the SAME traversal guard, completeness guard,
      exact-SAFE partition, and invariant re-assertion — the host does NOT trust the in-guest
      file any more than a locally-run screener file. (Architecture decision D1.)

    -Mode is passed through to the screener (Run mode only). The partition decision itself is
    mode-independent: only exact 'SAFE' releases. The 'moderate' review-queue refinement
    (UNCERTAIN → held-for-human-review sub-bucket) is deferred to a later task.

    INJECTION: -ScreenerPath is explicit so tests can point at the real script without
    hard-coding a relative path, and error tests can point at a nonexistent path to exercise
    the fail-closed branch without any mocking infrastructure.

    CONSUME MODE (production path): the in-guest screener runs offline against personal data,
    writes a verdicts.json to the OUTPUT disk, and the host consumes that file via -VerdictsPath.
    The consumed file is copied into the run's manifest/ dir as an audit record, then goes
    through the identical host-side guards as a screener-produced file.

    Pure host-side orchestration: no Hyper-V calls. This module is intentionally thin —
    it delegates ALL content classification to the screener process.
#>

Set-StrictMode -Version Latest

# C2.6 — pull in the runs/day release-rate-cap primitives (Test-ReleaseAllowed / Register-
# Release). Dot-sourced from the SAME directory (mirrors this file's own role as a standalone,
# independently-dot-sourceable module — every existing test Describe block dot-sources ONLY
# "SensitivityGate.ps1" today, so pulling ReleaseGovernor.ps1 in here, rather than requiring
# every caller/test to dot-source both files, keeps that contract unbroken). Idempotent: PS
# re-dot-sourcing the same file just redefines the same functions, so this is safe even if a
# caller ALSO explicitly dot-sources ReleaseGovernor.ps1 itself (as ReleaseGovernor.Tests.ps1's
# own Describe blocks do, to call Test-ReleaseAllowed/Register-Release directly).
. (Join-Path $PSScriptRoot 'ReleaseGovernor.ps1')

# ---------------------------------------------------------------------------
# C2.4 — REGENERATOR CORE. The host is the sole author of the RELEASED surface: it validates
# every consumed verdict against the SAME fixed enum schema the producer (guest/screener.py,
# C2.1) emits, re-hashes each file immediately before release, and builds the released report
# fresh from validated fields only — the guest's verdicts.json is never copied verbatim into
# the released report (it is retained ONLY as an audit copy under manifest/). Mirrored here
# (not imported) because this module is pure PowerShell with no Python dependency at load time;
# a drift between this mirror and screener.py's enums is caught by SensitivityGate.Tests.ps1's
# schema-validation Describe block plus the shared messy-drive fixture round-trip.
# ---------------------------------------------------------------------------
$script:VerdictSchema = @{
    VerdictEnum   = @('SAFE', 'HELD', 'ERROR')
    ErrorCodeEnum = @('NONE', 'EXTRACT_FAIL', 'OFF_SCHEMA', 'DETECTOR_ERROR', 'UNSUPPORTED')
    FlagVocab     = @('aws_key', 'credential', 'financial', 'health', 'ssn', 'email', 'pii', 'secret', 'entropy', 'other')
    AllowedKeys   = @('name', 'sha256', 'verdict', 'error_code', 'flags')
}

<#
.SYNOPSIS
    C2.4 — validate a single consumed verdict object against the fixed enum schema.
.DESCRIPTION
    Fail-closed schema gate: returns $true ONLY if the verdict is built EXACTLY from the
    pinned enum alphabet (Task C2.1's producer schema, mirrored above) — no unknown key
    (including a producer-supplied 'run_id', which is NOT part of the verdict schema; the
    host generates run_id itself, never trusting a producer-supplied value), no out-of-enum
    'verdict'/'error_code' value, no off-vocabulary 'flags' entry, and a well-formed 64-char
    lowercase-hex 'sha256'. Anything else -> $false, which routes the verdict to HELD with
    heldReason='off-schema' in the caller. This confines the verdict channel to the schema
    alphabet even against a malicious/buggy producer — the ONE place a careless widening of
    the accepted shape could reopen a free-form channel, so keep this strict and literal.
#>
function Test-VerdictSchema {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] $Verdict
    )
    $props = @($Verdict.PSObject.Properties.Name)
    # Exact key set match (not subset): an off-schema key (including a decoy 'run_id') fails
    # closed here. A MISSING required key also fails closed (fewer keys != a valid partial verdict).
    $extra   = @($props | Where-Object { $script:VerdictSchema.AllowedKeys -notcontains $_ })
    $missing = @($script:VerdictSchema.AllowedKeys | Where-Object { $props -notcontains $_ })
    if ($extra.Count -gt 0 -or $missing.Count -gt 0) { return $false }

    # CASE-SENSITIVE (-ccontains/-cnotmatch): PowerShell's default comparison operators are
    # case-INSENSITIVE, so without the 'c'-prefixed variants 'safe'/'Safe'/'SAFE_but_lowercase'
    # would all wrongly match the 'SAFE' enum member, an uppercase-hex sha256 would pass the
    # lowercase-hex shape check, etc. The producer (guest/screener.py) emits an EXACT alphabet
    # (uppercase enum members, lowercase hex sha256) — the host must reject any case variant as
    # off-schema, not silently normalize/accept it.
    if ($script:VerdictSchema.VerdictEnum -cnotcontains [string]$Verdict.verdict) { return $false }
    if ($script:VerdictSchema.ErrorCodeEnum -cnotcontains [string]$Verdict.error_code) { return $false }

    $sha = [string]$Verdict.sha256
    if ($sha -cnotmatch '^[0-9a-f]{64}$') { return $false }

    $flags = @($Verdict.flags)
    foreach ($f in $flags) {
        if ($script:VerdictSchema.FlagVocab -cnotcontains [string]$f) { return $false }
    }

    return $true
}

function Invoke-SensitivityGate {
<#
.SYNOPSIS
    Run the offline screener over $StagingDir and partition artifacts into released/held.
    Or consume a pre-existing verdicts file (in-guest-screen → host-partition production path).

.DESCRIPTION
    Orchestrates the three-phase gate in one of two input modes:

    Run mode (-ScreenerPath):
      1. Run screener.py → emit a per-file verdicts JSON.
      2. Partition: copy SAFE files to <OutputDir>/released/, everything else to /held/.
      3. Assert released ⊆ SAFE (belt-and-braces re-check before writing the manifest).

    Consume mode (-VerdictsPath):
      1. Copy the supplied verdicts file into the run's manifest/ dir (audit record).
      2. Partition using the IDENTICAL traversal guard, completeness guard, exact-SAFE
         partition, and invariant re-assertion as Run mode — the host does NOT trust the
         in-guest-produced file any more than a locally-run screener file (D1).

    Throws on any screener failure, missing verdicts file, or invariant violation.
    Returns a [pscustomobject] with .Released, .Held, .ManifestPath for callers that need
    to act on the partition result (e.g. a pipeline that gates the next stage on .Released).

.PARAMETER StagingDir
    Directory of candidate artifacts to screen. Must exist; files are read-only by the screener.

.PARAMETER OutputDir
    Root output dir. Subdirs released/, held/, and manifest/ are created here.

.PARAMETER Mode
    Screener mode passed through to screener.py (Run mode only). 'aggressive' (default) is
    fail-closed. The partition decision itself is mode-independent: only exact 'SAFE' releases.

.PARAMETER ScreenerPath
    (Run mode) Absolute path to screener.py. Explicit to keep test injection clean.

.PARAMETER VerdictsPath
    (Consume mode) Absolute path to a verdicts.json produced in-guest. The file is copied
    into the run's manifest/ dir as an audit record, then goes through the identical
    host-side guards as a screener-produced file (traversal guard, completeness guard,
    exact-SAFE partition, invariant re-assertion). Fail-closed: throws if the file is absent.

.PARAMETER MaxReleasedBytes
    C2.5 backstop. Per-artifact size cap in bytes (inclusive upper bound); a SAFE file over
    this size is HELD with heldReason='over-byte-budget'. Default 1048576 (1 MiB) — a FORK for
    Allen, tunable at Phase 6; injectable so tests pin behavior without a hard-coded constant.

.PARAMETER MaxReleasedFiles
    C2.5 backstop. Per-run releasable-file-count cap (inclusive upper bound); once this many
    files have released in the current run, every further SAFE candidate is HELD with
    heldReason='over-file-budget'. Default 16 — a FORK for Allen, tunable at Phase 6.

.PARAMETER RateLedgerPath
    C2.6 backstop, OPT-IN. Path to the host-side runs/day release-rate JSON ledger (see
    ReleaseGovernor.ps1). Omit to skip the rate-cap check entirely (unchanged pre-C2.6
    behavior). When supplied, -RateProfile and -RateToday become effectively required (the
    rate check needs both to look up the right ledger entry) — this is intentionally NOT
    enforced via ParameterSetName so a caller who supplies -RateLedgerPath alone gets a clear
    runtime error rather than a confusing parameter-set resolution failure.

.PARAMETER RateProfile
    C2.6 backstop. The profile name the ledger is keyed by (e.g. 'ralph'). Required when
    -RateLedgerPath is supplied.

.PARAMETER RateToday
    C2.6 backstop. The UTC calendar day ('yyyy-MM-dd') to check/increment against. INJECTED
    (never computed from the live wall clock inside this module) so tests are deterministic;
    the production caller (Invoke-Voidseal.ps1) is responsible for supplying the HOST's real
    [datetime]::UtcNow.ToString('yyyy-MM-dd') — never guest-reported time. Required when
    -RateLedgerPath is supplied.

.PARAMETER MaxReleasesPerDay
    C2.6 backstop. Per-profile, per-UTC-day release-event cap (inclusive upper bound; a
    profile already AT this many releases today is denied the next one). Default 5 — a FORK
    for Allen, tunable at Phase 6. Only consulted when -RateLedgerPath is supplied.

.OUTPUTS
    [pscustomobject] @{ Released=[array]; Held=[array]; ManifestPath=[string] }
    where Released/Held are arrays of the screener's verdict objects ({name,verdict,detectors}).
#>
    [CmdletBinding(DefaultParameterSetName='Run')]
    param(
        [Parameter(Mandatory)] [string] $StagingDir,
        [Parameter(Mandatory)] [string] $OutputDir,
        [ValidateSet('aggressive','moderate')] [string] $Mode = 'aggressive',
        [Parameter(Mandatory, ParameterSetName='Run')]     [string] $ScreenerPath,
        [Parameter(Mandatory, ParameterSetName='Consume')] [string] $VerdictsPath,
        # C2.5 — released-byte budget backstop. FORK (Allen, plan Task C2.5): these are
        # conservative placeholder defaults, tunable at Phase 6 — NOT a claim that 1 MiB / 16
        # files is the production number. Injectable so tests pin behavior without hard-coding
        # a production constant (mirrors -ScreenerPath's injection pattern).
        [ValidateRange(1, [long]::MaxValue)] [long] $MaxReleasedBytes = 1048576,
        [ValidateRange(1, [int]::MaxValue)]  [int]  $MaxReleasedFiles = 16,
        # C2.6 — runs/day release rate cap backstop. OPT-IN: omitting -RateLedgerPath skips the
        # check entirely (see the .PARAMETER doc block above + the C2.6 module-header section).
        [string] $RateLedgerPath,
        [string] $RateProfile,
        [string] $RateToday,
        [ValidateRange(1, [int]::MaxValue)] [int] $MaxReleasesPerDay = 5
    )

    # C2.6 — validate the opt-in trio together (NOT via ParameterSetName; -RateLedgerPath can
    # legitimately combine with EITHER -ScreenerPath OR -VerdictsPath, and PowerShell parameter
    # sets are one-dimensional, so layering a second set here would force an awkward 4-way
    # cross-product). A caller that supplies -RateLedgerPath without both -RateProfile and
    # -RateToday cannot be safely evaluated (there is no ledger KEY) — fail closed with a clear
    # message rather than silently skipping the rate check the caller explicitly asked to enable.
    $rateCapEnabled = -not [string]::IsNullOrWhiteSpace($RateLedgerPath)
    if ($rateCapEnabled -and ([string]::IsNullOrWhiteSpace($RateProfile) -or [string]::IsNullOrWhiteSpace($RateToday))) {
        throw ("Invoke-SensitivityGate: -RateLedgerPath was supplied but -RateProfile/-RateToday " +
               "were not — the rate cap needs both to identify the ledger entry. Fail closed.")
    }

    # Create output subdirs unconditionally — fail-closed means these exist even when we throw
    # below, so the caller can inspect an empty released/ to confirm nothing escaped.
    $released = Join-Path $OutputDir 'released'
    $held     = Join-Path $OutputDir 'held'
    $man      = Join-Path $OutputDir 'manifest'
    foreach ($d in @($released, $held, $man)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }

    $vjson = Join-Path $man 'verdicts.json'

    # Phase 1: produce (or acquire) the verdicts file.
    # Both paths lead to $vjson existing in the manifest dir before the shared parse/partition.
    if ($PSCmdlet.ParameterSetName -eq 'Run') {
        # Run mode: execute the screener and capture its output.
        # Capture stdout+stderr together so we can surface the diagnostic in the throw message.
        # The screener writes its JSON to --out $vjson directly; we are not parsing stdout.
        # FAIL CLOSED: any non-zero exit means classification is incomplete => throw, release nothing.
        # NOTE: the python executable ('python' on the host, 'python3' in-guest) and the gate's
        # production runtime location (host vs in-guest) are wired in Phase 1 — out of scope here.
        $screenerOutput = & python $ScreenerPath --in $StagingDir --out $vjson --mode $Mode 2>&1
        if ($LASTEXITCODE -ne 0) {
            # $screenerOutput can be $null/empty (a screener that exits non-zero silently). Coerce to a
            # human-readable placeholder so the diagnostic never renders a bare 'Output: '.
            $so = if ([string]::IsNullOrWhiteSpace([string]$screenerOutput)) { '(no output)' } else { [string]$screenerOutput }
            throw ("Invoke-SensitivityGate: screener failed (exit $LASTEXITCODE) — fail closed, " +
                   "nothing released. Output: $so")
        }
        if (-not (Test-Path -LiteralPath $vjson)) {
            throw ("Invoke-SensitivityGate: screener exited 0 but produced no verdicts file at " +
                   "'$vjson' — fail closed, nothing released.")
        }
    } else {
        # Consume mode: the verdicts file was produced in-guest; the host ingests it here.
        # FAIL CLOSED: if the file is absent, there is nothing to partition against => throw.
        if (-not (Test-Path -LiteralPath $VerdictsPath)) {
            throw ("Invoke-SensitivityGate: verdicts file not found at '$VerdictsPath' — " +
                   "fail closed, nothing released.")
        }
        # Copy the consumed file into the manifest dir so the run's audit record is self-contained.
        # -ErrorAction Stop: a failed copy is a hard failure, not a swallowed error.
        Copy-Item -LiteralPath $VerdictsPath -Destination $vjson -ErrorAction Stop
    }

    # Phase 2: partition.
    # Wrap with @(...) so ConvertFrom-Json single-element returns a real array, not a scalar
    # — Set-StrictMode -Version Latest would blow up on .Count of a scalar otherwise.
    $verdicts = @(Get-Content $vjson -Raw | ConvertFrom-Json)

    # Fail-closed hardening (defense in depth): the screener emits BASENAMES only (its p.name). A
    # verdict 'name' that is not a plain leaf — empty, or containing a path separator / '..' / drive /
    # rooted path — is anomalous (a tampered or out-of-contract verdicts file). REFUSE the entire
    # partition rather than risk copying a file from OUTSIDE the staging dir into released/. This is
    # layered ON TOP of the exact-'SAFE' release rule: even a SAFE-marked traversal name cannot
    # exfiltrate an unscreened external file. Run this pass over ALL verdicts BEFORE any Copy-Item,
    # so the partition is clean all-or-nothing — nothing is copied if any single name is anomalous.
    foreach ($v in $verdicts) {
        $nm = [string]$v.name
        if ([string]::IsNullOrWhiteSpace($nm) -or ($nm -ne (Split-Path -Path $nm -Leaf))) {
            throw "Invoke-SensitivityGate: verdict name '$nm' is not a plain filename (path separator / traversal) — fail closed, refusing the partition."
        }
    }

    # Fail-closed completeness: the screener must have produced a verdict for EVERY file in staging.
    # A staged file with no verdict would otherwise be silently dropped (neither released nor held) —
    # the gate must not trust the screener's completeness. Compare top-level basenames (flat-staging
    # design, consistent with the screener's p.name + the traversal guard). OrdinalIgnoreCase to match
    # Windows path semantics. An unaccounted staged file => REFUSE.
    $verdictNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($v in $verdicts) { [void]$verdictNames.Add([string]$v.name) }
    foreach ($f in @(Get-ChildItem -LiteralPath $StagingDir -File)) {
        if (-not $verdictNames.Contains($f.Name)) {
            throw "Invoke-SensitivityGate: staged file '$($f.Name)' has no screener verdict — the screen is incomplete. Fail closed, refusing the partition."
        }
    }

    # C2.4 — host-generated run_id. Generated ONCE per gate invocation, NEVER derived from or
    # trusted from any producer-supplied field (a verdict carrying its own 'run_id' key is itself
    # off-schema per Test-VerdictSchema's exact-key-set check above, so a decoy can never survive
    # to this point anyway — this is the second, independent layer: even if schema validation were
    # ever weakened, the regenerated report below only ever writes THIS host-generated value).
    $runId = [guid]::NewGuid().ToString()

    # C2.6 — runs/day release rate cap (THIRD backstop; consulted ONCE, before the per-file
    # loop, not per-candidate). When enabled (-RateLedgerPath supplied), an over-cap or
    # unprovable (corrupt/unreadable) ledger means this ENTIRE run releases nothing — every
    # candidate is routed to HELD with heldReason='over-rate-cap' regardless of how clean its
    # own verdict is, BEFORE the C2.4 schema/re-hash checks even run. This mirrors C2.5's
    # fail-closed hold-all-over-cap posture: there is no meaningful "release the first N anyway"
    # partial-allow here — the cap is per-RUN (a run either may release or may not), not
    # per-file. $rateCapDenied gates the loop below; the C2.4/C2.5 per-file logic is UNCHANGED
    # when the rate cap is disabled (default) or under-cap.
    $rateCapDenied = $false
    if ($rateCapEnabled) {
        $rateCapDenied = -not (Test-ReleaseAllowed -Profile $RateProfile -LedgerPath $RateLedgerPath `
                                 -Today $RateToday -MaxReleasesPerDay $MaxReleasesPerDay)
    }

    $rel = [System.Collections.Generic.List[object]]::new()
    $hel = [System.Collections.Generic.List[object]]::new()

    # C2.5 — released-byte budget backstop. This is the SECOND backstop behind the regenerator
    # (C2.4): even a schema-valid, hash-bound, exact-SAFE file is capped on a per-artifact SIZE
    # and on the RUN'S total releasable FILE COUNT. Both caps are inclusive upper bounds (a file
    # exactly AT -MaxReleasedBytes, or the Nth file exactly AT -MaxReleasedFiles, still releases).
    # Over either cap -> HELD (fail-closed; "lowest-risk-first" ordering is not meaningful here,
    # so ALL excess-over-the-count-cap candidates are held, not just the last one in). This is
    # SACRED-tightening-only: the budget can only move a would-have-released file to HELD, never
    # the reverse — it is layered strictly AFTER the schema/re-hash gates below, never before.
    $releasedCount = 0

    foreach ($v in $verdicts) {
        $src = Join-Path $StagingDir $v.name

        # C2.6 step 0 — runs/day rate cap, checked FIRST (before C2.4's own schema/re-hash
        # gates): an over-cap/unprovable-ledger run holds EVERY candidate, independent of that
        # candidate's own verdict validity. Skipping straight to HELD here (rather than falling
        # through into the schema check) is deliberate — heldReason must read 'over-rate-cap'
        # for the WHOLE run, not get overwritten by a coincidental 'off-schema' on some entries
        # and 'over-rate-cap' on others, which would obscure the actual reason nothing released.
        if ($rateCapDenied) {
            Copy-Item -LiteralPath $src -Destination $held -ErrorAction Stop
            $hel.Add(($v | Select-Object *, @{Name='heldReason'; Expression={'over-rate-cap'}}))
            continue
        }

        # C2.4 step 1 — enum-schema validation (REGENERATOR CORE). A verdict that is not built
        # EXACTLY from the fixed producer enum (unknown key, out-of-enum verdict/error_code, an
        # off-vocabulary flag, or a malformed sha256) is UNTRUSTED — route it to HELD with
        # heldReason='off-schema' rather than trusting/copying it. This confines the verdict
        # channel to the schema alphabet even against a malicious producer (the alphabet stays
        # fixed regardless of what free-form content a compromised/buggy guest tries to smuggle).
        if (-not (Test-VerdictSchema -Verdict $v)) {
            Copy-Item -LiteralPath $src -Destination $held -ErrorAction Stop
            $hel.Add(($v | Select-Object *, @{Name='heldReason'; Expression={'off-schema'}}))
            continue
        }

        # The ONE releasable verdict is the exact string 'SAFE'. HELD/ERROR (and any value that
        # somehow slipped past schema validation) → HELD (fail-closed). CASE-SENSITIVE (-cne):
        # a lowercase/mixed-case 'safe'/'Safe' must never satisfy this check.
        if ($v.verdict -cne 'SAFE') {
            Copy-Item -LiteralPath $src -Destination $held -ErrorAction Stop
            $hel.Add($v)
            continue
        }

        # C2.4 step 2 — re-hash binding (closes the P1#3 TOCTOU / post-screen swap). Re-hash the
        # STAGED file's bytes immediately before release and compare against the verdict's own
        # (schema-validated, well-formed) sha256. A mismatch means the bytes on disk right now are
        # NOT provably what the screener evaluated — release nothing for this file; HELD instead.
        $want = [string]$v.sha256
        $got  = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($got -ne $want) {
            Copy-Item -LiteralPath $src -Destination $held -ErrorAction Stop
            $hel.Add(($v | Select-Object *, @{Name='heldReason'; Expression={'hash-mismatch'}}))
            continue
        }

        # C2.5 step 1 — per-artifact size cap. An oversize file is a backstop HOLD regardless of
        # how clean the verdict is (schema-valid, hash-bound, exact-SAFE). Measure the STAGED
        # file's actual on-disk length — the same bytes the re-hash gate above just confirmed
        # match the verdict — never a producer-claimed size field (there is no such field; the
        # verdict schema has none, by design).
        $sizeBytes = (Get-Item -LiteralPath $src).Length
        if ($sizeBytes -gt $MaxReleasedBytes) {
            Copy-Item -LiteralPath $src -Destination $held -ErrorAction Stop
            $hel.Add(($v | Select-Object *, @{Name='heldReason'; Expression={'over-byte-budget'}}))
            continue
        }

        # C2.5 step 2 — releasable file-count cap. Fail-closed / hold-all-over-cap: once the
        # run has already accepted $MaxReleasedFiles releases, EVERY further candidate this run
        # — no matter how clean — is HELD. There is no meaningful "lowest risk first" ordering
        # to prioritize by, so the cap is enforced strictly in verdicts-array order.
        if ($releasedCount -ge $MaxReleasedFiles) {
            Copy-Item -LiteralPath $src -Destination $held -ErrorAction Stop
            $hel.Add(($v | Select-Object *, @{Name='heldReason'; Expression={'over-file-budget'}}))
            continue
        }

        # -ErrorAction Stop makes a failed copy THROW rather than emit a swallowed non-terminating
        # error: without it, a missing source file would let $rel.Add run anyway, so .Released /
        # the manifest would CLAIM a release that never hit disk. Fail closed — record a release
        # only AFTER the copy is confirmed.
        Copy-Item -LiteralPath $src -Destination $released -ErrorAction Stop
        $rel.Add($v)
        $releasedCount++
    }

    # Phase 3: belt-and-braces re-assertion of the released ⊆ SAFE invariant.
    # This SHOULD be unreachable given the loop above, but defends against future edits that
    # accidentally widen the releasable set (e.g. adding an OR branch). We throw rather than
    # emit a silently-corrupted partition. CASE-SENSITIVE (-cne): a case-variant verdict is a
    # violation of the exact-alphabet contract, not a valid SAFE.
    $violation = @($rel | Where-Object { $_.verdict -cne 'SAFE' })
    if ($violation.Count -gt 0) {
        throw ("Invoke-SensitivityGate: INVARIANT VIOLATION — a non-SAFE artifact reached " +
               "'released'. Fail closed. Violators: " +
               ($violation | ForEach-Object { "$($_.name)=$($_.verdict)" } | Join-String -Separator ', '))
    }

    # C2.4 step 4 — REGENERATE the released report from a HOST/TCB template parameterized ONLY by
    # validated enum values + the host run_id + released name/sha256. The guest's verdicts.json
    # bytes are NEVER copied verbatim into this report — building each released entry as a FRESH
    # [pscustomobject] with a hard-coded field set means a free-form value on an (already-rejected)
    # off-schema verdict has no path into the released surface, and even a SAFE, schema-valid
    # verdict's released entry carries only 'name'/'sha256' (verdict/error_code/flags are HELD-side
    # audit detail, not part of the regenerated released report). The consumed guest verdicts.json
    # remains available as an audit copy under manifest/verdicts.json (written above, unchanged) —
    # it is not part of, and never referenced by, the released/ dir.
    $regeneratedReleased = @($rel | ForEach-Object {
        [pscustomobject]@{ name = [string]$_.name; sha256 = [string]$_.sha256 }
    })

    # C2.6 — increment the rate-cap ledger IFF (a) the rate cap is enabled for this call AND
    # (b) this run actually released at least one file. This is the ONE place Register-Release
    # is invoked: exactly once per run that released something, never once per file (see the
    # "RELEASE-EVENT SEMANTICS" note in ReleaseGovernor.ps1) and never for a run whose .Released
    # ended up empty — including a run THIS SAME rate cap just denied ($rateCapDenied -> the
    # loop above HELD everything, so $regeneratedReleased.Count is 0 here, so this branch is
    # correctly skipped; a denial must never count as a release, or a persistent attacker could
    # use denied runs to inflate the ledger and starve out a legitimate later release, which
    # would be a self-inflicted availability bug, not a security one, but is still wrong).
    if ($rateCapEnabled -and $regeneratedReleased.Count -gt 0) {
        Register-Release -Profile $RateProfile -LedgerPath $RateLedgerPath -Today $RateToday
    }

    $report = [pscustomobject]@{
        run_id   = $runId
        mode     = $Mode
        released = $regeneratedReleased
        held     = @($hel)
        total    = $verdicts.Count
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $man 'sensitivity-report.json')

    # Return a thin result object — callers gate their next pipeline stage on .Released.
    # C2.4 (Fix 2): .Released is the SAME host-regenerated {name,sha256}-only array used for the
    # on-disk report ($regeneratedReleased), NOT the raw $rel list of guest verdict objects.
    # scripts/Invoke-Voidseal.ps1 surfaces $gateResult.Released directly on $report.Released, which
    # is returned to the CALLER of Invoke-Voidseal — so a producer-controlled (even schema-valid,
    # bounded-enum) 'flags'/'error_code'/'verdict' field must never ride out on that surface. .Held
    # intentionally KEEPS its full audit shape (including heldReason) — HELD entries are meant to
    # carry forensic detail; only the RELEASED surface is minimized to the fixed release contract.
    [pscustomobject]@{
        Released     = $regeneratedReleased
        Held         = @($hel)
        ManifestPath = Join-Path $man 'sensitivity-report.json'
    }
}
