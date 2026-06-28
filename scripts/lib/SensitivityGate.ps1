<#
.SYNOPSIS
    Voidseal — Sensitivity Gate: offline screener runner + artifact partitioner.

.DESCRIPTION
    Dot-source this file to get:

        Invoke-SensitivityGate -StagingDir <path> -OutputDir <path> [-Mode aggressive|moderate]
                               -ScreenerPath <path>

    THE JOB:
      Run the offline Python screener (`guest/screener.py`) against a STAGING directory of
      candidate artifacts, then PARTITION them into two output buckets:

          <OutputDir>/released/   — ONLY files the screener marked exactly 'SAFE'
          <OutputDir>/held/       — EVERYTHING else (SENSITIVE, UNCERTAIN, or any unknown verdict)
          <OutputDir>/manifest/sensitivity-report.json  — full partition record

    THE INVARIANT (released ⊆ SAFE):
      This is the non-negotiable security property of the gate. The only releasable verdict is
      the exact string 'SAFE'. SENSITIVE, UNCERTAIN, and any unrecognised verdict are HELD
      (fail-closed by construction). A belt-and-braces re-assertion throws immediately if the
      partition logic ever produces a violation — defence in depth against future code changes.

    FAIL-CLOSED ON ERROR:
      A non-zero screener exit code or a missing verdicts file means the screen did not
      complete. In that case we THROW and release NOTHING — an inability to screen is never
      a pass (same design principle as Assert-Sealed refusing to certify if the host cannot
      be queried).

    -Mode is passed through to the screener (aggressive|moderate). The partition decision
    itself is mode-independent: only exact 'SAFE' releases. The 'moderate' review-queue
    refinement (UNCERTAIN → held-for-human-review sub-bucket) is deferred to a later task.

    INJECTION: -ScreenerPath is explicit so tests can point at the real script without
    hard-coding a relative path, and error tests can point at a nonexistent path to exercise
    the fail-closed branch without any mocking infrastructure.

    Pure host-side orchestration: no Hyper-V calls. This module is intentionally thin —
    it delegates ALL content classification to the screener process.
#>

Set-StrictMode -Version Latest

function Invoke-SensitivityGate {
<#
.SYNOPSIS
    Run the offline screener over $StagingDir and partition artifacts into released/held.

.DESCRIPTION
    Orchestrates the three-phase gate:
      1. Run screener.py → emit a per-file verdicts JSON.
      2. Partition: copy SAFE files to <OutputDir>/released/, everything else to /held/.
      3. Assert released ⊆ SAFE (belt-and-braces re-check before writing the manifest).

    Throws on any screener failure, missing verdicts file, or invariant violation.
    Returns a [pscustomobject] with .Released, .Held, .ManifestPath for callers that need
    to act on the partition result (e.g. a pipeline that gates the next stage on .Released).

.PARAMETER StagingDir
    Directory of candidate artifacts to screen. Must exist; files are read-only by the screener.

.PARAMETER OutputDir
    Root output dir. Subdirs released/, held/, and manifest/ are created here.

.PARAMETER Mode
    Screener mode passed through to screener.py. 'aggressive' (default) is fail-closed.
    The partition decision itself is mode-independent: only exact 'SAFE' releases.

.PARAMETER ScreenerPath
    Absolute path to screener.py. Explicit to keep test injection clean.

.OUTPUTS
    [pscustomobject] @{ Released=[array]; Held=[array]; ManifestPath=[string] }
    where Released/Held are arrays of the screener's verdict objects ({name,verdict,detectors}).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $StagingDir,
        [Parameter(Mandatory)] [string] $OutputDir,
        [ValidateSet('aggressive','moderate')] [string] $Mode = 'aggressive',
        [Parameter(Mandatory)] [string] $ScreenerPath
    )

    # Create output subdirs unconditionally — fail-closed means these exist even when we throw
    # below, so the caller can inspect an empty released/ to confirm nothing escaped.
    $released = Join-Path $OutputDir 'released'
    $held     = Join-Path $OutputDir 'held'
    $man      = Join-Path $OutputDir 'manifest'
    foreach ($d in @($released, $held, $man)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }

    $vjson = Join-Path $man 'verdicts.json'

    # Phase 1: run the screener.
    # Capture stdout+stderr together so we can surface the diagnostic in the throw message.
    # The screener writes its JSON to --out $vjson directly; we are not parsing stdout.
    # FAIL CLOSED: any non-zero exit means classification is incomplete => throw, release nothing.
    $screenerOutput = & python $ScreenerPath --in $StagingDir --out $vjson --mode $Mode 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("Invoke-SensitivityGate: screener failed (exit $LASTEXITCODE) — fail closed, " +
               "nothing released. Output: $screenerOutput")
    }
    if (-not (Test-Path -LiteralPath $vjson)) {
        throw ("Invoke-SensitivityGate: screener exited 0 but produced no verdicts file at " +
               "'$vjson' — fail closed, nothing released.")
    }

    # Phase 2: partition.
    # Wrap with @(...) so ConvertFrom-Json single-element returns a real array, not a scalar
    # — Set-StrictMode -Version Latest would blow up on .Count of a scalar otherwise.
    $verdicts = @(Get-Content $vjson -Raw | ConvertFrom-Json)

    $rel = [System.Collections.Generic.List[object]]::new()
    $hel = [System.Collections.Generic.List[object]]::new()

    foreach ($v in $verdicts) {
        $src = Join-Path $StagingDir $v.name
        # The ONE releasable verdict is the exact string 'SAFE'.
        # SENSITIVE, UNCERTAIN, and any future/unknown verdict → HELD (fail-closed).
        if ($v.verdict -eq 'SAFE') {
            Copy-Item -LiteralPath $src -Destination $released
            $rel.Add($v)
        } else {
            Copy-Item -LiteralPath $src -Destination $held
            $hel.Add($v)
        }
    }

    # Phase 3: belt-and-braces re-assertion of the released ⊆ SAFE invariant.
    # This SHOULD be unreachable given the loop above, but defends against future edits that
    # accidentally widen the releasable set (e.g. adding an OR branch). We throw rather than
    # emit a silently-corrupted partition.
    $violation = @($rel | Where-Object { $_.verdict -ne 'SAFE' })
    if ($violation.Count -gt 0) {
        throw ("Invoke-SensitivityGate: INVARIANT VIOLATION — a non-SAFE artifact reached " +
               "'released'. Fail closed. Violators: " +
               ($violation | ForEach-Object { "$($_.name)=$($_.verdict)" } | Join-String -Separator ', '))
    }

    # Write the manifest. Includes full verdict objects (name, verdict, detectors) so the record
    # is self-contained — a reviewer can audit why each file was held without re-running the screener.
    $report = [pscustomobject]@{
        mode     = $Mode
        released = @($rel)
        held     = @($hel)
        total    = $verdicts.Count
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $man 'sensitivity-report.json')

    # Return a thin result object — callers gate their next pipeline stage on .Released.
    [pscustomobject]@{
        Released     = @($rel)
        Held         = @($hel)
        ManifestPath = Join-Path $man 'sensitivity-report.json'
    }
}
