Describe 'screener.py verdicts' {
  BeforeAll {
    $fx = Join-Path $PSScriptRoot 'fixtures/messy-drive'
    $script:out = Join-Path $env:TEMP "screen-$([guid]::NewGuid())"; New-Item -ItemType Directory -Path $script:out | Out-Null
    python "$PSScriptRoot/../guest/screener.py" --in $fx --out "$script:out/verdicts.json" --mode aggressive
    $script:V = Get-Content "$script:out/verdicts.json" -Raw | ConvertFrom-Json
  }
  # C2.1 minimal enum schema: verdict in {SAFE, HELD, ERROR}. A detector hit (what used to
  # be SENSITIVE) and readable-but-not-prose (what used to be UNCERTAIN) both collapse to
  # HELD -- the WHY now lives in .flags / .error_code, never a wider free-form verdict value.
  It 'marks the credential file HELD with the aws_key flag' {
    $v = $V | Where-Object name -eq 'creds.txt'
    $v.verdict | Should -Be 'HELD'
    $v.flags | Should -Contain 'aws_key'
  }
  It 'marks the finance file HELD with the financial flag' {
    $v = $V | Where-Object name -eq 'finance-statement.txt'
    $v.verdict | Should -Be 'HELD'
    $v.flags | Should -Contain 'financial'
  }
  It 'marks the health file HELD with the health flag' {
    $v = $V | Where-Object name -eq 'health-note.txt'
    $v.verdict | Should -Be 'HELD'
    $v.flags | Should -Contain 'health'
  }
  It 'marks clean prose SAFE' {
    ($V | Where-Object name -eq 'prose-essay.txt').verdict | Should -Be 'SAFE'
  }
  It 'marks clean cover-letter prose SAFE' {
    ($V | Where-Object name -eq 'prose-letter.md').verdict | Should -Be 'SAFE'
  }
  It 'marks a credential embedded in prose HELD (env-var pattern, never SAFE)' {
    ($V | Where-Object name -eq 'prose-with-token.md').verdict | Should -Be 'HELD'
  }
  It 'defaults unknown/non-prose to HELD (fail-closed), never SAFE-by-omission' {
    ($V | Where-Object name -eq 'spreadsheet-dump.csv').verdict | Should -Be 'HELD'
  }
  AfterAll { if ($script:out) { Remove-Item -Recurse -Force $script:out -ErrorAction SilentlyContinue } }
}

Describe 'Invoke-SensitivityGate partition' {
  BeforeAll {
    . "$PSScriptRoot/../scripts/lib/SensitivityGate.ps1"
    $script:screener = "$PSScriptRoot/../guest/screener.py"
    $script:staging = Join-Path $TestDrive 'staging'
    New-Item -ItemType Directory -Path $script:staging -Force | Out-Null
    Copy-Item "$PSScriptRoot/fixtures/messy-drive/*" $script:staging
    $script:out = Join-Path $TestDrive 'out'
    New-Item -ItemType Directory -Path $script:out -Force | Out-Null
    $script:r = Invoke-SensitivityGate -StagingDir $script:staging -OutputDir $script:out `
                  -Mode aggressive -ScreenerPath $script:screener
  }
  It 'releases ONLY SAFE; everything else held (released subset of SAFE)' {
    $relNames = @((Get-ChildItem (Join-Path $script:out 'released')).Name)
    $heldNames = @((Get-ChildItem (Join-Path $script:out 'held')).Name)
    $relNames  | Should -Not -Contain 'creds.txt'
    $relNames  | Should -Not -Contain 'finance-statement.txt'
    $relNames  | Should -Not -Contain 'health-note.txt'
    $relNames  | Should -Not -Contain 'prose-with-token.md'
    $heldNames | Should -Contain 'creds.txt'
    $heldNames | Should -Contain 'finance-statement.txt'
    $heldNames | Should -Contain 'health-note.txt'
    $heldNames | Should -Contain 'prose-with-token.md'
    $heldNames | Should -Contain 'spreadsheet-dump.csv'   # UNCERTAIN is held too (fail-closed)
    $relNames  | Should -Contain 'prose-essay.txt'
    $relNames  | Should -Contain 'prose-letter.md'
    @($script:r.Released).Count | Should -BeGreaterThan 0  # the prose files
    # C2.4 (Fix 2): .Released is {name,sha256}-only (host-regenerated) — no 'verdict' field to
    # assert on here; that every released entry IS SAFE is a structural invariant of the
    # regenerator (enforced above by the partition + belt-and-braces re-assertion), not something
    # the returned .Released surface restates.
    @($script:r.Released | ForEach-Object { $_.name }) | Should -Not -Contain 'creds.txt'  # SENSITIVE never in .Released
  }
  It 'writes a sensitivity manifest with released/held + reasons' {
    Test-Path (Join-Path $script:out 'manifest/sensitivity-report.json') | Should -BeTrue
  }
  It 'fails closed when the screener errors (throws; releases nothing)' {
    $staging2 = Join-Path $TestDrive 'staging2'; New-Item -ItemType Directory -Path $staging2 -Force | Out-Null
    Copy-Item "$PSScriptRoot/fixtures/messy-drive/prose-essay.txt" $staging2
    $out2 = Join-Path $TestDrive 'out2'; New-Item -ItemType Directory -Path $out2 -Force | Out-Null
    { Invoke-SensitivityGate -StagingDir $staging2 -OutputDir $out2 -Mode aggressive `
        -ScreenerPath "$PSScriptRoot/../guest/does-not-exist.py" } | Should -Throw
    # nothing must have been released
    @(Get-ChildItem (Join-Path $out2 'released') -ErrorAction SilentlyContinue).Count | Should -Be 0
  }
  It 'fails closed on a path-traversal verdict name (never releases a file outside staging)' {
    # An external file that must NEVER be released:
    $evil = Join-Path $TestDrive 'evil.txt'; Set-Content -LiteralPath $evil -Value 'EXTERNAL-SECRET'
    $staging3 = Join-Path $TestDrive 'staging3'; New-Item -ItemType Directory -Path $staging3 -Force | Out-Null
    $out3 = Join-Path $TestDrive 'out3'; New-Item -ItemType Directory -Path $out3 -Force | Out-Null
    # A stub screener that IGNORES --in and writes a crafted verdicts.json marking a traversal name SAFE.
    $stub = Join-Path $TestDrive 'stub-traversal.py'
    @'
import argparse, json, pathlib
ap = argparse.ArgumentParser()
ap.add_argument('--in', dest='inp'); ap.add_argument('--out'); ap.add_argument('--mode')
a = ap.parse_args()
pathlib.Path(a.out).write_text(json.dumps([{"name": "../evil.txt", "verdict": "SAFE", "detectors": []}]))
'@ | Set-Content -LiteralPath $stub -Encoding utf8
    { Invoke-SensitivityGate -StagingDir $staging3 -OutputDir $out3 -Mode aggressive -ScreenerPath $stub } | Should -Throw
    # The external file must NOT have been copied into released/. Extract names via ForEach-Object
    # (StrictMode-safe: '@().Name' on an empty array throws under Set-StrictMode -Version Latest).
    $relNames3 = @(Get-ChildItem (Join-Path $out3 'released') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $relNames3 | Should -Not -Contain 'evil.txt'
  }
  It 'fails closed when a staged file has no screener verdict (incomplete screen)' {
    $st = Join-Path $TestDrive 'staging-incomplete'; New-Item -ItemType Directory -Path $st -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $st 'a.txt') -Value 'alpha'
    Set-Content -LiteralPath (Join-Path $st 'b.txt') -Value 'bravo'   # this one gets NO verdict
    $o = Join-Path $TestDrive 'out-incomplete'; New-Item -ItemType Directory -Path $o -Force | Out-Null
    $stub = Join-Path $TestDrive 'stub-partial.py'
    @'
import argparse, json, pathlib
ap = argparse.ArgumentParser(); ap.add_argument('--in', dest='inp'); ap.add_argument('--out'); ap.add_argument('--mode')
a = ap.parse_args()
pathlib.Path(a.out).write_text(json.dumps([{"name": "a.txt", "verdict": "SAFE", "detectors": []}]))
'@ | Set-Content -LiteralPath $stub -Encoding utf8
    { Invoke-SensitivityGate -StagingDir $st -OutputDir $o -Mode aggressive -ScreenerPath $stub } | Should -Throw
  }
  It 'manifest content reflects the partition (released=SAFE, held includes sensitive, total counted)' {
    $report = Get-Content (Join-Path $script:out 'manifest/sensitivity-report.json') -Raw | ConvertFrom-Json
    # C2.4: the released section is HOST-REGENERATED from validated fields only — entries carry
    # ONLY name/sha256 (no 'verdict' field; that every released entry IS SAFE is a structural
    # invariant of the regenerator, not something the released report itself needs to restate).
    @($report.released) | ForEach-Object {
      @($_.PSObject.Properties.Name | Sort-Object) | Should -Be @('name', 'sha256')
    }
    @($report.held | ForEach-Object { $_.name }) | Should -Contain 'creds.txt'
    $report.total | Should -Be 7
  }
}

Describe 'Invoke-SensitivityGate -VerdictsPath (consume mode)' {
  BeforeAll {
    . "$PSScriptRoot/../scripts/lib/SensitivityGate.ps1"

    # Helper: create a verdicts array that matches what the real screener produces for
    # the messy-drive fixture (7 files). C2.1 locked schema: verdict in {SAFE, HELD, ERROR},
    # error_code in {NONE, EXTRACT_FAIL, OFF_SCHEMA, DETECTOR_ERROR, UNSUPPORTED}, flags is a
    # bounded closed vocabulary, sha256 is the content-binding field C2.4's re-hash gate checks.
    # sha256 is computed HERE (not hardcoded) so a fixture edit can never silently desync it from
    # the real file bytes under tests/fixtures/messy-drive.
    function script:HashOf($name) {
      (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot "fixtures/messy-drive/$name") -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $script:messyVerdicts = @(
      [pscustomobject]@{ name = 'creds.txt';             sha256 = (HashOf 'creds.txt');             verdict = 'HELD'; error_code = 'NONE';        flags = @('aws_key') }
      [pscustomobject]@{ name = 'finance-statement.txt'; sha256 = (HashOf 'finance-statement.txt'); verdict = 'HELD'; error_code = 'NONE';        flags = @('financial') }
      [pscustomobject]@{ name = 'health-note.txt';       sha256 = (HashOf 'health-note.txt');       verdict = 'HELD'; error_code = 'NONE';        flags = @('health') }
      [pscustomobject]@{ name = 'prose-essay.txt';       sha256 = (HashOf 'prose-essay.txt');       verdict = 'SAFE'; error_code = 'NONE';        flags = @() }
      [pscustomobject]@{ name = 'prose-letter.md';       sha256 = (HashOf 'prose-letter.md');       verdict = 'SAFE'; error_code = 'NONE';        flags = @() }
      [pscustomobject]@{ name = 'spreadsheet-dump.csv';  sha256 = (HashOf 'spreadsheet-dump.csv');  verdict = 'HELD'; error_code = 'UNSUPPORTED'; flags = @() }
      [pscustomobject]@{ name = 'prose-with-token.md';   sha256 = (HashOf 'prose-with-token.md');   verdict = 'HELD'; error_code = 'NONE';        flags = @('credential') }
    )
  }

  It 'produces the same partition as Run mode (released=SAFE only, held=everything else)' {
    # Arrange — copy messy-drive into a staging dir; hand the pre-written verdicts.json to the gate.
    $staging = Join-Path $TestDrive 'consume-staging'
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    Copy-Item "$PSScriptRoot/fixtures/messy-drive/*" $staging

    $vfile = Join-Path $TestDrive 'consume-verdicts.json'
    $script:messyVerdicts | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8

    $output = Join-Path $TestDrive 'consume-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $staging -OutputDir $output -VerdictsPath $vfile

    # Partition assertions: exactly the two SAFE prose files released.
    $relNames = @(Get-ChildItem (Join-Path $output 'released') | ForEach-Object { $_.Name })
    $helNames = @(Get-ChildItem (Join-Path $output 'held')     | ForEach-Object { $_.Name })

    $relNames | Should -Contain 'prose-essay.txt'
    $relNames | Should -Contain 'prose-letter.md'
    $relNames | Should -Not -Contain 'creds.txt'
    $relNames | Should -Not -Contain 'finance-statement.txt'
    $relNames | Should -Not -Contain 'health-note.txt'
    $relNames | Should -Not -Contain 'spreadsheet-dump.csv'
    $relNames | Should -Not -Contain 'prose-with-token.md'

    $helNames | Should -Contain 'creds.txt'
    $helNames | Should -Contain 'finance-statement.txt'
    $helNames | Should -Contain 'health-note.txt'
    $helNames | Should -Contain 'spreadsheet-dump.csv'
    $helNames | Should -Contain 'prose-with-token.md'

    # C2.4 (Fix 2): .Released is {name,sha256}-only (host-regenerated) — no 'verdict' field
    # rides on the returned surface; the exact-SAFE partition is enforced upstream of this return.
    @($r.Released).Count | Should -BeGreaterThan 0
    foreach ($entry in @($r.Released)) {
      @($entry.PSObject.Properties.Name | Sort-Object) | Should -Be @('name', 'sha256')
    }
  }

  It 'host re-validates consumed file — traversal name still throws; evil.txt NOT released' {
    # Arrange — an "evil.txt" placed OUTSIDE staging; a crafted verdicts.json marks it SAFE with
    # a traversal name.  The host traversal guard must catch this EVEN on a consumed file.
    $evil = Join-Path $TestDrive 'evil.txt'
    Set-Content -LiteralPath $evil -Value 'EXTERNAL-SECRET'

    $staging = Join-Path $TestDrive 'traversal-staging'
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    # staging is empty — the traversal guard runs before any copy.

    $vfile = Join-Path $TestDrive 'traversal-verdicts.json'
    @( [pscustomobject]@{ name = '../evil.txt'; verdict = 'SAFE'; detectors = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8

    $output = Join-Path $TestDrive 'traversal-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    { Invoke-SensitivityGate -StagingDir $staging -OutputDir $output -VerdictsPath $vfile } |
      Should -Throw

    # evil.txt must NOT appear in released/ — the traversal guard fired before any copy.
    $relNames = @(Get-ChildItem (Join-Path $output 'released') -ErrorAction SilentlyContinue |
                  ForEach-Object { $_.Name })
    $relNames | Should -Not -Contain 'evil.txt'
  }

  It 'completeness guard runs on the consumed file — unvouched staged file throws' {
    # A staging dir with two files; the consumed verdicts only cover one.
    # The completeness guard must catch the gap and throw, releasing nothing.
    $staging = Join-Path $TestDrive 'completeness-staging'
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $staging 'a.txt') -Value 'alpha'
    Set-Content -LiteralPath (Join-Path $staging 'b.txt') -Value 'bravo'   # no verdict for this one

    $vfile = Join-Path $TestDrive 'completeness-verdicts.json'
    @( [pscustomobject]@{ name = 'a.txt'; verdict = 'SAFE'; detectors = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8

    $output = Join-Path $TestDrive 'completeness-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    { Invoke-SensitivityGate -StagingDir $staging -OutputDir $output -VerdictsPath $vfile } |
      Should -Throw
  }

  It 'missing -VerdictsPath file fails closed — throws before any copy' {
    $staging = Join-Path $TestDrive 'missing-vp-staging'
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $staging 'x.txt') -Value 'data'

    $output = Join-Path $TestDrive 'missing-vp-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $nonExistent = Join-Path $TestDrive 'does-not-exist-verdicts.json'

    { Invoke-SensitivityGate -StagingDir $staging -OutputDir $output -VerdictsPath $nonExistent } |
      Should -Throw
  }
}

# ===========================================================================
# C2.4 — REGENERATOR CORE (gate side, [KEY]). Invoke-SensitivityGate Consume mode must, for
# every verdict, in order: (1) validate against the C2.1 enum schema (unknown key / out-of-
# enum value / off-vocab flag / malformed sha256 -> HELD heldReason=off-schema, NEVER trusted
# or released); (2) immediately before release, RE-HASH the staged file's bytes and release a
# SAFE verdict ONLY if current_sha256 == verdict.sha256 (else HELD heldReason=hash-mismatch —
# closes the P1#3 TOCTOU/post-screen-swap); (3) stamp a HOST-generated run_id (a producer-
# supplied run_id field is itself off-schema, since run_id is not in the C2.1 verdict schema,
# and must be ignored/rejected); (4) REGENERATE the released report from a TCB-owned template
# parameterized ONLY by validated enum fields + run_id + released name/sha256 — the guest's
# verdicts.json bytes / any free-form field NEVER appear in the released report. All four are
# strictly-tightening (only ever narrow the releasable set) and layered UNDER the existing
# traversal guard / completeness guard / exact-SAFE partition / invariant re-assertion.
# ===========================================================================
Describe 'Invoke-SensitivityGate — C2.4 regenerator core (schema validation + re-hash + host run_id + regenerated report)' {
  BeforeAll {
    . "$PSScriptRoot/../scripts/lib/SensitivityGate.ps1"

    $script:regenStaging = Join-Path $TestDrive 'regen-staging'
    New-Item -ItemType Directory -Path $script:regenStaging -Force | Out-Null
    $script:safeBytes = [System.Text.Encoding]::UTF8.GetBytes(
      "The morning light filtered gently through the tall oak trees, casting long shadows. " +
      "Birds began their chorus well before dawn, filling the quiet air with intricate song."
    )
    [System.IO.File]::WriteAllBytes((Join-Path $script:regenStaging 'essay.txt'), $script:safeBytes)
    $script:safeHash = (Get-FileHash -LiteralPath (Join-Path $script:regenStaging 'essay.txt') -Algorithm SHA256).Hash.ToLowerInvariant()
  }

  It 'off-schema: an out-of-enum verdict value routes to HELD (heldReason=off-schema), never released' {
    $vfile = Join-Path $TestDrive 'off-schema-verdict.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE_BUT_ACTUALLY_FREEFORM'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'off-schema-verdict-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because 'an out-of-enum verdict value is off-schema -> HELD, never released'
    $relNames = @(Get-ChildItem (Join-Path $output 'released') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $relNames | Should -Not -Contain 'essay.txt'
    $helNames = @(Get-ChildItem (Join-Path $output 'held') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $helNames | Should -Contain 'essay.txt'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'off-schema: an extra free-form key on an otherwise-SAFE verdict routes to HELD (heldReason=off-schema)' {
    $vfile = Join-Path $TestDrive 'off-schema-key.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @(); smuggled = 'free-form-canary-value' } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'off-schema-key-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because 'an extra free-form key is off-schema even though verdict=SAFE -> HELD'
    (@($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]).heldReason | Should -Be 'off-schema'
  }

  It 'off-schema: an off-vocabulary flag routes to HELD (heldReason=off-schema)' {
    $vfile = Join-Path $TestDrive 'off-schema-flag.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @('not_a_real_flag') } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'off-schema-flag-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because 'an off-vocabulary flag is off-schema -> HELD'
    (@($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]).heldReason | Should -Be 'off-schema'
  }

  It 'off-schema: a malformed sha256 (wrong length / non-hex) routes to HELD (heldReason=off-schema)' {
    $vfile = Join-Path $TestDrive 'off-schema-sha.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = 'not-a-real-sha256'; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'off-schema-sha-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because 'a malformed sha256 is off-schema -> HELD'
    (@($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]).heldReason | Should -Be 'off-schema'
  }

  It 'off-schema: a producer-supplied run_id field is rejected as off-schema (host run_id is never consumer-derived)' {
    # run_id is NOT part of the C2.1 verdict schema. A producer that stuffs a decoy run_id
    # into a verdict must be treated exactly like any other unknown-key smuggle attempt.
    $vfile = Join-Path $TestDrive 'off-schema-runid.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @(); run_id = 'PRODUCER-CHOSEN-RUN-ID-DECOY' } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'off-schema-runid-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because 'a producer-supplied run_id is an off-schema key -> HELD'
    (@($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]).heldReason | Should -Be 'off-schema'
  }

  It 'hash-mismatch: a SAFE, enum-valid verdict whose sha256 does not match the staged bytes -> HELD (heldReason=hash-mismatch)' {
    $vfile = Join-Path $TestDrive 'hash-mismatch.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = ('0' * 64); verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'hash-mismatch-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because 'a SHA mismatch means the staged bytes are not provably what was screened -> HELD (TOCTOU close)'
    $relNames = @(Get-ChildItem (Join-Path $output 'released') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $relNames | Should -Not -Contain 'essay.txt'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]
    $heldEntry.heldReason | Should -Be 'hash-mismatch'
  }

  It 'hash-mismatch: a post-screen swapped file (bytes on disk changed after the verdict was formed) -> HELD, not released' {
    # Simulates the P1#3 TOCTOU: the verdict was computed over the ORIGINAL bytes; the staged
    # file is then swapped for different content before the gate runs. Re-hash-at-release must
    # catch this even though the sha256 field itself is well-formed (64 lowercase hex chars).
    $swapStaging = Join-Path $TestDrive 'swap-staging'
    New-Item -ItemType Directory -Path $swapStaging -Force | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $swapStaging 'essay.txt'), $script:safeBytes)
    $originalHash = (Get-FileHash -LiteralPath (Join-Path $swapStaging 'essay.txt') -Algorithm SHA256).Hash.ToLowerInvariant()

    $vfile = Join-Path $TestDrive 'swap-verdicts.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $originalHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8

    # Swap the staged bytes AFTER the verdict was formed but BEFORE the gate runs.
    [System.IO.File]::WriteAllBytes((Join-Path $swapStaging 'essay.txt'), [System.Text.Encoding]::UTF8.GetBytes('SWAPPED-AFTER-SCREEN'))

    $output = Join-Path $TestDrive 'swap-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $swapStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because 'the staged bytes no longer match the screened hash -> HELD, closes the TOCTOU swap'
    (@($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]).heldReason | Should -Be 'hash-mismatch'
  }

  It 'positive path: a clean, enum-valid SAFE verdict whose sha256 matches the staged bytes is released' {
    $vfile = Join-Path $TestDrive 'positive-path.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'positive-path-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    $relNames = @(Get-ChildItem (Join-Path $output 'released') | ForEach-Object { $_.Name })
    $relNames | Should -Contain 'essay.txt'
    @($r.Released).Count | Should -Be 1
    # C2.4 (Fix 2): .Released is {name,sha256}-only — no 'verdict' field on the returned entry.
    $r.Released[0].name   | Should -Be 'essay.txt'
    $r.Released[0].sha256 | Should -Be $script:safeHash
  }

  It 'host run_id: the manifest carries a host-generated run_id, non-empty and NOT the decoy the input supplied' {
    $vfile = Join-Path $TestDrive 'runid-manifest.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'runid-manifest-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    $report = Get-Content $r.ManifestPath -Raw | ConvertFrom-Json
    [string]$report.run_id | Should -Not -BeNullOrEmpty -Because 'the regenerated report must carry a host-generated run_id'
    [string]$report.run_id | Should -Not -Be 'PRODUCER-CHOSEN-RUN-ID-DECOY'
  }

  It 'host run_id: two separate gate runs against the same input get DIFFERENT run_ids (host-generated per invocation, not derived from content)' {
    $vfile = Join-Path $TestDrive 'runid-distinct.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8

    $out1 = Join-Path $TestDrive 'runid-distinct-out1'; New-Item -ItemType Directory -Path $out1 -Force | Out-Null
    $out2 = Join-Path $TestDrive 'runid-distinct-out2'; New-Item -ItemType Directory -Path $out2 -Force | Out-Null

    $r1 = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $out1 -VerdictsPath $vfile
    $r2 = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $out2 -VerdictsPath $vfile

    $report1 = Get-Content $r1.ManifestPath -Raw | ConvertFrom-Json
    $report2 = Get-Content $r2.ManifestPath -Raw | ConvertFrom-Json
    [string]$report1.run_id | Should -Not -Be ([string]$report2.run_id)
  }

  It 'regenerated report: contains ONLY schema fields + run_id + released name/sha256 — a free-form guest canary string never appears' {
    # The consumed verdicts.json carries a canary free-form value smuggled into an otherwise
    # off-schema (rejected) entry AND, separately, a legitimate SAFE entry. The regenerated
    # released report must be built FRESH from validated enum values only — even the raw
    # (audit-copy) guest verdicts.json content must not leak into the report's released section.
    $vfile = Join-Path $TestDrive 'regen-report.json'
    @(
      [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() }
    ) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'regen-report-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile
    $reportRaw = Get-Content $r.ManifestPath -Raw
    $report = $reportRaw | ConvertFrom-Json

    # The released section is a FRESH host object: only the fixed field set, nothing else.
    $releasedEntry = @($report.released)[0]
    $allowedReleasedKeys = @('name', 'sha256')
    $actualKeys = @($releasedEntry.PSObject.Properties.Name)
    foreach ($k in $actualKeys) { $allowedReleasedKeys | Should -Contain $k -Because "released report entries must be host-regenerated from validated fields only (found extra key '$k')" }
    $releasedEntry.name   | Should -Be 'essay.txt'
    $releasedEntry.sha256 | Should -Be $script:safeHash
  }

  It 'regenerated report: a free-form canary value on an off-schema entry never appears in the released section (may appear only in the held audit trail)' {
    # Two files: 'canary.txt' carries a smuggled free-form key (off-schema -> HELD, audit-recorded
    # verbatim as forensic evidence) and 'essay.txt' is a legitimate, separate SAFE file that DOES
    # release. The regenerator property under test: the canary must NEVER appear in the report's
    # 'released' section (host-regenerated from validated fields only), even though the raw guest
    # verdicts.json (and this HELD entry's audit copy) may retain it for forensics.
    $canaryStaging = Join-Path $TestDrive 'canary-staging'
    New-Item -ItemType Directory -Path $canaryStaging -Force | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $canaryStaging 'essay.txt'), $script:safeBytes)
    [System.IO.File]::WriteAllBytes((Join-Path $canaryStaging 'canary.txt'), [System.Text.Encoding]::UTF8.GetBytes('irrelevant content'))
    $essayHash  = (Get-FileHash -LiteralPath (Join-Path $canaryStaging 'essay.txt')  -Algorithm SHA256).Hash.ToLowerInvariant()
    $canaryHash = (Get-FileHash -LiteralPath (Join-Path $canaryStaging 'canary.txt') -Algorithm SHA256).Hash.ToLowerInvariant()

    $vfile = Join-Path $TestDrive 'regen-canary.json'
    @(
      [pscustomobject]@{ name = 'essay.txt';  sha256 = $essayHash;  verdict = 'SAFE'; error_code = 'NONE'; flags = @() }
      [pscustomobject]@{ name = 'canary.txt'; sha256 = $canaryHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @(); canary = 'FREEFORM-EXFIL-CHANNEL-CANARY-STRING' }
    ) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'regen-canary-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $canaryStaging -OutputDir $output -VerdictsPath $vfile

    # canary.txt is off-schema (extra key) -> HELD, never released; essay.txt IS released.
    @($r.Released | ForEach-Object { $_.name }) | Should -Contain 'essay.txt'
    @($r.Released | ForEach-Object { $_.name }) | Should -Not -Contain 'canary.txt'

    $report = Get-Content $r.ManifestPath -Raw | ConvertFrom-Json
    $reportReleasedRaw = $report.released | ConvertTo-Json -Depth 6
    $reportReleasedRaw | Should -Not -Match 'FREEFORM-EXFIL-CHANNEL-CANARY-STRING' -Because 'the regenerated released section must never carry a free-form guest value, even one attached to a different file in the same run'
  }

  It 'guest verdicts.json is retained ONLY as an audit copy under manifest/, never on the released path' {
    $vfile = Join-Path $TestDrive 'audit-copy.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'audit-copy-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $null = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    # The audit copy of the guest's raw verdicts.json lives under manifest/ (already the case
    # pre-C2.4 at SensitivityGate.ps1:155) — assert it is NOT duplicated into released/.
    Test-Path (Join-Path $output 'manifest/verdicts.json') | Should -BeTrue -Because 'the guest verdicts.json audit copy must still exist under manifest/'
    Test-Path (Join-Path $output 'released/verdicts.json') | Should -BeFalse -Because 'the guest verdicts.json must NEVER appear on the released path'
  }

  It 'well-formed multi-file SAFE batch still releases all matching files (existing processor e2e stays green)' {
    # A regression guard: the regenerator additions must not break the ordinary multi-file
    # happy path any differently than before — every enum-valid, hash-matching SAFE file
    # releases; everything else (HELD/ERROR-shaped) does not.
    $batchStaging = Join-Path $TestDrive 'batch-staging'
    New-Item -ItemType Directory -Path $batchStaging -Force | Out-Null
    Copy-Item "$PSScriptRoot/fixtures/messy-drive/*" $batchStaging
    function _h($n) { (Get-FileHash -LiteralPath (Join-Path $batchStaging $n) -Algorithm SHA256).Hash.ToLowerInvariant() }
    $vfile = Join-Path $TestDrive 'batch-verdicts.json'
    @(
      [pscustomobject]@{ name = 'creds.txt';             sha256 = (_h 'creds.txt');             verdict = 'HELD'; error_code = 'NONE';        flags = @('aws_key') }
      [pscustomobject]@{ name = 'finance-statement.txt'; sha256 = (_h 'finance-statement.txt'); verdict = 'HELD'; error_code = 'NONE';        flags = @('financial') }
      [pscustomobject]@{ name = 'health-note.txt';       sha256 = (_h 'health-note.txt');       verdict = 'HELD'; error_code = 'NONE';        flags = @('health') }
      [pscustomobject]@{ name = 'prose-essay.txt';       sha256 = (_h 'prose-essay.txt');       verdict = 'SAFE'; error_code = 'NONE';        flags = @() }
      [pscustomobject]@{ name = 'prose-letter.md';       sha256 = (_h 'prose-letter.md');       verdict = 'SAFE'; error_code = 'NONE';        flags = @() }
      [pscustomobject]@{ name = 'spreadsheet-dump.csv';  sha256 = (_h 'spreadsheet-dump.csv');  verdict = 'HELD'; error_code = 'UNSUPPORTED'; flags = @() }
      [pscustomobject]@{ name = 'prose-with-token.md';   sha256 = (_h 'prose-with-token.md');   verdict = 'HELD'; error_code = 'NONE';        flags = @('credential') }
    ) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'batch-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $batchStaging -OutputDir $output -VerdictsPath $vfile

    $relNames = @($r.Released | ForEach-Object { $_.name })
    $relNames | Should -Contain 'prose-essay.txt'
    $relNames | Should -Contain 'prose-letter.md'
    $relNames | Should -Not -Contain 'creds.txt'
    @($r.Released).Count | Should -Be 2
  }

  # =========================================================================
  # Fix 3 (adversarial-review) — exact-case enum alphabet enforcement. The producer
  # (guest/screener.py) emits an EXACT alphabet: uppercase verdict/error_code enum members,
  # lowercase-hex sha256. PowerShell's default comparison operators (-contains/-notmatch/-ne)
  # are case-INSENSITIVE, so without -ccontains/-cnotmatch/-cne a case-variant value
  # ('safe', 'Safe', an uppercase sha256, etc.) would wrongly validate/release. These tests
  # prove the host REJECTS every case variant — each one would have been RED (wrongly
  # released, or wrongly missing the {name,sha256}-only shape) against the pre-Fix-1/Fix-2
  # case-insensitive code.
  # =========================================================================
  It 'exact-case: verdict=''safe'' (all-lowercase) is HELD, never released' {
    $vfile = Join-Path $TestDrive 'case-lower-safe.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'safe'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'case-lower-safe-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because "verdict='safe' is a case variant of the 'SAFE' enum member, not a member of it -> off-schema -> HELD"
    $relNames = @(Get-ChildItem (Join-Path $output 'released') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $relNames | Should -Not -Contain 'essay.txt'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'exact-case: verdict=''Safe'' (title-case) is HELD, never released' {
    $vfile = Join-Path $TestDrive 'case-title-safe.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'Safe'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'case-title-safe-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because "verdict='Safe' is a case variant of the 'SAFE' enum member, not a member of it -> off-schema -> HELD"
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'exact-case: error_code=''none'' (lowercase) is HELD/rejected as off-schema' {
    $vfile = Join-Path $TestDrive 'case-lower-errorcode.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'none'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'case-lower-errorcode-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because "error_code='none' is a case variant of the 'NONE' enum member, not a member of it -> off-schema -> HELD (even though verdict=SAFE)"
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'exact-case: flags=@(''AWS_KEY'') (uppercase) is HELD/rejected as off-schema' {
    $vfile = Join-Path $TestDrive 'case-upper-flag.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @('AWS_KEY') } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'case-upper-flag-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because "flags=@('AWS_KEY') is a case variant of the 'aws_key' flag vocabulary member, not a member of it -> off-schema -> HELD (even though verdict=SAFE)"
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'exact-case: an UPPERCASED real sha256 is HELD/rejected as off-schema (never SAFE-released)' {
    $vfile = Join-Path $TestDrive 'case-upper-sha.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash.ToUpperInvariant(); verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'case-upper-sha-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because 'an uppercase-hex sha256 fails the lowercase-hex shape check -> off-schema -> HELD, even though it is the correct hash value modulo case'
    $relNames = @(Get-ChildItem (Join-Path $output 'released') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $relNames | Should -Not -Contain 'essay.txt'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'essay.txt' })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'exact-case: .Released entries expose ONLY name+sha256 — no flags/error_code/verdict property (Fix 2, {name,sha256}-only surface)' {
    $vfile = Join-Path $TestDrive 'released-shape.json'
    @( [pscustomobject]@{ name = 'essay.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'released-shape-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:regenStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released).Count | Should -Be 1
    $entry = $r.Released[0]
    $actualKeys = @($entry.PSObject.Properties.Name | Sort-Object)
    $actualKeys | Should -Be @('name', 'sha256') -Because 'the in-memory .Released surface (scripts/Invoke-Voidseal.ps1 forwards this as $report.Released to the CALLER) must never carry a producer-controlled verdict/error_code/flags field'
    $actualKeys | Should -Not -Contain 'verdict'
    $actualKeys | Should -Not -Contain 'error_code'
    $actualKeys | Should -Not -Contain 'flags'
  }
}

# ===========================================================================
# WHOLE-BRANCH-REVIEW HARDENING (C2-regen, 2026-07-02) — Fix A + the 3 MINOR schema-strictness
# fixes. Fix A: the producer-controlled verdict 'name' rides VERBATIM onto released[].name /
# .Released today; the host must independently enforce the outbox's own
# ^[A-Za-z0-9._-]{1,40}$ charset/length cap (guest/outbox.py's _NAME_RE) so the gate is
# self-sufficient even if the upstream outbox check were ever bypassed/changed — a violating
# name is UNTRUSTED, exactly like any other off-schema field (heldReason='off-schema').
# MINOR 1: sha256 '$' -> '\z' (a trailing-newline-suffixed 65-char value must not pass).
# MINOR 2: reject array-typed scalar fields (a JSON-round-tripped 'verdict':["SAFE"] must not
# [string]-coerce past the exact-case check). MINOR 3: ':'/wildcard chars in name are covered
# by the same charset cap as Fix A (confirmed by a dedicated ADS-shaped-name case below).
# ===========================================================================
Describe 'Invoke-SensitivityGate — whole-branch-review hardening (Fix A name charset/length + MINOR schema strictness)' {
  BeforeAll {
    . "$PSScriptRoot/../scripts/lib/SensitivityGate.ps1"

    $script:hardBytes = [System.Text.Encoding]::UTF8.GetBytes(
      "A calm, unremarkable paragraph of ordinary prose, included only so the file has some " +
      "harmless bytes to hash and release under the various hardening test scenarios below."
    )
  }

  # Helper: FRESH staging dir per call (mirrors New-BudgetSafeFile above) — stage $Name (the
  # ON-DISK filename) with the shared hardening bytes and return {StagingDir, Path, Sha256}.
  # Callers may then hand a DIFFERENT (e.g. illegal) name in the verdict while the real file
  # backing it is legally named on disk, or vice versa, per scenario.
  function script:New-HardeningFile {
    param([string] $Name, [string] $Key = $Name)
    $stagingDir = Join-Path $TestDrive "hardening-staging-$Key"
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
    $path = Join-Path $stagingDir $Name
    [System.IO.File]::WriteAllBytes($path, $script:hardBytes)
    [pscustomobject]@{
      StagingDir = $stagingDir
      Sha256     = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
  }

  It 'Fix A: an oversize (41-char) SAFE verdict name is HELD (heldReason=off-schema), never released' {
    $name = ('a' * 41) + '.txt'   # 45 chars total, well over the 40-char cap
    $f = New-HardeningFile -Name $name -Key 'oversize'

    $vfile = Join-Path $TestDrive 'fixa-oversize.json'
    @( [pscustomobject]@{ name = $name; sha256 = $f.Sha256; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'fixa-oversize-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile

    @($r.Released) | Should -BeNullOrEmpty -Because 'a 41+-char name exceeds the outbox NAME_RE 40-char cap -> off-schema -> HELD even though verdict=SAFE'
    $relNames = @(Get-ChildItem (Join-Path $output 'released') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $relNames | Should -Not -Contain $name
    $heldEntry = @($r.Held | Where-Object { $_.name -eq $name })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'Fix A: an ADS-shaped name (colon, e.g. note.txt:ads) fails Test-VerdictSchema directly (off-schema)' {
    # A colon is outside the outbox's ^[A-Za-z0-9._-]{1,40}$ alphabet. We cannot literally create
    # an NTFS ADS-named FILE on disk here (Windows would treat 'note.txt:ads' as a stream on
    # 'note.txt'), so this proves the SCHEMA gate itself rejects the verdict's name field directly —
    # the property under test is that Test-VerdictSchema's charset check fires on ':' regardless
    # of whether a real file could ever be staged under that literal name.
    $verdict = [pscustomobject]@{ name = 'note.txt:ads'; sha256 = ('0' * 64); verdict = 'SAFE'; error_code = 'NONE'; flags = @() }
    Test-VerdictSchema -Verdict $verdict | Should -BeFalse -Because "a colon (ADS-shaped name) is outside ^[A-Za-z0-9._-]{1,40}`$ -> off-schema"
  }

  It 'Fix A: an ADS-shaped verdict name is HELD end-to-end (heldReason=off-schema), never released' {
    $f = New-HardeningFile -Name 'note.txt' -Key 'ads-e2e'
    $vfile = Join-Path $TestDrive 'fixa-ads-e2e.json'
    @( [pscustomobject]@{ name = 'note.txt:ads'; sha256 = $f.Sha256; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'fixa-ads-e2e-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    # The verdict names 'note.txt:ads' but staging only has 'note.txt' -- the completeness guard
    # would ALSO catch this (an unvouched staged file), so the whole run throws (fail-closed).
    # Either failure mode (per-file HELD or whole-run throw) satisfies "never released"; assert
    # the observable property that matters: nothing escapes to released/.
    { Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile } | Should -Throw
    $relNames = @(Get-ChildItem (Join-Path $output 'released') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $relNames | Should -Not -Contain 'note.txt:ads'
    $relNames | Should -Not -Contain 'note.txt'
  }

  It 'Fix A: a traversal-shaped name (../x) fails Test-VerdictSchema directly (name charset excludes path separators)' {
    $verdict = [pscustomobject]@{ name = '../x'; sha256 = ('0' * 64); verdict = 'SAFE'; error_code = 'NONE'; flags = @() }
    Test-VerdictSchema -Verdict $verdict | Should -BeFalse -Because "'../x' contains '/' which is outside the ^[A-Za-z0-9._-]{1,40}`$ charset -> off-schema (belt-and-braces alongside the existing traversal guard)"
  }

  It 'MINOR 1 (sha256 \z): a sha256 with a trailing newline (65 chars, .NET "$" would match before it) is off-schema -> HELD' {
    $f = New-HardeningFile -Name 'trailing-nl.txt' -Key 'trailing-nl'
    $vfile = Join-Path $TestDrive 'minor1-trailing-nl.json'
    # ConvertTo-Json would escape a literal "`n" safely; embed it directly in the sha256 string.
    $badSha = "$($f.Sha256)`n"
    @( [pscustomobject]@{ name = 'trailing-nl.txt'; sha256 = $badSha; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'minor1-trailing-nl-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile

    @($r.Released | ForEach-Object { $_.name }) | Should -Not -Contain 'trailing-nl.txt' -Because 'a 65-char sha256 ending in a newline must fail a \z-anchored check, even though .NET "$" would match before the trailing newline'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'trailing-nl.txt' })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'MINOR 1 (sha256 \z): direct schema-function proof — a 65-char newline-suffixed sha256 fails Test-VerdictSchema' {
    $f = New-HardeningFile -Name 'direct-nl.txt' -Key 'direct-nl'
    $verdict = [pscustomobject]@{ name = 'direct-nl.txt'; sha256 = "$($f.Sha256)`n"; verdict = 'SAFE'; error_code = 'NONE'; flags = @() }
    Test-VerdictSchema -Verdict $verdict | Should -BeFalse -Because '.NET regex "$" matches before a trailing newline; only \z is a true end-of-string anchor'
  }

  It 'MINOR 2 (array-typed fields): a JSON-round-tripped verdict:["SAFE"] array is off-schema -> HELD, never released' {
    $f = New-HardeningFile -Name 'array-verdict.txt' -Key 'array-verdict'
    # Hand-construct the raw JSON so 'verdict' is a genuine JSON array, then let ConvertFrom-Json
    # (inside the gate) materialize it as an Object[] the way a compromised/buggy producer's
    # verdicts.json could. ConvertTo-Json on a PS array of one element would normally COLLAPSE to
    # a scalar, so we write the JSON text directly to force a true array-typed field.
    $rawJson = @"
[
  { "name": "array-verdict.txt", "sha256": "$($f.Sha256)", "verdict": ["SAFE"], "error_code": "NONE", "flags": [] }
]
"@
    $vfile = Join-Path $TestDrive 'minor2-array-verdict.json'
    Set-Content -LiteralPath $vfile -Value $rawJson -Encoding utf8
    $output = Join-Path $TestDrive 'minor2-array-verdict-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile

    @($r.Released | ForEach-Object { $_.name }) | Should -Not -Contain 'array-verdict.txt' -Because 'verdict:["SAFE"] is an array-typed field that must not [string]-coerce past the exact-case SAFE check'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'array-verdict.txt' })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'MINOR 2 (array-typed fields): a JSON-round-tripped sha256 wrapped in an array is off-schema -> HELD' {
    $f = New-HardeningFile -Name 'array-sha.txt' -Key 'array-sha'
    $rawJson = @"
[
  { "name": "array-sha.txt", "sha256": ["$($f.Sha256)"], "verdict": "SAFE", "error_code": "NONE", "flags": [] }
]
"@
    $vfile = Join-Path $TestDrive 'minor2-array-sha.json'
    Set-Content -LiteralPath $vfile -Value $rawJson -Encoding utf8
    $output = Join-Path $TestDrive 'minor2-array-sha-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile

    @($r.Released | ForEach-Object { $_.name }) | Should -Not -Contain 'array-sha.txt' -Because 'sha256:["<hash>"] is an array-typed field that must not [string]-coerce past the sha256 shape check'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'array-sha.txt' })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'MINOR 2 (array-typed fields): a JSON-round-tripped error_code:["NONE"] array is off-schema -> HELD' {
    $f = New-HardeningFile -Name 'array-errorcode.txt' -Key 'array-errorcode'
    $rawJson = @"
[
  { "name": "array-errorcode.txt", "sha256": "$($f.Sha256)", "verdict": "SAFE", "error_code": ["NONE"], "flags": [] }
]
"@
    $vfile = Join-Path $TestDrive 'minor2-array-errorcode.json'
    Set-Content -LiteralPath $vfile -Value $rawJson -Encoding utf8
    $output = Join-Path $TestDrive 'minor2-array-errorcode-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile

    @($r.Released | ForEach-Object { $_.name }) | Should -Not -Contain 'array-errorcode.txt' -Because 'error_code:["NONE"] is an array-typed field that must not [string]-coerce past the exact-case check'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'array-errorcode.txt' })[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'MINOR 2 (array-typed fields): a JSON-round-tripped name array is off-schema -> HELD, never released' {
    $f = New-HardeningFile -Name 'array-name-target.txt' -Key 'array-name'
    $rawJson = @"
[
  { "name": ["array-name-target.txt"], "sha256": "$($f.Sha256)", "verdict": "SAFE", "error_code": "NONE", "flags": [] }
]
"@
    $vfile = Join-Path $TestDrive 'minor2-array-name.json'
    Set-Content -LiteralPath $vfile -Value $rawJson -Encoding utf8
    $output = Join-Path $TestDrive 'minor2-array-name-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    # An array-typed 'name' does NOT fool Split-Path -Leaf's traversal guard (PowerShell
    # positionally unwraps a single-element array to its scalar there, so 'name' -eq
    # Split-Path-Leaf(name) still holds) — the real backstop is Test-VerdictSchema's array-type
    # rejection (MINOR 2), which routes this to the normal off-schema HELD path, same as any
    # other malformed verdict. No exception; nothing released.
    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile

    @($r.Released | ForEach-Object { $_.name }) | Should -Not -Contain 'array-name-target.txt' -Because 'an array-typed name must not [string]-coerce past the schema check'
    $relNames = @(Get-ChildItem (Join-Path $output 'released') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $relNames | Should -Not -Contain 'array-name-target.txt'
    $heldEntry = @($r.Held)[0]
    $heldEntry.heldReason | Should -Be 'off-schema'
  }

  It 'sanity: .Released entries still expose only the intended {name, sha256} shape after hardening (no regression)' {
    $f = New-HardeningFile -Name 'sanity-clean.txt' -Key 'sanity-clean'
    $vfile = Join-Path $TestDrive 'sanity-clean.json'
    @( [pscustomobject]@{ name = 'sanity-clean.txt'; sha256 = $f.Sha256; verdict = 'SAFE'; error_code = 'NONE'; flags = @() } ) |
      ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'sanity-clean-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile

    @($r.Released | ForEach-Object { $_.name }) | Should -Contain 'sanity-clean.txt'
    $entry = @($r.Released | Where-Object { $_.name -eq 'sanity-clean.txt' })[0]
    @($entry.PSObject.Properties.Name | Sort-Object) | Should -Be @('name', 'sha256')
  }
}

Describe 'Invoke-SensitivityGate — C2.5 released-byte budget backstop (per-artifact size + file-count caps)' {
  BeforeAll {
    . "$PSScriptRoot/../scripts/lib/SensitivityGate.ps1"
  }

  # Helper: create a FRESH staging dir + write a SAFE, enum-valid, hash-matching file+verdict
  # pair into it. Each call gets its OWN staging dir (a $TestDrive subfolder keyed by $Name) —
  # NOT a directory shared across It blocks — because Invoke-SensitivityGate's completeness
  # guard (SensitivityGate.ps1, ~line 268) throws if a staging dir contains any file with no
  # matching verdict, so files from an earlier test must never linger alongside a later test's
  # single-verdict input.
  # Defined as $script: scope (not a bare function) — Pester's per-It scoping means a plain
  # 'function' declared in BeforeAll is not visible inside each It block.
  function script:New-BudgetSafeFile {
    param([string] $Name, [byte[]] $Bytes)
    $stagingDir = Join-Path $TestDrive "budget-staging-$Name"
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
    $path = Join-Path $stagingDir $Name
    [System.IO.File]::WriteAllBytes($path, $Bytes)
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    [pscustomobject]@{
      StagingDir = $stagingDir
      Verdict    = [pscustomobject]@{ name = $Name; sha256 = $hash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() }
    }
  }

  It 'over-budget: a SAFE, enum-valid, hash-matching file whose size exceeds -MaxReleasedBytes -> HELD (heldReason=over-byte-budget)' {
    $bigBytes = [byte[]]::new(2048)
    $f = New-BudgetSafeFile -Name 'big.txt' -Bytes $bigBytes
    $vfile = Join-Path $TestDrive 'over-budget-bytes.json'
    @($f.Verdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'over-budget-bytes-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile -MaxReleasedBytes 1024 -MaxReleasedFiles 16

    @($r.Released | ForEach-Object { $_.name }) | Should -Not -Contain 'big.txt' -Because 'a file over -MaxReleasedBytes must never release'
    $relNames = @(Get-ChildItem (Join-Path $output 'released') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $relNames | Should -Not -Contain 'big.txt'
    $helNames = @(Get-ChildItem (Join-Path $output 'held') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $helNames | Should -Contain 'big.txt'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'big.txt' })[0]
    $heldEntry.heldReason | Should -Be 'over-byte-budget'
  }

  It 'at-limit: a file whose size is EXACTLY -MaxReleasedBytes passes (cap is inclusive)' {
    $exactBytes = [byte[]]::new(1024)
    $f = New-BudgetSafeFile -Name 'exact.txt' -Bytes $exactBytes
    $vfile = Join-Path $TestDrive 'at-limit-bytes.json'
    @($f.Verdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'at-limit-bytes-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile -MaxReleasedBytes 1024 -MaxReleasedFiles 16

    @($r.Released | ForEach-Object { $_.name }) | Should -Contain 'exact.txt' -Because 'a file exactly AT the byte cap must still release (cap is an inclusive upper bound)'
    $relNames = @(Get-ChildItem (Join-Path $output 'released') | ForEach-Object { $_.Name })
    $relNames | Should -Contain 'exact.txt'
  }

  It 'within-budget: a small file under -MaxReleasedBytes releases normally' {
    $smallBytes = [System.Text.Encoding]::UTF8.GetBytes('a small safe file, well under any reasonable byte budget')
    $f = New-BudgetSafeFile -Name 'small.txt' -Bytes $smallBytes
    $vfile = Join-Path $TestDrive 'within-budget.json'
    @($f.Verdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'within-budget-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile -MaxReleasedBytes 1048576 -MaxReleasedFiles 16

    @($r.Released | ForEach-Object { $_.name }) | Should -Contain 'small.txt'
  }

  It 'default budget: -MaxReleasedBytes defaults to 1 MiB (1048576) when not supplied' {
    # Pin the documented default so a future accidental change to the FORK constant is caught.
    # A file at exactly 1MiB+1 byte must be HELD under the DEFAULT (no -MaxReleasedBytes passed).
    $overDefaultBytes = [byte[]]::new(1048577)
    $f = New-BudgetSafeFile -Name 'over-default.txt' -Bytes $overDefaultBytes
    $vfile = Join-Path $TestDrive 'default-bytes.json'
    @($f.Verdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'default-bytes-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile

    @($r.Released | ForEach-Object { $_.name }) | Should -Not -Contain 'over-default.txt' -Because 'the default -MaxReleasedBytes is 1 MiB (1048576) -- a 1MiB+1 file must HELD under defaults'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'over-default.txt' })[0]
    $heldEntry.heldReason | Should -Be 'over-byte-budget'
  }

  It 'over-file-count: more than -MaxReleasedFiles SAFE candidates -> the excess are HELD (heldReason=over-file-budget), the rest release' {
    $countStaging = Join-Path $TestDrive 'count-staging'
    New-Item -ItemType Directory -Path $countStaging -Force | Out-Null
    $verdicts = @()
    for ($i = 1; $i -le 5; $i++) {
      $name = "file$i.txt"
      $bytes = [System.Text.Encoding]::UTF8.GetBytes("small safe content number $i, well under any byte cap")
      $path = Join-Path $countStaging $name
      [System.IO.File]::WriteAllBytes($path, $bytes)
      $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
      $verdicts += [pscustomobject]@{ name = $name; sha256 = $hash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() }
    }
    $vfile = Join-Path $TestDrive 'over-file-count.json'
    $verdicts | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'over-file-count-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $countStaging -OutputDir $output -VerdictsPath $vfile -MaxReleasedBytes 1048576 -MaxReleasedFiles 3

    @($r.Released).Count | Should -Be 3 -Because 'only the first -MaxReleasedFiles SAFE candidates may release; the excess is HELD (fail-closed, hold-all-over-cap)'
    @($r.Held | Where-Object { $_.heldReason -eq 'over-file-budget' }).Count | Should -Be 2 -Because 'exactly the overflow (5 candidates - 3 cap = 2) must be HELD with heldReason=over-file-budget'
    # released ⊆ SAFE still holds: nothing HELD by count leaks into released/.
    $relOnDisk = @(Get-ChildItem (Join-Path $output 'released') | ForEach-Object { $_.Name })
    $relOnDisk.Count | Should -Be 3
  }

  It 'at-file-count-limit: exactly -MaxReleasedFiles SAFE candidates all release (cap is inclusive)' {
    $countStaging = Join-Path $TestDrive 'count-limit-staging'
    New-Item -ItemType Directory -Path $countStaging -Force | Out-Null
    $verdicts = @()
    for ($i = 1; $i -le 3; $i++) {
      $name = "limit$i.txt"
      $bytes = [System.Text.Encoding]::UTF8.GetBytes("small safe content number $i")
      $path = Join-Path $countStaging $name
      [System.IO.File]::WriteAllBytes($path, $bytes)
      $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
      $verdicts += [pscustomobject]@{ name = $name; sha256 = $hash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() }
    }
    $vfile = Join-Path $TestDrive 'at-file-count-limit.json'
    $verdicts | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'at-file-count-limit-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $countStaging -OutputDir $output -VerdictsPath $vfile -MaxReleasedBytes 1048576 -MaxReleasedFiles 3

    @($r.Released).Count | Should -Be 3 -Because 'exactly AT the file-count cap must still all release (cap is an inclusive upper bound)'
  }

  It 'default budget: -MaxReleasedFiles defaults to 16 when not supplied' {
    $countStaging = Join-Path $TestDrive 'default-count-staging'
    New-Item -ItemType Directory -Path $countStaging -Force | Out-Null
    $verdicts = @()
    for ($i = 1; $i -le 17; $i++) {
      $name = "dflt$i.txt"
      $bytes = [System.Text.Encoding]::UTF8.GetBytes("small safe content number $i")
      $path = Join-Path $countStaging $name
      [System.IO.File]::WriteAllBytes($path, $bytes)
      $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
      $verdicts += [pscustomobject]@{ name = $name; sha256 = $hash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() }
    }
    $vfile = Join-Path $TestDrive 'default-count.json'
    $verdicts | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'default-count-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    # No -MaxReleasedFiles supplied -- exercise the documented default (16).
    $r = Invoke-SensitivityGate -StagingDir $countStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released).Count | Should -Be 16 -Because 'the default -MaxReleasedFiles is 16 -- 17 SAFE candidates means exactly 1 excess is HELD'
    @($r.Held | Where-Object { $_.heldReason -eq 'over-file-budget' }).Count | Should -Be 1
  }

  It 'sacred (tighten-only): the budget can only REMOVE files from released, never add — an over-budget file stays HELD even though it is otherwise a clean SAFE/enum-valid/hash-matching verdict' {
    # This is a regression guard for the SACRED invariant text in the plan: the budget is a
    # BACKSTOP layered strictly on top of the existing gates, never a path that could release
    # something the pre-C2.5 partition would have held.
    $bigBytes = [byte[]]::new(4096)
    $f = New-BudgetSafeFile -Name 'sacred-big.txt' -Bytes $bigBytes
    $vfile = Join-Path $TestDrive 'sacred.json'
    @($f.Verdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'sacred-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $f.StagingDir -OutputDir $output -VerdictsPath $vfile -MaxReleasedBytes 1024 -MaxReleasedFiles 16

    @($r.Released) | Should -BeNullOrEmpty
    (@($r.Held | Where-Object { $_.name -eq 'sacred-big.txt' })[0]).verdict | Should -Be 'SAFE' -Because 'the held audit entry keeps its true verdict=SAFE -- the budget HOLDS it, it does not relabel it as unsafe'
  }

  It 'existing processor e2e stays green: the messy-drive fixture SAFE files (small/few) still release under DEFAULT budgets' {
    $batchStaging = Join-Path $TestDrive 'default-batch-staging'
    New-Item -ItemType Directory -Path $batchStaging -Force | Out-Null
    Copy-Item "$PSScriptRoot/fixtures/messy-drive/*" $batchStaging
    function _h($n) { (Get-FileHash -LiteralPath (Join-Path $batchStaging $n) -Algorithm SHA256).Hash.ToLowerInvariant() }
    $vfile = Join-Path $TestDrive 'default-batch-verdicts.json'
    @(
      [pscustomobject]@{ name = 'creds.txt';             sha256 = (_h 'creds.txt');             verdict = 'HELD'; error_code = 'NONE';        flags = @('aws_key') }
      [pscustomobject]@{ name = 'finance-statement.txt'; sha256 = (_h 'finance-statement.txt'); verdict = 'HELD'; error_code = 'NONE';        flags = @('financial') }
      [pscustomobject]@{ name = 'health-note.txt';       sha256 = (_h 'health-note.txt');       verdict = 'HELD'; error_code = 'NONE';        flags = @('health') }
      [pscustomobject]@{ name = 'prose-essay.txt';       sha256 = (_h 'prose-essay.txt');       verdict = 'SAFE'; error_code = 'NONE';        flags = @() }
      [pscustomobject]@{ name = 'prose-letter.md';       sha256 = (_h 'prose-letter.md');       verdict = 'SAFE'; error_code = 'NONE';        flags = @() }
      [pscustomobject]@{ name = 'spreadsheet-dump.csv';  sha256 = (_h 'spreadsheet-dump.csv');  verdict = 'HELD'; error_code = 'UNSUPPORTED'; flags = @() }
      [pscustomobject]@{ name = 'prose-with-token.md';   sha256 = (_h 'prose-with-token.md');   verdict = 'HELD'; error_code = 'NONE';        flags = @('credential') }
    ) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'default-batch-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    # No -MaxReleasedBytes/-MaxReleasedFiles supplied -- exercise the production defaults.
    $r = Invoke-SensitivityGate -StagingDir $batchStaging -OutputDir $output -VerdictsPath $vfile

    $relNames = @($r.Released | ForEach-Object { $_.name })
    $relNames | Should -Contain 'prose-essay.txt'
    $relNames | Should -Contain 'prose-letter.md'
    @($r.Released).Count | Should -Be 2
  }
}

Describe 'screener.py Presidio+spaCy upgrade (regex/crude fallback, strictly tighter)' {
  BeforeAll {
    $script:screener = "$PSScriptRoot/../guest/screener.py"
    $script:hasPresidio = $false
    & python -c "import presidio_analyzer" 2>$null
    if ($LASTEXITCODE -eq 0) { $script:hasPresidio = $true }
    $script:hasSpacy = $false
    & python -c "import spacy; spacy.load('en_core_web_sm')" 2>$null
    if ($LASTEXITCODE -eq 0) { $script:hasSpacy = $true }

    $script:din = Join-Path $TestDrive 'pii-in'; New-Item -ItemType Directory -Path $script:din -Force | Out-Null
    # email-doc: clean PROSE that contains ONE email -> without the email regex it'd be SAFE; with it, HELD.
    Set-Content -LiteralPath (Join-Path $script:din 'email-doc.txt') -Value @'
I wanted to follow up on our wonderful conversation from last week about the community garden project. It was truly inspiring to see so many neighbors come together for a shared cause. If you have any further questions or would simply like to continue the discussion, please feel free to reach me at jane.doe@example.com whenever it is convenient for you. I look forward to hearing your thoughts and to working alongside everyone again very soon.
'@
    # Presidio fixture: clean prose (passes the crude floor -> SAFE dep-free) whose ONLY sensitive
    # feature is a private person name -> Presidio NER is the only stage that can demote it off SAFE.
    # Tests the high-risk SAFE->HELD path (a doc that WOULD be released without Presidio).
    # Fictional private name (not a public figure, which Presidio can deny-list / low-score).
    Set-Content -LiteralPath (Join-Path $script:din 'name-doc.txt') -Value @'
The afternoon review ran far longer than anyone had expected that day. Margaret Osei opened with a brief summary of the quarter and then handed the floor over to the rest of the group for comment. Questions came quickly, and the discussion soon wandered into territory that no one in the room had planned for at all. By the time the long session finally ended and the room emptied out, the early enthusiasm had given way to a quiet and thoughtful sort of fatigue.
'@
    # list-like: crude-prose-but-verb-poor -> passes the crude floor so the spaCy POS refinement is
    # the only stage that can demote it (otherwise this dep-gated test wouldn't exercise spaCy).
    # NO digits/numbering (digits lower the alpha ratio); noun phrases only (verb_ratio ~ 0 -> demote).
    Set-Content -LiteralPath (Join-Path $script:din 'list-like.txt') -Value @'
The weathered oak desk. A faded velvet armchair. The brass reading lamp. A small ceramic vase. The wooden coat rack. A worn leather satchel. The cast iron kettle. A folded woolen blanket. The polished silver tray. A chipped porcelain teacup. The dusty glass decanter. A frayed cotton rug. The tarnished copper pot. A cracked marble statue. The faded canvas tent. A rusty garden trowel. The chipped enamel basin. A tattered paper map. The smooth river stone. A bent willow basket. The hollow bamboo flute. A speckled robin egg. The gnarled apple branch. A pale autumn leaf.
'@
    $script:vout = Join-Path $TestDrive 'pii-verdicts.json'
    & python $script:screener --in $script:din --out $script:vout --mode aggressive
    $script:V = @(Get-Content $script:vout -Raw | ConvertFrom-Json)
  }
  It 'always (dep-free regex) marks a document containing an email HELD' {
    (@($script:V | Where-Object { $_.name -eq 'email-doc.txt' })[0]).verdict | Should -Be 'HELD'
  }
  It 'fail-closed preserved: the upgrade never promotes the HELD csv to SAFE' {
    # re-screen the messy-drive fixture; spreadsheet-dump.csv must remain non-SAFE regardless of deps.
    $mdOut = Join-Path $TestDrive 'md-verdicts.json'
    & python $script:screener --in (Join-Path $PSScriptRoot 'fixtures/messy-drive') --out $mdOut --mode aggressive
    $md = @(Get-Content $mdOut -Raw | ConvertFrom-Json)
    (@($md | Where-Object { $_.name -eq 'spreadsheet-dump.csv' })[0]).verdict | Should -Not -Be 'SAFE'
  }
  It 'marks a clean-prose doc with a private person name HELD (Presidio NER, SAFE->HELD path)' {
    if (-not $script:hasPresidio) { Set-ItResult -Skipped -Because 'Presidio not staged in this environment (live-run only)'; return }
    (@($script:V | Where-Object { $_.name -eq 'name-doc.txt' })[0]).verdict | Should -Be 'HELD'
  }
  It 'does NOT classify a list-like noun-phrase passage as SAFE prose (spaCy POS refinement)' {
    if (-not $script:hasSpacy) { Set-ItResult -Skipped -Because 'spaCy/en_core_web_sm not staged (live-run only)'; return }
    (@($script:V | Where-Object { $_.name -eq 'list-like.txt' })[0]).verdict | Should -Not -Be 'SAFE'
  }
}
