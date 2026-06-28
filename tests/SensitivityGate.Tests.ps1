Describe 'screener.py verdicts' {
  BeforeAll {
    $fx = Join-Path $PSScriptRoot 'fixtures/messy-drive'
    $script:out = Join-Path $env:TEMP "screen-$([guid]::NewGuid())"; New-Item -ItemType Directory -Path $script:out | Out-Null
    python "$PSScriptRoot/../guest/screener.py" --in $fx --out "$script:out/verdicts.json" --mode aggressive
    $script:V = Get-Content "$script:out/verdicts.json" -Raw | ConvertFrom-Json
  }
  It 'marks the credential file SENSITIVE' {
    ($V | Where-Object name -eq 'creds.txt').verdict | Should -Be 'SENSITIVE'
  }
  It 'marks the finance file SENSITIVE' {
    ($V | Where-Object name -eq 'finance-statement.txt').verdict | Should -Be 'SENSITIVE'
  }
  It 'marks the health file SENSITIVE' {
    ($V | Where-Object name -eq 'health-note.txt').verdict | Should -Be 'SENSITIVE'
  }
  It 'marks clean prose SAFE' {
    ($V | Where-Object name -eq 'prose-essay.txt').verdict | Should -Be 'SAFE'
  }
  It 'marks clean cover-letter prose SAFE' {
    ($V | Where-Object name -eq 'prose-letter.md').verdict | Should -Be 'SAFE'
  }
  It 'marks a credential embedded in prose SENSITIVE (env-var pattern, never SAFE)' {
    ($V | Where-Object name -eq 'prose-with-token.md').verdict | Should -Be 'SENSITIVE'
  }
  It 'defaults unknown/non-prose to UNCERTAIN (fail-closed), never SAFE-by-omission' {
    ($V | Where-Object name -eq 'spreadsheet-dump.csv').verdict | Should -BeIn @('UNCERTAIN','SENSITIVE')
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
    $script:r.Released | ForEach-Object { $_.verdict | Should -Be 'SAFE' }  # released ⊆ SAFE
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
    # email-doc: clean PROSE that contains ONE email -> without the email regex it'd be SAFE; with it, SENSITIVE.
    Set-Content -LiteralPath (Join-Path $script:din 'email-doc.txt') -Value @'
I wanted to follow up on our wonderful conversation from last week about the community garden project. It was truly inspiring to see so many neighbors come together for a shared cause. If you have any further questions or would simply like to continue the discussion, please feel free to reach me at jane.doe@example.com whenever it is convenient for you. I look forward to hearing your thoughts and to working alongside everyone again very soon.
'@
    # name-doc: prose with a clear PERSON name (Presidio NER target).
    Set-Content -LiteralPath (Join-Path $script:din 'name-doc.txt') -Value @'
The keynote was delivered by Barack Obama, who spoke at length about civic participation and the importance of local engagement. The audience listened intently as the speaker walked through several stories drawn from years of public service, and the room responded warmly to each reflection offered throughout the long and memorable afternoon session.
'@
    # numbered-list: NON-narrative list that the crude heuristic may call SAFE but spaCy should reject.
    Set-Content -LiteralPath (Join-Path $script:din 'numbered-list.txt') -Value @'
1. Widget. 2. Gadget. 3. Sprocket. 4. Flange. 5. Bracket. 6. Coupler. 7. Bearing. 8. Washer. 9. Gasket. 10. Bolt. 11. Nut. 12. Pin. 13. Clip. 14. Rivet. 15. Spacer. 16. Shim. 17. Dowel. 18. Stud. 19. Ferrule. 20. Grommet. 21. Bushing. 22. Collar. 23. Sleeve. 24. Cap. 25. Plug.
'@
    $script:vout = Join-Path $TestDrive 'pii-verdicts.json'
    & python $script:screener --in $script:din --out $script:vout --mode aggressive
    $script:V = @(Get-Content $script:vout -Raw | ConvertFrom-Json)
  }
  It 'always (dep-free regex) marks a document containing an email SENSITIVE' {
    (@($script:V | Where-Object { $_.name -eq 'email-doc.txt' })[0]).verdict | Should -Be 'SENSITIVE'
  }
  It 'fail-closed preserved: the upgrade never promotes the UNCERTAIN csv to SAFE' {
    # re-screen the messy-drive fixture; spreadsheet-dump.csv must remain non-SAFE regardless of deps.
    $mdOut = Join-Path $TestDrive 'md-verdicts.json'
    & python $script:screener --in (Join-Path $PSScriptRoot 'fixtures/messy-drive') --out $mdOut --mode aggressive
    $md = @(Get-Content $mdOut -Raw | ConvertFrom-Json)
    (@($md | Where-Object { $_.name -eq 'spreadsheet-dump.csv' })[0]).verdict | Should -Not -Be 'SAFE'
  }
  It 'marks a PII person-name document SENSITIVE (Presidio NER)' {
    if (-not $script:hasPresidio) { Set-ItResult -Skipped -Because 'Presidio not staged in this environment (live-run only)'; return }
    (@($script:V | Where-Object { $_.name -eq 'name-doc.txt' })[0]).verdict | Should -Be 'SENSITIVE'
  }
  It 'does NOT classify a numbered list as SAFE prose (spaCy POS refinement)' {
    if (-not $script:hasSpacy) { Set-ItResult -Skipped -Because 'spaCy/en_core_web_sm not staged (live-run only)'; return }
    (@($script:V | Where-Object { $_.name -eq 'numbered-list.txt' })[0]).verdict | Should -Not -Be 'SAFE'
  }
}
