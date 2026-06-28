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
    @($report.released | ForEach-Object { $_.verdict } | Where-Object { $_ -ne 'SAFE' }).Count | Should -Be 0
    @($report.held | ForEach-Object { $_.name }) | Should -Contain 'creds.txt'
    $report.total | Should -Be 7
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
    # Presidio fixture: clean prose (passes the crude floor -> SAFE dep-free) whose ONLY sensitive
    # feature is a private person name -> Presidio NER is the only stage that can demote it off SAFE.
    # Tests the high-risk SAFE->SENSITIVE path (a doc that WOULD be released without Presidio).
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
  It 'marks a clean-prose doc with a private person name SENSITIVE (Presidio NER, SAFE->SENSITIVE path)' {
    if (-not $script:hasPresidio) { Set-ItResult -Skipped -Because 'Presidio not staged in this environment (live-run only)'; return }
    (@($script:V | Where-Object { $_.name -eq 'name-doc.txt' })[0]).verdict | Should -Be 'SENSITIVE'
  }
  It 'does NOT classify a list-like noun-phrase passage as SAFE prose (spaCy POS refinement)' {
    if (-not $script:hasSpacy) { Set-ItResult -Skipped -Because 'spaCy/en_core_web_sm not staged (live-run only)'; return }
    (@($script:V | Where-Object { $_.name -eq 'list-like.txt' })[0]).verdict | Should -Not -Be 'SAFE'
  }
}
