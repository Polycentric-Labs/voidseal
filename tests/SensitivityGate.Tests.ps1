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
