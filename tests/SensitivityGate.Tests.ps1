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
    $heldNames | Should -Contain 'creds.txt'
    $heldNames | Should -Contain 'spreadsheet-dump.csv'   # UNCERTAIN is held too (fail-closed)
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
}
