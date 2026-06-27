Describe 'screener.py verdicts' {
  BeforeAll {
    $fx = Join-Path $PSScriptRoot 'fixtures/messy-drive'
    $out = Join-Path $env:TEMP "screen-$([guid]::NewGuid())"; New-Item -ItemType Directory -Path $out | Out-Null
    python "$PSScriptRoot/../guest/screener.py" --in $fx --out "$out/verdicts.json" --mode aggressive
    $script:V = Get-Content "$out/verdicts.json" -Raw | ConvertFrom-Json
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
  It 'defaults unknown/non-prose to UNCERTAIN (fail-closed), never SAFE-by-omission' {
    ($V | Where-Object name -eq 'spreadsheet-dump.csv').verdict | Should -BeIn @('UNCERTAIN','SENSITIVE')
  }
}
