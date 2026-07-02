# C2.6 — runs/day release rate cap (host-enforced, fail-closed backstop).
#
# Intent (plan _dev/plans/2026-07-01-pre-phase6-hardening-plan.md, Task C2.6): cap AGGREGATE
# leakage (per-run bits x runs/interval), on top of the C2.4 regenerator + C2.5 byte-budget
# backstops. A host-side JSON ledger, keyed by PROFILE + UTC DAY, tracks how many times a
# profile's screener has RELEASED (a "release event" = one Invoke-SensitivityGate run whose
# .Released is non-empty; see ReleaseGovernor.ps1 header for the exact semantics) in the
# current day. Before a processor run is allowed to release, the gate consults the ledger:
# at/under the cap -> proceed (and increment on an actual release); over the cap -> DENY
# (hold everything this run, heldReason='over-rate-cap', release nothing).
#
# FAIL-CLOSED: an unreadable/corrupt ledger, or a missing ledger that cannot be freshly
# written, is UNKNOWN state -> DENY (never silently treated as "0 releases today").
#
# Determinism: -RateLedgerPath (mirrors -ScreenerPath/-VerdictsPath injection) points every
# test at a $TestDrive ledger file -- no global host state is ever touched. -Today is injected
# as a fixed 'yyyy-MM-dd' UTC string so no test depends on the real wall clock.

Describe 'ReleaseGovernor -- Test-ReleaseAllowed / Register-Release (ledger primitives)' {
  BeforeAll {
    . "$PSScriptRoot/../scripts/lib/ReleaseGovernor.ps1"
  }

  It 'a missing ledger file is treated as zero releases today (fresh state) -- allowed under any cap >= 1' {
    $ledger = Join-Path $TestDrive 'fresh-missing-ledger.json'
    Test-Path -LiteralPath $ledger | Should -BeFalse

    $allowed = Test-ReleaseAllowed -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01' -MaxReleasesPerDay 1
    $allowed | Should -BeTrue
  }

  It 'Register-Release creates the ledger file on first use and records one release for today' {
    $ledger = Join-Path $TestDrive 'first-register-ledger.json'
    Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01'

    Test-Path -LiteralPath $ledger | Should -BeTrue
    $doc = Get-Content -LiteralPath $ledger -Raw | ConvertFrom-Json
    $doc.ralph.'2026-07-01' | Should -Be 1
  }

  It 'Register-Release increments an existing count for the same profile+day' {
    $ledger = Join-Path $TestDrive 'increment-ledger.json'
    Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01'
    Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01'
    Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01'

    $doc = Get-Content -LiteralPath $ledger -Raw | ConvertFrom-Json
    $doc.ralph.'2026-07-01' | Should -Be 3
  }

  It 'the ledger is keyed PER-PROFILE -- a different profile has an independent count' {
    $ledger = Join-Path $TestDrive 'per-profile-ledger.json'
    Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01'
    Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01'
    Register-Release -Profile 'other-processor' -LedgerPath $ledger -Today '2026-07-01'

    $doc = Get-Content -LiteralPath $ledger -Raw | ConvertFrom-Json
    $doc.ralph.'2026-07-01' | Should -Be 2
    $doc.'other-processor'.'2026-07-01' | Should -Be 1
  }

  It 'a fresh UTC day resets the count -- yesterday''s releases do not count against today''s cap' {
    $ledger = Join-Path $TestDrive 'day-reset-ledger.json'
    # Seed yesterday at the cap.
    for ($i = 0; $i -lt 5; $i++) { Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-06-30' }

    $allowed = Test-ReleaseAllowed -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01' -MaxReleasesPerDay 5
    $allowed | Should -BeTrue -Because 'the UTC day changed -- yesterday''s count must not carry over'

    $doc = Get-Content -LiteralPath $ledger -Raw | ConvertFrom-Json
    $doc.ralph.'2026-06-30' | Should -Be 5 -Because 'the historical day''s count is preserved on disk, just not consulted for a different day'
  }

  It 'at-cap: exactly -MaxReleasesPerDay releases already today -> the NEXT release is DENIED (cap is an inclusive-used, exclusive-next bound)' {
    $ledger = Join-Path $TestDrive 'at-cap-ledger.json'
    for ($i = 0; $i -lt 3; $i++) { Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01' }

    $allowed = Test-ReleaseAllowed -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01' -MaxReleasesPerDay 3
    $allowed | Should -BeFalse -Because 'the day already has 3 releases against a cap of 3 -- a 4th would exceed it'
  }

  It 'under-cap: 2 releases today against a cap of 3 -> allowed (a 3rd release would land exactly at the cap)' {
    $ledger = Join-Path $TestDrive 'under-cap-ledger.json'
    for ($i = 0; $i -lt 2; $i++) { Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01' }

    $allowed = Test-ReleaseAllowed -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01' -MaxReleasesPerDay 3
    $allowed | Should -BeTrue
  }

  It 'fail-closed: a CORRUPT ledger (invalid JSON) -> DENY, never treated as zero-releases' {
    $ledger = Join-Path $TestDrive 'corrupt-ledger.json'
    Set-Content -LiteralPath $ledger -Value '{ this is not valid json ][' -Encoding utf8

    $allowed = Test-ReleaseAllowed -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01' -MaxReleasesPerDay 100
    $allowed | Should -BeFalse -Because 'an unparseable ledger cannot prove the profile is under-cap -- fail closed, even with a huge cap'
  }

  It 'fail-closed: a ledger whose per-profile value is not a valid count (e.g. a nested object) -> DENY' {
    $ledger = Join-Path $TestDrive 'malformed-shape-ledger.json'
    '{"ralph": {"2026-07-01": "not-a-number"}}' | Set-Content -LiteralPath $ledger -Encoding utf8

    $allowed = Test-ReleaseAllowed -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01' -MaxReleasesPerDay 100
    $allowed | Should -BeFalse -Because 'a non-numeric count is an untrustworthy ledger shape -- fail closed'
  }

  It 'fail-closed: an UNREADABLE ledger path (a directory, not a file) -> DENY' {
    # A directory at the ledger path makes Get-Content fail -- must DENY, not silently pass.
    $ledger = Join-Path $TestDrive 'ledger-is-a-directory.json'
    New-Item -ItemType Directory -Path $ledger -Force | Out-Null

    $allowed = Test-ReleaseAllowed -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01' -MaxReleasesPerDay 100
    $allowed | Should -BeFalse -Because 'a ledger path that cannot be read as a file cannot prove under-cap -- fail closed'
  }

  It 'fail-closed: a missing-but-UNWRITABLE ledger directory -> Register-Release throws (never silently drops the increment)' {
    # A LedgerPath whose parent directory does not exist and cannot be created (points inside
    # a file, not a directory) models "missing but unwritable" -- the write must fail loudly,
    # never silently succeed-but-not-persist (which would let releases go uncounted).
    $blocker = Join-Path $TestDrive 'blocker-file.json'
    Set-Content -LiteralPath $blocker -Value 'not a directory' -Encoding utf8
    $ledger = Join-Path $blocker 'nested/ledger.json'

    { Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01' } | Should -Throw
  }
}

Describe 'Invoke-SensitivityGate -- C2.6 runs/day rate cap integration (over-cap -> DENY/hold-all, under-cap -> release + increment)' {
  BeforeAll {
    . "$PSScriptRoot/../scripts/lib/SensitivityGate.ps1"

    $script:rateStaging = Join-Path $TestDrive 'rate-staging'
    New-Item -ItemType Directory -Path $script:rateStaging -Force | Out-Null
    $script:safeBytes = [System.Text.Encoding]::UTF8.GetBytes(
      "A quiet stream wound through the valley, catching the late afternoon sun on its ripples."
    )
    [System.IO.File]::WriteAllBytes((Join-Path $script:rateStaging 'note.txt'), $script:safeBytes)
    $script:safeHash = (Get-FileHash -LiteralPath (Join-Path $script:rateStaging 'note.txt') -Algorithm SHA256).Hash.ToLowerInvariant()
    $script:safeVerdict = [pscustomobject]@{ name = 'note.txt'; sha256 = $script:safeHash; verdict = 'SAFE'; error_code = 'NONE'; flags = @() }
  }

  It 'under-cap: a release proceeds normally and increments the ledger by one release event' {
    $vfile = Join-Path $TestDrive 'under-cap-gate.json'
    @($script:safeVerdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'under-cap-gate-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    $ledger = Join-Path $TestDrive 'under-cap-gate-ledger.json'

    $r = Invoke-SensitivityGate -StagingDir $script:rateStaging -OutputDir $output -VerdictsPath $vfile `
           -RateLedgerPath $ledger -RateProfile 'ralph' -RateToday '2026-07-01' -MaxReleasesPerDay 5

    @($r.Released | ForEach-Object { $_.name }) | Should -Contain 'note.txt'
    $doc = Get-Content -LiteralPath $ledger -Raw | ConvertFrom-Json
    $doc.ralph.'2026-07-01' | Should -Be 1
  }

  It 'over-cap: the ledger pre-seeded AT the cap for today -> the gate holds EVERYTHING (heldReason=over-rate-cap), .Released empty' {
    . "$PSScriptRoot/../scripts/lib/ReleaseGovernor.ps1"
    $ledger = Join-Path $TestDrive 'over-cap-gate-ledger.json'
    Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01'
    Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01'

    $vfile = Join-Path $TestDrive 'over-cap-gate.json'
    @($script:safeVerdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'over-cap-gate-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:rateStaging -OutputDir $output -VerdictsPath $vfile `
           -RateLedgerPath $ledger -RateProfile 'ralph' -RateToday '2026-07-01' -MaxReleasesPerDay 2

    @($r.Released) | Should -BeNullOrEmpty -Because 'the day is already at the 2-release cap -- this run must release nothing'
    $relNames = @(Get-ChildItem (Join-Path $output 'released') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $relNames | Should -Not -Contain 'note.txt'
    $helNames = @(Get-ChildItem (Join-Path $output 'held') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $helNames | Should -Contain 'note.txt'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'note.txt' })[0]
    $heldEntry.heldReason | Should -Be 'over-rate-cap'
  }

  It 'over-cap: the ledger count is NOT incremented further by a denied run (a DENY is not itself a release)' {
    . "$PSScriptRoot/../scripts/lib/ReleaseGovernor.ps1"
    $ledger = Join-Path $TestDrive 'over-cap-no-increment-ledger.json'
    Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01'

    $vfile = Join-Path $TestDrive 'over-cap-no-increment-gate.json'
    @($script:safeVerdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'over-cap-no-increment-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $null = Invoke-SensitivityGate -StagingDir $script:rateStaging -OutputDir $output -VerdictsPath $vfile `
              -RateLedgerPath $ledger -RateProfile 'ralph' -RateToday '2026-07-01' -MaxReleasesPerDay 1

    $doc = Get-Content -LiteralPath $ledger -Raw | ConvertFrom-Json
    $doc.ralph.'2026-07-01' | Should -Be 1 -Because 'a DENIED run must not itself be counted as a release'
  }

  It 'fail-closed: an unreadable/corrupt ledger -> DENY (hold everything), even though the file would release under normal partition rules' {
    $ledger = Join-Path $TestDrive 'gate-corrupt-ledger.json'
    Set-Content -LiteralPath $ledger -Value 'not valid json [[' -Encoding utf8

    $vfile = Join-Path $TestDrive 'gate-corrupt-ledger-verdicts.json'
    @($script:safeVerdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'gate-corrupt-ledger-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:rateStaging -OutputDir $output -VerdictsPath $vfile `
           -RateLedgerPath $ledger -RateProfile 'ralph' -RateToday '2026-07-01' -MaxReleasesPerDay 1000

    @($r.Released) | Should -BeNullOrEmpty -Because 'a corrupt ledger cannot prove under-cap, regardless of how high the cap is'
    $heldEntry = @($r.Held | Where-Object { $_.name -eq 'note.txt' })[0]
    $heldEntry.heldReason | Should -Be 'over-rate-cap'
  }

  It 'no rate-cap params supplied: the gate behaves exactly as before C2.6 (no -RateLedgerPath -> the rate-cap check is skipped, not enforced against an implicit ledger)' {
    # C2.6 is an OPT-IN backstop layered on top of C2.4/C2.5 -- a caller that does not pass
    # -RateLedgerPath (e.g. every pre-C2.6 test in this suite, and Run-mode callers) must see
    # unchanged behavior. This guards against C2.6 silently becoming a mandatory global gate
    # keyed on some default path that could collide across unrelated test runs.
    $vfile = Join-Path $TestDrive 'no-ratecap-verdicts.json'
    @($script:safeVerdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'no-ratecap-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:rateStaging -OutputDir $output -VerdictsPath $vfile

    @($r.Released | ForEach-Object { $_.name }) | Should -Contain 'note.txt'
  }

  It 'sacred (tighten-only): an over-cap HELD entry keeps its true verdict=SAFE in the audit record -- the cap HOLDS, it does not relabel' {
    $ledger = Join-Path $TestDrive 'sacred-ratecap-ledger.json'
    . "$PSScriptRoot/../scripts/lib/ReleaseGovernor.ps1"
    Register-Release -Profile 'ralph' -LedgerPath $ledger -Today '2026-07-01'

    $vfile = Join-Path $TestDrive 'sacred-ratecap.json'
    @($script:safeVerdict) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $vfile -Encoding utf8
    $output = Join-Path $TestDrive 'sacred-ratecap-out'
    New-Item -ItemType Directory -Path $output -Force | Out-Null

    $r = Invoke-SensitivityGate -StagingDir $script:rateStaging -OutputDir $output -VerdictsPath $vfile `
           -RateLedgerPath $ledger -RateProfile 'ralph' -RateToday '2026-07-01' -MaxReleasesPerDay 1

    (@($r.Held | Where-Object { $_.name -eq 'note.txt' })[0]).verdict | Should -Be 'SAFE' -Because 'the rate cap HOLDS an otherwise-SAFE file -- it never relabels the underlying verdict'
  }
}
