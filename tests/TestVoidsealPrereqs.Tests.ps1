#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for scripts/Test-VoidsealPrereqs.ps1 (Q-4: the one-command
    "do I qualify to run voidseal live" prerequisite gate).

.DESCRIPTION
    This is the fail-safe design's own proof: dot-source the script (which must NOT
    auto-run/print on dot-source — only on direct execution, per the script's own
    bottom-of-file guard) and assert Test-VoidsealPrereqs runs to completion WITHOUT
    throwing and WITHOUT elevation, on ANY host — including this CI/dev host, which may
    or may not actually have Hyper-V reachable. A check that cannot be verified (e.g.
    Get-WindowsOptionalFeature needing elevation) must degrade to an UNKNOWN row, never
    an unhandled exception and never a false PASS — that degrade-gracefully behavior is
    exactly what this file pins.

    Deliberately does NOT mock the Hyper-V/WMI surface: the whole point of the script is
    to run its OWN real inspection unelevated, so the test exercises that real path.
#>

BeforeAll {
    $script:RepoRoot   = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:RepoRoot 'scripts/Test-VoidsealPrereqs.ps1'

    Test-Path -LiteralPath $script:ScriptPath | Should -BeTrue -Because 'the prereq checker script must exist'

    # Dot-source: per the script's own design this must NOT auto-run/print anything
    # (the bottom-of-file invocation only fires when the script is executed directly,
    # not dot-sourced) — it just loads Test-VoidsealPrereqs into this scope.
    . $script:ScriptPath
}

Describe 'Test-VoidsealPrereqs — fail-safe read-only prerequisite checker' {

    It 'is defined after dot-sourcing the script' {
        Get-Command Test-VoidsealPrereqs -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'runs to completion without throwing, with no arguments (no elevation, no real Hyper-V required)' {
        { $script:Results = Test-VoidsealPrereqs } | Should -Not -Throw
        $script:Results | Should -Not -BeNullOrEmpty
    }

    It 'returns one row per check, each shaped {Name, Status, Detail, Critical}' {
        foreach ($row in @($script:Results)) {
            $row.PSObject.Properties.Name | Should -Contain 'Name'
            $row.PSObject.Properties.Name | Should -Contain 'Status'
            $row.PSObject.Properties.Name | Should -Contain 'Detail'
            $row.PSObject.Properties.Name | Should -Contain 'Critical'
            [string]::IsNullOrWhiteSpace($row.Name)   | Should -BeFalse -Because 'every row must be named'
            [string]::IsNullOrWhiteSpace($row.Detail)  | Should -BeFalse -Because 'every row must explain itself'
        }
    }

    It 'every row Status is one of PASS/FAIL/WARN/UNKNOWN — never a raw error object or empty string' {
        $allowed = @('PASS', 'FAIL', 'WARN', 'UNKNOWN')
        foreach ($row in @($script:Results)) {
            $row.Status | Should -BeIn $allowed -Because "row '$($row.Name)' must use the fixed status vocabulary"
        }
    }

    It 'checks the expected named preconditions (maps 1:1 to operator-runbook.md §0)' {
        $names = @($script:Results | ForEach-Object { $_.Name })
        $names | Should -Contain 'PowerShell >= 7'
        $names | Should -Contain 'Pester >= 5'
        $names | Should -Contain 'Windows edition supports Hyper-V'
        $names | Should -Contain 'Hyper-V feature enabled'
        $names -join ',' | Should -Match 'vmms'
        $names -join ',' | Should -Match 'Elevated'
        $names -join ',' | Should -Match 'Golden parent VHDX'
    }

    It 'reports PASS for this dev/CI host''s own PowerShell version (running under Pester means PS7 is present)' {
        ($script:Results | Where-Object Name -eq 'PowerShell >= 7').Status | Should -Be 'PASS'
    }

    It 'Pester is never a CRITICAL check (missing/old Pester must not gate the live-run verdict)' {
        ($script:Results | Where-Object Name -eq 'Pester >= 5').Critical | Should -BeFalse
    }

    It 'WARNs (not FAILs) on the golden VHDX check when -ParentDiskPath is omitted' {
        $vhdxRow = $script:Results | Where-Object Name -eq 'Golden parent VHDX (-ParentDiskPath)'
        $vhdxRow.Status | Should -Be 'WARN' -Because 'the checker must stay useful without a golden image path'
    }

    It 'FAILs the golden VHDX check when -ParentDiskPath points at a nonexistent file' {
        $bogus = Join-Path $TestDrive 'does-not-exist.vhdx'
        $withPath = Test-VoidsealPrereqs -ParentDiskPath $bogus
        ($withPath | Where-Object Name -eq 'Golden parent VHDX (-ParentDiskPath)').Status | Should -Be 'FAIL'
    }

    It 'PASSes the golden VHDX check when -ParentDiskPath points at a real file' {
        $real = Join-Path $TestDrive 'golden.vhdx'
        Set-Content -LiteralPath $real -Value 'not a real vhdx, just a placeholder for Test-Path' -Encoding UTF8
        $withPath = Test-VoidsealPrereqs -ParentDiskPath $real
        ($withPath | Where-Object Name -eq 'Golden parent VHDX (-ParentDiskPath)').Status | Should -Be 'PASS'
    }

    It 'never crashes the Hyper-V-feature check even without elevation (UNKNOWN or PASS/FAIL, never a raised exception)' {
        # This is the fail-safe assertion the whole task hinges on: a check that lacks the
        # rights to run (Get-WindowsOptionalFeature -Online commonly needs elevation) must
        # degrade to UNKNOWN with a note, never throw and never silently report PASS.
        $featureRow = $script:Results | Where-Object Name -eq 'Hyper-V feature enabled'
        $featureRow | Should -Not -BeNullOrEmpty
        $featureRow.Status | Should -BeIn @('PASS', 'FAIL', 'UNKNOWN')
    }
}

Describe 'Get-VoidsealOverallVerdict — verdict folding' {

    It 'reports NOT READY when any CRITICAL row is FAIL' {
        $rows = @(
            [pscustomobject]@{ Name = 'a'; Status = 'PASS'; Detail = 'ok'; Critical = $true }
            [pscustomobject]@{ Name = 'b'; Status = 'FAIL'; Detail = 'bad'; Critical = $true }
        )
        Get-VoidsealOverallVerdict -Results $rows | Should -Match '^NOT READY'
    }

    It 'reports UNKNOWN when no CRITICAL row FAILs but one is UNKNOWN' {
        $rows = @(
            [pscustomobject]@{ Name = 'a'; Status = 'PASS'; Detail = 'ok'; Critical = $true }
            [pscustomobject]@{ Name = 'b'; Status = 'UNKNOWN'; Detail = 'dunno'; Critical = $true }
        )
        Get-VoidsealOverallVerdict -Results $rows | Should -Match '^UNKNOWN'
    }

    It 'reports READY when every CRITICAL row PASSes, regardless of non-critical WARN/FAIL' {
        $rows = @(
            [pscustomobject]@{ Name = 'a'; Status = 'PASS'; Detail = 'ok'; Critical = $true }
            [pscustomobject]@{ Name = 'b'; Status = 'WARN'; Detail = 'meh'; Critical = $true }
            [pscustomobject]@{ Name = 'c'; Status = 'FAIL'; Detail = 'not critical'; Critical = $false }
        )
        Get-VoidsealOverallVerdict -Results $rows | Should -Match '^READY'
    }
}

Describe 'Direct execution vs. dot-source — the bottom-of-file guard' {

    It 'does NOT print the report banner when dot-sourced (already proven implicitly by BeforeAll, pinned explicitly here)' {
        # Re-dot-source in an isolated child scope and capture ALL output streams; the
        # banner text ("Voidseal prerequisite check") must not appear.
        $out = & {
            . $script:ScriptPath
        } *>&1 | Out-String
        $out | Should -Not -Match 'Voidseal prerequisite check'
    }
}
