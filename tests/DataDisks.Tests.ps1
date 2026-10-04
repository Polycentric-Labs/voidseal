#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for pre-built data disks (scripts/lib/DataDisks.ps1 and its callers).

.DESCRIPTION
    Covers the shared verify-before-attach helper (also used by the DEPS disk), the DataDisks
    declaration and its fail-closed refusals, attach and record before the seal, seal acceptance,
    the guest runner mount lines, the post-run re-hash, the CopyDirectoryToVhdx backend method and
    scripts/New-VoidsealDataDisk.ps1. Everything runs against the fake backend: no VM, no elevation.
#>

BeforeAll {
    $script:SkillRoot = Split-Path -Parent $PSScriptRoot
    $script:TierDir   = Join-Path $script:SkillRoot 'tier-profiles'
    . (Join-Path $script:SkillRoot 'scripts/Invoke-Voidseal.ps1')
}

Describe 'Assert-DiskImageVerified (the shared verify-before-attach helper)' {

    BeforeAll {
        $script:VerifyArgs = {
            param($Backend, $Path, $Hash)
            @{
                VMName             = 'vm-verify'
                Path               = $Path
                ExpectedHash       = $Hash
                DiskLabel          = "data disk 'corpus'"
                DiskKind           = 'data disk'
                MissingHashMessage = 'no hash was supplied for this disk'
                HashOrigin         = 'operator-recorded'
                Backend            = $Backend
            }
        }
    }

    It 'returns the verified lowercase hash when the expected hash matches (case-insensitive, trimmed)' {
        $b = New-FakeHyperVBackend
        $p = 'C:\data\corpus.vhdx'
        & $b.NewVHD @{ Path = $p; SizeBytes = 1GB; Dynamic = $true }
        $h = [string](& $b.GetVhdxImageHash @{ Path = $p })
        $a = & $script:VerifyArgs $b $p ("  " + $h.ToUpperInvariant() + " ")
        Assert-DiskImageVerified @a | Should -Be $h
    }

    It 'refuses a disk GetVHDInfo cannot read (missing file)' {
        $b = New-FakeHyperVBackend
        $a = & $script:VerifyArgs $b 'C:\data\absent.vhdx' ('a' * 64)
        { Assert-DiskImageVerified @a } | Should -Throw -ExpectedMessage '*unreadable via GetVHDInfo*'
    }

    It 'refuses a differencing disk before hashing it' {
        $b = New-FakeHyperVBackend
        $p = 'C:\data\diff.vhdx'
        & $b.NewVHD @{ Path = $p; Differencing = $true; ParentPath = 'C:\elsewhere\parent.vhdx' }
        $a = & $script:VerifyArgs $b $p ('a' * 64)
        { Assert-DiskImageVerified @a } | Should -Throw -ExpectedMessage '*DIFFERENCING*'
        @($b.FakeCallLog | Where-Object { $_.Op -eq 'GetVhdxImageHash' }).Count | Should -Be 0 -Because 'structure is checked before any hash'
    }

    It 'refuses a missing expected hash with the caller''s message' {
        $b = New-FakeHyperVBackend
        $p = 'C:\data\corpus.vhdx'
        & $b.NewVHD @{ Path = $p; SizeBytes = 1GB; Dynamic = $true }
        $a = & $script:VerifyArgs $b $p ''
        { Assert-DiskImageVerified @a } | Should -Throw -ExpectedMessage 'no hash was supplied for this disk'
    }

    It 'refuses a mismatched hash and names both values' {
        $b = New-FakeHyperVBackend
        $p = 'C:\data\corpus.vhdx'
        & $b.NewVHD @{ Path = $p; SizeBytes = 1GB; Dynamic = $true }
        $a = & $script:VerifyArgs $b $p ('0' * 64)
        { Assert-DiskImageVerified @a } | Should -Throw -ExpectedMessage '*integrity check FAILED*operator-recorded*'
    }

    It 'never attaches anything itself (the caller owns attach and record)' {
        $b = New-FakeHyperVBackend
        $p = 'C:\data\corpus.vhdx'
        & $b.NewVHD @{ Path = $p; SizeBytes = 1GB; Dynamic = $true }
        $h = [string](& $b.GetVhdxImageHash @{ Path = $p })
        $a = & $script:VerifyArgs $b $p $h
        $null = Assert-DiskImageVerified @a
        @($b.FakeCallLog | Where-Object { $_.Op -eq 'GetVhdxImageHash' }).Count | Should -Be 2 -Because 'one hash in the test setup, one in the helper'
        # Structurally: the only backend members the helper touches are the two read-only probes.
        $ast = (Get-Command Assert-DiskImageVerified).ScriptBlock.Ast
        $members = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and
                                    $n.Expression.Extent.Text -eq '$Backend' }, $true) |
                     ForEach-Object { $_.Member.Extent.Text } | Sort-Object -Unique)
        $members | Should -Be @('GetVHDInfo', 'GetVhdxImageHash') -Because 'verification must never attach or mount'
        @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                         $n.GetCommandName() -match 'Mount-VHD|Add-VMHardDiskDrive' }, $true)).Count | Should -Be 0
    }
}
