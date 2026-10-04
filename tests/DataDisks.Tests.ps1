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

    # A Disk-mode, transport-only outbox profile (the firefox shape): the kind of run data disks serve.
    $script:Fx = @{} + (Import-TierProfile -Path (Join-Path $script:TierDir 'tier0.psd1'))
    $script:Fx['Name']         = 'datadisk-test'
    $script:Fx['WorkloadMode'] = 'Disk'
    $script:Fx['Inputs']       = @{}
    $script:Fx['FileSystem']   = 'exFAT'
    $script:Fx['OutboxOutput'] = $true
    $script:Fx['Entrypoint']   = 'python3 /mnt/in/summarize.py --corpus /mnt/data/corpus --out /run/staging/result.html'
    Assert-TierProfileValid -Profile $script:Fx -Context 'TEST data-disk fixture'

    # Data disks live OUTSIDE the sandbox storage root; these paths are fake-backend records only.
    $script:DataRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vs-datadisk-{0}" -f ([guid]::NewGuid().ToString('N')))
    $script:Decl = {
        param([string] $Name, [string] $Path, [string] $Hash)
        if (-not $Path) { $Path = Join-Path $script:DataRoot "$Name.vhdx" }
        if (-not $Hash) { $Hash = 'a' * 64 }
        @{ Name = $Name; Path = $Path; ImageHash = $Hash }
    }
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

Describe 'ConvertTo-DataDiskList (declaration validation, pure)' {

    It 'normalizes a valid declaration: canonical path, lowercase hash, entry order kept' {
        $list = ConvertTo-DataDiskList -Value @(
            @{ Name = 'corpus'; Path = 'C:\vs\data\..\data\corpus.vhdx'; ImageHash = ('AB' * 32) },
            @{ Name = 'wheels'; Path = 'C:\vs\data\wheels.VHDX'; ImageHash = ('0' * 64) }
        )
        $list.Count | Should -Be 2
        $list[0].Name | Should -Be 'corpus'
        $list[0].Path | Should -Be 'C:\vs\data\corpus.vhdx'
        $list[0].ImageHash | Should -BeExactly ('ab' * 32)
        $list[1].Name | Should -Be 'wheels'
    }

    It 'accepts a single hashtable and $null' {
        @(ConvertTo-DataDiskList -Value @{ Name = 'one'; Path = 'C:\vs\one.vhdx'; ImageHash = ('f' * 64) }).Count | Should -Be 1
        @(ConvertTo-DataDiskList -Value $null).Count | Should -Be 0
    }

    It 'refuses the name <Name>' -TestCases @(
        @{ Name = 'Corpus' }, @{ Name = 'toolongname' }, @{ Name = '' }, @{ Name = 'a b' },
        @{ Name = 'x;rm' }, @{ Name = '../x' }, @{ Name = 'a$(id)' }, @{ Name = "a`nb" }, @{ Name = 'dat-a' }
    ) {
        param($Name)
        { ConvertTo-DataDiskList -Value @{ Name = $Name; Path = 'C:\vs\x.vhdx'; ImageHash = ('a' * 64) } } |
            Should -Throw -ExpectedMessage '*name*'
    }

    It 'refuses duplicate names' {
        { ConvertTo-DataDiskList -Value @(
            @{ Name = 'dup'; Path = 'C:\vs\a.vhdx'; ImageHash = ('a' * 64) },
            @{ Name = 'dup'; Path = 'C:\vs\b.vhdx'; ImageHash = ('a' * 64) }) } | Should -Throw -ExpectedMessage '*more than once*'
    }

    It 'refuses the same path twice, even in another case or form' {
        { ConvertTo-DataDiskList -Value @(
            @{ Name = 'a'; Path = 'C:\vs\same.vhdx'; ImageHash = ('a' * 64) },
            @{ Name = 'b'; Path = 'c:\VS\x\..\SAME.vhdx'; ImageHash = ('a' * 64) }) } | Should -Throw -ExpectedMessage '*more than once*'
    }

    It 'refuses more than 8 data disks' {
        $nine = 1..9 | ForEach-Object { @{ Name = "d$_"; Path = "C:\vs\d$_.vhdx"; ImageHash = ('a' * 64) } }
        { ConvertTo-DataDiskList -Value $nine } | Should -Throw -ExpectedMessage '*at most 8*'
        $eight = 1..8 | ForEach-Object { @{ Name = "d$_"; Path = "C:\vs\d$_.vhdx"; ImageHash = ('a' * 64) } }
        @(ConvertTo-DataDiskList -Value $eight).Count | Should -Be 8
    }

    It 'refuses an unknown key (a typo must not silently drop the hash)' {
        { ConvertTo-DataDiskList -Value @{ Name = 'a'; Path = 'C:\vs\a.vhdx'; Hash = ('a' * 64) } } |
            Should -Throw -ExpectedMessage '*unknown key*'
    }

    It 'refuses a non-hashtable entry' {
        { ConvertTo-DataDiskList -Value @('C:\vs\a.vhdx') } | Should -Throw -ExpectedMessage '*not a hashtable*'
    }

    It 'refuses the path <Path>' -TestCases @(
        @{ Path = 'corpus.vhdx' }, @{ Path = '.\corpus.vhdx' }, @{ Path = '\vs\corpus.vhdx' },
        @{ Path = '\\server\share\corpus.vhdx' }, @{ Path = '\\?\C:\vs\corpus.vhdx' }, @{ Path = '\\.\PhysicalDrive0' },
        @{ Path = 'C:\vs\corpus.vhdx:stream' }, @{ Path = 'C:\vs\corpus.vhd' }, @{ Path = 'C:\vs\corpus.iso' },
        @{ Path = '' }, @{ Path = "C:\vs\cor`npus.vhdx" }
    ) {
        param($Path)
        { ConvertTo-DataDiskList -Value @{ Name = 'corpus'; Path = $Path; ImageHash = ('a' * 64) } } |
            Should -Throw -ExpectedMessage '*corpus*'
    }

    It 'refuses a secret-shaped path (invariant 1 source of truth)' {
        { ConvertTo-DataDiskList -Value @{ Name = 'keys'; Path = 'C:\Users\someone\.ssh\keys.vhdx'; ImageHash = ('a' * 64) } } |
            Should -Throw -ExpectedMessage '*secret*'
    }

    It 'refuses the ImageHash <Hash>' -TestCases @(
        @{ Hash = '' }, @{ Hash = ('a' * 63) }, @{ Hash = ('a' * 65) }, @{ Hash = ('g' * 64) }, @{ Hash = ('a' * 32 + ' ' + 'a' * 31) }
    ) {
        param($Hash)
        { ConvertTo-DataDiskList -Value @{ Name = 'corpus'; Path = 'C:\vs\corpus.vhdx'; ImageHash = $Hash } } |
            Should -Throw -ExpectedMessage '*ImageHash*'
    }

    It 'refuses a declaration with no ImageHash key at all' {
        { ConvertTo-DataDiskList -Value @{ Name = 'corpus'; Path = 'C:\vs\corpus.vhdx' } } |
            Should -Throw -ExpectedMessage '*ImageHash is missing*'
    }

    It 'derives the label VSD + upper-cased name, within the exFAT limit' {
        Get-DataDiskLabel -Name 'corpus' | Should -BeExactly 'VSDCORPUS'
        (Get-DataDiskLabel -Name 'abcdefgh').Length | Should -BeLessOrEqual 11
        { Get-DataDiskLabel -Name 'Bad' } | Should -Throw
    }
}

Describe 'DataDisks in profiles (loader)' {

    It 'Assert-TierProfileValid refuses a profile whose DataDisks are invalid' {
        $p = @{} + $script:Fx
        $p['DataDisks'] = @(@{ Name = 'BAD'; Path = 'C:\vs\a.vhdx'; ImageHash = ('a' * 64) })
        { Assert-TierProfileValid -Profile $p -Context 'TEST' } | Should -Throw -ExpectedMessage '*name*'
    }

    It 'a workload .psd1 layers DataDisks onto the tier and validates them' {
        $hash = 'c' * 64
        $lines = @(
            '@{',
            '    BaseTier     = 0',
            "    Name         = 'dd-workload'",
            "    WorkloadMode = 'Disk'",
            '    OutboxOutput = $true',
            "    Entrypoint   = 'python3 /mnt/in/summarize.py --out /run/staging/result.html'",
            "    DataDisks    = @( @{ Name = 'NAMEHERE'; Path = 'D:\vs\corpus.vhdx'; ImageHash = '$hash' } )",
            '}'
        )
        $wl = Join-Path $TestDrive 'dd-workload.psd1'
        ($lines -join "`n").Replace('NAMEHERE', 'corpus') | Set-Content -LiteralPath $wl -Encoding utf8
        $m = Import-WorkloadProfile -Path $wl -TierProfileDir $script:TierDir
        @($m['DataDisks']).Count | Should -Be 1
        @($m['DataDisks'])[0].Name | Should -Be 'corpus'

        $bad = Join-Path $TestDrive 'dd-bad.psd1'
        ($lines -join "`n").Replace('NAMEHERE', 'Corpus') | Set-Content -LiteralPath $bad -Encoding utf8
        { Import-WorkloadProfile -Path $bad -TierProfileDir $script:TierDir } | Should -Throw -ExpectedMessage '*name*'
    }
}

Describe 'Assert-DataDiskPathsIsolated (no alias of run disks, DEPS or the golden parent)' {

    BeforeAll {
        $script:IsoRoot = Join-Path $TestDrive 'sandboxes'
        New-Item -ItemType Directory -Path $script:IsoRoot -Force | Out-Null
        $script:OkDir = Join-Path $TestDrive 'datadisks'
        New-Item -ItemType Directory -Path $script:OkDir -Force | Out-Null
        $script:Iso = {
            param([string] $Path, [string] $Deps, [string] $Parent)
            Assert-DataDiskPathsIsolated -DataDisks @(@{ Name = 'corpus'; Path = $Path; ImageHash = ('a' * 64) }) `
                -StorageRoot $script:IsoRoot -DepsDiskPath $Deps -ParentDiskPath $Parent
        }
    }

    It 'accepts a path outside every protected location' {
        { & $script:Iso (Join-Path $script:OkDir 'corpus.vhdx') $null $null } | Should -Not -Throw
    }

    It 'refuses a path under the storage root (any VM folder, any case)' {
        { & $script:Iso (Join-Path $script:IsoRoot 'sbx-x\sbx-x-input.vhdx') $null $null } | Should -Throw -ExpectedMessage '*storage root*'
        { & $script:Iso ((Join-Path $script:IsoRoot 'other\a.vhdx').ToUpperInvariant()) $null $null } | Should -Throw -ExpectedMessage '*storage root*'
    }

    It 'does not confuse a sibling folder that merely shares the root''s prefix' {
        $sib = $script:IsoRoot + '-archive'
        { & $script:Iso (Join-Path $sib 'corpus.vhdx') $null $null } | Should -Not -Throw
    }

    It 'refuses the DEPS disk and the golden parent' {
        $deps = Join-Path $script:OkDir 'deps.vhdx'
        $gold = Join-Path $script:OkDir 'golden.vhdx'
        { & $script:Iso $deps $deps $null } | Should -Throw -ExpectedMessage '*DEPS disk*'
        { & $script:Iso $gold $null $gold.ToUpperInvariant() } | Should -Throw -ExpectedMessage '*golden parent*'
    }

    It 'refuses a path that reaches the storage root through a junction' {
        $j = Join-Path $TestDrive 'innocent'
        New-Item -ItemType Junction -Path $j -Target $script:IsoRoot | Out-Null
        { & $script:Iso (Join-Path $j 'sbx-y\sbx-y-system.vhdx') $null $null } | Should -Throw -ExpectedMessage '*storage root*'
    }

    It 'refuses a symbolic-link file that points at the golden parent' {
        $gold = Join-Path $script:OkDir 'golden2.vhdx'
        Set-Content -LiteralPath $gold -Value 'x'
        $link = Join-Path $script:OkDir 'link.vhdx'
        try { New-Item -ItemType SymbolicLink -Path $link -Target $gold -ErrorAction Stop | Out-Null }
        catch { Set-ItResult -Skipped -Because "creating a symbolic link needs Developer Mode or elevation here: $($_.Exception.Message)"; return }
        { & $script:Iso $link $null $gold } | Should -Throw -ExpectedMessage '*golden parent*'
    }

    It 'refuses a data disk file with a second hard link' {
        $real = Join-Path $script:OkDir 'real.vhdx'
        Set-Content -LiteralPath $real -Value 'x'
        New-Item -ItemType HardLink -Path (Join-Path $script:OkDir 'alias.vhdx') -Target $real | Out-Null
        { & $script:Iso $real $null $null } | Should -Throw -ExpectedMessage '*hard link*'
    }
}

Describe 'Invoke-Voidseal data-disk preflight (refused before anything is provisioned)' {

    It 'refuses data disks on a Serial-mode run, before any VM exists' {
        $b = New-FakeHyperVBackend
        $serial = @{} + $script:Fx
        $serial['WorkloadMode'] = 'Serial'
        $serial.Remove('OutboxOutput')
        { Invoke-Voidseal -Tier 0 -Profile $serial -Workload @{ DataDisks = @(& $script:Decl 'corpus') } `
            -Name 'sbx-dd-serial' -Backend $b } | Should -Throw -ExpectedMessage '*Serial*'
        (& $b.GetVM @{ Name = 'sbx-dd-serial' }) | Should -BeNullOrEmpty
        @($b.FakeCallLog).Count | Should -Be 0 -Because 'nothing touched the backend'
    }

    It 'refuses an invalid -Workload.DataDisks declaration before any VM exists' {
        $b = New-FakeHyperVBackend
        { Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = @(& $script:Decl 'corpus' $null 'nothex') } `
            -Name 'sbx-dd-badhash' -Backend $b } | Should -Throw -ExpectedMessage '*ImageHash*'
        (& $b.GetVM @{ Name = 'sbx-dd-badhash' }) | Should -BeNullOrEmpty
    }

    It 'refuses a data disk under the sandbox storage root before any VM exists' {
        $b = New-FakeHyperVBackend
        $inRoot = Join-Path (Split-Path -Parent (Get-SandboxStorageRoot -Name 'x')) 'sbx-other\sbx-other-input.vhdx'
        { Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = @(& $script:Decl 'corpus' $inRoot) } `
            -Name 'sbx-dd-inroot' -Backend $b } | Should -Throw -ExpectedMessage '*storage root*'
        (& $b.GetVM @{ Name = 'sbx-dd-inroot' }) | Should -BeNullOrEmpty
    }

    It 'refuses a data disk that is the DEPS disk' {
        $b = New-FakeHyperVBackend
        $deps = Join-Path $script:DataRoot 'deps.vhdx'
        { Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DepsDiskPath = $deps; DataDisks = @(& $script:Decl 'deps' $deps) } `
            -Name 'sbx-dd-deps' -Backend $b } | Should -Throw -ExpectedMessage '*DEPS disk*'
    }

    It 'refuses a data disk that is the golden parent (-ParentDiskPath)' {
        $b = New-FakeHyperVBackend
        $gold = Join-Path $script:DataRoot 'golden.vhdx'
        { Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = @(& $script:Decl 'gold' $gold) } `
            -ParentDiskPath $gold -Name 'sbx-dd-gold' -Backend $b } | Should -Throw -ExpectedMessage '*golden parent*'
    }

    It 'a -Workload.DataDisks value replaces the profile''s, and an empty one removes them' {
        $profileDecl = @(@{ Name = 'BAD!'; Path = 'C:\vs\x.vhdx'; ImageHash = ('a' * 64) })
        # The profile's (invalid) declaration is never consulted when the workload supplies its own.
        @(Resolve-DataDiskDeclaration -Workload @{ DataDisks = @() } -Profile @{ DataDisks = $profileDecl }).Count | Should -Be 0
        $r2 = Resolve-DataDiskDeclaration -Workload @{ DataDisks = @((& $script:Decl 'two'), (& $script:Decl 'three')) } `
                                          -Profile @{ DataDisks = @(& $script:Decl 'one') }
        @($r2 | ForEach-Object { $_.Name }) | Should -Be @('two', 'three')
        $r3 = Resolve-DataDiskDeclaration -Workload @{ WorkloadMode = 'Disk' } -Profile @{ DataDisks = @(& $script:Decl 'one') }
        @($r3 | ForEach-Object { $_.Name }) | Should -Be @('one')
    }
}
