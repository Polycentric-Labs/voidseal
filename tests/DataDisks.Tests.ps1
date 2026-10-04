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
    # The outbox helper preflight requires both guest helpers on INPUT for a transport-only profile.
    $script:Fx['Inputs']       = @{}
    foreach ($helper in @('run_disk_workload.py', 'outbox.py')) {
        $script:Fx['Inputs'][$helper] = Get-Content -LiteralPath (Join-Path $script:SkillRoot "guest/$helper") -Raw
    }
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
        # Structurally: across the three helpers the only backend members touched are the two
        # read-only probes and the file copy. None of them attaches or mounts.
        $members = foreach ($fn in 'Assert-DiskStructure', 'Assert-DiskImageVerified', 'New-VerifiedDiskCopy') {
            $ast = (Get-Command $fn).ScriptBlock.Ast
            $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and
                           $n.Expression.Extent.Text -eq '$Backend' }, $true) | ForEach-Object { $_.Member.Extent.Text }
            @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                             $n.GetCommandName() -match 'Mount-VHD|Add-VMHardDiskDrive' }, $true)).Count | Should -Be 0
        }
        @($members | Sort-Object -Unique) | Should -Be @('CopyVhdxFile', 'GetVHDInfo', 'GetVhdxImageHash')
    }
}

Describe 'New-VerifiedDiskCopy (the per-run working copy both DEPS and data disks use)' {

    BeforeAll {
        $script:CopyArgs = {
            param($Backend, $Desc, $Path, $Copy, $Hash)
            @{
                VMName = 'vm-copy'; Path = $Path; CopyPath = $Copy; ExpectedHash = $Hash
                DiskLabel = "data disk 'corpus'"; DiskKind = 'data disk'; HashOrigin = 'operator-recorded'
                MissingHashMessage = 'no hash was supplied for this disk'; Descriptor = $Desc; Backend = $Backend
            }
        }
        $script:NewOriginal = {
            param($Backend, [string] $Path)
            & $Backend.NewOutputVhdx @{ Path = $Path; Label = 'VSDCORPUS'; FileSystem = 'exFAT'; SizeBytes = 64MB }
            [string](& $Backend.GetVhdxImageHash @{ Path = $Path })
        }
    }

    It 'copies the original, records only the copy on CreatedDisks, and verifies the COPY' {
        $b = New-FakeHyperVBackend
        $desc = [pscustomobject]@{ Name = 'vm-copy'; CreatedDisks = @('C:\sb\vm-copy\vm-copy-system.vhdx') }
        $orig = 'C:\data\corpus.vhdx'; $copy = 'C:\sb\vm-copy\vm-copy-data-corpus.vhdx'
        $h = & $script:NewOriginal $b $orig
        $a = & $script:CopyArgs $b $desc $orig $copy $h
        New-VerifiedDiskCopy @a | Should -Be $h
        @($desc.CreatedDisks) | Should -Contain $copy
        @($desc.CreatedDisks) | Should -Not -Contain $orig
        (& $b.GetVHDInfo @{ Path = $copy }).Label | Should -Be 'VSDCORPUS'
        $log = @($b.FakeCallLog)
        @($log | Where-Object { $_.Op -eq 'GetVhdxImageHash' -and $_.Path -eq $copy }).Count | Should -Be 1 -Because 'the copy is what gets hashed'
        @($log | Where-Object { $_.Op -eq 'GetVhdxImageHash' -and $_.Path -eq $orig }).Count | Should -Be 1 -Because 'only the test setup hashed the original'
    }

    It 'refuses when the COPY does not match, even though the original would (and still records the copy for teardown)' {
        $b = New-FakeHyperVBackend
        $desc = [pscustomobject]@{ Name = 'vm-copy'; CreatedDisks = @() }
        $orig = 'C:\data\corpus.vhdx'; $copy = 'C:\sb\vm-copy\bad-copy.vhdx'
        $h = & $script:NewOriginal $b $orig
        # A copy that lands different from its source (a flaky copy, or a swap mid-copy).
        $driftDir = Join-Path $TestDrive 'drift'
        New-Item -ItemType Directory -Path $driftDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $driftDir 'drift.txt') -Value 'x'
        $realCopy = $b.CopyVhdxFile
        $b.CopyVhdxFile = { param($P) & $realCopy $P; & $b.CopyDirectoryToVhdx @{ Path = $P.Destination; SourceDir = $driftDir } }.GetNewClosure()
        $a = & $script:CopyArgs $b $desc $orig $copy $h
        { New-VerifiedDiskCopy @a } | Should -Throw -ExpectedMessage "*working copy of '$orig'*"
        @($desc.CreatedDisks) | Should -Contain $copy -Because 'a copy that exists must be deleted at teardown'
    }

    It 'makes no copy when the original is unreadable, differencing, or has no expected hash' {
        $b = New-FakeHyperVBackend
        $desc = [pscustomobject]@{ Name = 'vm-copy'; CreatedDisks = @() }
        $a = & $script:CopyArgs $b $desc 'C:\data\absent.vhdx' 'C:\sb\c1.vhdx' ('a' * 64)
        { New-VerifiedDiskCopy @a } | Should -Throw -ExpectedMessage '*unreadable via GetVHDInfo*'
        & $b.NewVHD @{ Path = 'C:\data\diff.vhdx'; Differencing = $true; ParentPath = 'C:\x\p.vhdx' }
        $a = & $script:CopyArgs $b $desc 'C:\data\diff.vhdx' 'C:\sb\c2.vhdx' ('a' * 64)
        { New-VerifiedDiskCopy @a } | Should -Throw -ExpectedMessage '*DIFFERENCING*'
        $null = & $script:NewOriginal $b 'C:\data\ok.vhdx'
        $a = & $script:CopyArgs $b $desc 'C:\data\ok.vhdx' 'C:\sb\c3.vhdx' ''
        { New-VerifiedDiskCopy @a } | Should -Throw -ExpectedMessage 'no hash was supplied for this disk'
        @($b.FakeCallLog | Where-Object { $_.Op -eq 'CopyVhdxFile' }).Count | Should -Be 0
        @($desc.CreatedDisks).Count | Should -Be 0
    }

    It 'never overwrites an existing destination, and never records a file it did not create' {
        $b = New-FakeHyperVBackend
        $desc = [pscustomobject]@{ Name = 'vm-copy'; CreatedDisks = @() }
        $h = & $script:NewOriginal $b 'C:\data\corpus.vhdx'
        $null = & $script:NewOriginal $b 'C:\sb\taken.vhdx'
        $a = & $script:CopyArgs $b $desc 'C:\data\corpus.vhdx' 'C:\sb\taken.vhdx' $h
        { New-VerifiedDiskCopy @a } | Should -Throw -ExpectedMessage '*already exists*'
        @($desc.CreatedDisks) | Should -Not -Contain 'C:\sb\taken.vhdx'
    }
}

Describe 'CopyVhdxFile backend method' {

    It 'is in the manifest with Path and Destination, and both factories implement it' {
        (Get-HyperVBackendMethodManifest)['CopyVhdxFile'] | Should -Be @('Path', 'Destination')
        (New-FakeHyperVBackend).CopyVhdxFile | Should -BeOfType [scriptblock]
        (New-RealHyperVBackend).CopyVhdxFile | Should -BeOfType [scriptblock]
    }

    It 'fake: refuses a source attached to a running VM' {
        $b = New-FakeHyperVBackend
        & $b.NewVM @{ Name = 'vm-busy' }
        & $b.NewVHD @{ Path = 'C:\data\busy.vhdx'; SizeBytes = 64MB; Dynamic = $true }
        & $b.AddHardDiskDrive @{ VMName = 'vm-busy'; Path = 'C:\data\busy.vhdx' }
        & $b.StartVM @{ Name = 'vm-busy' }
        { & $b.CopyVhdxFile @{ Path = 'C:\data\busy.vhdx'; Destination = 'C:\sb\x.vhdx' } } | Should -Throw -ExpectedMessage '*locked*'
    }

    Context 'real body, in-process on temp files (it runs no Hyper-V cmdlet)' {
        BeforeAll {
            $script:RealB = New-RealHyperVBackend
            $script:CopyDir = Join-Path $TestDrive 'realcopy'
            New-Item -ItemType Directory -Path $script:CopyDir -Force | Out-Null
            $script:SrcFile = Join-Path $script:CopyDir 'orig.vhdx'
            $bytes = [byte[]](0..255 + 0..255)
            [System.IO.File]::WriteAllBytes($script:SrcFile, $bytes)
            (Get-Item -LiteralPath $script:SrcFile).IsReadOnly = $true
        }

        It 'copies byte for byte into a new folder, clears ReadOnly, and leaves no partial file' {
            $dst = Join-Path $script:CopyDir 'run\copy.vhdx'
            & $script:RealB.CopyVhdxFile @{ Path = $script:SrcFile; Destination = $dst }
            [System.IO.File]::ReadAllBytes($dst) | Should -Be ([System.IO.File]::ReadAllBytes($script:SrcFile))
            (Get-Item -LiteralPath $dst).IsReadOnly | Should -BeFalse
            (Get-Item -LiteralPath $script:SrcFile).IsReadOnly | Should -BeTrue -Because 'the original is untouched'
            @(Get-ChildItem -LiteralPath (Split-Path -Parent $dst) -Filter '*.partial-*').Count | Should -Be 0
        }

        It 'refuses an existing destination and a missing source' {
            $dst = Join-Path $script:CopyDir 'exists.vhdx'
            Set-Content -LiteralPath $dst -Value 'keep me'
            { & $script:RealB.CopyVhdxFile @{ Path = $script:SrcFile; Destination = $dst } } | Should -Throw -ExpectedMessage '*already exists*'
            (Get-Content -LiteralPath $dst -Raw).Trim() | Should -Be 'keep me'
            { & $script:RealB.CopyVhdxFile @{ Path = (Join-Path $script:CopyDir 'nope.vhdx'); Destination = (Join-Path $script:CopyDir 'n2.vhdx') } } |
                Should -Throw -ExpectedMessage '*does not exist*'
        }

        It 'removes the partial file when the copy fails (source held open exclusively)' {
            $dst = Join-Path $script:CopyDir 'locked-copy.vhdx'
            $fs = [System.IO.File]::Open($script:SrcFile, 'Open', 'Read', 'None')
            try {
                { & $script:RealB.CopyVhdxFile @{ Path = $script:SrcFile; Destination = $dst } } | Should -Throw
            }
            finally { $fs.Dispose() }
            Test-Path -LiteralPath $dst | Should -BeFalse
            @(Get-ChildItem -LiteralPath $script:CopyDir -Filter 'locked-copy.vhdx.partial-*').Count | Should -Be 0
        }
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

    It 'protects the run''s resolved storage root (-StorageRoot), not the default one' {
        $custom = Join-Path $TestDrive 'custom-root'
        $b = New-FakeHyperVBackend
        $inCustom = Join-Path $custom 'sbx-other\sbx-other-input.vhdx'
        { Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = @(& $script:Decl 'corpus' $inCustom) } `
            -StorageRoot $custom -Name 'sbx-dd-custom' -Backend $b } | Should -Throw -ExpectedMessage "*storage root ('$custom')*"
        (& $b.GetVM @{ Name = 'sbx-dd-custom' }) | Should -BeNullOrEmpty
    }

    It 'protects a storage root given by VOIDSEAL_STORAGE_ROOT' {
        $envRoot = Join-Path $TestDrive 'env-root'
        $saved = $env:VOIDSEAL_STORAGE_ROOT
        try {
            $env:VOIDSEAL_STORAGE_ROOT = $envRoot
            $b = New-FakeHyperVBackend
            { Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = @(& $script:Decl 'corpus' (Join-Path $envRoot 'x\x.vhdx')) } `
                -Name 'sbx-dd-envroot' -Backend $b } | Should -Throw -ExpectedMessage "*storage root ('$envRoot')*"
        }
        finally { $env:VOIDSEAL_STORAGE_ROOT = $saved }
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

Describe 'Invoke-Voidseal copies, verifies, attaches and seals data disks' {

    BeforeAll {
        # A transport-only outbox carrying result.html, so a run can reach Success end to end.
        $stage = Join-Path $TestDrive 'dd-staging'
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $stage 'result.html'), [System.Text.Encoding]::UTF8.GetBytes('<p>summary</p>'))
        $verdicts = Join-Path $TestDrive 'dd-verdicts.json'
        '[]' | Set-Content -LiteralPath $verdicts -Encoding utf8 -NoNewline
        $blobFile = Join-Path $TestDrive 'dd-outbox.bin'
        Push-Location $script:SkillRoot
        try { & python -c "import sys; sys.path.insert(0, 'guest'); import outbox; outbox.write_outbox_from_dir(r'$stage', r'$verdicts', r'$blobFile', workload_rc=0)" }
        finally { Pop-Location }
        $LASTEXITCODE | Should -Be 0
        $script:DdBlob = [System.IO.File]::ReadAllBytes($blobFile)

        # A fake backend with N pre-built data disks registered, plus an attach recorder.
        $script:NewDataRun = {
            param([string[]] $Names, [switch] $NoBlob, [switch] $NeverOff, [string[]] $GuestWrites = @())
            $fakeArgs = @{ SimulateSelfPowerOff = $true }
            if ($NeverOff) { $fakeArgs = @{ SimulateNeverOff = $true } }
            elseif (-not $NoBlob) { $fakeArgs.SimulateOutboxBlob = $script:DdBlob }
            if ($GuestWrites.Count -gt 0) {
                $fakeArgs.SimulateGuestDiskWrite = @($GuestWrites)
            }
            $b = New-FakeHyperVBackend @fakeArgs
            $attached = [System.Collections.Generic.List[string]]::new()
            $orig = $b.AddHardDiskDrive
            $b.AddHardDiskDrive = { param($P) $attached.Add([string]$P.Path); & $orig $P }.GetNewClosure()
            $decl = foreach ($n in @($Names)) {
                $p = Join-Path $script:DataRoot "$n.vhdx"
                & $b.NewVHD @{ Path = $p; SizeBytes = 1GB; Dynamic = $true }
                @{ Name = $n; Path = $p; ImageHash = [string](& $b.GetVhdxImageHash @{ Path = $p }) }
            }
            return @{ Backend = $b; Attached = $attached; Decl = @($decl) }
        }
        $script:RunWith = {
            param($Run, [string] $VmName, $Decl)
            if ($null -eq $Decl) { $Decl = $Run.Decl }
            Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = $Decl } `
                -Name $VmName -ArtifactRoot (Join-Path $TestDrive "art-$VmName") -Destination (Join-Path $TestDrive "dest-$VmName") `
                -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $Run.Backend -WarningAction SilentlyContinue
        }
        # Where a run puts its working copy of a data disk (the default storage root in these tests).
        $script:CopyOf = { param([string] $Vm, [string] $DiskName) Join-Path (Get-SandboxStorageRoot -Name $Vm) ("{0}-data-{1}.vhdx" -f $Vm, $DiskName) }
    }

    It 'copies, verifies, attaches and records each data disk; the seal certifies; the run succeeds' {
        $run = & $script:NewDataRun -Names @('corpus', 'wheels')
        $report = & $script:RunWith $run 'sbx-dd-ok'
        $report.Error | Should -BeNullOrEmpty
        @($report.States) | Should -Contain 'SEALED'
        $report.SealVerdict | Should -BeTrue
        $report.RunResult.Status | Should -Be 'Success'
        $rec = @($report.Descriptor.DataDisks)
        $rec.Count | Should -Be 2
        $rec[0].Name | Should -Be 'corpus'
        $rec[0].Label | Should -BeExactly 'VSDCORPUS'
        $rec[0].ImageHash | Should -Be $run.Decl[0].ImageHash
        $rec[1].SourcePath | Should -Be $run.Decl[1].Path
        $rec[1].Path | Should -Be (& $script:CopyOf 'sbx-dd-ok' 'wheels')
        foreach ($r in $rec) { $run.Attached | Should -Contain $r.Path }
        foreach ($d in $run.Decl) { $run.Attached | Should -Not -Contain $d.Path -Because 'the original is never attached' }
    }

    It 'reports a per-disk summary: name, original, verified hash, working copy, changed' {
        $run = & $script:NewDataRun -Names @('corpus')
        $report = & $script:RunWith $run 'sbx-dd-summary'
        $s = @($report.DataDisks)
        $s.Count | Should -Be 1
        $s[0].Name | Should -Be 'corpus'
        $s[0].SourcePath | Should -Be $run.Decl[0].Path
        $s[0].ImageHash | Should -Be $run.Decl[0].ImageHash
        $s[0].CopyPath | Should -Be (& $script:CopyOf 'sbx-dd-summary' 'corpus')
        $s[0].Changed | Should -BeFalse
    }

    It 'puts only the working copy on CreatedDisks: teardown deletes the copy and keeps the original' {
        $run = & $script:NewDataRun -Names @('corpus')
        $report = & $script:RunWith $run 'sbx-dd-gc'
        $copy = & $script:CopyOf 'sbx-dd-gc' 'corpus'
        @($report.Descriptor.CreatedDisks) | Should -Contain $copy
        @($report.Descriptor.CreatedDisks) | Should -Not -Contain $run.Decl[0].Path
        (& $run.Backend.GetVHDInfo @{ Path = $copy }) | Should -BeNullOrEmpty -Because 'the working copy is deleted at teardown'
        (& $run.Backend.GetVHDInfo @{ Path = $run.Decl[0].Path }) | Should -Not -BeNullOrEmpty -Because 'the operator data disk survives teardown'
        (& $run.Backend.GetVM @{ Name = 'sbx-dd-gc' }) | Should -BeNullOrEmpty -Because 'the VM itself is gone'
    }

    It 'a hash mismatch on ANY disk attaches NO data disk, never seals, and the copies made are deleted' {
        $run = & $script:NewDataRun -Names @('corpus', 'wheels')
        $second = @{} + $run.Decl[1]
        $second.ImageHash = 'f' * 64
        $report = & $script:RunWith $run 'sbx-dd-mismatch' @($run.Decl[0], $second)
        $report.Error | Should -Match "data disk 'wheels' integrity check FAILED"
        @($report.States) | Should -Not -Contain 'SEALED'
        foreach ($n in 'corpus', 'wheels') {
            $c = & $script:CopyOf 'sbx-dd-mismatch' $n
            $run.Attached | Should -Not -Contain $c -Because 'all disks are verified before the first attach'
            (& $run.Backend.GetVHDInfo @{ Path = $c }) | Should -BeNullOrEmpty -Because 'teardown deletes every copy made'
        }
        @($run.Backend.FakeCallLog | Where-Object { $_.Op -eq 'StartVM' }).Count | Should -Be 0
    }

    It 'refuses a data disk the host cannot read, before any attach' {
        $run = & $script:NewDataRun -Names @('corpus')
        $decl = @($run.Decl[0], @{ Name = 'ghost'; Path = (Join-Path $script:DataRoot 'ghost.vhdx'); ImageHash = ('a' * 64) })
        $report = & $script:RunWith $run 'sbx-dd-ghost' $decl
        $report.Error | Should -Match 'unreadable via GetVHDInfo'
        $run.Attached | Should -Not -Contain (& $script:CopyOf 'sbx-dd-ghost' 'corpus')
    }

    It 'refuses a differencing data disk, without copying it' {
        $run = & $script:NewDataRun -Names @()
        $p = Join-Path $script:DataRoot 'diff.vhdx'
        & $run.Backend.NewVHD @{ Path = $p; Differencing = $true; ParentPath = 'C:\elsewhere\base.vhdx' }
        $report = & $script:RunWith $run 'sbx-dd-diff' @(@{ Name = 'diff'; Path = $p; ImageHash = ('a' * 64) })
        $report.Error | Should -Match 'DIFFERENCING'
        @($report.States) | Should -Not -Contain 'SEALED'
        @($run.Backend.FakeCallLog | Where-Object { $_.Op -eq 'CopyVhdxFile' }).Count | Should -Be 0
    }

    It 'reports DataDiskChanged = $false when every original re-hashes to its recorded value' {
        $run = & $script:NewDataRun -Names @('corpus', 'wheels')
        $report = & $script:RunWith $run 'sbx-dd-same'
        $report.DataDiskChanged | Should -BeFalse
        foreach ($d in @($report.Descriptor.DataDisks)) {
            $d.Changed | Should -BeFalse
            $d.PostRunImageHash | Should -Be $d.ImageHash
        }
    }

    It 'a guest write lands on the working copy only: the original stays verified and a second run reuses it' {
        $vm = 'sbx-dd-guestwrite'
        $run = & $script:NewDataRun -Names @('corpus', 'wheels') -GuestWrites @((& $script:CopyOf $vm 'wheels'))
        $report = & $script:RunWith $run $vm
        $report.RunResult.Status | Should -Be 'Success'
        $report.DataDiskChanged | Should -BeFalse -Because 'the guest only ever had the copy, which teardown deleted'
        [string](& $run.Backend.GetVhdxImageHash @{ Path = $run.Decl[1].Path }) | Should -Be $run.Decl[1].ImageHash
        # The same originals, the same recorded hashes, a fresh run: still accepted.
        $again = & $script:RunWith $run "$vm-2"
        $again.Error | Should -BeNullOrEmpty
        $again.RunResult.Status | Should -Be 'Success'
    }

    It 'a change to the ORIGINAL on the host during the run sets DataDiskChanged and warns, without failing the run' {
        $run = & $script:NewDataRun -Names @('corpus')
        $orig = $run.Decl[0].Path
        $drift = Join-Path $TestDrive 'host-drift'
        New-Item -ItemType Directory -Path $drift -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $drift 'swapped.txt') -Value 'changed on the host'
        $b = $run.Backend
        $realStart = $b.StartVM
        $b.StartVM = {
            param($P)
            & $realStart $P
            # Something on the host rewrites the original while the guest runs.
            & $b.RemoveVHD @{ Path = $orig }
            & $b.NewOutputVhdx @{ Path = $orig; Label = 'VSDCORPUS'; FileSystem = 'exFAT'; SizeBytes = 64MB }
            & $b.CopyDirectoryToVhdx @{ Path = $orig; SourceDir = $drift }
        }.GetNewClosure()
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = $run.Decl } `
            -Name 'sbx-dd-hostdrift' -ArtifactRoot (Join-Path $TestDrive 'art-hd') -Destination (Join-Path $TestDrive 'dest-hd') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b -WarningVariable wv -WarningAction SilentlyContinue
        $report.RunResult.Status | Should -Be 'Success'
        $report.DataDiskChanged | Should -BeTrue
        @($report.DataDisks)[0].Changed | Should -BeTrue
        (@($wv) -join "`n") | Should -Match "data disk 'corpus' original .*not the recorded"
    }

    It 'the re-hash of the original runs after teardown; the pre-attach hash is of the copy' {
        $run = & $script:NewDataRun -Names @('corpus')
        $null = & $script:RunWith $run 'sbx-dd-order'
        $log = @($run.Backend.FakeCallLog)
        $origHashes = @(for ($i = 0; $i -lt $log.Count; $i++) { if ($log[$i].Op -eq 'GetVhdxImageHash' -and $log[$i].Path -eq $run.Decl[0].Path) { $i } })
        $origHashes.Count | Should -Be 2 -Because 'one in the test setup, one after the run'
        $copyHashes = @($log | Where-Object { $_.Op -eq 'GetVhdxImageHash' -and $_.Path -eq (& $script:CopyOf 'sbx-dd-order' 'corpus') })
        $copyHashes.Count | Should -Be 1 -Because 'the copy is verified once, before attach'
        $startIdx = @(for ($i = 0; $i -lt $log.Count; $i++) { if ($log[$i].Op -eq 'StartVM') { $i } })[0]
        $origHashes[1] | Should -BeGreaterThan $startIdx
        (& $run.Backend.GetVM @{ Name = 'sbx-dd-order' }) | Should -BeNullOrEmpty
    }

    It 'an original that cannot be re-hashed counts as changed (fail closed on the report)' {
        $run = & $script:NewDataRun -Names @('corpus')
        $orig = $run.Decl[0].Path
        $calls = @(0)
        $realHash = $run.Backend.GetVhdxImageHash
        $run.Backend.GetVhdxImageHash = {
            param($P)
            if ($P.Path -eq $orig) { $calls[0]++; throw 'simulated: file vanished' }
            & $realHash $P
        }.GetNewClosure()
        $report = & $script:RunWith $run 'sbx-dd-gone'
        $report.DataDiskChanged | Should -BeTrue
        @($report.Descriptor.DataDisks)[0].PostRunImageHash | Should -BeNullOrEmpty
    }

    It 'a hung guest that wrote to its copy leaves the original unchanged' {
        $vm = 'sbx-dd-hang'
        $run = & $script:NewDataRun -Names @('corpus') -NeverOff -GuestWrites @((& $script:CopyOf $vm 'corpus'))
        $report = & $script:RunWith $run $vm
        $report.RunResult.Status | Should -Be 'Failed'
        $report.DataDiskChanged | Should -BeFalse
    }

    It 'counts every working copy in the host free-space preflight' {
        # INPUT + OUTPUT are 1GB each and the preflight adds 1GB of headroom: 3GB fits in 3.5GB free.
        # A 1GB data disk's working copy (budgeted at its virtual size + 64MB) does not. A tiny golden
        # parent keeps the provisioner's own system-disk check (parent size + 1GB) inside the same figure.
        $gold = Join-Path $TestDrive 'tiny-golden.vhdx'
        [System.IO.File]::WriteAllBytes($gold, [byte[]]::new(4096))
        $fit = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateOutboxBlob $script:DdBlob -SimulateFreeSpaceBytes 3.5GB
        $ok = Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk' } -Name 'sbx-dd-space-ok' -ParentDiskPath $gold `
            -ArtifactRoot (Join-Path $TestDrive 'art-sp1') -Destination (Join-Path $TestDrive 'dest-sp1') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $fit -WarningAction SilentlyContinue
        $ok.Error | Should -BeNullOrEmpty -Because 'without a data disk the run fits'
        $tight = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateOutboxBlob $script:DdBlob -SimulateFreeSpaceBytes 3.5GB
        $p = Join-Path $script:DataRoot 'big.vhdx'
        & $tight.NewVHD @{ Path = $p; SizeBytes = 1GB; Dynamic = $true }
        $h = [string](& $tight.GetVhdxImageHash @{ Path = $p })
        $no = Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = @(@{ Name = 'big'; Path = $p; ImageHash = $h }) } `
            -Name 'sbx-dd-space-no' -ParentDiskPath $gold -ArtifactRoot (Join-Path $TestDrive 'art-sp2') -Destination (Join-Path $TestDrive 'dest-sp2') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $tight -WarningAction SilentlyContinue
        $no.Error | Should -Match 'insufficient host free space'
        @($tight.FakeCallLog | Where-Object { $_.Op -eq 'CopyVhdxFile' }).Count | Should -Be 0 -Because 'the refusal comes before any copy'
    }

    It 'leaves DataDiskChanged and DataDisks $null when no data disk was attached' {
        $run = & $script:NewDataRun -Names @()
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk' } `
            -Name 'sbx-dd-none' -ArtifactRoot (Join-Path $TestDrive 'art-none') -Destination (Join-Path $TestDrive 'dest-none') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $run.Backend -WarningAction SilentlyContinue
        $report.PSObject.Properties.Name | Should -Contain 'DataDiskChanged'
        $report.DataDiskChanged | Should -BeNullOrEmpty
        $report.DataDisks | Should -BeNullOrEmpty
    }

    It 'refuses data disks when there is no Entrypoint (no seed would mount them read-only)' {
        $run = & $script:NewDataRun -Names @('corpus')
        $noEp = @{} + $script:Fx
        $noEp.Remove('Entrypoint')
        { Invoke-Voidseal -Tier 0 -Profile $noEp -Workload @{ WorkloadMode = 'Disk'; DataDisks = $run.Decl } `
            -Name 'sbx-dd-noep' -Backend $run.Backend } | Should -Throw -ExpectedMessage '*no Entrypoint*'
    }

    It 'DEPS disk: a processor attaches a verified working copy and never the builder''s original' {
        $proc = @{} + $script:Fx
        $proc.Remove('OutboxOutput')
        $proc['Network'] = 'None'; $proc['EgressMode'] = 'None'; $proc['EgressAllowlist'] = @()
        $proc['ScreenConfig'] = @{ mode = 'aggressive' }
        $proc['Inputs'] = @{} + $script:Fx['Inputs']
        $proc['Inputs']['screener.py'] = Get-Content -LiteralPath (Join-Path $script:SkillRoot 'guest/screener.py') -Raw
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff
        $attached = [System.Collections.Generic.List[string]]::new()
        $realAdd = $b.AddHardDiskDrive
        $b.AddHardDiskDrive = { param($P) $attached.Add([string]$P.Path); & $realAdd $P }.GetNewClosure()
        $deps = Join-Path $script:DataRoot 'deps.vhdx'
        & $b.NewVHD @{ Path = $deps; SizeBytes = 1GB; Dynamic = $true }
        $h = [string](& $b.GetVhdxImageHash @{ Path = $deps })
        $report = Invoke-Voidseal -Tier 0 -Profile $proc -Workload @{ WorkloadMode = 'Disk'; DepsDiskPath = $deps; DepsImageHash = $h } `
            -Name 'sbx-dd-deps' -ArtifactRoot (Join-Path $TestDrive 'art-deps') -Destination (Join-Path $TestDrive 'dest-deps') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b -RateLedgerPath (Join-Path $TestDrive 'ledger.json') -WarningAction SilentlyContinue
        @($report.States) | Should -Contain 'SEALED'
        $copy = Join-Path (Get-SandboxStorageRoot -Name 'sbx-dd-deps') 'sbx-dd-deps-deps.vhdx'
        $report.Descriptor.DepsDiskPath | Should -Be $copy
        $report.Descriptor.DepsSourcePath | Should -Be $deps
        $report.Descriptor.DepsImageHash | Should -Be $h
        $attached | Should -Contain $copy
        $attached | Should -Not -Contain $deps
        @($report.Descriptor.CreatedDisks) | Should -Contain $copy
        (& $b.GetVHDInfo @{ Path = $copy }) | Should -BeNullOrEmpty -Because 'teardown deletes the working copy'
        (& $b.GetVHDInfo @{ Path = $deps }) | Should -Not -BeNullOrEmpty -Because 'the builder original stays reusable'
    }
}

Describe 'Assert-Sealed and recorded data disks' {

    BeforeAll {
        $script:SealedWithDisk = {
            param([string] $Name, [int] $Tier = 0)
            $t = @{} + $script:Fx
            $t['Tier'] = $Tier
            if ($Tier -ge 2) {
                $t['Network'] = 'Private-NoNIC'; $t['EgressMode'] = 'None'; $t['EgressAllowlist'] = @()
                $t['Extraction'] = 'ColdVHDX-Quarantine-CDR'
            }
            $b = New-FakeHyperVBackend
            $d = New-SandboxVM -Profile $t -Name $Name -Backend $b
            Lock-Sandbox -Descriptor $d -Backend $b
            $p = Join-Path $script:DataRoot "$Name-corpus.vhdx"
            & $b.NewVHD @{ Path = $p; SizeBytes = 64MB; Dynamic = $true }
            & $b.AddHardDiskDrive @{ VMName = $Name; Path = $p }
            return @{ Backend = $b; Desc = $d; Path = $p }
        }
    }

    It 'an attached but UNRECORDED data disk is refused as a residual' {
        $s = & $script:SealedWithDisk 'sbx-seal-unrec'
        { Assert-Sealed -Descriptor $s.Desc -Backend $s.Backend } | Should -Throw -ExpectedMessage '*unexpected*'
    }

    It 'a RECORDED data disk is accepted (any tier, including the Tier>=2 structural rule)' {
        foreach ($tier in 0, 2) {
            $s = & $script:SealedWithDisk "sbx-seal-rec$tier" $tier
            Set-DescriptorField -Descriptor $s.Desc -Name 'DataDisks' -Value @([pscustomobject]@{ Name = 'corpus'; Path = $s.Path; ImageHash = ('a' * 64) })
            Assert-Sealed -Descriptor $s.Desc -Backend $s.Backend | Should -BeTrue
        }
    }

    It 'recording one data disk does not admit a second, unrecorded one' {
        $s = & $script:SealedWithDisk 'sbx-seal-two'
        Set-DescriptorField -Descriptor $s.Desc -Name 'DataDisks' -Value @(@{ Name = 'corpus'; Path = $s.Path; ImageHash = ('a' * 64) })
        $rogue = Join-Path $script:DataRoot 'rogue.vhdx'
        & $s.Backend.NewVHD @{ Path = $rogue; SizeBytes = 64MB; Dynamic = $true }
        & $s.Backend.AddHardDiskDrive @{ VMName = 'sbx-seal-two'; Path = $rogue }
        { Assert-Sealed -Descriptor $s.Desc -Backend $s.Backend } | Should -Throw -ExpectedMessage '*unexpected*'
    }

    It 'a secret-shaped path is refused even when recorded as a data disk' {
        $s = & $script:SealedWithDisk 'sbx-seal-secret'
        $secret = Join-Path $script:DataRoot 'id_rsa.vhdx'
        & $s.Backend.NewVHD @{ Path = $secret; SizeBytes = 64MB; Dynamic = $true }
        & $s.Backend.AddHardDiskDrive @{ VMName = 'sbx-seal-secret'; Path = $secret }
        Set-DescriptorField -Descriptor $s.Desc -Name 'DataDisks' -Value @(
            @{ Name = 'corpus'; Path = $s.Path; ImageHash = ('a' * 64) }, @{ Name = 'key'; Path = $secret; ImageHash = ('a' * 64) })
        { Assert-Sealed -Descriptor $s.Desc -Backend $s.Backend } | Should -Throw -ExpectedMessage '*secret*'
    }
}

Describe 'Guest runners mount each data disk read-only and fail closed' {

    BeforeAll {
        $two = @(
            @{ Name = 'corpus'; Path = 'D:\vs\corpus.vhdx'; ImageHash = ('a' * 64) },
            @{ Name = 'wheels'; Path = 'D:\vs\wheels.vhdx'; ImageHash = ('b' * 64) }
        )
        $script:SeedProfiles = @{
            exfat  = @{ WorkloadMode = 'Disk'; Entrypoint = 'python3 /mnt/in/job.py --out /mnt/out/result.html'; DataDisks = $two }
            outbox = @{ WorkloadMode = 'Disk'; OutboxOutput = $true; Entrypoint = 'python3 /mnt/in/job.py --out /run/staging/result.html'; DataDisks = $two }
        }

        # The runner script embedded in the user-data (the write_files content block), dedented.
        function script:Get-RunnerScript {
            param([string] $UserData)
            $lines = $UserData -split "`n"
            $start = [array]::IndexOf($lines, '  - path: /usr/local/sbin/vmdep-workload')
            $start | Should -BeGreaterOrEqual 0
            $body = [System.Collections.Generic.List[string]]::new()
            for ($i = $start + 3; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^  - path: ') { break }
                $body.Add(($lines[$i] -replace '^      ', ''))
            }
            return ($body -join "`n")
        }

        # Each mount command that targets a data disk label (comment lines skipped).
        function script:Get-DataMountCommand {
            param([string] $Script)
            foreach ($line in ($Script -split "`n")) {
                if ($line.TrimStart().StartsWith('#')) { continue }
                foreach ($seg in ($line -split '\|\||&&|;')) {
                    if ($seg -match '^\s*mount\s.*\bLABEL=VSD') { $seg.Trim() }
                }
            }
        }

        # A POSIX sh for `-n` syntax checks: Debian's /bin/sh is dash. On Windows, use Git for Windows'
        # dash (never the WSL bash launcher that PATH may offer).
        $script:PosixSh = $null
        if ($IsWindows) {
            # git.exe lives in <GitRoot>\cmd, \bin or \mingw64\bin depending on how PATH was set up.
            foreach ($git in @(Get-Command git -CommandType Application -All -ErrorAction SilentlyContinue)) {
                $dir = Split-Path -Parent $git.Source
                for ($up = 0; $up -lt 3 -and -not $script:PosixSh -and $dir; $up++) {
                    $dir = Split-Path -Parent $dir
                    foreach ($c in 'usr\bin\dash.exe', 'usr\bin\sh.exe') {
                        $cand = Join-Path $dir $c
                        if (Test-Path -LiteralPath $cand) { $script:PosixSh = $cand; break }
                    }
                }
                if ($script:PosixSh) { break }
            }
        }
        else {
            $sh = Get-Command dash, sh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sh) { $script:PosixSh = $sh.Source }
        }
    }

    It '<Kind> runner: one read-only mount block per declared disk, by its VSD label' -ForEach @(
        @{ Kind = 'exfat' }, @{ Kind = 'outbox' }
    ) {
        $runner = Get-RunnerScript -UserData (New-CidataUserData -Profile $script:SeedProfiles[$Kind])
        $runner | Should -Match 'mkdir -p /mnt/data/corpus'
        $runner | Should -Match 'LABEL=VSDCORPUS /mnt/data/corpus'
        $runner | Should -Match 'LABEL=VSDWHEELS /mnt/data/wheels'
        $runner | Should -Not -Match '__DATA_DISK_MOUNTS__'
        $mounts = @(Get-DataMountCommand -Script $runner)
        $mounts.Count | Should -Be 4 -Because 'two disks, each with a uid/gid arm and a plain fallback arm'
        foreach ($m in $mounts) {
            $opt = [regex]::Match($m, '\s-o\s+(\S+)')
            $opt.Success | Should -BeTrue -Because "'$m' passes no option list, so it would mount read-write"
            $opts = $opt.Groups[1].Value -split ','
            $opts | Should -Contain 'ro'
            $opts | Should -Not -Contain 'rw'
        }
    }

    It '<Kind> runner: a disk that does not mount, or is not read-only, powers off before the entrypoint' -ForEach @(
        @{ Kind = 'exfat'; Marker = "printf '%s' 71" }, @{ Kind = 'outbox'; Marker = 'ABORT data-disk-not-mounted name=corpus label=VSDCORPUS' }
    ) {
        $runner = Get-RunnerScript -UserData (New-CidataUserData -Profile $script:SeedProfiles[$Kind])
        $runner | Should -Match ([regex]::Escape("if ! mountpoint -q /mnt/data/corpus; then"))
        $runner | Should -Match ([regex]::Escape('findmnt -no OPTIONS /mnt/data/corpus'))
        $guard = ($runner -split "`n" | Where-Object { $_ -match 'mountpoint -q /mnt/data/wheels' } | Select-Object -First 1)
        $guard | Should -Match 'poweroff; exit 0'
        $runner.IndexOf('mountpoint -q /mnt/data/wheels') | Should -BeLessThan $runner.IndexOf("/bin/sh -c '") -Because 'disks are mounted and checked before the workload runs'
        $runner | Should -Match ([regex]::Escape($Marker))
    }

    It '<Kind> runner: the script still parses as POSIX sh (dash -n) with data disks' -ForEach @(
        @{ Kind = 'exfat' }, @{ Kind = 'outbox' }
    ) {
        if (-not $script:PosixSh) { Set-ItResult -Skipped -Because 'no POSIX sh (dash) available on this host'; return }
        $runner = Get-RunnerScript -UserData (New-CidataUserData -Profile $script:SeedProfiles[$Kind])
        $f = Join-Path $TestDrive "runner-$Kind.sh"
        [System.IO.File]::WriteAllText($f, $runner, [System.Text.UTF8Encoding]::new($false))
        $out = & $script:PosixSh -n $f 2>&1
        $LASTEXITCODE | Should -Be 0 -Because "sh -n reported: $out"
    }

    It 'with no data disks the runners carry no data-disk mount and still parse' {
        foreach ($k in 'exfat', 'outbox') {
            $p = @{} + $script:SeedProfiles[$k]
            $p.Remove('DataDisks')
            $runner = Get-RunnerScript -UserData (New-CidataUserData -Profile $p)
            @(Get-DataMountCommand -Script $runner).Count | Should -Be 0
            $runner | Should -Not -Match 'mkdir -p /mnt/data'
            $runner | Should -Not -Match '__DATA_DISK_MOUNTS__'
            if ($script:PosixSh) {
                $f = Join-Path $TestDrive "runner-none-$k.sh"
                [System.IO.File]::WriteAllText($f, $runner, [System.Text.UTF8Encoding]::new($false))
                $null = & $script:PosixSh -n $f 2>&1
                $LASTEXITCODE | Should -Be 0
            }
        }
    }

    It 'refuses an unsafe name before it can reach the seed' {
        $p = @{} + $script:SeedProfiles['outbox']
        $p['DataDisks'] = @(@{ Name = 'x;reboot'; Path = 'D:\vs\x.vhdx'; ImageHash = ('a' * 64) })
        { New-CidataUserData -Profile $p } | Should -Throw -ExpectedMessage '*name*'
    }

    It 'the builder and Serial seeds refuse data disks instead of ignoring them' {
        $dd = @(@{ Name = 'corpus'; Path = 'D:\vs\corpus.vhdx'; ImageHash = ('a' * 64) })
        { New-CidataUserData -Profile @{ WorkloadMode = 'Disk'; EgressMode = 'SquidSniProxy'; Entrypoint = 'python3 /mnt/in/f.py'; EgressAllowlist = @('pypi.org'); DataDisks = $dd } } |
            Should -Throw -ExpectedMessage '*builder*'
        { New-CidataUserData -Profile @{ WorkloadMode = 'Serial'; Entrypoint = 'bash run.sh'; DataDisks = $dd } } |
            Should -Throw -ExpectedMessage '*Serial*'
    }

    It 'Invoke-Voidseal writes the mount lines into the CIDATA seed it attaches' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff
        $p = Join-Path $script:DataRoot 'seedcheck.vhdx'
        & $b.NewVHD @{ Path = $p; SizeBytes = 1GB; Dynamic = $true }
        $h = [string](& $b.GetVhdxImageHash @{ Path = $p })
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = @(@{ Name = 'corpus'; Path = $p; ImageHash = $h }) } `
            -Name 'sbx-dd-seed' -ArtifactRoot (Join-Path $TestDrive 'art-seed') -Destination (Join-Path $TestDrive 'dest-seed') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b -WarningAction SilentlyContinue
        $ud = (@($b.FakeCallLog | Where-Object { $_.Op -eq 'WriteVhdxFile' -and $_.Path -eq $report.Descriptor.SeedDiskPath -and $_.InnerPath -eq 'user-data' }) | Select-Object -First 1).Content
        $ud | Should -Match 'LABEL=VSDCORPUS /mnt/data/corpus'
    }
}

Describe 'CopyDirectoryToVhdx backend method' {

    BeforeAll {
        $script:Corpus = Join-Path $TestDrive 'sample-corpus'
        New-Item -ItemType Directory -Path (Join-Path $script:Corpus 'chapters') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:Corpus 'readme.txt') -Value 'A synthetic sample corpus.' -Encoding utf8
        Set-Content -LiteralPath (Join-Path $script:Corpus 'chapters\one.txt') -Value 'The quick brown fox.' -Encoding utf8
        Set-Content -LiteralPath (Join-Path $script:Corpus 'chapters\two.txt') -Value 'Jumps over the lazy dog.' -Encoding utf8
    }

    It 'is in the manifest with Path and SourceDir, and both factories implement it' {
        (Get-HyperVBackendMethodManifest)['CopyDirectoryToVhdx'] | Should -Be @('Path', 'SourceDir')
        (New-FakeHyperVBackend).CopyDirectoryToVhdx | Should -BeOfType [scriptblock]
        (New-RealHyperVBackend).CopyDirectoryToVhdx | Should -BeOfType [scriptblock]
    }

    It 'fake: records the sorted relative file list and folds the content into the image hash' {
        $b = New-FakeHyperVBackend
        $p = 'C:\vs\copy.vhdx'
        & $b.NewOutputVhdx @{ Path = $p; Label = 'VSDCOPY'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        $empty = [string](& $b.GetVhdxImageHash @{ Path = $p })
        & $b.CopyDirectoryToVhdx @{ Path = $p; SourceDir = $script:Corpus }
        $log = @($b.FakeCallLog | Where-Object { $_.Op -eq 'CopyDirectoryToVhdx' })
        $log.Count | Should -Be 1
        $log[0].FileCount | Should -Be 3
        [string](& $b.GetVhdxImageHash @{ Path = $p }) | Should -Not -Be $empty

        $b2 = New-FakeHyperVBackend
        & $b2.NewOutputVhdx @{ Path = $p; Label = 'VSDCOPY'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        & $b2.CopyDirectoryToVhdx @{ Path = $p; SourceDir = $script:Corpus }
        [string](& $b2.GetVhdxImageHash @{ Path = $p }) | Should -Be ([string](& $b.GetVhdxImageHash @{ Path = $p })) -Because 'same content, same hash'
    }

    It 'fake: refuses a missing disk, an unformatted or Raw disk, and a missing source' {
        $b = New-FakeHyperVBackend
        { & $b.CopyDirectoryToVhdx @{ Path = 'C:\vs\none.vhdx'; SourceDir = $script:Corpus } } | Should -Throw -ExpectedMessage '*does not exist*'
        & $b.NewVHD @{ Path = 'C:\vs\bare.vhdx'; SizeBytes = 64MB; Dynamic = $true }
        { & $b.CopyDirectoryToVhdx @{ Path = 'C:\vs\bare.vhdx'; SourceDir = $script:Corpus } } | Should -Throw -ExpectedMessage '*partition*'
        & $b.NewOutputVhdx @{ Path = 'C:\vs\raw.vhdx'; Label = 'X'; FileSystem = 'Raw'; SizeBytes = 64MB }
        { & $b.CopyDirectoryToVhdx @{ Path = 'C:\vs\raw.vhdx'; SourceDir = $script:Corpus } } | Should -Throw -ExpectedMessage '*partition*'
        & $b.NewOutputVhdx @{ Path = 'C:\vs\ok.vhdx'; Label = 'X'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        { & $b.CopyDirectoryToVhdx @{ Path = 'C:\vs\ok.vhdx'; SourceDir = (Join-Path $TestDrive 'nope') } } | Should -Throw -ExpectedMessage '*does not exist*'
    }

    It 'fake: refuses a disk attached to a running VM (the real Mount-VHD would hit a lock)' {
        $b = New-FakeHyperVBackend
        & $b.NewVM @{ Name = 'vm-copy' }
        & $b.NewOutputVhdx @{ Path = 'C:\vs\busy.vhdx'; Label = 'X'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        & $b.AddHardDiskDrive @{ VMName = 'vm-copy'; Path = 'C:\vs\busy.vhdx' }
        & $b.StartVM @{ Name = 'vm-copy' }
        { & $b.CopyDirectoryToVhdx @{ Path = 'C:\vs\busy.vhdx'; SourceDir = $script:Corpus } } | Should -Throw -ExpectedMessage '*locked*'
    }

    Context 'real body (out-of-process capture; no Hyper-V, no elevation)' {
        BeforeAll {
            $harness = Join-Path $PSScriptRoot 'fixtures/Invoke-RealCopyDirectoryCapture.ps1'
            $lib = Join-Path $script:SkillRoot 'scripts/lib/HyperVBackend.ps1'
            $pwsh = (Get-Process -Id $PID).Path
            if ([string]::IsNullOrWhiteSpace($pwsh)) { $pwsh = 'pwsh' }
            $raw = & $pwsh -NoProfile -File $harness -LibPath $lib 2>&1
            $line = (($raw | Out-String) -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
            $line | Should -Not -BeNullOrEmpty -Because "the harness must emit JSON; got: $raw"
            $script:CopyCap = $line | ConvertFrom-Json
        }

        It 'mounts, copies with the pinned robocopy flags onto the resolved volume, then dismounts' {
            $ok = $script:CopyCap.Ok
            $ok.err | Should -BeNullOrEmpty
            $ok.mounted | Should -Be 'C:\vs\data\corpus.vhdx'
            @($ok.robocopy)[0] | Should -Be $script:CopyCap.Root -Because 'the trailing separator is trimmed so robocopy never sees an escaped quote'
            @($ok.robocopy)[1] | Should -Be 'Q:\'
            foreach ($flag in '/E', '/COPY:D', '/DCOPY:D', '/R:0', '/W:0', '/XJ') { @($ok.robocopy) | Should -Contain $flag }
            @($ok.robocopy) | Should -Not -Contain '/MIR' -Because 'nothing on the disk should ever be purged by a copy'
            $ok.dismounts | Should -Be 1
        }

        It 'treats robocopy exit 8 as a failure and still dismounts' {
            $script:CopyCap.Fail.err | Should -Match 'robocopy failed \(exit 8\)'
            $script:CopyCap.Fail.dismounts | Should -Be 1
        }

        It 'refuses a missing source before mounting anything' {
            $script:CopyCap.NoSource.err | Should -Match 'does not exist'
            $script:CopyCap.NoSource.mounted | Should -BeNullOrEmpty
            $script:CopyCap.NoSource.robocopy | Should -BeNullOrEmpty
        }
    }
}

Describe 'scripts/New-VoidsealDataDisk.ps1 (fake backend)' {

    BeforeAll {
        . (Join-Path $script:SkillRoot 'scripts/New-VoidsealDataDisk.ps1') -DotSourceOnly
        $script:NewCorpus = {
            param([string] $Tag)
            $d = Join-Path $TestDrive "corpus-$Tag"
            New-Item -ItemType Directory -Path (Join-Path $d 'notes') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $d 'a.txt') -Value ('x' * 1000) -Encoding ascii -NoNewline
            Set-Content -LiteralPath (Join-Path $d 'notes\b.txt') -Value 'synthetic note' -Encoding ascii -NoNewline
            return $d
        }
        $script:OutDir = Join-Path $TestDrive 'disks'
        New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
    }

    It 'creates an exFAT disk labelled VSD<NAME>, copies the tree and returns the image hash' {
        $b = New-FakeHyperVBackend
        $src = & $script:NewCorpus 'ok'
        $dest = Join-Path $script:OutDir 'corpus.vhdx'
        $r = New-VoidsealDataDisk -SourceDir $src -Path $dest -Name 'corpus' -Backend $b
        $r.Label | Should -BeExactly 'VSDCORPUS'
        $r.FileCount | Should -Be 2
        $r.ImageHash | Should -Match '^[0-9a-f]{64}$'
        $r.ImageHash | Should -Be ([string](& $b.GetVhdxImageHash @{ Path = $dest }))
        $info = & $b.GetVHDInfo @{ Path = $dest }
        $info.FileSystem | Should -Be 'exFAT'
        $info.Label | Should -Be 'VSDCORPUS'
        @($b.FakeCallLog | Where-Object { $_.Op -eq 'CopyDirectoryToVhdx' }).Count | Should -Be 1
        # The printed declaration is accepted as-is.
        $decl = Invoke-Expression $r.Declaration
        @(ConvertTo-DataDiskList -Value $decl)[0].ImageHash | Should -Be $r.ImageHash
    }

    It 'sizes by default to clusters x 1.3 + 64 MB, in whole MiB; and refuses a too-small -SizeBytes' {
        $b = New-FakeHyperVBackend
        $src = & $script:NewCorpus 'size'
        $r = New-VoidsealDataDisk -SourceDir $src -Path (Join-Path $script:OutDir 'sized.vhdx') -Name 'sized' -Backend $b
        $content = 2 * 128KB
        $r.ContentBytes | Should -Be $content
        $r.SizeBytes | Should -Be ([long]([math]::Ceiling(([math]::Ceiling($content * 1.3) + 64MB) / [double]1MB)) * 1MB)
        ($r.SizeBytes % 1MB) | Should -Be 0
        { New-VoidsealDataDisk -SourceDir $src -Path (Join-Path $script:OutDir 'tiny.vhdx') -Name 'tiny' -SizeBytes 1MB -Backend $b } |
            Should -Throw -ExpectedMessage '*too small*'
    }

    It 'refuses a source tree with a secret-shaped file, and creates nothing' {
        $b = New-FakeHyperVBackend
        $src = & $script:NewCorpus 'secret'
        Set-Content -LiteralPath (Join-Path $src 'notes\.env') -Value 'X=1'
        $dest = Join-Path $script:OutDir 'secret.vhdx'
        { New-VoidsealDataDisk -SourceDir $src -Path $dest -Name 'secret' -Backend $b } | Should -Throw -ExpectedMessage '*secret-shaped*'
        (& $b.GetVHDInfo @{ Path = $dest }) | Should -BeNullOrEmpty
    }

    It 'refuses a source tree with a junction in it' {
        $b = New-FakeHyperVBackend
        $src = & $script:NewCorpus 'link'
        $outside = Join-Path $TestDrive 'outside'
        New-Item -ItemType Directory -Path $outside -Force | Out-Null
        New-Item -ItemType Junction -Path (Join-Path $src 'escape') -Target $outside | Out-Null
        { New-VoidsealDataDisk -SourceDir $src -Path (Join-Path $script:OutDir 'link.vhdx') -Name 'link' -Backend $b } |
            Should -Throw -ExpectedMessage '*junction*'
    }

    It 'refuses a bad name, a non-vhdx path, an existing file, a missing folder, a path inside the source, and the storage root' {
        $b = New-FakeHyperVBackend
        $src = & $script:NewCorpus 'dest'
        { New-VoidsealDataDisk -SourceDir $src -Path (Join-Path $script:OutDir 'x.vhdx') -Name 'Bad' -Backend $b } | Should -Throw -ExpectedMessage '*does not match*'
        { New-VoidsealDataDisk -SourceDir $src -Path (Join-Path $script:OutDir 'x.vhd') -Name 'x' -Backend $b } | Should -Throw -ExpectedMessage '*.vhdx*'
        $exists = Join-Path $script:OutDir 'exists.vhdx'; Set-Content -LiteralPath $exists -Value ''
        { New-VoidsealDataDisk -SourceDir $src -Path $exists -Name 'x' -Backend $b } | Should -Throw -ExpectedMessage '*already exists*'
        { New-VoidsealDataDisk -SourceDir $src -Path (Join-Path $TestDrive 'no\such\dir\x.vhdx') -Name 'x' -Backend $b } | Should -Throw -ExpectedMessage '*does not exist*'
        { New-VoidsealDataDisk -SourceDir $src -Path (Join-Path $src 'notes\self.vhdx') -Name 'x' -Backend $b } | Should -Throw -ExpectedMessage '*inside -SourceDir*'
        $inRoot = Join-Path (Split-Path -Parent (Get-SandboxStorageRoot -Name 'x')) 'x.vhdx'
        { New-VoidsealDataDisk -SourceDir $src -Path $inRoot -Name 'x' -Backend $b } | Should -Throw -ExpectedMessage '*storage root*'
        @($b.FakeCallLog | Where-Object { $_.Op -eq 'CopyDirectoryToVhdx' }).Count | Should -Be 0
    }

    It 'refuses a destination under a non-default -StorageRoot' {
        $b = New-FakeHyperVBackend
        $src = & $script:NewCorpus 'customroot'
        $custom = Join-Path $TestDrive 'dd-custom-root'
        New-Item -ItemType Directory -Path $custom -Force | Out-Null
        { New-VoidsealDataDisk -SourceDir $src -Path (Join-Path $custom 'x.vhdx') -Name 'x' -StorageRoot $custom -Backend $b } |
            Should -Throw -ExpectedMessage "*storage root ('$custom')*"
    }

    It 'removes the half-built disk when the copy fails' {
        $b = New-FakeHyperVBackend
        $b.CopyDirectoryToVhdx = { param($P) throw 'simulated robocopy failure (exit 16)' }
        $src = & $script:NewCorpus 'fail'
        $dest = Join-Path $script:OutDir 'fail.vhdx'
        { New-VoidsealDataDisk -SourceDir $src -Path $dest -Name 'fail' -Backend $b } | Should -Throw -ExpectedMessage '*exit 16*'
        (& $b.GetVHDInfo @{ Path = $dest }) | Should -BeNullOrEmpty
    }

    It 'end to end: a disk built here verifies, attaches, seals and re-hashes unchanged' {
        $b = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateOutboxBlob $script:DdBlob
        $src = & $script:NewCorpus 'e2e'
        $r = New-VoidsealDataDisk -SourceDir $src -Path (Join-Path $script:OutDir 'e2e.vhdx') -Name 'corpus' -Backend $b
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = @(Invoke-Expression $r.Declaration) } `
            -Name 'sbx-dd-e2e' -ArtifactRoot (Join-Path $TestDrive 'art-e2e') -Destination (Join-Path $TestDrive 'dest-e2e') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $b -WarningAction SilentlyContinue
        $report.Error | Should -BeNullOrEmpty
        $report.RunResult.Status | Should -Be 'Success'
        $report.DataDiskChanged | Should -BeFalse
    }
}
