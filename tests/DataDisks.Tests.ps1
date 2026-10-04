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

Describe 'Invoke-Voidseal attaches, records and seals verified data disks' {

    BeforeAll {
        # A transport-only outbox carrying result.html, so a run can reach Success end to end.
        $stage = Join-Path $TestDrive 'dd-staging'
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $stage 'result.html'), [System.Text.Encoding]::UTF8.GetBytes('<p>summary</p>'))
        $verdicts = Join-Path $TestDrive 'dd-verdicts.json'
        '[]' | Set-Content -LiteralPath $verdicts -Encoding utf8 -NoNewline
        $blobFile = Join-Path $TestDrive 'dd-outbox.bin'
        Push-Location $script:SkillRoot
        try { & python -c "import sys; sys.path.insert(0, 'guest'); import outbox; outbox.write_outbox_from_dir(r'$stage', r'$verdicts', r'$blobFile')" }
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
                $fakeArgs.SimulateGuestDiskWrite = @($GuestWrites | ForEach-Object { Join-Path $script:DataRoot "$_.vhdx" })
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
    }

    It 'verifies, attaches and records each data disk; the seal certifies; the run succeeds' {
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
        $rec[1].Path | Should -Be $run.Decl[1].Path
        foreach ($d in $run.Decl) { $run.Attached | Should -Contain $d.Path }
    }

    It 'never adds a data disk to CreatedDisks, so teardown leaves the file in place' {
        $run = & $script:NewDataRun -Names @('corpus')
        $report = & $script:RunWith $run 'sbx-dd-gc'
        @($report.Descriptor.CreatedDisks) | Should -Not -Contain $run.Decl[0].Path
        (& $run.Backend.GetVHDInfo @{ Path = $run.Decl[0].Path }) | Should -Not -BeNullOrEmpty -Because 'the operator data disk survives teardown'
        (& $run.Backend.GetVM @{ Name = 'sbx-dd-gc' }) | Should -BeNullOrEmpty -Because 'the VM itself is gone'
    }

    It 'a hash mismatch on ANY disk attaches NO data disk and never seals' {
        $run = & $script:NewDataRun -Names @('corpus', 'wheels')
        $second = @{} + $run.Decl[1]
        $second.ImageHash = 'f' * 64
        $report = & $script:RunWith $run 'sbx-dd-mismatch' @($run.Decl[0], $second)
        $report.Error | Should -Match "data disk 'wheels' integrity check FAILED"
        @($report.States) | Should -Not -Contain 'SEALED'
        foreach ($d in $run.Decl) { $run.Attached | Should -Not -Contain $d.Path -Because 'all disks are verified before the first attach' }
        @($run.Backend.FakeCallLog | Where-Object { $_.Op -eq 'StartVM' }).Count | Should -Be 0
    }

    It 'refuses a data disk the host cannot read, before any attach' {
        $run = & $script:NewDataRun -Names @('corpus')
        $decl = @($run.Decl[0], @{ Name = 'ghost'; Path = (Join-Path $script:DataRoot 'ghost.vhdx'); ImageHash = ('a' * 64) })
        $report = & $script:RunWith $run 'sbx-dd-ghost' $decl
        $report.Error | Should -Match 'unreadable via GetVHDInfo'
        $run.Attached | Should -Not -Contain $run.Decl[0].Path
    }

    It 'refuses a differencing data disk' {
        $run = & $script:NewDataRun -Names @()
        $p = Join-Path $script:DataRoot 'diff.vhdx'
        & $run.Backend.NewVHD @{ Path = $p; Differencing = $true; ParentPath = 'C:\elsewhere\base.vhdx' }
        $report = & $script:RunWith $run 'sbx-dd-diff' @(@{ Name = 'diff'; Path = $p; ImageHash = ('a' * 64) })
        $report.Error | Should -Match 'DIFFERENCING'
        @($report.States) | Should -Not -Contain 'SEALED'
    }

    It 'reports DataDiskChanged = $false when every data disk re-hashes to its recorded value' {
        $run = & $script:NewDataRun -Names @('corpus', 'wheels')
        $report = & $script:RunWith $run 'sbx-dd-same'
        $report.DataDiskChanged | Should -BeFalse
        foreach ($d in @($report.Descriptor.DataDisks)) {
            $d.Changed | Should -BeFalse
            $d.PostRunImageHash | Should -Be $d.ImageHash
        }
    }

    It 'a guest write to a data disk sets DataDiskChanged and warns, without failing a good run' {
        $run = & $script:NewDataRun -Names @('corpus', 'wheels') -GuestWrites @('wheels')
        $report = & $script:RunWith $run 'sbx-dd-tamper'
        $report.RunResult.Status | Should -Be 'Success' -Because 'the data disk is an input; a change is reported, not a run failure'
        $report.Error | Should -BeNullOrEmpty
        $report.DataDiskChanged | Should -BeTrue
        $byName = @{}; foreach ($d in @($report.Descriptor.DataDisks)) { $byName[$d.Name] = $d }
        $byName['wheels'].Changed | Should -BeTrue
        $byName['wheels'].PostRunImageHash | Should -Not -Be $byName['wheels'].ImageHash
        $byName['corpus'].Changed | Should -BeFalse
    }

    It 'the warning names the changed disk' {
        $run = & $script:NewDataRun -Names @('corpus') -GuestWrites @('corpus')
        $null = Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk'; DataDisks = $run.Decl } `
            -Name 'sbx-dd-warn' -ArtifactRoot (Join-Path $TestDrive 'art-warn') -Destination (Join-Path $TestDrive 'dest-warn') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $run.Backend -WarningVariable wv -WarningAction SilentlyContinue
        (@($wv) -join "`n") | Should -Match "data disk 'corpus'.*not the recorded"
    }

    It 'the re-hash runs after teardown (the VM is gone, so every data disk is detached)' {
        $run = & $script:NewDataRun -Names @('corpus')
        $null = & $script:RunWith $run 'sbx-dd-order'
        $log = @($run.Backend.FakeCallLog)
        $hashes = @(for ($i = 0; $i -lt $log.Count; $i++) { if ($log[$i].Op -eq 'GetVhdxImageHash' -and $log[$i].Path -eq $run.Decl[0].Path) { $i } })
        $hashes.Count | Should -Be 3 -Because 'one in the test setup, one before attach, one after the run'
        $startIdx = @(for ($i = 0; $i -lt $log.Count; $i++) { if ($log[$i].Op -eq 'StartVM') { $i } })[0]
        $hashes[2] | Should -BeGreaterThan $startIdx
        (& $run.Backend.GetVM @{ Name = 'sbx-dd-order' }) | Should -BeNullOrEmpty
    }

    It 'a data disk that cannot be re-hashed counts as changed (fail closed on the report)' {
        $run = & $script:NewDataRun -Names @('corpus')
        $calls = @(0)
        $orig = $run.Backend.GetVhdxImageHash
        $run.Backend.GetVhdxImageHash = { param($P) $calls[0]++; if ($calls[0] -ge 2) { throw 'simulated: file vanished' }; & $orig $P }.GetNewClosure()
        $report = & $script:RunWith $run 'sbx-dd-gone'
        $report.DataDiskChanged | Should -BeTrue
        @($report.Descriptor.DataDisks)[0].PostRunImageHash | Should -BeNullOrEmpty
    }

    It 'a guest write also counts when the guest hangs and is force-stopped' {
        $run = & $script:NewDataRun -Names @('corpus') -NeverOff -GuestWrites @('corpus')
        $report = & $script:RunWith $run 'sbx-dd-hang'
        $report.RunResult.Status | Should -Be 'Failed'
        $report.DataDiskChanged | Should -BeTrue
    }

    It 'leaves DataDiskChanged $null when no data disk was attached' {
        $run = & $script:NewDataRun -Names @()
        $report = Invoke-Voidseal -Tier 0 -Profile $script:Fx -Workload @{ WorkloadMode = 'Disk' } `
            -Name 'sbx-dd-none' -ArtifactRoot (Join-Path $TestDrive 'art-none') -Destination (Join-Path $TestDrive 'dest-none') `
            -WorkloadTimeoutSeconds 0 -BootPollDelaySeconds 0 -Backend $run.Backend -WarningAction SilentlyContinue
        $report.PSObject.Properties.Name | Should -Contain 'DataDiskChanged'
        $report.DataDiskChanged | Should -BeNullOrEmpty
    }

    It 'refuses data disks when there is no Entrypoint (no seed would mount them read-only)' {
        $run = & $script:NewDataRun -Names @('corpus')
        $noEp = @{} + $script:Fx
        $noEp.Remove('Entrypoint')
        { Invoke-Voidseal -Tier 0 -Profile $noEp -Workload @{ WorkloadMode = 'Disk'; DataDisks = $run.Decl } `
            -Name 'sbx-dd-noep' -Backend $run.Backend } | Should -Throw -ExpectedMessage '*no Entrypoint*'
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
