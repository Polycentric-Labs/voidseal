<#
    Offline unit tests for scripts/Get-VoidsealGoldenImage.ps1.

    The download / SHA hashing / qemu-img convert are LIVE-ONLY (real network + real qemu-img,
    operator-run) — like the Phase-6 items, they are NOT exercised here. What IS covered offline:
    the pure plan/URL/pin logic, the fail-closed SHA-512 compare gate, idempotency, and the
    orchestration SEAMS (qemu preflight fail-closed; the convert routes through the confined-qemu
    seam with a qcow2->vhdx arg vector). No network, no elevation, no real VM, no HyperVBackend touch.
#>

BeforeAll {
    # -DotSourceOnly: define the functions + dot-source HyperVBackend.ps1 (for Resolve-QemuImg /
    # Invoke-ConfinedQemu, which the seam tests mock) and return without running the orchestrator.
    . "$PSScriptRoot/../scripts/Get-VoidsealGoldenImage.ps1" -DotSourceOnly
}

Describe 'Resolve-GoldenImagePlan (pure)' {
    It 'builds the pinned base/serial/image URL (serial embedded in the filename)' {
        $p = Resolve-GoldenImagePlan -OutputPath 'g.vhdx' -WorkDir 'wd'
        $p.Url | Should -Be 'https://cloud.debian.org/images/cloud/bookworm/20260712-2537/debian-12-genericcloud-amd64-20260712-2537.qcow2'
    }
    It 'only ever downloads from cloud.debian.org (image + checksums)' {
        $p = Resolve-GoldenImagePlan -OutputPath 'g.vhdx' -WorkDir 'wd'
        ([uri]$p.Url).Host     | Should -Be 'cloud.debian.org'
        ([uri]$p.SumsUrl).Host | Should -Be 'cloud.debian.org'
    }
    It 'carries a 128-char lowercase-hex pinned SHA-512 (guards a fabricated/typo pin)' {
        (Resolve-GoldenImagePlan -OutputPath 'g.vhdx' -WorkDir 'wd').ExpectedSha512 |
            Should -Match '^[0-9a-f]{128}$'
    }
    It 'places the qcow download in WorkDir under the serial-embedded name' {
        (Resolve-GoldenImagePlan -OutputPath 'g.vhdx' -WorkDir 'wd').QcowPath |
            Should -Be (Join-Path 'wd' 'debian-12-genericcloud-amd64-20260712-2537.qcow2')
    }
}

Describe 'Compare-Sha512 (fail-closed verify gate)' {
    It 'is equal case-insensitively' { Compare-Sha512 -Expected 'ABc' -Actual 'abC' | Should -BeTrue }
    It 'fails on a one-nibble difference' {
        Compare-Sha512 -Expected ('a' * 128) -Actual (('a' * 127) + 'b') | Should -BeFalse
    }
    It 'fails closed on an empty actual' { Compare-Sha512 -Expected ('a' * 128) -Actual '' | Should -BeFalse }
    It 'fails closed on a whitespace actual' { Compare-Sha512 -Expected ('a' * 128) -Actual '   ' | Should -BeFalse }
}

Describe 'Test-GoldenImagePresent (idempotency / -Force)' {
    It 'skips when the output is present and no -Force' {
        $f = New-TemporaryFile
        try { Test-GoldenImagePresent -OutputPath $f.FullName -Force:$false | Should -BeTrue }
        finally { Remove-Item -LiteralPath $f.FullName -Force }
    }
    It 'does NOT skip with -Force even when present (rebuild)' {
        $f = New-TemporaryFile
        try { Test-GoldenImagePresent -OutputPath $f.FullName -Force | Should -BeFalse }
        finally { Remove-Item -LiteralPath $f.FullName -Force }
    }
    It 'does NOT skip when the output is absent' {
        Test-GoldenImagePresent -OutputPath 'X:\nope-does-not-exist.vhdx' -Force:$false | Should -BeFalse
    }
}

Describe 'Get-VoidsealGoldenImage orchestration (fail-closed seams)' {
    It '-Plan prints the plan and writes NO file (pure dry-run)' {
        $out = Join-Path $TestDrive 'golden.vhdx'
        $r = Get-VoidsealGoldenImage -OutputPath $out -WorkDir (Join-Path $TestDrive 'wd') -Plan 6>$null
        Test-Path -LiteralPath $out | Should -BeFalse
        $r.ExpectedSha512 | Should -Match '^[0-9a-f]{128}$'
    }
    It 'refuses fail-closed before any download when the qemu-img preflight throws (and flows the reused 8.2.0 floor)' {
        Mock Resolve-QemuImg { throw 'qemu-img not found on PATH' }
        Mock Get-DebianImage { throw 'the download must not be reached after a preflight failure' }
        { Get-VoidsealGoldenImage -OutputPath (Join-Path $TestDrive 'g.vhdx') -WorkDir (Join-Path $TestDrive 'wd2') 6>$null } |
            Should -Throw '*qemu-img*'
        # Prove the reused engine floor actually FLOWS into the preflight — not merely that it was called.
        Should -Invoke Resolve-QemuImg -Times 1 -Exactly -ParameterFilter { $MinVersion -eq '8.2.0' }
        Should -Invoke Get-DebianImage -Times 0
    }
    It 'idempotently skips (no download) when the output is already present and no -Force' {
        Mock Resolve-QemuImg { 'qemu-img' }
        Mock Get-DebianImage { throw 'must not download when the golden image is already present' }
        $out = Join-Path $TestDrive 'present.vhdx'
        'placeholder' | Set-Content -LiteralPath $out
        $r = Get-VoidsealGoldenImage -OutputPath $out -WorkDir (Join-Path $TestDrive 'wd4') 6>$null
        $r | Should -Be $out
        Should -Invoke Get-DebianImage -Times 0
    }
    It 'routes the convert through Invoke-ConfinedQemu with a qcow2->vhdx arg vector' {
        Mock Invoke-ConfinedQemu { $global:LASTEXITCODE = 0 }
        Mock Move-Item {}
        Convert-QcowToVhdx -QcowPath (Join-Path $TestDrive 'a.qcow2') `
                           -OutputPath (Join-Path $TestDrive 'b.vhdx') -QemuPath 'qemu-img' 6>$null
        Should -Invoke Invoke-ConfinedQemu -Times 1 -Exactly -ParameterFilter {
            $Arguments -contains 'convert' -and $Arguments -contains 'qcow2' -and
            $Arguments -contains 'vhdx'    -and $Arguments -contains '-O'
        }
    }
    It 'fails closed when the confined convert returns a non-zero exit code' {
        Mock Invoke-ConfinedQemu { $global:LASTEXITCODE = 1 }
        Mock Move-Item {}
        { Convert-QcowToVhdx -QcowPath (Join-Path $TestDrive 'a.qcow2') `
                             -OutputPath (Join-Path $TestDrive 'b.vhdx') -QemuPath 'qemu-img' 6>$null } |
            Should -Throw '*convert failed*'
    }
}
