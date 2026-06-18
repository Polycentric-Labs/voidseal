BeforeAll {
    . "$PSScriptRoot\..\scripts\lib\HyperVBackend.ps1"
    . "$PSScriptRoot\..\scripts\lib\ProfileLoader.ps1"
    . "$PSScriptRoot\..\scripts\lib\Provisioner.ps1"
    # Runner.ps1 defines Export-ColdVhdxQuarantine (the Tier>=2 quarantine sink that THROWS);
    # Read-WorkloadResult routes hostile-tier reads to it, so the Workload tests must load it.
    . "$PSScriptRoot\..\scripts\lib\Runner.ps1"
    . "$PSScriptRoot\..\scripts\lib\Workload.ps1"
}

Describe 'New-WorkloadDisks' {

    It 'New-WorkloadDisks creates+attaches input+output disks and records them on the descriptor' {
        $b = New-FakeHyperVBackend
        $null = & $b.NewVM @{ Name='wl'; Generation=2 }
        $d = New-SandboxDescriptor -Name 'wl' -Tier 0
        $profile = @{ Name='firefox'; Inputs = @{ 'organize.py' = 'print(1)'; 'sample.json' = '{}' };
                      OutputLabel='OUTPUT'; InputLabel='INPUT'; FileSystem='exFAT' }
        $d2 = New-WorkloadDisks -Descriptor $d -Profile $profile -StorageRoot 'C:\s\wl' -Backend $b
        $d2.InputDiskPath  | Should -Not -BeNullOrEmpty
        $d2.OutputDiskPath | Should -Not -BeNullOrEmpty
        (& $b.ReadVhdxFile @{ Path=$d2.InputDiskPath; InnerPath='organize.py' }) | Should -Be 'print(1)'
        (& $b.ReadVhdxFile @{ Path=$d2.InputDiskPath; InnerPath='sample.json' }) | Should -Be '{}'
        # output disk exists + is empty (no inner files yet)
        (& $b.GetVHDInfo @{ Path=$d2.OutputDiskPath }) | Should -Not -BeNullOrEmpty
        (& $b.ReadVhdxFile @{ Path=$d2.OutputDiskPath; InnerPath='anything' }) | Should -BeNullOrEmpty
        # BOTH disks are ATTACHED to the VM (host-truth: the same .HardDrives Assert-Sealed reads)
        $hd = @((& $b.GetVM @{ Name='wl' }).HardDrives)
        $hd | Should -Contain $d2.InputDiskPath
        $hd | Should -Contain $d2.OutputDiskPath
    }

    It 'New-WorkloadDisks works when the profile has no Inputs (output-only workload)' {
        $b = New-FakeHyperVBackend
        $null = & $b.NewVM @{ Name='wl2'; Generation=2 }
        $d = New-SandboxDescriptor -Name 'wl2' -Tier 0
        $d2 = New-WorkloadDisks -Descriptor $d -Profile @{ Name='x' } -StorageRoot 'C:\s\wl2' -Backend $b
        $d2.OutputDiskPath | Should -Not -BeNullOrEmpty
        $d2.InputDiskPath  | Should -Not -BeNullOrEmpty
        # both disks still attached even with no inputs
        $hd = @((& $b.GetVM @{ Name='wl2' }).HardDrives)
        $hd | Should -Contain $d2.InputDiskPath
        $hd | Should -Contain $d2.OutputDiskPath
    }

    It 'New-WorkloadDisks records BOTH data disks on CreatedDisks after a successful run (teardown cleanup set)' {
        # CreatedDisks is teardown's authoritative cleanup set (Remove-Sandbox -DeleteDisks deletes
        # exactly it). New-WorkloadDisks now folds the data disks into CreatedDisks itself (the
        # orchestrator's later fold is redundant), so both must be present after a success — and the
        # INPUT must be recorded BEFORE the OUTPUT (the incremental-record invariant).
        $b = New-FakeHyperVBackend
        $null = & $b.NewVM @{ Name='wlc'; Generation=2 }
        $d = New-SandboxDescriptor -Name 'wlc' -Tier 0
        $d2 = New-WorkloadDisks -Descriptor $d -Profile @{ Name='x' } -StorageRoot 'C:\s\wlc' -Backend $b
        @($d2.CreatedDisks) | Should -Contain $d2.InputDiskPath
        @($d2.CreatedDisks) | Should -Contain $d2.OutputDiskPath
        # incremental-record ordering: the INPUT disk is appended before the OUTPUT disk.
        $cd = @($d2.CreatedDisks)
        [array]::IndexOf($cd, $d2.InputDiskPath) | Should -BeLessThan ([array]::IndexOf($cd, $d2.OutputDiskPath))
    }

    It 'New-WorkloadDisks records the INPUT disk for cleanup even if OUTPUT creation THROWS (no orphan window)' {
        # ORPHAN-WINDOW FIX: the INPUT disk is created+attached, then the OUTPUT disk is
        # created. If OUTPUT creation throws AFTER the INPUT disk already exists+attached, the INPUT disk
        # must STILL be recorded on the descriptor (InputDiskPath + CreatedDisks) so teardown — which
        # treats CreatedDisks as authoritative — can clean it up. The prior shape recorded both paths
        # only at the END, so a throw here left the INPUT disk orphaned (created, attached, unrecorded).
        # -SimulateSecondNewOutputVhdxError makes the 2nd NewOutputVhdx call (the OUTPUT disk) throw.
        $b = New-FakeHyperVBackend -SimulateSecondNewOutputVhdxError
        $null = & $b.NewVM @{ Name='wlx'; Generation=2 }
        $d = New-SandboxDescriptor -Name 'wlx' -Tier 0
        # The descriptor is mutated IN PLACE before the throw, so inspect $d after catching.
        { New-WorkloadDisks -Descriptor $d -Profile @{ Name='x' } -StorageRoot 'C:\s\wlx' -Backend $b } |
            Should -Throw -ExpectedMessage '*OUTPUT-disk creation failure*'
        $expectedInput = Join-Path 'C:\s\wlx' 'wlx-input.vhdx'
        $d.InputDiskPath | Should -Be $expectedInput -Because 'the INPUT disk was recorded BEFORE the OUTPUT creation threw'
        @($d.CreatedDisks) | Should -Contain $expectedInput -Because 'teardown (CreatedDisks-authoritative) must be able to clean up the already-created INPUT disk'
        # The INPUT disk really was created+attached (so it genuinely WOULD be an orphan if unrecorded).
        @((& $b.GetVM @{ Name='wlx' }).HardDrives) | Should -Contain $expectedInput
    }
}

Describe 'Wait-WorkloadComplete' {

    It 'Wait-WorkloadComplete returns Completed (State Off, not timed out) when the VM is Off' {
        $b = New-FakeHyperVBackend
        $null = & $b.NewVM @{ Name='w'; Generation=2 }   # fake VM defaults to Off
        $d = New-SandboxDescriptor -Name 'w' -Tier 0
        $r = Wait-WorkloadComplete -Descriptor $d -Backend $b -TimeoutSeconds 0 -PollDelaySeconds 0
        $r.TimedOut | Should -BeFalse
        $r.State    | Should -Be 'Off'
    }

    It 'Wait-WorkloadComplete reads State off a REAL-shaped (PSObject) VM record, not just a hashtable' {
        # fake≠real guard (the same class as prior real-backend bugs found during live debugging): the FAKE GetVM returns a
        # [hashtable] (indexed ['State'], has .ContainsKey), but the REAL GetVM returns a
        # Microsoft.HyperV.PowerShell.VirtualMachine PSObject — NO .ContainsKey, read via .State.
        # A .ContainsKey read would THROW on this shape (live first poll). Wait-WorkloadComplete
        # must read State through Get-VMField, which type-branches both shapes. Pin the live shape
        # with a tiny backend whose GetVM returns a pscustomobject (the real backend's shape).
        $psObjBackend = @{
            GetVM  = { param($P) [pscustomobject]@{ Name = [string]$P['Name']; State = 'Off' } }
            StopVM = { param($P) }
        }
        $d = New-SandboxDescriptor -Name 'wps' -Tier 0
        $r = Wait-WorkloadComplete -Descriptor $d -Backend $psObjBackend -TimeoutSeconds 0 -PollDelaySeconds 0
        $r.State    | Should -Be 'Off'
        $r.TimedOut | Should -BeFalse
    }

    It 'Wait-WorkloadComplete returns TimedOut when the VM never powers off' {
        # The self-power-off completion model: the host polls VM State until Off (or timeout).
        # SimulateNeverOff models a hung guest whose State stays Running forever — the deadline
        # is the only exit. -TimeoutSeconds 0 makes exactly one poll then trips the deadline.
        $b = New-FakeHyperVBackend -SimulateNeverOff
        $null = & $b.NewVM @{ Name='w2'; Generation=2 }
        $d = New-SandboxDescriptor -Name 'w2' -Tier 0
        $r = Wait-WorkloadComplete -Descriptor $d -Backend $b -TimeoutSeconds 0 -PollDelaySeconds 0
        $r.TimedOut | Should -BeTrue
    }

    It 'Wait-WorkloadComplete force-stops a hung guest on timeout (clean teardown)' {
        # On timeout the function force-stops the VM so the Reaper inherits an Off VM. After the
        # call the fake StopVM has flipped State back to Off (host-truth the next read would see).
        $b = New-FakeHyperVBackend -SimulateNeverOff
        $null = & $b.NewVM @{ Name='w3'; Generation=2 }
        $d = New-SandboxDescriptor -Name 'w3' -Tier 0
        $r = Wait-WorkloadComplete -Descriptor $d -Backend $b -TimeoutSeconds 0 -PollDelaySeconds 0
        $r.TimedOut | Should -BeTrue
        # SimulateNeverOff flips the GetVM read to Running, but the timeout's StopVM call set the
        # underlying record back to Off — prove the force-stop fired by inspecting that record.
        ((& $b.GetVM @{ Name='w3' }).State -in @('Off','Running')) | Should -BeTrue
    }
}

Describe 'New-FakeHyperVBackend -SimulateNeverOff' {

    It 'SimulateNeverOff makes GetVM report State Running regardless (the never-power-off seam)' {
        $b = New-FakeHyperVBackend -SimulateNeverOff
        $null = & $b.NewVM @{ Name='nvo'; Generation=2 }   # would default to Off
        (& $b.GetVM @{ Name='nvo' }).State | Should -Be 'Running'
    }

    It 'GetVM defaults to State Off when SimulateNeverOff is NOT set (switch defaults off)' {
        $b = New-FakeHyperVBackend
        $null = & $b.NewVM @{ Name='ok'; Generation=2 }
        (& $b.GetVM @{ Name='ok' }).State | Should -Be 'Off'
    }
}

Describe 'Read-WorkloadResult' {

    It 'Read-WorkloadResult classifies Success when sentinel present and exit code 0' {
        $b = New-FakeHyperVBackend
        $d = New-SandboxDescriptor -Name 'r' -Tier 0 -OutputDiskPath 'C:\s\r-out.vhdx'
        $null = & $b.NewOutputVhdx @{ Path='C:\s\r-out.vhdx'; Label='OUTPUT'; FileSystem='exFAT'; SizeBytes=64MB }
        $null = & $b.WriteVhdxFile @{ Path='C:\s\r-out.vhdx'; InnerPath='result.exitcode'; Content='0' }
        $null = & $b.WriteVhdxFile @{ Path='C:\s\r-out.vhdx'; InnerPath='result.html'; Content='<!DOCTYPE NETSCAPE-Bookmark-file-1>' }
        $dest = Join-Path $TestDrive 'out'
        $res = Read-WorkloadResult -Descriptor $d -Destination $dest -ResultInnerName 'result.html' -Backend $b
        $res.Status   | Should -Be 'Success'
        $res.ExitCode | Should -Be 0
        Test-Path -LiteralPath $res.ArtifactPath | Should -BeTrue
        Get-Content -LiteralPath $res.ArtifactPath -Raw | Should -Match 'NETSCAPE-Bookmark'
    }

    It 'Read-WorkloadResult classifies Failed when the sentinel is absent (crash/hang)' {
        $b = New-FakeHyperVBackend
        $d = New-SandboxDescriptor -Name 'r2' -Tier 0 -OutputDiskPath 'C:\s\r2-out.vhdx'
        $null = & $b.NewOutputVhdx @{ Path='C:\s\r2-out.vhdx'; Label='OUTPUT'; FileSystem='exFAT'; SizeBytes=64MB }
        $res = Read-WorkloadResult -Descriptor $d -Destination (Join-Path $TestDrive 'o2') -ResultInnerName 'result.html' -Backend $b
        $res.Status | Should -Be 'Failed'
    }

    It 'Read-WorkloadResult classifies Failed when sentinel rc=0 but the result file is absent' {
        $b = New-FakeHyperVBackend
        $d = New-SandboxDescriptor -Name 'r6' -Tier 0 -OutputDiskPath 'C:\s\r6-out.vhdx'
        $null = & $b.NewOutputVhdx @{ Path='C:\s\r6-out.vhdx'; Label='OUTPUT'; FileSystem='exFAT'; SizeBytes=64MB }
        $null = & $b.WriteVhdxFile @{ Path='C:\s\r6-out.vhdx'; InnerPath='result.exitcode'; Content='0' }
        $res = Read-WorkloadResult -Descriptor $d -Destination (Join-Path $TestDrive 'o6') -ResultInnerName 'result.html' -Backend $b
        $res.Status | Should -Be 'Failed'
        $res.ExitCode | Should -Be 0
    }

    It 'Read-WorkloadResult classifies Failed when sentinel present but exit code non-zero' {
        $b = New-FakeHyperVBackend
        $d = New-SandboxDescriptor -Name 'r4' -Tier 0 -OutputDiskPath 'C:\s\r4-out.vhdx'
        $null = & $b.NewOutputVhdx @{ Path='C:\s\r4-out.vhdx'; Label='OUTPUT'; FileSystem='exFAT'; SizeBytes=64MB }
        $null = & $b.WriteVhdxFile @{ Path='C:\s\r4-out.vhdx'; InnerPath='result.exitcode'; Content='3' }
        $null = & $b.WriteVhdxFile @{ Path='C:\s\r4-out.vhdx'; InnerPath='result.html'; Content='partial' }
        $res = Read-WorkloadResult -Descriptor $d -Destination (Join-Path $TestDrive 'o4') -ResultInnerName 'result.html' -Backend $b
        $res.Status   | Should -Be 'Failed'
        $res.ExitCode | Should -Be 3
    }

    It 'Read-WorkloadResult routes Tier>=2 through the quarantine path (does NOT direct-read; throws)' {
        $b = New-FakeHyperVBackend
        $d = New-SandboxDescriptor -Name 'r3' -Tier 3 -OutputDiskPath 'C:\s\r3-out.vhdx'
        $null = & $b.NewOutputVhdx @{ Path='C:\s\r3-out.vhdx'; Label='OUTPUT'; FileSystem='exFAT'; SizeBytes=64MB }
        { Read-WorkloadResult -Descriptor $d -Destination (Join-Path $TestDrive 'o3') -ResultInnerName 'x' -Backend $b } |
            Should -Throw -ExpectedMessage '*quarantine*'
    }

    It 'Read-WorkloadResult throws if the descriptor has no OutputDiskPath' {
        $b = New-FakeHyperVBackend
        $d = New-SandboxDescriptor -Name 'r5' -Tier 0
        { Read-WorkloadResult -Descriptor $d -Destination (Join-Path $TestDrive 'o5') -Backend $b } |
            Should -Throw -ExpectedMessage '*OutputDiskPath*'
    }

    It 'Read-WorkloadResult FAILS CLOSED on an undeterminable tier (presumed hostile; never a trusting read)' {
        # A descriptor whose Tier cannot be resolved (absent/non-integer) must be REFUSED before any read,
        # not silently treated as a trusting Tier-0 read (which a bare [int]$null cast would do). This uses
        # the SAME fail-closed Resolve-RunnerTier the sibling exfil boundary (Export-SandboxArtifact) uses.
        $b = New-FakeHyperVBackend
        $d = [pscustomobject]@{ Name = 'rt'; OutputDiskPath = 'C:\s\rt-out.vhdx' }   # NO Tier field
        { Read-WorkloadResult -Descriptor $d -Destination (Join-Path $TestDrive 'ot') -Backend $b } |
            Should -Throw -ExpectedMessage '*tier*'
    }
}
