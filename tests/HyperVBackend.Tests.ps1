#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 tests for scripts/lib/HyperVBackend.ps1 (the mockable Hyper-V backend).

.DESCRIPTION
    Contract under test: a mockable Hyper-V backend — the SINGLE seam through which
    every later component (Provisioner, Sealer, Runner) touches Hyper-V.

    A backend is a [hashtable] of scriptblocks (one per operation). Two factories
    produce the SAME shape:
        New-RealHyperVBackend   — wraps the real Hyper-V cmdlets; fails closed with a
                                  single clear message on permission/availability errors.
        New-FakeHyperVBackend   — in-memory state so the consumers unit-test with no live VM.

    Every method is invoked uniformly:  & $backend.<Method> @{ <named args> }
    (a single hashtable argument), so signatures are uniform + parity-checkable.

    ENVIRONMENT FACT (this session): Hyper-V is installed + running but this process
    is NOT elevated / not in Hyper-V Administrators, so real Get-VM/New-VM throw
    "You do not have the required permission". The tests therefore exercise the REAL
    backend ONLY via its surface + TestAvailable's graceful classification — never by
    actually creating a VM. The FAKE backend carries all behavioral assertions.

    TDD: written first; drives the HyperVBackend.ps1 implementation.
#>

BeforeAll {
    # Resolve the skill root from this test file's location: <root>/tests/ -> <root>
    $script:SkillRoot = Split-Path -Parent $PSScriptRoot
    $script:LibPath   = Join-Path $script:SkillRoot 'scripts/lib/HyperVBackend.ps1'

    Test-Path $script:LibPath | Should -BeTrue -Because 'the backend script must exist to be tested'
    . $script:LibPath

    # The canonical method manifest the lib must export (single source of truth).
    # Each entry: method name -> the named arg keys it accepts.
    $script:ExpectedMethods = Get-HyperVBackendMethodManifest
}

# ===========================================================================
#  Surface / manifest
# ===========================================================================
Describe 'HyperVBackend — method manifest (the contract surface)' {

    It 'exposes a non-empty manifest of methods' {
        $script:ExpectedMethods | Should -Not -BeNullOrEmpty
        $script:ExpectedMethods | Should -BeOfType [System.Collections.IDictionary]
    }

    It 'covers every operation the Provisioner/Sealer/Runner need' {
        # If any later task would have to call a raw Hyper-V cmdlet, that operation is
        # missing here. This list is the completeness gate for the whole build.
        $required = @(
            # capability probe
            'TestAvailable'
            # VM lifecycle
            'NewVM', 'GetVM', 'StartVM', 'StopVM', 'RemoveVM'
            # hardware
            'SetProcessor', 'SetMemory', 'SetFirmware', 'SetComPort', 'GetComPort'
            # guest command delivery (the Runner serial seam)
            'InvokeGuestCommand'
            # host channels (the seal surface)
            'SetHostChannel', 'GetHostChannels'
            # disk
            'NewVHD', 'NewOutputVhdx', 'WriteVhdxFile', 'ReadVhdxFile', 'GetVHDInfo', 'RemoveVHD', 'AddHardDiskDrive', 'RemoveHardDiskDrive', 'SetDvdDrive', 'RemoveDvdDrive', 'GetDvdDrives'
            # switch / network
            'NewSwitch', 'GetSwitch', 'RemoveSwitch', 'ConnectNetworkAdapter', 'RemoveNetworkAdapter', 'GetNetworkAdapter'
            # checkpoint
            'Checkpoint', 'RestoreCheckpoint', 'GetCheckpoint', 'RemoveCheckpoint'
        )
        foreach ($m in $required) {
            $script:ExpectedMethods.Keys | Should -Contain $m -Because "the consumers rely on backend.$m so they never call a raw Hyper-V cmdlet"
        }
    }

    It 'documents a non-empty arg-key list for every method that takes args (only TestAvailable is arg-less)' {
        # Arg-key drift guard: if a method silently grew/lost args, this catches the
        # manifest going stale. TestAvailable is the sole documented arg-less method (@()).
        foreach ($name in $script:ExpectedMethods.Keys) {
            $argKeys = @($script:ExpectedMethods[$name])
            if ($name -eq 'TestAvailable') {
                $argKeys.Count | Should -Be 0 -Because 'TestAvailable is the capability probe and takes no named args'
            }
            else {
                $argKeys.Count | Should -BeGreaterThan 0 -Because "$name is documented as taking named args; an empty list means the manifest drifted"
            }
        }
    }

    It 'every documented arg key is a non-empty string (no malformed manifest entries)' {
        foreach ($name in $script:ExpectedMethods.Keys) {
            foreach ($key in @($script:ExpectedMethods[$name])) {
                $key | Should -BeOfType [string] -Because "$name's arg keys must be string names"
                [string]::IsNullOrWhiteSpace($key) | Should -BeFalse -Because "$name has a blank/whitespace arg key, which is malformed"
            }
        }
    }

    It 'manifest documents NewOutputVhdx with its arg keys' {
        $m = Get-HyperVBackendMethodManifest
        $m.Keys | Should -Contain 'NewOutputVhdx'
        $m['NewOutputVhdx'] | Should -Contain 'Path'
        $m['NewOutputVhdx'] | Should -Contain 'Label'
        $m['NewOutputVhdx'] | Should -Contain 'FileSystem'
        $m['NewOutputVhdx'] | Should -Contain 'SizeBytes'
    }
}

# ===========================================================================
#  Interface parity — fake and real expose the SAME surface
# ===========================================================================
Describe 'HyperVBackend — interface parity (fake matches real)' {

    BeforeEach {
        $script:Real = New-RealHyperVBackend
        $script:Fake = New-FakeHyperVBackend
    }

    It 'both factories return a hashtable of scriptblocks' {
        $script:Real | Should -BeOfType [System.Collections.IDictionary]
        $script:Fake | Should -BeOfType [System.Collections.IDictionary]
        foreach ($k in $script:ExpectedMethods.Keys) {
            $script:Real[$k] | Should -BeOfType [scriptblock] -Because "real backend must implement $k"
            $script:Fake[$k] | Should -BeOfType [scriptblock] -Because "fake backend must implement $k"
        }
    }

    It 'the real and fake backends expose IDENTICAL method-name sets' {
        # A later component written against the fake must work against the real one.
        $realKeys = @($script:Real.Keys | Where-Object { $script:Real[$_] -is [scriptblock] } | Sort-Object)
        $fakeKeys = @($script:Fake.Keys | Where-Object { $script:Fake[$_] -is [scriptblock] } | Sort-Object)
        ($realKeys -join ',') | Should -Be ($fakeKeys -join ',')
    }

    It 'both backends implement exactly the manifest method set (no missing, no extra)' {
        $manifestKeys = @($script:ExpectedMethods.Keys | Sort-Object)
        foreach ($impl in @($script:Real, $script:Fake)) {
            $implMethodKeys = @($impl.Keys | Where-Object { $impl[$_] -is [scriptblock] } | Sort-Object)
            ($implMethodKeys -join ',') | Should -Be ($manifestKeys -join ',') -Because 'each backend must match the manifest exactly'
        }
    }

    It 'the FAKE actually consumes each method''s documented primary-identifier arg key (omitting it throws)' {
        # Arg-key drift guard with teeth: for every method, the manifest documents a
        # primary identifier ('Name' for VM/switch/VHD lifecycle, 'VMName' for ops on an
        # existing VM, 'Path' for the VHD-keyed queries). If the fake stopped reading that
        # documented key, calling WITHOUT it would no longer throw — this test fails then,
        # surfacing the manifest⇄implementation drift. (Real isn't exercised: it requires a
        # live elevated Hyper-V; its key-wiring is covered by the shared AssertArg path.)
        $fake = New-FakeHyperVBackend

        # Each method -> the documented arg key it MUST validate as required. Drawn straight
        # from the manifest's first identifying key. TestAvailable is arg-less (excluded).
        $primaryKey = @{
            NewVM = 'Name'; GetVM = 'Name'; StartVM = 'Name'; StopVM = 'Name'; RemoveVM = 'Name'
            SetProcessor = 'VMName'; SetMemory = 'VMName'; SetFirmware = 'VMName'; SetComPort = 'VMName'; GetComPort = 'VMName'
            InvokeGuestCommand = 'VMName'
            SetHostChannel = 'VMName'; GetHostChannels = 'VMName'
            NewVHD = 'Path'; NewOutputVhdx = 'Path'; WriteVhdxFile = 'Path'; ReadVhdxFile = 'Path'; GetVHDInfo = 'Path'; RemoveVHD = 'Path'
            AddHardDiskDrive = 'VMName'; RemoveHardDiskDrive = 'VMName'; SetDvdDrive = 'VMName'; RemoveDvdDrive = 'VMName'; GetDvdDrives = 'VMName'
            NewSwitch = 'Name'; GetSwitch = 'Name'; RemoveSwitch = 'Name'
            ConnectNetworkAdapter = 'VMName'; RemoveNetworkAdapter = 'VMName'; GetNetworkAdapter = 'VMName'
            Checkpoint = 'VMName'; RestoreCheckpoint = 'VMName'; GetCheckpoint = 'VMName'; RemoveCheckpoint = 'VMName'
        }

        # Sanity: the map covers exactly the non-TestAvailable manifest methods (so a NEW
        # method added to the manifest forces this map — and thus the contract — to update).
        $covered  = @($primaryKey.Keys | Sort-Object)
        $expected = @($script:ExpectedMethods.Keys | Where-Object { $_ -ne 'TestAvailable' } | Sort-Object)
        ($covered -join ',') | Should -Be ($expected -join ',') -Because 'every arg-taking manifest method must be in the primary-key drift map'

        foreach ($name in $primaryKey.Keys) {
            $key = $primaryKey[$name]
            $script:ExpectedMethods[$name] | Should -Contain $key -Because "$name's primary key '$key' must be one of its documented arg keys"
            # Invoke with the primary key absent (empty args). Reading the documented key as
            # required means this MUST throw; if it doesn't, the fake ignores the key (drift).
            { & $fake[$name] @{} } | Should -Throw -Because "$name must read its documented required arg '$key'; not throwing on omission means the manifest and the fake have drifted"
        }
    }
}

# ===========================================================================
#  TestAvailable — graceful capability probe (NEVER throws)
# ===========================================================================
Describe 'HyperVBackend — TestAvailable (capability probe, must not throw)' {

    It 'REAL TestAvailable returns a structured result and does NOT throw (even when Hyper-V unreachable)' {
        $real = New-RealHyperVBackend
        # NB: assign OUTSIDE a Should -Not -Throw block — a block scriptblock runs in a
        # child scope, so an assignment inside it would not reach the test scope. The
        # call not throwing IS the assertion (a throw here fails the test directly).
        $result = & $real.TestAvailable @{}

        $result | Should -BeOfType [System.Collections.IDictionary]
        $result.ContainsKey('Available') | Should -BeTrue
        $result.ContainsKey('Elevated')  | Should -BeTrue
        $result.ContainsKey('Reason')    | Should -BeTrue
        $result.Available | Should -BeOfType [bool]
        $result.Elevated  | Should -BeOfType [bool]

        # In this non-elevated session it WILL be unavailable with a permission Reason;
        # but if somehow run elevated, Available may be $true. Either way: no throw, and
        # when unavailable, Reason is populated.
        if (-not $result.Available) {
            $result.Reason | Should -Not -BeNullOrEmpty -Because 'an unavailable probe must explain why (actionable message)'
            $result.Reason | Should -Match '(?i)(permission|privilege|elevat|administrator|Hyper-V|unavailable|not installed|module)'
        }
    }

    It 'FAKE TestAvailable reports Available=$true (the fake is always usable in tests)' {
        $fake = New-FakeHyperVBackend
        $result = & $fake.TestAvailable @{}
        $result.Available | Should -BeTrue
        $result.ContainsKey('Reason') | Should -BeTrue
    }

    It 'a fake forced unavailable reports Available=$false with a Reason and still does not throw' {
        $fake = New-FakeHyperVBackend -SimulateUnavailable
        # Capture outside a Should -Not -Throw block (child-scope assignment caveat); a
        # throw on this call would fail the test directly, which is the no-throw assertion.
        $result = & $fake.TestAvailable @{}
        $result.Available | Should -BeFalse
        $result.Reason    | Should -Not -BeNullOrEmpty
    }
}

# ===========================================================================
#  FAKE backend — VM lifecycle behavior (the test seam for the consumers)
# ===========================================================================
Describe 'Fake backend — VM lifecycle' {

    BeforeEach { $script:B = New-FakeHyperVBackend }

    It 'NewVM then GetVM returns the created VM' {
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2; MemoryStartupBytes = 4GB }
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        $vm | Should -Not -BeNullOrEmpty
        $vm.Name | Should -Be 'vm1'
        $vm.Generation | Should -Be 2
        $vm.State | Should -Be 'Off'
    }

    It 'GetVM for a non-existent VM returns nothing (null/empty), does not throw' {
        # Capture outside Should -Not -Throw (child-scope assignment caveat).
        $vm = & $script:B.GetVM @{ Name = 'nope' }
        $vm | Should -BeNullOrEmpty
    }

    It 'NewVM twice with the same name throws (Hyper-V would reject a duplicate)' {
        & $script:B.NewVM @{ Name = 'dup'; Generation = 2 }
        { & $script:B.NewVM @{ Name = 'dup'; Generation = 2 } } | Should -Throw -ExpectedMessage '*already exists*'
    }

    It 'StartVM / StopVM transition the recorded State' {
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
        & $script:B.StartVM @{ Name = 'vm1' }
        (& $script:B.GetVM @{ Name = 'vm1' }).State | Should -Be 'Running'
        & $script:B.StopVM @{ Name = 'vm1' }
        (& $script:B.GetVM @{ Name = 'vm1' }).State | Should -Be 'Off'
    }

    It 'RemoveVM removes the VM but does NOT delete its VHDX records (caller cleans disks)' {
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
        & $script:B.NewVHD @{ Path = 'C:\vhd\vm1.vhdx'; SizeBytes = 40GB }
        & $script:B.AddHardDiskDrive @{ VMName = 'vm1'; Path = 'C:\vhd\vm1.vhdx' }

        & $script:B.RemoveVM @{ Name = 'vm1' }
        (& $script:B.GetVM @{ Name = 'vm1' }) | Should -BeNullOrEmpty -Because 'the VM is gone'

        # The VHDX record survives RemoveVM — it must NOT auto-delete disks (the Reaper's contract).
        # The disk record is queryable independently of the (now-deleted) VM.
        $info = & $script:B.GetVHDInfo @{ Path = 'C:\vhd\vm1.vhdx' }
        $info | Should -Not -BeNullOrEmpty -Because 'Remove-VM leaves disks; explicit VHDX cleanup is the caller step'
        $info.Path | Should -Be 'C:\vhd\vm1.vhdx'
    }
}

# ===========================================================================
#  FAKE backend — hardware
# ===========================================================================
Describe 'Fake backend — hardware (processor / memory / firmware / COM port)' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
    }

    It 'SetProcessor records count + ExposeVirtualizationExtensions (nested virt)' {
        & $script:B.SetProcessor @{ VMName = 'vm1'; Count = 4; ExposeVirtualizationExtensions = $true }
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        $vm.ProcessorCount | Should -Be 4
        $vm.ExposeVirtualizationExtensions | Should -BeTrue
    }

    It 'SetMemory records startup/dynamic settings' {
        & $script:B.SetMemory @{ VMName = 'vm1'; StartupBytes = 4GB; DynamicMemoryEnabled = $false }
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        $vm.MemoryStartupBytes | Should -Be 4GB
        $vm.DynamicMemoryEnabled | Should -BeFalse
    }

    It 'SetFirmware records the SecureBoot template (MicrosoftUEFICertificateAuthority for Debian)' {
        & $script:B.SetFirmware @{ VMName = 'vm1'; EnableSecureBoot = $true; SecureBootTemplate = 'MicrosoftUEFICertificateAuthority' }
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        $vm.SecureBootEnabled  | Should -BeTrue
        $vm.SecureBootTemplate | Should -Be 'MicrosoftUEFICertificateAuthority'
    }

    It 'SetComPort records the COM1 named-pipe path (the Linux mgmt channel)' {
        & $script:B.SetComPort @{ VMName = 'vm1'; Number = 1; Path = '\\.\pipe\vm1-com1' }
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        $vm.ComPorts[1] | Should -Be '\\.\pipe\vm1-com1'
    }

    # ---- GetComPort (the post-seal COM1-liveness read the gate routes through) ----
    # The seal must NEVER sever the Runner's COM1 serial command channel. Assert-Sealed reads COM1
    # back from host truth via GetComPort; the fake reads the state SetComPort records.
    It 'GetComPort returns the recorded port @{ Number; Path } after SetComPort' {
        & $script:B.SetComPort @{ VMName = 'vm1'; Number = 1; Path = '\\.\pipe\vm1-com1' }
        $com = & $script:B.GetComPort @{ VMName = 'vm1'; Number = 1 }
        $com | Should -Not -BeNullOrEmpty
        $com.Number | Should -Be 1
        $com.Path   | Should -Be '\\.\pipe\vm1-com1'
    }

    It 'GetComPort defaults to Number 1 (the COM1 management port) when Number is omitted' {
        & $script:B.SetComPort @{ VMName = 'vm1'; Number = 1; Path = '\\.\pipe\vm1-com1' }
        $com = & $script:B.GetComPort @{ VMName = 'vm1' }
        $com | Should -Not -BeNullOrEmpty
        $com.Path | Should -Be '\\.\pipe\vm1-com1'
    }

    It 'GetComPort returns $null when no COM port was wired (an unattached port is "not live")' {
        # Fresh VM, no SetComPort: COM1 has no pipe path.
        (& $script:B.GetComPort @{ VMName = 'vm1'; Number = 1 }) |
            Should -BeNullOrEmpty -Because 'a VM with no wired COM1 pipe has no live serial channel'
    }

    It 'GetComPort on a missing VM throws naming the VM (fail closed)' {
        { & $script:B.GetComPort @{ VMName = 'ghost'; Number = 1 } } | Should -Throw -ExpectedMessage '*ghost*'
    }
}

# ===========================================================================
#  FAKE backend — host channels (the SEAL surface: clipboard/shares/GSI/ESM)
# ===========================================================================
#  The Sealer turns these OFF; Assert-Sealed host-verifies they are. The backend
#  is the seam — the Sealer must NEVER reach for raw Set-VM / *-VMIntegrationService.
Describe 'Fake backend — host channels (the seal surface)' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
    }

    It 'a freshly-created VM reports ALL host channels ON (the unsealed default)' {
        # Hyper-V enables Guest Services / Enhanced Session by default; a new VM is NOT sealed.
        $ch = & $script:B.GetHostChannels @{ VMName = 'vm1' }
        $ch.Clipboard       | Should -BeTrue
        $ch.Shares          | Should -BeTrue
        $ch.GuestServices   | Should -BeTrue
        $ch.EnhancedSession | Should -BeTrue
    }

    It 'GetHostChannels returns exactly the four canonical channel keys' {
        $ch = & $script:B.GetHostChannels @{ VMName = 'vm1' }
        @($ch.Keys | Sort-Object) -join ',' | Should -Be 'Clipboard,EnhancedSession,GuestServices,Shares'
    }

    It 'SetHostChannel turns a single channel OFF (others untouched)' {
        & $script:B.SetHostChannel @{ VMName = 'vm1'; Channel = 'GuestServices'; Enabled = $false }
        $ch = & $script:B.GetHostChannels @{ VMName = 'vm1' }
        $ch.GuestServices   | Should -BeFalse -Because 'the channel we turned off must read off'
        $ch.EnhancedSession | Should -BeTrue  -Because 'turning one channel off must not affect the others'
    }

    It 'SetHostChannel can turn a channel back ON (round-trips)' {
        & $script:B.SetHostChannel @{ VMName = 'vm1'; Channel = 'Clipboard'; Enabled = $false }
        (& $script:B.GetHostChannels @{ VMName = 'vm1' }).Clipboard | Should -BeFalse
        & $script:B.SetHostChannel @{ VMName = 'vm1'; Channel = 'Clipboard'; Enabled = $true }
        (& $script:B.GetHostChannels @{ VMName = 'vm1' }).Clipboard | Should -BeTrue
    }

    It 'SetHostChannel rejects an unknown channel name' {
        { & $script:B.SetHostChannel @{ VMName = 'vm1'; Channel = 'NotAChannel'; Enabled = $false } } |
            Should -Throw -ExpectedMessage '*NotAChannel*' -Because 'only the four canonical channels are valid'
    }

    It 'SetHostChannel on a missing VM throws naming the VM' {
        { & $script:B.SetHostChannel @{ VMName = 'ghost'; Channel = 'Clipboard'; Enabled = $false } } |
            Should -Throw -ExpectedMessage '*ghost*'
    }

    It 'GetHostChannels returns a COPY (mutating the result does not change live state)' {
        $ch = & $script:B.GetHostChannels @{ VMName = 'vm1' }
        $ch.GuestServices = $false      # mutate the returned copy
        (& $script:B.GetHostChannels @{ VMName = 'vm1' }).GuestServices |
            Should -BeTrue -Because 'the read must hand back a copy, not a handle on live state'
    }

    It 'host-channel state survives a Checkpoint/Restore roundtrip' {
        # Seal-then-revert correctness: a channel turned off after the checkpoint comes back on restore.
        & $script:B.SetHostChannel @{ VMName = 'vm1'; Channel = 'GuestServices'; Enabled = $true }
        & $script:B.Checkpoint @{ VMName = 'vm1'; SnapshotName = 'gsi-on' }
        & $script:B.SetHostChannel @{ VMName = 'vm1'; Channel = 'GuestServices'; Enabled = $false }
        (& $script:B.GetHostChannels @{ VMName = 'vm1' }).GuestServices | Should -BeFalse
        & $script:B.RestoreCheckpoint @{ VMName = 'vm1'; SnapshotName = 'gsi-on' }
        (& $script:B.GetHostChannels @{ VMName = 'vm1' }).GuestServices |
            Should -BeTrue -Because 'the checkpoint captured the channel state; restore brings it back'
    }

    It 'the FAKE GetHostChannels can be made to THROW (SimulateChannelReadError) — the unreadable-channel seam' {
        # The fail-OPEN regression seam: a backend whose host-channel read fails must SURFACE
        # that failure, never silently report a channel as off. The fake's SimulateChannelReadError
        # models one channel's read throwing; Assert-Sealed's fail-closed test (Sealer.Tests.ps1)
        # relies on this seam to prove the gate refuses on an unreadable channel.
        $errFake = New-FakeHyperVBackend -SimulateChannelReadError
        & $errFake.NewVM @{ Name = 'vm-err'; Generation = 2 }
        { & $errFake.GetHostChannels @{ VMName = 'vm-err' } } |
            Should -Throw -ExpectedMessage '*channel*read*' -Because 'an unreadable channel must propagate so callers fail closed; it must never be coerced to off'
    }
}

# ===========================================================================
#  REAL backend — GetHostChannels FAILS CLOSED on the one REAL channel (GuestServices)
# ===========================================================================
#  THE CENTRAL SAFETY GUARD, updated for the LINUX-GUEST seal
#  model: the real GetHostChannels has exactly ONE host<->guest channel it can
#  read as host truth — the Guest Service Interface integration service (Copy-VMFile). That read
#  MUST rethrow on failure: a swallowed read (coercing an unreadable channel to "off") would let
#  Assert-Sealed certify a VM SEALED with the worst (bidirectional Copy-VMFile) channel actually
#  LIVE — a fail-OPEN.
#
#  The three ESM facets (EnhancedSession / Clipboard / Shares) are NO LONGER read from a host
#  property: a live diagnostic proved Disable-VMConsoleSupport does not flip ConsoleMode (it stays
#  0), so a ConsoleMode-keyed read could NEVER report them off on a real host (the seal refused
#  forever). They are reported OFF BY CONSTRUCTION (ESM clipboard/drive-redirection needs Windows-
#  guest components a stock Linux image structurally lacks, and the host exposes no per-VM ESM-on
#  signal for any guest). There is therefore NO ESM-facet read to fail closed — only the GSI read.
#  The real backend's internal cmdlets cannot be reliably shadowed inside Pester's managed scope
#  (its method closures resolve cmdlets against the session at .GetNewClosure() time, not the test
#  scope — see the file header), so we PIN the GSI rethrow STRUCTURALLY via the AST: the catch on
#  the GSI read MUST rethrow and MUST NOT contain a fail-open state assignment.
Describe 'Real backend — GetHostChannels rethrows the unreadable REAL channel (GuestServices fail-OPEN guard, AST-pinned)' {

    BeforeAll {
        $tokens = $null; $parseErrors = $null
        $script:LibAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:LibPath, [ref]$tokens, [ref]$parseErrors)
        @($parseErrors).Count | Should -Be 0 -Because 'the backend lib must parse cleanly to be analyzed'

        $script:RealFnAst = $script:LibAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                      $n.Name -eq 'New-RealHyperVBackend'
        }, $true) | Select-Object -First 1
        $script:RealFnAst | Should -Not -BeNullOrEmpty -Because 'the real backend factory must exist'

        # The GuestServices read try/catch inside the real GetHostChannels op (the ONE real channel).
        $allTry = $script:RealFnAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.TryStatementAst] }, $true)
        $script:GsiTry = $allTry | Where-Object { $_.Body.Extent.Text -match 'Guest Service Interface' } | Select-Object -First 1

        # Locate the `$b.GetHostChannels = { ... }` assignment body so we can scan the whole method.
        $script:RealChanAssign = $script:RealFnAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                      $n.Left.Extent.Text -eq '$b.GetHostChannels'
        }, $true) | Select-Object -First 1
    }

    It 'the Guest Service Interface (GuestServices) read catch RETHROWS — never coerces to off (THE fix)' {
        $script:GsiTry | Should -Not -BeNullOrEmpty -Because 'the GSI channel read must be wrapped in a try/catch'
        $catch = @($script:GsiTry.CatchClauses)[0]
        $catch | Should -Not -BeNullOrEmpty

        $hasThrow = $null -ne ($catch.Body.FindAll({
            param($n) $n -is [System.Management.Automation.Language.ThrowStatementAst] }, $true) | Select-Object -First 1)
        $hasThrow | Should -BeTrue -Because 'an unreadable GuestServices channel MUST propagate so Assert-Sealed fails closed'

        # The fail-OPEN signature the review caught: `catch { $gsiOn = $false }`. It must be gone.
        $hasFailOpenAssign = $null -ne ($catch.Body.FindAll({
            param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                      $n.Left.Extent.Text -eq '$gsiOn'
        }, $true) | Select-Object -First 1)
        $hasFailOpenAssign | Should -BeFalse -Because 'coercing an unreadable GuestServices channel to $false (off) is the fail-OPEN bug; the catch must rethrow, not assign'
    }

    It 'the ESM facets are NOT read from a host property (no Get-CimInstance / ConsoleMode member access gates the seal)' {
        # The headline of the Linux-guest model: GetHostChannels must NOT key the ESM facets off the
        # WMI console-mode property (it never flips with Disable-VMConsoleSupport, so the old read
        # reported the facets ON forever and the seal could never certify). Pin via the AST that the
        # method INVOKES no Get-CimInstance and reads no `.ConsoleMode` member — the facets are
        # reported off by construction. (AST-precise so a legitimate prose mention can't false-trip.)
        $script:RealChanAssign | Should -Not -BeNullOrEmpty -Because 'the real factory must define GetHostChannels'

        $cimCalls = $script:RealChanAssign.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                      $n.GetCommandName() -eq 'Get-CimInstance'
        }, $true)
        @($cimCalls).Count | Should -Be 0 -Because 'GetHostChannels no longer queries WMI for a per-VM ESM-on signal (none exists); the ESM-facet read is gone'

        $consoleModeReads = $script:RealChanAssign.FindAll({
            param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] -and
                      $n.Member.Extent.Text -match '(?i)^ConsoleMode$'
        }, $true)
        @($consoleModeReads).Count | Should -Be 0 -Because 'keying the ESM facets off the non-flipping ConsoleMode property is the bug found during live debugging; the facets must be reported off by construction'
    }
}

# ===========================================================================
#  REAL backend — the LINUX-GUEST host-channel seal model
# ===========================================================================
#  THE BEHAVIORAL REGRESSION TEST FOR THE SEAL GATE (security-critical), out-of-process.
#
#  History of the two live-debug bugs on this seam:
#
#  The invalid-enum bind: the real SetHostChannel mapped EnhancedSession onto
#  `Set-VM -EnhancedSessionTransportType None|HvSocket`. That enum has ONLY VMBus/HvSocket (no None),
#  so the disable path was an INVALID BIND that threw before any cmdlet ran and aborted Lock-Sandbox.
#  FIX (retained): route the disable through `Disable-VMConsoleSupport` (KVM/console off, belt-and-
#  braces); ON is `Enable-VMConsoleSupport`. This part STANDS and is still asserted below.
#
#  The GET half was WRONG: the original GET keyed the three ESM facets (EnhancedSession /
#  Clipboard / Shares) off the WMI `Msvm_VirtualSystemSettingData.ConsoleMode` (`-ne 3` => ON). But
#  a LIVE diagnostic on a real Gen2 VM proved `Disable-VMConsoleSupport` does NOT change ConsoleMode
#  — it stays 0 (Default) both before AND after. So `ConsoleMode -ne 3` ALWAYS read TRUE => the three
#  ESM facets ALWAYS reported ON => Assert-Sealed could NEVER certify a real, correctly-sealed Linux
#  VM (the seal refused forever).
#
#  THE CORRECT LINUX-GUEST MODEL (what this harness now proves):
#    * GuestServices = the ONE real autonomous host<->guest data channel (Copy-VMFile). Its SET
#      (Disable-VMIntegrationService) and its host-truth READ (.Enabled, fail-closed) are UNCHANGED.
#    * EnhancedSession / Clipboard / Shares = ESM facets. There is no per-VM "ESM off" toggle and
#      ESM clipboard/drive-redirection needs Windows-guest components a stock Linux image lacks, so
#      they are not live autonomous channels on a Linux guest. SetHostChannel still runs the belt-
#      and-braces Disable-VMConsoleSupport (harmless, closes the interactive KVM surface, does NOT
#      break COM1 serial); GetHostChannels reports them OFF BY CONSTRUCTION — it no longer reads
#      ConsoleMode. The headline regression: the facets read OFF even at ConsoleMode=0.
#
#  WHY OUT-OF-PROCESS: same reason as the NewVHD/provision harnesses — the real backend's closures
#  resolve their Hyper-V cmdlets against the session captured at .GetNewClosure() time, not the test
#  scope, so an in-process Mock can't intercept (and can't reproduce the invalid-enum bind). The
#  harness shadows Disable/Enable-VMConsoleSupport, Set-VM (a STRICT stub that THROWS the
#  invalid-enum error if -EnhancedSessionTransportType is ever passed), Enable/Disable-VM-
#  IntegrationService, Get-VMIntegrationService (GSI read; can be made to throw), and Get-CimInstance
#  (a NON-flipping ConsoleMode source returning 0 — the live-host reality) at top level, then drives
#  the REAL SetHostChannel / GetHostChannels.
Describe 'Real backend — Linux-guest host-channel seal model (invalid-enum SET fix + ESM-facets-off-by-construction GET fix; out-of-process)' {

    BeforeAll {
        $script:ChHarnessPath = Join-Path $PSScriptRoot 'fixtures/Invoke-RealHostChannelCapture.ps1'
        Test-Path $script:ChHarnessPath | Should -BeTrue -Because 'the host-channel capture harness must exist'

        $pwsh = (Get-Process -Id $PID).Path
        if ([string]::IsNullOrWhiteSpace($pwsh)) { $pwsh = 'pwsh' }
        $raw = & $pwsh -NoProfile -File $script:ChHarnessPath -LibPath $script:LibPath 2>&1
        $rawText = ($raw | Out-String).Trim()
        $jsonLine = ($rawText -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
        $jsonLine | Should -Not -BeNullOrEmpty -Because "the harness must emit JSON; got: $rawText"
        $script:ChCap = $jsonLine | ConvertFrom-Json
    }

    # ---- SET (seal): the invalid-enum fix is retained -----------------------------------------
    It 'SetHostChannel EnhancedSession-disable does NOT throw the invalid-enum bind (the live seal abort)' {
        # Pre-fix this $.err is the "Cannot convert value 'None' to ... EnhancedSessionTransportType" bind error.
        $script:ChCap.SetEsmDisable.err | Should -BeNullOrEmpty -Because 'disabling ESM must not pass the nonexistent None enum to Set-VM; it must call Disable-VMConsoleSupport'
    }

    It 'SetHostChannel EnhancedSession-disable calls Disable-VMConsoleSupport (belt-and-braces; closes the interactive KVM surface)' {
        $script:ChCap.SetEsmDisable.disableConsoleCalled | Should -BeTrue -Because 'turning EnhancedSession OFF per-VM is Disable-VMConsoleSupport (KVM off) — kept as belt-and-braces, confirmed not to break COM1 serial'
        $script:ChCap.SetEsmDisable.consoleVMName        | Should -Be 'sbx-seal'
    }

    It 'SetHostChannel EnhancedSession-disable NEVER passes -EnhancedSessionTransportType to Set-VM (no invalid None)' {
        $script:ChCap.SetEsmDisable.setVmEsmTransportPassed | Should -BeFalse -Because 'the disable path must not touch Set-VM -EnhancedSessionTransportType at all (None is not a valid enum value)'
        $script:ChCap.SetEsmDisable.setVmEsmTransportValue  | Should -BeNullOrEmpty
    }

    It 'SetHostChannel EnhancedSession-ENABLE calls Enable-VMConsoleSupport (symmetric; never used by the Sealer but must be correct)' {
        $script:ChCap.SetEsmEnable.err                 | Should -BeNullOrEmpty
        $script:ChCap.SetEsmEnable.enableConsoleCalled | Should -BeTrue
        $script:ChCap.SetEsmEnable.disableConsoleCalled | Should -BeFalse
        $script:ChCap.SetEsmEnable.setVmEsmTransportPassed | Should -BeFalse -Because 'enable must use Enable-VMConsoleSupport, not Set-VM -EnhancedSessionTransportType HvSocket'
    }

    It 'SetHostChannel Clipboard-disable rides on ESM -> also routes through Disable-VMConsoleSupport (clipboard is an ESM facet)' {
        $script:ChCap.SetClipDisable.err                  | Should -BeNullOrEmpty
        $script:ChCap.SetClipDisable.disableConsoleCalled | Should -BeTrue -Because 'Clipboard/Shares are facets of Enhanced Session; turning Clipboard OFF runs the belt-and-braces Disable-VMConsoleSupport'
        $script:ChCap.SetClipDisable.setVmEsmTransportPassed | Should -BeFalse
    }

    It 'SetHostChannel GuestServices-disable routes through Disable-VMIntegrationService (the real autonomous channel — unchanged)' {
        $script:ChCap.SetGsiDisable.err              | Should -BeNullOrEmpty
        $script:ChCap.SetGsiDisable.disableGsiCalled | Should -BeTrue -Because 'GuestServices is the real Copy-VMFile channel; its SET stays Disable-VMIntegrationService'
        $script:ChCap.SetGsiDisable.disableConsoleCalled | Should -BeFalse -Because 'GuestServices does not ride on the console-support mechanism'
    }

    # ---- GET (gate): the ESM-facets fix — OFF BY CONSTRUCTION at ConsoleMode 0 ----------------
    It 'HEADLINE: GetHostChannels reports the ESM facets OFF even though ConsoleMode stays 0 (the read no longer depends on ConsoleMode flipping)' {
        # The live-debug bug: ConsoleMode does NOT flip with Disable-VMConsoleSupport (stays 0). The old
        # ConsoleMode-keyed read therefore reported these three ON forever and Assert-Sealed could never
        # certify. Post-fix the facets are reported off by construction — OFF here despite ConsoleMode=0.
        $script:ChCap.GetEsmFacetsAtConsoleMode0.err             | Should -BeNullOrEmpty
        $script:ChCap.GetEsmFacetsAtConsoleMode0.EnhancedSession | Should -BeFalse -Because 'EnhancedSession is off by construction on a Linux guest (no per-VM ESM-on signal; ConsoleMode never flips)'
        $script:ChCap.GetEsmFacetsAtConsoleMode0.Clipboard       | Should -BeFalse -Because 'Clipboard is an ESM facet — off by construction'
        $script:ChCap.GetEsmFacetsAtConsoleMode0.Shares          | Should -BeFalse -Because 'Shares is an ESM facet — off by construction'
    }

    It 'GuestServices reads ON independently when the integration service is enabled (the ESM-off is not just "everything off")' {
        # In the headline scenario the GSI integration service is ENABLED, so GuestServices must read ON —
        # proving the three ESM facets are reported off SPECIFICALLY (by construction), not because the
        # method blanket-reports every channel off.
        $script:ChCap.GetEsmFacetsAtConsoleMode0.GuestServices | Should -BeTrue -Because 'GuestServices is the one real channel and reads its true (.Enabled) host state — ON here'
    }

    It 'GuestServices reads OFF when the integration service is disabled (the one real channel flips with host truth)' {
        $script:ChCap.GetGsiOffAtConsoleMode0.err           | Should -BeNullOrEmpty
        $script:ChCap.GetGsiOffAtConsoleMode0.GuestServices | Should -BeFalse -Because 'a disabled Guest Service Interface reads off — the real channel genuinely flips'
        # The ESM facets stay off by construction regardless.
        $script:ChCap.GetGsiOffAtConsoleMode0.EnhancedSession | Should -BeFalse
    }

    It 'GetHostChannels RETHROWS when the GuestServices read fails (the one real channel is unreadable => fail closed)' {
        # The fail-closed guard, behaviorally: if the host cannot read the Guest Service Interface state,
        # GetHostChannels must propagate the error (never coerce to off) so Assert-Sealed refuses.
        $script:ChCap.GetGsiThrows.err | Should -Not -BeNullOrEmpty -Because 'an unreadable GuestServices channel must propagate so the gate fails closed'
        $script:ChCap.GetGsiThrows.ch  | Should -BeNullOrEmpty -Because 'no channel hashtable should be returned when the real channel read throws'
    }
}

# ===========================================================================
#  REAL backend — NO code path passes the literal 'None' to a typed Hyper-V
#  EnhancedSessionTransportType parameter (invalid-enum guard, AST-pinned)
# ===========================================================================
#  A focused source-level guard: the nonexistent `None` enum value must NOT appear as an argument to
#  `-EnhancedSessionTransportType` anywhere in the backend. Pinned via the AST so a future edit that
#  reintroduces the invalid bind is caught even if the out-of-process harness scenario is bypassed.
Describe 'Real backend — never binds the nonexistent EnhancedSessionTransportType None enum (AST-pinned)' {

    BeforeAll {
        $tokens = $null; $parseErrors = $null
        $script:LibAst3 = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:LibPath, [ref]$tokens, [ref]$parseErrors)
        @($parseErrors).Count | Should -Be 0 -Because 'the backend lib must parse cleanly to be analyzed'
    }

    It 'no CommandAst passes -EnhancedSessionTransportType with a None argument' {
        # Find every command invocation in the lib; for each, scan its parameter/argument pairs for a
        # -EnhancedSessionTransportType immediately followed by a (constant or variable) 'None'.
        $cmds = $script:LibAst3.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)

        $offending = @()
        foreach ($c in $cmds) {
            $els = $c.CommandElements
            for ($i = 0; $i -lt $els.Count - 1; $i++) {
                $el = $els[$i]
                if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and
                    $el.ParameterName -eq 'EnhancedSessionTransportType') {
                    # The argument is either glued onto the param (-Param:Arg) or the next element.
                    $arg = if ($null -ne $el.Argument) { $el.Argument } else { $els[$i + 1] }
                    if ($arg -and $arg.Extent.Text -match "(?i)['""]?None['""]?$") {
                        $offending += $c.Extent.Text
                    }
                }
            }
        }
        @($offending).Count | Should -Be 0 -Because "the EnhancedSessionTransportType enum has only VMBus/HvSocket — binding 'None' is the invalid bind that aborted the live seal. Offenders: $($offending -join ' | ')"
    }

    It 'the literal string "None" does not appear as an EnhancedSessionTransportType assignment value anywhere in the lib' {
        # Belt-and-suspenders: even an intermediate `$transport = if (...) { 'HvSocket' } else { 'None' }`
        # (the original buggy shape) must be gone — there is no valid reason to compute a 'None' transport.
        $libText = Get-Content -LiteralPath $script:LibPath -Raw
        $libText | Should -Not -Match "EnhancedSessionTransportType\s+'None'" -Because 'the disable path must use Disable-VMConsoleSupport, never an EnhancedSessionTransportType None'
        $libText | Should -Not -Match "EnhancedSessionTransportType\s+\`$transport" -Because 'the computed-transport indirection (which produced None) must be removed'
    }
}

# ===========================================================================
#  REAL ⇄ FAKE parity for GetDvdDrives — the host-truth DVD read
# ===========================================================================
#  The Sealer's gate (Assert-Sealed) must read DVD state from HOST TRUTH via this method, NOT
#  off the GetVM object. The FAKE carries a scalar .DvdDrive; a REAL Get-VM object has NO such
#  property — DVD state lives in the DVDDrives collection, read via Get-VMDvdDrive. The fake's
#  behavioral parity (attach -> 1, detach -> 0) is covered in 'Fake backend — disk operations';
#  here we STRUCTURALLY pin the REAL backend's GetDvdDrives so the two backends agree in SHAPE:
#  the real method must read via Get-VMDvdDrive (the real DVD-state source — never off Get-VM)
#  and must return a unary-comma-wrapped collection (matching the fake + the other collection
#  methods). The real backend's internals can't be behaviorally exercised in this non-elevated
#  session (see the file header), so we PIN it via the AST — the same technique used for the
#  GetHostChannels fail-closed guard above.
Describe 'GetDvdDrives — real⇄fake shape parity (host-truth DVD read; AST-pinned real backend)' {

    BeforeAll {
        $tokens = $null; $parseErrors = $null
        $script:LibAst2 = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:LibPath, [ref]$tokens, [ref]$parseErrors)
        @($parseErrors).Count | Should -Be 0 -Because 'the backend lib must parse cleanly to be analyzed'

        $script:RealFn2 = $script:LibAst2.FindAll({
            param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                      $n.Name -eq 'New-RealHyperVBackend'
        }, $true) | Select-Object -First 1
        $script:RealFn2 | Should -Not -BeNullOrEmpty

        # Locate the `$b.GetDvdDrives = { ... }` assignment in the real factory.
        $script:RealDvdAssign = $script:RealFn2.FindAll({
            param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                      $n.Left.Extent.Text -eq '$b.GetDvdDrives'
        }, $true) | Select-Object -First 1
    }

    It 'the manifest documents GetDvdDrives taking VMName (read of an existing VM)' {
        $script:ExpectedMethods.Keys | Should -Contain 'GetDvdDrives'
        @($script:ExpectedMethods['GetDvdDrives']) | Should -Contain 'VMName'
    }

    It 'both backends expose GetDvdDrives as a scriptblock' {
        (New-RealHyperVBackend)['GetDvdDrives'] | Should -BeOfType [scriptblock]
        (New-FakeHyperVBackend)['GetDvdDrives'] | Should -BeOfType [scriptblock]
    }

    It 'the REAL GetDvdDrives reads DVD state via Get-VMDvdDrive (the real DVD-state source) — NOT off the Get-VM object' {
        $script:RealDvdAssign | Should -Not -BeNullOrEmpty -Because 'the real factory must define GetDvdDrives'
        $body = $script:RealDvdAssign.Right.Extent.Text
        $body | Should -Match 'Get-VMDvdDrive' -Because 'real Hyper-V DVD state is read via Get-VMDvdDrive; a real Get-VM object has no DvdDrive property'
        $body | Should -Match '(?s)\.Path' -Because 'each DVD slot exposes its media path via .Path'
    }

    It 'the REAL GetDvdDrives returns a unary-comma-wrapped collection (array semantics parity)' {
        $body = $script:RealDvdAssign.Right.Extent.Text
        # The collection-return contract used by GetNetworkAdapter / GetCheckpoint: `return ,@(...)`.
        $body | Should -Match 'return\s*,@\(' -Because 'collection-returning methods must wrap with ,@(...) so a single element keeps .Count semantics'
    }

    It 'the REAL GetDvdDrives lives ONLY in the backend (no raw Get-VMDvdDrive CALL leaks into the Sealer)' {
        # Self-review guard: the new raw Hyper-V cmdlet must live in the REAL backend method only.
        # Pin the INVOCATION (a CommandAst whose command name is Get-VMDvdDrive), not a prose mention
        # — the Sealer's docstring/comments legitimately NAME the cmdlet to explain the host-truth read.
        $sealerPath = Join-Path $script:SkillRoot 'scripts/lib/Sealer.ps1'
        $sTokens = $null; $sErrors = $null
        $sealerAst = [System.Management.Automation.Language.Parser]::ParseFile($sealerPath, [ref]$sTokens, [ref]$sErrors)
        @($sErrors).Count | Should -Be 0 -Because 'the Sealer must parse cleanly'
        $dvdCalls = $sealerAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                      $n.GetCommandName() -like '*VMDvdDrive'
        }, $true)
        @($dvdCalls).Count | Should -Be 0 -Because 'the Sealer must reach DVD state through the backend seam, never invoke a raw *-VMDvdDrive cmdlet'
    }
}

# ===========================================================================
#  REAL ⇄ FAKE parity for GetComPort — the post-seal COM1-liveness read
# ===========================================================================
#  The post-seal COM1-liveness assertion (Assert-Sealed) reads the Runner's serial command channel
#  from HOST TRUTH via this method so the seal can be POSITIVELY verified to have NOT severed COM1.
#  The fake's behavioral parity (SetComPort -> read back; no port -> $null) is covered in
#  'Fake backend — hardware'; here we STRUCTURALLY pin the REAL backend's GetComPort so the two
#  backends agree in SHAPE: the real method must read via Get-VMComPort (the real COM-port source —
#  never off Get-VM) and return a @{ Number; Path } record (or $null). The real backend's internals
#  can't be behaviorally exercised in this non-elevated session (see the file header), so we PIN it
#  via the AST — the same technique used for the GetDvdDrives / GetHostChannels guards above.
Describe 'GetComPort — real⇄fake shape parity (host-truth COM1 read; AST-pinned real backend)' {

    BeforeAll {
        $tokens = $null; $parseErrors = $null
        $script:LibAst4 = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:LibPath, [ref]$tokens, [ref]$parseErrors)
        @($parseErrors).Count | Should -Be 0 -Because 'the backend lib must parse cleanly to be analyzed'

        $script:RealFn4 = $script:LibAst4.FindAll({
            param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                      $n.Name -eq 'New-RealHyperVBackend'
        }, $true) | Select-Object -First 1
        $script:RealFn4 | Should -Not -BeNullOrEmpty

        # Locate the `$b.GetComPort = { ... }` assignment in the real factory.
        $script:RealComAssign = $script:RealFn4.FindAll({
            param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                      $n.Left.Extent.Text -eq '$b.GetComPort'
        }, $true) | Select-Object -First 1
    }

    It 'the manifest documents GetComPort taking VMName + Number (read of an existing VM''s port)' {
        $script:ExpectedMethods.Keys | Should -Contain 'GetComPort'
        @($script:ExpectedMethods['GetComPort']) | Should -Contain 'VMName'
        @($script:ExpectedMethods['GetComPort']) | Should -Contain 'Number'
    }

    It 'both backends expose GetComPort as a scriptblock (interface parity)' {
        (New-RealHyperVBackend)['GetComPort'] | Should -BeOfType [scriptblock]
        (New-FakeHyperVBackend)['GetComPort'] | Should -BeOfType [scriptblock]
    }

    It 'the REAL GetComPort reads the port via Get-VMComPort (the real COM-port source) — NOT off the Get-VM object' {
        $script:RealComAssign | Should -Not -BeNullOrEmpty -Because 'the real factory must define GetComPort'
        $body = $script:RealComAssign.Right.Extent.Text
        $body | Should -Match 'Get-VMComPort' -Because 'real Hyper-V COM-port state is read via Get-VMComPort'
        $body | Should -Match '(?s)\.Path' -Because 'the COM port exposes its pipe path via .Path (an empty path = not live)'
    }

    It 'the REAL GetComPort returns $null for an unattached / empty-path port (matching the fake)' {
        # Both backends treat a port with no pipe path as "not live" ($null). Pin the real backend's
        # null-on-empty-path branch structurally so the two agree in shape.
        $body = $script:RealComAssign.Right.Extent.Text
        $body | Should -Match '(?s)IsNullOrWhiteSpace' -Because 'an empty COM-port path is not a live channel; the real read must return $null for it (parity with the fake)'
        $body | Should -Match '(?s)return\s+\$null' -Because 'the real GetComPort must return $null for an absent/empty port'
    }

    It 'the REAL GetComPort lives ONLY in the backend (no raw Get-VMComPort CALL leaks into the Sealer)' {
        # Self-review guard: the new raw Hyper-V cmdlet must live in the REAL backend method only.
        # Pin the INVOCATION (a CommandAst whose command name is Get-VMComPort), not a prose mention.
        $sealerPath = Join-Path $script:SkillRoot 'scripts/lib/Sealer.ps1'
        $sTokens = $null; $sErrors = $null
        $sealerAst = [System.Management.Automation.Language.Parser]::ParseFile($sealerPath, [ref]$sTokens, [ref]$sErrors)
        @($sErrors).Count | Should -Be 0 -Because 'the Sealer must parse cleanly'
        $comCalls = $sealerAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                      $n.GetCommandName() -like '*VMComPort'
        }, $true)
        @($comCalls).Count | Should -Be 0 -Because 'the Sealer must reach COM-port state through the backend seam, never invoke a raw *-VMComPort cmdlet'
    }
}

# ===========================================================================
#  FAKE backend — disks
# ===========================================================================
Describe 'Fake backend — disk operations' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
    }

    It 'NewVHD records a created disk (queryable via GetVHDInfo)' {
        & $script:B.NewVHD @{ Path = 'C:\vhd\a.vhdx'; SizeBytes = 40GB }
        $info = & $script:B.GetVHDInfo @{ Path = 'C:\vhd\a.vhdx' }
        $info | Should -Not -BeNullOrEmpty
        $info.Path | Should -Be 'C:\vhd\a.vhdx'
        $info.SizeBytes | Should -Be 40GB
        # a non-existent VHD returns nothing without throwing
        (& $script:B.GetVHDInfo @{ Path = 'C:\vhd\ghost.vhdx' }) | Should -BeNullOrEmpty
    }

    It 'NewVHD -Differencing -ParentPath records the parent linkage' {
        & $script:B.NewVHD @{ Path = 'C:\vhd\parent.vhdx'; SizeBytes = 40GB }
        & $script:B.NewVHD @{ Path = 'C:\vhd\child.vhdx'; Differencing = $true; ParentPath = 'C:\vhd\parent.vhdx' }
        $info = & $script:B.GetVHDInfo @{ Path = 'C:\vhd\child.vhdx' }
        $info.Differencing | Should -BeTrue
        $info.ParentPath   | Should -Be 'C:\vhd\parent.vhdx'
    }

    It 'fake NewOutputVhdx records a formatted disk readable by GetVHDInfo' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\out.vhdx'; Label='OUTPUT'; FileSystem='exFAT'; SizeBytes=64MB }
        $info = & $b.GetVHDInfo @{ Path='C:\t\out.vhdx' }
        $info | Should -Not -BeNullOrEmpty
        $info.Label | Should -Be 'OUTPUT'
        $info.FileSystem | Should -Be 'exFAT'
    }

    # ---- fake≠real divergence guard (shared FileSystem/Label validation) ----
    # A bad FileSystem or over-length Label is recorded VERBATIM by the fake (test green)
    # but FAILS live on Format-Volume. The shared validator makes the fake fail IDENTICALLY
    # and EARLY, closing the divergence.
    It 'NewOutputVhdx (fake) rejects an unsupported FileSystem identically to real' {
        $b = New-FakeHyperVBackend
        { & $b.NewOutputVhdx @{ Path='C:\t\x.vhdx'; Label='OUTPUT'; FileSystem='ext4'; SizeBytes=64MB } } |
            Should -Throw -ExpectedMessage '*FileSystem*'
    }
    It 'NewOutputVhdx (fake) rejects an over-length exFAT label (>15)' {
        $b = New-FakeHyperVBackend
        { & $b.NewOutputVhdx @{ Path='C:\t\y.vhdx'; Label='THIS_LABEL_IS_WAY_TOO_LONG'; FileSystem='exFAT'; SizeBytes=64MB } } |
            Should -Throw -ExpectedMessage '*abel*'
    }
    It 'NewOutputVhdx (fake) accepts a valid lowercase exfat (normalized)' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\z.vhdx'; Label='OUTPUT'; FileSystem='exfat'; SizeBytes=64MB }
        (& $b.GetVHDInfo @{ Path='C:\t\z.vhdx' }).FileSystem | Should -Be 'exFAT'
    }

    # ---- per-VHDX file populate/read (host writes a seed file onto a VHDX, reads results off) ----
    It 'fake WriteVhdxFile then ReadVhdxFile round-trips a file' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\in.vhdx'; Label='INPUT'; FileSystem='exFAT'; SizeBytes=64MB }
        & $b.WriteVhdxFile @{ Path='C:\t\in.vhdx'; InnerPath='sample.json'; Content='{"x":1}' }
        (& $b.ReadVhdxFile @{ Path='C:\t\in.vhdx'; InnerPath='sample.json' }) | Should -Be '{"x":1}'
    }
    It 'fake ReadVhdxFile returns $null for a missing inner file' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\o.vhdx'; Label='OUTPUT'; FileSystem='exFAT'; SizeBytes=64MB }
        (& $b.ReadVhdxFile @{ Path='C:\t\o.vhdx'; InnerPath='nope.txt' }) | Should -BeNullOrEmpty
    }
    It 'fake WriteVhdxFile throws for a VHD that does not exist' {
        $b = New-FakeHyperVBackend
        { & $b.WriteVhdxFile @{ Path='C:\t\ghost.vhdx'; InnerPath='a'; Content='b' } } | Should -Throw -ExpectedMessage '*does not exist*'
    }
    It 'manifest documents WriteVhdxFile and ReadVhdxFile' {
        $m = Get-HyperVBackendMethodManifest
        $m.Keys | Should -Contain 'WriteVhdxFile'
        $m.Keys | Should -Contain 'ReadVhdxFile'
    }

    It 'AddHardDiskDrive then RemoveHardDiskDrive adjusts the VM disk list' {
        & $script:B.NewVHD @{ Path = 'C:\vhd\d.vhdx'; SizeBytes = 40GB }
        & $script:B.AddHardDiskDrive @{ VMName = 'vm1'; Path = 'C:\vhd\d.vhdx' }
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        @($vm.HardDrives) | Should -Contain 'C:\vhd\d.vhdx'

        & $script:B.RemoveHardDiskDrive @{ VMName = 'vm1'; Path = 'C:\vhd\d.vhdx' }
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        @($vm.HardDrives) | Should -Not -Contain 'C:\vhd\d.vhdx'
    }

    It 'AddHardDiskDrive on a VHD that was NEVER created throws (real Add-VMHardDiskDrive requires the file to exist)' {
        # Fake≠real fidelity: real Hyper-V errors if the .vhdx path does not exist. The fake
        # must mirror that — otherwise the consumers attach a phantom disk and tests go false-green.
        { & $script:B.AddHardDiskDrive @{ VMName = 'vm1'; Path = 'C:\vhd\never-created.vhdx' } } |
            Should -Throw -ExpectedMessage '*never-created.vhdx*' -Because 'attaching a disk whose VHD was never created via NewVHD must fail, as real Hyper-V does'
        # And the phantom disk must NOT have been recorded on the VM.
        @((& $script:B.GetVM @{ Name = 'vm1' }).HardDrives) | Should -Not -Contain 'C:\vhd\never-created.vhdx'
    }

    It 'AddHardDiskDrive on a VHD that WAS created via NewVHD still works (happy path preserved)' {
        & $script:B.NewVHD @{ Path = 'C:\vhd\real.vhdx'; SizeBytes = 40GB }
        { & $script:B.AddHardDiskDrive @{ VMName = 'vm1'; Path = 'C:\vhd\real.vhdx' } } | Should -Not -Throw
        @((& $script:B.GetVM @{ Name = 'vm1' }).HardDrives) | Should -Contain 'C:\vhd\real.vhdx'
    }

    It 'SetDvdDrive attaches an ISO; RemoveDvdDrive detaches it' {
        & $script:B.SetDvdDrive @{ VMName = 'vm1'; Path = 'C:\iso\seed.iso' }
        (& $script:B.GetVM @{ Name = 'vm1' }).DvdDrive | Should -Be 'C:\iso\seed.iso'
        & $script:B.RemoveDvdDrive @{ VMName = 'vm1' }
        (& $script:B.GetVM @{ Name = 'vm1' }).DvdDrive | Should -BeNullOrEmpty
    }

    # ---- GetDvdDrives (host-truth DVD read the Sealer's gate routes through) ----
    # The fake records DVD state as a scalar (.DvdDrive); a REAL Get-VM object has NO DvdDrive
    # property (DVD state lives in the DVDDrives COLLECTION, read via Get-VMDvdDrive). So the
    # Sealer must read DVD state through THIS backend method (host-truth) rather than off the
    # GetVM object, and the method must return a COLLECTION of attached DVD paths on both backends.
    It 'GetDvdDrives returns an empty collection when no ISO is attached' {
        $dvds = & $script:B.GetDvdDrives @{ VMName = 'vm1' }
        $dvds.Count | Should -Be 0 -Because 'a VM with no media in its DVD slot has no attached DVD paths'
    }

    It 'GetDvdDrives returns the attached ISO path after SetDvdDrive (Count = 1)' {
        & $script:B.SetDvdDrive @{ VMName = 'vm1'; Path = 'C:\iso\seed.iso' }
        # Read DIRECTLY (no @() wrap) — the backend must preserve array semantics itself.
        $dvds = & $script:B.GetDvdDrives @{ VMName = 'vm1' }
        $dvds.Count | Should -Be 1 -Because 'one ISO in the DVD slot is one attached DVD path'
        $dvds[0] | Should -Be 'C:\iso\seed.iso'
    }

    It 'GetDvdDrives returns empty again after RemoveDvdDrive (the detach is host-visible)' {
        & $script:B.SetDvdDrive @{ VMName = 'vm1'; Path = 'C:\iso\seed.iso' }
        (& $script:B.GetDvdDrives @{ VMName = 'vm1' }).Count | Should -Be 1 -Because 'precondition: the ISO is attached'
        & $script:B.RemoveDvdDrive @{ VMName = 'vm1' }
        (& $script:B.GetDvdDrives @{ VMName = 'vm1' }).Count |
            Should -Be 0 -Because 'after the detach the host sees NO attached DVD — the gate''s authority'
    }

    It 'GetDvdDrives on a missing VM throws naming the VM (fail closed)' {
        { & $script:B.GetDvdDrives @{ VMName = 'ghost' } } | Should -Throw -ExpectedMessage '*ghost*'
    }

    # ---- RemoveVHD (the Reaper's explicit disk-cleanup step) ----
    It 'RemoveVHD drops the VHD record (the explicit cleanup RemoveVM does NOT do)' {
        & $script:B.NewVHD @{ Path = 'C:\vhd\del.vhdx'; SizeBytes = 40GB }
        (& $script:B.GetVHDInfo @{ Path = 'C:\vhd\del.vhdx' }) | Should -Not -BeNullOrEmpty -Because 'precondition: the disk exists'
        & $script:B.RemoveVHD @{ Path = 'C:\vhd\del.vhdx' }
        (& $script:B.GetVHDInfo @{ Path = 'C:\vhd\del.vhdx' }) | Should -BeNullOrEmpty -Because 'RemoveVHD must forget the disk record'
    }

    It 'RemoveVHD on an unknown path is an idempotent no-op (does not throw)' {
        { & $script:B.RemoveVHD @{ Path = 'C:\vhd\never.vhdx' } } |
            Should -Not -Throw -Because 'deleting an absent disk is a no-op, mirroring the real Test-Path guard'
    }
}

# ===========================================================================
#  FAKE backend — switch + network adapter (the seal seam)
# ===========================================================================
Describe 'Fake backend — switch + network adapter' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
    }

    It 'NewSwitch then GetSwitch returns it with the right type' {
        & $script:B.NewSwitch @{ Name = 'sw-int'; SwitchType = 'Internal' }
        $sw = & $script:B.GetSwitch @{ Name = 'sw-int' }
        $sw | Should -Not -BeNullOrEmpty
        $sw.SwitchType | Should -Be 'Internal'
    }

    It 'GetSwitch for an unknown switch returns nothing without throwing' {
        # Capture outside Should -Not -Throw (child-scope assignment caveat).
        $sw = & $script:B.GetSwitch @{ Name = 'ghost' }
        $sw | Should -BeNullOrEmpty
    }

    It 'ConnectNetworkAdapter adds a NIC bound to a switch; GetNetworkAdapter lists it' {
        & $script:B.NewSwitch @{ Name = 'sw-int'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-int' }
        # Read DIRECTLY (no @() wrap) — the backend preserves array semantics itself, so a
        # caller must not need a defensive wrap to get a correct .Count.
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm1' }
        $nics.Count | Should -Be 1
        $nics[0].SwitchName | Should -Be 'sw-int'
    }

    It 'ConnectNetworkAdapter to a switch that was NEVER created throws (real Connect-VMNetworkAdapter errors on an unknown switch)' {
        # Fake≠real fidelity: real Hyper-V errors when the named switch does not exist. The
        # fake must mirror that — otherwise the consumers "connect" to a phantom switch and the
        # network-isolation tier checks go false-green.
        { & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'never-created-switch' } } |
            Should -Throw -ExpectedMessage '*never-created-switch*' -Because 'connecting to a switch never created via NewSwitch must fail, as real Hyper-V does'
        # And no phantom NIC should have been recorded on the VM (direct read, no @() wrap).
        (& $script:B.GetNetworkAdapter @{ VMName = 'vm1' }).Count | Should -Be 0
    }

    It 'ConnectNetworkAdapter to a switch that WAS created via NewSwitch still works (happy path preserved)' {
        & $script:B.NewSwitch @{ Name = 'sw-ok'; SwitchType = 'Internal' }
        { & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-ok' } } | Should -Not -Throw
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm1' }
        $nics.Count | Should -Be 1
        $nics[0].SwitchName | Should -Be 'sw-ok'
    }

    It 'RemoveSwitch drops the switch record (GetSwitch then returns nothing)' {
        # The Provisioner''s mid-provision ROLLBACK deletes any vSwitch it created
        # so a failed provision leaves no orphaned switch. (Also usable by the Sealer.)
        & $script:B.NewSwitch @{ Name = 'sw-del'; SwitchType = 'Internal' }
        (& $script:B.GetSwitch @{ Name = 'sw-del' }) | Should -Not -BeNullOrEmpty -Because 'precondition: the switch exists'
        & $script:B.RemoveSwitch @{ Name = 'sw-del' }
        (& $script:B.GetSwitch @{ Name = 'sw-del' }) | Should -BeNullOrEmpty -Because 'RemoveSwitch must forget the switch record'
    }

    It 'RemoveSwitch on an unknown switch is an idempotent no-op (does not throw)' {
        { & $script:B.RemoveSwitch @{ Name = 'never-made-switch' } } |
            Should -Not -Throw -Because 'removing an absent switch is a no-op, mirroring a Test/Get guard'
    }

    It 'after RemoveNetworkAdapter, GetNetworkAdapter returns empty (the SEAL operation)' {
        & $script:B.NewSwitch @{ Name = 'sw-int'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-int' }
        # Direct read (no @() wrap): the backend's unary-comma return preserves array semantics.
        (& $script:B.GetNetworkAdapter @{ VMName = 'vm1' }).Count | Should -Be 1

        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        (& $script:B.GetNetworkAdapter @{ VMName = 'vm1' }).Count | Should -Be 0 -Because 'sealing a Tier2/3 VM removes all NICs; Assert-Sealed verifies this from the host'
    }
}

# ===========================================================================
#  FAKE backend — checkpoints (the golden-image + revert seam)
# ===========================================================================
Describe 'Fake backend — checkpoints' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
    }

    It 'Checkpoint then GetCheckpoint lists the snapshot' {
        & $script:B.Checkpoint @{ VMName = 'vm1'; SnapshotName = 'golden' }
        # Direct read (no @() wrap) — the backend preserves array semantics for a single item.
        $cps = & $script:B.GetCheckpoint @{ VMName = 'vm1' }
        $cps.Name | Should -Contain 'golden'
    }

    It 'Checkpoint then RestoreCheckpoint roundtrips VM state' {
        # Snapshot at Off, start the VM, restore -> back to the snapshot's Off state.
        & $script:B.Checkpoint @{ VMName = 'vm1'; SnapshotName = 'golden' }
        & $script:B.StartVM @{ Name = 'vm1' }
        (& $script:B.GetVM @{ Name = 'vm1' }).State | Should -Be 'Running'

        & $script:B.RestoreCheckpoint @{ VMName = 'vm1'; SnapshotName = 'golden' }
        (& $script:B.GetVM @{ Name = 'vm1' }).State | Should -Be 'Off' -Because 'restore returns the VM to the checkpointed state'
    }

    It 'RestoreCheckpoint also rolls back the network-adapter set captured at checkpoint time' {
        # Seal-then-revert correctness: a NIC removed after the checkpoint comes back on restore.
        & $script:B.NewSwitch @{ Name = 'sw-int'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-int' }
        & $script:B.Checkpoint @{ VMName = 'vm1'; SnapshotName = 'with-nic' }

        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        (& $script:B.GetNetworkAdapter @{ VMName = 'vm1' }).Count | Should -Be 0

        & $script:B.RestoreCheckpoint @{ VMName = 'vm1'; SnapshotName = 'with-nic' }
        (& $script:B.GetNetworkAdapter @{ VMName = 'vm1' }).Count | Should -Be 1 -Because 'the checkpoint captured the NIC; restore brings it back'
    }

    It 'RemoveCheckpoint deletes the named snapshot' {
        & $script:B.Checkpoint @{ VMName = 'vm1'; SnapshotName = 'golden' }
        & $script:B.RemoveCheckpoint @{ VMName = 'vm1'; SnapshotName = 'golden' }
        (& $script:B.GetCheckpoint @{ VMName = 'vm1' }).Count | Should -Be 0
    }

    It 'RestoreCheckpoint for an unknown snapshot throws (caller passed a bad name)' {
        { & $script:B.RestoreCheckpoint @{ VMName = 'vm1'; SnapshotName = 'ghost' } } |
            Should -Throw -ExpectedMessage '*ghost*'
    }
}

# ===========================================================================
#  FAKE backend — collection-returning methods keep array semantics
# ===========================================================================
#  A scriptblock that returns @(<one item>) unrolls the wrapper on output, handing
#  the CALLER a bare element (e.g. a single NIC hashtable) whose .Count reflects the
#  hashtable's KEY count, not "1 NIC". Callers in the consumers will check `.Count` on these
#  results WITHOUT defensively wrapping in @(). The fix (return ,@(...)) makes a single-
#  element result stay an array. These tests assign the result DIRECTLY (no @() at the
#  call site) so they fail loudly if the unary-comma wrap is ever dropped.
Describe 'Fake backend — collection returns survive single-element unrolling' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
    }

    It 'GetNetworkAdapter returns an array with .Count = 1 for a single NIC (no caller @() wrap)' {
        & $script:B.NewSwitch @{ Name = 'sw-int'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-int' }
        # NB: NO @() around the call — the backend must preserve array semantics itself.
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm1' }
        $nics.Count | Should -Be 1 -Because 'a single NIC must report Count 1, not the hashtable key-count, to a caller that does not wrap in @()'
        $nics[0].SwitchName | Should -Be 'sw-int'
        ,$nics | Should -BeOfType [System.Array] -Because 'the backend wraps collection returns in a unary-comma array'
    }

    It 'GetNetworkAdapter returns an empty array (.Count = 0) when the VM has no NIC (no caller @() wrap)' {
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm1' }
        $nics.Count | Should -Be 0
    }

    It 'GetNetworkAdapter reports the right Count for multiple NICs (no caller @() wrap)' {
        & $script:B.NewSwitch @{ Name = 'sw-a'; SwitchType = 'Internal' }
        & $script:B.NewSwitch @{ Name = 'sw-b'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-a' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-b' }
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm1' }
        $nics.Count | Should -Be 2
    }

    It 'GetCheckpoint returns an array with .Count = 1 for a single checkpoint (no caller @() wrap)' {
        & $script:B.Checkpoint @{ VMName = 'vm1'; SnapshotName = 'golden' }
        # NO @() around the call.
        $cps = & $script:B.GetCheckpoint @{ VMName = 'vm1' }
        $cps.Count | Should -Be 1 -Because 'a single checkpoint must report Count 1 to a caller that does not wrap in @()'
        $cps[0].Name | Should -Be 'golden'
        ,$cps | Should -BeOfType [System.Array] -Because 'the backend wraps collection returns in a unary-comma array'
    }

    It 'GetCheckpoint returns an empty array (.Count = 0) when the VM has no checkpoints (no caller @() wrap)' {
        $cps = & $script:B.GetCheckpoint @{ VMName = 'vm1' }
        $cps.Count | Should -Be 0
    }

    It 'GetDvdDrives returns an array with .Count = 1 for a single attached ISO (no caller @() wrap)' {
        & $script:B.SetDvdDrive @{ VMName = 'vm1'; Path = 'C:\iso\seed.iso' }
        # NO @() around the call — the backend must preserve array semantics itself.
        $dvds = & $script:B.GetDvdDrives @{ VMName = 'vm1' }
        $dvds.Count | Should -Be 1 -Because 'a single attached DVD must report Count 1 to a caller that does not wrap in @()'
        $dvds[0] | Should -Be 'C:\iso\seed.iso'
        ,$dvds | Should -BeOfType [System.Array] -Because 'the backend wraps collection returns in a unary-comma array'
    }

    It 'GetDvdDrives returns an empty array (.Count = 0) when the VM has no DVD (no caller @() wrap)' {
        $dvds = & $script:B.GetDvdDrives @{ VMName = 'vm1' }
        $dvds.Count | Should -Be 0
    }
}

# ===========================================================================
#  Fake operations on a missing VM fail closed (so the consumers surface caller bugs)
# ===========================================================================
Describe 'Fake backend — operations on a missing VM throw clearly' {

    BeforeEach { $script:B = New-FakeHyperVBackend }

    It 'SetProcessor on a non-existent VM throws naming the VM' {
        { & $script:B.SetProcessor @{ VMName = 'ghost'; Count = 2 } } | Should -Throw -ExpectedMessage '*ghost*'
    }

    It 'StartVM on a non-existent VM throws naming the VM' {
        { & $script:B.StartVM @{ Name = 'ghost' } } | Should -Throw -ExpectedMessage '*ghost*'
    }
}

# ===========================================================================
#  REAL backend — fail-closed classification (surface only; no live VM created)
# ===========================================================================
Describe 'Real backend — fails closed with a clear, actionable message' {

    BeforeEach { $script:Real = New-RealHyperVBackend }

    It 'GetVM surfaces the permission error wrapped in the clear fail-closed message' {
        # In this non-elevated session this WILL hit the permission path. If somehow
        # elevated, GetVM returns (no VM named this) without throwing — both are fine.
        $probe = & $script:Real.TestAvailable @{}
        if (-not $probe.Available) {
            { & $script:Real.GetVM @{ Name = 'definitely-not-a-real-vm-xyz' } } |
                Should -Throw -ExpectedMessage '*Hyper-V unavailable or insufficient privilege*'
        }
        else {
            Set-ItResult -Skipped -Because 'session is elevated/permitted; the fail-closed branch is not reachable here'
        }
    }

    It 'NewVM surfaces the same clear fail-closed message (not a raw cmdlet error)' {
        $probe = & $script:Real.TestAvailable @{}
        if (-not $probe.Available) {
            { & $script:Real.NewVM @{ Name = 'should-never-be-created-xyz'; Generation = 2 } } |
                Should -Throw -ExpectedMessage '*insufficient privilege*'
        }
        else {
            Set-ItResult -Skipped -Because 'session is elevated; would actually create a VM, which the test must not do'
        }
    }

    It 'the fail-closed message names the remediation (elevation / Hyper-V Administrators)' {
        $probe = & $script:Real.TestAvailable @{}
        if (-not $probe.Available) {
            $msg = $null
            try { & $script:Real.GetVM @{ Name = 'x-nope' } } catch { $msg = $_.Exception.Message }
            $msg | Should -Match '(?i)elevat'
            $msg | Should -Match '(?i)Hyper-V Administrators'
        }
        else {
            Set-ItResult -Skipped -Because 'fail-closed branch not reachable when permitted'
        }
    }
}

# ===========================================================================
#  REAL backend — SetFirmware Secure Boot template-enumeration retry (RC5)
# ===========================================================================
#  RC5 (2026-06-24 live): after ~10 rapid create/destroy cycles, Hyper-V's vmms wedged its Secure
#  Boot template enumeration — `Set-VMFirmware -SecureBootTemplate <any>` failed
#  "... matches none of the secure boot templates ..." for EVERY template, and a `Restart-Service
#  vmms` did NOT clear it (needed a host reboot). The real SetFirmware must (a) RETRY the transient
#  enumeration error a few times with a short sleep, and (b) if it still fails, throw a CLEAR
#  actionable error naming the remediation (restart vmms / reboot the host) rather than leave a
#  half-provisioned VM behind.
#
#  The retry/clear-error logic is factored into the shared helper scriptblock
#  $script:SbInvokeFirmwareWithRetry so it is UNIT-testable in-process (drive it with a scriptblock
#  that throws the enumeration error N times) WITHOUT a live Hyper-V or the out-of-process harness —
#  exactly the path the real SetFirmware uses. The FAKE SetFirmware does not use it (it just records),
#  so fake≠real parity is unaffected (manifest + arg shape unchanged).
Describe 'Real backend — SetFirmware retries the transient Secure Boot template-enumeration wedge (RC5)' {

    It 'exposes the shared firmware-retry helper scriptblock' {
        $script:SbInvokeFirmwareWithRetry | Should -BeOfType [scriptblock] -Because 'the real SetFirmware factors its retry through this shared helper so it is unit-testable'
    }

    It 'SUCCEEDS without retry when the operation succeeds first try' {
        $calls = 0
        $op = { $script:fwCalls++ }
        $script:fwCalls = 0
        # MaxAttempts/DelayMs kept tiny so the test is instant.
        { & $script:SbInvokeFirmwareWithRetry -Operation { $script:fwCalls++ } -MaxAttempts 4 -DelayMilliseconds 1 } | Should -Not -Throw
        $script:fwCalls | Should -Be 1 -Because 'a first-try success must not retry'
    }

    It 'RETRIES the transient "matches none of the secure boot templates" error and then succeeds' {
        $script:fwCalls = 0
        $op = {
            $script:fwCalls++
            if ($script:fwCalls -lt 3) { throw "'MicrosoftUEFICertificateAuthority' matches none of the secure boot templates known to the host." }
            # third attempt succeeds
        }
        { & $script:SbInvokeFirmwareWithRetry -Operation $op -MaxAttempts 4 -DelayMilliseconds 1 } | Should -Not -Throw
        $script:fwCalls | Should -Be 3 -Because 'it must keep retrying the transient enumeration error until it succeeds'
    }

    It 'after exhausting retries on the enumeration error, throws an ACTIONABLE message (restart vmms / reboot host)' {
        $script:fwCalls = 0
        $op = { $script:fwCalls++; throw "'MicrosoftWindows' matches none of the secure boot templates known to the host." }
        $msg = $null
        try { & $script:SbInvokeFirmwareWithRetry -Operation $op -MaxAttempts 3 -DelayMilliseconds 1 } catch { $msg = $_.Exception.Message }
        $script:fwCalls | Should -Be 3 -Because 'all attempts must be spent before failing'
        $msg | Should -Not -BeNullOrEmpty
        $msg | Should -Match '(?i)secure boot template' -Because 'the message must name the failing condition'
        $msg | Should -Match '(?i)vmms'   -Because 'the operator remediation is to restart the vmms service'
        $msg | Should -Match '(?i)reboot' -Because 'and, if that does not help, reboot the host'
    }

    It 'does NOT retry an UNRELATED error — it rethrows immediately (no masking real failures)' {
        $script:fwCalls = 0
        $op = { $script:fwCalls++; throw 'some other firmware failure (not the enumeration wedge)' }
        { & $script:SbInvokeFirmwareWithRetry -Operation $op -MaxAttempts 5 -DelayMilliseconds 1 } |
            Should -Throw -ExpectedMessage '*some other firmware failure*'
        $script:fwCalls | Should -Be 1 -Because 'an unrelated error is not transient; retrying would only waste time and hide the real cause'
    }
}

# ===========================================================================
#  REAL backend — builds the right cmdlet params (out-of-process capture)
# ===========================================================================
#  THE BEHAVIORAL REGRESSION TEST FOR A REAL-BACKEND BUG FOUND DURING LIVE DEBUGGING.
#
#  A live Hyper-V boot (`Invoke-Voidseal -Tier 0 -Profile firefox -ParentDiskPath
#  <golden>.vhdx`) aborted at INIT with:
#      "HyperVBackend.NewVHD: required argument 'SizeBytes' is missing."
#  on the DIFFERENCING branch (golden parent -> differencing child), even though the
#  Provisioner correctly passed `@{ Path=<child>; Differencing=$true; ParentPath=<golden> }`
#  with NO SizeBytes (correct for a differencing disk).
#
#  ROOT CAUSE: the real NewVHD read its $P-derived args (Differencing / ParentPath / SizeBytes
#  / Dynamic) INSIDE the `& $InvokeOp { ... }` scriptblock. That inner block is a PLAIN
#  scriptblock run via `& $Operation` from $InvokeOp's frame; its cross-frame dynamic lookup of
#  `$GetArg`/`$P` as an `if` condition (with a trailing emitting `New-VHD @p` statement) misfired,
#  so `if (& $GetArg $P 'Differencing')` evaluated FALSEY and took the ELSE branch — which
#  asserts SizeBytes and threw. The SAME latent pattern lived in every real method that read $P
#  inside its InvokeOp block: NewVM, StopVM, RemoveVM, SetProcessor, SetMemory, SetFirmware,
#  NewVHD, NewSwitch. The FIX hoists every $P / $GetArg / $AssertArg read into method-body locals
#  BEFORE entering $InvokeOp, so the inner block references only plain locals.
#
#  WHY OUT-OF-PROCESS: the in-process mock suite could not catch this — the real
#  backend's methods are .GetNewClosure() scriptblocks that resolve their Hyper-V cmdlets against
#  the SESSION STATE captured when New-RealHyperVBackend ran. A shadow `function` / Pester `Mock`
#  installed in a TEST scope is NOT on that closure's resolution path (verified: both are bypassed
#  and the real cmdlet runs, hitting the permission wall on this non-elevated host). The ONLY
#  reliable interception is to define the shadow stub AND dot-source the lib in the SAME top-level
#  script scope. The harness tests/fixtures/Invoke-RealBackendCapture.ps1 does exactly that and
#  emits the recorded param set as JSON; we run it in a child `pwsh` here and assert on the result.
#  This RUNS the real method body's param-building logic with NO live Hyper-V and NO elevation —
#  it is the test that WOULD have caught the live bug. (Proven: against the pre-fix backend the
#  harness reports NewVHD_Diff err = "required argument 'SizeBytes' is missing"; against the fixed
#  backend err is null and the param set is correct.)
Describe 'Real backend — builds the right cmdlet params (out-of-process; live-debug regression)' {

    BeforeAll {
        $script:HarnessPath = Join-Path $PSScriptRoot 'fixtures/Invoke-RealBackendCapture.ps1'
        Test-Path $script:HarnessPath | Should -BeTrue -Because 'the out-of-process capture harness must exist'

        # Run the harness in a fresh child pwsh: top-level shadow stubs + dot-source means the real
        # backend's closures resolve New-VHD / New-VM / New-VMSwitch / Set-VMProcessor to the stubs,
        # so the real param-building logic runs without touching Hyper-V. Capture the JSON.
        $pwsh = (Get-Process -Id $PID).Path   # the exact pwsh running these tests
        if ([string]::IsNullOrWhiteSpace($pwsh)) { $pwsh = 'pwsh' }
        $raw = & $pwsh -NoProfile -File $script:HarnessPath -LibPath $script:LibPath 2>&1
        $rawText = ($raw | Out-String).Trim()
        # The harness emits a single JSON line; isolate it (defend against any stray stderr text).
        $jsonLine = ($rawText -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
        $jsonLine | Should -Not -BeNullOrEmpty -Because "the harness must emit JSON; got: $rawText"
        $script:Cap = $jsonLine | ConvertFrom-Json
    }

    # ---- NewVHD: THE headline regression --------------------------------------------------
    It 'NewVHD differencing call does NOT throw "SizeBytes is missing" (the live INIT failure)' {
        # Pre-fix this $.err is "HyperVBackend.NewVHD: required argument 'SizeBytes' is missing.".
        $script:Cap.NewVHD_Diff.err | Should -BeNullOrEmpty -Because 'a differencing child must not require SizeBytes; the in-InvokeOp $P-read bug threw it'
    }

    It 'NewVHD differencing call builds -Differencing + -ParentPath and OMITS -SizeBytes' {
        $cap = $script:Cap.NewVHD_Diff.cap
        $cap | Should -Not -BeNullOrEmpty -Because 'the real NewVHD must reach New-VHD (shadowed) — not throw before it'
        $cap.Differencing   | Should -BeTrue
        $cap.ParentPath     | Should -Be 'C:\sandbox\golden\debian-12-cloud.vhdx'
        $cap.SizeBytesGiven | Should -BeFalse -Because 'a differencing child inherits size from its parent; passing -SizeBytes is wrong'
    }

    It 'NewVHD fresh (non-differencing) call builds -SizeBytes + -Dynamic and OMITS -Differencing' {
        $cap = $script:Cap.NewVHD_Fresh.cap
        $script:Cap.NewVHD_Fresh.err | Should -BeNullOrEmpty
        $cap.SizeBytesGiven | Should -BeTrue
        $cap.SizeBytes      | Should -Be 42949672960
        $cap.Dynamic        | Should -BeTrue
        $cap.Fixed          | Should -BeFalse
        $cap.Differencing   | Should -BeFalse -Because 'a fresh sized disk is not a differencing disk'
    }

    It 'NewVHD fresh call with Dynamic=$false builds -Fixed instead of -Dynamic' {
        $cap = $script:Cap.NewVHD_Fixed.cap
        $script:Cap.NewVHD_Fixed.err | Should -BeNullOrEmpty
        $cap.Fixed   | Should -BeTrue
        $cap.Dynamic | Should -BeFalse
    }

    # ---- The other formerly-buggy methods (same in-InvokeOp $P-read pattern) --------------
    It 'NewVM passes through its optional $P-derived args (Generation / Memory / Switch / NoVHD)' {
        $script:Cap.NewVM.err | Should -BeNullOrEmpty
        $cap = $script:Cap.NewVM.cap
        $cap.GenerationGiven    | Should -BeTrue
        $cap.Generation         | Should -Be 2
        $cap.MemoryGiven        | Should -BeTrue
        $cap.MemoryStartupBytes | Should -Be 4294967296
        $cap.SwitchName         | Should -Be 'sw0'
        $cap.NoVHD              | Should -BeTrue
    }

    It 'NewSwitch External branch resolves NetAdapterName (an in-InvokeOp $P read in the original)' {
        $script:Cap.NewSwitch_Ext.err | Should -BeNullOrEmpty
        $cap = $script:Cap.NewSwitch_Ext.cap
        $cap.NetAdapterGiven | Should -BeTrue
        $cap.NetAdapterName  | Should -Be 'Ethernet0'
    }

    It 'NewSwitch Internal branch builds -SwitchType (no NetAdapterName needed)' {
        $script:Cap.NewSwitch_Int.err | Should -BeNullOrEmpty
        $cap = $script:Cap.NewSwitch_Int.cap
        $cap.SwitchTypeGiven | Should -BeTrue
        $cap.SwitchType      | Should -Be 'Internal'
    }

    It 'SetProcessor passes through Count + ExposeVirtualizationExtensions (in-InvokeOp $P reads)' {
        $script:Cap.SetProcessor.err | Should -BeNullOrEmpty
        $cap = $script:Cap.SetProcessor.cap
        $cap.CountGiven  | Should -BeTrue
        $cap.Count       | Should -Be 2
        $cap.ExposeGiven | Should -BeTrue
        $cap.Expose      | Should -BeTrue
    }
}
