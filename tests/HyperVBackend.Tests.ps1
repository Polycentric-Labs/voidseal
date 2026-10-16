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

    # AST helper shared by the Describes that pin a REAL backend method body (RemoveNetworkAdapter and the
    # passthrough reads): `& $script:GetRealBackendAssign 'Method'` returns the AssignmentStatementAst of
    # `$b.<Method> = { ... }` inside New-RealHyperVBackend, or $null when the factory defines no such method.
    $helperTokens = $null; $helperErrors = $null
    $helperAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:LibPath, [ref]$helperTokens, [ref]$helperErrors)
    @($helperErrors).Count | Should -Be 0 -Because 'the backend lib must parse cleanly to be analyzed'
    $script:RealFactoryAst = $helperAst.FindAll({
        param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                  $n.Name -eq 'New-RealHyperVBackend'
    }, $true) | Select-Object -First 1
    $script:RealFactoryAst | Should -Not -BeNullOrEmpty -Because 'the backend lib must define New-RealHyperVBackend'
    $script:GetRealBackendAssign = {
        param([string] $Method)
        return $script:RealFactoryAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                      $n.Left.Extent.Text -eq ('$b.' + $Method)
        }, $true) | Select-Object -First 1
    }

    # AST pin helpers: each returns the matching NODES under an AST, so a pin built on one is satisfied
    # only by real code, never by a comment or a string that names the call. 'AST pin helpers' below
    # proves each one rejects a commented-out or quoted call.
    #   PinFindCommand     <ast> <command> [<param>]  CommandAst invoking <command>, with -<param> when given
    #   PinFindPipedInto   <ast> <command>            CommandAst for <command> fed by an upstream pipeline element
    #   PinFindCountGuard  <ast>                      BinaryExpressionAst `<x>.Count -gt 0`
    #   PinFindCommaReturn <ast>                      ReturnStatementAst returning `,@(...)`
    $script:PinFindCommand = {
        param($Ast, [string] $Command, [string] $Param)
        @($Ast.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $Command
        }, $true) | Where-Object {
            [string]::IsNullOrEmpty($Param) -or @($_.CommandElements | Where-Object {
                $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq $Param }).Count -gt 0
        })
    }
    $script:PinFindPipedInto = {
        param($Ast, [string] $Command)
        @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.PipelineAst] }, $true) | ForEach-Object {
            $els = @($_.PipelineElements)
            for ($i = 1; $i -lt $els.Count; $i++) {
                if ($els[$i] -is [System.Management.Automation.Language.CommandAst] -and $els[$i].GetCommandName() -eq $Command) { $els[$i] }
            }
        })
    }
    $script:PinFindCountGuard = {
        param($Ast)
        @($Ast.FindAll({
            param($n) $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and
                      $n.Operator -eq [System.Management.Automation.Language.TokenKind]::Igt -and
                      $n.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and
                      $n.Left.Member.Extent.Text -eq 'Count' -and
                      $n.Right -is [System.Management.Automation.Language.ConstantExpressionAst] -and
                      $n.Right.Value -eq 0
        }, $true))
    }
    $script:PinFindCommaReturn = {
        param($Ast)
        @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ReturnStatementAst] -and $null -ne $n.Pipeline }, $true) |
            Where-Object {
                # `,@(...)` parses as a one-element ArrayLiteralAst wrapping an ArrayExpressionAst.
                $null -ne $_.Pipeline.Find({
                    param($m) $m -is [System.Management.Automation.Language.ArrayLiteralAst] -and
                              @($m.Elements).Count -eq 1 -and
                              $m.Elements[0] -is [System.Management.Automation.Language.ArrayExpressionAst]
                }, $true)
            })
    }
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
            'SetProcessor', 'SetMemory', 'SetFirmware', 'SetAutomaticCheckpoints', 'GetAutomaticCheckpoints', 'SetComPort', 'GetComPort'
            # host resource read (the free-RAM gate)
            'GetHostMemory'
            # guest command delivery (the Runner serial seam)
            'InvokeGuestCommand'
            # host channels (the seal surface)
            'SetHostChannel', 'GetHostChannels'
            # disk
            'NewVHD', 'NewOutputVhdx', 'WriteVhdxFile', 'ReadVhdxFile', 'WriteVhdxFileBytes', 'ReadVhdxFileBytes', 'ReadVhdxRawRegion', 'GetVhdxImageHash', 'GetVHDInfo', 'RemoveVHD', 'AddHardDiskDrive', 'RemoveHardDiskDrive', 'SetDvdDrive', 'RemoveDvdDrive', 'GetDvdDrives'
            # switch / network
            'NewSwitch', 'GetSwitch', 'RemoveSwitch', 'ConnectNetworkAdapter', 'RemoveNetworkAdapter', 'GetNetworkAdapter'
            # adapter guards (the Tier-1 seal sets them, the gate reads them back)
            'SetNetworkAdapterGuards', 'GetNetworkAdapterGuards'
            # passthrough devices (the seal gate's passthrough refusal)
            'GetGpuPartitionAdapters', 'GetAssignableDevices'
            # checkpoint
            'Checkpoint', 'RestoreCheckpoint', 'GetCheckpoint', 'RemoveCheckpoint'
        )
        foreach ($m in $required) {
            $script:ExpectedMethods.Keys | Should -Contain $m -Because "the consumers rely on backend.$m so they never call a raw Hyper-V cmdlet"
        }
    }

    It 'documents a non-empty arg-key list for every method that takes args (only TestAvailable, GetHostMemory, GetHostIPAddresses, GetNetNats and GetHostFirewallProfiles are arg-less)' {
        # Arg-key drift guard: if a method silently grew/lost args, this catches the
        # manifest going stale. TestAvailable (the capability probe) and GetHostMemory (a whole-host
        # read) are the documented arg-less methods (@()).
        foreach ($name in $script:ExpectedMethods.Keys) {
            $argKeys = @($script:ExpectedMethods[$name])
            if ($name -in @('TestAvailable', 'GetHostMemory', 'GetHostIPAddresses', 'GetNetNats', 'GetHostFirewallProfiles')) {
                $argKeys.Count | Should -Be 0 -Because "$name takes no named args"
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

    It 'manifest documents ReadVhdxRawRegion with Path + Offset + Length' {
        $m = Get-HyperVBackendMethodManifest
        $m.Contains('ReadVhdxRawRegion') | Should -BeTrue
        $m['ReadVhdxRawRegion'] | Should -Be @('Path','Offset','Length')
    }

    It 'manifest documents GetVhdxImageHash with Path' {
        $m = Get-HyperVBackendMethodManifest
        $m.Contains('GetVhdxImageHash') | Should -BeTrue
        $m['GetVhdxImageHash'] | Should -Be @('Path')
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
            SetProcessor = 'VMName'; SetMemory = 'VMName'; SetFirmware = 'VMName'; SetAutomaticCheckpoints = 'VMName'; GetAutomaticCheckpoints = 'VMName'; SetComPort = 'VMName'; GetComPort = 'VMName'
            InvokeGuestCommand = 'VMName'
            SetHostChannel = 'VMName'; GetHostChannels = 'VMName'
            NewVHD = 'Path'; NewOutputVhdx = 'Path'; WriteVhdxFile = 'Path'; ReadVhdxFile = 'Path'; WriteVhdxFileBytes = 'Path'; ReadVhdxFileBytes = 'Path'; ReadVhdxRawRegion = 'Path'; GetVhdxImageHash = 'Path'; GetVHDInfo = 'Path'; RemoveVHD = 'Path'; GetVolumeFreeSpace = 'Path'
            CopyDirectoryToVhdx = 'Path'; CopyVhdxFile = 'Path'; MoveVhdxFile = 'Path'
            AddHardDiskDrive = 'VMName'; RemoveHardDiskDrive = 'VMName'; SetDvdDrive = 'VMName'; RemoveDvdDrive = 'VMName'; GetDvdDrives = 'VMName'
            NewSwitch = 'Name'; GetSwitch = 'Name'; RemoveSwitch = 'Name'
            ConnectNetworkAdapter = 'VMName'; RemoveNetworkAdapter = 'VMName'; GetNetworkAdapter = 'VMName'
            SetNetworkAdapterGuards = 'VMName'; GetNetworkAdapterGuards = 'VMName'
            GetGpuPartitionAdapters = 'VMName'; GetAssignableDevices = 'VMName'
            AddSwitchHostIPAddress = 'SwitchName'; RemoveSwitchHostIPAddress = 'SwitchName'
            NewHostFirewallRule = 'Name'; GetHostFirewallRule = 'Name'; RemoveHostFirewallRule = 'Name'; GetHostFirewallRuleNames = 'NamePrefix'
            AddNetworkAdapterAcl = 'VMName'; GetNetworkAdapterAcls = 'VMName'; RemoveNetworkAdapterAcl = 'VMName'
            GetNetIPInterfaceForwarding = 'InterfaceAlias'
            StartEgressProxy = 'PythonExe'; StopEgressProxy = 'ProcessId'
            Checkpoint = 'VMName'; RestoreCheckpoint = 'VMName'; GetCheckpoint = 'VMName'; RemoveCheckpoint = 'VMName'
        }

        # Sanity: the map covers exactly the arg-taking manifest methods (so a NEW
        # method added to the manifest forces this map, and thus the contract, to update).
        # TestAvailable and GetHostMemory are arg-less, so they have no primary key to drop.
        $covered  = @($primaryKey.Keys | Sort-Object)
        $expected = @($script:ExpectedMethods.Keys | Where-Object { $_ -notin @('TestAvailable', 'GetHostMemory', 'GetHostIPAddresses', 'GetNetNats', 'GetHostFirewallProfiles') } | Sort-Object)
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

    It 'StopVM ends in Off with or without TurnOff, and logs both flags and the state it stopped from' {
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
        & $script:B.StartVM @{ Name = 'vm1' }
        & $script:B.StopVM @{ Name = 'vm1'; Force = $true }
        (& $script:B.GetVM @{ Name = 'vm1' }).State | Should -Be 'Off'
        & $script:B.StartVM @{ Name = 'vm1' }
        & $script:B.StopVM @{ Name = 'vm1'; TurnOff = $true; Force = $true }
        (& $script:B.GetVM @{ Name = 'vm1' }).State | Should -Be 'Off'
        $stops = @($script:B.FakeCallLog | Where-Object { $_.Op -eq 'StopVM' })
        $stops.Count | Should -Be 2
        $stops[0].TurnOff | Should -BeFalse
        $stops[0].Force   | Should -BeTrue
        $stops[1].TurnOff | Should -BeTrue
        $stops[1].FromState | Should -Be 'Running'
    }

    It '-SimulateStateAfterStart leaves a started VM Paused or Saved (a pause or save made outside the tool)' {
        foreach ($s in 'Paused', 'Saved') {
            $b = New-FakeHyperVBackend -SimulateStateAfterStart $s
            & $b.NewVM @{ Name = 'vm1'; Generation = 2 }
            & $b.StartVM @{ Name = 'vm1' }
            (& $b.GetVM @{ Name = 'vm1' }).State | Should -Be $s
            & $b.StopVM @{ Name = 'vm1'; TurnOff = $true }
            (& $b.GetVM @{ Name = 'vm1' }).State | Should -Be 'Off'
        }
        { New-FakeHyperVBackend -SimulateStateAfterStart 'Hibernated' } | Should -Throw
    }

    It 'StartVM logs exactly one Op=StartVM CallLog entry for the started VM (positive control — pins the invocation-was-reached instrumentation used by the I2b lifecycle-abort tests'' zero-StartVM-entries assertions)' {
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
        & $script:B.StartVM @{ Name = 'vm1' }
        $entries = @($script:B.FakeCallLog | Where-Object { $_.Op -eq 'StartVM' })
        $entries.Count | Should -Be 1 -Because 'StartVM must log its own invocation exactly once — otherwise a lifecycle test asserting zero StartVM CallLog entries would pass vacuously regardless of whether StartVM ran'
        $entries[0].VMName | Should -Be 'vm1'
    }

    It 'RemoveNetworkAdapter logs exactly one Op=RemoveNetworkAdapter CallLog entry for the VM (positive control — pins the invocation-was-reached instrumentation used by the builder no-seal tests'' zero-RemoveNetworkAdapter-entries assertions)' {
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        $entries = @($script:B.FakeCallLog | Where-Object { $_.Op -eq 'RemoveNetworkAdapter' })
        $entries.Count | Should -Be 1 -Because 'RemoveNetworkAdapter must log its own invocation exactly once — otherwise a test asserting zero RemoveNetworkAdapter CallLog entries would pass vacuously regardless of whether RemoveNetworkAdapter ran'
        $entries[0].VMName | Should -Be 'vm1'
    }

    It 'SetHostChannel logs exactly one Op=SetHostChannel CallLog entry for the VM (positive control — pins the invocation-was-reached instrumentation used by the builder no-seal tests'' zero-SetHostChannel-entries assertion)' {
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
        & $script:B.SetHostChannel @{ VMName = 'vm1'; Channel = 'Clipboard'; Enabled = $false }
        $entries = @($script:B.FakeCallLog | Where-Object { $_.Op -eq 'SetHostChannel' })
        $entries.Count | Should -Be 1 -Because 'SetHostChannel must log its own invocation exactly once — otherwise a test asserting zero SetHostChannel CallLog entries would pass vacuously regardless of whether SetHostChannel ran'
        $entries[0].VMName | Should -Be 'vm1'
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

    It 'a fresh VM carries Hyper-V''s own processor defaults (Maximum 100, RelativeWeight 100)' {
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        $vm.ProcessorMaximum        | Should -Be 100
        $vm.ProcessorRelativeWeight | Should -Be 100
    }

    It 'SetProcessor records Maximum and RelativeWeight when supplied' {
        & $script:B.SetProcessor @{ VMName = 'vm1'; Count = 2; Maximum = 50; RelativeWeight = 250 }
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        $vm.ProcessorMaximum        | Should -Be 50
        $vm.ProcessorRelativeWeight | Should -Be 250
        $vm.ProcessorCount          | Should -Be 2
    }

    It 'SetProcessor without Maximum/RelativeWeight leaves the recorded values untouched' {
        & $script:B.SetProcessor @{ VMName = 'vm1'; Maximum = 40; RelativeWeight = 300 }
        & $script:B.SetProcessor @{ VMName = 'vm1'; Count = 3 }
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        $vm.ProcessorMaximum        | Should -Be 40
        $vm.ProcessorRelativeWeight | Should -Be 300
        $vm.ProcessorCount          | Should -Be 3
    }

    It 'SetProcessor rejects what the real Set-VMProcessor rejects (Maximum outside 0..100, RelativeWeight outside 1..10000)' {
        { & $script:B.SetProcessor @{ VMName = 'vm1'; Maximum = 101 } }          | Should -Throw -ExpectedMessage '*Maximum*'
        { & $script:B.SetProcessor @{ VMName = 'vm1'; Maximum = -1 } }           | Should -Throw -ExpectedMessage '*Maximum*'
        { & $script:B.SetProcessor @{ VMName = 'vm1'; RelativeWeight = 0 } }     | Should -Throw -ExpectedMessage '*RelativeWeight*'
        { & $script:B.SetProcessor @{ VMName = 'vm1'; RelativeWeight = 10001 } } | Should -Throw -ExpectedMessage '*RelativeWeight*'
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        $vm.ProcessorMaximum | Should -Be 100 -Because 'a rejected call must not half-apply'
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
#  FAKE backend — SetAutomaticCheckpoints (RC7: the empty-OUTPUT root cause)
# ===========================================================================
#  RC7 (2026-06-25 live): Windows Hyper-V defaults AutomaticCheckpointsEnabled=ON, so each disk gets a
#  differencing .avhdx at VM start; the guest writes result.html into the .avhdx while the host reads
#  the BASE .vhdx (the empty pre-write layer) — every host read came back empty. Nothing in the engine
#  disabled it. SetAutomaticCheckpoints @{ VMName; Enabled } is the new backend method (real = Set-VM
#  -AutomaticCheckpointsEnabled; fake = flips the recorded flag), called by the Provisioner at provision
#  time. The fake VM's initial state mirrors Hyper-V's real default (AutomaticCheckpointsEnabled=$true)
#  so a test can prove the provisioner flips it to $false.
Describe 'Fake backend — SetAutomaticCheckpoints (RC7)' {

    BeforeEach {
        $script:B = New-FakeHyperVBackend
        & $script:B.NewVM @{ Name = 'vm1'; Generation = 2 }
    }

    It 'a freshly-created fake VM has AutomaticCheckpointsEnabled=$true (mirrors Hyper-V''s real default)' {
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        # The fake must seed the Hyper-V default so the disable is OBSERVABLE (true -> false).
        $vm.AutomaticCheckpointsEnabled | Should -BeTrue -Because 'Hyper-V enables automatic checkpoints by default; the fake must seed that so the disable is testable'
    }

    It 'SetAutomaticCheckpoints Enabled=$false flips the recorded flag to $false' {
        & $script:B.SetAutomaticCheckpoints @{ VMName = 'vm1'; Enabled = $false }
        (& $script:B.GetVM @{ Name = 'vm1' }).AutomaticCheckpointsEnabled |
            Should -BeFalse -Because 'disabling automatic checkpoints must be host-visible on the VM record'
    }

    It 'SetAutomaticCheckpoints Enabled=$true round-trips back to $true' {
        & $script:B.SetAutomaticCheckpoints @{ VMName = 'vm1'; Enabled = $false }
        (& $script:B.GetVM @{ Name = 'vm1' }).AutomaticCheckpointsEnabled | Should -BeFalse
        & $script:B.SetAutomaticCheckpoints @{ VMName = 'vm1'; Enabled = $true }
        (& $script:B.GetVM @{ Name = 'vm1' }).AutomaticCheckpointsEnabled | Should -BeTrue
    }

    It 'SetAutomaticCheckpoints on a missing VM throws naming the VM (fail closed)' {
        { & $script:B.SetAutomaticCheckpoints @{ VMName = 'ghost'; Enabled = $false } } |
            Should -Throw -ExpectedMessage '*ghost*'
    }

    It 'the manifest documents SetAutomaticCheckpoints with VMName + Enabled arg keys' {
        $m = Get-HyperVBackendMethodManifest
        $m.Keys | Should -Contain 'SetAutomaticCheckpoints'
        @($m['SetAutomaticCheckpoints']) | Should -Contain 'VMName'
        @($m['SetAutomaticCheckpoints']) | Should -Contain 'Enabled'
    }

    It 'both backends expose SetAutomaticCheckpoints as a scriptblock (interface parity)' {
        (New-RealHyperVBackend)['SetAutomaticCheckpoints'] | Should -BeOfType [scriptblock]
        (New-FakeHyperVBackend)['SetAutomaticCheckpoints'] | Should -BeOfType [scriptblock]
    }

    It 'GetAutomaticCheckpoints reads the recorded flag back as a [bool] (the seal gate''s host read)' {
        $v = & $script:B.GetAutomaticCheckpoints @{ VMName = 'vm1' }
        $v | Should -BeOfType [bool]
        $v | Should -BeTrue -Because 'a fresh VM carries the Hyper-V default'
        & $script:B.SetAutomaticCheckpoints @{ VMName = 'vm1'; Enabled = $false }
        (& $script:B.GetAutomaticCheckpoints @{ VMName = 'vm1' }) | Should -BeFalse
        @($script:ExpectedMethods['GetAutomaticCheckpoints']) | Should -Be @('VMName')
    }

    It 'SimulateAutomaticCheckpointsStuckOn: the disable does not take, so the read stays $true' {
        $b = New-FakeHyperVBackend -SimulateAutomaticCheckpointsStuckOn
        & $b.NewVM @{ Name = 'vm1'; Generation = 2 }
        & $b.SetAutomaticCheckpoints @{ VMName = 'vm1'; Enabled = $false }
        (& $b.GetAutomaticCheckpoints @{ VMName = 'vm1' }) | Should -BeTrue
    }

    It 'SimulateCheckpointPresent: every new VM lists one checkpoint, and it can be restored' {
        $b = New-FakeHyperVBackend -SimulateCheckpointPresent
        & $b.NewVM @{ Name = 'vm1'; Generation = 2 }
        $cps = & $b.GetCheckpoint @{ VMName = 'vm1' }
        $cps.Count   | Should -Be 1
        $cps[0].Name | Should -Be 'external-checkpoint'
        { & $b.RestoreCheckpoint @{ VMName = 'vm1'; SnapshotName = 'external-checkpoint' } } | Should -Not -Throw
        (& $script:B.GetCheckpoint @{ VMName = 'vm1' }).Count | Should -Be 0 -Because 'without the switch a new VM has no checkpoint'
    }

    It 'GetAutomaticCheckpoints on a missing VM throws naming the VM' {
        { & $script:B.GetAutomaticCheckpoints @{ VMName = 'ghost' } } | Should -Throw -ExpectedMessage '*ghost*'
    }
}

# ===========================================================================
#  REAL backend — SetAutomaticCheckpoints calls Set-VM -AutomaticCheckpointsEnabled (AST-pinned)
# ===========================================================================
#  The real backend's closures resolve their Hyper-V cmdlets against the session captured at
#  .GetNewClosure() time, not the test scope, so an in-process Mock can't intercept (see the file
#  header). We PIN the real SetAutomaticCheckpoints STRUCTURALLY via the AST — the same technique used
#  for the GetDvdDrives / GetComPort guards above: the real method must call Set-VM with the
#  -AutomaticCheckpointsEnabled parameter, and must route through the $InvokeOp fail-closed wrapper.
Describe 'Real backend — SetAutomaticCheckpoints uses Set-VM -AutomaticCheckpointsEnabled (RC7; AST-pinned)' {

    BeforeAll {
        $tokens = $null; $parseErrors = $null
        $script:LibAst5 = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:LibPath, [ref]$tokens, [ref]$parseErrors)
        @($parseErrors).Count | Should -Be 0 -Because 'the backend lib must parse cleanly to be analyzed'

        $script:RealFn5 = $script:LibAst5.FindAll({
            param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                      $n.Name -eq 'New-RealHyperVBackend'
        }, $true) | Select-Object -First 1
        $script:RealFn5 | Should -Not -BeNullOrEmpty

        # Locate the `$b.SetAutomaticCheckpoints = { ... }` assignment in the real factory.
        $script:RealAcAssign = $script:RealFn5.FindAll({
            param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                      $n.Left.Extent.Text -eq '$b.SetAutomaticCheckpoints'
        }, $true) | Select-Object -First 1
    }

    It 'the real factory defines SetAutomaticCheckpoints' {
        $script:RealAcAssign | Should -Not -BeNullOrEmpty -Because 'the real backend must implement SetAutomaticCheckpoints'
    }

    It 'the REAL SetAutomaticCheckpoints calls Set-VM with -AutomaticCheckpointsEnabled' {
        $body = $script:RealAcAssign.Right.Extent.Text
        $body | Should -Match 'Set-VM' -Because 'disabling automatic checkpoints is Set-VM -AutomaticCheckpointsEnabled <bool>'
        $body | Should -Match 'AutomaticCheckpointsEnabled' -Because 'the method must set the AutomaticCheckpointsEnabled property'
    }

    It 'the REAL SetAutomaticCheckpoints routes through the fail-closed $InvokeOp wrapper' {
        $body = $script:RealAcAssign.Right.Extent.Text
        $body | Should -Match '\$InvokeOp' -Because 'every real backend op routes through $InvokeOp so an availability/permission error becomes the single clear fail-closed message'
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
        # Hyper-V enables Enhanced Session and the Time Synchronization, Key-Value Pair Exchange, Backup
        # and Heartbeat integration services by default; a new VM is NOT sealed.
        $ch = & $script:B.GetHostChannels @{ VMName = 'vm1' }
        foreach ($name in 'Clipboard', 'Shares', 'GuestServices', 'EnhancedSession', 'TimeSync', 'KeyValueExchange', 'Backup', 'Heartbeat') {
            $ch[$name] | Should -BeTrue -Because "$name starts ON on a fresh VM, so the seal's disable is observable"
        }
    }

    It 'GetHostChannels returns exactly the eight canonical channel keys' {
        $ch = & $script:B.GetHostChannels @{ VMName = 'vm1' }
        @($ch.Keys | Sort-Object) -join ',' |
            Should -Be 'Backup,Clipboard,EnhancedSession,GuestServices,Heartbeat,KeyValueExchange,Shares,TimeSync'
    }

    It 'the canonical channel list adds the four integration services and leaves Shutdown out' {
        # Shutdown stays enabled on purpose: the engine stops VMs with StopVM without TurnOff, which asks
        # the guest to shut down through that service (docs/threat-model.md).
        $script:HostChannelNames -join ',' |
            Should -Be 'Clipboard,Shares,GuestServices,EnhancedSession,TimeSync,KeyValueExchange,Backup,Heartbeat'
        $script:HostChannelNames | Should -Not -Contain 'Shutdown'
    }

    It 'SetHostChannel turns each integration service OFF independently' {
        foreach ($name in 'TimeSync', 'KeyValueExchange', 'Backup', 'Heartbeat') {
            $b = New-FakeHyperVBackend
            & $b.NewVM @{ Name = 'vm1'; Generation = 2 }
            & $b.SetHostChannel @{ VMName = 'vm1'; Channel = $name; Enabled = $false }
            $ch = & $b.GetHostChannels @{ VMName = 'vm1' }
            $ch[$name] | Should -BeFalse -Because "$name was turned off"
            @($ch.Keys | Where-Object { $_ -ne $name -and -not $ch[$_] }).Count |
                Should -Be 0 -Because "turning $name off must not touch another channel"
        }
    }

    It 'SimulateChannelStuckOn: the disable of a stuck channel does not take; the others still turn off' {
        $b = New-FakeHyperVBackend -SimulateChannelStuckOn 'KeyValueExchange'
        & $b.NewVM @{ Name = 'vm1'; Generation = 2 }
        & $b.SetHostChannel @{ VMName = 'vm1'; Channel = 'KeyValueExchange'; Enabled = $false }
        & $b.SetHostChannel @{ VMName = 'vm1'; Channel = 'TimeSync'; Enabled = $false }
        $ch = & $b.GetHostChannels @{ VMName = 'vm1' }
        $ch.KeyValueExchange | Should -BeTrue  -Because 'a stuck channel stays ON after its disable'
        $ch.TimeSync         | Should -BeFalse -Because 'a channel that is not stuck still turns off'
    }

    It 'SimulateChannelStuckOn rejects a channel name the backend does not know' {
        { New-FakeHyperVBackend -SimulateChannelStuckOn 'Shutdown' } |
            Should -Throw -ExpectedMessage "*SimulateChannelStuckOn names unknown channel 'Shutdown'*"
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

    # ---- integration services (design E6): REAL reads by stable component GUID ------------------
    # The harness stubs return services with GERMAN display names, so these pass only if the real body
    # matches on the Id's trailing component GUID. Shutdown and Guest Service Interface are in the stub
    # set too, so a match that grabbed the wrong service would read the wrong value.
    It 'GetHostChannels reads the four integration services from the host (all ON) and returns all eight keys' {
        $c = $script:ChCap.IsGetAllOn
        $c.err  | Should -BeNullOrEmpty
        $c.keys | Should -Be 'Backup,Clipboard,EnhancedSession,GuestServices,Heartbeat,KeyValueExchange,Shares,TimeSync'
        foreach ($k in 'TimeSync', 'KeyValueExchange', 'Backup', 'Heartbeat') { $c.$k | Should -BeTrue -Because "$k is enabled on the host" }
    }

    It 'GetHostChannels reads them OFF when the host reports them disabled (a real read, not a constant)' {
        $c = $script:ChCap.IsGetAllOff
        $c.err | Should -BeNullOrEmpty
        foreach ($k in 'TimeSync', 'KeyValueExchange', 'Backup', 'Heartbeat') { $c.$k | Should -BeFalse -Because "$k is disabled on the host" }
    }

    It 'GetHostChannels maps each value to its own service (mixed states, localized names)' {
        $c = $script:ChCap.IsGetMixed
        $c.err              | Should -BeNullOrEmpty
        $c.KeyValueExchange | Should -BeTrue  -Because 'only Key-Value Pair Exchange is enabled in this scenario'
        $c.TimeSync         | Should -BeFalse
        $c.Backup           | Should -BeFalse
        $c.Heartbeat        | Should -BeFalse
    }

    It 'GetHostChannels THROWS when an integration service is missing from the host enumeration (fail closed)' {
        $script:ChCap.IsGetMissingKvp.err  | Should -BeLike "*could not identify the 'KeyValueExchange' integration service*0 matching*"
        $script:ChCap.IsGetMissingKvp.keys | Should -BeNullOrEmpty
    }

    It 'GetHostChannels THROWS when two services carry the same component id (ambiguous, fail closed)' {
        $script:ChCap.IsGetDuplicate.err | Should -BeLike "*could not identify the 'Heartbeat' integration service*2 matching*"
    }

    It 'GetHostChannels THROWS when a service reports a non-boolean Enabled (no truthiness coercion)' {
        $script:ChCap.IsGetNonBool.err | Should -BeLike "*'Backup' integration service*no boolean Enabled state*"
    }

    It 'GetHostChannels THROWS when the integration-service enumeration itself fails' {
        $script:ChCap.IsGetEnumThrows.err  | Should -BeLike '*simulated Get-VMIntegrationService enumeration failure*'
        $script:ChCap.IsGetEnumThrows.keys | Should -BeNullOrEmpty
    }

    It 'SetHostChannel disables each integration service by piping the ID-matched object, never by -Name' {
        $expect = @{
            IsSetTimeSyncOff  = '2497F4DE-E9FA-4204-80E4-4B75C46419C0'
            IsSetKvpOff       = '2A34B1C2-FD73-4043-8A5B-DD2159BC743F'
            IsSetBackupOff    = '5CED1297-4598-4915-A5FC-AD21BB4D02A4'
            IsSetHeartbeatOff = '84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47'
        }
        foreach ($key in $expect.Keys) {
            $c = $script:ChCap.$key
            $c.err | Should -BeNullOrEmpty -Because $key
            @($c.disabledIds) | Should -Be @("Microsoft:00000000-0000-0000-0000-000000000ABC\$($expect[$key])") -Because "$key must disable exactly its own service"
            @($c.enabledIds).Count | Should -Be 0
            $c.anyNameGiven | Should -BeFalse -Because 'display names are localized; the set must not pass -Name'
            $c.gsiByName    | Should -BeFalse -Because 'the integration-service set must not reach the GuestServices by-name path'
        }
    }

    It 'SetHostChannel ENABLE pipes the matched object to Enable-VMIntegrationService (symmetric)' {
        $c = $script:ChCap.IsSetHeartbeatOn
        $c.err | Should -BeNullOrEmpty
        @($c.enabledIds) | Should -Be @('Microsoft:00000000-0000-0000-0000-000000000ABC\84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47')
        @($c.disabledIds).Count | Should -Be 0
    }

    It 'SetHostChannel THROWS when the service to disable cannot be found (no silent no-op)' {
        $script:ChCap.IsSetMissing.err | Should -BeLike "*could not identify the 'TimeSync' integration service*0 matching*"
        @($script:ChCap.IsSetMissing.disabledIds).Count | Should -Be 0
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
#  Integration services in the seal: matched by component GUID, never by localized name
# ===========================================================================
Describe 'Integration-service seal: matched by stable component GUID, never by localized name (AST-pinned real)' {

    It 'the component GUID table names exactly the four sealed services with their Hyper-V component ids' {
        $script:IntegrationServiceIds.Keys -join ',' | Should -Be 'TimeSync,KeyValueExchange,Backup,Heartbeat'
        $script:IntegrationServiceIds.TimeSync         | Should -Be '2497F4DE-E9FA-4204-80E4-4B75C46419C0'
        $script:IntegrationServiceIds.KeyValueExchange | Should -Be '2A34B1C2-FD73-4043-8A5B-DD2159BC743F'
        $script:IntegrationServiceIds.Backup           | Should -Be '5CED1297-4598-4915-A5FC-AD21BB4D02A4'
        $script:IntegrationServiceIds.Heartbeat        | Should -Be '84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47'
        @($script:IntegrationServiceIds.Values) | Should -Not -Contain '9F8233AC-BE49-4C79-8EE3-E7E1985B2077' -Because 'Shutdown (9F8233AC) stays enabled and must never be in the sealed set'
    }

    It 'neither real SetHostChannel nor real GetHostChannels passes an English integration-service name to a cmdlet' {
        $english = @('Time Synchronization', 'Key-Value Pair Exchange', 'Backup (volume shadow copy)', 'Heartbeat', 'Shutdown')
        foreach ($method in 'SetHostChannel', 'GetHostChannels') {
            $assign = & $script:GetRealBackendAssign $method
            $assign | Should -Not -BeNullOrEmpty
            $cmds = $assign.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
            $byName = @($cmds | Where-Object {
                $els = $_.CommandElements
                $hit = $false
                for ($i = 0; $i -lt $els.Count - 1; $i++) {
                    if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $els[$i].ParameterName -eq 'Name' -and
                        $english -contains $els[$i + 1].Extent.Text.Trim("'", '"')) { $hit = $true }
                }
                $hit
            })
            $byName.Count | Should -Be 0 -Because "$method must find the integration services by component GUID; display names are localized"
        }
    }

    It 'real GetHostChannels enumerates the services with Get-VMIntegrationService and no -Name (a host read, not a constant)' {
        $assign = & $script:GetRealBackendAssign 'GetHostChannels'
        $enum = @($assign.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                      $n.GetCommandName() -eq 'Get-VMIntegrationService' -and
                      -not ($n.CommandElements | Where-Object {
                          $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Name' })
        }, $true))
        $enum.Count | Should -BeGreaterThan 0 -Because 'the four integration services must be read from the host by enumerating the VM''s services'
    }

    It 'the GUID matcher returns the single match, and throws on zero matches, two matches, or an object with no Id' {
        $guid = '84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47'
        $one  = [pscustomobject]@{ Id = "Microsoft:X\$guid"; Enabled = $true }
        (& $script:SbFindIntegrationService @($one) 'Heartbeat' $guid 'vm1').Id | Should -Be $one.Id
        (& $script:SbFindIntegrationService @([pscustomobject]@{ Id = "microsoft:x\$($guid.ToLowerInvariant())" }) 'Heartbeat' $guid 'vm1') |
            Should -Not -BeNullOrEmpty -Because 'the GUID compare is case-insensitive'
        { & $script:SbFindIntegrationService @() 'Heartbeat' $guid 'vm1' } |
            Should -Throw -ExpectedMessage "*'Heartbeat' integration service*0 matching*"
        { & $script:SbFindIntegrationService @($one, $one) 'Heartbeat' $guid 'vm1' } |
            Should -Throw -ExpectedMessage "*'Heartbeat' integration service*2 matching*"
        { & $script:SbFindIntegrationService @([pscustomobject]@{ Name = 'Heartbeat'; Enabled = $true }) 'Heartbeat' $guid 'vm1' } |
            Should -Throw -ExpectedMessage '*0 matching*' -Because 'an object without an Id is never matched by its Name'
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

    It 'the REAL GetComPort reads with -ErrorAction Stop, never SilentlyContinue (an unreadable port must throw)' {
        $call = @($script:RealComAssign.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-VMComPort'
        }, $true))
        $call.Count | Should -Be 1
        $call[0].Extent.Text | Should -Match '-ErrorAction\s+Stop'
        $call[0].Extent.Text | Should -Not -Match 'SilentlyContinue' -Because 'a swallowed failure would make the COM2 refusal fail open'
    }

    It 'the FAKE models an empty COM2 by default and a wired one with -SimulateCom2Path' {
        $b = New-FakeHyperVBackend
        & $b.NewVM @{ Name = 'vm1'; Generation = 2 }
        (& $b.GetComPort @{ VMName = 'vm1'; Number = 2 }) | Should -BeNullOrEmpty
        $w = New-FakeHyperVBackend -SimulateCom2Path '\\.\pipe\extra'
        & $w.NewVM @{ Name = 'vm1'; Generation = 2 }
        $port = & $w.GetComPort @{ VMName = 'vm1'; Number = 2 }
        $port.Number | Should -Be 2
        $port.Path   | Should -Be '\\.\pipe\extra'
        (& $w.GetComPort @{ VMName = 'vm1'; Number = 1 }) | Should -BeNullOrEmpty -Because 'the switch seeds COM2 only'
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

    # ---- Task 4.2: Raw FileSystem mode (create-without-format) ----
    It 'NewOutputVhdx (fake) accepts FileSystem=Raw and records FileSystem=Raw' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\raw.vhdx'; Label='OUTPUT'; FileSystem='Raw'; SizeBytes=1GB }
        $info = & $b.GetVHDInfo @{ Path='C:\t\raw.vhdx' }
        $info | Should -Not -BeNullOrEmpty
        $info.FileSystem | Should -Be 'Raw' -Because 'a Raw disk is recorded with FileSystem=Raw'
    }
    It 'NewOutputVhdx (fake) Raw disk keeps its Label as mock-internal discovery tag' {
        # The Label on a Raw disk is a MOCK-INTERNAL discovery tag (the real raw disk has no FS label;
        # real GetVHDInfo returns no Label — non-observable divergence documented here per task-4.2-brief).
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\rawlbl.vhdx'; Label='OUTPUT'; FileSystem='Raw'; SizeBytes=1GB }
        $info = & $b.GetVHDInfo @{ Path='C:\t\rawlbl.vhdx' }
        $info.Label | Should -Be 'OUTPUT' -Because 'the Label is a mock-internal tag so findOutputDisk still discovers the Raw OUTPUT disk'
    }
    It 'NewOutputVhdx (fake) accepts lowercase raw and normalizes to Raw' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\rawlc.vhdx'; Label='OUTPUT'; FileSystem='raw'; SizeBytes=1GB }
        $info = & $b.GetVHDInfo @{ Path='C:\t\rawlc.vhdx' }
        $info.FileSystem | Should -Be 'Raw' -Because 'Raw is case-normalized like exFAT'
    }
    It 'NewOutputVhdx (fake) Raw disk does not impose a label-length ceiling (no Format-Volume runs)' {
        # Raw = create-without-format: no Format-Volume, so no real label limit applies.
        # The Label is a mock-internal tag only — any length is accepted.
        $b = New-FakeHyperVBackend
        { & $b.NewOutputVhdx @{ Path='C:\t\rawlong.vhdx'; Label='THIS_LABEL_IS_WAY_TOO_LONG_FOR_EXFAT'; FileSystem='Raw'; SizeBytes=1GB } } |
            Should -Not -Throw -Because 'Raw skips Format-Volume so no label-length ceiling applies'
    }
    It 'SECURITY: real NewOutputVhdx Raw branch does NOT reference Format-Volume (AST check)' {
        # Guard that the REAL backend Raw branch genuinely skips formatting — via a real AST walk,
        # not a comment-canary regex (a comment can survive deletion of the actual guard it describes).
        $realB = New-RealHyperVBackend
        $ast = $realB.NewOutputVhdx.Ast

        # Presence check: a Raw branch exists at all.
        $src = $realB.NewOutputVhdx.ToString()
        $src | Should -Match '(?i)raw' -Because 'the real NewOutputVhdx must have a Raw branch'

        # Find every Format-Volume command node. At least one must exist (the non-Raw path formats).
        $fmtCalls = $ast.FindAll({
                param($n)
                $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Format-Volume'
            }, $true)
        $fmtCalls.Count | Should -BeGreaterThan 0 -Because 'the non-Raw path must call Format-Volume'

        # Find the Raw-branch IfStatementAst: the clause whose condition extent mentions 'Raw'.
        $ifStatements = $ast.FindAll({
                param($n)
                $n -is [System.Management.Automation.Language.IfStatementAst]
            }, $true)
        $rawIf = $ifStatements | Where-Object {
            $_.Clauses | Where-Object { $_.Item1.Extent.Text -match "-eq 'Raw'|Raw" }
        } | Select-Object -First 1
        $rawIf | Should -Not -BeNullOrEmpty -Because 'an if-statement gating on Raw must exist'

        # Within the Raw clause's body, find the early ReturnStatementAst.
        $rawClause = $rawIf.Clauses | Where-Object { $_.Item1.Extent.Text -match "-eq 'Raw'|Raw" } | Select-Object -First 1
        $rawReturn = $rawClause.Item2.FindAll({
                param($n)
                $n -is [System.Management.Automation.Language.ReturnStatementAst]
            }, $true) | Select-Object -First 1
        $rawReturn | Should -Not -BeNullOrEmpty -Because 'the Raw branch must contain an early return'

        # THE core assertion: the Raw branch's return occurs (textually/structurally) BEFORE every
        # Format-Volume call reachable in the scriptblock. This fails if the early return is removed
        # or moved to after Format-Volume — which the old comment-canary would not have caught.
        foreach ($fmt in $fmtCalls) {
            $rawReturn.Extent.StartOffset | Should -BeLessThan $fmt.Extent.StartOffset `
                -Because 'the Raw path must return before any Format-Volume is reachable'
        }
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

    # ---- I2a: byte-transfer variants (the string path corrupts 0x00/0x80-0xFF; see WriteVhdxFile) ----
    It 'manifest documents WriteVhdxFileBytes and ReadVhdxFileBytes' {
        $m = Get-HyperVBackendMethodManifest
        $m.Keys | Should -Contain 'WriteVhdxFileBytes'
        $m['WriteVhdxFileBytes'] | Should -Contain 'Path'
        $m['WriteVhdxFileBytes'] | Should -Contain 'InnerPath'
        $m['WriteVhdxFileBytes'] | Should -Contain 'Bytes'
        $m.Keys | Should -Contain 'ReadVhdxFileBytes'
        $m['ReadVhdxFileBytes'] | Should -Contain 'Path'
        $m['ReadVhdxFileBytes'] | Should -Contain 'InnerPath'
    }
    It 'fake WriteVhdxFileBytes then ReadVhdxFileBytes round-trips arbitrary bytes incl. 0x00 and 0x80-0xFF (string path would corrupt these)' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\bin-in.vhdx'; Label='INPUT'; FileSystem='Raw'; SizeBytes=1GB }
        $bytes = [byte[]]@(0x00,0x01,0x7F,0x80,0xFE,0xFF,0x00,0xAA)
        & $b.WriteVhdxFileBytes @{ Path='C:\t\bin-in.vhdx'; InnerPath='blob.bin'; Bytes=$bytes }
        $got = & $b.ReadVhdxFileBytes @{ Path='C:\t\bin-in.vhdx'; InnerPath='blob.bin' }
        ,$got | Should -Not -BeNullOrEmpty
        $got | Should -BeOfType [byte]
        [System.Linq.Enumerable]::SequenceEqual([byte[]]$got, $bytes) | Should -BeTrue
    }
    It 'fake WriteVhdxFileBytes then ReadVhdxFileBytes round-trips a single-byte payload without array-unrolling to a scalar' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\bin-one.vhdx'; Label='INPUT'; FileSystem='Raw'; SizeBytes=1GB }
        $bytes = [byte[]]@(0x2A)
        & $b.WriteVhdxFileBytes @{ Path='C:\t\bin-one.vhdx'; InnerPath='one.bin'; Bytes=$bytes }
        $got = & $b.ReadVhdxFileBytes @{ Path='C:\t\bin-one.vhdx'; InnerPath='one.bin' }
        , $got | Should -Not -BeNullOrEmpty
        ($got -is [byte[]]) | Should -BeTrue -Because 'a leading-comma return must prevent PowerShell from unrolling a 1-element array to a scalar'
        $got.Length | Should -Be 1
        $got[0] | Should -Be 0x2A
    }
    It 'fake ReadVhdxFileBytes returns $null for an absent inner file' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\bin-missing.vhdx'; Label='INPUT'; FileSystem='Raw'; SizeBytes=1GB }
        (& $b.ReadVhdxFileBytes @{ Path='C:\t\bin-missing.vhdx'; InnerPath='missing.bin' }) | Should -Be $null
    }
    It 'fake WriteVhdxFileBytes throws for a VHD that does not exist' {
        $b = New-FakeHyperVBackend
        { & $b.WriteVhdxFileBytes @{ Path='C:\t\ghost.vhdx'; InnerPath='a'; Bytes=[byte[]]@(1,2,3) } } | Should -Throw -ExpectedMessage '*does not exist*'
    }
    It 'fake ReadVhdxFileBytes throws for a VHD that does not exist' {
        $b = New-FakeHyperVBackend
        { & $b.ReadVhdxFileBytes @{ Path='C:\t\ghost2.vhdx'; InnerPath='a' } } | Should -Throw -ExpectedMessage '*does not exist*'
    }
    It 'fake ReadVhdxFileBytes on a file written via the STRING WriteVhdxFile returns its UTF-8 bytes (honest cross-read, not a fake shortcut)' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\bin-cross.vhdx'; Label='INPUT'; FileSystem='exFAT'; SizeBytes=64MB }
        & $b.WriteVhdxFile @{ Path='C:\t\bin-cross.vhdx'; InnerPath='sample.json'; Content='{"x":1}' }
        $got = & $b.ReadVhdxFileBytes @{ Path='C:\t\bin-cross.vhdx'; InnerPath='sample.json' }
        [System.Linq.Enumerable]::SequenceEqual([byte[]]$got, [System.Text.Encoding]::UTF8.GetBytes('{"x":1}')) | Should -BeTrue
    }
    It 'fake WriteVhdxFileBytes stores an immutable copy (mutating the caller''s array after the call does not affect stored bytes)' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\bin-mut.vhdx'; Label='INPUT'; FileSystem='Raw'; SizeBytes=1GB }
        $bytes = [byte[]]@(0x11,0x22,0x33)
        & $b.WriteVhdxFileBytes @{ Path='C:\t\bin-mut.vhdx'; InnerPath='m.bin'; Bytes=$bytes }
        $bytes[0] = 0xFF
        $got = & $b.ReadVhdxFileBytes @{ Path='C:\t\bin-mut.vhdx'; InnerPath='m.bin' }
        $got[0] | Should -Be 0x11 -Because 'the fake must store a copy, not a reference to the caller''s array'
    }
    It 'fake ReadVhdxFileBytes returns a fresh copy on each read (mutating a returned array does not corrupt a later read) — ULTRACODE fake≠real gate regression' {
        # This is the READ-side aliasing gap (distinct from the WRITE-side copy test above): the fake's
        # store previously handed back the LIVE stored reference (`return ,$v`), so a caller mutating its
        # own read result would silently corrupt every subsequent read of the same key — a divergence the
        # real backend can never exhibit (ReadAllBytes allocates a fresh byte[] every call; the filesystem
        # is the immutability boundary). Fixed via copy-on-read in ReadVhdxFileBytes.
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\bin-alias.vhdx'; Label='INPUT'; FileSystem='Raw'; SizeBytes=1GB }
        $bytes = [byte[]]@(0x01,0x02,0x03)
        & $b.WriteVhdxFileBytes @{ Path='C:\t\bin-alias.vhdx'; InnerPath='a.bin'; Bytes=$bytes }
        $first = & $b.ReadVhdxFileBytes @{ Path='C:\t\bin-alias.vhdx'; InnerPath='a.bin' }
        $first[0] = 0xEE   # mutate the CALLER's copy of the read result
        $second = & $b.ReadVhdxFileBytes @{ Path='C:\t\bin-alias.vhdx'; InnerPath='a.bin' }
        $second[0] | Should -Be 0x01 -Because 'ReadVhdxFileBytes must hand out a fresh copy each call, not a live alias into the fake''s own store'
        [System.Linq.Enumerable]::SequenceEqual([byte[]]$second, [byte[]]@(0x01,0x02,0x03)) | Should -BeTrue
    }
    # F2 FIX (follow-up task, closes the gap flagged above): a WriteVhdxFileBytes round-trip of a
    # genuine 0-LENGTH byte[] payload used to throw ArgumentNullException, because
    # $script:SbAssertArg's `return $P[$Key]` (no leading comma) unrolled a 0-length array argument
    # to $null across ITS OWN `&`-invocation boundary, before WriteVhdxFileBytes's
    # `[byte[]](& $AssertArg ...)` cast ever saw it. That reproduced identically on the REAL and
    # FAKE write paths (both share the `[byte[]](& $AssertArg $P 'Bytes' 'WriteVhdxFileBytes')`
    # hoist) — fake≠real-PARITY-PRESERVING, not a divergence. Fixed by comma-wrapping SbAssertArg's
    # return (`return ,$P[$Key]`); see that scriptblock's header comment (HyperVBackend.ps1) and the
    # direct helper coverage in the "$script:SbAssertArg — array shape preservation" Describe block
    # below. This test proves the fix end-to-end through the fake's actual write/read path.
    It 'fake WriteVhdxFileBytes with an empty [byte[]] payload writes an empty inner file (F2: $SbAssertArg 0-length shape fix)' {
        $b = New-FakeHyperVBackend
        & $b.NewOutputVhdx @{ Path='C:\t\bin-empty.vhdx'; Label='INPUT'; FileSystem='Raw'; SizeBytes=1GB }
        { & $b.WriteVhdxFileBytes @{ Path='C:\t\bin-empty.vhdx'; InnerPath='empty.bin'; Bytes=[byte[]]@() } } |
            Should -Not -Throw -Because 'a genuinely-empty [byte[]] Bytes arg must not unroll to $null and trip the required-argument-missing throw'
        $got = & $b.ReadVhdxFileBytes @{ Path='C:\t\bin-empty.vhdx'; InnerPath='empty.bin' }
        ($got -is [byte[]]) | Should -BeTrue -Because 'the round-tripped empty payload must come back as an intact [byte[]], not $null'
        $got.Length | Should -Be 0
    }
    It 'REAL byte-return composition-analog: a return crossing the exact two `&`-boundary shape (& $InvokeOp { return ,,$x }) yields an intact [byte[]] for 0/1/N bytes, while a single comma through the SAME shape does not — ULTRACODE fake≠real gate regression' {
        # HyperVBackend.ps1's REAL ReadVhdxFileBytes/ReadVhdxRawRegion route their byte[] return through
        # $InvokeOp (`try { return (& $Operation) } catch {...}`), a scriptblock invoked via `&` — a SECOND
        # `&`-boundary on top of the inner operation block's own `return`. $InvokeOp is a local closure
        # inside New-RealHyperVBackend (not exported), so it cannot be driven directly without live
        # Mount-VHD/Hyper-V (LIVE-ONLY-UNPROVEN, matching this file's existing pattern for other real-only
        # methods, e.g. ReadVhdxRawRegion's qemu-img path). This test reconstructs the IDENTICAL
        # two-boundary composition in isolation and empirically pins the array-unrolling contract that
        # both real fixes rely on, so a future edit that collapses back to a single comma fails loudly.
        $invokeOp = {
            param([scriptblock] $Operation)
            try { return (& $Operation) }
            catch { throw }
        }.GetNewClosure()

        foreach ($n in 0, 1, 4) {
            $payload = [byte[]]::new($n)
            for ($i = 0; $i -lt $n; $i++) { $payload[$i] = [byte](($i + 1) % 256) }

            $doubleComma = & $invokeOp { return ,,$payload }.GetNewClosure()
            ($doubleComma -is [byte[]]) | Should -BeTrue -Because "n=$n through the double-`&` boundary must survive as [byte[]] with a double leading comma"
            $doubleComma.Count | Should -Be $n

            $singleComma = & $invokeOp { return ,$payload }.GetNewClosure()
            ($singleComma -is [byte[]]) | Should -BeFalse -Because "n=$n through the SAME double-`&` boundary with only a SINGLE comma must NOT survive as [byte[]] (proves the double comma is load-bearing, not redundant)"
        }
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

    It 'RemoveHardDiskDrive THROWS when no attached drive has the path (never a silent success), leaving the other disks attached' {
        & $script:B.NewVHD @{ Path = 'C:\vhd\d1.vhdx'; SizeBytes = 40GB }
        & $script:B.AddHardDiskDrive @{ VMName = 'vm1'; Path = 'C:\vhd\d1.vhdx' }
        { & $script:B.RemoveHardDiskDrive @{ VMName = 'vm1'; Path = 'C:\vhd\never-attached.vhdx' } } |
            Should -Throw -ExpectedMessage "*no hard disk drive on 'vm1' has the path 'C:\vhd\never-attached.vhdx'; nothing was detached*"
        @((& $script:B.GetVM @{ Name = 'vm1' }).HardDrives) | Should -Be @('C:\vhd\d1.vhdx')
        # A second detach of the same path is the same refusal: the first one already took it off the VM.
        & $script:B.RemoveHardDiskDrive @{ VMName = 'vm1'; Path = 'C:\vhd\d1.vhdx' }
        { & $script:B.RemoveHardDiskDrive @{ VMName = 'vm1'; Path = 'C:\vhd\d1.vhdx' } } | Should -Throw -ExpectedMessage '*nothing was detached*'
        @($script:B.FakeCallLog | Where-Object { $_.Op -eq 'RemoveHardDiskDrive' }).Count | Should -Be 3 -Because 'every attempt is logged, refused ones included'
    }

    It 'NewVHD on a path that already exists THROWS (real New-VHD refuses to overwrite) and leaves the existing record as it was' {
        & $script:B.NewVHD @{ Path = 'C:\vhd\once.vhdx'; SizeBytes = 40GB }
        { & $script:B.NewVHD @{ Path = 'C:\vhd\once.vhdx'; SizeBytes = 1GB } } |
            Should -Throw -ExpectedMessage "*'C:\vhd\once.vhdx' already exists*"
        (& $script:B.GetVHDInfo @{ Path = 'C:\vhd\once.vhdx' }).SizeBytes | Should -Be 40GB
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
#  $script:SbAssertArg — array shape preservation across the & boundary (F2)
# ===========================================================================
# The helper is shared by BOTH factories (hoisted into each factory's locals), so testing it
# directly here — rather than only indirectly via a backend method — pins its contract once for
# both. See the scriptblock's own header comment (HyperVBackend.ps1) for the pipeline-unroll
# mechanism these tests exercise.
Describe '$script:SbAssertArg — array shape preservation across the & boundary (F2)' {

    It 'returns an intact 0-length [byte[]] for an empty array arg (not $null)' {
        $got = & $script:SbAssertArg @{ Bytes = [byte[]]@() } 'Bytes' 'X'
        ($got -is [byte[]]) | Should -BeTrue -Because 'a 0-length [byte[]] must survive the & boundary shape-intact, not unroll to $null'
        $got.Length | Should -Be 0
    }

    It 'returns an intact 1-element [byte[]] (no collapse to a bare scalar [byte])' {
        $got = & $script:SbAssertArg @{ Bytes = [byte[]]@(42) } 'Bytes' 'X'
        ($got -is [byte[]]) | Should -BeTrue -Because 'a 1-element [byte[]] must not collapse to a scalar [byte] crossing the & boundary'
        $got.Length | Should -Be 1
        $got[0] | Should -Be 42
    }

    It 'returns an intact n-element [byte[]] with values preserved (no re-collection to [object[]])' {
        $got = & $script:SbAssertArg @{ Bytes = [byte[]]@(1,2,3) } 'Bytes' 'X'
        ($got -is [byte[]]) | Should -BeTrue -Because 'an n-element [byte[]] must not re-collect as [object[]] crossing the & boundary'
        $got.Count | Should -Be 3
        [System.Linq.Enumerable]::SequenceEqual([byte[]]$got, [byte[]]@(1,2,3)) | Should -BeTrue
    }

    It 'returns a plain [string] arg unchanged (shape guard: the fix must not disturb the scalar case)' {
        $got = & $script:SbAssertArg @{ Name = 'vm1' } 'Name' 'X'
        ($got -is [string]) | Should -BeTrue
        $got | Should -Be 'vm1'
    }

    It 'returns a [hashtable] arg unchanged (shape guard: the fix must not disturb the dictionary case)' {
        $inner = @{ a = 1; b = 2 }
        $got = & $script:SbAssertArg @{ Cfg = $inner } 'Cfg' 'X'
        ($got -is [hashtable]) | Should -BeTrue
        $got.a | Should -Be 1
        $got.b | Should -Be 2
    }

    It 'still throws the required-argument-missing message for an absent key (unchanged refusal)' {
        { & $script:SbAssertArg @{ } 'Missing' 'SomeMethod' } |
            Should -Throw -ExpectedMessage "*required argument 'Missing' is missing*"
    }

    It 'still throws the required-argument-missing message for a present-but-$null value (unchanged refusal)' {
        { & $script:SbAssertArg @{ Missing = $null } 'Missing' 'SomeMethod' } |
            Should -Throw -ExpectedMessage "*required argument 'Missing' is missing*"
    }

    It 'still throws the required-argument-missing message for a whitespace-only string value (unchanged refusal)' {
        { & $script:SbAssertArg @{ Missing = '   ' } 'Missing' 'SomeMethod' } |
            Should -Throw -ExpectedMessage "*required argument 'Missing' is missing*"
    }
}

# ===========================================================================
#  $script:SbIsUnavailableError — name-scoped CommandNotFound classification (F3)
# ===========================================================================
# I5a lesson: EVERY real method's body runs inside $InvokeOp, which routes any caught error
# through this classifier. A BLANKET "any CommandNotFoundException is Hyper-V unavailable"
# branch would rebrand a closure-capture NameError (the I5a bug class — e.g. a renamed helper
# called by bare name from inside a .GetNewClosure()'d body) as a misleading "Hyper-V
# unavailable / insufficient privilege" message instead of surfacing the real
# CommandNotFoundException. So the classifier must be scoped by the missing command's NAME:
# only genuinely Hyper-V-cmdlet-shaped names (Get-VM, New-VHD, ...) classify as unavailable.
# Tested directly here (like $script:SbAssertArg above) so the contract is pinned once,
# independent of any one backend method's wiring.
Describe '$script:SbIsUnavailableError — name-scoped CommandNotFound classification (F3)' {

    BeforeAll {
        # A minimal stand-in exception living in the SAME namespace prefix the classifier
        # checks (Microsoft.HyperV.PowerShell*), so the tests below exercise the actual
        # '-like' namespace match instead of assuming it. Avoids depending on the real Hyper-V
        # module's internal VirtualizationException, which has no public constructor.
        if (-not ('Microsoft.HyperV.PowerShell.VoidsealTestException' -as [type])) {
            Add-Type -TypeDefinition @'
namespace Microsoft.HyperV.PowerShell {
    public class VoidsealTestException : System.Exception {
        public VoidsealTestException(string message) : base(message) {}
    }
}
'@
        }
    }

    It 'classifies a REAL CommandNotFoundException for a Hyper-V-shaped VM cmdlet name as unavailable' {
        $errorRecord = $null
        try { & 'Get-VMAbsentZz9' } catch { $errorRecord = $_ }
        $errorRecord.Exception | Should -BeOfType ([System.Management.Automation.CommandNotFoundException])
        (& $script:SbIsUnavailableError $errorRecord) | Should -BeTrue -Because 'Get-VM*-shaped missing commands are the Hyper-V-module-absent case'
    }

    It 'classifies a REAL CommandNotFoundException for a Hyper-V-shaped VHD cmdlet name as unavailable' {
        $errorRecord = $null
        try { & 'Mount-VHDAbsentZz9' } catch { $errorRecord = $_ }
        $errorRecord.Exception | Should -BeOfType ([System.Management.Automation.CommandNotFoundException])
        (& $script:SbIsUnavailableError $errorRecord) | Should -BeTrue -Because 'Mount-VHD*-shaped missing commands are the Hyper-V-module-absent case'
    }

    It 'does NOT classify a REAL CommandNotFoundException for a non-Hyper-V helper name as unavailable (the I5a closure-NameError class)' {
        $errorRecord = $null
        try { & 'Invoke-ConfinedQemuAbsentZz9' } catch { $errorRecord = $_ }
        $errorRecord.Exception | Should -BeOfType ([System.Management.Automation.CommandNotFoundException])
        (& $script:SbIsUnavailableError $errorRecord) | Should -BeFalse -Because 'a renamed/missing non-Hyper-V helper called from inside a closure must surface as its real CommandNotFoundException, not a mislabeled "Hyper-V unavailable"'
    }

    It 'does NOT classify a REAL CommandNotFoundException for an arbitrary non-Hyper-V name as unavailable' {
        $errorRecord = $null
        try { & 'Format-ThingAbsentZz9' } catch { $errorRecord = $_ }
        $errorRecord.Exception | Should -BeOfType ([System.Management.Automation.CommandNotFoundException])
        (& $script:SbIsUnavailableError $errorRecord) | Should -BeFalse
    }

    It 'still classifies a Microsoft.HyperV.PowerShell*-namespace permission-denied error as unavailable (existing behavior preserved)' {
        $ex = New-Object Microsoft.HyperV.PowerShell.VoidsealTestException('You do not have the required permission to complete this task.')
        $errorRecord = New-Object System.Management.Automation.ErrorRecord($ex, 'X', [System.Management.Automation.ErrorCategory]::PermissionDenied, $null)
        (& $script:SbIsUnavailableError $errorRecord) | Should -BeTrue
    }

    It 'still classifies a Microsoft.HyperV.PowerShell*-namespace service-down error as unavailable (existing behavior preserved)' {
        $ex = New-Object Microsoft.HyperV.PowerShell.VoidsealTestException('The Virtual Machine Management service is not running.')
        $errorRecord = New-Object System.Management.Automation.ErrorRecord($ex, 'X', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
        (& $script:SbIsUnavailableError $errorRecord) | Should -BeTrue
    }

    It 'still classifies generic permission phrasing from any exception layer as unavailable (existing behavior preserved)' {
        $ex = New-Object System.Exception('Access is denied. Run as Administrator or join Hyper-V Administrators.')
        $errorRecord = New-Object System.Management.Automation.ErrorRecord($ex, 'X', [System.Management.Automation.ErrorCategory]::PermissionDenied, $null)
        (& $script:SbIsUnavailableError $errorRecord) | Should -BeTrue
    }

    It 'still returns $false for an arbitrary unrelated exception (existing behavior preserved)' {
        $ex = New-Object System.InvalidOperationException('the widget is jammed')
        $errorRecord = New-Object System.Management.Automation.ErrorRecord($ex, 'X', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)
        (& $script:SbIsUnavailableError $errorRecord) | Should -BeFalse
    }

    It 'still returns $false for a $null ErrorRecord (existing behavior preserved)' {
        (& $script:SbIsUnavailableError $null) | Should -BeFalse
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

    It 'NewVM without a SwitchName still creates ONE unconnected adapter (real New-VM always does)' {
        # Microsoft Learn's New-VM reference (-SwitchName): Hyper-V gives every new VM one virtual network
        # adapter, and connecting it to a switch is optional. The fake used to create none, which hid every
        # no-NIC seal gap at Tier 0 (zero adapters on the fake, one on real Hyper-V).
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm1' }
        $nics.Count | Should -Be 1 -Because 'real New-VM creates exactly one adapter even with no -SwitchName'
        [string]$nics[0].SwitchName | Should -BeNullOrEmpty -Because 'with no -SwitchName the default adapter is not connected'
    }

    It 'NewVM WITH a SwitchName creates ONE adapter, already connected to that switch' {
        & $script:B.NewSwitch @{ Name = 'sw-new'; SwitchType = 'Internal' }
        & $script:B.NewVM @{ Name = 'vm2'; Generation = 2; SwitchName = 'sw-new' }
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm2' }
        $nics.Count | Should -Be 1
        $nics[0].SwitchName | Should -Be 'sw-new'
    }

    It 'ConnectNetworkAdapter CONNECTS the existing default adapter instead of adding a second one (real branch parity)' {
        # The real ConnectNetworkAdapter reads the VM's first adapter and calls Connect-VMNetworkAdapter when
        # one exists; it calls Add-VMNetworkAdapter only when the VM has none. A provisioned VM therefore
        # ends with exactly ONE adapter, on the switch.
        (& $script:B.GetNetworkAdapter @{ VMName = 'vm1' }).Count | Should -Be 1 -Because 'precondition: the default adapter exists'
        & $script:B.NewSwitch @{ Name = 'sw-int'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-int' }
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm1' }
        $nics.Count | Should -Be 1 -Because 'connecting reuses the default adapter; it must not append a second NIC'
        $nics[0].SwitchName | Should -Be 'sw-int'
    }

    It 'ConnectNetworkAdapter ADDS an adapter only when the VM has none (after a removal)' {
        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        & $script:B.NewSwitch @{ Name = 'sw-int'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-int' }
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm1' }
        $nics.Count | Should -Be 1
        $nics[0].SwitchName | Should -Be 'sw-int'
    }

    It 'RemoveNetworkAdapter on a VM with no adapters is an idempotent no-op (matches the hardened real method)' {
        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        { & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' } } | Should -Not -Throw
        (& $script:B.GetNetworkAdapter @{ VMName = 'vm1' }).Count | Should -Be 0
    }

    It 'ConnectNetworkAdapter binds the VM''s adapter to a switch; GetNetworkAdapter lists it' {
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
        # And no phantom binding was recorded: the VM still has only its default adapter, unconnected.
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm1' }
        $nics.Count | Should -Be 1 -Because 'the failed connect must not add an adapter'
        [string]$nics[0].SwitchName | Should -BeNullOrEmpty -Because 'the failed connect must not bind the default adapter to a phantom switch'
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

    # ---- adapter guards (SetNetworkAdapterGuards / GetNetworkAdapterGuards) ----
    It 'a new VM''s adapter carries Hyper-V''s guard defaults: MacAddressSpoofing, DhcpGuard and RouterGuard all Off' {
        $g = & $script:B.GetNetworkAdapterGuards @{ VMName = 'vm1' }
        $g.MacAddressSpoofing | Should -Be 'Off'
        $g.DhcpGuard          | Should -Be 'Off'
        $g.RouterGuard        | Should -Be 'Off'
    }

    It 'SetNetworkAdapterGuards records the three values and GetNetworkAdapterGuards reads them back' {
        & $script:B.SetNetworkAdapterGuards @{ VMName = 'vm1'; MacAddressSpoofing = 'Off'; DhcpGuard = 'On'; RouterGuard = 'On' }
        $g = & $script:B.GetNetworkAdapterGuards @{ VMName = 'vm1' }
        $g.MacAddressSpoofing | Should -Be 'Off'
        $g.DhcpGuard          | Should -Be 'On'
        $g.RouterGuard        | Should -Be 'On'
        # An adapter added by hand (no guard keys) reads the defaults, like a real adapter added outside the tool.
        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        (& $script:B.GetVM @{ Name = 'vm1' }).NetworkAdapters.Add(@{ SwitchName = $null; Name = 'Network Adapter' })
        (& $script:B.GetNetworkAdapterGuards @{ VMName = 'vm1' }).DhcpGuard | Should -Be 'Off'
    }

    It 'SetNetworkAdapterGuards rejects anything but ''On'' / ''Off'' (what the OnOffState enum accepts), leaving the adapter untouched, and requires all three' {
        { & $script:B.SetNetworkAdapterGuards @{ VMName = 'vm1'; MacAddressSpoofing = 'Off'; DhcpGuard = 'Yes'; RouterGuard = 'On' } } |
            Should -Throw -ExpectedMessage "*DhcpGuard must be 'On' or 'Off' (got 'Yes')*"
        { & $script:B.SetNetworkAdapterGuards @{ VMName = 'vm1'; MacAddressSpoofing = 'off'; DhcpGuard = 'On'; RouterGuard = 'On' } } |
            Should -Throw -ExpectedMessage "*MacAddressSpoofing must be 'On' or 'Off'*" -Because 'the compare is exact; the enum renders On and Off'
        (& $script:B.GetNetworkAdapterGuards @{ VMName = 'vm1' }).RouterGuard | Should -Be 'Off' -Because 'a rejected call changes nothing'
        { & $script:B.SetNetworkAdapterGuards @{ VMName = 'vm1'; MacAddressSpoofing = 'Off'; DhcpGuard = 'On' } } |
            Should -Throw -ExpectedMessage "*required argument 'RouterGuard'*"
    }

    It 'GetNetworkAdapterGuards THROWS when the VM has zero or two adapters (the gate must never pick one)' {
        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        { & $script:B.GetNetworkAdapterGuards @{ VMName = 'vm1' } } | Should -Throw -ExpectedMessage '*expected exactly one network adapter*found 0*'
        $vm = & $script:B.GetVM @{ Name = 'vm1' }
        $vm.NetworkAdapters.Add(@{ SwitchName = $null; Name = 'Network Adapter' })
        $vm.NetworkAdapters.Add(@{ SwitchName = $null; Name = 'Network Adapter 2' })
        { & $script:B.GetNetworkAdapterGuards @{ VMName = 'vm1' } } | Should -Throw -ExpectedMessage '*found 2*'
    }

    It 'SetNetworkAdapterGuards on a VM with no adapter is a no-op (nothing to set), and -SimulateAdapterGuardsStuck leaves the values as they were' {
        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        { & $script:B.SetNetworkAdapterGuards @{ VMName = 'vm1'; MacAddressSpoofing = 'Off'; DhcpGuard = 'On'; RouterGuard = 'On' } } | Should -Not -Throw
        $stuck = New-FakeHyperVBackend -SimulateAdapterGuardsStuck
        & $stuck.NewVM @{ Name = 'vm2'; Generation = 2 }
        & $stuck.SetNetworkAdapterGuards @{ VMName = 'vm2'; MacAddressSpoofing = 'Off'; DhcpGuard = 'On'; RouterGuard = 'On' }
        (& $stuck.GetNetworkAdapterGuards @{ VMName = 'vm2' }).DhcpGuard | Should -Be 'Off' -Because 'the set did not take'
        @($stuck.FakeCallLog | Where-Object { $_.Op -eq 'SetNetworkAdapterGuards' }).Count | Should -Be 1 -Because 'the attempt is still logged'
    }
}

# ===========================================================================
#  REAL RemoveNetworkAdapter: documented parameter sets only, idempotent (AST-pinned)
# ===========================================================================
#  Lock-Sandbox calls this on every NoAdapter seal (Tier 0, Tier >= 2, any processor). It has never run
#  live, so its body must rely only on documented cmdlet behavior: enumerate the adapters, then pipe the
#  objects to Remove-VMNetworkAdapter (the ResourceObject parameter set), and do nothing when there are
#  none. The real body cannot run in this non-elevated session, so pin it via the AST.
Describe 'RemoveNetworkAdapter: the REAL method uses only documented parameter sets and is idempotent (AST-pinned)' {

    BeforeAll {
        $script:RealRemoveNicAssign = & $script:GetRealBackendAssign 'RemoveNetworkAdapter'
    }

    # These pins walk AST nodes (CommandAst, PipelineAst, BinaryExpressionAst), not the method's source
    # text. A text regex also matched a comment, so deleting the call but leaving a comment that named it
    # still passed; the 'pin helpers' Describe below proves each helper rejects exactly that.
    It 'enumerates the adapters with Get-VMNetworkAdapter -VMName (the harness below proves the removal only receives what was enumerated)' {
        $script:RealRemoveNicAssign | Should -Not -BeNullOrEmpty -Because 'the real factory must define RemoveNetworkAdapter'
        @(& $script:PinFindCommand $script:RealRemoveNicAssign 'Get-VMNetworkAdapter' 'VMName').Count |
            Should -BeGreaterThan 0 -Because 'the adapters to remove are read from host truth first'
    }

    It 'removes by piping the adapter objects, never with Remove-VMNetworkAdapter -VMName' {
        @(& $script:PinFindPipedInto $script:RealRemoveNicAssign 'Remove-VMNetworkAdapter').Count |
            Should -BeGreaterThan 0 -Because 'piping adapter objects uses the documented ResourceObject parameter set'
        @(& $script:PinFindCommand $script:RealRemoveNicAssign 'Remove-VMNetworkAdapter' 'VMName').Count |
            Should -Be 0 -Because 'omitting -Name in the VMName set relies on undocumented remove-everything behavior'
    }

    It 'guards the removal on a non-zero adapter count (idempotent, like the fake)' {
        @(& $script:PinFindCountGuard $script:RealRemoveNicAssign).Count |
            Should -BeGreaterThan 0 -Because 'a VM with no adapters must be a no-op, as the fake already is'
    }
}

# ===========================================================================
#  The AST pin helpers fail when the pinned code is gone
# ===========================================================================
#  Each helper is run against a synthetic scriptblock where the call survives only in a comment or a string
#  (it must find nothing) and against one where the call is real (it must find it). This is the evidence
#  that a pin built on the helper fails when the pinned call is removed.
Describe 'AST pin helpers: comments and strings do not satisfy a pin' {

    It 'PinFindCommand: a commented-out or quoted call is not a call; a real one is' {
        $gone = { # Get-VMGpuPartitionAdapter -VMName $vm
                  $note = 'Get-VMGpuPartitionAdapter -VMName $vm'
                  return ,@() }.Ast
        $here = { return ,@(Get-VMGpuPartitionAdapter -VMName $vm -ErrorAction Stop) }.Ast
        @(& $script:PinFindCommand $gone 'Get-VMGpuPartitionAdapter' 'VMName').Count | Should -Be 0
        @(& $script:PinFindCommand $here 'Get-VMGpuPartitionAdapter' 'VMName').Count | Should -Be 1
        @(& $script:PinFindCommand $here 'Get-VMGpuPartitionAdapter' 'Name').Count   | Should -Be 0 -Because 'the parameter filter is exact'
    }

    It 'PinFindPipedInto: only a real pipeline into the command counts' {
        $gone = { # $nics | Remove-VMNetworkAdapter
                  Remove-VMNetworkAdapter -VMName $vm }.Ast
        $here = { $nics | Remove-VMNetworkAdapter -ErrorAction Stop }.Ast
        @(& $script:PinFindPipedInto $gone 'Remove-VMNetworkAdapter').Count | Should -Be 0
        @(& $script:PinFindPipedInto $here 'Remove-VMNetworkAdapter').Count | Should -Be 1
    }

    It 'PinFindCountGuard: only a real `.Count -gt 0` comparison counts' {
        $gone = { # if ($nics.Count -gt 0) { }
                  if ($nics) { } }.Ast
        $here = { if ($nics.Count -gt 0) { } }.Ast
        @(& $script:PinFindCountGuard $gone).Count | Should -Be 0
        @(& $script:PinFindCountGuard $here).Count | Should -Be 1
    }

    It 'PinFindCommaReturn: only a real `return ,@(...)` counts' {
        $gone = { # return ,@(Get-Thing)
                  return @(Get-Thing) }.Ast
        $here = { return ,@(Get-Thing) }.Ast
        @(& $script:PinFindCommaReturn $gone).Count | Should -Be 0
        @(& $script:PinFindCommaReturn $here).Count | Should -Be 1
    }
}

# ===========================================================================
#  Passthrough-device reads: GetGpuPartitionAdapters + GetAssignableDevices
# ===========================================================================
#  Host-truth reads for the seal gate's passthrough refusal. A GPU partition adapter exposes the host
#  GPU driver stack; a device assigned by Discrete Device Assignment can be a physical NIC that
#  GetNetworkAdapter never lists. The real bodies cannot run in this non-elevated session, so they are
#  pinned via the AST; the fake carries the behavioral checks.
Describe 'Passthrough-device reads: GetGpuPartitionAdapters + GetAssignableDevices (real/fake parity; AST-pinned real)' {

    It 'the manifest documents both reads taking exactly VMName' {
        foreach ($m in 'GetGpuPartitionAdapters', 'GetAssignableDevices') {
            $script:ExpectedMethods.Keys | Should -Contain $m
            @($script:ExpectedMethods[$m]) | Should -Be @('VMName')
        }
    }

    It 'the REAL <Method> calls <Cmdlet> -VMName and returns a ,@(...) collection (AST nodes, not text)' -ForEach @(
        @{ Method = 'GetGpuPartitionAdapters'; Cmdlet = 'Get-VMGpuPartitionAdapter' },
        @{ Method = 'GetAssignableDevices';    Cmdlet = 'Get-VMAssignableDevice' }
    ) {
        $assign = & $script:GetRealBackendAssign $Method
        $assign | Should -Not -BeNullOrEmpty -Because "the real factory must define $Method"
        @(& $script:PinFindCommand $assign $Cmdlet 'VMName').Count | Should -BeGreaterThan 0 -Because "the read must invoke $Cmdlet for the VM it was given"
        @(& $script:PinFindCommaReturn $assign).Count | Should -BeGreaterThan 0 -Because 'a single item must keep .Count = 1 for an unwrapped caller'
    }

    It 'the FAKE reports none by default, as arrays (no caller @() wrap needed)' {
        $b = New-FakeHyperVBackend
        & $b.NewVM @{ Name = 'vm1'; Generation = 2 }
        $gpu = & $b.GetGpuPartitionAdapters @{ VMName = 'vm1' }
        $dda = & $b.GetAssignableDevices    @{ VMName = 'vm1' }
        $gpu.Count | Should -Be 0
        $dda.Count | Should -Be 0
        ,$gpu | Should -BeOfType [System.Array]
        ,$dda | Should -BeOfType [System.Array]
    }

    It 'the FAKE reports a seeded device with .Count = 1 (single-element array semantics)' {
        $b = New-FakeHyperVBackend
        & $b.NewVM @{ Name = 'vm1'; Generation = 2 }
        $vm = & $b.GetVM @{ Name = 'vm1' }
        $vm.GpuPartitionAdapters.Add(@{ Id = 'gpu-p-0' })
        $vm.AssignableDevices.Add(@{ LocationPath = 'PCIROOT(0)#PCI(0300)' })
        (& $b.GetGpuPartitionAdapters @{ VMName = 'vm1' }).Count | Should -Be 1
        (& $b.GetAssignableDevices    @{ VMName = 'vm1' }).Count | Should -Be 1
    }

    It 'the FAKE throws for an unknown VM, like the other per-VM reads' {
        $b = New-FakeHyperVBackend
        { & $b.GetGpuPartitionAdapters @{ VMName = 'ghost' } } | Should -Throw -ExpectedMessage '*ghost*'
        { & $b.GetAssignableDevices    @{ VMName = 'ghost' } } | Should -Throw -ExpectedMessage '*ghost*'
    }

    It 'the Sealer never invokes either cmdlet directly (the reads live only behind the backend seam)' {
        $sealerPath = Join-Path $script:SkillRoot 'scripts/lib/Sealer.ps1'
        $sTokens = $null; $sErrors = $null
        $sealerAst = [System.Management.Automation.Language.Parser]::ParseFile($sealerPath, [ref]$sTokens, [ref]$sErrors)
        @($sErrors).Count | Should -Be 0 -Because 'the Sealer must parse cleanly'
        $raw = $sealerAst.FindAll({
            param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                      $n.GetCommandName() -in @('Get-VMGpuPartitionAdapter', 'Get-VMAssignableDevice')
        }, $true)
        @($raw).Count | Should -Be 0 -Because 'the Sealer reads passthrough state through the backend, never a raw cmdlet'
    }
}

# ===========================================================================
#  Seal-device methods: the REAL bodies, executed out of process against stub cmdlets
# ===========================================================================
#  The AST pins check the text; this runs the real bodies. A child pwsh dot-sources the lib beside
#  recording stubs (the only interception that reaches a real closure) and prints what happened.
Describe 'Seal-device methods: the REAL bodies, executed out of process against stub cmdlets' {

    BeforeAll {
        $harness = Join-Path $PSScriptRoot 'fixtures/Invoke-RealSealDeviceCapture.ps1'
        Test-Path $harness | Should -BeTrue -Because 'the out-of-process seal-device harness must exist'
        $pwsh = (Get-Process -Id $PID).Path   # the exact pwsh running these tests
        if ([string]::IsNullOrWhiteSpace($pwsh)) { $pwsh = 'pwsh' }
        $raw = & $pwsh -NoProfile -File $harness -LibPath $script:LibPath 2>&1
        $rawText = ($raw | Out-String).Trim()
        $jsonLine = ($rawText -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
        $jsonLine | Should -Not -BeNullOrEmpty -Because "the harness must emit JSON; got: $rawText"
        $script:SealDevCap = $jsonLine | ConvertFrom-Json
    }

    It 'RemoveNetworkAdapter on a VM with no adapter: enumerates it, removes nothing, does not throw' {
        $script:SealDevCap.Remove_None.err | Should -BeNullOrEmpty
        $script:SealDevCap.Remove_None.enumeratedVM | Should -Be 'vm1'
        @($script:SealDevCap.Remove_None.removed).Count | Should -Be 0 -Because 'an idempotent removal must not call the cmdlet when there is nothing to remove'
    }

    It 'RemoveNetworkAdapter on a VM with one adapter: pipes exactly that adapter to the removal' {
        $script:SealDevCap.Remove_One.err | Should -BeNullOrEmpty
        @($script:SealDevCap.Remove_One.removed) | Should -Be @('nic-0')
    }

    It 'RemoveNetworkAdapter on a VM with two adapters: pipes both, and never names the VM on the removal' {
        $script:SealDevCap.Remove_Two.err | Should -BeNullOrEmpty
        @($script:SealDevCap.Remove_Two.removed) | Should -Be @('nic-0', 'nic-1')
        $script:SealDevCap.Remove_Two.anyByVMName | Should -BeFalse -Because 'removal goes through the piped adapter objects, not the VMName parameter set'
    }

    It 'ConnectNetworkAdapter on a VM that has its default adapter: CONNECTS it and adds nothing (the production path)' {
        $script:SealDevCap.Connect_Default.err | Should -BeNullOrEmpty
        @($script:SealDevCap.Connect_Default.connected) | Should -Be @('vm1>sw0')
        @($script:SealDevCap.Connect_Default.added).Count | Should -Be 0 -Because 'real New-VM always leaves an adapter, so the provisioner must reuse it rather than add a second'
    }

    It 'ConnectNetworkAdapter on a VM with no adapter: ADDS one bound to the switch and connects nothing' {
        $script:SealDevCap.Connect_None.err | Should -BeNullOrEmpty
        @($script:SealDevCap.Connect_None.added) | Should -Be @('vm1>sw0')
        @($script:SealDevCap.Connect_None.connected).Count | Should -Be 0
    }

    It 'GetGpuPartitionAdapters returns an ARRAY with .Count 0, 1 and 2 for 0, 1 and 2 adapters (no caller @() wrap)' {
        foreach ($case in @(@{ Key = 'Gpu_None'; N = 0 }, @{ Key = 'Gpu_One'; N = 1 }, @{ Key = 'Gpu_Two'; N = 2 })) {
            $c = $script:SealDevCap.($case.Key)
            $c.err       | Should -BeNullOrEmpty
            $c.queriedVM | Should -Be 'vm1' -Because "$($case.Key): the real body must query the VM it was asked about"
            $c.isArray   | Should -BeTrue -Because "$($case.Key): a single adapter must not unroll to a bare object across the two & boundaries"
            $c.count     | Should -Be $case.N
        }
    }

    It 'GetAssignableDevices returns an ARRAY with .Count 0 and 1 for 0 and 1 devices (no caller @() wrap)' {
        foreach ($case in @(@{ Key = 'Dda_None'; N = 0 }, @{ Key = 'Dda_One'; N = 1 })) {
            $c = $script:SealDevCap.($case.Key)
            $c.err       | Should -BeNullOrEmpty
            $c.queriedVM | Should -Be 'vm1' -Because "$($case.Key): the real body must query the VM it was asked about"
            $c.isArray   | Should -BeTrue -Because "$($case.Key): a single device must not unroll to a bare object"
            $c.count     | Should -Be $case.N
        }
    }

    It 'GetComPort returns $null for an empty COM2 and the pipe record for a wired one, reading the port it was asked for' {
        $script:SealDevCap.Com2_Empty.err    | Should -BeNullOrEmpty
        $script:SealDevCap.Com2_Empty.read   | Should -Be 'vm1#2'
        $script:SealDevCap.Com2_Empty.isNull | Should -BeTrue -Because 'an empty COM2 path is not a live channel'
        $script:SealDevCap.Com2_Path.err     | Should -BeNullOrEmpty
        $script:SealDevCap.Com2_Path.number  | Should -Be 2
        $script:SealDevCap.Com2_Path.path    | Should -Be '\\.\pipe\extra'
        $script:SealDevCap.Com1_Path.path    | Should -Be '\\.\pipe\vm1-com1' -Because 'the COM1 read is unchanged'
    }

    It 'GetComPort THROWS when Get-VMComPort fails (never reads an unreadable COM2 as "no path")' {
        # The stub reports a non-terminating error like a real cmdlet. Under the old -ErrorAction
        # SilentlyContinue this came back $null with no error, which the COM2 refusal would read as clean.
        $script:SealDevCap.Com2_Fail.err  | Should -Match 'simulated Get-VMComPort failure'
        $script:SealDevCap.Com2_Fail.read | Should -Be 'vm1#2'
    }

    It 'GetAutomaticCheckpoints returns the real [bool] off Get-VM, $false and $true alike' {
        $script:SealDevCap.AutoCp_Off.err    | Should -BeNullOrEmpty
        $script:SealDevCap.AutoCp_Off.isBool | Should -BeTrue
        $script:SealDevCap.AutoCp_Off.value  | Should -BeFalse
        $script:SealDevCap.AutoCp_On.value   | Should -BeTrue
    }

    It 'GetAutomaticCheckpoints THROWS on a missing property, a non-boolean value, zero or two VMs, and a failed Get-VM' {
        $script:SealDevCap.AutoCp_NoProp.err | Should -BeLike '*reported no boolean AutomaticCheckpointsEnabled*'
        $script:SealDevCap.AutoCp_String.err | Should -BeLike '*reported no boolean AutomaticCheckpointsEnabled*' -Because 'the string False is truthy and must never be coerced'
        $script:SealDevCap.AutoCp_NoVM.err   | Should -BeLike '*expected exactly one VM*found 0*'
        $script:SealDevCap.AutoCp_TwoVMs.err | Should -BeLike '*expected exactly one VM*found 2*'
        $script:SealDevCap.AutoCp_Fail.err   | Should -Match 'simulated Get-VM failure' -Because 'a non-terminating Get-VM error must surface (-ErrorAction Stop)'
    }

    It 'GetCheckpoint returns an ARRAY for 0 and 1 checkpoints, and THROWS when Get-VMSnapshot fails' {
        $script:SealDevCap.CpList_None.isArray | Should -BeTrue
        $script:SealDevCap.CpList_None.count   | Should -Be 0
        $script:SealDevCap.CpList_One.isArray  | Should -BeTrue -Because 'a single checkpoint must not unroll to a bare object'
        $script:SealDevCap.CpList_One.count    | Should -Be 1
        $script:SealDevCap.CpList_Fail.err     | Should -Match 'simulated Get-VMSnapshot failure' -Because 'an unreadable checkpoint list must not read as empty'
    }

    It 'a failing passthrough cmdlet propagates as a throw (the gate turns it into a refusal)' {
        $script:SealDevCap.Gpu_Throw.err | Should -Match 'simulated Get-VMGpuPartitionAdapter failure'
        $script:SealDevCap.Gpu_Throw.queriedVM | Should -Be 'vm1' -Because 'the throwing cmdlet was still asked about the right VM'
    }

    It 'RemoveHardDiskDrive detaches exactly the drive with the path, and THROWS when no attached drive has it' {
        $script:SealDevCap.Detach_Match.err | Should -BeNullOrEmpty
        @($script:SealDevCap.Detach_Match.removed) | Should -Be @('C:\s\b.vhdx')
        $script:SealDevCap.Detach_NoMatch.err | Should -BeLike "*no hard disk drive on 'vm1' has the path 'C:\s\c.vhdx'; nothing was detached*"
        @($script:SealDevCap.Detach_NoMatch.removed).Count | Should -Be 0
        $script:SealDevCap.Detach_None.err | Should -BeLike '*nothing was detached*' -Because 'a VM with no drives at all is the same refusal'
    }

    It 'SetNetworkAdapterGuards passes the VM name and the three values through to Set-VMNetworkAdapter, and refuses a value the enum would reject before calling it' {
        $c = $script:SealDevCap.Guards_Set
        $c.err | Should -BeNullOrEmpty
        $c.call.VMName             | Should -Be 'vm1'
        $c.call.MacAddressSpoofing | Should -Be 'Off'
        $c.call.DhcpGuard          | Should -Be 'On'
        $c.call.RouterGuard        | Should -Be 'On'
        $script:SealDevCap.Guards_SetBad.err    | Should -Match "RouterGuard must be 'On' or 'Off'"
        $script:SealDevCap.Guards_SetBad.called | Should -BeFalse -Because 'the value is refused before the cmdlet runs'
    }

    It 'GetNetworkAdapterGuards reads the one adapter''s guards as On/Off text off the enum properties' {
        $c = $script:SealDevCap.Guards_GetOne
        $c.err | Should -BeNullOrEmpty
        $c.queriedVM | Should -Be 'vm1'
        $c.result.MacAddressSpoofing | Should -Be 'Off'
        $c.result.DhcpGuard          | Should -Be 'On'
        $c.result.RouterGuard        | Should -Be 'On'
        $c.types | Should -Be 'String,String,String' -Because 'the enum values are rendered as text for the gate to compare exactly'
    }

    It 'GetNetworkAdapterGuards THROWS for zero or two adapters, for an adapter without a guard property, and for a failing enumeration' {
        $script:SealDevCap.Guards_GetNone.err   | Should -BeLike '*expected exactly one network adapter*found 0*'
        $script:SealDevCap.Guards_GetTwo.err    | Should -BeLike '*expected exactly one network adapter*found 2*'
        $script:SealDevCap.Guards_GetNoProp.err | Should -BeLike '*reports no RouterGuard value*'
        $script:SealDevCap.Guards_GetFail.err   | Should -Match 'simulated Get-VMNetworkAdapter failure'
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

    It 'a ConnectNetworkAdapter after a checkpoint does not leak into the snapshot (in-place NIC write stays isolated)' {
        # The fake's ConnectNetworkAdapter rewrites an existing adapter in place, and GetNetworkAdapter hands
        # back live records. The checkpoint deep-copies, so the snapshot must still show the old switch.
        & $script:B.NewSwitch @{ Name = 'sw-a'; SwitchType = 'Internal' }
        & $script:B.NewSwitch @{ Name = 'sw-b'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-a' }
        & $script:B.Checkpoint @{ VMName = 'vm1'; SnapshotName = 'on-a' }

        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-b' }
        (& $script:B.GetNetworkAdapter @{ VMName = 'vm1' })[0].SwitchName | Should -Be 'sw-b'

        & $script:B.RestoreCheckpoint @{ VMName = 'vm1'; SnapshotName = 'on-a' }
        (& $script:B.GetNetworkAdapter @{ VMName = 'vm1' })[0].SwitchName | Should -Be 'sw-a' -Because 'the snapshot was taken while the adapter sat on sw-a'

        # Mutating the restored record must not reach back into the stored snapshot either.
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-b' }
        & $script:B.RestoreCheckpoint @{ VMName = 'vm1'; SnapshotName = 'on-a' }
        (& $script:B.GetNetworkAdapter @{ VMName = 'vm1' })[0].SwitchName | Should -Be 'sw-a' -Because 'a second restore must still find the snapshot untouched'
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
        # A fresh VM carries its default adapter (real New-VM parity); remove it to reach the no-NIC state.
        & $script:B.RemoveNetworkAdapter @{ VMName = 'vm1' }
        $nics = & $script:B.GetNetworkAdapter @{ VMName = 'vm1' }
        $nics.Count | Should -Be 0
    }

    It 'GetNetworkAdapter reports the right Count for multiple NICs (no caller @() wrap)' {
        # Connect the default adapter, then seed a second adapter straight onto the fake VM record (the
        # record-mutation idiom Sealer.Tests.ps1 uses). ConnectNetworkAdapter reuses an existing adapter
        # rather than appending one, so it cannot build a two-NIC VM on its own.
        & $script:B.NewSwitch @{ Name = 'sw-a'; SwitchType = 'Internal' }
        & $script:B.NewSwitch @{ Name = 'sw-b'; SwitchType = 'Internal' }
        & $script:B.ConnectNetworkAdapter @{ VMName = 'vm1'; SwitchName = 'sw-a' }
        (& $script:B.GetVM @{ Name = 'vm1' }).NetworkAdapters.Add(@{ SwitchName = 'sw-b'; Name = 'Network Adapter 2' })
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
#  REAL backend — ReadVhdxRawRegion rides out a transient detach SETTLE-LAG lock (RC8/MUST-FIX 1)
# ===========================================================================
#  Mirror of the SbInvokeFirmwareWithRetry pattern. The real ReadVhdxRawRegion's qemu-img convert can
#  hit a sub-second SHARING VIOLATION when Remove-VMHardDiskDrive / Stop-VM has returned but the Hyper-V
#  worker-process handle on the .vhdx has not yet been released (a fresh RC8 — a SUCCESSFUL run that
#  spuriously fails on the first open). The convert is wrapped in the shared $script:SbInvokeWithLockRetry
#  helper: a LOCK-CLASS error is retried (the handle is releasing), any OTHER error rethrows immediately,
#  and exhaustion fails closed with a clear "...still locked after N attempts..." message. Factored out so
#  it is UNIT-testable in-process (drive it with a stub Operation that throws a lock-class error N times
#  then returns a sentinel) WITHOUT a live VM — exactly the path the real ReadVhdxRawRegion uses. The FAKE
#  models the same bounded tolerance via -SimulateDetachSettleLag (see the fake-axes Describe below); the
#  two budgets share the SAME default MaxAttempts (5) so they agree.
Describe 'Real backend — ReadVhdxRawRegion rides out a transient detach settle-lag lock (RC8; lock-retry helper)' {

    It 'exposes the shared lock-retry helper scriptblock' {
        $script:SbInvokeWithLockRetry | Should -BeOfType [scriptblock] -Because 'the real ReadVhdxRawRegion factors its convert retry through this shared helper so it is unit-testable'
    }

    It 'SUCCEEDS without retry when the operation succeeds first try' {
        $script:lockCalls = 0
        { & $script:SbInvokeWithLockRetry -Operation { $script:lockCalls++; 'OK' } -MaxAttempts 5 -DelayMilliseconds 1 } | Should -Not -Throw
        $script:lockCalls | Should -Be 1 -Because 'a first-try success must not retry'
    }

    It 'RETRIES a lock-class error (sharing violation) N times then returns the sentinel for N < MaxAttempts' {
        $script:lockCalls = 0
        $op = {
            $script:lockCalls++
            if ($script:lockCalls -lt 3) { throw 'qemu-img: Could not open: The process cannot access the file because it is being used by another process.' }
            'SENTINEL'   # third attempt succeeds
        }
        $result = & $script:SbInvokeWithLockRetry -Operation $op -MaxAttempts 5 -DelayMilliseconds 1
        $script:lockCalls | Should -Be 3 -Because 'it must keep retrying the transient lock until the handle releases'
        $result | Should -Be 'SENTINEL' -Because 'a lag WITHIN budget must return the operation result'
    }

    It 'after exhausting retries on a lock-class error (N >= MaxAttempts), throws a fail-closed message naming the unreleased handle' {
        $script:lockCalls = 0
        $op = { $script:lockCalls++; throw 'sharing violation' }
        $msg = $null
        try { & $script:SbInvokeWithLockRetry -Operation $op -MaxAttempts 3 -DelayMilliseconds 1 } catch { $msg = $_.Exception.Message }
        $script:lockCalls | Should -Be 3 -Because 'all attempts must be spent before failing closed'
        $msg | Should -Not -BeNullOrEmpty
        $msg | Should -Match '(?i)still locked' -Because 'the message must name the persistent-lock condition'
        $msg | Should -Match '(?i)(handle|released|detach)' -Because 'the remediation is that the VHDX handle was not released after detach'
        $msg | Should -Match '(?i)failing closed' -Because 'an unresolved lock fails closed, never silently'
    }

    It 'does NOT retry an UNRELATED error — it rethrows immediately (no masking malformed-image failures)' {
        $script:lockCalls = 0
        $op = { $script:lockCalls++; throw 'qemu-img: error while reading sector: Invalid argument (a malformed image, not a lock)' }
        { & $script:SbInvokeWithLockRetry -Operation $op -MaxAttempts 5 -DelayMilliseconds 1 } |
            Should -Throw -ExpectedMessage '*malformed image*'
        $script:lockCalls | Should -Be 1 -Because 'a malformed-image error is not transient; retrying would mask the real cause'
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

# ===========================================================================
#  GetVhdxImageHash — whole-image deps fingerprint (fake axes + real never-mounts)
# ===========================================================================
Describe 'GetVhdxImageHash — whole-image deps fingerprint (fake axes + real never-mounts)' {
    BeforeAll {
        function script:New-DepsFake([byte[]] $blob, [int] $lag = 0, [string] $vm = 'b1', [string] $disk = 'C:\s\deps.vhdx') {
            $f = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateDepsImageBlob $blob -SimulateDetachSettleLag $lag
            & $f.NewVM @{ Name = $vm; Generation = 2 }
            & $f.SetAutomaticCheckpoints @{ VMName = $vm; Enabled = $false }
            & $f.NewOutputVhdx @{ Path = $disk; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
            & $f.AddHardDiskDrive @{ VMName = $vm; Path = $disk }
            return $f
        }
        # No -SimulateSelfPowerOff: StartVM leaves State='Running' (the live worker holds the lock). The deps
        # blob is NOT recorded without SelfPowerOff, but the *locked*/Off-but-attached tests only assert a
        # throw / a successful (possibly empty) hash, so that is fine.
        function script:New-DepsFakeRunning([string] $vm = 'br', [string] $disk = 'C:\s\depsr.vhdx') {
            $f = New-FakeHyperVBackend
            & $f.NewVM @{ Name = $vm; Generation = 2 }
            & $f.SetAutomaticCheckpoints @{ VMName = $vm; Enabled = $false }
            & $f.NewOutputVhdx @{ Path = $disk; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
            & $f.AddHardDiskDrive @{ VMName = $vm; Path = $disk }
            return $f
        }
    }
    It 'AXIS 1: hashing a disk attached to a RUNNING VM throws *locked* (live worker holds the lock; real never says *still attached*)' {
        # FIX-2: gate on the holder State. A Running holder => sharing violation => $LockRetry => *locked*.
        # (The pre-fix fake threw *still attached* for ANY attach regardless of State; the real never does.)
        $f = New-DepsFakeRunning
        & $f.StartVM @{ Name = 'br' }   # no SelfPowerOff -> State='Running', disk still attached
        { & $f.GetVhdxImageHash @{ Path = 'C:\s\depsr.vhdx' } } | Should -Throw -ExpectedMessage '*locked*'
    }
    It 'AXIS 1 (FIX-2): an OFF-but-attached disk is OpenRead-able -> returns a hash (the real allows it; the builder post-power-off pre-detach window)' {
        # NewVM + NewOutputVhdx + AddHardDiskDrive, but NO StartVM: State stays 'Off' while the disk is still
        # attached. The real OpenReads (no live vmwp handle) and returns a hash; the fake must too (pre-fix it
        # over-strictly refused). Empty image -> SHA-256 of zero bytes (the canonical empty digest).
        $f = New-DepsFakeRunning 'boff' 'C:\s\depsoff.vhdx'
        $h = & $f.GetVhdxImageHash @{ Path = 'C:\s\depsoff.vhdx' }   # must NOT throw (proven by reaching here)
        $h | Should -BeOfType ([string])
        $h | Should -Match '^[0-9a-f]{64}$'
    }
    It 'AXIS 1+3: after detach, returns the SHA-256 of the recorded bytes; deterministic; FakeCallLog proves detach precedes hash' {
        $f = New-DepsFake ([byte[]](1..32))
        & $f.StartVM @{ Name = 'b1' }
        & $f.RemoveHardDiskDrive @{ VMName = 'b1'; Path = 'C:\s\deps.vhdx' }
        $h1 = & $f.GetVhdxImageHash @{ Path = 'C:\s\deps.vhdx' }
        $h2 = & $f.GetVhdxImageHash @{ Path = 'C:\s\deps.vhdx' }
        $h1 | Should -Be $h2
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $want = [System.BitConverter]::ToString($sha.ComputeHash([byte[]](1..32))).Replace('-','').ToLowerInvariant()
        $sha.Dispose()
        $h1 | Should -Be $want
        $ops = @($f.FakeCallLog | Where-Object { $_.Path -eq 'C:\s\deps.vhdx' } | ForEach-Object { $_.Op })
        ($ops.IndexOf('RemoveHardDiskDrive')) | Should -BeLessThan ($ops.IndexOf('GetVhdxImageHash'))
    }
    It 'RC7 (fake≠real symmetry): checkpoints LEFT ON -> deps land in the .avhdx child -> a host BASE-file hash sees SHA256(empty); checkpoints OFF -> the real deps hash' {
        # The signature RC7 model: the real GetVhdxImageHash OpenReads the BASE OutputDiskPath. If
        # AutomaticCheckpointsEnabled is ON at StartVM, the guest's deps land in the per-disk .avhdx CHILD
        # layer; a host BASE-file hash sees an EMPTY base. The fake models that by routing the blob to
        # DepsImageChildLayer (which GetVhdxImageHash does NOT read) when checkpoints are ON. Build the
        # fake WITHOUT calling SetAutomaticCheckpoints Enabled=$false (a fresh fake VM mirrors Hyper-V's
        # real default = ON) and prove the hash is SHA256 of EMPTY — the exact empty-hash RC7 bug.
        $blob = [byte[]](1..32)
        $emptyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

        # --- checkpoints ON (RC7 NOT fixed): blob hidden in the child -> base hash is SHA256(empty) ---
        $fOn = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateDepsImageBlob $blob
        & $fOn.NewVM @{ Name = 'rc7on'; Generation = 2 }                              # AutomaticCheckpointsEnabled defaults to $true (Hyper-V default)
        (& $fOn.GetVM @{ Name = 'rc7on' }).AutomaticCheckpointsEnabled | Should -BeTrue -Because 'a fresh fake VM mirrors Hyper-V''s checkpoints-ON default'
        & $fOn.NewOutputVhdx @{ Path = 'C:\s\rc7on.vhdx'; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
        & $fOn.AddHardDiskDrive @{ VMName = 'rc7on'; Path = 'C:\s\rc7on.vhdx' }
        & $fOn.StartVM @{ Name = 'rc7on' }
        & $fOn.RemoveHardDiskDrive @{ VMName = 'rc7on'; Path = 'C:\s\rc7on.vhdx' }
        (& $fOn.GetVhdxImageHash @{ Path = 'C:\s\rc7on.vhdx' }) |
            Should -Be $emptyHash -Because 'checkpoints ON -> deps in the .avhdx child -> the host BASE-file hash sees deps-EMPTY base (RC7)'

        # --- checkpoints OFF (the RC7 fix): blob in the base -> the real deps hash ---
        $fOff = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateDepsImageBlob $blob
        & $fOff.NewVM @{ Name = 'rc7off'; Generation = 2 }
        & $fOff.SetAutomaticCheckpoints @{ VMName = 'rc7off'; Enabled = $false }      # the provisioner/builder RC7 fix
        & $fOff.NewOutputVhdx @{ Path = 'C:\s\rc7off.vhdx'; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
        & $fOff.AddHardDiskDrive @{ VMName = 'rc7off'; Path = 'C:\s\rc7off.vhdx' }
        & $fOff.StartVM @{ Name = 'rc7off' }
        & $fOff.RemoveHardDiskDrive @{ VMName = 'rc7off'; Path = 'C:\s\rc7off.vhdx' }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $want = [System.BitConverter]::ToString($sha.ComputeHash($blob)).Replace('-','').ToLowerInvariant(); $sha.Dispose()
        (& $fOff.GetVhdxImageHash @{ Path = 'C:\s\rc7off.vhdx' }) |
            Should -Be $want -Because 'checkpoints OFF -> deps in the base -> the host hash sees them'
        $want | Should -Not -Be $emptyHash -Because 'the non-empty deps hash must differ from SHA256(empty) for the RC7 contrast to be meaningful'
    }
    It 'AXIS 3: a DIFFERENT deps blob yields a DIFFERENT hash (tamper-sensitive)' {
        $fa = New-DepsFake ([byte[]](1..32)) 0 'ba' 'C:\s\a.vhdx'
        $fb = New-DepsFake ([byte[]](100..131)) 0 'bb' 'C:\s\b.vhdx'
        & $fa.StartVM @{ Name='ba' }; & $fa.RemoveHardDiskDrive @{ VMName='ba'; Path='C:\s\a.vhdx' }
        & $fb.StartVM @{ Name='bb' }; & $fb.RemoveHardDiskDrive @{ VMName='bb'; Path='C:\s\b.vhdx' }
        (& $fa.GetVhdxImageHash @{ Path='C:\s\a.vhdx' }) | Should -Not -Be (& $fb.GetVhdxImageHash @{ Path='C:\s\b.vhdx' })
    }
    It 'AXIS 2: settle-lag WITHIN budget rides out; EXCEEDING budget throws *still locked*' {
        $f3 = New-DepsFake ([byte[]](1..8)) 3 'bl' 'C:\s\dl.vhdx'
        & $f3.StartVM @{ Name='bl' }; & $f3.RemoveHardDiskDrive @{ VMName='bl'; Path='C:\s\dl.vhdx' }
        { & $f3.GetVhdxImageHash @{ Path='C:\s\dl.vhdx' } } | Should -Not -Throw
        $f7 = New-DepsFake ([byte[]](1..8)) 7 'bl2' 'C:\s\dl2.vhdx'
        & $f7.StartVM @{ Name='bl2' }; & $f7.RemoveHardDiskDrive @{ VMName='bl2'; Path='C:\s\dl2.vhdx' }
        { & $f7.GetVhdxImageHash @{ Path='C:\s\dl2.vhdx' } } | Should -Throw -ExpectedMessage '*still locked*'
    }
    It 'AXIS 2 BOUNDARY (FIX-1): lag=4 (== MaxAttempts-1) is tolerated; lag=5 (== MaxAttempts) fails closed *still locked*' {
        # The real $SbInvokeWithLockRetry (increment-then-compare, MaxAttempts=5) tolerates 4 transient
        # lock-failures and throws on the 5th attempt. Pin the exact edge: 4 must NOT throw, 5 must. (Pre-fix
        # the fake's check-before-decrement tolerated 5 and threw at 6 — one off, mock-green where real fails.)
        $f4 = New-DepsFake ([byte[]](1..8)) 4 'be4' 'C:\s\dl4.vhdx'
        & $f4.StartVM @{ Name='be4' }; & $f4.RemoveHardDiskDrive @{ VMName='be4'; Path='C:\s\dl4.vhdx' }
        { & $f4.GetVhdxImageHash @{ Path='C:\s\dl4.vhdx' } } | Should -Not -Throw -Because 'lag=4 == MaxAttempts-1 is the real''s tolerance'
        $f5 = New-DepsFake ([byte[]](1..8)) 5 'be5' 'C:\s\dl5.vhdx'
        & $f5.StartVM @{ Name='be5' }; & $f5.RemoveHardDiskDrive @{ VMName='be5'; Path='C:\s\dl5.vhdx' }
        { & $f5.GetVhdxImageHash @{ Path='C:\s\dl5.vhdx' } } | Should -Throw -ExpectedMessage '*still locked*' -Because 'lag=5 == MaxAttempts: the real throws on the 5th attempt'
    }
    It 'ERROR-PARITY: hashing a NON-EXISTENT disk throws (missing artifact), in both factories' {
        $f = New-DepsFake ([byte[]](1..8))
        { & $f.GetVhdxImageHash @{ Path = 'C:\s\nope.vhdx' } } | Should -Throw -ExpectedMessage '*does not exist*'
        # real: same fail-closed shape when the file is absent (no VM/elevation needed — Test-Path is false)
        $real = New-RealHyperVBackend
        { & $real.GetVhdxImageHash @{ Path = 'C:\does\not\exist.vhdx' } } | Should -Throw -ExpectedMessage '*does not exist*'
    }
    It 'SECURITY: the REAL GetVhdxImageHash NEVER references Mount-VHD / Add-VMHardDiskDrive / qemu (user-space file hash only)' {
        $real = New-RealHyperVBackend
        $body = $real.GetVhdxImageHash.ToString()
        $body | Should -Not -Match 'Mount-VHD'
        $body | Should -Not -Match 'Add-VMHardDiskDrive'
        $body | Should -Not -Match 'qemu'
        $body | Should -Match 'SHA256'
        $body | Should -Match 'OpenRead'
    }
}

Describe 'fake -SimulateVerdictBlob (the builder guest packing its verdict into the raw VERDICT disk)' {
    BeforeAll {
        # A VM with an OUTPUT (deps) disk and a raw VERDICT disk; $Setup tweaks the fake or VM before StartVM.
        function script:New-VerdictVm {
            param([hashtable] $FakeArgs, [bool] $CheckpointsOff = $true)
            $f = New-FakeHyperVBackend @FakeArgs
            & $f.NewVM @{ Name = 'vv'; Generation = 2 }
            if ($CheckpointsOff) { & $f.SetAutomaticCheckpoints @{ VMName = 'vv'; Enabled = $false } }
            & $f.NewOutputVhdx @{ Path = 'C:\s\deps.vhdx'; Label = 'OUTPUT'; FileSystem = 'exFAT'; SizeBytes = 64MB }
            & $f.NewOutputVhdx @{ Path = 'C:\s\verdict.vhdx'; Label = 'VERDICT'; FileSystem = 'Raw'; SizeBytes = 64MB }
            & $f.AddHardDiskDrive @{ VMName = 'vv'; Path = 'C:\s\deps.vhdx' }
            & $f.AddHardDiskDrive @{ VMName = 'vv'; Path = 'C:\s\verdict.vhdx' }
            return $f
        }
    }
    It 'after a clean power-off the blob is in the base region of the VERDICT disk only, and reads back byte for byte' {
        $f = script:New-VerdictVm -FakeArgs @{ SimulateSelfPowerOff = $true; SimulateVerdictBlob = [byte[]](1..16) }
        & $f.StartVM @{ Name = 'vv' }
        & $f.RemoveHardDiskDrive @{ VMName = 'vv'; Path = 'C:\s\verdict.vhdx' }
        & $f.RemoveHardDiskDrive @{ VMName = 'vv'; Path = 'C:\s\deps.vhdx' }
        $v = & $f.ReadVhdxRawRegion @{ Path = 'C:\s\verdict.vhdx'; Offset = 0; Length = 16 }
        ($v -join ',') | Should -Be ((1..16) -join ',')
        $d = & $f.ReadVhdxRawRegion @{ Path = 'C:\s\deps.vhdx'; Offset = 0; Length = 16 }
        @($d | Where-Object { $_ -ne 0 }).Count | Should -Be 0 -Because 'the deps disk never receives the verdict'
    }
    It 'write-flush gate: a guest that never powers off leaves the verdict disk all zeros' {
        $f = script:New-VerdictVm -FakeArgs @{ SimulateNeverOff = $true; SimulateVerdictBlob = [byte[]](1..16) }
        & $f.StartVM @{ Name = 'vv' }
        & $f.RemoveHardDiskDrive @{ VMName = 'vv'; Path = 'C:\s\verdict.vhdx' }
        $v = & $f.ReadVhdxRawRegion @{ Path = 'C:\s\verdict.vhdx'; Offset = 0; Length = 16 }
        @($v | Where-Object { $_ -ne 0 }).Count | Should -Be 0
    }
    It 'RC7: with automatic checkpoints left ON the blob hides in the child layer and a base read sees zeros' {
        $f = script:New-VerdictVm -FakeArgs @{ SimulateSelfPowerOff = $true; SimulateVerdictBlob = [byte[]](1..16) } -CheckpointsOff $false
        & $f.StartVM @{ Name = 'vv' }
        & $f.RemoveHardDiskDrive @{ VMName = 'vv'; Path = 'C:\s\verdict.vhdx' }
        $v = & $f.ReadVhdxRawRegion @{ Path = 'C:\s\verdict.vhdx'; Offset = 0; Length = 16 }
        @($v | Where-Object { $_ -ne 0 }).Count | Should -Be 0
    }
    It 'no VERDICT-labelled disk attached means nothing is recorded (and nothing throws)' {
        $f = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateVerdictBlob ([byte[]](1..16))
        & $f.NewVM @{ Name = 'vv'; Generation = 2 }
        & $f.NewOutputVhdx @{ Path = 'C:\s\deps.vhdx'; Label = 'OUTPUT'; FileSystem = 'exFAT'; SizeBytes = 64MB }
        & $f.AddHardDiskDrive @{ VMName = 'vv'; Path = 'C:\s\deps.vhdx' }
        { & $f.StartVM @{ Name = 'vv' } } | Should -Not -Throw
    }
}

Describe 'ReadVhdxRawRegion — user-space raw read (fake axes + real never-mounts)' {
    BeforeEach {
        $script:fake = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateOutboxBlob ([byte[]](1..16))
        & $script:fake.NewVM @{ Name = 'p1'; Generation = 2 }
        & $script:fake.SetAutomaticCheckpoints @{ VMName = 'p1'; Enabled = $false }   # the RC7 fix
        & $script:fake.NewOutputVhdx @{ Path = 'C:\s\out.vhdx'; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
        & $script:fake.AddHardDiskDrive @{ VMName = 'p1'; Path = 'C:\s\out.vhdx' }
    }
    It 'AXIS 1: reading a disk attached to a RUNNING VM throws *locked* (live worker holds the lock; real never says *still attached*)' {
        # FIX-2: gate on the holder State. Build a fake WITHOUT -SimulateSelfPowerOff so StartVM leaves
        # State='Running' (the live vmwp.exe holds the file lock) with the disk still attached. The fake must
        # throw a *locked* message (the real hits a sharing violation -> $LockRetry -> *locked*; it NEVER
        # emits *still attached*). Pre-fix the fake threw *still attached* for ANY attach regardless of State.
        $f = New-FakeHyperVBackend
        & $f.NewVM @{ Name = 'pr'; Generation = 2 }
        & $f.SetAutomaticCheckpoints @{ VMName = 'pr'; Enabled = $false }
        & $f.NewOutputVhdx @{ Path = 'C:\s\outr.vhdx'; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
        & $f.AddHardDiskDrive @{ VMName = 'pr'; Path = 'C:\s\outr.vhdx' }
        & $f.StartVM @{ Name = 'pr' }   # no SelfPowerOff -> State='Running', disk still attached
        { & $f.ReadVhdxRawRegion @{ Path = 'C:\s\outr.vhdx'; Offset = 0; Length = 16 } } |
            Should -Throw -ExpectedMessage '*locked*'
    }
    It 'AXIS 1 (FIX-2): an OFF-but-attached disk is qemu-readable -> returns bytes (the real allows it; the builder post-power-off pre-detach window)' {
        # NewVM + NewOutputVhdx + AddHardDiskDrive, but NO StartVM: State stays 'Off' while the disk is still
        # attached. The real qemu-img opens it (no live vmwp handle) and returns bytes; the fake must too
        # (pre-fix it over-strictly refused). No blob recorded -> a zero-padded buffer of the requested length.
        $f = New-FakeHyperVBackend
        & $f.NewVM @{ Name = 'poff'; Generation = 2 }
        & $f.SetAutomaticCheckpoints @{ VMName = 'poff'; Enabled = $false }
        & $f.NewOutputVhdx @{ Path = 'C:\s\outoff.vhdx'; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
        & $f.AddHardDiskDrive @{ VMName = 'poff'; Path = 'C:\s\outoff.vhdx' }
        # Call directly (must NOT throw — proven by reaching the asserts); a Should -Not -Throw scriptblock
        # would swallow the return value in its child scope.
        $bytes = & $f.ReadVhdxRawRegion @{ Path = 'C:\s\outoff.vhdx'; Offset = 0; Length = 16 }
        ,$bytes | Should -BeOfType ([byte[]])
        $bytes.Length | Should -Be 16
    }
    It 'AXIS 1+3: after detach + SelfPowerOff, returns the recorded outbox bytes; CallLog proves detach precedes read' {
        & $script:fake.StartVM @{ Name = 'p1' }
        & $script:fake.RemoveHardDiskDrive @{ VMName = 'p1'; Path = 'C:\s\out.vhdx' }
        $bytes = & $script:fake.ReadVhdxRawRegion @{ Path = 'C:\s\out.vhdx'; Offset = 0; Length = 16 }
        ,$bytes | Should -BeOfType ([byte[]])
        ($bytes -join ',') | Should -Be ((1..16) -join ',')
    }
    It 'AXIS 2: checkpoints ON (RC7 trap) -> base raw-read returns ALL ZEROS (outbox stuck in .avhdx child)' {
        & $script:fake.SetAutomaticCheckpoints @{ VMName = 'p1'; Enabled = $true }
        & $script:fake.StartVM @{ Name = 'p1' }
        & $script:fake.RemoveHardDiskDrive @{ VMName = 'p1'; Path = 'C:\s\out.vhdx' }
        $bytes = & $script:fake.ReadVhdxRawRegion @{ Path = 'C:\s\out.vhdx'; Offset = 0; Length = 16 }
        (@($bytes | Where-Object { $_ -ne 0 })).Count | Should -Be 0
    }
    It 'AXIS 4: an over-read past the written payload is zero-padded, never an error (FIXED-disk tail)' {
        & $script:fake.StartVM @{ Name = 'p1' }
        & $script:fake.RemoveHardDiskDrive @{ VMName = 'p1'; Path = 'C:\s\out.vhdx' }
        $bytes = & $script:fake.ReadVhdxRawRegion @{ Path = 'C:\s\out.vhdx'; Offset = 0; Length = 32 }
        $bytes.Length | Should -Be 32
        (@($bytes[16..31] | Where-Object { $_ -ne 0 })).Count | Should -Be 0
    }
    It 'MUST-FIX 1 (settle-lag WITHIN budget): -SimulateDetachSettleLag 2 still returns the recorded bytes (method tolerates a transient detach lock, like the real internal retry)' {
        # Rebuild with a small lag inside the read's internal retry budget (matches the real helper's
        # MaxAttempts default of 5). The method must ride it out and return the bytes.
        $f = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateOutboxBlob ([byte[]](1..16)) -SimulateDetachSettleLag 2
        & $f.NewVM @{ Name = 'p1'; Generation = 2 }
        & $f.SetAutomaticCheckpoints @{ VMName = 'p1'; Enabled = $false }
        & $f.NewOutputVhdx @{ Path = 'C:\s\out.vhdx'; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
        & $f.AddHardDiskDrive @{ VMName = 'p1'; Path = 'C:\s\out.vhdx' }
        & $f.StartVM @{ Name = 'p1' }
        & $f.RemoveHardDiskDrive @{ VMName = 'p1'; Path = 'C:\s\out.vhdx' }
        $bytes = & $f.ReadVhdxRawRegion @{ Path = 'C:\s\out.vhdx'; Offset = 0; Length = 16 }
        ($bytes -join ',') | Should -Be ((1..16) -join ',') -Because 'a lag within budget is retried away and the bytes are returned'
    }
    It 'MUST-FIX 1 (settle-lag BEYOND budget): -SimulateDetachSettleLag 99 fails closed with a lock message (handle never released)' {
        $f = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateOutboxBlob ([byte[]](1..16)) -SimulateDetachSettleLag 99
        & $f.NewVM @{ Name = 'p1'; Generation = 2 }
        & $f.SetAutomaticCheckpoints @{ VMName = 'p1'; Enabled = $false }
        & $f.NewOutputVhdx @{ Path = 'C:\s\out.vhdx'; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
        & $f.AddHardDiskDrive @{ VMName = 'p1'; Path = 'C:\s\out.vhdx' }
        & $f.StartVM @{ Name = 'p1' }
        & $f.RemoveHardDiskDrive @{ VMName = 'p1'; Path = 'C:\s\out.vhdx' }
        { & $f.ReadVhdxRawRegion @{ Path = 'C:\s\out.vhdx'; Offset = 0; Length = 16 } } |
            Should -Throw -ExpectedMessage '*still locked*'
    }
    It 'MUST-FIX 1 BOUNDARY (FIX-1): lag=4 (== MaxAttempts-1) is tolerated; lag=5 (== MaxAttempts) fails closed *still locked*' {
        # The real $SbInvokeWithLockRetry (increment-then-compare, MaxAttempts=5) tolerates 4 transient
        # lock-failures and throws on the 5th attempt. Pin the exact edge: 4 must NOT throw, 5 must. (Pre-fix
        # the fake's check-before-decrement tolerated 5 and threw at 6 — one off, mock-green where real fails.)
        $f4 = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateOutboxBlob ([byte[]](1..16)) -SimulateDetachSettleLag 4
        & $f4.NewVM @{ Name = 'pe4'; Generation = 2 }
        & $f4.SetAutomaticCheckpoints @{ VMName = 'pe4'; Enabled = $false }
        & $f4.NewOutputVhdx @{ Path = 'C:\s\oe4.vhdx'; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
        & $f4.AddHardDiskDrive @{ VMName = 'pe4'; Path = 'C:\s\oe4.vhdx' }
        & $f4.StartVM @{ Name = 'pe4' }
        & $f4.RemoveHardDiskDrive @{ VMName = 'pe4'; Path = 'C:\s\oe4.vhdx' }
        { & $f4.ReadVhdxRawRegion @{ Path = 'C:\s\oe4.vhdx'; Offset = 0; Length = 16 } } | Should -Not -Throw -Because 'lag=4 == MaxAttempts-1 is the real''s tolerance'
        $f5 = New-FakeHyperVBackend -SimulateSelfPowerOff -SimulateOutboxBlob ([byte[]](1..16)) -SimulateDetachSettleLag 5
        & $f5.NewVM @{ Name = 'pe5'; Generation = 2 }
        & $f5.SetAutomaticCheckpoints @{ VMName = 'pe5'; Enabled = $false }
        & $f5.NewOutputVhdx @{ Path = 'C:\s\oe5.vhdx'; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
        & $f5.AddHardDiskDrive @{ VMName = 'pe5'; Path = 'C:\s\oe5.vhdx' }
        & $f5.StartVM @{ Name = 'pe5' }
        & $f5.RemoveHardDiskDrive @{ VMName = 'pe5'; Path = 'C:\s\oe5.vhdx' }
        { & $f5.ReadVhdxRawRegion @{ Path = 'C:\s\oe5.vhdx'; Offset = 0; Length = 16 } } | Should -Throw -ExpectedMessage '*still locked*' -Because 'lag=5 == MaxAttempts: the real throws on the 5th attempt'
    }
    It 'MUST-FIX 2 (write-flush gate): a guest that NEVER cleanly powers off leaves the outbox UNFLUSHED -> raw read is ALL ZEROS' {
        # -SimulateNeverOff + -SimulateOutboxBlob but NO -SimulateSelfPowerOff: the blob must NOT be recorded
        # (a live unflushed disk reads zeros — the mock-green/live-empty trap the gate closes).
        $f = New-FakeHyperVBackend -SimulateNeverOff -SimulateOutboxBlob ([byte[]](1..16))
        & $f.NewVM @{ Name = 'p1'; Generation = 2 }
        & $f.SetAutomaticCheckpoints @{ VMName = 'p1'; Enabled = $false }
        & $f.NewOutputVhdx @{ Path = 'C:\s\out.vhdx'; Label = 'OUTPUT'; FileSystem = 'NTFS'; SizeBytes = 64MB }
        & $f.AddHardDiskDrive @{ VMName = 'p1'; Path = 'C:\s\out.vhdx' }
        & $f.StartVM @{ Name = 'p1' }
        & $f.RemoveHardDiskDrive @{ VMName = 'p1'; Path = 'C:\s\out.vhdx' }
        $bytes = & $f.ReadVhdxRawRegion @{ Path = 'C:\s\out.vhdx'; Offset = 0; Length = 16 }
        (@($bytes | Where-Object { $_ -ne 0 })).Count | Should -Be 0 -Because 'no clean self-power-off means the RAW region was never flushed'
    }
    It 'SECURITY: the REAL ReadVhdxRawRegion invokes NO host-attach/mount cmdlet (AST, not substring)' {
        # The project's ONLY encoded guard for the load-bearing Pass-5 no-host-attach decision, so it must
        # BIND THE REAL PROPERTY structurally. A substring match would PASS a future impl that host-attaches
        # via a different cmdlet (Mount-DiskImage / Add-PartitionAccessPath / a variable-built Add-VMHardDiskDrive)
        # and would FALSE-FAIL if a rationale comment moved into the body. An AST walk over CommandAst nodes
        # binds the actual invoked command names instead.
        $real = New-RealHyperVBackend
        $src  = $real.ReadVhdxRawRegion.ToString()
        $ast  = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
        $denylist = @('Mount-VHD','Mount-DiskImage','Add-VMHardDiskDrive','Add-PartitionAccessPath','Set-Disk','Initialize-Disk')
        foreach ($c in $cmds) {
            $name = $c.GetCommandName()    # $null for a dynamic invocation like `& $qemu.Source ...` (legit)
            if ($null -ne $name) { $denylist | Should -Not -Contain $name -Because "the user-space read must never host-attach/mount (Pass-5)" }
        }
        # No dynamic eval that could hide a mount behind a string.
        $src | Should -Not -Match 'Invoke-Expression'
        # The user-space mechanism is still present (positive assertion).
        $src | Should -Match 'qemu-img'
    }
    It 'SECURITY: the REAL ReadVhdxRawRegion resolves qemu-img through Resolve-QemuImg (version-floor + pin), not a bare Get-Command' {
        # I5a: a bare `Get-Command qemu-img` had no version floor and no binary pin, so ANY qemu-img on
        # PATH (however stale or substituted) would run against untrusted guest bytes. The real backend
        # must resolve through the testable, fail-closed helper instead.
        $real = New-RealHyperVBackend
        $src  = $real.ReadVhdxRawRegion.ToString()
        $src | Should -Match 'Resolve-QemuImg' -Because 'the real resolve must route through the version-floor + pin helper, not a bare Get-Command'
    }
    It 'SECURITY (review Critical, I5a wiring, out-of-process): the REAL ReadVhdxRawRegion ACTUALLY INVOKES Resolve-QemuImg with the configured floor propagated through the closure (not a string match)' {
        # The string-match test above only proves the SOURCE TEXT contains "Resolve-QemuImg" — it
        # would stay green even if the call read $script:QemuImgMinVersion directly (which resolves
        # EMPTY inside a .GetNewClosure()'d body, per this file's own closure-capture rule at
        # ~line 240) instead of a properly-hoisted factory-local. That exact regression shipped once:
        # a live run got -MinVersion '' -> ParameterBindingValidationException, misroutable through
        # $InvokeOp's SbIsUnavailableError path into a MISLEADING "Hyper-V unavailable" message (now
        # closed by the F3 name-scoping — `^\w+-(VM|VHD)`-only — since 'Resolve-QemuImg' isn't
        # Hyper-V-cmdlet-shaped, so that CommandNotFoundException now propagates raw and undisguised).
        #
        # WHY OUT-OF-PROCESS (mirrors 'Real backend — builds the right cmdlet params' above): verified
        # empirically in this task that an in-process Pester Mock of Get-QemuImgPath/Get-QemuImgVersion
        # does NOT intercept ReadVhdxRawRegion's closure at all here — ANY .GetNewClosure()'d scriptblock
        # invoked from inside a Pester It/Describe body fails to resolve a bare-name call to a dot-sourced
        # function (CommandNotFoundException: 'Resolve-QemuImg' is not recognized), reproduced even with
        # zero Mocks active and even via a trivial ad-hoc closure unrelated to New-RealHyperVBackend. That
        # is a Pester dynamic-module scoping fact of this closure pattern, not something the I5a hoist
        # fixes or should paper over. The harness below shadows the qemu seams AND dot-sources the lib in
        # the SAME top-level child-process scope (exactly Invoke-RealBackendCapture.ps1's proven pattern),
        # so the REAL closure body executes for real and the assertion is on its actual thrown message —
        # proving the configured floor value reached Resolve-QemuImg, not just that the source text
        # mentions it.
        $harness = Join-Path $PSScriptRoot 'fixtures/Invoke-RealReadVhdxRawRegionQemuFloor.ps1'
        Test-Path $harness | Should -BeTrue -Because 'the out-of-process qemu-floor-wiring harness must exist'

        $pwsh = (Get-Process -Id $PID).Path   # the exact pwsh running these tests
        if ([string]::IsNullOrWhiteSpace($pwsh)) { $pwsh = 'pwsh' }
        # '1.0.0' is deliberately BELOW $script:QemuImgMinVersion (8.2.0, the shipped default floor).
        $raw = & $pwsh -NoProfile -File $harness -LibPath $script:LibPath -StubVersion '1.0.0' 2>&1
        $rawText = ($raw | Out-String).Trim()
        $jsonLine = ($rawText -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
        $jsonLine | Should -Not -BeNullOrEmpty -Because "the harness must emit JSON; got: $rawText"
        $cap = $jsonLine | ConvertFrom-Json

        $cap.err | Should -Not -BeNullOrEmpty -Because 'a below-floor qemu-img version must fail closed'
        $cap.err | Should -Match 'below the required floor' -Because 'the specific Resolve-QemuImg floor error must surface, not a ParameterBindingValidationException (empty -MinVersion) or a mislabeled "Hyper-V unavailable"'
        $cap.err | Should -Match '8\.2\.0' -Because 'the CONFIGURED floor value must have propagated through the closure to Resolve-QemuImg, proving the hoist (not a $script: read that resolves empty)'
    }
    It 'SECURITY (I5b): the REAL ReadVhdxRawRegion routes the qemu convert through the Invoke-ConfinedQemu confinement seam, never a bare native call (AST, non-vacuous)' {
        # Finding I5 (part b): the qemu-img convert of an untrusted OUTPUT disk runs directly in the host
        # operator's session. Route it through a single confinement seam (Invoke-ConfinedQemu) so the REAL
        # mechanism (Tier-0/1 restricted-token/Job-Object shim, Tier-2/3 Windows Sandbox) is pluggable and
        # built/live-tested at Phase 6 — the seam ships now. An AST walk over CommandAst nodes binds the
        # ACTUAL invoked command name, so a rationale comment mentioning "convert" in prose cannot false-trip
        # this (a substring match would), and a future impl that calls the native exe under a different
        # variable name / a raw '&' invocation outside the seam WOULD be caught.
        $real = New-RealHyperVBackend
        $src  = $real.ReadVhdxRawRegion.ToString()
        $ast  = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)

        # Positive: Invoke-ConfinedQemu IS invoked as a command inside the real body.
        $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
        $cmdNames = $cmds | ForEach-Object { $_.GetCommandName() } | Where-Object { $null -ne $_ }
        $cmdNames | Should -Contain 'Invoke-ConfinedQemu' -Because 'the qemu-img convert must be routed through the confinement seam, not invoked directly'

        # Negative: no bare native invocation of the resolved qemu path (`& $qemuPath ...` / `& $qemu... convert`)
        # anywhere in the real body — every native exec must go through the seam. A CommandAst with a $null
        # command name is a dynamic invocation (`& $something ...`); assert none of those dynamic-invocation
        # source spans mention 'convert' outside of Invoke-ConfinedQemu's own argument list.
        $dynamicConvertCalls = $cmds | Where-Object {
            $null -eq $_.GetCommandName() -and $_.Extent.Text -match 'convert' -and $_.Extent.Text -notmatch 'Invoke-ConfinedQemu'
        }
        $dynamicConvertCalls | Should -BeNullOrEmpty -Because 'every native qemu-img convert invocation must go through Invoke-ConfinedQemu, never a bare dynamic call'

        # NON-VACUOUS CONTROL (mirrors the C1 no-Mount-VHD canary's own self-check): prove this AST technique
        # WOULD catch a bare `& $qemuPath convert ...` if one existed, by running the identical check against
        # a synthetic snippet that intentionally bypasses the seam.
        $bypassSrc = @'
$out = & $qemuPath convert -f vhdx -O raw -- $path $tmpRaw 2>&1
'@
        $bypassAst = [System.Management.Automation.Language.Parser]::ParseInput($bypassSrc, [ref]$null, [ref]$null)
        $bypassCmds = $bypassAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
        $bypassDynamicConvertCalls = $bypassCmds | Where-Object {
            $null -eq $_.GetCommandName() -and $_.Extent.Text -match 'convert' -and $_.Extent.Text -notmatch 'Invoke-ConfinedQemu'
        }
        $bypassDynamicConvertCalls | Should -Not -BeNullOrEmpty -Because 'the canary must be non-vacuous: a bare seam-bypassing convert call must be DETECTED by this exact technique, proving it is not silently passing everything'
    }
    It 'SECURITY (I5b, out-of-process): the REAL ReadVhdxRawRegion ACTUALLY INVOKES Invoke-ConfinedQemu at runtime (not just a string/AST match)' {
        # The AST test above proves the SOURCE routes through the seam. Confirm the seam is also REACHED at
        # runtime, mirroring the I5a qemu-floor-wiring harness pattern (Invoke-RealReadVhdxRawRegionQemuFloor.ps1):
        # shadow the qemu seams AND dot-source the lib in the SAME top-level child-process scope so the real
        # .GetNewClosure()'d body executes for real, then assert Invoke-ConfinedQemu was actually called.
        $harness = Join-Path $PSScriptRoot 'fixtures/Invoke-RealReadVhdxRawRegionConfinedQemu.ps1'
        Test-Path $harness | Should -BeTrue -Because 'the out-of-process Invoke-ConfinedQemu runtime-routing harness must exist'

        $pwsh = (Get-Process -Id $PID).Path   # the exact pwsh running these tests
        if ([string]::IsNullOrWhiteSpace($pwsh)) { $pwsh = 'pwsh' }
        $raw = & $pwsh -NoProfile -File $harness -LibPath $script:LibPath 2>&1
        $rawText = ($raw | Out-String).Trim()
        $jsonLine = ($rawText -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
        $jsonLine | Should -Not -BeNullOrEmpty -Because "the harness must emit JSON; got: $rawText"
        $cap = $jsonLine | ConvertFrom-Json

        $cap.invoked | Should -BeTrue -Because 'Invoke-ConfinedQemu must actually be called by the real ReadVhdxRawRegion closure at runtime, proving the seam is reached (not just present in source)'
        $cap.qemuPath | Should -Be 'C:\stub\qemu-img.exe' -Because 'the resolved qemu-img path must be passed through to the seam'
        ($cap.arguments -join ',') | Should -Match 'convert' -Because 'the convert subcommand must be passed as an Argument through the seam, not invoked directly'
    }
}

# ===========================================================================
#  Resolve-QemuImg (I5a) — version-floor (patch-currency) + optional SHA-256 pin
# ===========================================================================
#  Finding I5 (part a): the real ReadVhdxRawRegion ran qemu-img against an UNTRUSTED guest VHDX in the
#  host operator's session with NO version floor and NO binary pin — a stale or substituted qemu-img on
#  PATH would parse attacker-controlled bytes with no floor at all. This helper factors the resolve into
#  a pure, unit-testable seam: Get-QemuImgPath / Get-QemuImgVersion / Get-FileSha256 are thin wrappers
#  (over Get-Command qemu-img / `& qemu-img --version` / Get-FileHash) that Resolve-QemuImg calls, so
#  tests can Mock them directly (dot-sourced Pester Mock, no -ModuleName — matches this file's idiom).
#
#  FLOOR FRAMING (load-bearing, do not weaken): the MinVersion floor is a PATCH-CURRENCY check, not a
#  CVE-derived gate. The only real qemu VHDX-parser CVE found under verification is CVE-2014-0148 (a DoS,
#  fixed at QEMU 2.0) — nowhere near a modern floor. The floor exists so the resolver runs a CURRENTLY
#  PATCHED qemu (re-resolve the current stable at ship time), not because a specific CVE is fixed at that
#  version. Do not cite a CVE as the floor's justification.
Describe 'Resolve-QemuImg (I5 version-floor + SHA-256 pin)' {
    It 'fails closed when qemu-img version is below the floor' {
        Mock Get-QemuImgPath    { 'C:\qemu\qemu-img.exe' }
        Mock Get-QemuImgVersion { '1.7.0' }   # below floor 8.2.0
        { Resolve-QemuImg -MinVersion '8.2.0' } | Should -Throw -ExpectedMessage '*below the required floor*'
    }
    It 'fails closed when qemu-img is not found on PATH' {
        Mock Get-QemuImgPath { $null }
        { Resolve-QemuImg -MinVersion '8.2.0' } | Should -Throw -ExpectedMessage '*qemu-img not found*'
    }
    It 'passes when version meets the floor and no pin is supplied' {
        Mock Get-QemuImgVersion { '9.1.0' }
        Mock Get-QemuImgPath    { 'C:\qemu\qemu-img.exe' }
        Resolve-QemuImg -MinVersion '8.2.0' | Should -Be 'C:\qemu\qemu-img.exe'
    }
    It 'passes when version EXACTLY equals the floor (boundary, no pin)' {
        Mock Get-QemuImgVersion { '8.2.0' }
        Mock Get-QemuImgPath    { 'C:\qemu\qemu-img.exe' }
        Resolve-QemuImg -MinVersion '8.2.0' | Should -Be 'C:\qemu\qemu-img.exe'
    }
    It 'passes when version meets the floor AND the pinned SHA-256 matches (case-insensitive)' {
        Mock Get-QemuImgVersion { '9.1.0' }
        Mock Get-QemuImgPath    { 'C:\qemu\qemu-img.exe' }
        Mock Get-FileSha256     { 'A' * 64 }
        Resolve-QemuImg -MinVersion '8.2.0' -PinnedSha256 ('a' * 64) | Should -Be 'C:\qemu\qemu-img.exe'
    }
    It 'fails closed when the pinned SHA-256 does not match' {
        Mock Get-QemuImgVersion { '9.1.0' }; Mock Get-QemuImgPath { 'C:\qemu\qemu-img.exe' }
        Mock Get-FileSha256 { 'deadbeef' }
        { Resolve-QemuImg -MinVersion '8.2.0' -PinnedSha256 ('a'*64) } | Should -Throw -ExpectedMessage '*hash mismatch*'
    }
    It 'does NOT hash the binary at all when no pin is supplied (Get-FileSha256 not called)' {
        Mock Get-QemuImgVersion { '9.1.0' }
        Mock Get-QemuImgPath    { 'C:\qemu\qemu-img.exe' }
        Mock Get-FileSha256     { 'should-not-be-called' }
        Resolve-QemuImg -MinVersion '8.2.0' | Should -Be 'C:\qemu\qemu-img.exe'
        Should -Invoke Get-FileSha256 -Times 0
    }
}

# ===========================================================================
#  GetHostMemory: the host free-RAM read behind the engine's pre-boot gate
# ===========================================================================
Describe 'Fake backend - GetHostMemory' {

    It 'returns FreeBytes and TotalBytes as [long] byte counts, with a default that clears every shipped guest size' {
        $b = New-FakeHyperVBackend
        $m = & $b.GetHostMemory @{}
        $m.FreeBytes  | Should -BeOfType [long]
        $m.TotalBytes | Should -BeOfType [long]
        $m.FreeBytes  | Should -BeGreaterThan 32GB
        $m.TotalBytes | Should -BeGreaterOrEqual $m.FreeBytes
    }

    It 'is configurable through -SimulateHostFreeMemoryBytes / -SimulateHostTotalMemoryBytes' {
        $b = New-FakeHyperVBackend -SimulateHostFreeMemoryBytes 3GB -SimulateHostTotalMemoryBytes 16GB
        $m = & $b.GetHostMemory @{}
        $m.FreeBytes  | Should -Be 3GB
        $m.TotalBytes | Should -Be 16GB
    }

    It 'throws under -SimulateHostMemoryReadError (the unreadable-host case the gate must fail closed on)' {
        $b = New-FakeHyperVBackend -SimulateHostMemoryReadError
        { & $b.GetHostMemory @{} } | Should -Throw -ExpectedMessage '*GetHostMemory*'
    }
}

# ===========================================================================
#  REAL backend: processor caps + the CIM host-memory read (out-of-process capture)
# ===========================================================================
#  The real bodies cannot run here (no elevation, no live Hyper-V). Like the SetProcessor pass-through
#  above, they are driven out-of-process with recording shadow stubs: Set-VMProcessor records which
#  parameters arrived, and Get-CimInstance returns the shape the real class has (UInt64 properties in
#  KiB), so a missing unit conversion or a wrong class name shows up here and not on first live use.
Describe 'Real backend - SetProcessor caps and GetHostMemory (out-of-process capture)' {

    BeforeAll {
        $harness = Join-Path $PSScriptRoot 'fixtures/Invoke-RealBackendCapture.ps1'
        $pwsh = (Get-Process -Id $PID).Path
        if ([string]::IsNullOrWhiteSpace($pwsh)) { $pwsh = 'pwsh' }
        $raw = & $pwsh -NoProfile -File $harness -LibPath $script:LibPath 2>&1
        $rawText = ($raw | Out-String).Trim()
        $jsonLine = ($rawText -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
        $jsonLine | Should -Not -BeNullOrEmpty -Because "the harness must emit JSON; got: $rawText"
        $script:Cap2 = $jsonLine | ConvertFrom-Json
    }

    It 'SetProcessor passes -Maximum and -RelativeWeight through when supplied' {
        $script:Cap2.SetProcessor_Caps.err | Should -BeNullOrEmpty
        $cap = $script:Cap2.SetProcessor_Caps.cap
        $cap.MaximumGiven        | Should -BeTrue
        $cap.Maximum             | Should -Be 60
        $cap.RelativeWeightGiven | Should -BeTrue
        $cap.RelativeWeight      | Should -Be 500
        $cap.CountGiven          | Should -BeTrue
        $cap.Count               | Should -Be 2
    }

    It 'SetProcessor OMITS -Maximum and -RelativeWeight when they are not supplied (Hyper-V defaults stay)' {
        $cap = $script:Cap2.SetProcessor.cap
        $cap.MaximumGiven        | Should -BeFalse
        $cap.RelativeWeightGiven | Should -BeFalse
    }

    It 'SetProcessor passes only the one cap that was supplied' {
        $cap = $script:Cap2.SetProcessor_MaxOnly.cap
        $cap.MaximumGiven        | Should -BeTrue
        $cap.RelativeWeightGiven | Should -BeFalse
    }

    It 'GetHostMemory reads Win32_OperatingSystem and converts KiB to bytes (x1024)' {
        $script:Cap2.GetHostMemory.err | Should -BeNullOrEmpty
        $script:Cap2.GetHostMemory.cap.ClassName | Should -Be 'Win32_OperatingSystem'
        $script:Cap2.GetHostMemory.result.FreeBytes  | Should -Be (8388608 * 1024)  -Because 'FreePhysicalMemory is reported in KiB'
        $script:Cap2.GetHostMemory.result.TotalBytes | Should -Be (16777216 * 1024) -Because 'TotalVisibleMemorySize is reported in KiB'
    }

    It 'GetHostMemory does not truncate a figure above the Int32 range (the CIM properties are UInt64)' {
        $script:Cap2.GetHostMemory_Big.err | Should -BeNullOrEmpty
        $script:Cap2.GetHostMemory_Big.result.FreeBytes | Should -Be ([long]4294967296 * 1024)
    }

    It 'GetHostMemory throws (fail closed) when the CIM read returns nothing' {
        $script:Cap2.GetHostMemory_Null.err | Should -Match 'HyperVBackend\.GetHostMemory'
    }

    It 'GetHostMemory throws when the CIM instance carries no usable memory figures' {
        $script:Cap2.GetHostMemory_Empty.err | Should -Match 'HyperVBackend\.GetHostMemory'
    }
}

# ===========================================================================
#  REAL GetVM / GetSwitch: exact-name selection out of a wildcard by-name read
# ===========================================================================
#  Get-VM -Name and Get-VMSwitch -Name treat * ? [ ] as wildcards and Hyper-V allows duplicate VM names,
#  so the by-name read can return objects the caller never named, or several of the one it did. The real
#  bodies route the result through $script:SbSelectExactName; the helper is unit-tested here and the two
#  bodies are pinned to call it.
Describe '$script:SbSelectExactName: the exact-name pick behind the real GetVM and GetSwitch' {

    It 'returns $null for no exact match (including a wildcard hit on another name) and the one object for a single exact match' {
        (& $script:SbSelectExactName @() 'vm1' 'GetVM') | Should -BeNullOrEmpty
        $other = [pscustomobject]@{ Name = 'vm10'; State = 'Off' }
        (& $script:SbSelectExactName @($other) 'vm1' 'GetVM') | Should -BeNullOrEmpty -Because 'Get-VM -Name vm1* would return vm10; it is not vm1'
        $one = [pscustomobject]@{ Name = 'vm1'; State = 'Off' }
        $picked = & $script:SbSelectExactName @($other, $one) 'vm1' 'GetVM'
        $picked.Name | Should -Be 'vm1'
        $picked.State | Should -Be 'Off'
    }

    It 'compares case-sensitively and ignores an object without a Name' {
        (& $script:SbSelectExactName @([pscustomobject]@{ Name = 'VM1' }) 'vm1' 'GetVM') | Should -BeNullOrEmpty
        (& $script:SbSelectExactName @([pscustomobject]@{ VMName = 'vm1' }) 'vm1' 'GetVM') | Should -BeNullOrEmpty
    }

    It 'THROWS when more than one object carries exactly the name (a duplicate VM name is never resolved by picking the first)' {
        $dup = @([pscustomobject]@{ Name = 'vm1' }, [pscustomobject]@{ Name = 'vm1' })
        { & $script:SbSelectExactName $dup 'vm1' 'GetVM' } |
            Should -Throw -ExpectedMessage "HyperVBackend.GetVM: 2 objects are named exactly 'vm1'; refusing to pick one. Fail closed."
    }

    It 'the real GetVM and GetSwitch route their by-name read through the helper (AST-pinned)' {
        foreach ($method in 'GetVM', 'GetSwitch') {
            $assign = & $script:GetRealBackendAssign $method
            $assign | Should -Not -BeNullOrEmpty
            $calls = @($assign.FindAll({
                param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                          $n.CommandElements[0] -is [System.Management.Automation.Language.VariableExpressionAst] -and
                          $n.CommandElements[0].VariablePath.UserPath -eq 'SelectExact'
            }, $true))
            $calls.Count | Should -Be 1 -Because "$method must hand the by-name read to the exact-name pick"
            # The by-name read is collected into an array first, so a single object is never unrolled away.
            $byName = @($assign.FindAll({
                param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                          $n.GetCommandName() -in @('Get-VM', 'Get-VMSwitch') -and
                          @($n.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Name' }).Count -gt 0
            }, $true))
            $byName.Count | Should -Be 1
            # @( Get-VM ... ) parses as ArrayExpression > StatementBlock > Pipeline > Command.
            $byName[0].Parent.Parent.Parent | Should -BeOfType [System.Management.Automation.Language.ArrayExpressionAst] -Because "$method wraps the by-name read in @()"
        }
    }
}
