<#
.SYNOPSIS
    Out-of-process capture harness for the REAL HyperVBackend host-channel SEAL methods
    (the Linux-guest seal model: ESM facets cannot be
    per-VM-verified by ConsoleMode, so they are reported OFF BY CONSTRUCTION).

.DESCRIPTION
    THE behavioral regression harness for the live SEAL gate. History of this seam:

      The invalid-enum bind bug: the real SetHostChannel mapped EnhancedSession onto
        `Set-VM -EnhancedSessionTransportType None|HvSocket` — invalid (no `None` enum),
        the bind threw before any cmdlet ran and aborted Lock-Sandbox. Fixed: route the
        disable through `Disable-VMConsoleSupport` (KVM/console off, belt-and-braces; ON is
        `Enable-VMConsoleSupport`). That part of the fix STANDS and is still captured here.

      The GET half was WRONG (a later bug found during live debugging — the diagnosis THIS harness now pins):
        the GET keyed the three ESM-facet channels (EnhancedSession / Clipboard / Shares)
        off the WMI `Msvm_VirtualSystemSettingData.ConsoleMode` (`-ne 3` => ON). But a LIVE
        diagnostic on a real Gen2 VM proved `Disable-VMConsoleSupport` does NOT change
        ConsoleMode — it stays 0 (Default) both BEFORE and AFTER the call (likewise
        EnhancedSessionTransportType stays 0). So the `ConsoleMode -ne 3` read ALWAYS
        evaluated TRUE => the three ESM channels ALWAYS reported ON => Assert-Sealed could
        NEVER certify => the seal refused forever on a real Linux guest.

    THE CORRECT LINUX-GUEST MODEL (what this harness now proves):
      * GuestServices = the ONE real autonomous host<->guest data channel (Copy-VMFile /
        'Guest Service Interface'). SetHostChannel disables it via Disable-VMIntegrationService and
        GetHostChannels reads the real `.Enabled`, both FAIL CLOSED; since 2026-10-16 it is found by
        its component GUID (6C09BB55) with the other integration services, never by its English
        display name, so the stub set below carries it under a German name like the rest.
      * EnhancedSession / Clipboard / Shares = ESM facets. There is NO per-VM "ESM off"
        toggle and ESM clipboard/drive-redirection needs Windows-guest components a stock
        Linux image structurally lacks — so they are NOT live autonomous channels on a Linux
        guest and the host cannot expose a per-VM ESM-on signal for ANY guest. The seal
        closes them BEST-EFFORT via the (belt-and-braces) `Disable-VMConsoleSupport`, and
        GetHostChannels reports them OFF BY CONSTRUCTION — it NO LONGER reads ConsoleMode.
        The headline regression: GetHostChannels must report these three OFF even when
        ConsoleMode is 0 (the live-host reality), i.e. the read must NOT depend on
        ConsoleMode flipping (it doesn't).

    WHY A CHILD PROCESS: the real backend's methods are .GetNewClosure() scriptblocks that
    resolve their Hyper-V cmdlets against the SESSION STATE captured when New-RealHyperVBackend
    ran (the scope the lib was dot-sourced into). A shadow stub / Pester Mock installed in a TEST
    scope is NOT on that closure's command-resolution path. The ONLY reliable interception is to
    define the shadow stubs AND dot-source the lib in the SAME top-level script scope — which is
    exactly what THIS script does. We shadow Disable/Enable-VMConsoleSupport, Set-VM (to PROVE the
    invalid-enum bind never happens — a shadow that THROWS if -EnhancedSessionTransportType is
    ever passed), Get-VMIntegrationService (GuestServices read), and Get-CimInstance (a NON-
    flipping ConsoleMode source that mimics the live host: it returns 0 regardless). Then drive
    the REAL SetHostChannel / GetHostChannels and emit, as JSON, exactly which cmdlets fired and
    what GetHostChannels read back. This RUNS the real method bodies with NO live Hyper-V and NO
    elevation.

.PARAMETER LibPath
    Absolute path to scripts/lib/HyperVBackend.ps1.

.OUTPUTS
    A single-line JSON object on stdout:
      {
        "SetEsmDisable":  { "err":..., "disableConsoleCalled":bool, "enableConsoleCalled":bool,
                            "setVmEsmTransportPassed":bool, "setVmEsmTransportValue":<string|null>,
                            "consoleVMName":<string|null> },
        "SetEsmEnable":   { ... same shape ... },
        "SetClipDisable": { ... Clipboard rides on ESM -> must also DisableConsole ... },
        "SetGsiDisable":  { ... GuestServices disable -> Disable-VMIntegrationService ... },
        "GetEsmFacetsAtConsoleMode0": { "err":..., "EnhancedSession":bool, "Clipboard":bool,
                                        "Shares":bool, "GuestServices":bool },   # THE headline:
                            # ConsoleMode stays 0 (live-host reality) yet the 3 ESM facets read OFF.
        "GetGsiOffAtConsoleMode0":    { ... GuestServices reads OFF when GSI disabled (independent) ... },
        "GetGsiThrows":   { "err":..., "ch":<null> }                            # GSI unreadable -> rethrow.
      }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $LibPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Recording state the shadow stubs write into --------------------------------------------
$script:capDisableConsole = $null    # the -VMName Disable-VMConsoleSupport was called with (or $null)
$script:capEnableConsole  = $null    # the -VMName Enable-VMConsoleSupport was called with (or $null)
$script:capSetVmEsm       = $null    # the -EnhancedSessionTransportType value Set-VM was passed (THE BUG marker)
$script:capDisableGsi     = $null    # the -VMName Disable-VMIntegrationService was called with (or $null)
# Drives the GuestServices read for the GET tests; flip between calls.
$script:gsiEnabled        = $true
# The GuestServices read can be made to THROW (the one fail-closed channel) for the GSI-rethrow test.
$script:gsiThrows         = $false

# --- Recording shadow stubs (TOP-LEVEL scope, BEFORE the dot-source) -------------------------

function Disable-VMConsoleSupport {
    [CmdletBinding()]
    param([string[]] $VMName, $VM, [switch] $Passthru)
    $script:capDisableConsole = ($VMName | Select-Object -First 1)
}

function Enable-VMConsoleSupport {
    [CmdletBinding()]
    param([string[]] $VMName, $VM, [switch] $Passthru)
    $script:capEnableConsole = ($VMName | Select-Object -First 1)
}

# Strict Set-VM shadow: if the real backend EVER routes the EnhancedSession channel through
# Set-VM -EnhancedSessionTransportType (the invalid-enum bind bug), record the value AND throw the SAME invalid-enum
# error real Hyper-V throws — so a regression reproduces the live failure here, in-test.
function Set-VM {
    [CmdletBinding()]
    param([string] $Name, [string] $EnhancedSessionTransportType)
    if ($PSBoundParameters.ContainsKey('EnhancedSessionTransportType')) {
        $script:capSetVmEsm = $EnhancedSessionTransportType
        if ($EnhancedSessionTransportType -eq 'None') {
            throw "Cannot bind parameter 'EnhancedSessionTransportType'. Cannot convert value `"None`" to type Microsoft.HyperV.PowerShell.EnhancedSessionTransportType ... Specify one of: VMBus, HvSocket"
        }
    }
}

# Integration-service stub. Called WITH -Name it models the by-name lookup the real body no longer makes
# (kept so a regression back to the English-name read is visible: it returns an object whose Enabled is
# $script:gsiEnabled, and throws when $script:gsiThrows).
#
# Called WITHOUT -Name it models the enumeration the integration-service reads use (design E6): it
# returns $script:isServices, a list of objects carrying an Id ('Microsoft:<vm id>\<component GUID>'),
# a deliberately LOCALIZED Name (so a by-name lookup could not find them) and an Enabled value. That
# enumeration throws when $script:isEnumThrows.
$script:isEnumThrows = $false
$script:isServices   = @()
function Get-VMIntegrationService {
    [CmdletBinding()]
    param([string] $VMName, [string] $Name)
    if ($PSBoundParameters.ContainsKey('Name')) {
        if ($script:gsiThrows) {
            throw "stub: simulated Get-VMIntegrationService failure for '$VMName' (the GuestServices channel is unreadable)."
        }
        return [pscustomobject]@{ Name = $Name; Enabled = $script:gsiEnabled }
    }
    if ($script:isEnumThrows) {
        throw "stub: simulated Get-VMIntegrationService enumeration failure for '$VMName'."
    }
    foreach ($s in $script:isServices) { $s }
}

# Enable/Disable-VMIntegrationService stubs. Called with -Name they are the GuestServices SET (unchanged).
# Called with piped service objects they are the ID-matched SET of the integration services; each
# records the Id it received and whether a -Name was passed (it must not be: names are localized).
$script:capIsDisable = [System.Collections.Generic.List[object]]::new()
$script:capIsEnable  = [System.Collections.Generic.List[object]]::new()
function Enable-VMIntegrationService {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)] $VMIntegrationService, [string] $VMName, [string] $Name)
    process {
        if ($null -ne $VMIntegrationService) {
            $script:capIsEnable.Add([ordered]@{ Id = [string]$VMIntegrationService.Id; NameGiven = $PSBoundParameters.ContainsKey('Name') })
        }
    }
}
function Disable-VMIntegrationService {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)] $VMIntegrationService, [string] $VMName, [string] $Name)
    process {
        if ($null -ne $VMIntegrationService) {
            $script:capIsDisable.Add([ordered]@{ Id = [string]$VMIntegrationService.Id; NameGiven = $PSBoundParameters.ContainsKey('Name') })
        }
        else { $script:capDisableGsi = $VMName }
    }
}

# Get-CimInstance shadow: model the LIVE-HOST reality — ConsoleMode does NOT flip with
# Disable-VMConsoleSupport; it stays 0 (Default). The FIXED GetHostChannels must NOT read this
# at all for the ESM facets (it reports them off by construction). We keep the stub present and
# returning ConsoleMode=0 so that if a regression re-introduces a ConsoleMode-keyed read, the
# ESM facets would (wrongly) read ON — and the GetEsmFacetsAtConsoleMode0 test would FAIL.
function Get-CimInstance {
    [CmdletBinding()]
    param(
        [string] $Namespace,
        [string] $ClassName,
        [string] $Query,
        [Parameter(ValueFromPipeline)] $InputObject,
        $CimInstance,
        $Association
    )
    return [pscustomobject]@{
        ElementName       = 'stub-vm'
        ConsoleMode       = [uint16]0      # LIVE-HOST REALITY: stays 0 even after Disable-VMConsoleSupport.
        VirtualSystemType = 'Microsoft:Hyper-V:System:Realized'
        Description       = 'Active settings for the virtual machine'
    }
}

# Get-VM stub: the real GetHostChannels may still call Get-VM (e.g. to resolve the VM id). Return a
# minimal object carrying Name + Id so any id-based association path works.
function Get-VM {
    [CmdletBinding()]
    param([string] $Name)
    if (-not $PSBoundParameters.ContainsKey('Name') -or [string]::IsNullOrWhiteSpace($Name)) {
        return $null   # bare availability probe — emit nothing, don't throw
    }
    return [pscustomobject]@{ Name = $Name; Id = [guid]'00000000-0000-0000-0000-000000000abc' }
}

# Dot-source the lib INTO THIS top-level scope (so the backend closures capture the stubs above).
. $LibPath
$b = New-RealHyperVBackend

# --- Integration-service stub objects (design E6) -------------------------------------------------
# Component GUIDs as Hyper-V writes them into a VM's configuration; the Names are German on purpose, so
# only an Id-based match can find them. Shutdown and Guest Service Interface are present too, so a match
# that picked the wrong service would show up.
$script:vmIdPrefix = 'Microsoft:00000000-0000-0000-0000-000000000ABC\'
function New-StubServiceSet {
    param([hashtable] $Enabled = @{})
    $defs = [ordered]@{
        Heartbeat        = @('84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47', 'Taktsignal')
        Shutdown         = @('9F8233AC-BE49-4C79-8EE3-E7E1985B2077', 'Herunterfahren')
        TimeSync         = @('2497F4DE-E9FA-4204-80E4-4B75C46419C0', 'Zeitsynchronisierung')
        KeyValueExchange = @('2A34B1C2-FD73-4043-8A5B-DD2159BC743F', 'Austausch von Schluesselwertpaaren')
        Backup           = @('5CED1297-4598-4915-A5FC-AD21BB4D02A4', 'Sicherung (Volumeschattenkopie)')
        GuestServices    = @('6C09BB55-D683-4DA0-8931-C9BF705F6480', 'Gastdienstschnittstelle')
    }
    foreach ($k in $defs.Keys) {
        $on = if ($Enabled.ContainsKey($k)) { $Enabled[$k] } else { $true }
        [pscustomobject]@{ Id = $script:vmIdPrefix + $defs[$k][0]; Name = $defs[$k][1]; Enabled = $on }
    }
}
$script:isServices = @(New-StubServiceSet)

# Read GetHostChannels with a given service set; report the four integration-service values or the error.
function Invoke-IsGetCapture {
    param([object[]] $Services, [switch] $EnumThrows)
    $script:gsiEnabled   = $true
    $script:isServices   = $Services
    $script:isEnumThrows = $EnumThrows.IsPresent
    $err = $null; $ch = $null
    try { $ch = & $b.GetHostChannels @{ VMName = 'sbx-seal' } } catch { $err = $_.Exception.Message }
    $script:isEnumThrows = $false
    $script:isServices   = @(New-StubServiceSet)
    $res = [ordered]@{ err = $err; keys = if ($ch) { @($ch.Keys | Sort-Object) -join ',' } else { $null } }
    foreach ($k in 'GuestServices', 'TimeSync', 'KeyValueExchange', 'Backup', 'Heartbeat') {
        $res[$k] = if ($ch -and $ch.ContainsKey($k)) { $ch[$k] } else { $null }
    }
    return $res
}

# Drive the real SetHostChannel for one integration service; report what the piped stubs received.
function Invoke-IsSetCapture {
    param([string] $Channel, [bool] $Enabled, [object[]] $Services)
    $script:isServices   = if ($PSBoundParameters.ContainsKey('Services')) { $Services } else { @(New-StubServiceSet) }
    $script:capIsDisable = [System.Collections.Generic.List[object]]::new()
    $script:capIsEnable  = [System.Collections.Generic.List[object]]::new()
    $script:capDisableGsi = $null
    $script:gsiEnabled   = $true
    $err = $null
    try { & $b.SetHostChannel @{ VMName = 'sbx-seal'; Channel = $Channel; Enabled = $Enabled } | Out-Null } catch { $err = $_.Exception.Message }
    $script:isServices = @(New-StubServiceSet)
    return [ordered]@{
        err          = $err
        disabledIds  = @($script:capIsDisable | ForEach-Object { $_.Id })
        enabledIds   = @($script:capIsEnable  | ForEach-Object { $_.Id })
        anyNameGiven = [bool](@(@($script:capIsDisable) + @($script:capIsEnable) | Where-Object { $_.NameGiven }).Count)
        gsiByName    = ($null -ne $script:capDisableGsi)
    }
}

# --- SET scenarios -------------------------------------------------------------------------
function Invoke-SetCapture {
    param([scriptblock] $Call)
    $script:capDisableConsole = $null
    $script:capEnableConsole  = $null
    $script:capSetVmEsm       = $null
    $script:capDisableGsi     = $null
    $script:capIsDisable      = [System.Collections.Generic.List[object]]::new()
    $script:capIsEnable       = [System.Collections.Generic.List[object]]::new()
    $script:isServices        = @(New-StubServiceSet)
    $err = $null
    try { & $Call | Out-Null } catch { $err = $_.Exception.Message }
    # The GuestServices disable now arrives as the ID-matched Guest Service Interface object piped to
    # Disable-VMIntegrationService (capIsDisable); the by-name shape (capDisableGsi) is kept so a
    # regression to the English-name call would still register, and the test asserts it stays unused.
    $gsiGuid = '6C09BB55-D683-4DA0-8931-C9BF705F6480'
    $gsiDisabledById = [bool](@($script:capIsDisable | Where-Object { ([string]$_.Id).EndsWith($gsiGuid, [System.StringComparison]::OrdinalIgnoreCase) }).Count)
    return [ordered]@{
        err                     = $err
        disableConsoleCalled    = ($null -ne $script:capDisableConsole)
        enableConsoleCalled     = ($null -ne $script:capEnableConsole)
        consoleVMName           = [string]$script:capDisableConsole
        disableGsiCalled        = (($null -ne $script:capDisableGsi) -or $gsiDisabledById)
        disableGsiById          = $gsiDisabledById
        disableGsiByName        = ($null -ne $script:capDisableGsi)
        setVmEsmTransportPassed = ($null -ne $script:capSetVmEsm)
        setVmEsmTransportValue  = $script:capSetVmEsm
    }
}

# --- GET scenarios -------------------------------------------------------------------------
# Read GetHostChannels with the GSI integration-service state set, the ConsoleMode source pinned
# at 0 (live-host reality), and optionally a throwing GSI read.
function Invoke-GetCapture {
    param([bool] $GsiEnabled, [bool] $GsiThrows = $false)
    # The Guest Service Interface state lives in the enumerated service set (read by GUID); the by-name
    # stub value is set too so a regression to the English-name read would read the same state here and
    # be caught by the AST pin in the test file rather than by a lucky value.
    $script:gsiEnabled = $GsiEnabled
    $script:gsiThrows  = $GsiThrows
    $script:isServices = @(New-StubServiceSet -Enabled @{ GuestServices = $GsiEnabled })
    $err = $null; $ch = $null
    try { $ch = & $b.GetHostChannels @{ VMName = 'sbx-seal' } } catch { $err = $_.Exception.Message }
    $script:gsiThrows  = $false   # reset for the next scenario
    $script:isServices = @(New-StubServiceSet)
    return [ordered]@{
        err             = $err
        EnhancedSession = if ($ch) { [bool]$ch.EnhancedSession } else { $null }
        Clipboard       = if ($ch) { [bool]$ch.Clipboard }       else { $null }
        Shares          = if ($ch) { [bool]$ch.Shares }          else { $null }
        GuestServices   = if ($ch) { [bool]$ch.GuestServices }   else { $null }
    }
}

$out = [ordered]@{
    # The HEADLINE SET: SetHostChannel EnhancedSession-disable (what Lock-Sandbox does) still routes
    # through Disable-VMConsoleSupport (belt-and-braces, the invalid-enum fix retained) — NO invalid None enum.
    SetEsmDisable  = Invoke-SetCapture { & $b.SetHostChannel @{ VMName = 'sbx-seal'; Channel = 'EnhancedSession'; Enabled = $false } }
    # Symmetry: the enable path (Sealer never uses it, but the mapping must be correct).
    SetEsmEnable   = Invoke-SetCapture { & $b.SetHostChannel @{ VMName = 'sbx-seal'; Channel = 'EnhancedSession'; Enabled = $true } }
    # Clipboard rides on ESM — disabling it must also route through the console-support mechanism.
    SetClipDisable = Invoke-SetCapture { & $b.SetHostChannel @{ VMName = 'sbx-seal'; Channel = 'Clipboard'; Enabled = $false } }
    # GuestServices disable routes through Disable-VMIntegrationService (the real autonomous channel — unchanged).
    SetGsiDisable  = Invoke-SetCapture { & $b.SetHostChannel @{ VMName = 'sbx-seal'; Channel = 'GuestServices'; Enabled = $false } }
    # THE HEADLINE GET (ESM-facets-off regression): ConsoleMode stays 0 (live-host reality), yet the three
    # ESM facets MUST read OFF by construction. GSI enabled here so GuestServices reads ON independently
    # (proving the ESM-off is NOT just "everything off").
    GetEsmFacetsAtConsoleMode0 = Invoke-GetCapture -GsiEnabled $true
    # GuestServices reads OFF when the integration service is disabled (the real channel flips independently).
    GetGsiOffAtConsoleMode0    = Invoke-GetCapture -GsiEnabled $false
    # The Guest Service Interface is missing from the enumeration -> GetHostChannels THROWS (fail closed:
    # the one real channel cannot be read, and nothing may coerce it to off).
    GetGsiThrows   = (& {
        $script:gsiThrows  = $true
        $script:isServices = @(New-StubServiceSet | Where-Object { $_.Id -notlike '*6C09BB55-D683-4DA0-8931-C9BF705F6480' })
        $err = $null; $ch = $null
        try { $ch = & $b.GetHostChannels @{ VMName = 'sbx-seal' } } catch { $err = $_.Exception.Message }
        $script:gsiThrows  = $false
        $script:isServices = @(New-StubServiceSet)
        [ordered]@{ err = $err; ch = if ($null -ne $ch) { 'non-null' } else { $null } }
    })

    # ---- integration services (design E6): ID-matched real reads and sets ----
    IsGetAllOn      = Invoke-IsGetCapture -Services @(New-StubServiceSet)
    IsGetAllOff     = Invoke-IsGetCapture -Services @(New-StubServiceSet -Enabled @{ GuestServices = $false; TimeSync = $false; KeyValueExchange = $false; Backup = $false; Heartbeat = $false })
    IsGetMixed      = Invoke-IsGetCapture -Services @(New-StubServiceSet -Enabled @{ TimeSync = $false; KeyValueExchange = $true; Backup = $false; Heartbeat = $false })
    IsGetMissingKvp = Invoke-IsGetCapture -Services @(New-StubServiceSet | Where-Object { $_.Id -notlike '*2A34B1C2-FD73-4043-8A5B-DD2159BC743F' })
    IsGetDuplicate  = Invoke-IsGetCapture -Services (@(New-StubServiceSet) + @([pscustomobject]@{ Id = $script:vmIdPrefix + '84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47'; Name = 'Taktsignal'; Enabled = $false }))
    IsGetNonBool    = Invoke-IsGetCapture -Services @(New-StubServiceSet -Enabled @{ Backup = 'False' })
    IsGetEnumThrows = Invoke-IsGetCapture -Services @(New-StubServiceSet) -EnumThrows
    IsSetGsiOff       = Invoke-IsSetCapture -Channel 'GuestServices'    -Enabled $false
    IsSetTimeSyncOff  = Invoke-IsSetCapture -Channel 'TimeSync'         -Enabled $false
    IsSetKvpOff       = Invoke-IsSetCapture -Channel 'KeyValueExchange' -Enabled $false
    IsSetBackupOff    = Invoke-IsSetCapture -Channel 'Backup'           -Enabled $false
    IsSetHeartbeatOff = Invoke-IsSetCapture -Channel 'Heartbeat'        -Enabled $false
    IsSetHeartbeatOn  = Invoke-IsSetCapture -Channel 'Heartbeat'        -Enabled $true
    IsSetMissing      = Invoke-IsSetCapture -Channel 'TimeSync'         -Enabled $false -Services @(New-StubServiceSet | Where-Object { $_.Id -notlike '*2497F4DE-E9FA-4204-80E4-4B75C46419C0' })
}

$out | ConvertTo-Json -Depth 6 -Compress
