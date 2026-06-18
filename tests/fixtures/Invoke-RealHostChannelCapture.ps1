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
        'Guest Service Interface'). UNCHANGED: SetHostChannel disables it via
        Disable-VMIntegrationService; GetHostChannels reads the real `.Enabled` and FAILS
        CLOSED (catch { throw }). It still flips with the integration-service state.
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

# GuestServices read stub (THE fail-closed channel read). Reports .Enabled = $script:gsiEnabled,
# or THROWS when $script:gsiThrows (the unreadable-channel fail-closed scenario).
function Get-VMIntegrationService {
    [CmdletBinding()]
    param([string] $VMName, [string] $Name)
    if ($script:gsiThrows) {
        throw "stub: simulated Get-VMIntegrationService failure for '$VMName' (the GuestServices channel is unreadable)."
    }
    return [pscustomobject]@{ Name = $Name; Enabled = $script:gsiEnabled }
}

# Enable/Disable-VMIntegrationService stubs (the GuestServices SET mechanism — unchanged by this fix).
# Disable records the VMName so the SetGsiDisable scenario can prove it routed correctly.
function Enable-VMIntegrationService  { [CmdletBinding()] param([string] $VMName, [string] $Name) }
function Disable-VMIntegrationService {
    [CmdletBinding()]
    param([string] $VMName, [string] $Name)
    $script:capDisableGsi = $VMName
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

# --- SET scenarios -------------------------------------------------------------------------
function Invoke-SetCapture {
    param([scriptblock] $Call)
    $script:capDisableConsole = $null
    $script:capEnableConsole  = $null
    $script:capSetVmEsm       = $null
    $script:capDisableGsi     = $null
    $err = $null
    try { & $Call | Out-Null } catch { $err = $_.Exception.Message }
    return [ordered]@{
        err                     = $err
        disableConsoleCalled    = ($null -ne $script:capDisableConsole)
        enableConsoleCalled     = ($null -ne $script:capEnableConsole)
        consoleVMName           = [string]$script:capDisableConsole
        disableGsiCalled        = ($null -ne $script:capDisableGsi)
        setVmEsmTransportPassed = ($null -ne $script:capSetVmEsm)
        setVmEsmTransportValue  = $script:capSetVmEsm
    }
}

# --- GET scenarios -------------------------------------------------------------------------
# Read GetHostChannels with the GSI integration-service state set, the ConsoleMode source pinned
# at 0 (live-host reality), and optionally a throwing GSI read.
function Invoke-GetCapture {
    param([bool] $GsiEnabled, [bool] $GsiThrows = $false)
    $script:gsiEnabled = $GsiEnabled
    $script:gsiThrows  = $GsiThrows
    $err = $null; $ch = $null
    try { $ch = & $b.GetHostChannels @{ VMName = 'sbx-seal' } } catch { $err = $_.Exception.Message }
    $script:gsiThrows = $false   # reset for the next scenario
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
    # GuestServices read THROWS -> GetHostChannels rethrows (fail closed: the one real channel is unreadable).
    GetGsiThrows   = (& {
        $script:gsiThrows = $true
        $err = $null; $ch = $null
        try { $ch = & $b.GetHostChannels @{ VMName = 'sbx-seal' } } catch { $err = $_.Exception.Message }
        $script:gsiThrows = $false
        [ordered]@{ err = $err; ch = if ($null -ne $ch) { 'non-null' } else { $null } }
    })
}

$out | ConvertTo-Json -Depth 6 -Compress
