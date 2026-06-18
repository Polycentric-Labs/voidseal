<#
.SYNOPSIS
    Out-of-process capture harness for the REAL-backed New-SandboxVM return-value contract
    (a real-backend bug found during live debugging — output-stream pollution).

.DESCRIPTION
    THE behavioral regression harness for the live failure: `Invoke-Voidseal -Tier 0` reached
    PROVISIONED then aborted at STAGED with "Import-SandboxAsset: descriptor has no VM Name",
    and teardown then failed with "The property 'CreatedDisks' cannot be found on this object."

    ROOT CAUSE: New-SandboxVM is meant to return ONLY the New-SandboxDescriptor object. But the
    REAL backend methods (New-VM / Set-VM* / Add-VMHardDiskDrive / New-VMSwitch / Connect-VM* /
    New-VHD / ...) emit Hyper-V objects to the OUTPUT STREAM. Those effect-only calls were NOT
    captured, so PowerShell collected every stray emission as part of New-SandboxVM's return —
    making it an ARRAY @(<VM object>, ..., <descriptor>) instead of the lone descriptor. The
    orchestrator's $descriptor became that array; Import-SandboxAsset got element [0] (a raw VM
    object with no .Name) and teardown saw no .CreatedDisks. The FAKE backend returns quiet
    hashtables that don't pollute the stream, so all mock tests passed and ONLY the live path broke.

    WHY A CHILD PROCESS: the real backend's methods are .GetNewClosure() scriptblocks that resolve
    their Hyper-V cmdlets against the SESSION STATE captured when New-RealHyperVBackend ran (the
    scope the lib was dot-sourced into). A shadow stub / Pester Mock installed in a TEST scope is
    NOT on that closure's command-resolution path. The ONLY reliable interception is to define the
    shadow stubs AND dot-source the libs in the SAME top-level script scope — which is exactly what
    THIS script does. Each shadow stub here EMITS a dummy PSCustomObject to the output stream,
    MIMICKING the real cmdlets that pollute it. We then drive the REAL New-SandboxVM end-to-end and
    emit, as JSON, how many objects landed on its output stream and whether the (last) one is a
    descriptor. Pre-fix: Count > 1 and the descriptor isn't the only thing returned. Post-fix:
    Count == 1 and it carries .Name + .CreatedDisks. This is the test that WOULD have caught the
    live bug (the in-process mock suite structurally could not).

.PARAMETER ProvisionerPath
    Absolute path to scripts/lib/Provisioner.ps1.
.PARAMETER BackendPath
    Absolute path to scripts/lib/HyperVBackend.ps1.

.OUTPUTS
    A single-line JSON object on stdout:
      {
        "err": <string|null>,           # the thrown message if New-SandboxVM threw, else null
        "count": <int>,                 # number of objects on New-SandboxVM's output stream
        "lastIsDescriptor": <bool>,     # last emitted object looks like a descriptor (has Name+CreatedDisks)
        "name": <string|null>,          # the last object's .Name (descriptor's VM name)
        "createdDisksGiven": <bool>,    # last object exposes a .CreatedDisks property
        "createdDisksCount": <int>,     # how many disks it records
        "elem0HasName": <bool>          # element [0] of the return has a non-empty .Name (false when polluted)
      }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ProvisionerPath,
    [Parameter(Mandatory)] [string] $BackendPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- State the stateful Get-VM stub keys off of (created VM names) --------------------------
$script:CreatedVMs = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)

# --- Recording shadow stubs (TOP-LEVEL scope, BEFORE the dot-source, so the backend closures
#     capture THIS scope and resolve their cmdlet calls to these stubs). EACH effect-method stub
#     EMITS a dummy object to the output stream — mimicking the REAL Hyper-V cmdlets that pollute
#     the stream and which, uncaptured, leak into New-SandboxVM's return value. ----------------

function New-VHD {
    [CmdletBinding()]
    param([string] $Path, [long] $SizeBytes, [switch] $Differencing,
          [string] $ParentPath, [switch] $Dynamic, [switch] $Fixed)
    # Real New-VHD emits a Microsoft.Vhd.PowerShell.VirtualHardDisk object.
    [pscustomobject]@{ __Stub = 'VHD'; Path = $Path }
}

function New-VM {
    [CmdletBinding()]
    param([string] $Name, [int] $Generation, [long] $MemoryStartupBytes,
          [string] $Path, [string] $SwitchName, [switch] $NoVHD)
    [void]$script:CreatedVMs.Add($Name)
    # Real New-VM emits a Microsoft.HyperV.PowerShell.VirtualMachine object — the headline polluter
    # (this is the raw VM object that became element [0] of New-SandboxVM's return in the live bug).
    [pscustomobject]@{ __Stub = 'VM'; VMName = $Name; ProcessorCount = 0 }
}

function Set-VMMemory {
    [CmdletBinding()] param([string] $VMName, [long] $StartupBytes, [bool] $DynamicMemoryEnabled)
    [pscustomobject]@{ __Stub = 'SetVMMemory'; VMName = $VMName }
}

function Set-VMProcessor {
    [CmdletBinding()] param([string] $VMName, [int] $Count, [bool] $ExposeVirtualizationExtensions)
    [pscustomobject]@{ __Stub = 'SetVMProcessor'; VMName = $VMName }
}

function Set-VMFirmware {
    [CmdletBinding()]
    # Real backend passes -EnableSecureBoot 'On'|'Off' (a string, not a switch) — mirror that.
    param([string] $VMName, [string] $EnableSecureBoot, [string] $SecureBootTemplate, $BootOrder)
    [pscustomobject]@{ __Stub = 'SetVMFirmware'; VMName = $VMName }
}

function Set-VMComPort {
    [CmdletBinding()] param([string] $VMName, [int] $Number, [string] $Path)
    [pscustomobject]@{ __Stub = 'SetVMComPort'; VMName = $VMName }
}

function Add-VMHardDiskDrive {
    [CmdletBinding()] param([string] $VMName, [string] $Path)
    # Real Add-VMHardDiskDrive emits a Microsoft.HyperV.PowerShell.HardDiskDrive object.
    [pscustomobject]@{ __Stub = 'HardDiskDrive'; VMName = $VMName; Path = $Path }
}

function New-VMSwitch {
    [CmdletBinding()] param([string] $Name, [string] $SwitchType, [string] $NetAdapterName)
    # Real New-VMSwitch emits a Microsoft.HyperV.PowerShell.VMSwitch object.
    [pscustomobject]@{ __Stub = 'VMSwitch'; Name = $Name }
}

function Get-VMNetworkAdapter {
    [CmdletBinding()] param([string] $VMName)
    # ConnectNetworkAdapter probes for an existing NIC first; report none so the Add branch runs.
    return $null
}

function Add-VMNetworkAdapter {
    [CmdletBinding()] param([string] $VMName, [string] $SwitchName)
    # Real Add-VMNetworkAdapter emits a Microsoft.HyperV.PowerShell.VMNetworkAdapter object.
    [pscustomobject]@{ __Stub = 'VMNetworkAdapter'; VMName = $VMName }
}

function Connect-VMNetworkAdapter {
    [CmdletBinding()] param([string] $VMName, [string] $SwitchName)
    [pscustomobject]@{ __Stub = 'ConnectVMNetworkAdapter'; VMName = $VMName }
}

function Get-VMSwitch {
    [CmdletBinding()] param([string] $Name)
    # The provisioner's GetSwitch probe must report "no such switch" so NewSwitch runs.
    # The bare availability probe (no -Name) returns nothing and must not throw.
    return $null
}

function Get-VM {
    [CmdletBinding()] param([string] $Name)
    # GetVM calls Get-VM TWICE: a bare availability probe (no -Name) then Get-VM -Name <vm>.
    # Stateful so the pre-NewVM idempotency check sees NO existing VM ($null) but the post-build
    # readback returns a VM object carrying a .State for the descriptor.
    if (-not $PSBoundParameters.ContainsKey('Name') -or [string]::IsNullOrWhiteSpace($Name)) {
        return $null   # bare availability probe — emit nothing, do not throw
    }
    if ($script:CreatedVMs.Contains($Name)) {
        return [pscustomobject]@{ __Stub = 'VM'; VMName = $Name; State = 'Off' }
    }
    return $null
}

# Dot-source the libs INTO THIS top-level scope (so the backend closures capture the stubs above).
. $BackendPath
. $ProvisionerPath

# A normalized Tier-1 profile (the shape Import-TierProfile emits): Substrate=HyperV-Gen2 so the
# NIC/switch branch runs (max polluters), plus the COM1 + firmware steps. Tier 0 in the live run
# rode the same New-SandboxVM path; Tier-1's HyperV-Gen2 substrate exercises EVERY effect-only call.
$profile = @{
    Tier               = 1
    Substrate          = 'HyperV-Gen2'
    GuestImage         = 'debian-12'
    Memory             = '4GB'
    Cpu                = 4
    NestedVirt         = $false
    SecureBootTemplate = 'MicrosoftUEFICertificateAuthority'
    ManagementChannel  = 'Com1Serial'
    Network            = 'Internal+Allowlist'
}

# The differencing branch needs a REAL, NON-SPARSE parent file on disk: New-SandboxVM's sparse-
# parent preflight (pure host-FS) requires the supplied parent to EXIST and not be sparse. Create a
# plain temp file (a normal file is never sparse) to stand in for the golden disk; the shadowed
# New-VHD never reads its bytes, so any content is fine. This drives the NewVHD differencing branch
# (the live run passed -ParentDiskPath <golden.vhdx>) without tripping the preflight.
$goldenParent = Join-Path ([System.IO.Path]::GetTempPath()) ("vmdep-prov-golden-{0}.vhdx" -f ([guid]::NewGuid().ToString('N')))
Set-Content -LiteralPath $goldenParent -Value 'golden-parent-payload' -NoNewline -Encoding ascii

$err = $null
$result = $null
try {
    # Capture EVERYTHING New-SandboxVM puts on its output stream — wrap in @() so a single object
    # and a polluted array both normalize to an array we can count.
    $result = @(New-SandboxVM -Profile $profile -Name 'sbx-pollute' `
        -ParentDiskPath $goldenParent -Backend (New-RealHyperVBackend))
}
catch {
    $err = $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $goldenParent -Force -ErrorAction SilentlyContinue
}

$count             = if ($null -ne $result) { @($result).Count } else { 0 }
$last              = if ($count -gt 0) { $result[$count - 1] } else { $null }
$elem0             = if ($count -gt 0) { $result[0] } else { $null }

function Test-HasProp { param($Obj, [string] $Name)
    if ($null -eq $Obj) { return $false }
    return ($null -ne $Obj.PSObject.Properties[$Name])
}
function Get-PropVal { param($Obj, [string] $Name)
    if (Test-HasProp $Obj $Name) { return $Obj.PSObject.Properties[$Name].Value }
    return $null
}

$lastIsDescriptor   = (Test-HasProp $last 'Name') -and (Test-HasProp $last 'CreatedDisks')
$name               = [string](Get-PropVal $last 'Name')
$createdDisksGiven  = Test-HasProp $last 'CreatedDisks'
$createdDisks       = @(Get-PropVal $last 'CreatedDisks')
$elem0Name          = [string](Get-PropVal $elem0 'Name')

$out = [ordered]@{
    err               = $err
    count             = $count
    lastIsDescriptor  = [bool]$lastIsDescriptor
    name              = $name
    createdDisksGiven = [bool]$createdDisksGiven
    createdDisksCount = [int]$createdDisks.Count
    elem0HasName      = (-not [string]::IsNullOrWhiteSpace($elem0Name))
}
$out | ConvertTo-Json -Depth 6 -Compress
