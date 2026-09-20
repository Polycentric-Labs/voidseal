<#
.SYNOPSIS
    Out-of-process live-invocation harness for the I5b Invoke-ConfinedQemu confinement-seam WIRING.

.DESCRIPTION
    The AST canary test (tests/HyperVBackend.Tests.ps1, 'SECURITY (I5b): ... AST, non-vacuous') proves the
    real ReadVhdxRawRegion's SOURCE TEXT routes the qemu-img convert call through Invoke-ConfinedQemu rather
    than a bare native invocation. That is a structural guarantee only — it would stay green even if, say,
    a future edit shadowed Invoke-ConfinedQemu with a same-named local variable that never actually reached
    the seam function at call time. This harness proves the seam is REACHED AT RUNTIME.

    WHY OUT-OF-PROCESS (mirrors Invoke-RealReadVhdxRawRegionQemuFloor.ps1's own rationale, itself mirroring
    Invoke-RealBackendCapture.ps1's for NewVHD/NewVM/NewSwitch/SetProcessor): empirically verified that a
    .GetNewClosure()'d scriptblock invoked from inside a Pester It/Describe body fails to resolve a
    bare-name call to a dot-sourced FUNCTION via an in-process Pester Mock/shadow — the ONLY reliable
    interception is to shadow the seam AND dot-source the lib in the SAME top-level script scope. This
    script does exactly that: it shadows Get-QemuImgPath/Get-QemuImgVersion (so Resolve-QemuImg succeeds
    without a real qemu-img on PATH) AND Invoke-ConfinedQemu itself (recording that it was called, with what
    arguments), then calls the real ReadVhdxRawRegion and reports what it observed.

    Because there is no real qemu-img binary and no real .vhdx file, the stubbed Invoke-ConfinedQemu returns
    a synthetic non-zero exit via $LASTEXITCODE so ReadVhdxRawRegion throws AFTER the seam call is recorded
    — this harness only needs to prove the seam was REACHED with the right arguments, not that a full
    convert+read round-trip succeeds (that is LIVE-ONLY-UNPROVEN until Phase 6, same as the rest of this
    method).

.PARAMETER LibPath
    Absolute path to scripts/lib/HyperVBackend.ps1.

.OUTPUTS
    A single-line JSON object on stdout:
        { "invoked": <bool>, "qemuPath": <string|null>, "arguments": <string[]|null> }
    'invoked' is $true iff the shadowed Invoke-ConfinedQemu was called by the real ReadVhdxRawRegion
    closure. 'qemuPath'/'arguments' capture what it was called with (for asserting the right values
    propagated through the closure).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $LibPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Dot-source the lib INTO THIS top-level scope FIRST. Invoke-ConfinedQemu (like Get-QemuImgPath/
# Get-QemuImgVersion) IS defined BY this file — so the shadow stubs below MUST come AFTER the dot-source,
# or the dot-source's real definitions would clobber them (same-scope function redefinition is
# last-writer-wins). New-RealHyperVBackend is called AFTER the shadows are in place so ReadVhdxRawRegion's
# .GetNewClosure() captures a session state where its bare-name calls resolve to these stubs.
. $LibPath

function Get-QemuImgPath {
    return 'C:\stub\qemu-img.exe'
}

function Get-QemuImgVersion {
    param([Parameter(Mandatory)] [string] $Path)
    return '99.0.0'   # comfortably above the shipped default floor -> Resolve-QemuImg succeeds
}

$script:ConfinedQemuInvoked   = $false
$script:ConfinedQemuQemuPath  = $null
$script:ConfinedQemuArguments = $null

function Invoke-ConfinedQemu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $QemuPath,
        [Parameter(Mandatory)] [string[]] $Arguments
    )
    $script:ConfinedQemuInvoked   = $true
    $script:ConfinedQemuQemuPath  = $QemuPath
    $script:ConfinedQemuArguments = $Arguments
    # No real qemu-img to run. Report a synthetic failure via $LASTEXITCODE so the caller's
    # `if ($LASTEXITCODE -ne 0)` throws right after recording the call above — this harness only needs to
    # observe that the seam was reached with the right arguments, not a full convert+read round-trip.
    $global:LASTEXITCODE = 1
    return 'stub: no real qemu-img in this harness'
}

$real = New-RealHyperVBackend

try {
    & $real.ReadVhdxRawRegion @{ Path = 'C:\dummy.vhdx'; Offset = 0; Length = 16 } | Out-Null
}
catch {
    # Expected: the synthetic non-zero exit above makes ReadVhdxRawRegion throw. We only care whether
    # Invoke-ConfinedQemu was reached first, captured in the $script: vars above.
}

[ordered]@{
    invoked   = $script:ConfinedQemuInvoked
    qemuPath  = $script:ConfinedQemuQemuPath
    arguments = $script:ConfinedQemuArguments
} | ConvertTo-Json -Compress
