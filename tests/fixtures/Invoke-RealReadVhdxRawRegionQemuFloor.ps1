<#
.SYNOPSIS
    Out-of-process live-invocation harness for the I5a qemu-img version-floor WIRING fix.

.DESCRIPTION
    Regression harness for the review Critical finding: the real ReadVhdxRawRegion's closure body
    called `Resolve-QemuImg -MinVersion $script:QemuImgMinVersion -PinnedSha256 $script:QemuImgPinnedSha256`
    directly inside `& $InvokeOp { ... }` (itself nested inside the .GetNewClosure()'d
    $b.ReadVhdxRawRegion). A closure does NOT resolve a `$script:`-prefixed variable READ back to the
    top-level script scope (see the file's own closure-capture note, ~HyperVBackend.ps1:240) — it came
    back EMPTY at call time, so live it threw ParameterBindingValidationException on the Mandatory
    -MinVersion string param (or, depending on how that surfaces, got mislabeled "Hyper-V unavailable"
    via SbIsUnavailableError's CommandNotFoundException branch). See tests/HyperVBackend.Tests.ps1
    'ReadVhdxRawRegion — user-space raw read' Describe, the "review Critical, I5a wiring" It, for the
    full root-cause note.

    WHY A CHILD PROCESS (not an in-process Pester Mock, unlike Resolve-QemuImg's OWN unit tests):
    empirically verified in this task that ANY .GetNewClosure()'d scriptblock invoked from inside a
    Pester It/Describe body fails to resolve a bare-name call to a dot-sourced FUNCTION (not just
    Hyper-V cmdlets) — `CommandNotFoundException: 'Resolve-QemuImg' is not recognized`, reproduced even
    with a trivial ad-hoc `{ Resolve-QemuImg -MinVersion '8.2.0' }.GetNewClosure()` unrelated to
    New-RealHyperVBackend, and even with ZERO Pester Mocks active. This mirrors the EXACT reason
    tests/fixtures/Invoke-RealBackendCapture.ps1 already exists for NewVHD/NewVM/NewSwitch/SetProcessor:
    a shadow stub installed in a TEST scope is not on a real-backend closure's resolution path. The
    ONLY reliable interception is to shadow the qemu seams AND dot-source the lib in the SAME top-level
    script scope, exactly like that harness — which is what THIS script does for Resolve-QemuImg's own
    seams (Get-QemuImgPath / Get-QemuImgVersion) instead of the Hyper-V cmdlets.

.PARAMETER LibPath
    Absolute path to scripts/lib/HyperVBackend.ps1.

.PARAMETER StubVersion
    The version string the shadowed Get-QemuImgVersion should report (e.g. a below-floor '1.0.0').

.OUTPUTS
    A single-line JSON object on stdout: { "err": <string|null> }
    'err' is $null if ReadVhdxRawRegion did NOT throw (unexpected for a below-floor version), or the
    thrown exception's message otherwise.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $LibPath,

    [Parameter(Mandatory)]
    [string] $StubVersion
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Dot-source the lib INTO THIS top-level scope FIRST. Unlike Invoke-RealBackendCapture.ps1's
# New-VHD/New-VM/New-VMSwitch (real Hyper-V cmdlets the lib never defines), Get-QemuImgPath /
# Get-QemuImgVersion ARE defined BY this file (they're its own seams) — so the shadow stubs below
# MUST come AFTER the dot-source, or the dot-source's real definitions would clobber them (same-scope
# function redefinition is last-writer-wins). New-RealHyperVBackend is called AFTER the shadows are in
# place so ReadVhdxRawRegion's .GetNewClosure() captures a session state where the bare-name calls to
# Get-QemuImgPath/Get-QemuImgVersion resolve to these stubs, never a real qemu-img binary.
. $LibPath

function Get-QemuImgPath {
    return 'C:\stub\qemu-img.exe'
}

function Get-QemuImgVersion {
    param([Parameter(Mandatory)] [string] $Path)
    return $StubVersion
}

$real = New-RealHyperVBackend

$err = $null
try {
    & $real.ReadVhdxRawRegion @{ Path = 'C:\dummy.vhdx'; Offset = 0; Length = 16 } | Out-Null
}
catch {
    $err = $_.Exception.Message
}

[ordered]@{ err = $err } | ConvertTo-Json -Compress
