<#
.SYNOPSIS
    Voidseal seal policy: the network-adapter predicate shared by the Provisioner and the Sealer.

.DESCRIPTION
    Get-SealNicPolicy answers "does this VM keep a NIC?" for New-SandboxVM (Provisioner.ps1),
    Lock-Sandbox and Assert-Sealed (Sealer.ps1). It lives in its own file so each of those files can
    dot-source it and work on its own: before 2026-10-03 it sat in Provisioner.ps1, and a session that
    loaded Sealer.ps1 alone could not seal. Pure logic, no Hyper-V calls, safe to dot-source anywhere.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
    The ONE predicate for a sandbox VM's network-adapter posture: 'IsolatedInternalSwitch' or 'NoAdapter'.
.DESCRIPTION
    Three call sites used to answer "does this VM keep a NIC?" on their own: the Provisioner keyed on
    Substrate, Lock-Sandbox on Tier, and Assert-Sealed on Tier plus a Network field that production
    never recorded. They drifted, so a processor kept its default adapter through the seal and a Tier-1
    processor was certified with a CONNECTED adapter. All three now ask this function.

    The rule is an allow-list with one entry. A VM keeps a NIC (on an isolated Internal vSwitch) only
    when its Tier is exactly 1 AND its Network label is present and is not 'None'. Every other input
    returns 'NoAdapter': Tier 0, Tier >= 2, a processor (Network='None') at any tier, a blank label,
    and an out-of-range tier. Unexpected input therefore lands on the strict side. The 'None' match is
    case-insensitive, like the loader's processor rule, and it also trims surrounding whitespace, which
    the loader does not, so this predicate is the stricter of the two.
.PARAMETER Tier
    The VM's risk tier (descriptor or profile Tier).
.PARAMETER Network
    The VM's Network posture label (descriptor or profile Network). Blank or $null means NoAdapter.
#>
function Get-SealNicPolicy {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [int] $Tier,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Network
    )
    if ($Tier -eq 1 -and -not [string]::IsNullOrWhiteSpace($Network) -and $Network.Trim() -ne 'None') {
        return 'IsolatedInternalSwitch'
    }
    return 'NoAdapter'
}
