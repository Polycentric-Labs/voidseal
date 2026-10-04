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

    The rule is an allow-list with one entry. A VM keeps a NIC (on its own Internal vSwitch) only when
    its Tier is exactly 1 AND its Network label is exactly 'Internal+Allowlist', the value
    tier-profiles/tier1.psd1 ships (surrounding whitespace is trimmed; the comparison is otherwise
    exact and case-sensitive). 'NoAdapter' covers Tier 0, Tier >= 2, an out-of-range tier, a processor
    (Network='None') at any tier, and a blank label. A Tier-1 label that is none of those THROWS: before
    2026-10-03 any such label kept a NIC, so the docstring's "one entry" was really "anything but
    None". Throwing (rather than quietly returning NoAdapter) stops a mislabeled Tier-1 profile at
    provisioning instead of handing it a VM without the network it asked for.

    The 'None' match is case-insensitive, like the loader's processor rule, and it also trims
    surrounding whitespace, which the loader does not. "Processor" here means Network='None' alone; the
    loader's Test-IsProcessorProfile also requires a ScreenConfig, because it decides screener routing.
    Both definitions land on NoAdapter: a Network='None' profile has no NIC whether or not it screens.
.PARAMETER Tier
    The VM's risk tier (descriptor or profile Tier).
.PARAMETER Network
    The VM's Network posture label (descriptor or profile Network). Blank or $null means NoAdapter; an
    unrecognized non-blank label at Tier 1 throws.
#>
function Get-SealNicPolicy {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [int] $Tier,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $Network
    )
    if ($Tier -ne 1 -or [string]::IsNullOrWhiteSpace($Network)) { return 'NoAdapter' }
    $label = $Network.Trim()
    if ($label -eq 'None') { return 'NoAdapter' }
    if ($label -ceq 'Internal+Allowlist') { return 'IsolatedInternalSwitch' }
    throw ("Get-SealNicPolicy: Tier-1 Network label '$label' is not recognized (expected 'Internal+Allowlist' " +
           "for a networked VM or 'None' for a processor). Refusing to guess a network-adapter policy. Fail closed.")
}
