<#
.SYNOPSIS
    Voidseal — Test-VoidsealPrereqs: a read-only "do I qualify to run this live" checker
    (Firecracker `devtool checkenv` analog).

.DESCRIPTION
    Hyper-V live-run eligibility is genuinely hard to self-check by reading docs — it spans
    Windows edition, an optional-feature flag, a running service, session elevation / group
    membership, and a golden disk image. This script converts operator-runbook.md §0's prose
    preconditions into one command with a per-check PASS/FAIL/WARN/UNKNOWN table + an overall
    verdict, so a user can find out "not ready, and here is exactly why" without guessing.

    Each printed row maps to a runbook §0 precondition:
      PowerShell >= 7                          engine requirement (every script in scripts/
                                                is PS7; this is NOT the same PowerShell that
                                                may already be on PATH as `powershell.exe`).
      Pester >= 5                              needed to run the test suite
                                                (`Invoke-Pester -Path tests`) — NOT required
                                                for a live deploy, so it never fails the
                                                overall verdict on its own.
      Windows edition supports Hyper-V         Hyper-V requires Pro/Enterprise/Education (or
                                                Server); Home cannot run it at all — runbook §0.
      Hyper-V feature enabled                  the Windows optional feature must be turned on
                                                (separate from the service below — see the
                                                caveat).
      vmms service present/running             runbook §0.1 — the Hyper-V Virtual Machine
                                                Management service must be up.
      Elevated OR Hyper-V Administrators       runbook §0.1 — `New-SandboxVM`'s own
                                                `TestAvailable` preflight fails closed on
                                                exactly this; mirrored here read-only.
      Golden parent VHDX (-ParentDiskPath)      runbook §0.3 — the Debian-12 golden image +
                                                cloud-init seed (guest-images/debian-12-cloud.md).
                                                Optional: WARN (not FAIL) when omitted, because
                                                the checker is still useful without it.

    HARD DESIGN CONSTRAINTS (do not weaken these when editing):
      * READ-ONLY. This script inspects; it never creates/modifies/removes a VM, switch, disk,
        service, or setting. There is no `New-*`/`Set-*`/`Remove-*`/`Start-*`/`Stop-*` against
        any Hyper-V or system object anywhere below.
      * RUNS UNELEVATED. Running the CHECKER never requires admin rights. A check that needs
        rights it doesn't have (e.g. Get-WindowsOptionalFeature -Online commonly does) reports
        UNKNOWN with a note to re-run elevated — never a crash, never a false PASS.
      * FAIL-SAFE. Every check body runs inside Invoke-VoidsealCheck's try/catch: an unexpected
        exception anywhere becomes an UNKNOWN row with the error reason, never an unhandled
        throw that aborts the whole table, and never a silent PASS.
      * Deliberately avoids PowerShell-7-only syntax (ternary `?:`, `??`, `??=`) even though the
        rest of the repo is PS7-only: this ONE script needs to still PARSE and RUN under
        Windows PowerShell 5.1 so that a user on an older PowerShell gets an honest "PowerShell
        >= 7: FAIL" row instead of a parser error before anything prints. Preserve this if
        editing.

    Passing every check is NECESSARY, not SUFFICIENT — see the caveat block the script prints
    after the table (nested virtualization, admin-rights scope, feature-vs-service, and the
    things this script deliberately does NOT check: host-patch CVE floors, disk space).

.PARAMETER ParentDiskPath
    Optional path to the golden Debian-12 parent .vhdx (see guest-images/debian-12-cloud.md).
    If omitted, that one check WARNs ("not checked") rather than failing.

.EXAMPLE
    pwsh scripts/Test-VoidsealPrereqs.ps1

.EXAMPLE
    pwsh scripts/Test-VoidsealPrereqs.ps1 -ParentDiskPath D:\vhdx\debian12-golden.vhdx

.EXAMPLE
    # Load the function without running/printing anything (e.g. from a test):
    . .\scripts\Test-VoidsealPrereqs.ps1
    $rows = Test-VoidsealPrereqs
#>

[CmdletBinding()]
param(
    [string] $ParentDiskPath
)

Set-StrictMode -Version Latest

# --------------------------------------------------------------------------
# Cross-version-safe Windows detection. Deliberately NOT `$IsWindows` — that
# automatic variable does not exist on Windows PowerShell 5.1, and under
# Set-StrictMode that would throw before we ever got to print anything. This
# form works on 5.1 and 7+ alike.
# --------------------------------------------------------------------------
function Test-IsWindowsHost {
    [OutputType([bool])]
    param()
    try {
        return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
    }
    catch {
        # Should not happen, but never let the platform probe itself throw.
        return $false
    }
}

# --------------------------------------------------------------------------
# Invoke-VoidsealCheck: the ONE place fail-safety lives. Every named check
# below is a scriptblock that returns @{ Status = 'PASS'|'FAIL'|'WARN';
# Detail = '<message>' } — Invoke-VoidsealCheck wraps the call so ANY
# exception the body raises (permission denial, cmdlet not found, WMI
# hiccup, ...) is caught here and turned into a normal UNKNOWN row instead
# of propagating and aborting the whole table.
#
# $Critical marks whether a FAIL/UNKNOWN on this row gates the overall
# verdict to "NOT READY" / "UNKNOWN" (see Get-VoidsealOverallVerdict). Pester
# is the one check that is never critical: it gates the ability to run the
# TEST SUITE, not a live deploy.
# --------------------------------------------------------------------------
function Invoke-VoidsealCheck {
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [scriptblock] $Body,
        [bool] $Critical = $true
    )
    try {
        $r = & $Body
        if ($null -eq $r -or -not $r.ContainsKey('Status')) {
            return [pscustomobject]@{
                Name = $Name; Status = 'UNKNOWN'; Detail = 'Check body returned no verdict.'; Critical = $Critical
            }
        }
        return [pscustomobject]@{ Name = $Name; Status = $r.Status; Detail = $r.Detail; Critical = $Critical }
    }
    catch {
        return [pscustomobject]@{
            Name     = $Name
            Status   = 'UNKNOWN'
            Detail   = "Check threw and was caught (fail-safe): $($_.Exception.Message)"
            Critical = $Critical
        }
    }
}

<#
.SYNOPSIS
    Run every Voidseal live-run prerequisite check and return the results — pure inspection,
    no printing, no elevation required, never throws (see Invoke-VoidsealCheck).
.DESCRIPTION
    Returns an array of [pscustomobject] rows: Name, Status (PASS/FAIL/WARN/UNKNOWN), Detail,
    Critical (bool — whether this row's FAIL/UNKNOWN gates the overall verdict). Callers that
    just want the table (a human running the script directly) get printing via the
    bottom-of-file invocation below; a test can call this function directly and assert on the
    returned shape without any console output.
.PARAMETER ParentDiskPath
    See the script-level help above.
#>
function Test-VoidsealPrereqs {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $ParentDiskPath
    )

    $results = [System.Collections.Generic.List[object]]::new()

    if (-not (Test-IsWindowsHost)) {
        $results.Add([pscustomobject]@{
            Name     = 'Platform'
            Status   = 'FAIL'
            Detail   = ('Voidseal is Windows/Hyper-V only. This host reports platform ' +
                        "'$([System.Environment]::OSVersion.Platform)', not Win32NT. " +
                        'Every other check below is skipped as moot.')
            Critical = $true
        })
        return $results.ToArray()
    }

    # ---- 1. PowerShell >= 7 (the engine requirement) --------------------
    $results.Add((Invoke-VoidsealCheck -Name 'PowerShell >= 7' -Critical $true -Body {
        $v = $PSVersionTable.PSVersion
        if ($v.Major -ge 7) {
            return @{ Status = 'PASS'; Detail = "PowerShell $v." }
        }
        return @{
            Status = 'FAIL'
            Detail = "PowerShell $v — Voidseal's engine requires PowerShell >= 7. Install " +
                     "PowerShell 7+ and re-run every voidseal command via 'pwsh', not " +
                     "'powershell.exe'."
        }
    }))

    # ---- 2. Pester >= 5 (test suite only — never gates the live verdict) --
    $results.Add((Invoke-VoidsealCheck -Name 'Pester >= 5' -Critical $false -Body {
        $mods = Get-Module -ListAvailable -Name Pester -ErrorAction Stop
        if (-not $mods -or @($mods).Count -eq 0) {
            return @{
                Status = 'WARN'
                Detail = 'Pester module not found. Not required for a live Invoke-Voidseal ' +
                         "run — only for the test suite (Invoke-Pester -Path tests). " +
                         'Install: Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser.'
            }
        }
        $best = $mods | Sort-Object -Property Version -Descending | Select-Object -First 1
        if ($best.Version.Major -ge 5) {
            return @{ Status = 'PASS'; Detail = "Pester $($best.Version) found." }
        }
        return @{
            Status = 'WARN'
            Detail = "Pester $($best.Version) found, but the suite requires >= 5. " +
                     'Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser.'
        }
    }))

    # ---- 3. Windows edition supports Hyper-V -----------------------------
    $results.Add((Invoke-VoidsealCheck -Name 'Windows edition supports Hyper-V' -Critical $true -Body {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = [string]$os.Caption
        if ($caption -match '(?i)\bHome\b') {
            return @{
                Status = 'FAIL'
                Detail = "$caption — Home editions cannot run Hyper-V at all (needs " +
                         'Pro/Enterprise/Education, or Windows Server).'
            }
        }
        if ($caption -match '(?i)(Pro|Enterprise|Education|Server)') {
            return @{ Status = 'PASS'; Detail = "$caption." }
        }
        return @{
            Status = 'UNKNOWN'
            Detail = "$caption — could not classify this edition string. Verify manually " +
                     'that it is Pro/Enterprise/Education/Server; Home cannot run Hyper-V.'
        }
    }))

    # ---- 4. Hyper-V optional feature enabled -----------------------------
    # NOTE: Get-WindowsOptionalFeature -Online commonly needs elevation. A permission
    # failure here reports UNKNOWN with a note — per the task's fail-safe requirement,
    # this is NEVER classified as FAIL just because we lack rights to check it.
    $results.Add((Invoke-VoidsealCheck -Name 'Hyper-V feature enabled' -Critical $true -Body {
        $feature = $null
        $lastErr = $null
        foreach ($featureName in @('Microsoft-Hyper-V-All', 'Microsoft-Hyper-V')) {
            try {
                $candidate = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
                if ($null -ne $candidate) { $feature = $candidate; break }
            }
            catch {
                $lastErr = $_
            }
        }
        if ($null -ne $feature) {
            if ($feature.State -eq 'Enabled') {
                return @{ Status = 'PASS'; Detail = "$($feature.FeatureName) is Enabled." }
            }
            return @{
                Status = 'FAIL'
                Detail = "$($feature.FeatureName) State=$($feature.State). Enable it: " +
                         "Windows Features UI ('Turn Windows features on or off' -> " +
                         "Hyper-V), or an ELEVATED 'Enable-WindowsOptionalFeature -Online " +
                         "-FeatureName Microsoft-Hyper-V-All' (requires a reboot)."
            }
        }
        $msg = if ($lastErr) { $lastErr.Exception.Message } else { 'no matching feature name resolved' }
        return @{
            Status = 'UNKNOWN'
            Detail = "Could not query the Hyper-V optional feature ($msg). This call " +
                     're-run this checker in an ELEVATED session for a definitive answer, ' +
                     "or check manually: 'dism /online /get-featureinfo " +
                     "/featurename:Microsoft-Hyper-V-All'."
        }
    }))

    # ---- 5. vmms service present/running ---------------------------------
    $results.Add((Invoke-VoidsealCheck -Name 'vmms service (Hyper-V Virtual Machine Management)' -Critical $true -Body {
        try {
            $svc = Get-Service -Name 'vmms' -ErrorAction Stop
        }
        catch {
            return @{
                Status = 'FAIL'
                Detail = "vmms service not found — Hyper-V is not installed on this host " +
                         "($($_.Exception.Message))."
            }
        }
        if ($svc.Status -eq 'Running') {
            return @{ Status = 'PASS'; Detail = "Status=Running, StartType=$($svc.StartType)." }
        }
        return @{
            Status = 'FAIL'
            Detail = "Status=$($svc.Status), StartType=$($svc.StartType). Start it (elevated): " +
                     "'Start-Service vmms'. Note: the FEATURE being enabled and the SERVICE " +
                     'actually running are different things — see the caveat below.'
        }
    }))

    # ---- 6. Elevated OR Hyper-V Administrators ---------------------------
    $results.Add((Invoke-VoidsealCheck -Name 'Elevated session OR Hyper-V Administrators membership' -Critical $true -Body {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($id)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $isHyperVAdmin = $false
        try {
            # BUILTIN\Hyper-V Administrators — well-known SID, stable across locales.
            $hvSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-578')
            $isHyperVAdmin = $principal.IsInRole($hvSid)
        }
        catch {
            # IsInRole(SID) failing (rare) does not invalidate the Administrator result above;
            # just fall through with $isHyperVAdmin left $false.
        }
        if ($isAdmin) {
            return @{ Status = 'PASS'; Detail = 'Session is elevated (Administrator role).' }
        }
        if ($isHyperVAdmin) {
            return @{
                Status = 'PASS'
                Detail = 'Not elevated, but the user is a member of Hyper-V Administrators ' +
                         '(sufficient per the runbook).'
            }
        }
        return @{
            Status = 'FAIL'
            Detail = 'Neither elevated nor detected in Hyper-V Administrators. Live runs ' +
                     'need one or the other (New-SandboxVM fails closed on exactly this). ' +
                     'Note: UAC token filtering means a non-elevated process run BY an ' +
                     'administrator can under-report here — re-run this checker from an ' +
                     'elevated pwsh (Run as Administrator) for a definitive answer.'
        }
    }))

    # ---- 7. Golden parent VHDX (optional) --------------------------------
    $results.Add((Invoke-VoidsealCheck -Name 'Golden parent VHDX (-ParentDiskPath)' -Critical $true -Body {
        if ([string]::IsNullOrWhiteSpace($ParentDiskPath)) {
            return @{
                Status = 'WARN'
                Detail = 'Not checked — pass -ParentDiskPath <path-to-golden.vhdx> to verify. ' +
                         'See guest-images/debian-12-cloud.md for how to build it.'
            }
        }
        if (Test-Path -LiteralPath $ParentDiskPath) {
            return @{ Status = 'PASS'; Detail = "Found at '$ParentDiskPath'." }
        }
        return @{
            Status = 'FAIL'
            Detail = "Not found at '$ParentDiskPath'. Build it per " +
                     'guest-images/debian-12-cloud.md.'
        }
    }))

    return $results.ToArray()
}

# --------------------------------------------------------------------------
# Get-VoidsealOverallVerdict: fold the per-check rows into one headline.
#   - Any CRITICAL row FAIL      -> "NOT READY" (a real, known blocker).
#   - Else any CRITICAL row UNKNOWN -> "UNKNOWN" (can't confirm; go verify by hand).
#   - Else                       -> "READY" (every necessary check passed —
#                                    see the caveat: necessary, not sufficient).
# Non-critical rows (Pester) and WARN rows never gate this.
# --------------------------------------------------------------------------
function Get-VoidsealOverallVerdict {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [object[]] $Results
    )
    $criticalFails    = @($Results | Where-Object { $_.Critical -and $_.Status -eq 'FAIL' })
    $criticalUnknowns = @($Results | Where-Object { $_.Critical -and $_.Status -eq 'UNKNOWN' })

    if ($criticalFails.Count -gt 0) {
        $names = ($criticalFails | ForEach-Object { $_.Name }) -join '; '
        return "NOT READY — blocked on: $names"
    }
    if ($criticalUnknowns.Count -gt 0) {
        $names = ($criticalUnknowns | ForEach-Object { $_.Name }) -join '; '
        return "UNKNOWN — could not verify: $names (see the UNKNOWN rows' Detail for how to check by hand, often by re-running elevated)"
    }
    return 'READY — every necessary check passed (see the caveat below: necessary, not sufficient)'
}

# --------------------------------------------------------------------------
# The "necessary but not sufficient" caveat (Qubes-style): named gotchas that
# a clean PASS table does not, and cannot, rule out.
# --------------------------------------------------------------------------
$script:VoidsealCaveatText = @'
Passing every check above is NECESSARY, not SUFFICIENT, for a successful live run:

  - Nested virtualization: if THIS host is itself a VM (cloud instance, another
    hypervisor's guest, a CI runner), Hyper-V may not be exposed to a nested guest
    even when every check above passes on paper — nested Hyper-V has to be
    explicitly enabled by the OUTER hypervisor/host, and not all of them expose it.
    If you're not sure whether you're on bare metal, check `(Get-CimInstance
    Win32_ComputerSystem).Model` for a hypervisor vendor string ("Virtual Machine",
    "VMware...", "KVM", ...).
  - Admin-rights scope: "Elevated OR Hyper-V Administrators" above is a snapshot of
    THIS process's token, not your account's ceiling. A standard admin account not
    running elevated (UAC token filtering) can under-report; being newly added to
    Hyper-V Administrators does not take effect until you sign out/in (or start a
    fresh session).
  - Feature vs. service: the Hyper-V FEATURE being Enabled and the vmms SERVICE
    actually Running are two different, independently-failing things — enabling
    the feature requires a reboot before the service exists to check at all.
  - This checker deliberately does NOT verify the host-patch CVE floors from
    operator-runbook.md §0.2 (Hyper-V RCE/EoP fixes) or available disk/memory —
    both matter for a live run and neither is safe to infer generically; run the
    §0.2 commands by hand before a live run.
  - A clean "READY" here proves the PRECONDITIONS this checker can see are met. It
    does not run a VM, does not prove the golden image + cloud-init seed are wired
    correctly end-to-end, and is not a substitute for the live-smoke-test walkthrough
    (docs/live-smoke-test.md).
'@

# --------------------------------------------------------------------------
# Bottom-of-file: run + print ONLY when this script is executed directly
# (e.g. `pwsh scripts/Test-VoidsealPrereqs.ps1`), never when dot-sourced
# (`. .\scripts\Test-VoidsealPrereqs.ps1`) to load the function for a test
# or for interactive re-use with different -ParentDiskPath values.
# --------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    if (-not (Test-IsWindowsHost)) {
        Write-Host 'Voidseal is Windows/Hyper-V only. This host is not Windows — nothing to check.' -ForegroundColor Yellow
    }

    $checkResults = Test-VoidsealPrereqs -ParentDiskPath $ParentDiskPath

    Write-Host ''
    Write-Host 'Voidseal prerequisite check (read-only, no elevation required to run this check)' -ForegroundColor Cyan
    Write-Host '================================================================================' -ForegroundColor Cyan
    $checkResults | Format-Table -Property Name, Status, Detail -AutoSize -Wrap | Out-Host

    $verdict = Get-VoidsealOverallVerdict -Results $checkResults
    $verdictColor = if ($verdict -like 'READY*') { 'Green' } elseif ($verdict -like 'NOT READY*') { 'Red' } else { 'Yellow' }
    Write-Host "Overall: $verdict" -ForegroundColor $verdictColor
    Write-Host ''
    Write-Host $script:VoidsealCaveatText -ForegroundColor DarkGray
}
