<#
.SYNOPSIS
    Voidseal: host Python interpreter resolution (Resolve-PythonExe).

.DESCRIPTION
    Dot-source this file to get Resolve-PythonExe. It is shared by Invoke-Voidseal.ps1 (the
    seam-#2 outbox read shells host/read_outbox.py) and SensitivityGate.ps1 (Run mode shells
    guest/screener.py on the host), so both resolve the same real interpreter instead of a bare
    `python` that PATH may map to an App Execution Alias stub. Has no dependencies; safe to
    dot-source more than once.
#>

Set-StrictMode -Version Latest

# --------------------------------------------------------------------------
# Resolve-PythonExe: robust host python3/python resolution.
#
# A hard `& python3` BREAKS the Windows host: the Windows Python installer provides
# `python`, not `python3`. The in-guest binary is `python3` (Debian), but the HOST
# shelling `host/read_outbox.py` at the seam-#2 gate is Windows PowerShell, which
# needs the Windows `python` executable. Get-Command probes both names; throw fail-
# closed naming both if NEITHER resolves (prefer python3 on non-Windows for safety).
#
# Windows App Execution Aliases (zero-byte python.exe / python3.exe reparse points under
# %LOCALAPPDATA%\Microsoft\WindowsApps) are skipped. Launching one goes through MSIX package
# activation, and what runs next is up to the package: the Store redirector, a packaged
# interpreter, or the Python install manager's launcher, which picks a runtime from its own
# settings. So the interpreter that parses a guest-written outbox can be chosen by something
# other than PATH, and activation adds a step that can fail. PowerShell 7 reports a failed first
# launch as "StandardOutputEncoding is only supported when standard output is redirected" (its
# ShellExecute retry keeps the encoding it set for captured output), which hides the Win32 error.
# The result is the first non-alias match: python3 before python, each name in PATH order.
# --------------------------------------------------------------------------
<#
.SYNOPSIS
    Resolve the host Python executable path (python3 preferred, python fallback).
.DESCRIPTION
    A hard `& python3` breaks on Windows hosts where the Python installer provides
    `python`. This asks Get-Command for every Application match of each name and returns
    the first real interpreter, skipping Windows App Execution Aliases. Throws a clear
    fail-closed message naming both candidates if neither resolves, listing any alias it
    skipped.
.PARAMETER CommandLookup
    Returns the PATH-ordered Application matches for one command name. Defaults to
    Get-Command -Name <name> -CommandType Application -All; tests inject a fake so the
    result does not depend on the machine's PATH.
#>
function Resolve-PythonExe {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [scriptblock] $CommandLookup = {
            param($Name) Get-Command -Name $Name -CommandType Application -All -ErrorAction SilentlyContinue
        }
    )

    $skippedAliases = [System.Collections.Generic.List[string]]::new()
    foreach ($name in 'python3', 'python') {
        foreach ($cmd in @(& $CommandLookup $name)) {
            if ($null -eq $cmd) { continue }
            # Aliases are recognized by location: a \Microsoft\WindowsApps\ segment pair matches the
            # alias directory under any profile root plus its per-package subfolders, with no
            # file-system access, so the choice depends only on what the lookup returned.
            if ($cmd.Source -match '[\\/]Microsoft[\\/]WindowsApps[\\/]') {
                $skippedAliases.Add($cmd.Source)
                continue
            }
            return $cmd.Source
        }
    }

    $aliasNote = ''
    if ($skippedAliases.Count -gt 0) {
        $aliasNote = (' as a real interpreter (skipped Windows App Execution Alias stub(s), which ' +
                      'launch through MSIX package activation: {0})') -f ($skippedAliases -join ', ')
    }
    throw ("Resolve-PythonExe: neither 'python3' nor 'python' was found on PATH$aliasNote. " +
           "Install Python and ensure it is on the PATH (Windows: the Python installer " +
           "adds 'python'; Linux/macOS: 'python3'). Failing closed.")
}
