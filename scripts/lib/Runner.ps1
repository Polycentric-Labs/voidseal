<#
.SYNOPSIS
    Voidseal — Runner + Capturer + Extractor.

.DESCRIPTION
    The "run the workload, capture out-of-band, extract one-way" trio that follows the seal.
    EVERYTHING that touches Hyper-V goes through the backend abstraction
    (HyperVBackend.ps1); this file NEVER calls a raw Hyper-V cmdlet. That single seam is what
    lets the whole thing unit-test against the in-memory fake.

    Dot-source this file (after HyperVBackend.ps1 + ProfileLoader.ps1 + Provisioner.ps1 + Sealer.ps1)
    to get:

        Start-SandboxWorkload  -Descriptor <d> -Entrypoint <cmd> [-ArtifactRoot <dir>]
                               [-TimeoutSeconds <n>] [-Backend]
        Export-SandboxArtifact -Descriptor <d> -ResultPath <path> -Destination <host-dir> [-Backend]
        Export-ColdVhdxQuarantine -Descriptor <d> ... [-Backend]   # Tier>=2 sink — THROWS (post-v1)

    INJECTION: backend-touching functions take `-Backend <hashtable>` defaulting to
    `(New-RealHyperVBackend)`. Production passes nothing (real Hyper-V); tests pass
    `-Backend (New-FakeHyperVBackend)` and assert against the fake's in-memory state.

    THE RUNNER (Start-SandboxWorkload — Runner/Capturer):
      The guest is a Linux VM driven over the COM1 named-pipe serial console (PowerShell Direct is
      Windows-guest-only). The Runner:
        1. preflight TestAvailable (fail closed if Hyper-V is unreachable — never claim a phantom run),
        2. StartVM (ensure the sealed-but-off VM is powered on),
        3. deliver the entrypoint over the serial seam (backend.InvokeGuestCommand — the FAKE records
           the command + returns canned output; the REAL impl wires the COM1 pipe),
        4. ARM host-side capture (out-of-band, P8 — never trust the guest to self-report): write run
           metadata (start/end, exit status, captured stdout/stderr) to a host-side artifact dir.
      Returns a run-result PSCustomObject the orchestrator + Extractor consume. A NON-ZERO guest exit
      is a RUN OUTCOME reported on the result (ExitCode), NOT a thrown error — the orchestrator decides.

    THE EXTRACTOR (Export-SandboxArtifact — the one-way-out boundary):
      * Tier 0/1: the workload isn't presumed hostile — the host READS the designated result file/dir
        into the host destination (one-way OUT). This is the trusting host-read.
      * Tier >= 2: presumed HOSTILE. The cold-VHDX -> revert -> detach -> read-only-mount-in-quarantine
        -> AV+CDR -> inert-promote flow is scaffolded/benign-only and NOT built in v1. The
        Tier>=2 path MUST route to Export-ColdVhdxQuarantine, a clearly-marked sink that THROWS
        NotImplemented. It MUST NOT fall through to the Tier-0/1 trusting read — extracting from a
        presumed-hostile tier via the trusting path would defeat the whole containment model.

    BACKEND ADDENDUM:
      * InvokeGuestCommand @{ VMName; Command; TimeoutSeconds } -> @{ ExitCode; Stdout; Stderr } —
        added to the backend (manifest + both factories + parity/drift tests). The backend previously had no
        way to deliver a command to a Linux guest + read its result; the Runner must NOT open the
        COM1 named pipe / drive the serial console with a raw cmdlet. Real backend = a best-effort
        named-pipe serial client (exercised live in the operator-run smoke test, not in a non-elevated
        session); fake = records the command + returns canned output. Follows the RemoveVHD /
        RemoveSwitch / SetHostChannel addendum precedent. See HyperVBackend.ps1.
#>

Set-StrictMode -Version Latest

# --------------------------------------------------------------------------
# Internal helpers (shared shape readers — mirror the Sealer/Provisioner accessors)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Read a field off a sandbox descriptor (PSCustomObject OR hashtable) with a default. StrictMode-safe.
.DESCRIPTION
    Re-declared locally (small + self-contained) so this file is usable when dot-sourced standalone,
    matching Get-DescriptorField in Sealer.ps1. Branches on hashtable vs PSObject.
#>
function Get-RunnerDescriptorField {
    [CmdletBinding()]
    param([AllowNull()] $Descriptor, [Parameter(Mandatory)] [string] $Name, $Default = $null)
    if ($null -eq $Descriptor) { return $Default }
    if ($Descriptor -is [System.Collections.IDictionary]) {
        if ($Descriptor.Contains($Name) -and $null -ne $Descriptor[$Name]) { return $Descriptor[$Name] }
        return $Default
    }
    $prop = $Descriptor.PSObject.Properties[$Name]
    if ($null -ne $prop -and $null -ne $prop.Value) { return $prop.Value }
    return $Default
}

<#
.SYNOPSIS
    Resolve a descriptor's Tier to a definite integer in 0..3, or $null if it cannot be determined.
.DESCRIPTION
    FAIL-CLOSED tier resolution for the artifact-exfil boundary (Export-SandboxArtifact). A safety
    function guarding the one-way-OUT path must NEVER guess "trusting tier 0" when the descriptor's
    Tier is absent / $null / not a clean integer / out of the valid 0..3 range. Those cases are
    UNDETERMINABLE and the caller must treat them as hostile (route to the quarantine stub / refuse),
    NOT default them to the Tier-0/1 trusting host-read.

    Returns:
      * an [int] in 0..3 when the descriptor carries a clean, in-range integer (or numeric STRING) Tier;
      * $null when the Tier is absent, $null, non-integer ('banana'), fractional, or out of range (e.g. 7).
    Uses a strict [int]::TryParse on the string form (no culture surprises, no silent [int] coercion of
    a non-numeric to a throw mid-flow) so the decision is explicit at the call site.
#>
function Resolve-RunnerTier {
    [CmdletBinding()]
    [OutputType([System.Nullable[int]])]
    param([AllowNull()] $Descriptor)
    # Pull the RAW value with NO default — a missing/$null field yields $null (undeterminable), never 0.
    $raw = Get-RunnerDescriptorField -Descriptor $Descriptor -Name 'Tier' -Default $null
    if ($null -eq $raw) { return $null }
    # Already an integral numeric type? Accept directly (still range-checked below).
    if ($raw -is [int] -or $raw -is [long] -or $raw -is [short] -or $raw -is [byte]) {
        $n = [int]$raw
    }
    else {
        # Anything else (string, double, etc.): require a strict whole-number parse of its string form.
        # [int]::TryParse rejects 'banana', '2.5', '', whitespace — those stay undeterminable ($null).
        $parsed = 0
        if (-not [int]::TryParse(([string]$raw).Trim(), [ref] $parsed)) { return $null }
        $n = $parsed
    }
    if ($n -lt 0 -or $n -gt 3) { return $null }   # out of the valid tier range => undeterminable
    return $n
}

<#
.SYNOPSIS
    Wait for the guest to become BOOT-READY by probing the serial seam, retrying until a cheap probe
    command succeeds or the deadline elapses. Returns a result hashtable; NEVER throws on a not-ready
    guest (it RETURNS Ready=$false so the caller reports a clean timeout instead of crashing).
.DESCRIPTION
    A real Debian guest needs ~20-60s to boot + run cloud-init (which the SEED ISO drives) before the
    serial-getty console accepts a command. Calling InvokeGuestCommand immediately after StartVM would
    race the boot, so the Runner probes readiness FIRST. The probe is a cheap command (default 'true')
    whose SUCCESS (ExitCode 0) means the console is up. The wait/poll is INJECTABLE so tests never sleep:
      * -DeadlineSeconds 0  -> exactly ONE probe attempt, no inter-attempt sleep (instant for the fake).
      * -PollDelaySeconds 0 -> the retry loop does not sleep between attempts (tests pass 0).
    A backend/serial failure mid-probe (InvokeGuestCommand THROWS) is treated as "not ready yet" — it is
    caught and retried, never propagated — so a guest that is still coming up does not crash the wait. A
    persistently-unavailable backend is the caller's preflight concern (handled before this is reached).
.PARAMETER Backend
    The Hyper-V backend.
.PARAMETER VMName
    The VM to probe.
.PARAMETER ProbeCommand
    The cheap readiness probe command (default 'true').
.PARAMETER DeadlineSeconds
    Max seconds to keep probing. 0 = a single attempt.
.PARAMETER PollDelaySeconds
    Seconds to sleep between failed attempts (0 in tests so the loop never sleeps).
.PARAMETER PerProbeTimeoutSeconds
    TimeoutSeconds handed to each probe's InvokeGuestCommand.
#>
function Wait-GuestBootReady {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [hashtable] $Backend,
        [Parameter(Mandatory)] [string] $VMName,
        [string] $ProbeCommand = 'true',
        [int]    $DeadlineSeconds = 60,
        [int]    $PollDelaySeconds = 5,
        [int]    $PerProbeTimeoutSeconds = 30
    )

    $started  = (Get-Date).ToUniversalTime()
    $deadline = (Get-Date).AddSeconds([Math]::Max(0, $DeadlineSeconds))
    $attempts = 0
    $lastErr  = ''

    while ($true) {
        $attempts++
        try {
            $probe = & $Backend.InvokeGuestCommand @{ VMName = $VMName; Command = $ProbeCommand; TimeoutSeconds = $PerProbeTimeoutSeconds }
            $isDict = ($probe -is [System.Collections.IDictionary])
            $rc = [int]$(if ($isDict -and $probe.Contains('ExitCode')) { $probe['ExitCode'] } else { -1 })
            if ($rc -eq 0) {
                return @{
                    Ready    = $true
                    Attempts = $attempts
                    Status   = "guest became boot-ready after $attempts probe attempt(s)"
                    WaitedAt = $started.ToString('o')
                }
            }
            $lastErr = "probe '$ProbeCommand' returned non-zero exit $rc"
        }
        catch {
            # A serial/backend hiccup mid-boot is "not ready yet" — retry, never crash the wait.
            $lastErr = $_.Exception.Message
        }

        # Deadline check AFTER the attempt so DeadlineSeconds 0 still makes exactly one attempt.
        if ((Get-Date) -ge $deadline) {
            return @{
                Ready    = $false
                Attempts = $attempts
                Status   = "guest did NOT become boot-ready within ${DeadlineSeconds}s ($attempts probe attempt(s)); last: $lastErr"
                WaitedAt = $started.ToString('o')
            }
        }
        if ($PollDelaySeconds -gt 0) { Start-Sleep -Seconds $PollDelaySeconds }
    }
}

# --------------------------------------------------------------------------
# Public: Start-SandboxWorkload  (the Runner + host-side Capturer)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Start a sealed sandbox VM, deliver the entrypoint over the COM1 serial seam, arm host-side
    capture, and return a run-result. NEVER calls a raw Hyper-V cmdlet (goes through the backend).
.DESCRIPTION
    See the file header (THE RUNNER). The seal gate (Assert-Sealed) is the ORCHESTRATOR's
    responsibility before calling this — the Runner itself just needs a provisioned VM to start. A
    non-zero guest exit is reported on the result (ExitCode), not thrown. Fails closed if the host
    is unreachable (TestAvailable preflight) so it never claims a phantom run.
.PARAMETER Descriptor
    The sandbox descriptor (its Name identifies the VM; Tier is recorded on the result/capture).
.PARAMETER Entrypoint
    The workload command to run in the guest (e.g. 'bash ralph_loop.sh').
.PARAMETER ArtifactRoot
    Host-side directory under which the capture artifact is written (out-of-band). Defaults to a
    per-VM dir under the system temp path. Created if absent.
.PARAMETER TimeoutSeconds
    Max seconds to wait for the guest command (passed to the backend's InvokeGuestCommand). Default 300.
.PARAMETER BootWaitSeconds
    BOOT-READINESS deadline. After StartVM and BEFORE delivering the entrypoint, the Runner runs a
    cheap readiness PROBE (BootProbeCommand) over the serial seam, retrying until it succeeds or this many
    seconds elapse. A FIRST cloud-init boot off a fresh differencing disk needs ~90-180s before the serial
    console accepts a command (a live run timed out at 60s), so the default is 180 on the LIVE path. The
    probe/delay is INJECTABLE so tests never sleep: BootWaitSeconds 0 makes a SINGLE probe attempt (no real
    delay); with the FAKE (instant-ready) that one attempt succeeds and the entrypoint runs. If the guest
    never becomes ready before the deadline the Runner REPORTS a clear timeout on the run result (ExitCode
    != 0, BootWaitStatus) — it does NOT crash and it does NOT deliver the entrypoint (so the first command
    never races a guest that did not come up). Default 180.
.PARAMETER BootProbeCommand
    The cheap command the readiness probe delivers (default 'true') — its success means the serial console
    is up and the guest is accepting commands. Its OUTPUT is discarded; only success/failure gates the run.
.PARAMETER BootPollDelaySeconds
    Seconds to wait BETWEEN failed probe attempts (default 5 on the LIVE path). Injected as 0 in tests so
    the retry loop never sleeps. Only used when BootWaitSeconds > 0 (i.e. when more than one attempt fits).
.PARAMETER Backend
    The Hyper-V backend. Defaults to the real one; tests inject the fake.
#>
function Start-SandboxWorkload {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Descriptor,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Entrypoint,
        [string] $ArtifactRoot,
        [int]    $TimeoutSeconds = 300,
        [int]    $BootWaitSeconds = 180,
        [string] $BootProbeCommand = 'true',
        [int]    $BootPollDelaySeconds = 5,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    if ($null -eq $Descriptor) {
        throw "Start-SandboxWorkload: -Descriptor is null. Pass a New-SandboxVM descriptor."
    }
    $vmName = [string](Get-RunnerDescriptorField -Descriptor $Descriptor -Name 'Name')
    if ([string]::IsNullOrWhiteSpace($vmName)) {
        throw "Start-SandboxWorkload: descriptor has no VM Name."
    }
    if ([string]::IsNullOrWhiteSpace($Entrypoint)) {
        throw "Start-SandboxWorkload: -Entrypoint is blank. A workload needs a command to run."
    }
    $tier = [int](Get-RunnerDescriptorField -Descriptor $Descriptor -Name 'Tier' -Default 0)

    # --- preflight: fail closed if Hyper-V is unreachable (never claim a phantom run) ----
    $probe = & $Backend.TestAvailable @{}
    if (-not $probe.Available) {
        $reason = if ($probe.ContainsKey('Reason') -and $probe.Reason) { $probe.Reason } else { '(no reason reported)' }
        throw "Start-SandboxWorkload: cannot run '$vmName' — Hyper-V unavailable or insufficient privilege. Backend reports: $reason"
    }

    # --- the VM must exist on the backend --------------------------------
    $vm = & $Backend.GetVM @{ Name = $vmName }
    if ($null -eq $vm) {
        throw "Start-SandboxWorkload: no VM named '$vmName' on the backend; cannot run a workload on a missing VM."
    }

    # --- resolve the host-side artifact dir (out-of-band capture lands here) ----
    if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
        $ArtifactRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("Voidseal\artifacts\{0}" -f $vmName)
    }
    if (-not (Test-Path -LiteralPath $ArtifactRoot)) {
        New-Item -ItemType Directory -Path $ArtifactRoot -Force | Out-Null
    }

    # --- 1. start the VM (a sealed VM is powered off) --------------------
    # Effect-only: suppress ($null = ...) so the REAL backend's Start-VM stream emission can't leak
    # into Start-SandboxWorkload's return (it returns a run-result object; a stray emission would
    # turn that into an array) — the output-stream-pollution class of bug.
    $null = & $Backend.StartVM @{ Name = $vmName }

    # --- 1b. WAIT for the guest to become boot-ready ----------------
    # A real Debian guest needs ~20-60s to boot + run cloud-init (driven by the SEED ISO) before the
    # serial-getty console accepts a command. Probe readiness BEFORE delivering the entrypoint so the
    # first command never races the boot. The wait is INJECTABLE (BootWaitSeconds / BootPollDelaySeconds)
    # so tests don't sleep: 0 makes a single instant probe the fake passes immediately. If the guest
    # never becomes ready, REPORT a clear timeout on the run result (no crash) and do NOT deliver the
    # entrypoint (the result mirrors the run-result shape so the orchestrator + capture handle it like
    # any failed run; teardown still runs in the orchestrator's finally).
    $bootStartedAt = (Get-Date).ToUniversalTime()
    $boot = Wait-GuestBootReady -Backend $Backend -VMName $vmName -ProbeCommand $BootProbeCommand `
        -DeadlineSeconds $BootWaitSeconds -PollDelaySeconds $BootPollDelaySeconds -PerProbeTimeoutSeconds $TimeoutSeconds
    if (-not [bool]$boot['Ready']) {
        $bootEndedAt = (Get-Date).ToUniversalTime()
        $bootStatus  = [string]$boot['Status']
        # Arm host-side capture for the failed boot too (out-of-band record of the timeout).
        $bootCapture = [ordered]@{
            VMName         = $vmName
            Tier           = $tier
            Entrypoint     = $Entrypoint
            ExitCode       = -1
            BootWaitStatus = $bootStatus
            StartedAt      = $bootStartedAt.ToString('o')
            EndedAt        = $bootEndedAt.ToString('o')
            Stdout         = ''
            Stderr         = $bootStatus
        }
        $bootCapturePath = Join-Path $ArtifactRoot ('run-{0:yyyyMMddTHHmmssfffZ}.json' -f $bootStartedAt)
        $bootCapture | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $bootCapturePath -Encoding utf8
        return [pscustomobject]@{
            VMName         = $vmName
            Tier           = $tier
            Entrypoint     = $Entrypoint
            ExitCode       = -1
            Stdout         = ''
            Stderr         = $bootStatus
            BootWaitStatus = $bootStatus
            StartedAt      = $bootStartedAt
            EndedAt        = $bootEndedAt
            CapturePath    = $bootCapturePath
            ArtifactRoot   = $ArtifactRoot
        }
    }

    # --- 2. deliver the entrypoint over the serial seam + capture its output ----
    # DEFERRED (to the real backend): the serial-console exit-code/output framing carries no
    # per-command RC nonce yet, so a chatty guest could in principle spoof the reported result. The
    # integrity nonce belongs with the real COM1 named-pipe client, not this fake-backed v1.
    $startedAt = (Get-Date).ToUniversalTime()
    $invoke    = & $Backend.InvokeGuestCommand @{ VMName = $vmName; Command = $Entrypoint; TimeoutSeconds = $TimeoutSeconds }
    $endedAt   = (Get-Date).ToUniversalTime()

    # Read the result fields defensively (a real/fake backend returns a hashtable; treat a malformed
    # result as a failed run rather than crashing). `if` is a STATEMENT in PowerShell, so wrap in $().
    $isDict   = ($invoke -is [System.Collections.IDictionary])
    $exitCode = [int]$(if ($isDict -and $invoke.Contains('ExitCode')) { $invoke['ExitCode'] } else { -1 })
    $stdout   = [string]$(if ($isDict -and $invoke.Contains('Stdout')) { $invoke['Stdout'] } else { '' })
    $stderr   = [string]$(if ($isDict -and $invoke.Contains('Stderr')) { $invoke['Stderr'] } else { '' })

    # --- 3. ARM host-side capture: write run metadata out-of-band --------
    # P8: capture is host-side, NEVER trusting the guest to self-report. The captured stdout/stderr
    # arrived via the serial seam (the backend), not a guest-written file we blindly ingest.
    $capture = [ordered]@{
        VMName     = $vmName
        Tier       = $tier
        Entrypoint = $Entrypoint
        ExitCode   = $exitCode
        StartedAt  = $startedAt.ToString('o')
        EndedAt    = $endedAt.ToString('o')
        Stdout     = $stdout
        Stderr     = $stderr
    }
    $capturePath = Join-Path $ArtifactRoot ('run-{0:yyyyMMddTHHmmssfffZ}.json' -f $startedAt)
    $capture | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $capturePath -Encoding utf8

    # --- run-result the orchestrator + Extractor consume ------------------
    return [pscustomobject]@{
        VMName         = $vmName
        Tier           = $tier
        Entrypoint     = $Entrypoint
        ExitCode       = $exitCode
        Stdout         = $stdout
        Stderr         = $stderr
        BootWaitStatus = [string]$boot['Status']   # the boot-readiness outcome (the guest WAS ready here)
        StartedAt      = $startedAt
        EndedAt        = $endedAt
        CapturePath    = $capturePath
        ArtifactRoot   = $ArtifactRoot
    }
}

# --------------------------------------------------------------------------
# Public: Export-ColdVhdxQuarantine  (the Tier>=2 extraction sink — STUB, THROWS)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Tier >= 2 one-way artifact exit via the cold-VHDX -> quarantine VM -> CDR flow. NOT IMPLEMENTED
    in v1 (scaffolded/benign-only, post-v1) — THROWS a clear NotImplemented message.
.DESCRIPTION
    This is the single clearly-marked SINK for Tier >= 2 extraction. A presumed-hostile
    guest's artifacts must NEVER be read with the trusting Tier-0/1 host-read. The full flow (guest
    writes to a dedicated output-VHDX -> power off -> revert to a clean snapshot -> DETACH the VHDX ->
    mount it READ-ONLY in a SEPARATE no-net quarantine VM -> AV scan + Content-Disarm-&-Reconstruction
    -> promote only inert, sanitized formats to the host) is the riskiest post-v1 work and is
    deliberately NOT built this round. Calling it THROWS so that:
      (a) a Tier >= 2 extraction can never silently succeed via a trusting read, and
      (b) no one can accidentally wire a Tier-0/1-style read through this function later by mistake.
    Live detonation/extraction from a hostile tier stays gated behind explicit operator approval + a
    verified-isolation build.
.PARAMETER Descriptor
    The sandbox descriptor (Tier >= 2). Accepted so the signature matches the real flow it stubs.
.PARAMETER ResultPath
    The in-guest / output-VHDX result location (unused by the stub — recorded in the throw context).
.PARAMETER Destination
    The intended host destination (unused by the stub).
.PARAMETER Backend
    The Hyper-V backend. Accepted for signature parity with the real flow.
#>
function Export-ColdVhdxQuarantine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Descriptor,
        [string] $ResultPath,
        [string] $Destination,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    $vmName = [string](Get-RunnerDescriptorField -Descriptor $Descriptor -Name 'Name' -Default '(unknown)')
    $tier   = [int](Get-RunnerDescriptorField -Descriptor $Descriptor -Name 'Tier' -Default 2)
    throw ("Export-ColdVhdxQuarantine: the Tier-$tier cold-VHDX -> quarantine-VM -> CDR extraction " +
           "flow is NOT IMPLEMENTED in v1 (scaffolded/benign-only, post-v1). Refusing to " +
           "extract from presumed-hostile VM '$vmName' — a Tier>=2 artifact must go through the cold " +
           "output-VHDX + read-only quarantine mount + Content-Disarm-&-Reconstruction (CDR) + inert-" +
           "format promotion, NEVER the trusting Tier-0/1 host-read. Live hostile-tier extraction is " +
           "gated behind explicit approval + a verified-isolation build.")
}

# --------------------------------------------------------------------------
# Public: Export-SandboxArtifact  (the Extractor — one-way OUT, tier-routed)
# --------------------------------------------------------------------------

<#
.SYNOPSIS
    Extract a workload's result artifact across the one-way boundary into a host destination.
    Tier 0/1: a trusting host-read. Tier >= 2: routes to the quarantine stub (THROWS), never the read.
.DESCRIPTION
    See the file header (THE EXTRACTOR). The tier is read from the descriptor and decides the path
    BEFORE any read happens, so a Tier >= 2 extraction can never fall through to the trusting read.
.PARAMETER Descriptor
    The sandbox descriptor (its Tier routes the extraction; Name is used in messages).
.PARAMETER ResultPath
    The host-readable result file or directory the workload emitted (Tier 0/1). For Tier >= 2 it is
    passed to the quarantine stub (which throws before reading it).
.PARAMETER Destination
    The host-side destination directory artifacts are copied into (Tier 0/1). Created if absent.
.PARAMETER Backend
    The Hyper-V backend. Defaults to the real one; tests inject the fake. (Tier 0/1 extraction
    is a host filesystem read and does not currently call the backend, but the param is kept for
    signature uniformity + the Tier >= 2 quarantine flow that will.)
#>
function Export-SandboxArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Descriptor,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $ResultPath,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Destination,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    if ($null -eq $Descriptor) {
        throw "Export-SandboxArtifact: -Descriptor is null. Pass a sandbox descriptor."
    }
    $vmName = [string](Get-RunnerDescriptorField -Descriptor $Descriptor -Name 'Name' -Default '(unknown)')

    # --- TIER ROUTING (decided BEFORE any read) --------------------------
    # FAIL CLOSED on an undeterminable tier. Resolve-RunnerTier returns a definite int in 0..3 or $null
    # (Tier absent / $null / non-integer / out of range). For a boundary guarding artifact EXFIL from a
    # possibly-hostile VM, "unknown tier => trusting tier-0 read" is the wrong default — an undeterminable
    # tier is treated as MAXIMALLY hostile and refused HERE, before any tier comparison, so it can never
    # fall through to the Tier-0/1 trusting host-read. The throw makes the "could not determine tier"
    # reason explicit; nothing is copied to the host. (A determinable Tier>=2 routes to the quarantine
    # sink just below — also a throw — so every non-Tier-0/1 path fails closed.)
    $tier = Resolve-RunnerTier -Descriptor $Descriptor
    if ($null -eq $tier) {
        $rawTier = Get-RunnerDescriptorField -Descriptor $Descriptor -Name 'Tier' -Default '(absent)'
        throw ("Export-SandboxArtifact: cannot determine the tier of '$vmName' (descriptor Tier = " +
               "'$rawTier' is absent/null/non-integer/out-of-range). Refusing to extract via the trusting " +
               "Tier-0/1 host-read — an undeterminable tier is treated as presumed-HOSTILE and must go " +
               "through the cold-VHDX quarantine flow, never the trusting read. Set an explicit Tier in 0..3.")
    }

    # Tier >= 2 is presumed hostile: route to the quarantine sink, which THROWS. This MUST come
    # before the Tier-0/1 read so a hostile-tier artifact is never trustingly copied to the host.
    if ($tier -ge 2) {
        return (Export-ColdVhdxQuarantine -Descriptor $Descriptor -ResultPath $ResultPath -Destination $Destination -Backend $Backend)
    }

    # --- Tier 0/1: the trusting one-way host-read ------------------------
    if ([string]::IsNullOrWhiteSpace($ResultPath)) {
        throw "Export-SandboxArtifact: -ResultPath is blank; nothing to extract for '$vmName'."
    }
    if (-not (Test-Path -LiteralPath $ResultPath)) {
        throw "Export-SandboxArtifact: result artifact not found at '$ResultPath' (nothing to extract — fail closed)."
    }
    if ([string]::IsNullOrWhiteSpace($Destination)) {
        throw "Export-SandboxArtifact: -Destination is blank."
    }
    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    $written = [System.Collections.Generic.List[string]]::new()
    $item = Get-Item -LiteralPath $ResultPath
    if ($item.PSIsContainer) {
        # A result DIRECTORY: COLLECT its contents into the destination (one-way out). We copy the
        # directory's children (not the dir itself) so the emitted artifacts land directly under the
        # host destination, then report each top-level item the host now holds.
        $children = @(Get-ChildItem -LiteralPath $ResultPath -Force)
        foreach ($child in $children) {
            $dest = Join-Path $Destination $child.Name
            Copy-Item -LiteralPath $child.FullName -Destination $dest -Recurse -Force
            $written.Add($dest)
        }
        # An empty result dir still yields a (now-created) destination so the caller has a path.
        if ($written.Count -eq 0) { $written.Add($Destination) }
    }
    else {
        # A result FILE: copy it into the destination dir (one-way out).
        $leaf = Split-Path -Leaf $ResultPath
        $dest = Join-Path $Destination $leaf
        Copy-Item -LiteralPath $ResultPath -Destination $dest -Force
        $written.Add($dest)
    }

    return $written.ToArray()
}
