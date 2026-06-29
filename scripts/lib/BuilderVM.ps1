<#
.SYNOPSIS
    Voidseal — Invoke-BuilderVM, the Tier-1 builder orchestrator.

.DESCRIPTION
    Runs a DepsSpec in a net-restricted Hyper-V VM and emits a hash-verified deps.vhdx.

    MIRRORS Invoke-Voidseal's INIT->PROVISION->disks->seed->start->wait->detach flow
    (Invoke-Voidseal.ps1:242-463), MINUS THE SEAL, plus a whole-image hash + emit.

    FLOW:
      INIT        load + validate the builder profile (must be EgressMode='SquidSniProxy').
      PROVISION   New-SandboxVM — Tier-1 VM with NIC (the fetch needs the net).
      DISKS       New-WorkloadDisks — INPUT (runner+DepsSpec) + OUTPUT (deps.vhdx-to-be).
      SEED        New-WorkloadSeedDisk — CIDATA data disk carrying the Squid seed (RC6).
      RC7         SetAutomaticCheckpoints Enabled=$false — so guest writes land in the base
                  .vhdx, not a differencing .avhdx, which is what the host hashes.
      NO SEAL     The builder is Tier-1 NET-RESTRICTED — it KEEPS its NIC + Squid egress for
                  the whole run (it must fetch deps). Do NOT call Lock-Sandbox/Assert-Sealed.
      RUN         StartVM -> Wait-WorkloadComplete (the guest fetches deps, self-powers-off).
      DETACH      RemoveHardDiskDrive the OUTPUT/deps disk BEFORE the hash (an attached disk is
                  locked; the fake THROWS on GetVhdxImageHash while still attached).
      HASH        GetVhdxImageHash — whole-file SHA-256 in USER-SPACE (NEVER Mount-VHD).
      EMIT        Record DepsDiskPath + WholeImageHash + Status=Success.
      TEARDOWN    Remove-Sandbox in a finally. NOTE: in the DEFAULT case $DepsDiskPath == OutputDiskPath,
                  which New-WorkloadDisks PUT in CreatedDisks, so Remove-Sandbox -DeleteDisks DELETES it.
                  deps.vhdx persistence is LIVE-only, pending the Phase-6 Copy-Item to a stable path that
                  is NOT in CreatedDisks (the commented-out Copy-Item below the hash). Until then the
                  whole-image hash is the durable artifact; the deps .vhdx itself does not survive teardown.

    DESIGN DECISIONS (resolved — do not redesign):
      * No host-mount: the integrity artifact is the whole-image hash (GetVhdxImageHash, raw).
      * Success = clean power-off: -not $wait.TimedOut -> Status='Success'; timeout -> 'Failed'.
        The exitcode/per-file-manifest outbox read DEFERS to Phase 4.
      * deps.vhdx persistence is LIVE-only (Phase 6): in the DEFAULT case DepsDiskPath == OutputDiskPath,
        which IS in CreatedDisks, so teardown's Remove-Sandbox -DeleteDisks DELETES it. The Phase-6
        Copy-Item to a stable path NOT in CreatedDisks is what will make deps.vhdx survive; until then the
        mock just sets DepsDiskPath to the OUTPUT path and records the hash (the durable artifact).

    Dot-source this file AFTER Invoke-Voidseal.ps1 (which dot-sources all engine libs:
    HyperVBackend.ps1, ProfileLoader.ps1, Provisioner.ps1, Sealer.ps1, Runner.ps1,
    Workload.ps1, SeedBuilder.ps1, SensitivityGate.ps1).

    RETURNS [hashtable]:
        DepsDiskPath   — host-side path to the emitted deps.vhdx (or $null on failure).
        WholeImageHash — lowercase hex SHA-256 of the deps.vhdx (or $null on failure).
        Status         — 'Success' | 'Failed'.
        Error          — the failure message on a non-Success run, or $null.
        States         — the lifecycle phases traversed (INIT, PROVISIONED, STAGED, RUNNING,
                         DETACHED, HASHED, DESTROYED), for diagnostics.
#>

Set-StrictMode -Version Latest

# NOTE: Resolve-PythonExe is defined in Invoke-Voidseal.ps1 (fold-in #1).
# Always dot-source Invoke-Voidseal.ps1 BEFORE this file. The test BeforeAll
# does this; the function is available without re-defining it here.

# --------------------------------------------------------------------------
# Public: Invoke-BuilderVM (the Tier-1 builder orchestrator)
# --------------------------------------------------------------------------
<#
.SYNOPSIS
    Run the Tier-1 builder: provision -> disks -> seed -> run (no seal) -> detach -> hash -> emit.
.PARAMETER Profile
    A builder profile NAME, a .psd1 PATH, or an already-normalized profile HASHTABLE.
    Must have EgressMode='SquidSniProxy' and a DepsSpec key.
.PARAMETER Name
    (Optional) the VM name. Defaults to a unique 'bld-<rand>'.
.PARAMETER DepsDiskPath
    (Optional) the host-side path to emit the deps.vhdx to. Defaults to the OUTPUT disk path
    (the working disk the Provisioner/WorkloadDisks created). In the mock, these are identical.
    LIVE-only (Phase 6): the OUTPUT disk is moved/copied to this stable path so teardown can
    remove the working disks while deps.vhdx persists.
.PARAMETER RunnerScriptPath
    (Optional) the host path to the in-guest fetch_deps.py runner (seeded into the INPUT disk).
    Defaults to guest/fetch_deps.py under the skill root.
.PARAMETER WorkloadTimeoutSeconds
    (Optional) wall-clock deadline for the guest to self-power-off. Default 600. Pass 0 in
    tests (one instant poll then trips the deadline — no real sleep).
.PARAMETER Backend
    The Hyper-V backend. Defaults to the real one; tests inject the fake.
#>
function Invoke-BuilderVM {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [AllowNull()] $Profile,
        [string]    $Name,
        [string]    $DepsDiskPath,
        [string]    $RunnerScriptPath = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'guest\fetch_deps.py'),
        [int]       $WorkloadTimeoutSeconds = 600,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )

    # --- INIT: load + validate the profile (fail-closed before any backend call) ---
    $resolved = Resolve-DeployProfile -Profile $Profile -Tier 1

    # Builder guard: refuse anything that isn't a SquidSniProxy-egress profile.
    if ([string]$resolved['EgressMode'] -ne 'SquidSniProxy') {
        throw ("Invoke-BuilderVM: '$([string]$resolved['Name'])' is not a builder profile " +
               "(EgressMode='$([string]$resolved['EgressMode'])', need 'SquidSniProxy'). " +
               "Pass a builder profile (e.g. profiles/builder.psd1). Failing closed.")
    }
    if (-not $resolved.ContainsKey('DepsSpec')) {
        throw "Invoke-BuilderVM: builder profile has no DepsSpec key. Failing closed."
    }

    if ([string]::IsNullOrWhiteSpace($Name)) {
        $Name = "bld-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8))
    }

    # Inject the runner + the DepsSpec into the INPUT disk at deploy time (mirrors how
    # the firefox orchestrator injects the organizer script via -Workload.Inputs).
    $depsSpecJson = $resolved['DepsSpec'] | ConvertTo-Json -Depth 8
    $runnerContent = if (Test-Path -LiteralPath $RunnerScriptPath -PathType Leaf) {
        [System.IO.File]::ReadAllText($RunnerScriptPath)
    } else {
        # In the mock the runner file may not exist on disk; use a placeholder so the
        # INPUT-disk population step does not throw on a missing file.
        "# fetch_deps.py placeholder (mock — file not present at $RunnerScriptPath)"
    }
    $resolved['Inputs'] = @{
        'fetch_deps.py'  = $runnerContent
        'deps-spec.json' = $depsSpecJson
    }

    # --- lifecycle state + result ---
    $states = [System.Collections.Generic.List[string]]::new()
    $result = @{
        DepsDiskPath   = $null
        WholeImageHash = $null
        Status         = 'Failed'
        Error          = $null
        States         = @()
    }

    $descriptor = $null
    $states.Add('INIT')

    try {
        # --- PROVISIONED: create the Tier-1 VM (NIC stays up — net-restricted, not no-NIC) ---
        $descriptor = New-SandboxVM -Profile $resolved -Name $Name -Backend $Backend
        $states.Add('PROVISIONED')

        # --- STAGED: workload data disks + CIDATA seed disk (RC6, mirrors the disk-mode path) ---
        $diskStorageRoot = Get-SandboxStorageRoot -Name $Name

        # INPUT disk (runner + DepsSpec) + OUTPUT disk (will hold deps after the fetch).
        # New-WorkloadDisks records both on the descriptor (InputDiskPath / OutputDiskPath +
        # CreatedDisks) so teardown's Remove-Sandbox -DeleteDisks cleans them up.
        $descriptor = New-WorkloadDisks -Descriptor $descriptor -Profile $resolved `
            -StorageRoot $diskStorageRoot -Backend $Backend

        # CIDATA seed disk (RC6): the builder seed rides a recorded data disk, not a DVD,
        # so it survives through to the boot cloud-init reads it. The builder profile
        # declares Entrypoint (the fetch_deps.py call) — fold it into $resolved so
        # New-WorkloadSeedDisk -> New-CidataUserData substitutes the right command.
        # (Resolve-DeployProfile returns a mutable clone; direct assignment is StrictMode-safe.)
        if ($resolved.ContainsKey('Entrypoint') -and -not [string]::IsNullOrWhiteSpace([string]$resolved['Entrypoint'])) {
            $descriptor = New-WorkloadSeedDisk -Descriptor $descriptor -Profile $resolved `
                -StorageRoot $diskStorageRoot -Backend $Backend
        }
        $states.Add('STAGED')

        # --- RC7: disable automatic checkpoints BEFORE StartVM so the guest's writes land
        # in the base .vhdx (not a differencing .avhdx). The provisioner already calls this
        # at provision time; a belt-and-braces second call here is the explicit builder guard
        # (the builder's whole-image hash depends on it). Mirrors the processor orchestrator's
        # explicit RC7 call just before StartVM.
        $null = & $Backend.SetAutomaticCheckpoints @{ VMName = $Name; Enabled = $false }

        # --- NO SEAL: the builder is Tier-1 NET-RESTRICTED. It KEEPS its NIC + Squid egress
        # for the full run (it must fetch deps). Do NOT call Lock-Sandbox / Assert-Sealed. ---

        # --- RUNNING: start the VM + wait for the guest to self-power-off ---
        $null = & $Backend.StartVM @{ Name = $Name }
        $states.Add('RUNNING')

        $wait = Wait-WorkloadComplete -Descriptor $descriptor -Backend $Backend `
            -TimeoutSeconds $WorkloadTimeoutSeconds

        if ($wait.TimedOut) {
            # The guest never self-powered-off within the deadline (hung / fetch failed).
            # Wait-WorkloadComplete already force-stopped it so the Reaper inherits a clean Off VM.
            # Record a failed run; do NOT attempt to hash a disk whose contents may be incomplete.
            throw ("Invoke-BuilderVM: '$Name' did not power off within $WorkloadTimeoutSeconds s " +
                   "(hung/failed fetch); no deps artifact emitted.")
        }
        $states.Add('CAPTURED')

        # --- DETACH the OUTPUT/deps disk BEFORE the host hash ---
        # An attached disk is locked (Hyper-V worker holds the file handle while the VM
        # ran); the fake's GetVhdxImageHash THROWS on an attached-while-Running disk.
        # Detach BEFORE the hash so GetVhdxImageHash can open the file. After power-off
        # the worker handle has been released, so even an Off-but-attached disk is hashable
        # on the real backend — but we detach anyway (defense-in-depth + mirrors the
        # processor orchestrator's post-run detach).
        if ($descriptor.OutputDiskPath) {
            $null = & $Backend.RemoveHardDiskDrive @{ VMName = $Name; Path = $descriptor.OutputDiskPath }
        }
        $states.Add('DETACHED')

        # --- WHOLE-IMAGE HASH (no mount): the Phase-3 supply-chain integrity artifact ---
        $outputPath = [string]$descriptor.OutputDiskPath
        if ([string]::IsNullOrWhiteSpace($outputPath)) {
            throw "Invoke-BuilderVM: descriptor has no OutputDiskPath after disk creation."
        }
        $hash = [string](& $Backend.GetVhdxImageHash @{ Path = $outputPath })
        $states.Add('HASHED')

        # --- EMIT: record the deps disk path + hash ---
        # LIVE-only (Phase 6): copy/move the OUTPUT .vhdx to $DepsDiskPath (a stable path
        # NOT in CreatedDisks) so teardown can remove the working disks while deps.vhdx
        # persists. The copy is byte-identical -> same whole-file hash.
        # MOCK: set DepsDiskPath to the OUTPUT path and record the hash; no file I/O.
        if ([string]::IsNullOrWhiteSpace($DepsDiskPath)) { $DepsDiskPath = $outputPath }
        # LIVE-only (Phase 6): $null = Copy-Item -LiteralPath $outputPath -Destination $DepsDiskPath -Force

        $result.DepsDiskPath   = $DepsDiskPath
        $result.WholeImageHash = $hash
        $result.Status         = 'Success'
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Warning "Invoke-BuilderVM: aborting '$Name' after a lifecycle failure: $($_.Exception.Message)"
    }
    finally {
        # --- DESTROYED: teardown ALWAYS runs (no orphaned VM/disk/switch) ---
        # deps.vhdx persistence is LIVE-only (Phase 6). In the DEFAULT case $DepsDiskPath ==
        # OutputDiskPath, which New-WorkloadDisks PUT in CreatedDisks (the system disk + INPUT +
        # OUTPUT + seed disk), so Remove-Sandbox -DeleteDisks DELETES it here — deps.vhdx does NOT
        # survive teardown today. The Phase-6 Copy-Item (commented out above the EMIT) copies the
        # OUTPUT .vhdx to a stable path NOT in CreatedDisks; only THEN does the deps artifact persist.
        # Until then the whole-image hash is the durable record, not the .vhdx file.
        try {
            if ($null -ne $descriptor) {
                Remove-Sandbox -Name $Name -DeleteDisks -Descriptor $descriptor -Backend $Backend
            }
            else {
                Remove-Sandbox -Name $Name -Backend $Backend
            }
            if ($null -eq $result.Error) { $states.Add('DESTROYED') }
        }
        catch {
            Write-Warning "Invoke-BuilderVM: teardown of '$Name' failed: $($_.Exception.Message)"
        }
        $result.States = $states.ToArray()
    }

    return $result
}
