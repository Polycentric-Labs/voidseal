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
      DETACH      RemoveHardDiskDrive the OUTPUT/deps disk BEFORE the verdict read, the move and the
                  hash (an attached disk is locked; the fake THROWS on GetVhdxImageHash while attached).
      VERDICT     Read-BuilderVerdict: the guest's exit-code file and the deps manifest, read off the
                  detached OUTPUT disk through the backend's ReadVhdxFile. Success needs the file to read
                  exactly 0 AND the manifest to be present; anything else is Status='FetchFailed' with the
                  reason, fail-closed (no artifact is emitted and teardown deletes the disk).
      MOVE        MoveVhdxFile: the finished deps.vhdx leaves the sandbox folder for -DepsOutputDir (default
                  <ArtifactRoot>\deps), a place that is never in CreatedDisks, so teardown cannot delete it.
      HASH        GetVhdxImageHash on the MOVED file: whole-file SHA-256 in USER-SPACE (NEVER Mount-VHD),
                  taken after the verdict read so it describes the bytes a consumer will copy.
      EMIT        Record DepsDiskPath + DepsImageHash + Status=Success.
      TEARDOWN    Remove-Sandbox -DeleteDisks in a finally. It deletes only what the run created (the
                  descriptor's CreatedDisks); the moved deps.vhdx is not on that list and lives outside the
                  storage root (Resolve-BuilderDepsDestination refuses anything inside it), so it survives.

    DESIGN DECISIONS (resolved, do not redesign):
      * The integrity artifact is the whole-image hash (GetVhdxImageHash, raw, no mount). The ONE host read
        of the OUTPUT disk is the verdict (two small files through ReadVhdxFile, a Mount-VHD of the guest-
        written exFAT volume, done before the hash). It is isolated in Read-BuilderVerdict so a different
        verdict transport can replace it without touching the rest of the flow.
      * Success = the exit-code file reads exactly 0 and the manifest is present. A power-off that never
        wrote the file (crash, abort branch) or wrote anything else is 'FetchFailed'; a timeout or any other
        lifecycle error is 'Failed'. The serial [voidseal-diag] markers stay the second source.
      * deps.vhdx survives teardown: it is moved out to a path the run did not create, and its hash is taken
        there. DepsDiskPath and DepsImageHash in the result go straight to -Workload.DepsDiskPath and
        -Workload.DepsImageHash of a later run, which attaches a verified working copy of it.

    Dot-source this file AFTER Invoke-Voidseal.ps1 (which dot-sources all engine libs:
    HyperVBackend.ps1, ProfileLoader.ps1, Provisioner.ps1, Sealer.ps1, Runner.ps1,
    Workload.ps1, SeedBuilder.ps1, SensitivityGate.ps1, DataDisks.ps1).

    RETURNS [hashtable]:
        DepsDiskPath   - host-side path to the emitted deps.vhdx, outside the sandbox folder (or $null).
        DepsImageHash  - lowercase hex SHA-256 of that file (or $null on failure).
        WholeImageHash - the same value as DepsImageHash (the earlier name, kept for callers).
        ExitCode       - the builder's exit code as the guest recorded it, or $null when none was read.
        Status         - 'Success' | 'FetchFailed' | 'Failed'.
        Error          - the failure message on a non-Success run, or $null.
        States         - the lifecycle phases traversed (INIT, PROVISIONED, STAGED, RUNNING, CAPTURED,
                         DETACHED, VERDICT, MOVED, HASHED, DESTROYED), for diagnostics.
#>

Set-StrictMode -Version Latest

# NOTE: Resolve-PythonExe is defined in scripts/lib/PythonResolver.ps1, which
# Invoke-Voidseal.ps1 dot-sources. Always dot-source Invoke-Voidseal.ps1 BEFORE this file. The test BeforeAll
# does this; the function is available without re-defining it here.

# --------------------------------------------------------------------------
# Internal: where the finished deps.vhdx goes, and the checks that keep it safe
# --------------------------------------------------------------------------
<#
.SYNOPSIS
    Resolve and validate the host path the builder moves its deps.vhdx to (fail-closed, before any backend call).
.DESCRIPTION
    The destination is -DepsDiskPath (an exact file path) or '<dir>\deps-<Name>.vhdx', where <dir> is
    -DepsOutputDir or, by default, '<ArtifactRoot>\deps' (ArtifactRoot defaulting to
    '<temp>\Voidseal\artifacts\<Name>', as Invoke-Voidseal does). It is refused when:
      * both -DepsDiskPath and -DepsOutputDir were given;
      * it is not an absolute local path (relative, drive-relative, UNC, extended and device paths);
      * it does not end in '.vhdx';
      * it, or the link-resolved form of it, is inside the sandbox storage base: everything under the
        storage base is created by a run and deleted by its teardown, so a deps disk there would not survive;
      * a file or folder is already at that path (a move never overwrites, and a long fetch must not be
        lost to a name clash discovered at the end).
    Returns the full path.
#>
function Resolve-BuilderDepsDestination {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $StorageBase,
        [AllowNull()] [AllowEmptyString()] [string] $ArtifactRoot,
        [AllowNull()] [AllowEmptyString()] [string] $DepsOutputDir,
        [AllowNull()] [AllowEmptyString()] [string] $DepsDiskPath
    )

    $hasFile = -not [string]::IsNullOrWhiteSpace($DepsDiskPath)
    $hasDir  = -not [string]::IsNullOrWhiteSpace($DepsOutputDir)
    if ($hasFile -and $hasDir) {
        throw "Invoke-BuilderVM: -DepsDiskPath and -DepsOutputDir are alternatives; pass one. Failing closed."
    }

    if ($hasFile) {
        $dest = $DepsDiskPath.Trim(); $source = '-DepsDiskPath'
    }
    else {
        if ($hasDir) { $dir = $DepsOutputDir.Trim(); $source = '-DepsOutputDir' }
        else {
            $root = if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
                Join-Path ([System.IO.Path]::GetTempPath()) ("Voidseal\artifacts\{0}" -f $Name)
            } else { $ArtifactRoot.Trim() }
            $dir = Join-Path $root 'deps'; $source = 'the default <ArtifactRoot>\deps'
        }
        $dest = Join-Path $dir ("deps-{0}.vhdx" -f $Name)
    }

    if (($dest -match '^(\\\\|//)') -or -not [System.IO.Path]::IsPathFullyQualified($dest)) {
        throw ("Invoke-BuilderVM: the deps destination ($source, '$dest') is not an absolute local path " +
               "(for example 'D:\VoidsealDeps'). Relative, drive-relative, UNC, extended and device paths " +
               "are refused. Failing closed BEFORE anything is created.")
    }
    if (-not $dest.EndsWith('.vhdx', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Invoke-BuilderVM: the deps destination ($source, '$dest') must end in '.vhdx'. Failing closed."
    }

    $forms = {
        param([string] $p)
        $lex = [System.IO.Path]::GetFullPath($p).TrimEnd('\', '/')
        $fin = Resolve-HostFinalPath -Path $p
        return @(@($lex, $fin) | Select-Object -Unique)
    }
    foreach ($baseForm in @(& $forms $StorageBase)) {
        foreach ($destForm in @(& $forms $dest)) {
            if (Test-PathUnderRoot -Candidate $destForm -Root $baseForm) {
                throw ("Invoke-BuilderVM: the deps destination ($source, '$dest') is inside the sandbox storage " +
                       "root ('$baseForm'). A run's teardown deletes what it created there, so the deps disk " +
                       "would not survive. Choose a folder outside it. Failing closed.")
            }
        }
    }
    if (Test-Path -LiteralPath $dest) {
        throw ("Invoke-BuilderVM: the deps destination ($source, '$dest') already exists. A move never " +
               "overwrites; choose another folder or remove the old file. Failing closed BEFORE the build.")
    }
    return $dest
}

<#
.SYNOPSIS
    Read the builder's verdict off its detached OUTPUT disk: the guest's exit-code file and the deps manifest.
.DESCRIPTION
    The runner writes the entrypoint's exit status to 'result.exitcode' on the OUTPUT volume as its last
    act, and fetch_deps.py writes 'deps-manifest.json' there only after every fetcher succeeded. Both are
    read through the backend's ReadVhdxFile (a host read of the guest-written volume; the one the builder
    flow makes, see the header). The verdict is fail-closed:
      * no exit-code file            -> not ok (the runner never reached its write, or aborted before it);
      * the file is not exactly '0'  -> not ok (a non-zero code, or content that is not a plain number);
      * exit code 0 but no manifest  -> not ok.
    Only a file that reads exactly 0 (surrounding whitespace aside) AND a non-empty manifest give Ok.
    The reason never repeats the file's content, only its length when it is not a number.
.OUTPUTS
    [hashtable] @{ Ok [bool]; ExitCode [int] or $null; ManifestPresent [bool]; Reason [string] or $null }.
#>
function Read-BuilderVerdict {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $OutputDiskPath,
        [Parameter(Mandatory)] [hashtable] $Backend,
        [string] $ExitCodeInnerName = 'result.exitcode',
        [string] $ManifestInnerName = 'deps-manifest.json'
    )

    $raw = & $Backend.ReadVhdxFile @{ Path = $OutputDiskPath; InnerPath = $ExitCodeInnerName }
    if ($null -eq $raw) {
        return @{ Ok = $false; ExitCode = $null; ManifestPresent = $false
                  Reason = "no exit-code file '$ExitCodeInnerName' on the OUTPUT disk (the runner crashed, aborted before the fetch, or never mounted OUTPUT)" }
    }
    $text = ([string]$raw).Trim()
    if ($text -ceq '0') {
        $rc = 0
    }
    elseif ($text -match '^[1-9][0-9]{0,8}$') {
        $rc = [int]$text
        return @{ Ok = $false; ExitCode = $rc; ManifestPresent = $false
                  Reason = "the builder exited non-zero (exit code $rc)" }
    }
    else {
        return @{ Ok = $false; ExitCode = $null; ManifestPresent = $false
                  Reason = "the exit-code file '$ExitCodeInnerName' is not a plain exit code ($($text.Length) character(s))" }
    }

    $manifest = & $Backend.ReadVhdxFile @{ Path = $OutputDiskPath; InnerPath = $ManifestInnerName }
    if ([string]::IsNullOrWhiteSpace([string]$manifest)) {
        return @{ Ok = $false; ExitCode = 0; ManifestPresent = $false
                  Reason = "the builder exited 0 but '$ManifestInnerName' is absent or empty on the OUTPUT disk" }
    }
    return @{ Ok = $true; ExitCode = 0; ManifestPresent = $true; Reason = $null }
}

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
.PARAMETER DepsOutputDir
    (Optional) the host directory the finished deps.vhdx is moved into, as 'deps-<Name>.vhdx'. Defaults to
    '<ArtifactRoot>\deps'. Must be an absolute local path and must not be inside the sandbox storage root
    (teardown deletes everything the run created there). The destination file must not exist yet; both
    are checked before anything is created, so a long build is never lost to a name clash.
.PARAMETER DepsDiskPath
    (Optional) the exact host path to move the deps.vhdx to, instead of a file under -DepsOutputDir. The
    same rules apply (absolute, local, '.vhdx', outside the storage root, not existing). Not combinable
    with -DepsOutputDir.
.PARAMETER ArtifactRoot
    (Optional) the host directory this run's artifacts go under. Defaults to '<temp>\Voidseal\artifacts\<Name>'
    (the same default Invoke-Voidseal uses). Only the default -DepsOutputDir comes from it.
.PARAMETER RunnerScriptPath
    (Optional) the host path to the in-guest fetch_deps.py runner (seeded into the INPUT disk).
    Defaults to guest/fetch_deps.py under the skill root.
.PARAMETER WorkloadTimeoutSeconds
    (Optional) wall-clock deadline for the guest to self-power-off. An explicitly bound value wins (an
    explicit 0 counts), then the profile's WorkloadTimeoutSeconds key (60..86400), then 600. Pass 0 in
    tests (one instant poll then trips the deadline — no real sleep).
.PARAMETER StorageRoot
    (Optional) the base directory for the builder's disks (<StorageRoot>\<Name>). Beats the
    VOIDSEAL_STORAGE_ROOT environment variable, which beats the %ProgramData%\Voidseal\sandboxes default.
    Must be an absolute local path; anything else throws before the run starts.
.PARAMETER HostMemoryMarginBytes
    (Optional) headroom the host must keep free beyond the guest's memory, passed to New-SandboxVM's
    free-RAM gate (see Invoke-Voidseal). Omit it to take the provisioner's default (2GB).
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
        [string]    $DepsOutputDir,
        [string]    $ArtifactRoot,
        [string]    $RunnerScriptPath = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'guest\fetch_deps.py'),
        [int]       $WorkloadTimeoutSeconds = 600,
        [string]    $StorageRoot,
        [ValidateRange(0, [long]::MaxValue)] [long] $HostMemoryMarginBytes,
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

    # E3: an explicit -WorkloadTimeoutSeconds wins, then the profile's WorkloadTimeoutSeconds, then 600
    # (the same precedence as Invoke-Voidseal).
    $effectiveTimeoutSeconds = if ($PSBoundParameters.ContainsKey('WorkloadTimeoutSeconds')) {
        $WorkloadTimeoutSeconds
    } elseif ($resolved.ContainsKey('WorkloadTimeoutSeconds') -and $null -ne $resolved['WorkloadTimeoutSeconds']) {
        [int]$resolved['WorkloadTimeoutSeconds']
    } else {
        600
    }

    # E2: resolve the storage root once; a bad root throws here, before any backend call. Every disk of the
    # run (system, INPUT, OUTPUT, seed) lives under <base>\<Name>.
    $storageBase  = Resolve-SandboxStorageBase -StorageRoot $StorageRoot
    $vmStorageDir = Join-Path $storageBase $Name

    # Where the finished deps.vhdx will live. A bad destination (relative, UNC, not .vhdx, inside the
    # storage root, already there) throws here, before the first backend call: a caller error, and a
    # fetch is too long to lose to it at the end.
    $depsDestination = Resolve-BuilderDepsDestination -Name $Name -StorageBase $storageBase `
        -ArtifactRoot $ArtifactRoot -DepsOutputDir $DepsOutputDir -DepsDiskPath $DepsDiskPath

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
        DepsImageHash  = $null
        WholeImageHash = $null
        ExitCode       = $null
        Status         = 'Failed'
        Error          = $null
        States         = @()
    }

    $descriptor = $null
    $states.Add('INIT')

    try {
        # --- PROVISIONED: create the Tier-1 VM (NIC stays up — net-restricted, not no-NIC) ---
        $provArgs = @{ Profile = $resolved; Name = $Name; StorageRoot = $storageBase; Backend = $Backend }
        if ($PSBoundParameters.ContainsKey('HostMemoryMarginBytes')) { $provArgs.HostMemoryMarginBytes = $HostMemoryMarginBytes }
        $descriptor = New-SandboxVM @provArgs
        $states.Add('PROVISIONED')

        # --- STAGED: workload data disks + CIDATA seed disk (RC6, mirrors the disk-mode path) ---
        $diskStorageRoot = $vmStorageDir

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
            -TimeoutSeconds $effectiveTimeoutSeconds

        if ($wait.TimedOut) {
            # The guest never self-powered-off within the deadline (hung / fetch failed).
            # Wait-WorkloadComplete already force-stopped it so the Reaper inherits a clean Off VM.
            # Record a failed run; do NOT attempt to hash a disk whose contents may be incomplete.
            throw ("Invoke-BuilderVM: '$Name' did not power off within $effectiveTimeoutSeconds s " +
                   "(hung/failed fetch); no deps artifact emitted.")
        }
        $states.Add('CAPTURED')

        # --- DETACH the OUTPUT/deps disk BEFORE the host read and hash ---
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

        # --- VERDICT: the exit-code file must read exactly 0 and the manifest must be present ---
        # Read BEFORE the move and the hash: the read touches the volume, so the hash below is of the final
        # bytes. Fail-closed: a missing, unparsable or non-zero exit code, or a missing manifest, is a
        # FetchFailed run with the reason; nothing is emitted and teardown deletes the disk.
        $outputPath = [string]$descriptor.OutputDiskPath
        if ([string]::IsNullOrWhiteSpace($outputPath)) {
            throw "Invoke-BuilderVM: descriptor has no OutputDiskPath after disk creation."
        }
        $verdict = Read-BuilderVerdict -OutputDiskPath $outputPath -Backend $Backend
        $result.ExitCode = $verdict.ExitCode
        $states.Add('VERDICT')
        if (-not $verdict.Ok) {
            $result.Status = 'FetchFailed'
            throw ("Invoke-BuilderVM: '$Name' did not produce deps: $($verdict.Reason); no deps artifact emitted. " +
                   "The serial [voidseal-diag] markers say where the guest stopped.")
        }

        # --- MOVE: deps.vhdx leaves the sandbox folder, so teardown cannot delete it ---
        # The destination was validated at INIT (outside the storage root, absent). Teardown deletes only
        # the descriptor's CreatedDisks; refuse here if the destination somehow is one of them.
        if (@($descriptor.CreatedDisks) | Where-Object { [string]$_ -ieq $depsDestination }) {
            throw "Invoke-BuilderVM: the deps destination '$depsDestination' is a disk this run created and would delete at teardown. Failing closed."
        }
        $null = & $Backend.MoveVhdxFile @{ Path = $outputPath; Destination = $depsDestination }
        $states.Add('MOVED')

        # --- WHOLE-IMAGE HASH (no mount): tamper-evidence of the deps hand-off (NOT upstream
        # authenticity) --- this hash proves the deps.vhdx the processor attaches is BYTE-IDENTICAL
        # to what the builder emitted (detects tamper/substitution in the host<->processor hand-off,
        # C2-regen's DEPS-disk-integrity check). It says NOTHING about whether the packages/models
        # INSIDE the disk are what upstream actually published — that provenance is established (or
        # not) per-fetcher at fetch time: apt is authenticated by default (dpkg/APT signature
        # verification against the Debian archive keyring); pip enforces per-package hashes only when
        # driven by a `pip-compile --generate-hashes` lockfile (Pip.RequirementsFile — see
        # guest/fetch_deps.py); HF pins an exact --revision commit SHA (immutable snapshot, not
        # "whatever main resolves to today"). See docs/operator-runbook.md for the full breakdown.
        # --- Phase-3 artifact ---
        # The hash is taken on the MOVED file. If it cannot be taken, the file stays where it is but is
        # not reported as an artifact: nothing unverified is ever handed out.
        try {
            $hash = [string](& $Backend.GetVhdxImageHash @{ Path = $depsDestination })
        }
        catch {
            throw ("Invoke-BuilderVM: the deps disk was moved to '$depsDestination' but its hash could not be taken " +
                   "($($_.Exception.Message)). It is NOT verified: do not use it. Failing closed.")
        }
        $states.Add('HASHED')

        # --- EMIT: record the deps disk path + hash ---
        # Both go straight into a later run's -Workload.DepsDiskPath and -Workload.DepsImageHash.
        $result.DepsDiskPath   = $depsDestination
        $result.DepsImageHash  = $hash
        $result.WholeImageHash = $hash
        $result.Status         = 'Success'
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Warning "Invoke-BuilderVM: aborting '$Name' after a lifecycle failure: $($_.Exception.Message)"
    }
    finally {
        # --- DESTROYED: teardown ALWAYS runs (no orphaned VM/disk/switch) ---
        # Remove-Sandbox -DeleteDisks deletes the descriptor's CreatedDisks (the system disk + INPUT +
        # OUTPUT + seed disk) and nothing else. After a good run the OUTPUT disk has been moved out, so its
        # old path is already gone (RemoveVHD is a no-op on an absent file), and the moved deps.vhdx is
        # neither on that list nor under the storage root: it survives. After a failed run the OUTPUT disk
        # is still in the sandbox folder and is deleted with the rest.
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
