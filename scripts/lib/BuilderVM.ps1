<#
.SYNOPSIS
    Voidseal — Invoke-BuilderVM, the Tier-1 builder orchestrator.

.DESCRIPTION
    Runs a DepsSpec in a net-restricted Hyper-V VM and emits a hash-verified deps.vhdx.

    MIRRORS Invoke-Voidseal's INIT->PROVISION->disks->seed->seal->gate->proxy->start->wait->detach flow,
    plus a whole-image hash + emit. The builder is a Tier-1 HostProxy run like any other: its NIC stays,
    and the host proxy on the gateway of its own /30 is the only way out.

    FLOW:
      INIT        load + validate the builder profile (a Tier-1 HostProxy profile with a DepsSpec; the
                  loader's builder rule already pins that shape).
      PROVISION   New-SandboxVM: a Tier-1 VM with its NIC (the fetch needs the net) and a HostProxy
                  address plan on the descriptor.
      DISKS       New-WorkloadDisks - INPUT (runner+DepsSpec) + OUTPUT (deps.vhdx-to-be, exFAT, never
                  host-mounted); New-BuilderVerdictDisk - a small RAW verdict disk beside them.
      SEED        New-WorkloadSeedDisk: the CIDATA data disk carrying the builder runner, the proxy
                  settings, the in-guest lockdown and the network-config (RC6).
      RC7         SetAutomaticCheckpoints Enabled=$false, so guest writes land in the base
                  .vhdx, not a differencing .avhdx, which is what the host hashes.
      SEAL        Lock-Sandbox keeps the NIC, installs the host side of egress from the plan (gateway
                  address, firewall rules, port ACL), detaches media and turns the host channels off;
                  then Assert-Sealed, a HARD GATE: it reads every host object back, the egress ones
                  included, and a verdict that is not literally $true fails the run before StartVM.
      PROXY       Start-SandboxEgressProxy: the host CONNECT proxy on the gateway, enforcing the merged
                  EgressAllowlist, after the gate and before the guest boots.
      RUN         StartVM -> Wait-WorkloadComplete (the guest fetches deps over the proxy, self-powers-off).
      DETACH      RemoveHardDiskDrive the OUTPUT/deps disk AND the verdict disk BEFORE the verdict read,
                  the move and the hash (an attached disk is locked; the fake THROWS on GetVhdxImageHash
                  while attached).
      VERDICT     Read-BuilderVerdict: the guest packs result.exitcode and deps-manifest.json into the raw
                  verdict disk with the shared outbox producer, and the host reads that outbox in user
                  space (Read-OutboxToGateInput: ReadVhdxRawRegion + host/read_outbox.py), mounting
                  nothing. Success needs the exit code to read exactly 0 AND the manifest to be present
                  and non-empty; anything else is Status='FetchFailed' with the reason, fail-closed (no
                  artifact is emitted and teardown deletes the disks).
      MOVE        MoveVhdxFile: the finished deps.vhdx leaves the sandbox folder for -DepsOutputDir (default
                  <ArtifactRoot>\deps), a place that is never in CreatedDisks, so teardown cannot delete it.
      HASH        GetVhdxImageHash on the MOVED file: whole-file SHA-256 in USER-SPACE (NEVER Mount-VHD),
                  taken after the verdict read so it describes the bytes a consumer will copy.
      EMIT        Record DepsDiskPath + DepsImageHash + Status=Success.
      TEARDOWN    Remove-Sandbox -DeleteDisks in a finally. It stops the proxy and removes the host egress
                  objects it recorded, then deletes only what the run created (the descriptor's
                  CreatedDisks); the moved deps.vhdx is not on that list and lives outside the storage
                  root (Resolve-BuilderDepsDestination refuses anything inside it), so it survives.

    DESIGN DECISIONS (resolved, do not redesign):
      * The integrity artifact is the whole-image hash (GetVhdxImageHash, raw, no mount). The deps disk is
        never mounted or read by the host at all (C1: the host never mounts a file system the guest wrote).
        The verdict travels on a second, small RAW disk in the user-space outbox format, so this file never
        calls ReadVhdxFile, ReadVhdxFileBytes or Mount-VHD (a test pins that on the AST).
      * Success = the verdict's exit code reads exactly 0 and its manifest is present and non-empty. A
        power-off that never packed a valid verdict (crash, abort branch) or packed anything else is
        'FetchFailed'; a timeout or any other lifecycle error (including a host read that itself fails, such
        as a locked disk) is 'Failed'. The serial [voidseal-diag] markers stay the second source.
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
        SealVerdict    - $true when Assert-Sealed certified the VM; $false when the gate refused or was
                         never reached.
        EgressProxyLog - the host proxy's per-connection JSON log in the artifact folder, or $null when
                         the proxy never started.
        States         - the lifecycle phases traversed (INIT, PROVISIONED, STAGED, SEALED, RUNNING,
                         CAPTURED, DETACHED, VERDICT, MOVED, HASHED, DESTROYED), for diagnostics.
#>

Set-StrictMode -Version Latest

# NOTE: Resolve-PythonExe is defined in scripts/lib/PythonResolver.ps1, which
# Invoke-Voidseal.ps1 dot-sources. Always dot-source Invoke-Voidseal.ps1 BEFORE this file. The test BeforeAll
# does this; the function is available without re-defining it here.

# --------------------------------------------------------------------------
# The raw verdict disk: sized to the outbox bounds, created and recorded per run
# --------------------------------------------------------------------------
# guest/outbox.py is the single source of the container format: MAX_ENTRIES = 256 records of 104 bytes,
# a 24-byte header, and at most MAX_TOTAL = 64 MiB of payload. The largest blob the producer can write is
# therefore 24 + 256 * 104 + 64 MiB bytes, so a disk of that size (rounded up to a whole MiB, the unit a
# fixed VHDX is created in) can never truncate a container the format allows. A test pins these numbers
# against outbox.py itself. The real verdict is two small files; the size is the format's bound, not the
# expected payload.
$script:BuilderVerdictDiskBytes = [long]([math]::Ceiling((24 + (256 * 104) + 64MB) / 1MB) * 1MB)

<#
.SYNOPSIS
    Create, record and attach the builder's raw verdict disk.
.DESCRIPTION
    A Raw disk (NewOutputVhdx FileSystem='Raw': a fixed VHDX with no partition table and no file system),
    labelled 'VERDICT' (a discovery tag the fake uses; a real raw disk has no label). The guest finds it by
    that rawness (the only whole disk with no partition table and no file system signature), packs the
    verdict into it with the shared outbox producer, and the host reads it back in user space.
    Recorded on the descriptor (VerdictDiskPath, and a deduped append to CreatedDisks) right after the
    CREATE and before the attach, the same incremental-record rule New-WorkloadDisks follows, so that
    teardown (Remove-Sandbox -DeleteDisks, which deletes exactly CreatedDisks) removes it even if the
    attach throws. Returns the mutated descriptor.
#>
function New-BuilderVerdictDisk {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Descriptor,
        [Parameter(Mandatory)] [string] $StorageRoot,
        [hashtable] $Backend = (New-RealHyperVBackend)
    )
    $name = [string]$Descriptor.Name
    $path = Join-Path $StorageRoot ("{0}-verdict.vhdx" -f $name)

    $null = & $Backend.NewOutputVhdx @{ Path = $path; Label = 'VERDICT'; FileSystem = 'Raw'; SizeBytes = $script:BuilderVerdictDiskBytes }
    Set-DescriptorField -Descriptor $Descriptor -Name 'VerdictDiskPath' -Value $path
    $set = [System.Collections.Generic.List[string]]::new()
    foreach ($cd in @($Descriptor.CreatedDisks)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$cd)) { $set.Add([string]$cd) }
    }
    if ($set -notcontains $path) { $set.Add($path) }
    $Descriptor.CreatedDisks = $set.ToArray()
    $null = & $Backend.AddHardDiskDrive @{ VMName = $name; Path = $path }
    return $Descriptor
}

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
    True when the file exists and holds at least one byte that is not ASCII whitespace.
.DESCRIPTION
    Scans in chunks and stops at the first such byte, so a manifest of any size costs one small read at
    best. Used for the manifest's "present and non-empty" rule without loading the file as text.
#>
function Test-BuilderManifestPresent {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $buf = [byte[]]::new(8192)
        while (($n = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
            for ($i = 0; $i -lt $n; $i++) {
                $c = $buf[$i]
                if ($c -ne 32 -and ($c -lt 9 -or $c -gt 13)) { return $true }
            }
        }
        return $false
    }
    finally { $stream.Dispose() }
}

<#
.SYNOPSIS
    Read the builder's verdict off its detached raw verdict disk: the guest's exit code and the deps manifest.
.DESCRIPTION
    The runner packs 'result.exitcode' and 'deps-manifest.json' into the raw verdict disk with the shared
    outbox producer (guest/run_disk_workload.py, no new on-disk format), and the host reads that outbox in
    USER SPACE with the reader every other OUTPUT read uses: Read-OutboxToGateInput, which is
    ReadVhdxRawRegion (a qemu-img slice of the detached disk) and host/read_outbox.py. Nothing is mounted,
    so the host's partition and file system drivers never parse anything the guest wrote. The disk path
    passed in must be the verdict disk, never the deps disk: the deps disk is not read at all.

    The verdict is fail-closed:
      * no valid outbox on the disk   -> not ok (the runner aborted before packing one, packed nothing the
                                         reader accepts, or the container failed its checks: bad magic,
                                         bounds, name, hash). The reason is fixed text; it never repeats
                                         anything from the container or the reader's own message;
      * no exit-code entry            -> not ok;
      * the entry is not exactly '0'  -> not ok (a non-zero code, or content that is not a plain number);
      * exit code 0 but no manifest   -> not ok.
    Only an entry that reads exactly 0 (surrounding whitespace aside) AND a non-empty manifest give Ok. The
    reason never repeats entry content, only its length when it is not a number.

    A failure of the READ itself (the disk missing, still locked, qemu-img unavailable) is not the guest's
    verdict, so it propagates and the run becomes Failed, never a guessed Success or FetchFailed.

    The outbox is parsed into a private temp folder that is removed before this returns (it holds bytes
    the guest wrote, up to the container's bound). Pass -WorkDir to keep it somewhere you own; the caller
    then owns the cleanup.
.OUTPUTS
    [hashtable] @{ Ok [bool]; ExitCode [int] or $null; ManifestPresent [bool]; Reason [string] or $null }.
#>
function Read-BuilderVerdict {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $VerdictDiskPath,
        [Parameter(Mandatory)] [hashtable] $Backend,
        [string] $WorkDir,
        [string] $ExitCodeInnerName = 'result.exitcode',
        [string] $ManifestInnerName = 'deps-manifest.json'
    )

    $ownsWorkDir = [string]::IsNullOrWhiteSpace($WorkDir)
    if ($ownsWorkDir) {
        $WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('voidseal-verdict-{0}' -f [guid]::NewGuid().ToString('N'))
    }
    try {
        try {
            $gateInput = Read-OutboxToGateInput -OutputDiskPath $VerdictDiskPath -Destination $WorkDir -Backend $Backend
        }
        catch {
            # Read-OutboxToGateInput prefixes every guest-caused refusal 'outbox read:' (header missing or
            # not the magic, count/total over the bound, read_outbox.py rejecting the container). Anything
            # else is the host's own failure and propagates.
            if ($_.Exception.Message -like 'outbox read:*') {
                return @{ Ok = $false; ExitCode = $null; ManifestPresent = $false
                          Reason = 'no valid verdict outbox on the verdict disk (the runner aborted before packing one, packed nothing readable, or the container failed its checks)' }
            }
            throw
        }

        $staging  = Join-Path $gateInput 'staging'
        $exitPath = Join-Path $staging $ExitCodeInnerName
        if (-not (Test-Path -LiteralPath $exitPath -PathType Leaf)) {
            return @{ Ok = $false; ExitCode = $null; ManifestPresent = $false
                      Reason = "the verdict outbox has no '$ExitCodeInnerName' entry (the runner never reached its pack step)" }
        }
        $size = (Get-Item -LiteralPath $exitPath).Length
        if ($size -gt 32) {
            return @{ Ok = $false; ExitCode = $null; ManifestPresent = $false
                      Reason = "the exit-code entry '$ExitCodeInnerName' is not a plain exit code ($size byte(s))" }
        }
        $text = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($exitPath)).Trim()
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
                      Reason = "the exit-code entry '$ExitCodeInnerName' is not a plain exit code ($($text.Length) character(s))" }
        }

        if (-not (Test-BuilderManifestPresent -Path (Join-Path $staging $ManifestInnerName))) {
            return @{ Ok = $false; ExitCode = 0; ManifestPresent = $false
                      Reason = "the builder exited 0 but '$ManifestInnerName' is absent or empty in the verdict outbox" }
        }
        return @{ Ok = $true; ExitCode = 0; ManifestPresent = $true; Reason = $null }
    }
    finally {
        if ($ownsWorkDir) { Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# --------------------------------------------------------------------------
# Public: Invoke-BuilderVM (the Tier-1 builder orchestrator)
# --------------------------------------------------------------------------
<#
.SYNOPSIS
    Run the Tier-1 builder: provision -> disks -> seed -> seal -> gate -> proxy -> run -> detach -> hash -> emit.
.PARAMETER Profile
    A builder profile NAME, a .psd1 PATH, or an already-normalized profile HASHTABLE.
    Must be a Tier-1 HostProxy profile with a DepsSpec key (profiles/builder.psd1 inherits the mode from
    tier1.psd1; the loader refuses any other shape for a DepsSpec).
.PARAMETER Name
    (Optional) the VM name. Defaults to a unique 'bld-<rand>'. A supplied name must start with a letter or
    digit and contain only letters, digits, '.', '_' and '-', 64 characters at most (the same rule as
    Invoke-Voidseal -Name: it names the VM, its disks and its deps file, and Get-VM -Name treats
    * ? [ ] as wildcards).
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
    Defaults to guest/fetch_deps.py under the skill root. The verdict producer the runner packs its
    verdict with (guest/run_disk_workload.py and guest/outbox.py) is always taken from the skill's
    guest folder and seeded beside it; a missing helper fails the run before anything is created.
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
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
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

    # Builder guard: the fetch rides the host proxy, so the profile must be HostProxy and must carry the
    # DepsSpec that makes it a builder. The loader's builder rule pins the same shape (Tier 1,
    # Network 'Internal+Allowlist'); this is the orchestrator's own check on the profile it was handed.
    if ([string]$resolved['EgressMode'] -cne 'HostProxy') {
        throw ("Invoke-BuilderVM: '$([string]$resolved['Name'])' is not a builder profile " +
               "(EgressMode='$([string]$resolved['EgressMode'])', need 'HostProxy': the builder fetches over the host proxy). " +
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

    # The run's artifact folder (the host proxy logs there); the same default Resolve-BuilderDepsDestination
    # derives the default deps folder from.
    $effectiveArtifactRoot = if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
        Join-Path ([System.IO.Path]::GetTempPath()) ("Voidseal\artifacts\{0}" -f $Name)
    } else { $ArtifactRoot.Trim() }

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
    # The guest packs its verdict into the raw verdict disk with the shared outbox producer, which rides
    # the INPUT disk like the runner does. A builder that cannot ship it could not report a verdict, so a
    # missing helper is a caller-side defect: refuse now, before the first backend call.
    $guestDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'guest'
    foreach ($helper in @('run_disk_workload.py', 'outbox.py')) {
        $helperPath = Join-Path $guestDir $helper
        if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
            throw ("Invoke-BuilderVM: the verdict producer helper '$helper' is missing at '$helperPath'. The builder " +
                   "packs its verdict with it, so there would be no way to report one. Failing closed before anything is created.")
        }
        $resolved['Inputs'][$helper] = [System.IO.File]::ReadAllText($helperPath)
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
        SealVerdict    = $false
        EgressProxyLog = $null
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
            -StorageRoot $diskStorageRoot -ExtraBudgetBytes $script:BuilderVerdictDiskBytes -Backend $Backend

        # The raw verdict disk (the free-space preflight above already counted it): the guest packs its
        # verdict here and the host reads it in user space. Recorded as a run-created disk, so teardown
        # deletes it with the rest.
        $descriptor = New-BuilderVerdictDisk -Descriptor $descriptor -StorageRoot $diskStorageRoot -Backend $Backend

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

        # --- SEALED: cut the VM to Tier-1 isolation, then the HARD GATE ---------------------------
        # The builder keeps its NIC (Tier 1, Network 'Internal+Allowlist'), so Lock-Sandbox leaves the
        # adapter, installs the host side of egress from the descriptor's HostProxy plan (gateway
        # address, host firewall rules, port ACL), detaches import media and turns the host channels
        # off. Assert-Sealed then reads every host object back, the egress ones included. It is
        # throw-only today; the explicit verdict check below holds even if it ever returned $false
        # instead. Either refusal lands in the outer catch, which records it and tears down, so the
        # guest never boots on an uncertified VM.
        Lock-Sandbox -Descriptor $descriptor -Backend $Backend
        $sealOk = Assert-Sealed -Descriptor $descriptor -Backend $Backend
        $result.SealVerdict = (($sealOk -is [bool]) -and $sealOk)
        if (-not $result.SealVerdict) {
            throw "Invoke-BuilderVM: seal gate did not certify '$Name' (Assert-Sealed returned a non-true verdict); refusing to start the builder."
        }
        $states.Add('SEALED')

        # --- PROXY: the host CONNECT proxy, after the gate and before the guest boots -----------------
        # The one door the host objects leave open. It enforces the merged EgressAllowlist (the Debian
        # mirrors, PyPI and the Hugging Face hosts the DepsSpec needs), writes one JSON line per CONNECT
        # to the artifact folder, and exits at the deadline plus a margin or with this process. Teardown
        # (Remove-Sandbox) stops it first. A proxy that does not come up is a lifecycle failure.
        Start-SandboxEgressProxy -Descriptor $descriptor -Allowlist @($resolved['EgressAllowlist']) `
            -RunDirectory $effectiveArtifactRoot -MaxLifetimeSeconds ($effectiveTimeoutSeconds + 900) `
            -PythonExe (Resolve-PythonExe) -Backend $Backend
        $result.EgressProxyLog = [string]$descriptor.EgressProxy.LogPath

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

        # --- DETACH the OUTPUT/deps disk and the verdict disk BEFORE the host read and hash ---
        # An attached disk is locked (Hyper-V worker holds the file handle while the VM
        # ran); the fake's GetVhdxImageHash THROWS on an attached-while-Running disk.
        # Detach BEFORE the hash so GetVhdxImageHash can open the file. After power-off
        # the worker handle has been released, so even an Off-but-attached disk is hashable
        # on the real backend — but we detach anyway (defense-in-depth + mirrors the
        # processor orchestrator's post-run detach).
        if ($descriptor.OutputDiskPath) {
            $null = & $Backend.RemoveHardDiskDrive @{ VMName = $Name; Path = $descriptor.OutputDiskPath }
        }
        if ($descriptor.VerdictDiskPath) {
            $null = & $Backend.RemoveHardDiskDrive @{ VMName = $Name; Path = $descriptor.VerdictDiskPath }
        }
        $states.Add('DETACHED')

        # --- VERDICT: the exit code must read exactly 0 and the manifest must be present ---
        # Read from the raw verdict disk in user space (an outbox read, no mount); the deps disk is not read
        # at all, so nothing the host does touches it before the hash below. Fail-closed: no valid verdict,
        # an unparsable or non-zero exit code, or a missing manifest, is a FetchFailed run with the reason;
        # nothing is emitted and teardown deletes the disks.
        $outputPath = [string]$descriptor.OutputDiskPath
        if ([string]::IsNullOrWhiteSpace($outputPath)) {
            throw "Invoke-BuilderVM: descriptor has no OutputDiskPath after disk creation."
        }
        $verdictPath = [string]$descriptor.VerdictDiskPath
        if ([string]::IsNullOrWhiteSpace($verdictPath)) {
            throw "Invoke-BuilderVM: descriptor has no VerdictDiskPath after disk creation."
        }
        $verdict = Read-BuilderVerdict -VerdictDiskPath $verdictPath -Backend $Backend
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
        # OUTPUT + verdict + seed disk) and nothing else. After a good run the OUTPUT disk has been moved out, so its
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
