# Voidseal — Operator Runbook

> How you run the deployer: preconditions, the provision → run → teardown
> walkthrough, the host-patch **CVE floors**, the **elevation** requirement, credential
> handling, and how to run the tests. Companion to [`tier-reference.md`](tier-reference.md)
> (the tier model + P1–P10 acceptance rubric) and the Claude-facing
> [`../SKILL.md`](../SKILL.md).
>
> This runbook covers **running** a deploy (the two shipped example profiles, `firefox` and
> `ralph`). To **author your own workload profile** instead, see
> [`authoring-a-workload-profile.md`](authoring-a-workload-profile.md) (the field contract + a
> minimal skeleton to copy) — then come back here for the run mechanics.

---

## 0. Preconditions (do these BEFORE any live run)

**One-command check first.** Hyper-V eligibility (edition, feature-vs-service, elevation scope)
is genuinely hard to self-check by reading prose — `scripts/Test-VoidsealPrereqs.ps1` converts
every precondition below into a read-only, unelevated PASS/FAIL/WARN/UNKNOWN table plus an overall
verdict:

```powershell
pwsh scripts/Test-VoidsealPrereqs.ps1
# or, to also verify the golden parent disk:
pwsh scripts/Test-VoidsealPrereqs.ps1 -ParentDiskPath <golden.vhdx>
```

It never creates/modifies a VM or setting, and never requires elevation to run — a check that
needs rights it doesn't have (e.g. the Hyper-V optional-feature query) reports UNKNOWN with a note
rather than a false PASS. Passing every row is **necessary, not sufficient** — the script prints a
caveat block (nested virtualization, admin-rights scope, feature-vs-service, host-patch floors)
after the table. The subsections below are the underlying preconditions it's built from, and the
manual verification path if you want to check any of them by hand.

### 0.1 Elevation (mandatory for live runs)

Live runs touch real Hyper-V and **require an elevated PowerShell session whose user is in
the `Hyper-V Administrators` group** (or a full elevated administrator).

- `New-SandboxVM` runs a `TestAvailable` preflight and **fails closed** with an actionable
  message if Hyper-V is unreachable or the session is not elevated — it never half-builds a VM.
- The **test suite mocks the backend**, so tests run unprivileged. Only the *live*
  end-to-end path needs elevation.

Verify quickly:

```powershell
# Are we elevated?
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# Is the Hyper-V management service up?
Get-Service vmms | Select-Object Status, StartType
```

### 0.2 Host-patch CVE floors

The hypervisor host MUST be patched to these floors before running sandboxes — a vulnerable
hypervisor undermines the entire containment model (a VM-escape defeats every tier).

| Hypervisor | Floor | Why |
|---|---|---|
| **Hyper-V (Win11 Pro — the v1 host)** | **≥ May-2026 cumulative update** | Covers all three: **CVE-2026-26156** (RCE) + **CVE-2026-32149** (EoP), both April-2026, and **CVE-2026-40402** (use-after-free EoP, CVSS 9.3), May-2026. |
| **VirtualBox** (if ever used) | **strictly > 7.2.6** (April-2026 Oracle CPU build) | **7.2.6 itself is vulnerable** (CVE-2026-35242, Core priv-esc). Phrase as ">7.2.6" — **never** "7.2.6 or later". |
| **VMware Workstation** (if ever used) | **≥ 17.6.3** | Remediates **CVE-2025-22224 / CVE-2025-22226** (VMSA-2025-0004, a critical VMX-escape, exploited in the wild). Note: this is a **2025** CVE fix, not 2026. |

Check the Hyper-V host floor:

```powershell
# Build/UBR should be at or past the May-2026 cumulative update for your Win11 channel.
Get-ComputerInfo -Property OsName, OsVersion, OsBuildNumber, WindowsVersion
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, InstalledOn
```

If the host is below the floor, **stop** and patch before running any tier.

### 0.3 Golden parent disk + workload assets

- Build the Debian 12 golden `.vhdx` — run `pwsh scripts/Get-VoidsealGoldenImage.ps1` (downloads the pinned
  image, verifies its SHA-512, converts to VHDX; `-Plan` previews the pinned URL + hash), or follow
  [`../guest-images/debian-12-cloud.md`](../guest-images/debian-12-cloud.md) by hand.
- Put a file at every host path a profile's `StageAssets` names (today only ralph's
  `ralph-claude-code.iso`; Ralph has no tags, so its pin note is a commit SHA): the import fails
  closed on a missing file. The ISO does not reach the guest, because the seal ejects it before the
  guest's only boot, so a live ralph run needs the pinned repo already in the golden image at
  `/opt/ralph/ralph-claude-code`.

### 0.4 Builder deps: what is (and isn't) verified

The `builder` profile (Phase 2+) fetches pip wheels, apt `.deb`s, and Hugging Face models into a
`deps.vhdx` that a downstream Tier-1 `processor` run attaches. Two **different** integrity
properties are in play here — do not conflate them:

- **Whole-image hash (`DepsImageHash`, `GetVhdxImageHash`)** — this is **tamper-evidence of the
  deps hand-off**, i.e. proof that the `deps.vhdx` a processor VM attaches is byte-identical to
  what the builder emitted. It catches substitution/corruption in the host-side hand-off between
  the builder run and the processor run. **It says nothing about whether the packages/models
  inside the disk are what upstream actually published** — that's a separate, per-fetcher
  question (below).
- **Per-fetcher upstream provenance** — established (or not) at *fetch* time, inside
  `guest/fetch_deps.py`:
  - **apt** is authenticated by default — `apt-get download` verifies each `.deb` against the
    Debian archive's GPG-signed `Release`/`Packages` metadata (dpkg/APT signature verification).
    No extra wiring needed.
  - **pip** enforces per-package hashes **only** when driven by a hashed requirements file. A
    bare `pip download --require-hashes <packages>` with no `-r <file>` is a **no-op** — pip has
    nothing to check hashes *against*. `fetch_deps.py`'s `build_commands` now **rejects**
    `Pip.RequireHashes=True` unless `Pip.RequirementsFile` is also set (`ValueError` at plan/build
    time, not a silent pass-through). The lockfile itself is **minted by the operator/build step**,
    not by `fetch_deps.py`:

    ```bash
    # Operator step (NOT run inside the guest / fetch_deps.py). Produces a requirements.txt
    # carrying --hash=sha256:... for every pinned package AND its full transitive closure.
    pip-compile --generate-hashes --output-file=requirements.txt requirements.in
    ```

    This gives **reproducibility against a defined input** (the lockfile you compiled and
    reviewed) — it is **not** cryptographic proof of upstream authorship the way a signed
    artifact would be; a compromised PyPI package present when you ran `pip-compile` is hashed
    faithfully, not detected.
  - **Hugging Face** models are pinned with `--revision <full-40-char-commit-sha>`
    (`HuggingFace.Revision` in the DepsSpec) so the fetch is an immutable snapshot rather than
    "whatever `main` currently resolves to". This does not by itself verify the *content* —
    it verifies you got the *exact commit* you reviewed/pinned, and that a later force-push to
    `main` cannot silently swap what gets fetched.
  - **PEP 740 attestations** (the newer cryptographic-provenance mechanism for PyPI) are **not
    universal**: as of this writing `transformers` and `numpy` publish PEP 740 attestations,
    **`torch` does not**. Do not assume attestation coverage across a dependency set without
    checking package-by-package.
- **Net effect:** the whole-image hash + per-fetcher pinning together give you "the processor got
  exactly what the builder fetched, and the builder fetched exactly the pinned/hashed inputs you
  reviewed" — a defined, reproducible, tamper-evident chain. They do **not** give you upstream
  cryptographic authenticity for every artifact (pip in particular is reproducibility, not
  provenance, unless every package in the closure separately ships PEP 740).

See `profiles/builder.psd1`'s `DepsSpec` for the `RequirementsFile` / `Revision` keys in
practice, and `guest/fetch_deps.py` for the enforcement.

### 0.5 Builder result: the verdict and the deps disk

`Invoke-BuilderVM` returns a hashtable. `Status` is `Success` only when the verdict the guest packed into
its small raw verdict disk (read by the host in user space; nothing is mounted) carries `result.exitcode`
with exactly `0` and a non-empty `deps-manifest.json`; a missing or invalid verdict, an unparsable or
non-zero exit code, or a missing manifest, is `FetchFailed` (the reason is in `Error`, the code in
`ExitCode`), and a timeout or any other lifecycle error, including a host read that itself fails, is
`Failed`. A power-off alone does not count as success. The deps disk is never read by the host, only
moved and hashed. Only a `Success` run emits a disk:

| Field | Meaning |
|---|---|
| `DepsDiskPath` | the finished `deps-<Name>.vhdx`, moved out of the sandbox folder into `-DepsOutputDir` (default `<ArtifactRoot>\deps`); `-DepsDiskPath` names an exact file instead |
| `DepsImageHash` | whole-image SHA-256 of that file, taken after the move (`WholeImageHash` is the same value, kept for older callers) |
| `ExitCode` | the exit code the guest recorded, or `$null` when none was read |

Feed the first two straight into the processor run:

```powershell
$built = Invoke-BuilderVM -Profile builder -DepsOutputDir 'D:\VoidsealDeps'
Invoke-Voidseal -Tier 1 -Profile <processor-profile> `
    -Workload @{ DepsDiskPath = $built.DepsDiskPath; DepsImageHash = $built.DepsImageHash } ...
```

The processor run copies the file into its own sandbox folder and attaches the copy (see the data-disk
notes), so the builder's file is reusable. `-DepsOutputDir` must be an absolute local path outside the
sandbox storage root, and the file must not exist yet; both are checked before the build starts.

---

## 1. Provision → run → teardown walkthrough

All commands run from the **voidseal repo root** in an **elevated** session:

```powershell
# From the voidseal repo root.

# Dot-source the orchestrator — it pulls in the whole engine (backend, loader,
# provisioner, sealer, runner). This is the single entry surface.
. .\scripts\Invoke-Voidseal.ps1
```

### 1.1 Tier-0 Firefox organizer (offline, simplest — start here)

The `firefox` profile is a **Disk-mode** workload (`WorkloadMode = 'Disk'`): inputs ride the
INPUT data disk (guest `/mnt/in`), the result lands on the OUTPUT data disk at the engine default
inner-name `result.html` (guest `/mnt/out/result.html`), and the guest self-powers-off. The profile
ships `Inputs = @{}` because a `.psd1` cannot cleanly inline a whole Python file — so the
**live-acceptance step populates `Inputs` from the host files** declared in the profile's
`InputFiles` map, then passes them through `-Workload`. The populate reads each host file into an
innerName→content hashtable. Since C1.4, `firefox` opts into the shared user-space outbox transport
(`OutboxOutput = $true` — Raw OUTPUT, host reads it via `ReadVhdxRawRegion`, never `Mount-VHD`), so
`InputFiles` carries **four** entries: the organizer script + sample profile (the workload itself)
plus `run_disk_workload.py` + its `outbox.py` dependency (the shared in-guest outbox producer the
seed's disk-mode runner invokes after the organizer writes `result.html` into staging):

> **Operator note — the qemu-img raw read.** `ReadVhdxRawRegion` avoids a kernel filesystem mount of the
> guest-written OUTPUT disk by running `qemu-img convert -f vhdx -O raw` offline instead. That trades a
> kernel-parse risk for a different one: `qemu-img`'s own VHDX parser now runs against those same untrusted
> bytes, in **your** (the operator's) session. The only catalogued QEMU VHDX-parser CVE is
> **CVE-2014-0148** (a DoS, fixed at QEMU 2.0) — there is no catalogued RCE here. The real concern is the
> **undiscovered-bug class**: an unpatched memory-safety bug in an offline parser handling adversarial
> input. Mitigated today by a patch-currency version floor + optional SHA-256 pin (`Resolve-QemuImg`) and a
> confinement seam every convert call is routed through (`Invoke-ConfinedQemu`) — but that seam's v1 is a
> **pass-through** (LIVE-ONLY-UNPROVEN); the real confinement (restricted-token/Job-Object shim for
> Tier-0/1, Windows Sandbox for Tier-2/3) is wired and live-tested at Phase 6, not yet. See `SECURITY.md`
> §"The qemu-img raw read" for the full writeup.

```powershell
# Populate the INPUT-disk inputs from the host files — the organizer + sample profile (the
# workload) and run_disk_workload.py + outbox.py (the shared outbox producer, C1.3/C1.4).
$inputs = @{
    'organize_bookmarks.py' = (Get-Content -LiteralPath 'C:\sandbox\organizer-src\organize_bookmarks.py' -Raw)
    'sample-bookmarks.json' = (Get-Content -LiteralPath 'C:\sandbox\firefox-sample-profile\sample-bookmarks.json' -Raw)
    'run_disk_workload.py'  = (Get-Content -LiteralPath 'C:\sandbox\organizer-src\run_disk_workload.py' -Raw)
    'outbox.py'             = (Get-Content -LiteralPath 'C:\sandbox\organizer-src\outbox.py' -Raw)
}

$report = Invoke-Voidseal -Tier 0 -Profile firefox `
    -Workload @{ WorkloadMode = 'Disk'; Inputs = $inputs; ResultInnerName = 'result.html'; SentinelInnerName = 'result.exitcode' } `
    -ParentDiskPath 'C:\sandbox\golden\debian-12-cloud.vhdx' `
    -Destination 'C:\sandbox\extracted\firefox'

$report.States              # INIT..DESTROYED on success
$report.RunResult.Status    # Success when the sentinel parses 0 AND result.html is present
                            # (an OutboxOutput profile: Success on entrypoint exit code 0, WorkloadFailed
                            # with RunResult.ExitCode set when it exits non-zero)
$report.ExtractedArtifact   # the emitted Netscape-HTML file (result.html), copied to the host
```

> **Organizer-script contract (must match the runner):** `organize_bookmarks.py` reads its
> `--profile` from `/mnt/in` and writes `--out /run/staging/result.html`. Not `/mnt/out`: firefox is
> an `OutboxOutput` profile, so OUTPUT is Raw and never mounted, and `New-CidataUserData` refuses to
> build a seed whose entrypoint names `/mnt/out`. Not `bookmarks.html` either (the serial-era inner
> name). See `docs/live-smoke-test.md` §4A.2 for the host-side pre-run gate. The host source
> `C:\sandbox\organizer-src\organize_bookmarks.py` must be a version aligned to those paths.

> **DATA-ACCESS:** the `firefox` profile defaults to a **synthetic/sample** profile copy.
> Running on your real Firefox data requires **explicit per-task authorization** and
> pointing the input source at a **COPY** of the real profile (Firefox closed) — never the
> live profile dir, and never `logins.json`/`key4.db`/`cookies.sqlite`.

### 1.2 Tier-1 Ralph loop (net-restricted agent loop)

```powershell
# Provision the credential token FIRST (file-to-file copy — see §2). Then:
$report = Invoke-Voidseal -Tier 1 -Profile ralph `
    -Workload @{ ResultPath = 'C:\sandbox\ralph-workdir\out' } `
    -ParentDiskPath 'C:\sandbox\golden\debian-12-cloud.vhdx' `
    -Destination 'C:\sandbox\extracted\ralph'

$report.SealVerdict   # MUST be $true — the loop only runs on a sealed VM
$report.RunResult.ExitCode
```

> **Operator note — what `SealVerdict = $true` guarantees for Tier-1, and what it doesn't.** A Tier-1
> VM legitimately keeps its NIC (net-restricted, not no-net), so the seal can't certify "no network" the
> way it does for a Tier-0, Tier ≥ 2 or processor VM. What it certifies instead: `Assert-Sealed` reads the NICs from the
> **host** and refuses to certify unless there is exactly one, on the VM's own recorded switch (the
> `<vm>-int` Internal switch recorded as the descriptor's `SwitchName`), and that switch reads as
> `SwitchType=Internal`. An External or Private switch, any other Internal switch, or a second NIC is
> refused. That's a real, host-verified guarantee that the guest's only
> possible route off-box is the host-controlled gateway on that Internal switch — **for a purpose-built
> Internal switch.** On its own it says nothing about which destinations are reachable; for that, see
> the HostProxy paragraph below. **It DOES, now, refuse the built-in
> "Default Switch" by name:** the Default Switch is itself `SwitchType=Internal` (Hyper-V's
> ICS/internet-connected switch), so the SwitchType check alone could not distinguish it from a
> purpose-built isolated Internal switch — the seal now ALSO verifies the switch is not the Default
> Switch, by name, and refuses it if it is. Real Tier-1 provisioning uses a purpose-built Internal
> switch, never the Default Switch. **This by-name match is the switch's ENGLISH friendly name**; on a
> non-English/localized Windows host the friendly name differs, so the by-name refusal does not fire
> there — the locale-independent guarantee is the immutable-GUID refusal
> (`c08cb7b8-9b3c-408e-8e30-5e16a3aeb444`), which is Phase-6-live, not yet shipped. This by-name refusal
> is a reachability/isolation control, not egress filtering; see below.
>
> **HostProxy (what `tier1.psd1` ships).** For a VM with `EgressMode='HostProxy'`, `SealVerdict = $true`
> also means the gate read back, from the host, the gateway address on `vEthernet (<vm>-int)`, the seven
> host firewall rules on that interface and the three port ACL entries on the VM's NIC, each exactly as
> recorded, and found no NAT over the VM's /30. Those leave one path open: TCP from the guest's address to
> the host proxy on the gateway, which tunnels only `CONNECT <name>:443` for names on the merged
> `EgressAllowlist`. The guest has no route, NAT or resolver. The proxy starts after the gate and before the
> VM; its per-connection log is `report.EgressProxyLog` (`egress-proxy.log` in the artifact folder), one
> JSON line per connection with the requested name, decision, reason code and byte counts, never payload.
> Read it after a run to see what the workload tried to reach. Running this mode needs the elevated
> session the rest of a live run needs (it creates a host address, firewall rules and port ACL entries),
> and teardown removes exactly what the run created; a removal that fails shows up as
> `TeardownStatus = 'FAILED: ...'` naming the object, which you then remove by hand (rules are named
> `Voidseal-egress-<vm>-*`, in the group "Voidseal egress"). It is mock-green only until the first elevated
> run; `docs/phase-6-live-runbook.md` section 2 lists the checks. Keep allowlists narrow: an allowed name
> that fronts a shared CDN or a public storage service can carry traffic for parties other than the
> intended one.
>
> The in-guest controls (the in-guest default-DROP the HostProxy seed still installs, and, for a profile
> set to `InGuestSquid` or the builder, the in-guest iptables and Squid) are **not** a containment
> boundary: a compromised or adversarial guest with code execution can flush its own rules or kill its own
> Squid. Under `InGuestSquid` and the builder they are the only egress control, so a "sealed" VM in those
> modes is isolation-verified, not egress-filtered; see `SECURITY.md` for the full writeup. The full live
> sequence (host egress enforcement, qemu-img confinement, seal-time assertions) is
> `docs/phase-6-live-runbook.md`.

### 1.3 Reading the report

`Invoke-Voidseal` returns a structured report (never throws on a *lifecycle* failure — it
records it and tears down). Input-validation errors (bad tier, missing profile) **do** throw.

| Field | Meaning |
|---|---|
| `States` | states traversed in order (e.g. `INIT..DESTROYED`, or stopping before `RUNNING` on a seal-gate abort) |
| `SealVerdict` | `$true` only if `Assert-Sealed` certified the VM |
| `RunResult` | the workload result (`VMName`/`ExitCode`/`CapturePath`/…) or `$null` if it never ran |
| `ExtractedArtifact` | host-side path(s) the one-way extractor wrote, or `$null` |
| `TeardownStatus` | teardown outcome — **always runs**, so no orphaned VM/disk/switch |
| `Error` | the failure message if the deploy aborted; `$null` on full success |

### 1.4 Teardown is automatic

Teardown runs in a `finally` — a seal-gate abort or any mid-flow failure still reaps the
VM, deletes its created disks, and removes the per-VM Internal switch the provision created
(Tier 1). To confirm nothing is orphaned after a run:

```powershell
Get-VM -Name 'sbx-*' -ErrorAction SilentlyContinue   # should not list the run's VM
Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object Name -like 'sbx-*-int'   # should be empty
```

If you ever need a manual reap (e.g. an interrupted session):

```powershell
. .\scripts\lib\HyperVBackend.ps1
. .\scripts\lib\ProfileLoader.ps1
. .\scripts\lib\Provisioner.ps1
Remove-Sandbox -Name '<vm-name>' -DeleteDisks
# Without the run's descriptor, Remove-Sandbox cannot tell whether it owns a switch, so it leaves
# switches alone. Remove a leftover per-VM switch by hand:
Remove-VMSwitch -Name '<vm-name>-int' -Force        # only if Get-VMSwitch still shows it
```

### 1.5 Sizing a run: Memory, Cpu, CPU caps, the deadline and the host free-RAM gate

A workload profile may size its own guest instead of taking the tier's numbers:

```powershell
@{
    BaseTier   = 1
    Name       = 'bigger-job'
    Entrypoint = '/usr/local/bin/run.sh'
    Memory     = '8GB'             # 512MB..64GB
    Cpu        = 6                 # 1..32
    CpuMaximumPercent = 50         # optional: each virtual processor may use at most 50%
    CpuRelativeWeight = 200        # optional: scheduling weight vs other VMs (Hyper-V default 100)
}
```

The caps are optional. Leave them out and Hyper-V's defaults apply. When set they reach
`Set-VMProcessor -Maximum` / `-RelativeWeight`.

A workload that needs more (or less) than the default ten minutes sets its own deadline with
`WorkloadTimeoutSeconds = 3600` (60 to 86400). `-WorkloadTimeoutSeconds` on `Invoke-Voidseal` or
`Invoke-BuilderVM` still wins, but only when you pass it explicitly; with neither the deadline is 600
seconds. Past the deadline the guest is force-stopped and the run reports `Failed`.

Before it creates anything, `New-SandboxVM` compares the host's free physical memory with the guest's
`Memory` plus a margin. The margin defaults to 2GB and is the `-HostMemoryMarginBytes` parameter on
`Invoke-Voidseal` and `Invoke-BuilderVM`:

```powershell
$report = Invoke-Voidseal -Tier 1 -Profile bigger-job -HostMemoryMarginBytes 4GB ...
$report.Error   # on a refusal: '... host free memory is <n> bytes but the guest needs <m> bytes plus a <k> byte margin ...'
```

A refusal ends the run at `INIT` with nothing provisioned. The gate also refuses when the host's memory
cannot be read at all. Two things to know on a live host. The figure is Windows' *free* physical memory,
which does not count the standby cache, so it reads lower than Task Manager's "Available"; close
something or lower the margin if a roomy-looking host is refused. And the real read
(`Get-CimInstance Win32_OperatingSystem`, KiB converted to bytes) is pinned by an out-of-process stub
test but has not run on a live host yet.

### 1.6 Where the disks live: `-StorageRoot` and `VOIDSEAL_STORAGE_ROOT`

Every run keeps its VM folder and disks (system, CIDATA seed, INPUT, OUTPUT) under one base directory, in a
folder named after the VM: `<base>\<vm-name>\`. The base is chosen in this order:

1. the `-StorageRoot` parameter of `Invoke-Voidseal`, `Invoke-BuilderVM` or `New-SandboxVM`;
2. the `VOIDSEAL_STORAGE_ROOT` environment variable;
3. the default, `%ProgramData%\Voidseal\sandboxes`.

```powershell
$report = Invoke-Voidseal -Tier 1 -Profile ralph -StorageRoot 'D:\VoidsealSandboxes' ...
# or, for every run in this session:
$env:VOIDSEAL_STORAGE_ROOT = 'D:\VoidsealSandboxes'
```

A blank value counts as unset. A chosen root must be an absolute local path: a relative path, a drive-relative
path (`D:dir`), a rooted path with no drive (`\dir`) and any UNC, extended or device path (`\\server\share`,
`\\?\D:\dir`) is refused, and `Invoke-Voidseal` throws before the run starts. The host free-space check
measures the volume that hosts the chosen root, so moving the root to a bigger drive is the fix for
`insufficient host free space`. `-ArtifactRoot` (where the Runner's capture and the extracted result go) is a
separate setting and is unchanged.

Teardown deletes only the disk paths the run's descriptor recorded; it never recomputes the root, so
changing the environment variable between a provision and its teardown cannot redirect a delete. Live-only,
not yet exercised: on a real host the VM folder is created by Hyper-V when the first disk is made, as it is
under the default root today, so the drive must exist and be writable by the Hyper-V service.

---

## 2. Credential handling (binding — a strict secret-handling protocol)

The Ralph loop's `claude` CLI needs an OAuth token. The rules:

- **File-to-file only.** The token is delivered as a **`.token` FILE**, mounted
  **read-only** into the guest (read-only file bind-mount pattern) — **never** via `-e`, **never** embedded in a
  profile, **never** echoed through a shell, **never** displayed in chat.
- **Do NOT mount the live `~/.claude/.credentials.json`.** The loader's secret-refusal list
  includes `.credentials.json`, so a profile that mounts it is **refused at load time** (by
  design). Instead, do a **one-time file-to-file copy** of just the token into a dedicated,
  non-secret-shaped path with a `.token` extension. You run this yourself — the value
  never transits an agent's context:

  ```powershell
  # You run this. The token value is never read into chat / a tool argument.
  $dest = 'C:\sandbox\agent-cred'
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Copy-Item "$env:USERPROFILE\.claude\.credentials.json" "$dest\agent.token"
  ```

  `ralph.psd1` mounts **that** copied file read-only.
- **Rotate** the token after any session that touched it. Re-copy + re-deploy to refresh.
- The same applies to anything whose **path shape** is secret-like (`.env*`, `*.pem`, `*.key`,
  keystores, `id_ed25519*`, `credentials*.json`, `.netrc`, `.git-credentials`, `*.tfvars`, anything
  under `.ssh/`, `.gnupg/` or `.secrets/`, and more): the loader refuses it as a `Mounts` **or**
  `StageAssets` source. `tier-profiles/SCHEMA.md` carries the full list. The check reads the name,
  never the file, so renaming a credential defeats it: the rule below (copy the token to a dedicated
  `.token` path) is the practice that actually protects you.

---

## 3. Tier 2/3 — not armed in v1

Tier 2 (disposable no-net) and Tier 3 (airgapped detonation) are **scaffolded and validated
with benign placeholder inputs only**. There is **no live malware or plugin detonation** in
v1. The Tier ≥ 2 extraction routes to a **quarantine sink that THROWS** (the cold-VHDX →
quarantine-VM → CDR → inert-promote flow is post-v1). Do not point a Tier 2/3 run at a real
untrusted artifact until you explicitly green-light verified isolation.

---

## 4. Running the tests

From the skill root (no elevation needed — the backend is mocked):

```powershell
# Full suite
Invoke-Pester -Path tests/

# A single area
Invoke-Pester -Path tests/Profiles.Tests.ps1 -Output Detailed
Invoke-Pester -Path tests/InvokeVoidseal.Tests.ps1 -Output Detailed

# CI-style (writes testResults.xml, gitignored)
Invoke-Pester -Path tests/ -CI
```

The must-pass safety tests are the profile-loader refusals (secret-shaped `Mounts` and `StageAssets`
sources, Tier >= 2 starvation, the pre-seal gate) and the seal-gate abort in
`tests/InvokeVoidseal.Tests.ps1`. A red on any of those means a containment guarantee regressed, so
do not ship. Run the Python suite too if you touched anything under `guest/`:
`python -m pytest tests/guest tests/host -q`.

---

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Hyper-V unavailable or insufficient privilege` on provision | session not elevated / not in Hyper-V Administrators | re-launch PowerShell **as administrator** (§0.1) |
| `declares a secret-shaped mount source …` at load | a `Mounts` source matches the secret list (e.g. the live `.credentials.json`) | mount a copied `.token` file in a non-secret path instead (§2) |
| `seal gate did not certify …` in the report | `Assert-Sealed` failed (NIC still attached / a host channel readable) | inspect the profile's `HostChannels` (all `$false` for VM tiers) + that `Lock-Sandbox` removed the NIC; the abort already tore the VM down |
| `Tier-… cold-VHDX … is NOT IMPLEMENTED` | a Tier ≥ 2 extraction was attempted | expected — Tier ≥ 2 extraction is post-v1; do not run hostile tiers live in v1 |
| `... is not an absolute local path` from a `Sandbox storage root` message | `-StorageRoot` or `VOIDSEAL_STORAGE_ROOT` is relative, drive-relative, UNC or a device path | set an absolute local path such as `D:\VoidsealSandboxes` (§1.6) |
| `refusing to provision ...: host free memory is ... bytes but the guest needs ...` | the host's free RAM is below the guest's `Memory` plus the margin, or the host memory read failed | free host memory, lower the profile's `Memory`, or lower `-HostMemoryMarginBytes` (§1.5) |
| cloud-init is slow to finish or never reaches `done` on a live first boot | the seal turned off Key-Value Pair Exchange, and the guest is searching datasources (the Azure datasource uses KVP) | pin `datasource_list: [ NoCloud ]` under `/etc/cloud/cloud.cfg.d/` in the golden image and rebuild it; do not re-enable KVP (the gate refuses a VM with it on). Check with `cloud-init status --long` and `cloud-id` (expect `nocloud`) |
| TLS fails in the guest with a certificate not-yet-valid or expired error, or `date -u` is far from the host | the seal turned off Time Synchronization and nothing re-syncs the clock (no NTP under HostProxy, no NIC elsewhere); the guest runs on its RTC | compare `date -u` with the host's UTC time; an offset equal to the host's UTC offset means the RTC is read as local time (`timedatectl set-local-rtc 0` in the golden image); bound long runs with `-WorkloadTimeoutSeconds`; do not re-enable Time Synchronization or open UDP 123 |
| serial console silent on a live Tier-1 boot | guest `serial-getty@ttyS0` not enabled / wrong `CIDATA` label | re-check the seed `user-data` + that the ISO volume label is exactly `CIDATA` (see the guest-image recipe) |
