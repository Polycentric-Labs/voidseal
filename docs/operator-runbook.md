# Voidseal — Operator Runbook

> How you run the deployer: preconditions, the provision → run → teardown
> walkthrough, the host-patch **CVE floors**, the **elevation** requirement, credential
> handling, and how to run the tests. Companion to [`tier-reference.md`](tier-reference.md)
> (the tier model + P1–P10 acceptance rubric) and the Claude-facing
> [`../SKILL.md`](../SKILL.md).

---

## 0. Preconditions (do these BEFORE any live run)

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

- Build the Debian 12 golden `.vhdx` per [`../guest-images/debian-12-cloud.md`](../guest-images/debian-12-cloud.md).
- Stage workload assets (the pinned Ralph repo ISO, the organizer ISO) at the host paths the
  profiles' `StageAssets` reference, with the SHA pinned (Ralph has no tags — pin a commit SHA).

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
$report.ExtractedArtifact   # the emitted Netscape-HTML file (result.html), copied to the host
```

> **Organizer-script contract (must match the runner):** `organize_bookmarks.py` reads its
> `--profile` from `/mnt/in` and writes `--out /mnt/out/result.html` (NOT `bookmarks.html`, the
> serial/container-era inner name). See `guest-images/debian-12-cloud.md` §2a + §5. The host source
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
> way it does at Tier ≥ 2. What it certifies instead: `Assert-Sealed` reads the NIC's vSwitch from the
> **host** and refuses to certify unless that switch is an isolated **Internal** vSwitch — never an
> unfiltered External or Private switch. That's a real, host-verified guarantee that the guest's only
> possible route off-box is the host-controlled gateway on that Internal switch — **for a purpose-built
> Internal switch.** It is **not** a guarantee that egress is filtered — nothing today inspects or
> restricts what crosses that gateway once traffic is on it. **It DOES, now, refuse the built-in
> "Default Switch" by name:** the Default Switch is itself `SwitchType=Internal` (Hyper-V's
> ICS/internet-connected switch), so the SwitchType check alone could not distinguish it from a
> purpose-built isolated Internal switch — the seal now ALSO verifies the switch is not the Default
> Switch, by name, and refuses it if it is. Real Tier-1 provisioning uses a purpose-built Internal
> switch, never the Default Switch. This by-name refusal is a reachability/isolation control, not
> egress filtering — see below.
>
> The in-guest controls (the builder profile's iptables default-DROP-plus-allowlist, the in-guest Squid
> SNI proxy) are **not** a containment boundary: a compromised or adversarial guest with code-execution
> can flush its own `iptables` rules or kill its own Squid — you cannot have the untrusted principal police
> itself. Treat them as defense-in-depth, not as what stands between an exfiltrating workload and the
> internet. The layer that WOULD make that guarantee — a host-run transparent Squid SNI-splice proxy plus
> host-side NAT (`New-NetNat`) and a host default-DROP policy on the gateway interface, so filtering
> happens from a position the guest cannot reach — is the **Phase-6-live** work, not yet built. Until then,
> a "sealed" Tier-1 VM is isolation-verified, not egress-filtered; see `SECURITY.md` for the full writeup.

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
VM and deletes its created disks. To confirm nothing is orphaned after a run:

```powershell
Get-VM -Name 'sbx-*' -ErrorAction SilentlyContinue   # should not list the run's VM
```

If you ever need a manual reap (e.g. an interrupted session):

```powershell
. .\scripts\lib\HyperVBackend.ps1
. .\scripts\lib\ProfileLoader.ps1
. .\scripts\lib\Provisioner.ps1
Remove-Sandbox -Name '<vm-name>' -DeleteDisks
```

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
- The same applies to anything secret-shaped (`.env*`, `*.pem`, `*.key`,
  `credentials*.json`, `~/.ssh/*`, `.npmrc`, …): the loader refuses to mount it, full stop.

---

## 3. Tier 2/3 — not armed this round

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
Invoke-Pester -Path tests/DeploySandbox.Tests.ps1 -Output Detailed

# CI-style (writes testResults.xml, gitignored)
Invoke-Pester -Path tests/ -CI
```

The must-pass safety tests are the profile-loader invariant refusals (secret-mount, Tier ≥ 2
starvation, the pre-seal gate) and the seal-gate abort in `DeploySandbox.Tests.ps1`. A red
on any of those means a containment guarantee regressed — do not ship.

---

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Hyper-V unavailable or insufficient privilege` on provision | session not elevated / not in Hyper-V Administrators | re-launch PowerShell **as administrator** (§0.1) |
| `declares a secret-shaped mount source …` at load | a `Mounts` source matches the secret list (e.g. the live `.credentials.json`) | mount a copied `.token` file in a non-secret path instead (§2) |
| `seal gate did not certify …` in the report | `Assert-Sealed` failed (NIC still attached / a host channel readable) | inspect the profile's `HostChannels` (all `$false` for VM tiers) + that `Lock-Sandbox` removed the NIC; the abort already tore the VM down |
| `Tier-… cold-VHDX … is NOT IMPLEMENTED` | a Tier ≥ 2 extraction was attempted | expected — Tier ≥ 2 extraction is post-v1; do not run hostile tiers live this round |
| serial console silent on a live Tier-1 boot | guest `serial-getty@ttyS0` not enabled / wrong `CIDATA` label | re-check the seed `user-data` + that the ISO volume label is exactly `CIDATA` (see the guest-image recipe) |
