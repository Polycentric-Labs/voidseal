# Voidseal — Live Smoke Test (operator-run)

> **Who runs this:** you, from an **elevated** PowerShell 7 session. An unelevated agent
> session **cannot** run this — the build session is not elevated / not in `Hyper-V Administrators`, so its
> `TestAvailable` preflight returns `Available=$false` and `New-SandboxVM` fails closed
> before touching Hyper-V. This is the **first real VM provisioning** of the deployer.
>
> **What it proves:** milestones **4** (Tier-0 Firefox proof) and **5** (Tier-1
> Ralph proof) — the Tier 0/1 lifecycle end-to-end, on a **live** Hyper-V backend, after a
> mock-backed `292/292` green suite. It does **NOT** exercise Tier 2/3 (harness-only this
> round) and does **NOT** touch your real personal data (synthetic-by-default).
>
> **Safe by default:** synthetic Firefox data; a bounded Ralph loop; no auto-push; manual
> cleanup documented at every milestone. Companion docs (do **not** re-read wholesale — they
> are the source of truth for their topics): [`operator-runbook.md`](operator-runbook.md)
> (CVE floors, elevation, credentials), [`../guest-images/debian-12-cloud.md`](../guest-images/debian-12-cloud.md)
> (golden disk + CIDATA seed), [`tier-reference.md`](tier-reference.md) (the P1–P10 rubric),
> [`../tier-profiles/SCHEMA.md`](../tier-profiles/SCHEMA.md) (the profile contract).

---

## ⚠️ Read this first — known v1 engine gaps that affect a LIVE run

The mock-backed suite is green, but the **fake backend models things the real engine does
not yet wire**. A live run will surface these. None block the *containment* proofs
(provision → seal → gate → run → extract → destroy), but they change what you must stage by
hand. **Read all four before milestone 1.**

| # | Gap (verified against the built code) | What it means for a live run |
|---|---|---|
| **Gap 1** | **Tier 0 provisions a Hyper-V VM, not a container.** `New-SandboxVM` is Hyper-V-only; the `Substrate='Container'` value in `tier0.psd1` only causes the network block (`if ($Profile['Substrate'] -eq 'HyperV-Gen2')`) to be **skipped** — so a Tier-0 VM is a real **Gen2 VM with no NIC**. Documented in SKILL.md + tier-reference.md. | The `firefox` proof boots a **Debian Gen2 VM** (offline, no NIC), *not* `docker sbx`. You **must** pass `-ParentDiskPath` to the same golden Debian `.vhdx` you build for Tier 1 (tier0's `GuestImage='debian-12-slim'` is a container-image label the engine ignores — there is no container runtime to honor it). |
| **Gap 2** | **Profile `Mounts` are NOT wired into the guest.** The only consumer of `Mounts` is `Assert-NoSecretMounts` (secret-shape validation). Nothing in the Provisioner/Runner attaches a host↔guest bind mount (the backend has no 9p/virtiofs/SMB mount method). | The firefox input/output dirs and Ralph's OAuth-token + workdir mounts **will not appear inside the guest automatically.** You must get those files in by a channel the engine *does* wire: **`StageAssets`** (each key attaches as a **read-only ISO**) or a manually-attached transfer VHDX, or bake them into the **CIDATA seed**. Plan the data path before you run. |
| **Gap 3** | **The result must land on a host-readable path for extraction.** `Export-SandboxArtifact` (Tier 0/1) does a host **filesystem** read of `-Workload.ResultPath`. Because of Gap 2 there is no automatic shared dir, so a `ResultPath` like `C:\sandbox\...\out\bookmarks.html` is **not** populated by the guest through a bind mount. | Decide how the guest's output reaches a host path: e.g. the workload writes to an **attached output VHDX** you then mount/read on the host, or you copy it out over the serial seam. For this smoke test you may stage a **pre-seeded `ResultPath` file** to drive the extraction step to green (see §3/§2) while you validate the *boundary*, and treat real guest-produced output as a follow-up once a transfer-out path is wired. |
| **Gap 4** | **The COM1 serial transport is live-only and best-effort v1.** `InvokeGuestCommand` (the real backend) opens `\\.\pipe\<vm>-com1` as a `NamedPipeClientStream`, writes `<cmd>; echo "__VMDEP_RC__:$?"`, and parses the RC marker. It is **never** exercised against a real guest (the fake carries all behavioral tests). It has **no per-command nonce** yet (deferred). | This is the single biggest live unknown. The guest **must** have `serial-getty@ttyS0` enabled with **autologin** (no password prompt — the client doesn't authenticate) and a shell that echoes the marker. If the pipe is unreachable or there's a login prompt, the Runner **times out** (`TimeoutSeconds`, default 300) and the run is reported as a failure — teardown still runs. |

> **Disposition for this round:** these gaps are about the *workload data path*, not the
> *containment engine*. The smoke test's job is to prove the lifecycle + the seal gate on a
> real backend. Where a gap blocks an end-to-end data flow, the step below says so and gives
> a safe stand-in (e.g. a pre-seeded `ResultPath`) so you can still certify the milestone.
> Wiring `Mounts`/transfer-out is a follow-up build item, not part of this smoke test.

---

## 0. Preconditions

Do **all** of these before any live invocation. Several point at the operator runbook —
follow it there rather than duplicating.

### 0.1 Elevated PowerShell **or** `Hyper-V Administrators` membership

A live run **requires** an elevated session whose user can manage Hyper-V. Two ways:

```powershell
# (a) Simplest: launch PowerShell 7 with "Run as administrator".
# Verify elevation:
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)   # must print True
```

```powershell
# (b) OR add your user to the Hyper-V Administrators group (then a normal pwsh can manage
#     Hyper-V without full admin). Run ONCE from an elevated prompt:
Add-LocalGroupMember -Group 'Hyper-V Administrators' -Member $env:USERNAME
#  >>> You MUST sign out and back in (or reboot) for the new group membership to take
#  >>> effect in your token. Until then TestAvailable will still report not-elevated.
```

### 0.2 Host patched to the CVE floors

A vulnerable hypervisor defeats every tier. **Do not skip.** The floors + the check
commands live in [`operator-runbook.md` §0.2](operator-runbook.md) (Hyper-V **≥ May-2026
cumulative update**; VirtualBox **> 7.2.6**; VMware **≥ 17.6.3**). If the host is below the
Hyper-V floor, **stop and patch** before running any tier.

### 0.3 Hyper-V enabled on the host

```powershell
# The Hyper-V platform feature must be Enabled (reboot if you just enabled it).
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All |
    Select-Object FeatureName, State          # State must be 'Enabled'

# And the management service must be running:
Get-Service vmms | Select-Object Status, StartType   # Status 'Running'
```

If `Microsoft-Hyper-V-All` is `Disabled`:
`Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All` then reboot.

### 0.4 PowerShell 7 + dot-source the engine

```powershell
$PSVersionTable.PSVersion        # 7.x expected (the engine uses PS7 ternary + null-coalescing)

# From the voidseal repo root.

# Invoke-Voidseal.ps1 dot-sources the whole engine (backend + loader + provisioner + sealer
# + runner). This is the single Claude-facing entry surface.
. .\scripts\Invoke-Voidseal.ps1
```

### 0.5 Confirm THIS session can manage Hyper-V (`TestAvailable` FIRST)

Run the backend's capability probe before anything else. In Claude's build session this
returns `Available=$false`; in your elevated session it should now return `$true`.

```powershell
$probe = & (New-RealHyperVBackend).TestAvailable @{}
$probe   # expect: Available=True ; Elevated=True ; Reason='Hyper-V reachable.'
```

> If `Available` is `$false`: you are not elevated / not in `Hyper-V Administrators` (re-do
> §0.1, **sign out/in** if you used the group route), or `vmms` is down (§0.3). **Do not
> proceed** — every live step fails closed on this probe anyway.

---

## 1. Build the golden Debian-12 `.vhdx` + CIDATA seed ISO

Follow [`../guest-images/debian-12-cloud.md`](../guest-images/debian-12-cloud.md) end to
end. It is the source of truth; this is the **acceptance checklist** for "done":

- [ ] A **Debian 12 genericcloud `.vhdx`** exists (converted from the official qcow2 with
      `qemu-img convert -O vhdx`). This is the **golden parent disk** — you pass its path to
      `Invoke-Voidseal -ParentDiskPath`; each run gets a differencing child.
- [ ] The image contains **`grub-efi-amd64-signed`** (Secure Boot dependency — the
      provisioner always provisions with Secure Boot **ON**; there is **no** CLI flag to
      disable it). The `MicrosoftUEFICertificateAuthority` template is the verified path.
- [ ] A **CIDATA seed ISO** is built with the volume label **exactly `CIDATA`** (uppercase,
      case-sensitive — non-negotiable) containing root-level **`meta-data`** + **`user-data`**.
- [ ] The `user-data` enables **`serial-getty@ttyS0`** with **autologin** for the non-root
      `sandbox` user (Gap 4 — the Runner's serial client does not authenticate; a password
      prompt makes it time out), the grub `console=ttyS0,115200n8` params, and installs
      **bubblewrap** + **ca-certificates**.
- [ ] A **non-root run-user** (`sandbox`) exists (the workload never runs as root).

Then fill the profile placeholders that point at these host artifacts:

```powershell
# The golden parent disk path you just built — used as -ParentDiskPath on every live run.
# (Pick your own location; this is the operator-runbook's example path.)
$GoldenVhdx = 'C:\sandbox\golden\debian-12-cloud.vhdx'
Test-Path $GoldenVhdx    # must be True before milestone 1/2
```

> `tier1.psd1` names `GuestImage='debian-12-cloud'` + `SecureBootTemplate=...`; those are
> **descriptive** — the bootable disk is supplied at run time via `-ParentDiskPath`. Per
> **Gap 1**, do the same for the Tier-0 firefox run.

---

## 2. Dry-run against the FAKE backend first (zero real risk)

Prove the logic is green and watch the state machine before any real VM exists.

### 2.1 The mock-backed suite MUST be `292/292` green

```powershell
Invoke-Pester -Path tests/
# Expect: Tests Passed: 292, Failed: 0, Errors: 0
```

If **any** test is red — especially the profile-loader invariant refusals (secret-mount,
Tier ≥ 2 starvation) or the seal-gate abort in `DeploySandbox.Tests.ps1` — a containment
guarantee regressed. **Stop. Do not run live.**

### 2.2 A dry Invoke-Voidseal over the fake backend

This exercises the **exact** orchestrator path you'll run live, but against the in-memory
fake — no Hyper-V, no elevation needed. **Verified green** against
this engine. Two things must exist on the host before the run (the orchestrator validates
both — see the note below):

1. the `-Workload.ResultPath` file (the fake guest does not write it, so the EXTRACTED step
   needs something to read — mirrors how the e2e tests drive it); and
2. **every `StageAssets` source the profile declares** — the orchestrator's STAGED step
   calls `Import-SandboxAsset`, which **`Test-Path`s the host source and fails closed if it
   is missing, on BOTH the fake and the real backend** (the validation is host-side, before
   any attach). The `ralph` profile declares `StageAssets = @{ 'C:\sandbox\assets\ralph-claude-code.iso' = ... }`,
   so that path must exist (a dummy placeholder file is fine for the dry run).

```powershell
# (1) A throwaway artifact root + a pre-seeded result file for the extraction step.
$dryRoot = Join-Path $env:TEMP 'vmdep-dryrun'
$dryRes  = Join-Path $dryRoot 'bookmarks.html'
New-Item -ItemType Directory -Force -Path $dryRoot | Out-Null
'<!DOCTYPE NETSCAPE-Bookmark-file-1>' | Set-Content -LiteralPath $dryRes -Encoding utf8

# (2) A dummy StageAssets source so the STAGED import doesn't fail closed.
#     (For the LIVE Tier-1 run this is the REAL ralph-claude-code ISO — see §4.)
$asset = 'C:\sandbox\assets\ralph-claude-code.iso'
New-Item -ItemType Directory -Force -Path (Split-Path $asset) | Out-Null
if (-not (Test-Path $asset)) { 'dummy-iso-placeholder' | Set-Content -LiteralPath $asset -Encoding ascii }

$report = Invoke-Voidseal -Tier 1 -Profile ralph `
    -Workload @{ Entrypoint = 'bash /opt/ralph/ralph-claude-code/ralph_loop.sh'; ResultPath = $dryRes } `
    -Name 'sbx-dryrun' `
    -ArtifactRoot $dryRoot -Destination (Join-Path $dryRoot 'extracted') `
    -Backend (New-FakeHyperVBackend)        # <-- the FAKE: nothing real is created

$report.States            # expect: INIT PROVISIONED STAGED SEALED RUNNING CAPTURED EXTRACTED DESTROYED
$report.SealVerdict       # expect: True
$report.RunResult.ExitCode  # expect: 0 (the fake returns a canned success)
$report.Error             # expect: $null (blank)
$report.TeardownStatus    # expect: 'OK (VM removed, created disks deleted)'
$report.ExtractedArtifact # expect: <Destination>\bookmarks.html
```

> **Why the StageAssets source must exist even for the fake run:** an
> earlier draft of this note claimed it didn't — that was wrong, and the dry run fails closed
> at STAGED without it (`Import-SandboxAsset: ISO source not found ... (fail closed before
> attaching)`, `SealVerdict=False`, teardown still runs). That is the **engine behaving
> correctly** — `Import-SandboxAsset` validates the host source path before any attach,
> independent of backend. Create the dummy placeholder above (step 2) and the run goes green.
> For the **live** Tier-1 run (§4) that same path must hold the REAL ralph ISO.

When the dry run shows the full `INIT..DESTROYED` traversal with `SealVerdict=True`,
`ExitCode=0`, a blank `Error`, and a clean teardown, the logic is sound and you can go live.

> If you copy-paste these one-liners into a `pwsh -Command` block and see two trailing red
> `$LASTEXITCODE` / `$_ec` errors AFTER the verdict prints, ignore them — that is a shell
> epilogue artifact (PowerShell-native cmdlets don't set `$LASTEXITCODE`), not a deployer
> error. Running the block interactively in an open pwsh session avoids it.

---

## 3. Milestone 1 — Firefox proof (Tier 0), LIVE, SYNTHETIC data

**Proves milestone 4.** The cleanest end-to-end exercise: offline (no NIC), no
egress dependency. Per **Gap 1** this runs as a **Debian Gen2 VM with no NIC**, not a container.

### 3.1 Synthetic data only (DATA-ACCESS rule — binding)

This milestone operates on a **SYNTHETIC / sample** Firefox profile copy. Reading your
**real** Firefox profile (bookmarks / history / `places.sqlite`) requires **explicit
per-task authorization** and is **NOT** part of this smoke test. "Personal-only this round"
is not standing read-authorization (see `firefox.psd1` header + the operator-runbook
DATA-ACCESS note). Build a sample profile dir with a couple of dummy bookmarks; never point
at the live profile, and never at `logins.json` / `key4.db` / `cookies.sqlite`.

### 3.2 Stage the data path (Gap 2 / Gap 3)

Because `Mounts` are not wired (Gap 2), get the organizer script + the sample profile into the
guest via **`StageAssets`** (read-only ISO) — the organizer ISO key in `firefox.psd1`
(`C:\sandbox\assets\firefox-organizer.iso`) must **exist on disk** for the live run. Decide
how the guest's emitted HTML reaches a host path (Gap 3); for this smoke test you may pre-seed
the `ResultPath` to drive the extraction boundary to green while the transfer-out path is a
follow-up.

```powershell
# Pre-create the host-side result path so the EXTRACTED step has a file to read (Gap 3 stand-in).
$ffOut = 'C:\sandbox\firefox-organizer-out'
New-Item -ItemType Directory -Force -Path $ffOut | Out-Null
# (If/when guest output is wired to a host path, this file is overwritten by the real run.)
'<!DOCTYPE NETSCAPE-Bookmark-file-1>' | Set-Content -LiteralPath (Join-Path $ffOut 'bookmarks.html') -Encoding utf8
```

### 3.3 The live invocation

```powershell
$report = Invoke-Voidseal -Tier 0 -Profile firefox `
    -Workload @{ ResultPath = 'C:\sandbox\firefox-organizer-out\bookmarks.html' } `
    -ParentDiskPath $GoldenVhdx `
    -Destination 'C:\sandbox\extracted\firefox'
# (default -Backend is the REAL Hyper-V backend — no -Backend argument)
```

> `-ParentDiskPath $GoldenVhdx` is **required here per Gap 1** — without a bootable parent disk
> the Tier-0 VM has nothing to boot. (The operator-runbook's Tier-0 example omits it because
> it predates this clarification; include it.)

### 3.4 What success looks like

```powershell
$report.States              # INIT PROVISIONED STAGED SEALED RUNNING CAPTURED EXTRACTED DESTROYED
$report.SealVerdict         # True  (Assert-Sealed certified the VM from the host)
$report.RunResult.ExitCode  # 0 if the organizer ran clean over the serial seam
$report.ExtractedArtifact   # the host path(s) the one-way extractor wrote (the Netscape-HTML file)
$report.Error               # $null on full success
$report.TeardownStatus      # 'OK (VM removed, created disks deleted)'
```

- The extracted artifact is a **Netscape-HTML** file whose first line is exactly
  `<!DOCTYPE NETSCAPE-Bookmark-file-1>`, copied into `C:\sandbox\extracted\firefox\`.
- The VM is **gone** (teardown runs in a `finally`).
- If the serial seam can't reach the guest (Gap 4), `RunResult.ExitCode` will be `-1` or the
  run reports a timeout in `Error` — that's a **serial-transport issue**, not a containment failure;
  the VM is still torn down.

### 3.5 Manual cleanup if it fails mid-flow

Teardown is automatic, but if a session was interrupted (Ctrl-C, crash) reap by hand:

```powershell
. .\scripts\lib\HyperVBackend.ps1
. .\scripts\lib\ProfileLoader.ps1
. .\scripts\lib\Provisioner.ps1
Remove-Sandbox -Name '<the VM name from $report.Name, e.g. sbx-0-xxxxxxxx>' -DeleteDisks
```

---

## 4. Milestone 2 — Ralph proof (Tier 1), LIVE

**Proves milestone 5.** A net-**restricted** (not no-net) Gen2 VM that runs a
**bounded** Ralph loop reaching `api.anthropic.com` through the in-guest nftables allowlist.

### 4.1 Pin the upstream SHA (placeholder in `ralph.psd1`)

`frankbria/ralph-claude-code` is **bash, has no tags** → pin a **commit SHA**, never a tag.
In `profiles/ralph.psd1`, the `StageAssets` value documents `@ <PIN-COMMIT-SHA>` — replace
that with the exact commit you vendored, then build the read-only ISO the key points at
(`C:\sandbox\assets\ralph-claude-code.iso`) from the repo at that SHA. The ISO **must exist
on disk** for the live run (Gap 2 — this is the wired channel that actually lands the repo in
the guest, read-only to `/opt/ralph`).

### 4.2 The Claude OAuth token — file-to-file, **never** paste a token

The loader **refuses** secret-shaped mounts, so you do **not** mount the live
`~/.claude/.credentials.json` (it's on the refusal list). Instead do a **one-time
file-to-file copy** of just the token into a non-secret-shaped `.token` path. **You run
this yourself; the value never transits an agent's context, a shell echo, or a tool argument:**

```powershell
# You run this. The token value is never read into chat / a tool argument / a log.
$dest = 'C:\sandbox\agent-cred'
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item "$env:USERPROFILE\.claude\.credentials.json" "$dest\agent.token"
```

The `ralph.psd1` profile references **that** `.token` path (`C:\sandbox\agent-cred\agent.token`).
The `.token` leaf is not on the refusal list, so the profile loads. **Caveat (Gap 2):** the
profile's `Mounts` are validated but **not wired into the guest**, so getting the token file
*into* the sealed VM is **not** automatic — bake it into the CIDATA seed or a StageAssets ISO
by hand (read-only), or accept that the live loop authenticates only once a token-delivery
channel is wired. Either way: **rotate the token after any session that touched it.**

### 4.3 The live invocation

```powershell
$report = Invoke-Voidseal -Tier 1 -Profile ralph `
    -Workload @{ ResultPath = 'C:\sandbox\ralph-workdir\out' } `
    -ParentDiskPath $GoldenVhdx `
    -Destination 'C:\sandbox\extracted\ralph'
# (default -Backend = real Hyper-V)
```

### 4.4 What success looks like

```powershell
$report.SealVerdict          # MUST be True — the loop only runs on a SEALED VM (hard gate)
$report.States               # INIT..DESTROYED on success
$report.RunResult.ExitCode   # the Ralph loop's exit status over the serial seam
$report.ExtractedArtifact    # the extracted workspace diff/output dir, copied to the host
```

- The **net-restricted** VM keeps its NIC (Tier 1 is restricted, **not** no-NIC — only
  Tier ≥ 2 removes the NIC). Egress is the **in-guest nftables allowlist** (`api.anthropic.com`
  et al.). **Important:** `Lock-Sandbox` does **not** install the nftables rules — egress
  restriction is an **in-guest** concern set up by the CIDATA seed / staging. The
  seal removes host↔guest channels + detaches import media; the allowlist is the guest's job.
- The Ralph loop is **bounded** — rate/iteration caps (`MAX_CALLS_PER_HOUR`,
  `CLAUDE_TIMEOUT_MINUTES`, etc.) are set via env in the **guest** (cloud-init / seed), not in
  the profile. Confirm your seed sets a small cap for the smoke test so it can't run away.
  Also bound the host-side wait with `-TimeoutSeconds` if you call the Runner directly.
- **No auto-push.** Ralph commits land in the in-guest workspace; the diff is extracted for
  you to **review and cherry-pick** into the real repo. There is no remote and no push —
  the cherry-pick-after-review gate is preserved (the review-before-integrate model).

### 4.5 Manual cleanup if it fails mid-flow

Same as §3.5, with the Tier-1 VM name (`$report.Name`, e.g. `sbx-1-xxxxxxxx`):

```powershell
Remove-Sandbox -Name '<sbx-1-...>' -DeleteDisks
```

---

## 4A. Milestone 3 — Firefox Tier-0 REAL workload round-trip (disk mode)

**Proves the disk-passing goal:** a real workload runs *inside* the sealed guest and its **real** output
comes back — not the pre-seeded stand-in Milestone 1 used. This is the **disk-passing** model:
the host hands the guest its inputs on an INPUT data disk + a pre-formatted (exFAT) OUTPUT
disk, the guest's cloud-init runner mounts both, runs the organizer, writes `result.html` +
an exit-code sentinel `result.exitcode` to the OUTPUT disk, **unmounts then self-powers-off**;
the host polls `State==Off` (with a timeout), detaches the disks, reads the output natively
(`Mount-VHD -ReadOnly`, no WSL), and **classifies success/failure from the sentinel** — it
never assumes "Off == success".

> **Why this exists:** Milestone 1 reached `INIT…DESTROYED` + `SealVerdict=True` but its
> `bookmarks.html` was a stand-in because the serial command channel raced the boot. The
> disk-passing model replaces that fragile handshake. The engine is **mock-proven (425 tests)**;
> this milestone is its first *live* exercise.

### 4A.1 Preconditions (mostly reuse Milestone-1 groundwork)

- The golden Debian `.vhdx` (non-sparse) at `C:\sandbox\golden\debian-12-cloud.vhdx` — same as §3.
- The **CIDATA seed ISO** at `C:\sandbox\assets\cidata-seed.iso` — BUT for disk mode it must carry the
  **disk-mode workload-runner** `user-data` (see `guest-images/debian-12-cloud.md` §2a), not the
  bare serial-getty seed. The runner mounts `LABEL=INPUT` ro at `/mnt/in` + `LABEL=OUTPUT` rw at
  `/mnt/out`, runs the entrypoint, writes `result.html` + `result.exitcode`, `umount`s, then
  `poweroff`s, substituting the firefox profile's `Entrypoint`
  (`python3 /mnt/in/organize_bookmarks.py --profile /mnt/in --out /mnt/out/result.html`).

  **Build it with the `New-CidataSeed` builder** (`scripts/lib/SeedBuilder.ps1`, dot-sourced by the
  orchestrator) — it emits the §2a runner with the entrypoint substituted and writes the ISO with the
  `CIDATA` volume label via built-in Windows IMAPI2 (no ADK/WSL needed). It selects the runner shape
  from the profile's `WorkloadMode` (`Disk` → the disk runner; anything else → the serial baseline),
  and fails closed if the entrypoint contains a single quote or newline (it runs as `sh -c '…'`):

  ```powershell
  . .\scripts\Invoke-Voidseal.ps1
  $ff = Import-WorkloadProfile -Path .\profiles\firefox.psd1 -TierProfileDir .\tier-profiles
  New-CidataSeed -Profile $ff      # -> writes the profile's SeedIso (C:\sandbox\assets\cidata-seed.iso)
  ```

  Verify the produced ISO before the run (the volume label must be exactly `CIDATA`, and the disk-mode
  markers must be present — `vmdep-workload`, `LABEL=INPUT`/`OUTPUT`, `result.exitcode`, the substituted
  entrypoint — with NO leftover `serial-getty`). **Ralph (Tier 1, §4) reuses the same `cidata-seed.iso`
  path with the SERIAL seed** — regenerate per-profile before each run (`New-CidataSeed` on the ralph
  profile rebuilds the serial seed; on firefox it rebuilds the disk seed).
- The image must already contain **python3** (the runner does NOT apt-install — sealed/offline).
  The Debian genericcloud image has python3; if your organizer needs `lz4`, bake it into the
  golden image at image-prep (the live run is offline).
- **The image must have a non-root `sandbox` user** (debian-12-cloud.md §2 creates it) — the runner
  runs the entrypoint as `sandbox`, falling back to root only if it's absent.
- **Confirm the exfat kernel module loads in the golden image** before the run — the Debian *cloud*
  kernel can be driver-trimmed. Boot the golden image once (or chroot) and run
  `modprobe exfat && lsmod | grep exfat`. If it's absent, either install `exfatprogs`/enable the
  module at image-prep, **or** switch the firefox profile to `FileSystem='FAT32'` (one host-side knob;
  both drivers are in-kernel — no guest change needed). exFAT-unavailable otherwise degrades to a
  clean host-classified `Failed` (no sentinel), not a hang.
- **`ds=nocloud`** on the guest kernel cmdline (GRUB, baked at image-prep) is a boot-speed
  tunable — without it the first boot adds a 2–5 min datasource-probe delay (the host
  `-WorkloadTimeoutSeconds` default 600 still bounds it, so it's not a blocker).

### 4A.2 The organizer script must be /mnt/in ⇄ /mnt/out aligned (one-time check)

The host source `C:\sandbox\organizer-src\organize_bookmarks.py` must **read its `--profile`
from `/mnt/in`** and **write `--out` to `/mnt/out/result.html`** (the runner invokes it that
way). If your current copy writes `bookmarks.html` or reads a different path, use an aligned
copy for the live run. (Don't worry about the OLD `firefox.psd1` `Mounts`/`StageAssets`/`/work/out`
comments — those are the superseded serial/container-era mechanism; Disk mode uses the data disks.)

> **★ HARD PRE-RUN GATE — validate the organizer on the host first.** The organizer lives *outside*
> this repo (`C:\sandbox\organizer-src\`); no test and no reviewer has exercised it, yet it is the
> entire content path of the run. The disk-mode runner makes **`--out` the SOLE writer** of
> `result.html` (it no longer redirects stdout into that file), so the organizer **must write the
> file itself via `--out`**. Confirm this on the host (or any Debian shell) **before** the live run —
> it costs seconds and prevents a spurious `Failed`/empty-artifact that would otherwise look like a
> guest bug:
>
> ```powershell
> $tmp = Join-Path $env:TEMP 'org-pretest'; New-Item -ItemType Directory -Force $tmp | Out-Null
> Copy-Item 'C:\sandbox\firefox-sample-profile\sample-bookmarks.json' $tmp
> python3 'C:\sandbox\organizer-src\organize_bookmarks.py' --profile $tmp --out (Join-Path $tmp 'result.html') *> (Join-Path $tmp 'stdout.log')
> $html = Get-Content -LiteralPath (Join-Path $tmp 'result.html') -Raw
> # GATE 1: the script WROTE result.html itself (via --out), and it is non-empty.
> [string]::IsNullOrWhiteSpace($html) | Should-BeFalse   # (or: if empty, --out is not wired — FIX before the live run)
> # GATE 2: first line is EXACTLY the Netscape doctype (Firefox-importable).
> ($html -split "`n")[0].Trim() -eq '<!DOCTYPE NETSCAPE-Bookmark-file-1>'   # must be $true
> # GATE 3: dedup actually happened — fewer <A> entries than the 4-item sample.
> ([regex]::Matches($html,'(?i)<a\s').Count) -lt 4                          # must be $true
> ```
>
> If `result.html` is empty after this, the organizer is writing to **stdout** instead of `--out` —
> the runner will NOT capture that into `result.html` (by design, to avoid the double-write that can
> corrupt the HTML), so the live run would extract an empty artifact. Fix the organizer to write via
> `--out` (or, if you truly want stdout capture, change the runner to redirect — but then drop the
> script's `--out`; never both on the same path).

### 4A.3 Populate the INPUT disk from your host files, then deploy

The firefox profile ships `Inputs = @{}` (empty by design — a `.psd1` can't cleanly inline a
Python file). You inject the real inputs at deploy time via `-Workload.Inputs` (the engine
folds this onto the resolved profile → `New-WorkloadDisks` writes them onto the INPUT disk).
The map is `innerName -> CONTENT`:

```powershell
$GoldenVhdx = 'C:\sandbox\golden\debian-12-cloud.vhdx'

# Read the organizer script + the synthetic sample into an innerName -> content map.
$inputs = @{
    'organize_bookmarks.py' = Get-Content -LiteralPath 'C:\sandbox\organizer-src\organize_bookmarks.py' -Raw
    'sample-bookmarks.json' = Get-Content -LiteralPath 'C:\sandbox\firefox-sample-profile\sample-bookmarks.json' -Raw
}

. .\scripts\Invoke-Voidseal.ps1

$report = Invoke-Voidseal -Tier 0 -Profile firefox `
    -Workload @{ WorkloadMode = 'Disk'; Inputs = $inputs;
                 ResultInnerName = 'result.html'; SentinelInnerName = 'result.exitcode' } `
    -ParentDiskPath $GoldenVhdx `
    -Destination 'C:\sandbox\extracted\firefox-g4'
```

> **DATA-ACCESS rule:** `sample-bookmarks.json` is **synthetic**. Running against your **real**
> Firefox profile requires explicit per-task authorization AND pointing the input at a *copy*
> of the real profile (Firefox closed) — never the live profile. The default here is synthetic.

### 4A.4 What success looks like

```powershell
$report | Format-List States, SealVerdict, `
    @{n='Status';e={$_.RunResult.Status}}, @{n='ExitCode';e={$_.RunResult.ExitCode}}, `
    ExtractedArtifact, Error, TeardownStatus
```

| Field | Success value |
|---|---|
| `States` | `INIT … STAGED SEALED RUNNING CAPTURED EXTRACTED DESTROYED` |
| `SealVerdict` | `True` (the data disks are *recorded*, so the gate certifies) |
| `RunResult.Status` | **`Success`** |
| `RunResult.ExitCode` | `0` |
| `ExtractedArtifact` | `C:\sandbox\extracted\firefox-g4\result.html` — a **real, guest-generated** Netscape-HTML, first line `<!DOCTYPE NETSCAPE-Bookmark-file-1>`, with **fewer** entries than the 4-item sample (dedup applied → proves the guest actually ran the organizer) |
| `TeardownStatus` | `OK (VM removed, created disks deleted)` |

Then confirm no orphans (as §3.3): `Get-VM -Name 'sbx-*'` empty; `Get-VMSwitch | ? Name -like 'sbx-*-int'` empty.

### 4A.5 How to read a FAILURE (the host classifies — it never guesses)

| `RunResult.Status` / `Reason` | Meaning | Where to look |
|---|---|---|
| `Failed`, reason mentions **`sentinel`** | The guest never wrote `result.exitcode` → the workload crashed, hung pre-write, or cloud-init didn't run the runner | The guest serial console / the OUTPUT disk's `stderr.txt` (mount it read-only on the host: `Mount-VHD -Path <out.vhdx> -ReadOnly`). Most likely: the runner didn't mount the disks (label mismatch?), python3 missing, or the organizer path wrong (`/mnt/in`). |
| `Failed`, reason mentions **timed out** | The guest never reached `State=Off` within `-WorkloadTimeoutSeconds` | Boot too slow (add `ds=nocloud`) or the runner never called `poweroff` (an exFAT umount hang — check the runner's umount-retry loop). The VM was force-stopped + torn down. |
| `Failed`, `ExitCode` non-zero (e.g. 3) | The organizer ran but exited non-zero | A real organizer bug; `result.html`/`stderr.txt` may still hold partial output (extracted). |
| `Failed`, reason mentions **`result … empty`** | The guest wrote a 0-byte/whitespace `result.html` (e.g. the organizer printed to stdout instead of `--out`) | Re-run the §4A.2 pre-run gate — the organizer is not writing the file via `--out`. **Host-side**, not a containment issue. |
| `Failed`, reason mentions **`detach`** | A transient host-side `Remove-VMHardDiskDrive` failed after the run; the host skipped the read rather than read a possibly-still-attached disk | **Host-side**, not a guest bug. `result.html` is likely fine on the OUTPUT disk — just re-run. The VM was still torn down (no orphan). |
| `SealVerdict=False` | Aborted **before** RUNNING — the seal gate refused | `$report.Error` says why (an unrecorded disk, a live host channel). The data disks ARE recorded, so this should NOT happen for a clean firefox run; if it does, the seal found something unexpected — investigate before re-running. |

Whatever the outcome, **teardown still runs** (the `finally`), so you won't accumulate orphans.

### 4A.6 The live-only-unproven list (what this milestone is actually testing for the first time)

The 425 mock tests prove the *host orchestration* + *classification* logic. These pieces run for
the **first time** on real hardware here — if something snags, it's most likely one of these,
**not** a containment failure:

1. **Host disk format** — `New-VHD`+`Mount-VHD`+`Initialize-Disk -GPT`+`New-Partition`+`Format-Volume -exFAT`+`Dismount` (the `NewOutputVhdx` real path; has a Get-Disk settle-retry).
2. **Native host read** — `Mount-VHD` (read-**write**, see note) + drive-letter assign + read + `Dismount` (the `ReadVhdxFile` real path). NOTE: `ReadVhdxFile` deliberately mounts the OUTPUT disk read-write, not read-only — a read-only mount on Windows often won't auto-assign a drive letter and `Add-PartitionAccessPath -AssignDriveLetter` can throw against a write-protected volume, which would make this *first* read spuriously report `result read failed`. RW is safe (the OUTPUT disk is the deployer's own host-formatted volume, detached from the powered-off guest; Tier ≥ 2 untrusted output never reaches here — it quarantines first). If a read *still* fails after this, suspect the guest didn't write `result.html`/`result.exitcode` (item 3), not the mount.
3. **The guest cloud-init runner** — does the seed's `vmdep-workload` unit actually run, mount the exFAT disks by LABEL, run the entrypoint **as the non-root `sandbox` user**, write `result.html` (via the entrypoint's `--out`) + the `result.exitcode` sentinel, and self-poweroff? (First live exercise.) The runner is started **`--no-block`** so its `poweroff` doesn't race `cloud-final`, and `exit`s after a mount-failure `poweroff` (so it never runs against an unmounted `/mnt/out`). If the run fails, mount the OUTPUT disk read-only on the host and read `/stdout.log` + `/stderr.txt`.
4. **exFAT mount in the guest** — the in-kernel `exfat` module auto-loading on `mount LABEL=OUTPUT` (Debian 6.1 kernel; the runner `modprobe`s it), **with `uid=/gid=` options** so the non-root `sandbox` user can read `/mnt/in` and write `/mnt/out`. If exFAT is somehow unavailable, switch the firefox profile to `FileSystem='FAT32'` (one knob; ≤4 GiB/file, fine here).
5. **Detach timing** — `RemoveHardDiskDrive` against the now-Off VM. A transient detach throw is **caught**: the run is reported `Failed` (reason names the *detach* → host-side, not a guest bug) and the host **skips the read** rather than read a possibly-still-attached disk; teardown still removes the VM. Never a corruption-read, never a lifecycle abort.
6. **Host drive-letter assignment** — `Add-PartitionAccessPath -AssignDriveLetter` on a freshly-mounted exFAT volume (the `$script:SbResolveVolumeLetter` path used by Write/ReadVhdxFile). Now settle-retried (Get-Disk **and** Get-Partition) and the assigned letter is validated `^[A-Za-z]$`; a still-blank letter throws a clear named error rather than building a `\0:\` path.

### 4A.7 Manual cleanup if interrupted

```powershell
Remove-Sandbox -Name '<sbx-0-... from $report.Name>' -DeleteDisks
```

---

## 5. Per-tier seal verification

The seal gate (`Assert-Sealed`) runs **inside** `Invoke-Voidseal` as a hard gate before
RUNNING. You verify it certified by reading the report; for Tier 1 you also spot-check that
egress is actually restricted.

### 5.1 Eyeball that the gate certified

```powershell
$report.SealVerdict    # MUST be $true for BOTH milestones — the workload only runs if so.
```

- If `SealVerdict` is `$false`, the deploy **aborted before RUNNING** (the workload never
  ran) and the report's `Error` says why (e.g. a NIC still attached at Tier ≥ 2, a host
  channel still readable, a residual disk). The VM was still torn down. Inspect the profile's
  `HostChannels` (all `$false` for VM tiers) and that `Lock-Sandbox` ran — see the
  operator-runbook troubleshooting table.
- `States` should include `SEALED` on success; a seal-gate abort stops **before** `RUNNING`.

### 5.2 Tier-1 egress is actually restricted (quick in-guest test)

The seal does **not** enforce egress (5/§4.4) — the in-guest nftables allowlist does. Verify
it from **inside** the guest over the serial console: a non-allowlisted host must be blocked
while an allowlisted one is reachable.

```text
# In the guest serial console (the host drives \\.\pipe\<vm>-com1):
#   allowlisted -> should connect:
curl -sS -m 8 https://api.anthropic.com/ -o /dev/null ; echo "anthropic rc=$?"
#   NOT allowlisted -> should FAIL (blocked by nftables default-deny):
curl -sS -m 8 https://example.com/ -o /dev/null ; echo "example rc=$?"
```

Expect a **non-zero / timeout** rc for `example.com` (blocked) and `rc=0` for
`api.anthropic.com` (allowed). A reachable `example.com` means the in-guest allowlist isn't
in force — fix the seed's nftables setup before trusting the tier. (This is an *in-guest*
control and is bypassable by guest-root — acceptable for v1's trusted-workload Tier 1; host/
hypervisor enforcement is the documented escalation, per tier-reference.md.)

---

## 6. Teardown + rollback (confirm no orphans)

Teardown runs in a `finally`, so a clean run leaves nothing behind. Confirm:

```powershell
# No leftover sandbox VM (the run's name was $report.Name, like sbx-0-xxxxxxxx / sbx-1-xxxxxxxx):
Get-VM -Name 'sbx-*' -ErrorAction SilentlyContinue        # should list nothing from the run

# No leftover Internal vSwitch the Tier-1 provision may have created (named '<vm>-int'):
Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object Name -like 'sbx-*-int'   # should be empty

# No leftover differencing disk under the sandbox storage root:
Get-ChildItem 'C:\ProgramData\Voidseal\sandboxes' -Recurse -Filter '*.vhdx' -ErrorAction SilentlyContinue
#   (storage root = %ProgramData%\Voidseal\sandboxes\<vmName>; -DeleteDisks removes the created child)
```

Manual reap (any orphan from an interrupted run) — idempotent, safe to re-run:

```powershell
. .\scripts\lib\HyperVBackend.ps1
. .\scripts\lib\ProfileLoader.ps1
. .\scripts\lib\Provisioner.ps1
Remove-Sandbox -Name '<orphan vm name>' -DeleteDisks
# If a vSwitch lingers (rare — the provisioner reaps switches it created on rollback):
Remove-VMSwitch -Name '<orphan>-int' -Force        # only if Get-VMSwitch shows it
```

> `Remove-Sandbox` stops the VM if running, unregisters it, and (with `-DeleteDisks`) deletes
> the disks. Without a `-Descriptor` it deletes whatever disks were attached; the **golden
> parent** is never touched (the run only ever creates a **differencing child**).

---

## 7. What this proves — and what it does NOT

**Proves (milestones 4 & 5, on a live backend):**

- Tier-0 Firefox: the full `INIT → … → DESTROYED` lifecycle with **zero egress dependency**,
  the seal gate certifying, a one-way host-read extraction, and a clean teardown — the core
  engine end-to-end.
- Tier-1 Ralph: the same lifecycle on a **net-restricted** Gen2 VM, with a **bounded** agent
  loop reaching only the allowlisted egress, the diff extracted for **human cherry-pick**
  (no auto-push), and a clean teardown.
- The **host-verified seal gate** is a real gate on a real backend (the workload only runs on
  `SealVerdict=$true`).

**Does NOT do (out of scope this round — gated behind explicit future authorization):**

- **No Tier 2/3 live detonation.** Those paths are scaffold/harness-only; the Tier ≥ 2
  extractor routes to a quarantine sink that **throws** (`Export-ColdVhdxQuarantine` is
  NotImplemented in v1). No live malware or untrusted-plugin detonation until you
  green-light verified isolation.
- **No real personal data.** Synthetic/sample Firefox data only; real-profile reads need
  explicit per-task authorization (DATA-ACCESS rule).
- **Does not validate the un-wired data path (Gap 2 / Gap 3).** Host↔guest `Mounts` and a robust
  transfer-out are **not** wired in v1 — where this smoke test uses a pre-seeded `ResultPath`,
  it certifies the *extraction boundary*, not a full guest-produced artifact round-trip. That
  wiring is a follow-up build item, not part of this smoke test.
- **Does not harden the serial transport (Gap 4).** The COM1 client is best-effort v1 with no
  per-command nonce; the smoke test exercises it live for the first time but does not certify
  it against an adversarial guest.

---

## 8. Sign-off checklist

Tick each as you go. **Record the result** in your run log (a dated
entry: pass/fail per milestone, the report `States`/`SealVerdict`/`ExitCode` for each, and
any gap-related friction observed).

**Preconditions**
- [ ] Elevated session **or** `Hyper-V Administrators` membership (signed out/in if group route) — §0.1
- [ ] Host patched to the Hyper-V CVE floor (≥ May-2026 CU) — §0.2 / operator-runbook §0.2
- [ ] `Microsoft-Hyper-V-All` Enabled + `vmms` Running — §0.3
- [ ] PowerShell 7; engine dot-sourced (`. .\scripts\Invoke-Voidseal.ps1`) — §0.4
- [ ] `TestAvailable` returns `Available=$true` in **this** session — §0.5

**Golden image**
- [ ] Debian-12 golden `.vhdx` built; `$GoldenVhdx` resolves; `grub-efi-amd64-signed` present — §1
- [ ] CIDATA seed ISO built (label exactly `CIDATA`; `meta-data`+`user-data`; serial-getty autologin) — §1

**Dry run**
- [ ] `Invoke-Pester -Path tests/` → **all green, 0 failed** (425+ as of the disk-mode build; the exact count grows as features land) — §2.1
- [ ] Fake-backend `Invoke-Voidseal` shows `INIT..DESTROYED`, `SealVerdict=$true`, clean teardown — §2.2

**Milestone 1 — Firefox (Tier 0), synthetic (containment proof, stand-in output)**
- [ ] Synthetic/sample profile only (no real data) — §3.1
- [ ] Organizer ISO staged on disk; `ResultPath` stand-in seeded (Gap 3) — §3.2
- [ ] Live `Invoke-Voidseal -Tier 0 -Profile firefox -ParentDiskPath $GoldenVhdx ...` run — §3.3
- [ ] `SealVerdict=$true`; Netscape-HTML extracted; VM destroyed; `Error=$null` — §3.4

**Milestone 3 — Firefox Tier-0 REAL workload (disk mode) — the real round-trip**
- [ ] CIDATA seed carries the **disk-mode workload-runner** user-data (not the bare serial seed); the golden image has the non-root **`sandbox`** user — §4A.1 / debian-12-cloud.md §2
- [ ] `ds=nocloud` baked into guest GRUB; python3 (+ any organizer deps) in the golden image — §4A.1
- [ ] **★ HARD GATE:** host-side organizer pre-test passes — writes `result.html` via `--out` (non-empty), first line is exactly `<!DOCTYPE NETSCAPE-Bookmark-file-1>`, dedup applied (<4 `<A>`) — §4A.2
- [ ] `-Workload.Inputs` populated from the host organizer + sample; live `Invoke-Voidseal -Tier 0 -Profile firefox -Workload @{WorkloadMode='Disk';Inputs=...}` run — §4A.3
- [ ] `RunResult.Status='Success'`, `ExitCode=0`, a **real guest-generated** `result.html` (dedup applied), VM destroyed — §4A.4

**Milestone 2 — Ralph (Tier 1)**
- [ ] Upstream SHA pinned in `ralph.psd1`; Ralph repo ISO built at that SHA, on disk — §4.1
- [ ] OAuth token copied file-to-file to the `.token` path by you (no paste) — §4.2
- [ ] Live `Invoke-Voidseal -Tier 1 -Profile ralph -ParentDiskPath $GoldenVhdx ...` run — §4.3
- [ ] `SealVerdict=$true`; bounded loop; diff extracted; **no push**; VM destroyed — §4.4

**Seal verification + teardown**
- [ ] `SealVerdict=$true` for both milestones — §5.1
- [ ] Tier-1 egress test: `example.com` blocked, `api.anthropic.com` allowed — §5.2
- [ ] No orphaned VM / vSwitch / VHDX after both runs — §6

**Post**
- [ ] Token rotated (if a live Ralph run touched it) — §4.2
- [ ] Result recorded in your run log (pass/fail + report fields + gap notes)
