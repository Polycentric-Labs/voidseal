---
name: voidseal
description: >
  Provision a risk-tiered, sandboxed/airgapped Hyper-V VM (or Tier-0 container) on
  a Windows 11 Pro host, inject the files/tools a task needs, SEAL it to the
  required isolation, run the workload, capture results across a one-way boundary, and
  tear it down. Use when the user says "provision a sandbox VM", "spin up an isolated VM",
  "deploy a sandboxed / airgapped VM", "run this in a throwaway VM", "sandbox this
  agent loop / plugin / untrusted code", or invokes /voidseal. Two v1 workload
  profiles ship: `ralph` (Tier-1 net-restricted Claude Code agent loop) and `firefox`
  (Tier-0 bookmark organizer on a profile COPY). Tier 0 is live-proven on real Hyper-V
  (firefox disk-mode round-trip); Tier 1 (net-restricted VM) is mock-green with its live
  run pending; Tier 2 (disposable no-net) + Tier 3 (airgapped detonation) are
  scaffolded/harness-only this round — NO live malware or plugin detonation. Live runs
  require an ELEVATED session (Hyper-V Administrators).
---

# voidseal — risk-tiered sandbox VM provisioning

A Claude-facing **skill + PowerShell engine** that auto-provisions **risk-tiered,
sandboxed Hyper-V VMs** (and Tier-0 containers) so you can work on risky things —
autonomous agent loops, untrusted plugins, eventually malware — without exposing the
host. It runs the full lifecycle:

```
INIT -> PROVISIONED -> STAGED -> SEALED -> RUNNING -> CAPTURED -> EXTRACTED -> DESTROYED
```

**Design north star (Anthropic containment P1):** *supervise capability, not behavior* —
assume the agent/code inside is a prompt-injectable insider; make the blast radius
structurally small. Isolation strength is matched to the task's risk via the **tier axis**.

> **Status (v1):** core engine + the Tier 0/1 Hyper-V provisioning paths built + tested. The whole
> module is **mock-backed green (485 tests)**, AND the **Tier-0 `firefox` disk-mode round-trip is now
> LIVE-PROVEN on real Hyper-V** (2026-06-25 — Milestone 3: provision → host-verified seal gate →
> disk-passing workload → host-read result → clean teardown, end to end; the first live run drove out
> 7 real `fake≠real` host/Hyper-V gaps, all since fixed). The **Tier-1 `ralph` live run is still
> pending** (mock-green; not yet exercised on metal — and serial-mode seed delivery needs the same
> seal-survival treatment disk mode got). Tier 0's **container substrate is not yet built** (v1
> provisions Tier 0 via the Hyper-V path; the Docker / `docker sbx` / sandbox-runtime substrate is a
> planned future addition). Tier 2/3 are **scaffolded code paths validated with benign inputs only** —
> no untrusted plugin or malware is run until you explicitly green-light verified isolation.
> Credential-injecting host-Envoy is **deferred to Phase-1B** (v1 egress is a credential-FREE
> FQDN/nftables allowlist).

## The tier model

| Tier | Substrate | Network / egress | Credentials | Extraction | Lifecycle | v1 status |
|---|---|---|---|---|---|---|
| **0** | **Hyper-V path / lightweight guest** today (container runtime — Docker / devcontainer / `docker sbx` / sandbox-runtime — is **PLANNED, not yet built**) | host-proxy allowlist (default offline) | none | host reads result dir | `--rm` ephemeral (container tier, when built) | **validated (mock-backed; live run = the live smoke test, operator-run, elevated)** — `firefox` proof runs the Hyper-V path |
| **1** | Hyper-V Gen2 VM | Internal switch + **in-guest nftables** FQDN allowlist (block QUIC/DoH/DoT); credential-FREE | scoped, on-demand, **default none** | host reads result dir | snapshot-revert | **validated (mock-backed; live run = the live smoke test, operator-run, elevated)** — `ralph` proof |
| **2** | Hyper-V VM, disposable | **no NIC** (structurally starved) | **none** (enforced) | **cold output-VHDX → quarantine VM → CDR → inert promote** | create → destroy | **scaffold / benign dry-run only** |
| **3** | Hyper-V Gen2, **no NIC** + sinkhole VM | **structurally no egress** | **none** (enforced) | same as Tier 2, mandatory | detonate → wipe | **scaffold / benign dry-run only** |

> **On the "container" substrate for Tier 0:** the v1 engine provisions **only** through
> Hyper-V (`New-SandboxVM` is Hyper-V-only). The container runtime listed for Tier 0
> (Docker / devcontainer / `docker sbx` / sandbox-runtime) is **design-intent for a future
> addition** — it is **not wired** in v1, so nothing here invokes `docker sbx`. The Tier-0
> `firefox` proof runs through the Hyper-V path / a lightweight guest, not a container.
> **On "validated":** the whole engine is **mock-backed** — all tests run against the fake
> Hyper-V backend (no real VM is created in CI). The first real, elevated end-to-end run is
> the live smoke test (operator-run, elevated) (see [Elevation requirement](#elevation-requirement)).

The loader **structurally enforces** the high-tier guarantees: a Tier ≥ 2 profile that
declares any credential, egress mode, or allowlist entry is **refused at load time**
(fail-closed), and the runtime seal gate refuses to mark a Tier-3 VM sealed if it detects
any live NIC, secret volume, or egress route.

## How to invoke

The Claude-facing entry point is **`scripts/Invoke-Voidseal.ps1`**, which dot-sources the
whole engine. From an **elevated** PowerShell session at the skill root:

```powershell
# Dot-source the orchestrator (pulls in the backend + loader + provisioner + sealer + runner).
. .\scripts\Invoke-Voidseal.ps1

# Tier-1 Ralph loop (net-restricted Claude Code agent loop):
$report = Invoke-Voidseal -Tier 1 -Profile ralph `
    -Workload @{ ResultPath = 'C:\sandbox\ralph-workdir\out' } `
    -ParentDiskPath 'C:\sandbox\golden\debian-12-cloud.vhdx'

# Tier-0 Firefox bookmark organizer (offline, on a profile COPY):
$report = Invoke-Voidseal -Tier 0 -Profile firefox `
    -Workload @{ ResultPath = 'C:\sandbox\firefox-organizer-out\bookmarks.html' }

$report.States        # the states traversed, in order (INIT..DESTROYED on success)
$report.SealVerdict   # $true only if Assert-Sealed certified the VM
$report.ExtractedArtifact   # host-side path(s) the one-way extractor wrote
$report.TeardownStatus      # teardown always runs (no orphaned VM/disk/switch)
```

`-Profile` accepts a **bare name** (resolved against `profiles/<name>.psd1` or
`tier-profiles/tier<N>.psd1`), a **`.psd1` path**, or an already-normalized **profile
hashtable**. `-Tier` is cross-checked against the resolved profile's own `Tier` (a
mismatch is a caller error and throws). See the full parameter list in the
`Invoke-Voidseal` comment-based help (`Get-Help Invoke-Voidseal -Full`).

### What the orchestrator does, state by state

- **INIT** — load + validate the tier/workload profile (fail-closed on a bad/unknown profile).
- **PROVISIONED** — `New-SandboxVM` creates the substrate (Gen2, Secure Boot template, COM1 serial, Internal switch) from the profile. Left **powered off**.
- **STAGED** — `Import-SandboxAsset` for each `StageAssets` entry (one-way IN, read-only ISO, **before** the seal). The loader already refused any secret-shaped source, so staging cannot smuggle a secret in.
- **SEALED** — `Lock-Sandbox` cuts the VM to the tier's isolation, then **`Assert-Sealed` is a HARD GATE**. If it fails, the deploy **aborts here** — the workload never runs and the VM is torn down.
- **RUNNING** — `Start-SandboxWorkload` boots the sealed VM and delivers the entrypoint over the **COM1 named-pipe serial seam** (PowerShell Direct is Windows-guest-only; the Debian guest is driven over serial).
- **CAPTURED** — the run-result + its host-side capture artifact are recorded **out-of-band** (P8 — never trust the guest to self-report).
- **EXTRACTED** — `Export-SandboxArtifact`, one-way OUT. Tier 0/1: a trusting host-read of the emitted result. **Tier ≥ 2: routes to the quarantine sink, which THROWS** (the cold-VHDX/CDR flow is post-v1) — a hostile-tier artifact is never trustingly copied to the host.
- **DESTROYED** — `Remove-Sandbox` stops + unregisters + deletes the created disks. Teardown **always runs** (in a `finally`), so a mid-flow failure leaves no orphan.

## The two v1 workload profiles

| Profile | Tier | What it runs | Egress | Data |
|---|---|---|---|---|
| **`profiles/ralph.psd1`** | 1 | `bash ralph_loop.sh` (`frankbria/ralph-claude-code`, pinned by **commit SHA** — it's bash, has no tags). Drives the `claude` CLI ≥ 2.0.76 headless (`claude -p … --output-format json --allowedTools … --resume`; **no** `--dangerously-skip-permissions`). Bare Debian VM, no nested devcontainer; native bubblewrap for defense-in-depth. | inherits tier1's nftables FQDN allowlist (`api.anthropic.com`, `github.com`, npm, pypi …) + install-time origins | OAuth token via **read-only file bind-mount** — never `-e`, never embedded |
| **`profiles/firefox.psd1`** | 0 | `organize_bookmarks.py` — dedupe + frecency-rank + auto-folder a Firefox profile, emit an importable `<!DOCTYPE NETSCAPE-Bookmark-file-1>` HTML file. Operates on a **COPY** (`places.sqlite` closed-copy + `bookmarkbackups/*.jsonlz4` via `lz4.block`), never mutates live, never reads `logins.json`/`key4.db`/`cookies.sqlite`. | **none** (offline; the lone optional dead-link check escalates to Tier 1) | **defaults to SYNTHETIC/sample data**; real profile data needs explicit per-task authorization |

## Safety invariants (load-time + runtime — fail closed)

These are enforced in code (`scripts/lib/ProfileLoader.ps1`) and covered by must-pass tests:

1. **Secret-file mount refusal** — any `Mounts` source matching the exclusion list
   (`.env*`, `*.pem`, `*.key`, `*.p12`/`*.pfx`, `id_rsa*`, `credentials*.json`,
   `.credentials.json`, `~/.aws/credentials`, `~/.ssh/*`, `~/.kube/config`,
   `~/.docker/config.json`, `.npmrc`, `.pypirc`, `*-service-account.json`, anything
   under a `.secrets/` dir; trailing-dot/space and NTFS-ADS bypasses normalized away) is
   **refused** — the file is never even opened. *This is why the Ralph profile mounts a
   copied `.token` file, never the live `~/.claude/.credentials.json` (which IS refused).*
2. **Credential + network starvation at Tier ≥ 2** — a Tier ≥ 2 profile MUST set
   `Credentials='None'`, `EgressMode='None'`, and an empty `EgressAllowlist`, or it is
   refused at load time.
3. **Extraction by tier** — Tier ≥ 2 MUST use the cold-VHDX quarantine extraction; the
   trusting host-read is structurally unreachable for a hostile tier.
4. **The seal gate is mandatory** — `Assert-Sealed` is host-verified and fails closed; a
   VM that fails it **never reaches the workload-run state**. Even a (hypothetical future)
   non-throwing false verdict still blocks RUNNING (defense-in-depth, test-locked).
5. **One-way boundaries** — assets flow IN before the seal (read-only ISO); results flow
   OUT after the run (host-read at Tier 0/1; quarantine/CDR sink at Tier ≥ 2). No live
   host-filesystem mount of a hostile guest.
6. **Harness-only for the dangerous tiers this round** — Tier 2/3 paths run only with
   benign placeholder inputs. **No live malware or plugin detonation** until you
   explicitly green-light verified isolation.

## Elevation requirement

Live runs touch real Hyper-V and **require an elevated PowerShell session whose user is in
the Hyper-V Administrators group** (or an elevated admin). `New-SandboxVM` runs a
`TestAvailable` preflight and **fails closed with an actionable message** if Hyper-V is
unreachable or the session is not elevated — it never half-builds a VM. The **test suite
mocks the backend**, so tests run unprivileged; only the *live* end-to-end path needs
elevation (that is the live smoke test, operator-run, elevated).

## Operator docs

- **[`docs/operator-runbook.md`](docs/operator-runbook.md)** — provision/run/teardown
  walkthrough, the host-patch **CVE floors** (Hyper-V ≥ May-2026 CU; VirtualBox > 7.2.6;
  VMware 17.6.3), the elevation requirement, credential-handling reminders, and how to
  run the tests.
- **[`docs/tier-reference.md`](docs/tier-reference.md)** — the full tier model + the
  **P1–P10 containment rubric** (the per-tier acceptance checklist).
- **[`guest-images/debian-12-cloud.md`](guest-images/debian-12-cloud.md)** — the Debian 12
  cloud-init NoCloud recipe (Secure Boot template, COM1 serial-getty, the `CIDATA` seed ISO).
- **[`tier-profiles/SCHEMA.md`](tier-profiles/SCHEMA.md)** — the tier + workload profile
  schema (the build contract every profile targets).

## Repo layout

```
voidseal/                            # the repo root IS the skill
├── SKILL.md                         # this file — the Claude-facing entry point
├── scripts/
│   ├── Invoke-Voidseal.ps1           # top-level orchestrator (the entry surface)
│   └── lib/*.ps1                    # HyperVBackend, ProfileLoader, Provisioner, Sealer, Runner
├── tier-profiles/tier{0,1}.psd1     # isolation contracts (+ SCHEMA.md)
├── profiles/{ralph,firefox}.psd1    # the two v1 workload profiles
├── guest-images/debian-12-cloud.md  # cloud-init NoCloud recipe (a doc, not an image)
├── tests/                           # Pester unit + e2e + invariant + profile tests
└── docs/                            # operator runbook + tier reference
```

> Tier 2/3 profile *files* are not shipped as defaults (the engine supports them, and the
> orchestrator tests synthesize an in-memory Tier-2 fixture to exercise the starvation +
> quarantine paths). Add a Tier-2/3 profile only alongside an explicit verified-isolation
> green-light.

## Testing

From the skill root (no elevation needed — the backend is mocked):

```powershell
Invoke-Pester -Path tests/
```

All tests are green (unit + e2e + invariant refusals + the two profiles). The
profile-loader invariant refusals (secret-mount, Tier ≥ 2 starvation, the pre-seal gate)
and the seal-gate abort are **must-pass** tests.
