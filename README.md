# Voidseal

**A Claude-Code-native, Windows/Hyper-V, local high-assurance execution harness** for running untrusted
code, untrusted AI agents, and (eventually) malware without exposing your host — built around the one
thing nobody else ships: **an unskippable, host-verified, fail-closed seal gate that proves the VM is
starved of network, credentials, and host↔guest channels *before* any untrusted workload is allowed to
run.**

It's the risk-tiered, seal-verified version of the *"bring your own VM"* that
[Anthropic's own Claude Code security docs](https://docs.anthropic.com/en/docs/claude-code/security)
recommend for untrusted work — so it **complements** Claude Code's built-in (process-level) sandbox
rather than duplicating it.

> [!IMPORTANT]
> **Honesty up front (read this before you trust it with anything dangerous).**
> - **Nothing has run a full live acceptance yet.** The Tier-0/1 engine is **mock-proven** (400+ Pester
>   tests against a fake Hyper-V backend); the real end-to-end run is an operator-run, elevated step that
>   is *pending* (see [`docs/live-smoke-test.md`](docs/live-smoke-test.md)).
> - **Tier 2 and Tier 3 (disposable no-net / air-gapped detonation) are scaffold-only.** The
>   cold-VHDX→quarantine extraction sink throws `NotImplemented` in v1. **Do not run live malware or
>   untrusted-plugin detonation yet.**
> - **Windows + Hyper-V only**, today. The "Tier-0 container" substrate is design-intent — v1 provisions
>   Tier 0 as a no-NIC Hyper-V VM.
> - Tier-1 egress is an *in-guest* control (fine for Tier-1's trusted workloads), not a host-enforced
>   firewall in v1.

## What it is

Voidseal provisions a **risk-tiered** sandbox VM, injects what a task needs, **seals** it to the required
isolation, runs the workload, captures results across a one-way boundary, and always tears down (teardown
runs in a `finally` — a failure leaves no orphan). The lifecycle is an explicit state machine:
`INIT → PROVISIONED → STAGED → SEALED → RUNNING → CAPTURED → EXTRACTED → DESTROYED`.

Design north star: **supervise capability, not behavior** — assume the thing inside is a prompt-injectable
insider, and make the blast radius structurally small.

### The tiers

| Tier | Boundary | Network | Credentials | Use |
|---|---|---|---|---|
| **0** | lightweight / offline (no-NIC VM in v1) | host-proxy, default-offline | none | trusted local workloads, file organizers |
| **1** | net-restricted Hyper-V VM | allowlisted egress (in-guest) | scoped, on-demand | autonomous agent loops against a target repo |
| **2** | disposable, **no NIC** | none (structurally starved) | none (refused at load) | untrusted code *(scaffold-only in v1)* |
| **3** | air-gapped + sinkhole | none | none | malware detonation *(scaffold-only in v1)* |

Tier ≥ 2 profiles are **structurally refused** at load if they declare any credential or egress, and the
seal gate refuses a Tier ≥ 2 VM that still has a NIC, a secret volume, or a residual transfer medium.

## What makes it different

It's **not novel as any single primitive** — Qubes has security-tiered VMs, Cuckoo/CAPE detonate malware,
Firecracker/Kata are microVMs, and air-gapped detonation is standard practice. Voidseal is distinctive as
an **integrated combination on a specific delivery surface**:

1. **A risk-tier *ladder* in one tool** — most sandbox tools expose a single fixed boundary; Voidseal
   escalates Tier 0 → 3 with one interface.
2. **A host-side, fail-closed seal *verification* before run** — the host independently certifies the
   isolation actually holds (no network, no credentials, no channels) and *refuses to run otherwise*.
   This is the part nobody else ships: runtime *enforcement* (gVisor/Kata) and agent *health checks*
   (Cuckoo/CAPE) are not the same as a pre-run, host-side proof that the box is starved.
3. **A no-live-channel disk-passing model** — inputs/outputs ride attached data disks; the guest
   self-powers-off; the host classifies from an exit-code sentinel. Works identically even fully air-gapped.
4. **Windows/Hyper-V native** (most untrusted-code tooling is Linux/KVM/cloud) and **fully mockable** (the
   whole engine is unit-tested without elevation).

### vs. Claude Code's own sandbox

Claude Code's native sandbox is an **OS-process** boundary (Seatbelt/bubblewrap + a network proxy), macOS
and Linux only, single-boundary — great as the cheap default for routine coding. Voidseal sits one rung
above it: a **hardware-VM** guest boundary, a literal airgap, a host-verified seal, hostile-output
quarantine, and *root-in-guest without root-on-host*. Use Claude Code's sandbox for normal workspace-
contained work; reach for Voidseal when a process sandbox on your real host kernel isn't enough.

## Quick start

Requirements: Windows 10/11 Pro (Hyper-V), PowerShell 7, Pester 5; an elevated session (or `Hyper-V
Administrators` membership) to actually provision; a Debian-12 golden `.vhdx` + a cloud-init seed (see
[`guest-images/debian-12-cloud.md`](guest-images/debian-12-cloud.md)).

```powershell
# from the repo root, dot-source the engine and run the Tier-0 example workload
. .\scripts\Invoke-Voidseal.ps1
Invoke-Voidseal -Tier 0 -Profile firefox -ParentDiskPath <golden.vhdx> -Destination <out-dir>
```

See [`docs/operator-runbook.md`](docs/operator-runbook.md) for the full provision → run → teardown walk,
[`docs/tier-reference.md`](docs/tier-reference.md) for the per-tier containment rubric, and
[`profiles/`](profiles/) for the two worked example profiles (`firefox` = Tier-0 bookmark organizer,
`ralph` = Tier-1 net-restricted agent loop).

## Testing

The whole engine runs against a **fake Hyper-V backend** — no elevation, no real VM:

```powershell
Invoke-Pester -Path tests
```

CI runs the same on every push/PR. See [`CONTRIBUTING.md`](CONTRIBUTING.md) — especially the rule that the
fake backend must match real Hyper-V behavior.

## AI Assistance

This project was developed alongside AI platforms.

AI models and tools used: Claude, Codex, Cursor, Ollama (and other local models), OpenRouter (incl. Gemini, GPT, etc.), Perplexity.

## License

[MIT](LICENSE) © 2026 Allen Byrd
