# Voidseal — Tier Reference & Containment Rubric

> The risk-tier model + the Anthropic **P1–P10 containment principles** mapped to concrete
> deployer controls, used as the **per-tier acceptance checklist** (per-tier controls + the
> P1–P10 rubric). Companion to the
> [`operator-runbook.md`](operator-runbook.md) and the Claude-facing [`../SKILL.md`](../SKILL.md).

**Design north star (P1):** *supervise capability, not behavior.* Assume the agent/code
inside the sandbox is a prompt-injectable insider; make the blast radius **structurally**
small. The tier you pick = how much capability you're willing to grant.

---

## 1. The tier model

| Tier | Use it for | Substrate | Network | Egress (v1) | Credentials | Extraction | Lifecycle | v1 status |
|---|---|---|---|---|---|---|---|---|
| **0** | trusted dev + productivity on copies (e.g. the Firefox organizer) | **Hyper-V path / lightweight guest** in v1 — container runtime (Docker / devcontainer / `docker sbx` / sandbox-runtime) is **PLANNED, not yet built** | host-proxy allowlist | host firewall / proxy (default **offline**) | injected at proxy (none by default) | host reads result dir | `--rm` per task (container tier, when built) | **validated (mock-backed; live run = the live smoke test, operator-run, elevated)** |
| **1** | agent loops (Ralph), organizers, steady-state services | Hyper-V **Gen2 VM** | Internal switch + FQDN allowlist + **block DoH/DoT/QUIC/UDP-443** | **credential-FREE in-guest nftables** default-deny + DNS-resolved ipset allowlist | scoped, on-demand, **default none** | host reads result dir | snapshot-revert | **validated (mock-backed; live run = the live smoke test, operator-run, elevated)** |
| **2** | disposable analysis of semi-trusted artifacts | Hyper-V VM, disposable | **Private switch, no NIC** | **none** | **none** (enforced) | **cold output-VHDX → quarantine VM → CDR → inert promote** | create → destroy | **scaffold / benign dry-run** |
| **3** | airgapped detonation (eventually: malware) | Hyper-V Gen2, **no virtual NIC** + sinkhole VM | **structurally no egress** | **none** | **none** (enforced) | same as Tier 2, **mandatory** | detonate → wipe (revert between runs) | **scaffold / benign dry-run** |

> **Two accuracy notes on the table above.** (1) **"validated (mock-backed)"** — the engine
> is exercised entirely against a **fake Hyper-V backend**; every test runs unprivileged with
> no real VM created. The first real, elevated end-to-end run is the **live smoke test** (operator-run;
> see the [operator-runbook](operator-runbook.md)), not something v1 has executed live. (2) **Tier-0
> substrate** — v1's `New-SandboxVM` provisions **only via Hyper-V**; the container runtime
> listed for Tier 0 is **design-intent for a future addition**, not wired today, so the
> Tier-0 `firefox` proof runs through the Hyper-V path / a lightweight guest rather than
> `docker sbx`.

**Egress note (v1):** host-side Windows-Firewall FQDN allowlisting is **not
reliable** (DNS-based rules are brittle), so the Tier-1 default is **in-guest nftables**
(default-deny + a DNS-resolved ipset allowlist, QUIC/UDP-443 blocked, run unprivileged).
**No bearer tokens flow through egress** in v1, so the credential-injecting host-Envoy /
presence-boolean risk is entirely out of scope (deferred to Phase-1B). Honest caveat: any
*in-guest* control is bypassable by guest-root — for v1's **trusted-workload** Tier-1 that
is acceptable, and host/hypervisor-boundary enforcement is the documented escalation if an
in-guest-root adversary ever comes into scope. (This is also why the Tier-0 Firefox example
workload is the lead proof: the core ships and is validated without depending on the riskiest
decision.)

### Structural enforcement (not just convention)

The profile loader **fails closed** on the high-tier guarantees, and the seal gate verifies
from the host side:

- **Tier ≥ 2 starvation** — a Tier ≥ 2 profile MUST set `Credentials='None'`,
  `EgressMode='None'`, empty `EgressAllowlist`; otherwise it is **refused at load**.
- **Extraction by tier** — Tier ≥ 2 MUST use `ColdVHDX-Quarantine-CDR`; the trusting
  host-read is structurally unreachable for a hostile tier (the extractor routes Tier ≥ 2 to
  a sink that **throws**).
- **Secret-file refusal** — no secret-shaped mount source, any tier.
- **Pre-seal gate** — `Assert-Sealed` refuses to certify a Tier-3 VM if it detects a live
  NIC, a secret volume, a 1Password agent, or a non-empty egress route.

---

## 2. P1–P10 containment rubric (the acceptance checklist)

Each Anthropic principle → the concrete deployer control. **A tier "passes" only when its
row is green across P1–P10.** Use this as the sign-off checklist before trusting a tier.

| # | Principle | Deployer control | T0 | T1 | T2 | T3 |
|---|---|---|---|---|---|---|
| **P1** | Supervise **capability**, not behavior | the tier model itself — match isolation strength to task risk | ✅ | ✅ | ✅ | ✅ |
| **P2** | **Default-deny egress** | allowlist (T0/T1) / **no NIC** (T2/T3) | ✅ allowlist | ✅ nftables default-deny | ✅ no NIC | ✅ no NIC |
| **P3** | **Provenance proxy** (request attribution) | Phase-1B (v1 = FQDN + TLS-terminate; provenance deferred with credentials) | ➖ deferred | ➖ deferred | n/a (no egress) | n/a (no egress) |
| **P4** | **Credentials out of env** | injected-at-proxy (T0) / starved (T2/T3); never `-e`, file bind-mount only | ✅ | ✅ default-none | ✅ none | ✅ none |
| **P5** | **Least privilege** | non-root run-user, read-only code mounts, **secret-file refusal** | ✅ | ✅ | ✅ | ✅ |
| **P6** | **Ephemeral** | lifecycle per tier (`--rm` / snapshot-revert / create-destroy / detonate-wipe) | ✅ | ✅ | ✅ | ✅ |
| **P7** | **Battle-tested primitive** | Hyper-V (not a custom hypervisor) + container runtime | ✅ | ✅ | ✅ | ✅ |
| **P8** | **Out-of-band logging** | host/hypervisor-side capture; **never trust the in-guest trace** | ✅ proxy log | ✅ proxy + host telemetry | ✅ host capture only | ✅ host/hypervisor forensic review of outputs only |
| **P9** | **Human-in-the-loop**, sized to risk | extraction-gate at T2/T3; **absolute** at T3 | ➖ low risk | ➖ low risk | ✅ extraction gate | ✅ absolute gate |
| **P10** | **One-way flow + late trust** | import-one-way (read-only ISO) / extract-one-way (host-read or cold-VHDX/CDR); defer-trust + symlink-guard in guest bootstrap | ✅ | ✅ | ✅ | ✅ |

Legend: ✅ implemented & exercised · ➖ deferred / not-applicable-at-this-tier · (T2/T3 are
scaffolded + benign-dry-run only this round — the controls are coded and validated against
benign inputs; **no live untrusted artifact runs** until verified-isolation green-light).

### The two one-way boundaries (P10)

- **Import (one-way IN):** provision on an Internal/NAT switch → stage packages/assets
  (read-only ISO, large transfer-VHDX attach→copy→**scripted detach**) → hash/sig verify
  in-guest → checkpoint golden → **seal**. Small/known-good = read-only ISO; large =
  transfer-VHDX (not inherently one-way → scripted detach).
- **Extraction (one-way OUT):**
  - **T0/T1** — host reads a designated result dir / the workload writes artifacts the host
    collects out-of-band. (Low risk: these tiers aren't running presumed-hostile code.)
  - **T2/T3** — **cold output-VHDX** → power off → revert to clean snapshot → **detach** →
    mount **read-only in a SEPARATE no-net quarantine VM** → AV scan + **Content-Disarm-&-
    Reconstruction** → promote only **inert, sanitized formats**. **Never mount the hostile
    guest's filesystem on the trusted host.** **Transport ≠ content:** the one-way channel
    does nothing about a payload *inside* an artifact, so CDR + inert-format promotion is
    mandatory regardless of channel. (The exact offline CDR tool is an open post-v1 item —
    v1 scaffolds the flow and flags CDR as a manual/host-reviewed step.)

---

## 3. Analyze-before-detonate (Tier 2/3 — scaffolded)

Before any Tier-2/3 detonation: **Semgrep (fast) → CodeQL (deep taint) → supply-chain +
agentic-actions auditors → decision gate**. Static **clears** an artifact only if it has no
install/lifecycle hooks, no dynamic eval, no native/obfuscated code, statically-resolvable
IO, pinned non-vulnerable deps, and no taint reaching a sink; otherwise it **must detonate**
(in Tier 2/3). Cloud scanners (Aikido/Snyk/Socket) are **advisory-only, never an airgap
gate**. Output = a **signed, content-addressed behavior report**, diffable across versions.
**Scaffolded this round — not armed.**

---

## 4. Quick "which tier?" guide

- **Trusted code/data, operating on copies, needs the net or not** → **Tier 0** (container, fast).
- **An agent loop or organizer you trust, that needs a *restricted* allowlisted net** → **Tier 1** (net-restricted VM).
- **A semi-trusted artifact you want to analyze with no net** → **Tier 2** (disposable no-net) — *scaffold only this round.*
- **Presumed-hostile / malware, full airgap + detonation** → **Tier 3** — *scaffold only this round; live detonation is gated behind explicit operator approval + verified isolation.*

When in doubt, pick the **higher** tier — over-isolation costs a little speed; under-isolation
costs the host.
