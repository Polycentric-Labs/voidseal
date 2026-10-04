# Voidseal — Tier Reference & Containment Rubric

> The risk-tier model + the Anthropic **P1–P10 containment principles** mapped to concrete
> deployer controls, used as the **per-tier acceptance checklist** (per-tier controls + the
> P1–P10 rubric). Companion to the
> [`operator-runbook.md`](operator-runbook.md), the Claude-facing [`../SKILL.md`](../SKILL.md), and
> [`threat-model.md`](threat-model.md) (the per-tier IN SCOPE / HOST MISCONFIG / KNOWN LIMITATION
> classification behind the "v1 status" column below).

**Design north star (P1):** *supervise capability, not behavior.* Assume the agent/code
inside the sandbox is a prompt-injectable insider; make the blast radius **structurally**
small. The tier you pick = how much capability you're willing to grant.

---

## 1. The tier model

| Tier | Use it for | Substrate | Network | Egress (v1) | Credentials | Extraction | Lifecycle | v1 status |
|---|---|---|---|---|---|---|---|---|
| **0** | trusted dev + productivity on copies (e.g. the Firefox organizer) | **Hyper-V path / lightweight guest** in v1 — container runtime (Docker / devcontainer / `docker sbx` / sandbox-runtime) is **PLANNED, not yet built** | host-proxy allowlist | host firewall / proxy (default **offline**) | injected at proxy (none by default) | host reads result dir | `--rm` per task (container tier, when built) | **validated (mock-backed; live run = the live smoke test, operator-run, elevated)** |
| **1** | agent loops (Ralph), organizers, steady-state services | Hyper-V **Gen2 VM** | Internal switch (NIC kept; switch-isolation + Default-Switch by-name refusal are seal-verified) | **host-enforced, `EgressMode='HostProxy'`**: no route, NAT or resolver in the guest; a host CONNECT allowlist proxy on the VM's own /30 is the only way out, behind host firewall rules and a port ACL that `Assert-Sealed` verifies; in-guest default-DROP as defense in depth. Mock-green only | scoped, on-demand, **default none** | host reads result dir | snapshot-revert | **provisioning/seal: validated (mock-backed; live run = the live smoke test, operator-run, elevated). Egress: HostProxy built and gate-verified in the mock suite; NOT yet live-exercised (the first elevated run is Phase 6).** |
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

**Egress note (v1):** the Tier-1 profile ships **host-enforced** egress (`EgressMode='HostProxy'` in
`tier-profiles/tier1.psd1`, since 2026-10-03; design in `scripts/lib/HostEgress.ps1`):

- **Addressing.** Each VM gets a /30 inside `10.231.0.0/16`, chosen from a SHA-256 of its name. The host
  holds the gateway address (`.1` of the /30) on `vEthernet (<vm>-int)`; the guest gets `.2` through a
  cloud-init `network-config` with DHCP off, no route and no nameservers. A host address or NAT network
  that overlaps the /30, or a host that cannot be read, refuses the provision before anything exists.
- **The one door.** `scripts/egress/voidseal_egress_proxy.py` (standard-library Python) listens on the
  gateway address, port 13128. It accepts only `CONNECT <name>:443` for names on the merged
  `EgressAllowlist` (exact names; a leading-dot entry such as `.example.org` covers the domain and its
  subdomains), resolves the name on the host, refuses any answer with a private, loopback, link-local,
  multicast, reserved or non-global address, and dials the address it chose. No plain-HTTP proxying, no
  TLS interception. One JSON line per connection (name, decision, reason, byte counts, never payload)
  goes to `egress-proxy.log` in the run's artifact folder (`report.EgressProxyLog`).
- **Everything else closed, twice.** Host firewall rules on the vEthernet interface admit only TCP from
  the guest address to the proxy port (a Windows Block rule beats any Allow, so the Blocks are shaped
  around that one tuple), and a port ACL on the VM's NIC denies all traffic except stateful TCP from the
  guest to the proxy port. No NAT exists, so there is no route off the switch at all.
- **Verified at the seal.** `Lock-Sandbox` installs the gateway address, rules and ACL; `Assert-Sealed`
  refuses unless each is on the host exactly as recorded, the record is complete for the VM's plan, and
  no NAT covers the subnet. The proxy starts after the gate and before the guest boots; teardown removes
  exactly what was recorded.
- **Guest side.** `HTTPS_PROXY` / `https_proxy` (with `NO_PROXY` empty) in `/etc/environment` and a login
  profile script, apt's proxy setting with https sources, and an in-guest default-DROP that allows only
  the proxy port, applied on the guest's single boot. The in-guest layer is defense in depth.

**Residual:** an allowlist admits names, not parties, so a name that fronts a shared CDN or a public
storage service can carry traffic for someone else (`docs/threat-model.md`); keep allowlists narrow.
**Maturity:** mock-green only. The proxy is tested on loopback sockets and the host bodies against stub
cmdlets; nothing has crossed a real interface yet ([`phase-6-live-runbook.md`](phase-6-live-runbook.md)
section 2 lists the checks for the first elevated run).

`EgressMode='InGuestSquid'` still works for a tier file that sets it: the Serial seed's
`CidataSerialEgressTemplate` (`SeedBuilder.ps1`) installs **iptables default-DROP OUTPUT** plus a
**transparent Squid `dstdomain` allowlist** over the `EgressAllowlist`, ported from the builder's
mechanism. That mode is **defense in depth, not a boundary**: a compromised or root guest can flush its
own iptables or kill its own Squid, and the mock suite asserts the seed's shape only. It retired the
earlier schema-only `EgressMode='NftablesAllowlist'`, whose static FQDN-to-IP approach could not survive
CDN IP rotation; both Squid's `dstdomain` and the HostProxy proxy decide per request, by name, so
rotation behind a name does not matter to them. The builder keeps `SquidSniProxy`. **No bearer tokens
flow through egress** in v1 regardless, so the credential-injecting host-Envoy / presence-boolean risk
stays out of scope (deferred to Phase-1B). (This is also why the Tier-0 Firefox example workload is the
lead proof: the core ships and is validated without depending on the riskiest, not-yet-live-proven piece.)

### Structural enforcement (not just convention)

The profile loader **fails closed** on the high-tier guarantees, and the seal gate verifies
from the host side:

- **Tier ≥ 2 starvation** — a Tier ≥ 2 profile MUST set `Credentials='None'`,
  `EgressMode='None'`, empty `EgressAllowlist`; otherwise it is **refused at load**.
- **Extraction by tier** — Tier ≥ 2 MUST use `ColdVHDX-Quarantine-CDR`; the trusting
  host-read is structurally unreachable for a hostile tier (the extractor routes Tier ≥ 2 to
  a sink that **throws**).
- **Secret-file refusal** — no secret-shaped mount source, any tier.
- **Pre-seal gate**: `Assert-Sealed` refuses to certify a VM that must have no NIC (Tier 0,
  Tier ≥ 2, any processor) while the host reports one, refuses any passthrough device at every
  tier, and refuses a secret-shaped or unrecorded attached volume. At every tier it also refuses a
  host channel left on (the four original ones plus the Time Synchronization, Key-Value Pair
  Exchange, Backup and Heartbeat integration services; Shutdown stays on, and the reference TSC
  page still gives the guest host-paced time), a pipe path on COM2, automatic checkpoints, and any
  existing checkpoint.
- **Guest sizing bounds and the free-RAM gate**: the loader bounds `Memory` (`512MB` to `64GB`)
  and `Cpu` (1 to 32) for every tier and workload, and `New-SandboxVM` refuses, before it creates
  anything, to start a guest whose memory plus a margin (default 2GB) does not fit in the host's
  free RAM. An unreadable host is refused too. This is a resource guard for the host, not a
  containment boundary.

---

## 2. P1–P10 containment rubric (the acceptance checklist)

Each Anthropic principle → the concrete deployer control. **A tier "passes" only when its
row is green across P1–P10.** Use this as the sign-off checklist before trusting a tier.

| # | Principle | Deployer control | T0 | T1 | T2 | T3 |
|---|---|---|---|---|---|---|
| **P1** | Supervise **capability**, not behavior | the tier model itself — match isolation strength to task risk | ✅ | ✅ | ✅ | ✅ |
| **P2** | **Default-deny egress** | allowlist (T0/T1) / **no NIC** (T2/T3) | ✅ offline, no NIC: the seal removes the default adapter and `Assert-Sealed` host-verifies zero adapters (`Get-SealNicPolicy` returns `NoAdapter` for Tier 0); the declared `HostProxy` mode has nothing to act on without an adapter, tier0's `EgressAllowlist` is empty, and opt-in net steps escalate to Tier 1 | ✅ host-enforced allowlist (`HostProxy`: host CONNECT proxy, host firewall rules and a port ACL, verified by `Assert-Sealed`; no route, NAT or resolver in the guest); mock-green, not yet live-exercised | ✅ no NIC | ✅ no NIC |
| **P3** | **Provenance proxy** (request attribution) | Phase-1B (v1 = FQDN + TLS-terminate; provenance deferred with credentials) | ➖ deferred | ➖ deferred | n/a (no egress) | n/a (no egress) |
| **P4** | **Credentials out of env** | injected-at-proxy (T0) / starved (T2/T3); never `-e`, file bind-mount only | ✅ | ✅ default-none | ✅ none | ✅ none |
| **P5** | **Least privilege** | non-root run-user, read-only code mounts, **secret-file refusal** | ✅ | ✅ | ✅ | ✅ |
| **P6** | **Ephemeral** | lifecycle per tier (`--rm` / snapshot-revert / create-destroy / detonate-wipe) | ✅ | ✅ | ✅ | ✅ |
| **P7** | **Battle-tested primitive** | Hyper-V (not a custom hypervisor) + container runtime | ✅ | ✅ | ✅ | ✅ |
| **P8** | **Out-of-band logging** | host/hypervisor-side capture; **never trust the in-guest trace** | ✅ proxy log | ✅ proxy + host telemetry | ✅ host capture only | ✅ host/hypervisor forensic review of outputs only |
| **P9** | **Human-in-the-loop**, sized to risk | extraction-gate at T2/T3; **absolute** at T3 | ➖ low risk | ➖ low risk | ✅ extraction gate | ✅ absolute gate |
| **P10** | **One-way flow + late trust** | import-one-way (read-only ISO) / extract-one-way (host-read or cold-VHDX/CDR); defer-trust + symlink-guard in guest bootstrap | ✅ | ✅ | ✅ | ✅ |

Legend: ✅ implemented & exercised · 🛡️ implemented in mock only (SHAPE-asserted, not
live-exercised) as **defense-in-depth**, not this tier's structural boundary · ➖ deferred /
not-applicable-at-this-tier · (T2/T3 are scaffolded + benign-dry-run only in v1 — the
controls are coded and validated against benign inputs; **no live untrusted artifact runs**
until verified-isolation green-light).

### The two one-way boundaries (P10)

- **Import (one-way IN):** provision on an Internal/NAT switch → stage packages/assets
  (read-only ISO, large transfer-VHDX attach→copy→**scripted detach**) → hash/sig verify
  in-guest → checkpoint golden → **seal**. Small/known-good = read-only ISO; large =
  transfer-VHDX (not inherently one-way → scripted detach).
  **Not built in v1:** `Invoke-Voidseal` never boots the guest before the seal, so nothing is staged
  into it this way; a `StageAssets` ISO is attached and then ejected before the guest's only boot.
  The only file channel that reaches a running workload is Disk mode's INPUT disk (`Inputs`).
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
**Scaffolded in v1 — not armed.**

---

## 4. Quick "which tier?" guide

- **Trusted code/data, operating on copies, needs the net or not** → **Tier 0** (container, fast).
- **An agent loop or organizer you trust, that needs a *restricted* allowlisted net** → **Tier 1** (net-restricted VM; host-enforced allowlist egress, mock-green and not yet live-exercised; see the Egress note above).
- **A semi-trusted artifact you want to analyze with no net** → **Tier 2** (disposable no-net) — *scaffold only in v1.*
- **Presumed-hostile / malware, full airgap + detonation** → **Tier 3** — *scaffold only in v1; live detonation is gated behind explicit operator approval + verified isolation.*

When in doubt, pick the **higher** tier — over-isolation costs a little speed; under-isolation
costs the host.
