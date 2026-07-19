# Voidseal — Threat Model & Scoped Claims

> What Voidseal actually claims to defend against, per tier, and what it explicitly does not — modeled on
> gVisor's `SECURITY.md` (an attacker-prerequisite ladder crossed with a per-surface scope table) and
> bubblewrap's component-vs-product boundary statement. Companion to [`SECURITY.md`](../SECURITY.md) (the
> pointer + the covert-channel/qemu-img risk writeups), [`tier-reference.md`](tier-reference.md) (the tier
> model + P1–P10 rubric), and [`phase-6-live-runbook.md`](phase-6-live-runbook.md) (what Phase 6 adds,
> live, on top of everything described here). Every "IN SCOPE" row below names the exact gate in
> `scripts/lib/Sealer.ps1` or `scripts/lib/ProfileLoader.ps1` that a bug would have to defeat — if you find
> a claim here that doesn't trace to real code, that's a documentation bug; file it.

---

## 1. The claimed boundary (component, not product)

Voidseal's security claim is narrow and specific: the **host-verified, fail-closed `Assert-Sealed` gate**
(`scripts/lib/Sealer.ps1`) — a host-side proof, taken independently of anything the guest reports about
itself, that a VM has been starved of the capabilities its tier says it must not have (network adapters,
host↔guest channels, residual/secret disks, import media) **before** any untrusted workload is allowed to
run — plus the tier isolation that gate verifies (no-NIC at Tier ≥ 2, isolated-Internal-vSwitch at Tier 1).

What a workload **does once sealed and running** — whether its own logic is correct, whether it handles the
data it's given safely, whether an agent loop it drives goes off the rails — is **not** something Voidseal
guarantees. That is the calling profile's own model, the same way bubblewrap states plainly that it is a
low-level sandboxing component whose caller must supply the rest of the security posture, not a complete
sandboxing product on its own. Voidseal supervises **capability** (what the guest *can* reach), never
**behavior** (what the guest *chooses* to do with what it can reach) — this is the P1 design principle in
`tier-reference.md`, and it is also exactly where this document's scope line falls: a bug that lets a
workload defeat `Assert-Sealed` or escape its tier's isolation is a Voidseal defect; a workload that
behaves badly *inside* the capability envelope Voidseal actually gave it is not.

---

## 2. Attacker-prerequisite ladder

Scoped to Voidseal, gVisor-style (each rung names a starting capability, not a specific exploit):

| Rung | What the attacker already has | Voidseal's stance |
|---|---|---|
| **Remote** | No local presence at all — only whatever a sealed VM's tier lets its workload reach outbound (e.g. a malicious response served to an allowlisted fetch). | Folds into **GuestUser** below the moment the workload acts on it — Voidseal's design (P1) assumes every workload is a *possible* prompt-injectable insider from the start, so it does not need to reason separately about how a Remote attacker got in. |
| **GuestUser** | Arbitrary code execution inside the guest as the sandboxed, non-root run-user. | **The assumed baseline.** Every tier's isolation is designed against this starting point. |
| **GuestRoot** | Root/Administrator inside the guest. | Still assumed possible; this is the level at which any *in-guest* control (iptables, Squid, the ESM facets) is attacker-controlled and can be disabled — see the Tier-1 egress row below. |
| **MaliciousProfile** | No guest code-execution needed — the attack is at profile-authoring time: a crafted `.psd1` tries to smuggle a secret mount, weaken Tier ≥ 2 starvation, widen a builder allowlist, or downgrade `EgressMode`. | **In scope.** `ProfileLoader.ps1`'s `Assert-TierProfileValid` (run on every tier profile and every merged workload) is Voidseal's answer to exactly this rung. |
| **HostOperatorMisconfig** | The human running Voidseal makes an operational mistake — an unpatched host below the Hyper-V CVE floor, elevation granted more broadly than intended, a golden disk pointed at the wrong image. | **Out of scope**, by definition: this is a process/documentation problem, not a code defect, and no automated check can substitute for the operator reading `docs/operator-runbook.md` §0. |
| **HostRoot** | Administrator on the physical host itself, or a Hyper-V hypervisor-boundary compromise (a VM-escape 0-day). | **Out of scope for any sandbox tool.** If the attacker already owns the substrate underneath Voidseal, the sandbox boundary built on top of it is moot — the same floor gVisor, Kata, and Docker's own security model all draw under the host kernel/hypervisor they sit on. |

---

## 3. Per-tier scoped-claims table

Legend: 🟢 **IN SCOPE** (a bug here is a Voidseal defect — see the gate named below the table) · 🟡
**KNOWN LIMITATION, TRACKED** (a real, named gap; not yet closed) · ⚪ **OUT OF SCOPE / HOST MISCONFIG** · ➖
**N/A** (the class doesn't apply at this tier — e.g. no route exists to filter).

| Threat class | T0 | T1 | T2 | T3 |
|---|---|---|---|---|
| **VM-escape** (guest breaks the Hyper-V hypervisor boundary itself) | ⚪ | ⚪ | ⚪ | ⚪ |
| **Live NIC / egress route present at seal time** | 🟡 not host-verified for a non-processor profile | 🟢 must be an isolated Internal vSwitch, Default Switch refused by name | 🟢 zero NICs required | 🟢 zero NICs required |
| **Egress filtering** (which destinations are reachable through whatever route exists) | 🟡 declared, not implemented | 🟡 in-guest defense-in-depth only, GuestRoot-disableable | ➖ no route exists | ➖ no route exists |
| **Host↔guest channel left ON** (clipboard / shares / guest-services / enhanced-session) | 🟢 | 🟢 | 🟢 | 🟢 |
| **Residual / import / secret-shaped disk left attached** | 🟢 best-effort backstop | 🟢 best-effort backstop | 🟢 structural, authoritative | 🟢 structural, authoritative |
| **Malicious/malformed profile bypassing load-time invariants** | 🟢 | 🟢 | 🟢 | 🟢 |
| **Hostile-output extraction / quarantine** | ➖ not a presumed-hostile tier | ➖ not a presumed-hostile tier | 🟡 designed in scope; sink is a scaffold | 🟡 designed in scope; sink is a scaffold |
| **Host operator error** (unpatched host, wrong parent disk, elevation misuse, etc.) | ⚪ | ⚪ | ⚪ | ⚪ |

### Gate traceability, by class

**VM-escape.** Voidseal orchestrates Hyper-V; it does not implement a hypervisor. A guest that breaks the
VM boundary via a Hyper-V bug is a Hyper-V vulnerability, not a Voidseal defect — the same distinction
bubblewrap draws for the Linux kernel primitives it wraps. Keeping the host patched to the CVE floor
(`docs/operator-runbook.md` §0.2) is the operator's job; Voidseal cannot check whether the physical host
itself is patched.

**Live NIC / egress route present at seal time.**
- **T2/T3 — IN SCOPE.** `Assert-Sealed` requires the backend's `GetNetworkAdapter` call to return zero
  adapters for any Tier ≥ 2 VM, and — separately — for any "processor" profile (`Network='None'`) at *any*
  tier. A live NIC found at certify time throws and refuses to seal.
- **T1 — IN SCOPE, narrower.** Tier 1 legitimately keeps a NIC (net-restricted, not no-net).
  `Assert-Sealed`'s Tier-1 block requires that NIC's vSwitch to host-verify as `SwitchType='Internal'`, and
  separately refuses the built-in "Default Switch" **by name** (that switch is itself
  `SwitchType=Internal`, so the type check alone cannot distinguish it from a purpose-built isolated
  switch). A Tier-1 VM certified on an External/Private switch, or on the Default Switch, is a Voidseal
  defect. *(A Tier-1 profile that is itself a "processor" skips this switch check and instead must have
  literally zero NICs — the same rule as Tier ≥ 2.)* **Known gap inside this control:** the by-name refusal
  matches only the switch's English friendly name; the GUID-based refusal
  (`c08cb7b8-9b3c-408e-8e30-5e16a3aeb444`) that would also catch a localized non-English "Default Switch"
  name is Phase-6-live, not yet shipped (`phase-6-live-runbook.md` §4).
- **T0 — KNOWN LIMITATION, TRACKED, not a currently-certified guarantee.** `Assert-Sealed`'s NIC check only
  fires when the tier is ≥ 2 or the profile is a processor. A plain Tier-0 workload profile — `firefox.psd1`
  does not set `Network='None'` — is **not** covered by this check: the seal does not verify there is no
  live NIC on a Tier-0, non-processor VM. In practice, `Provisioner.ps1` only creates a switch/NIC when a
  profile's `Substrate` is `'HyperV-Gen2'`, and Tier 0's schema `Substrate` is `'Container'`, so no NIC
  happens to be created for the shipped Tier-0 profile today — but that is a side effect of the
  container-substrate scope gap (`tier-reference.md`'s "Tier-0 substrate" accuracy note: the container
  runtime is design-intent, not wired), not a host-verified invariant. Nothing in `Assert-Sealed` would
  catch a future Tier-0 code path that *did* wire a NIC.

**Egress filtering (which destinations are reachable through an existing route).**
- **T0 — KNOWN LIMITATION.** `tier0.psd1` declares `EgressMode='HostProxy'`, but per `tier-reference.md`'s
  P2 row this host-proxy allowlist is **not yet implemented** at all — no mechanism, in-guest or host-side,
  filters Tier-0 egress today.
- **T1 — KNOWN LIMITATION, TRACKED (the worked example this document exists to fold in honestly).**
  `tier1.psd1`'s `EgressMode='InGuestSquid'` ships a real, mock-shape-asserted **in-guest** mechanism: the
  seed's iptables default-DROP OUTPUT plus a transparent Squid `dstdomain` allowlist. This is
  **defense-in-depth, not a boundary** — it runs *inside* the guest, so a GuestRoot attacker can flush its
  own iptables rules or kill its own Squid process; the untrusted principal cannot be trusted to police
  itself, by construction. The host-verified boundary — a host-run Squid SNI-splice, `New-NetNat`, and a
  host default-DROP policy on the Internal switch's gateway — is **Phase-6-live, not yet built**
  (`phase-6-live-runbook.md` §2).
- **T2/T3 — N/A.** No NIC exists once sealed (see the row above), so there is no route for a filtering
  question to apply to.

**Host↔guest channel left ON.** IN SCOPE, every tier. `Assert-Sealed` reads all four channels
(clipboard/shares/guest-services/enhanced-session) back from the host via `GetHostChannels` and fails
closed both if any channel is ON *and* if a channel's state cannot be read at all. A channel silently left
enabled after `Lock-Sandbox` runs is a Voidseal defect at any tier.

**Residual / import / secret-shaped disk left attached.** IN SCOPE, every tier, with a strength gradient
the code itself draws:
- Every tier: any attached disk matching a secret-shaped path (`Test-IsSecretPath` — the same
  single-source-of-truth pattern list `ProfileLoader.ps1` uses at load time: `.env`, `*.pem`, `*.key`,
  `~/.ssh/`, `~/.aws/credentials`, etc.) is refused, and any transfer/import medium the seal should have
  detached but didn't is refused.
- Tier ≥ 2: the **structural, authoritative** rule — the *only* disks allowed to remain attached are the
  recorded system disk and the descriptor's recorded data disks; anything else is refused as a residual,
  independent of whether it happens to be secret-shaped or recorded as import media.
- Tier 0/1: a **best-effort backstop** applies the same "not in the expected set" test, but it can only
  catch what the descriptor didn't record — it is not the authoritative guarantee Tier ≥ 2 gets.

**Malicious/malformed profile bypassing load-time invariants.** IN SCOPE, every tier — this is the
`MaliciousProfile` rung's home gate. `ProfileLoader.ps1`'s `Assert-TierProfileValid` (run on every tier
profile *and* every merged workload) refuses: a secret-shaped `Mounts` source (`Assert-NoSecretMounts`); a
Tier ≥ 2 profile that doesn't set `Credentials='None'` / `EgressMode='None'` / an empty allowlist; a Tier ≥
2 profile that doesn't use `Extraction='ColdVHDX-Quarantine-CDR'`; a `HyperV-Gen2` profile with any
`HostChannels` entry `$true`; a Linux `GuestImage` without `ManagementChannel='Com1Serial'`; a
`Network='None'` processor that still declares egress; a builder (`EgressMode='SquidSniProxy'`) profile
with no `DepsSpec`, or an allowlist that doesn't cover its fetchers' required hosts; and an
`EgressAllowlist` entry containing a character outside the safe hostname charset (the guard against
injecting directives into the Squid `dstdomain` ACL). A profile that got any of these past the loader would
be a Voidseal defect.

**Hostile-output extraction / quarantine.**
- **T0/T1 — not applicable in the adversarial sense.** `Extraction='HostReadResultDir'` is a **trusting**
  host read by design, because Tier 0/1 workloads are not presumed hostile at the output stage. (The
  separate, opt-in Sensitivity-Gate/processor path for `Network='None'` + `ScreenConfig` profiles is a
  further refinement described in `SECURITY.md`'s "Release path" section — a policy-enforced regeneration
  control, not a tier-wide guarantee, and out of scope for this table.)
- **T2/T3 — designed in scope, maturity-gated.** `ProfileLoader.ps1` refuses any Tier ≥ 2 profile that
  doesn't declare `Extraction='ColdVHDX-Quarantine-CDR'`, and `Read-WorkloadResult`
  (`scripts/lib/Workload.ps1`) refuses to direct-read a Tier ≥ 2 output disk — an undeterminable tier is
  *also* presumed hostile — routing instead to `Export-ColdVhdxQuarantine` (`scripts/lib/Runner.ps1`),
  which **throws `NotImplemented`** this round, before any read. The *design* is correctly scoped (never a
  trusting host-read of hostile output); there is simply no live path behind it yet. See §4 below — this
  row is a maturity gap, not a scope gap.

**Host operator error.** OUT OF SCOPE by definition, every tier: an unpatched Hyper-V host below the CVE
floor (`docs/operator-runbook.md` §0.2), elevation/`Hyper-V Administrators` membership misused in a way
that produces a false pass, a golden `-ParentDiskPath` pointed at the wrong image, or Hyper-V's own
hypervisor protections disabled some other way. **Necessary but not sufficient**: every check above assumes
the substrate under it is sound.

---

## 4. Maturity vs. scope (kept separate on purpose)

The table above answers *"if this happened, would it be a Voidseal bug?"* — a scope question. The list
below answers a different question, *"has this actually been exercised?"* — a maturity question. Don't
blend them: something can be correctly scoped as IN SCOPE and still be unproven live.

- **Tier 0/1 provisioning + seal:** mock-proven against a fake Hyper-V backend (700+ Pester tests, no
  elevation, no real VM). The first live end-to-end run — the live smoke test — is the operator's own
  elevated step; nothing in this document should be read as a claim that it has been exercised live.
- **Tier-1 in-guest egress:** shape-asserted only. The mock suite proves the rendered Squid config text,
  the iptables rule text, and the ACL substitution are correct — it does not prove a real Squid/iptables
  process has ever actually spliced or dropped a real packet (`phase-6-live-runbook.md` §5).
- **Tier 2/3: scaffold-only.** There is **no shipped `tier-profiles/tier2.psd1` or `tier3.psd1`** — only
  `tier0.psd1` and `tier1.psd1` exist in the repo. The Tier ≥ 2 invariants above are enforced generically
  and unit-tested against inline fixture hashtables (`tests/ProfileLoader.Tests.ps1`), but an operator
  cannot run an end-to-end Tier-2/3 workload today without first authoring their own tier file — and even
  then, the extraction sink throws `NotImplemented`. **No live untrusted-artifact detonation is possible in
  v1**, regardless of what §3 says is correctly *scoped* — maturity gates it shut entirely.
- **qemu-img confinement** (`Invoke-ConfinedQemu`, `scripts/lib/HyperVBackend.ps1`): the confinement *seam*
  is shipped and every native `qemu-img convert` call is routed through it (AST-pinned by test), but v1 is
  a pass-through — no restricted-token/Job-Object/Windows-Sandbox confinement is wired yet. See
  `SECURITY.md`'s qemu-img section and `phase-6-live-runbook.md` §3 for the full writeup.

---

## 5. Reporting

See [`SECURITY.md`](../SECURITY.md#reporting-a-vulnerability) for the reporting channel. If you found a
claim in this document that doesn't trace to the code cited, that is itself a reportable documentation bug
— open it the same way.
