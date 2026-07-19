# Security

Voidseal is a defensive containment tool. Its design goal is to **supervise capability, not behavior** —
assume the code or agent inside the sandbox is a prompt-injectable insider, and make the blast radius
structurally small.

## Threat model (what Voidseal defends against)

- Untrusted code / autonomous agents / (eventually) malware running with the host's network, credentials,
  or filesystem in reach.
- A guest that misbehaves, is compromised, or lies about its own state.

The core control is the **host-verified, fail-closed seal gate** (`Assert-Sealed`): after isolation is
cut, the **host** (never the guest's self-report) certifies the VM has no network adapter, no credential
volume, no residual transfer medium, and no live host↔guest channel — and the workload is structurally
unreachable unless that certification returns true. For a Tier-1 VM, which legitimately keeps a NIC
(net-restricted, not no-net), the seal instead certifies that NIC's vSwitch is an isolated **Internal**
switch — never an unfiltered External or Private switch — so the guest's only possible route off-box is
the host-controlled gateway on that Internal switch. That is a host-verified **switch-isolation**
guarantee (reachability) for a **purpose-built** Internal switch, not a claim about which domains/IPs the
guest can reach once on that route — see "Tier-1 egress" below for why the two are not the same thing.
**Caveat:** the built-in "Default Switch" is itself `SwitchType=Internal` (it is Hyper-V's ICS/internet-
connected switch, not a purpose-built isolated one), so the SwitchType check alone cannot distinguish it
from a purpose-built isolated switch — but the seal now ALSO refuses it explicitly **by name**, so a
Default-Switch-connected NIC is refused, not certified. Real Tier-1 provisioning uses a purpose-built
Internal switch, never the Default Switch. **This by-name match is the switch's ENGLISH friendly name**
("Default Switch"); on a non-English/localized Windows host the friendly name differs, so the by-name
refusal does not fire there — the locale-independent guarantee is the immutable-GUID refusal
(`c08cb7b8-9b3c-408e-8e30-5e16a3aeb444`), which is Phase-6-live, not yet shipped. Host egress **filtering**
(Squid SNI-splice / `New-NetNat` / default-DROP) remains Phase-6-live (see "Tier-1 egress" below) — switch
isolation and by-name refusal are reachability controls, not a claim that egress is filtered. Higher tiers
additionally **starve** the guest of network and credentials at load time (refused if a Tier ≥ 2 profile
declares any), and route hostile output through a one-way cold-disk quarantine boundary rather than a
trusting host read.

## Release path (processor tier): policy-enforced release, not an information barrier

The **processor** profile tier (`Network='None'` AND a `ScreenConfig`) is the one place Voidseal moves
guest-produced content back to the host: an in-guest screener (`guest/screener.py`) evaluates each
artifact and a host-side gate (`Invoke-SensitivityGate`, `scripts/lib/SensitivityGate.ps1`) partitions
the result into `released/` (host-approved) and `held/` (everything else). Firefox (Tier-0, transport-
only) is a separate, unscreened path — see the note at the end of this section.

**What this control is not.** An earlier design implicitly framed the screener as an *information-level
data diode* — as if a passing "SAFE" verdict meant the released bytes were provably free of adversary-
chosen content. That framing over-claims. An offline content screen cannot give an information-theoretic
bound against a producer that fully controls what it emits: this is the classical Lampson/TCSEC covert-
channel result, and it is sharpened by modern provably-secure generative linguistic steganography, which
shows that ordinary-looking "clean" prose can carry attacker-chosen bits with no statistical tell a
detector could catch. No amount of tuning the screener's detectors closes that gap, because detection
accuracy on benign inputs says nothing about a worst-case adversarial input.

**What this control actually is.** Voidseal does not rely on detection to bound leakage — it relies on
**regeneration**. The host is the sole author of everything on the released surface:

- The screener emits an **enum-only verdict** with zero free-form fields: `verdict` ∈
  `{SAFE, HELD, ERROR}` (3), `error_code` ∈ `{NONE, EXTRACT_FAIL, OFF_SCHEMA, DETECTOR_ERROR,
  UNSUPPORTED}` (5), and `flags` — a subset of a fixed 10-tag detector vocabulary (`aws_key`,
  `credential`, `email`, `entropy`, `financial`, `health`, `other`, `pii`, `secret`, `ssn`) — plus
  `name` and `sha256`. `sha256` is independently re-derived and re-checked by the host rather than
  trusted (the host re-hashes the staged bytes and compares; a producer-claimed hash that doesn't
  match the real bytes never releases). `name` is validated against a fixed 40-character
  `[A-Za-z0-9._-]` charset (a violating name is rejected as off-schema — `held/`, never released) —
  but even a charset-confined guest name is **never itself released**: see the name-regeneration
  point below, which is what keeps `name` off the published bound entirely.
- The host **validates every verdict against that exact closed schema** before trusting it — an unknown
  key, an out-of-enum value, an off-vocabulary flag, an array-typed field where a scalar is expected,
  a name outside the 40-char restricted alphabet, or a malformed hash is rejected outright (routed to
  `held/`, never released), never coerced or partially accepted.
- The host **re-hashes each candidate file immediately before release** and releases only if the current
  bytes match the verdict's own `sha256` — this closes the window between when the file was screened and
  when it is copied out.
- The released report is **regenerated from scratch by the host** from the validated fields — the
  guest's `verdicts.json` is never copied into the released report verbatim, and the released entries
  themselves carry only `name` + a host-recomputed `sha256` (the `verdict`/`error_code`/`flags` enum
  fields stay on the `held/`-side audit trail; they never ride on the released surface at all). The
  `run_id` stamped on the report is a fresh host-generated GUID, never a producer-supplied value.
- **The released filename is host-regenerated, not the producer's name** (`scripts/lib/SensitivityGate.ps1`,
  `Get-ReleasedName`). Even confined to the 40-char restricted alphabet, a producer-chosen name is still
  a real channel — the same regeneration argument that applies to file *content* applies to the name,
  since detection/charset-capping cannot bound a worst-case adversarial string any more than a screener
  can bound worst-case adversarial bytes. So `released[].name` (and the in-memory `.Released` returned to
  `Invoke-Voidseal`'s caller) is **always the host-recomputed `sha256` of the released bytes** — a value
  the producer does not choose and cannot influence — never the guest's original filename. The original
  guest-chosen name is preserved *only* in the regenerated report's `released_audit` array
  (`{released_name, original_name, sha256}`, written to `manifest/sensitivity-report.json` alongside the
  retained verbatim `manifest/verdicts.json` audit copy) so an operator can still recover which released
  file is which — but that mapping never rides on `released/` or `.Released`. This closes the name channel
  to **zero** producer-influenced bits on the released surface.

Because every field that reaches the released surface is either drawn from a small closed enum the host
validates, or independently recomputed by the host (both the byte-content `sha256` and, as of the
host-name-regeneration hardening above, the filename itself), the **worst-case channel capacity is
computable directly from the schema**, not from how well the detectors happen to work on benign input.
That is the honest guarantee: **policy-enforced release with a quantified covert-channel bandwidth** — a
one-way, TCB-controlled declassification channel with a bounded, published worst-case capacity, not an
absolute information barrier.

**The published bound.** Summing `log2(|enum_i|)` over the verdict schema's enum fields (Σ over
`verdict{3}`, `error_code{5}`, and `flags` as a 10-bit subset-selector over the fixed 10-tag vocabulary,
since `flags` is a *set* — any of 2¹⁰ combinations — not a single enum draw):

| Field | Domain | Bits (`log2`) |
|---|---|---|
| `verdict` | 3 values | log2(3) ≈ 1.58 |
| `error_code` | 5 values | log2(5) ≈ 2.32 |
| `flags` | subset of 10 tags (2¹⁰ combinations) | log2(2¹⁰) = 10.00 |
| **Σ per screened artifact** | | **≈ 13.9 bits** |

`name` is **not** in this table: an earlier draft of this document counted a ≈240.9-bit worst-case
channel for `name` (40 chars × log2(65), the charset-capped-but-still-producer-chosen name riding
verbatim onto `released[].name`) — that was the correct bound *for the design at the time*, but it is no
longer the design. The released filename is now host-regenerated (see the name-regeneration point above):
the producer's name never reaches `released[].name` in any form, charset-capped or otherwise, so it
contributes exactly **0 bits** to the released surface today. `verdict`/`error_code`/`flags` are
genuinely held-side audit fields that never ride on `released/` at all (see the regenerator design above)
— their ≈13.9 bits are a ceiling for a hypothetical future schema change that put them on the released
surface, not bits an attacker can use today; the honest current bound on the released surface's
*enumerable* fields is 0 bits (the `name` field is host-derived; no other free field rides on
`released[]`). The remaining producer-influenced degrees of freedom that reach `released/` are: (1)
*which* of the staged files the host accepted as `SAFE` (one bit per staged file, bounded by the
file-count backstop below), and (2) each released file's own byte content (bounded by the byte-budget
backstop below) — filename is no longer one of them. The enum sizes are directly checkable against
`guest/screener.py` (`VERDICT_ENUM`, `ERROR_CODE_ENUM`, `FLAG_VOCAB`) and their pinned mirror in
`scripts/lib/SensitivityGate.ps1` (`$script:VerdictSchema`, including `NameRE`, which still gates what
name the host will even *trust* enough to hash-bind and audit-map, even though that name is never
released verbatim). Both are covered by a drift-pinning test (`tests/guest/test_screener.py`,
`test_module_enum_constants_match_the_pinned_vocabulary_copies`) so this number cannot silently go stale:
any change to the enum sizes must update this table in the same change.

**Two aggregate backstops, independent of the per-run bound.** The per-run figure above bounds a single
processor invocation; aggregate exposure over many runs is bounded separately by two host-enforced,
fail-closed caps (`scripts/lib/SensitivityGate.ps1`, `scripts/lib/ReleaseGovernor.ps1`):

- **Released-byte budget** — a per-artifact size cap (`-MaxReleasedBytes`, default 1 MiB) and a per-run
  releasable-file-count cap (`-MaxReleasedFiles`, default 16). Anything over either cap is held, not
  released, regardless of how clean its verdict is.
- **Runs/day rate cap** — a host-side ledger (`-MaxReleasesPerDay`, default 5) keyed by profile and UTC
  calendar day. A run at or over the cap releases nothing at all — the whole candidate set is held before
  the per-file schema/re-hash checks even run. An unreadable/corrupt ledger fails the same way (denied),
  never fails open.

Together these mean total exfiltratable content across a day is bounded by `runs/day x
min(byte-budget-bound, per-run-schema-bound)` — a number that shrinks as the caps tighten, never grows.

**Scope note.** This entire section describes the **processor** release path only. The **firefox**
profile (Tier-0) is transport-only and is *not* screened by this mechanism at all: its extracted artifact
is materialized host-side verbatim from a raw, user-space disk read via the shared in-guest outbox
producer (never a kernel filesystem mount of guest-written bytes — see `docs/operator-runbook.md` for the
outbox transport detail), with no sensitivity gate in the path. Firefox's containment guarantee is the
seal + disk-passing mechanism above, not the regenerator described in this section.

## The qemu-img raw read: an undiscovered-bug-class risk, not a catalogued RCE

The user-space outbox read (`ReadVhdxRawRegion`, `scripts/lib/HyperVBackend.ps1`) never `Mount-VHD`s the
guest-written OUTPUT disk (Pass-5: even a read-only host attach runs `partmgr.sys` + filesystem-recognizer
parses against attacker-controlled bytes). Instead it runs `qemu-img convert -f vhdx -O raw` offline against
the detached `.vhdx`, then reads the flattened raw bytes with a plain `FileStream`. This closes the
kernel-filesystem-parse risk, but it opens a different one: **`qemu-img`'s own VHDX parser now runs against
those same untrusted bytes, in the host operator's own session.**

**Be precise about what this risk is.** The only catalogued QEMU VHDX-parser CVE is **CVE-2014-0148**
(a heap-overflow **denial-of-service** in the VHDX image-parsing code, fixed at **QEMU 2.0**) — over a
decade old and far below any reasonable modern floor. Framing the current risk as "the qemu-img convert is
vulnerable to a known RCE" would be a **fabricated claim**: no such catalogued RCE exists for the modern
VHDX parser. The real concern is the **undiscovered-bug class**: any offline file-format parser handling
adversary-controlled input can contain an unpatched memory-safety bug, and `qemu-img convert` runs with the
full privileges of whoever invokes it — here, the host operator.

**Mitigations, in place today or planned:**

- **A patch-currency version floor** (`Resolve-QemuImg`, `-MinVersion`) — **not** a CVE-derived gate (see
  that function's own header comment, which is explicit on this point). The floor exists so the resolver
  runs a *currently patched* `qemu-img`, re-resolved and bumped periodically; it is not a claim that a
  specific CVE is fixed at exactly that version.
- **A SHA-256 pin of the qemu-img binary** (`Resolve-QemuImg -PinnedSha256`, optional) — refuses to run an
  unpinned or substituted parser binary when a pin is configured.
- **Per-tier confinement of the convert itself** (`Invoke-ConfinedQemu`, `scripts/lib/HyperVBackend.ps1`) —
  every native `qemu-img convert` invocation is routed through a single confinement seam rather than called
  directly. **v1 (shipped) is a pass-through** — the seam exists and every call site is routed through it
  (AST-pinned by test, non-vacuously), but the actual confinement mechanism is **not yet wired**: a
  restricted-token/Job-Object shim for Tier-0/1 (drop privileges + cap resources on the child `qemu-img`
  process) or a Windows Sandbox for Tier-2/3 (full OS-level confinement for the disposable/detonation
  tiers). **The real confinement mechanism is built and live-proven at Phase 6** — until then, treat the
  convert step as running with full host-operator privileges, mitigated only by the version floor and
  binary pin above.

## Status / honesty

- The Tier-0/1 engine is **mock-proven** (700+ tests against the fake backend). A live end-to-end
  acceptance run on real Hyper-V is the operator's elevated step and is **not** yet certified here.
- **Tier 2/3 (disposable no-net / air-gapped detonation) and the cold-VHDX→quarantine extraction are
  scaffold-only** in v1 (the quarantine sink throws `NotImplemented`). No live malware or untrusted-plugin
  detonation should be run until verified isolation is in place.
- **Tier-1 egress filtering is in-guest today, and an in-guest control is not a containment boundary.**
  The builder seed's iptables default-DROP-plus-allowlist and the in-guest Squid SNI proxy run *inside*
  the VM whose workload they're supposed to constrain. A guest with code-execution can flush its own
  `iptables` rules or kill its own Squid process — the untrusted principal cannot be trusted to police
  itself, by construction. Treat these in-guest rules as defense-in-depth (they raise the bar for an
  unsophisticated or non-adversarial workload) — not as the security boundary.
  - **What IS host-verified today: switch isolation, not egress filtering.** `Assert-Sealed` verifies
    (from the host, never the guest's self-report) that a Tier-1 VM's NIC sits on an isolated **Internal**
    vSwitch rather than an External or Private switch. That is a genuine host-enforced guarantee that the
    guest's only possible network path leaves through the host-controlled gateway on that Internal
    switch — an unfiltered External/Private switch is refused, fail-closed. It says nothing about *which*
    destinations are reachable through that gateway; today, nothing on the host filters what crosses it.
    **Caveat:** the built-in "Default Switch" is itself `SwitchType=Internal` (Hyper-V's ICS/internet-
    connected switch), so the SwitchType check alone cannot distinguish it from a purpose-built isolated
    Internal switch — but the seal now ALSO refuses it explicitly **by name** (host-verified, mock-tested),
    so a Default-Switch-connected NIC is refused, not certified. Real Tier-1 provisioning uses a purpose-
    built Internal switch, never the Default Switch. **This by-name match is the switch's ENGLISH friendly
    name**; on a non-English/localized Windows host the friendly name differs, so the by-name refusal does
    not fire there — the locale-independent guarantee is the immutable-GUID refusal
    (`c08cb7b8-9b3c-408e-8e30-5e16a3aeb444`), which is Phase-6-live, not yet shipped. This is still a
    reachability/isolation control, not egress filtering — see the next bullet.
  - **Egress filtering at the host is the Phase-6-live layer, not yet built.** The planned control is a
    host-run transparent Squid SNI-splice proxy plus a host-side NAT (`New-NetNat`) and a host default-DROP
    policy on the Internal switch's gateway interface — i.e. the same allow-only-what's-needed filtering
    the in-guest layer attempts today, but enforced from a position the guest cannot reach or disable.
    Until that lands, **do not read "the seal is host-verified" as "Tier-1 egress is filtered."** The seal
    verifies isolation (the guest can only reach the host gateway); it does not yet verify filtering (what
    the host gateway then permits through). See `docs/phase-6-live-runbook.md` for the full prescribed live
    sequence (host egress enforcement, qemu-img confinement, seal-time assertions to add live).

Do not rely on Voidseal as your sole boundary for genuinely hostile code until the higher tiers are
completed and you have independently verified the isolation on your host.

## Reporting a vulnerability

Please open a GitHub issue for non-sensitive reports. For anything that could weaken containment in a way
that shouldn't be public yet, contact the maintainer privately via the email on the GitHub profile rather
than filing a public issue.
