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
unreachable unless that certification returns true. Higher tiers additionally **starve** the guest of
network and credentials at load time (refused if a Tier ≥ 2 profile declares any), and route hostile
output through a one-way cold-disk quarantine boundary rather than a trusting host read.

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
  `name` and `sha256`, which the host independently re-derives and re-checks rather than trusting.
  There is no path in this schema for a producer to smuggle an arbitrary string through.
- The host **validates every verdict against that exact closed schema** before trusting it — an unknown
  key, an out-of-enum value, an off-vocabulary flag, or a malformed hash is rejected outright (routed to
  `held/`, never released), never coerced or partially accepted.
- The host **re-hashes each candidate file immediately before release** and releases only if the current
  bytes match the verdict's own `sha256` — this closes the window between when the file was screened and
  when it is copied out.
- The released report is **regenerated from scratch by the host** from the validated fields — the
  guest's `verdicts.json` is never copied into the released report verbatim, and the released entries
  themselves carry only `name` + a host-recomputed `sha256` (the `verdict`/`error_code`/`flags` enum
  fields stay on the `held/`-side audit trail; they never ride on the released surface at all). The
  `run_id` stamped on the report is a fresh host-generated GUID, never a producer-supplied value.

Because every field that reaches the released surface is either drawn from a small closed enum the host
validates, or independently recomputed by the host, the **worst-case channel capacity is computable
directly from the schema**, not from how well the detectors happen to work on benign input. That is the
honest guarantee: **policy-enforced release with a quantified covert-channel bandwidth** — a one-way,
TCB-controlled declassification channel with a bounded, published worst-case capacity, not an absolute
information barrier.

**The published bound.** Summing `log2(|enum_i|)` over the verdict schema's enum fields (Σ over
`verdict{3}`, `error_code{5}`, and `flags` as a 10-bit subset-selector over the fixed 10-tag vocabulary,
since `flags` is a *set* — any of 2¹⁰ combinations — not a single enum draw):

| Field | Domain | Bits (`log2`) |
|---|---|---|
| `verdict` | 3 values | log2(3) ≈ 1.58 |
| `error_code` | 5 values | log2(5) ≈ 2.32 |
| `flags` | subset of 10 tags (2¹⁰ combinations) | log2(2¹⁰) = 10.00 |
| **Σ per screened artifact** | | **≈ 13.9 bits** |

This ≈13.9-bit figure is the schema's *raw* declared capacity — the ceiling if the full verdict object
were ever exposed. In practice it is a conservative over-statement of the true released-surface bound,
because (per the regenerator design above) `verdict`/`error_code`/`flags` are **held-side audit fields
that never appear on the released surface at all** — the only producer-influenced degree of freedom that
actually reaches `released/` is *which* of the staged files the host accepted as `SAFE` (one bit per
staged file, bounded by the file-count backstop below), plus that file's own byte content (bounded by the
byte-budget backstop below). We publish the schema-derived ≈13.9-bit number rather than the tighter
released-surface number because it is the simpler, more conservative, and more auditable figure — it
bounds the channel even under a hypothetical future change that exposed the full verdict object on the
released side, and it is the number directly checkable against the enum sizes in `guest/screener.py`
(`VERDICT_ENUM`, `ERROR_CODE_ENUM`, `FLAG_VOCAB`) and their pinned mirror in
`scripts/lib/SensitivityGate.ps1` (`$script:VerdictSchema`). Both are covered by a drift-pinning test
(`tests/guest/test_screener.py`, `test_module_enum_constants_match_the_pinned_vocabulary_copies`) so this
number cannot silently go stale: any change to the enum sizes must update this table in the same change.

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

## Status / honesty

- The Tier-0/1 engine is **mock-proven** (400+ tests against the fake backend). A live end-to-end
  acceptance run on real Hyper-V is the operator's elevated step and is **not** yet certified here.
- **Tier 2/3 (disposable no-net / air-gapped detonation) and the cold-VHDX→quarantine extraction are
  scaffold-only** in v1 (the quarantine sink throws `NotImplemented`). No live malware or untrusted-plugin
  detonation should be run until verified isolation is in place.
- Tier-1 egress is an **in-guest** control (acceptable for Tier-1's trusted workloads); it is not a
  host-enforced firewall in v1.

Do not rely on Voidseal as your sole boundary for genuinely hostile code until the higher tiers are
completed and you have independently verified the isolation on your host.

## Reporting a vulnerability

Please open a GitHub issue for non-sensitive reports. For anything that could weaken containment in a way
that shouldn't be public yet, contact the maintainer privately via the email on the GitHub profile rather
than filing a public issue.
