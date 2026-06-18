# Changelog

## How this was built

Voidseal was developed with a deliberately adversarial process, because a containment tool that's
*almost* right is worse than useless:

- **Mockable-backend-first.** Every Hyper-V interaction goes through one seam with a real + a fake
  factory sharing a manifest-enforced method set, so the whole engine is unit-tested without elevation
  or a real VM (400+ Pester tests). The recurring failure mode it guards — "the fake accepts what real
  Hyper-V rejects" — is treated as the #1 bug class.
- **Subagent-driven development with two-stage review.** Each task was implemented, then reviewed for
  spec-compliance and for code quality before landing. The review loop caught **2 CRITICAL safety bugs**
  (seal-gate bypasses) that the happy-path tests missed.
- **A disk-passing workload model.** The first containment milestone proved the seal but the live
  serial command channel raced the guest boot; rather than paper over it, the workload path was
  redesigned to pass inputs/outputs on attached data disks with **no live host↔guest channel** — the
  guest self-powers-off and the host classifies the run from an exit-code sentinel. This works identically
  at every tier, including fully air-gapped.
- **Three independent review layers before the (pending) live acceptance.** A whole-implementation
  review, a multi-lens adversarial workflow (which independently corroborated the containment invariants
  and surfaced ~10 first-live-run reliability fixes), and a primary-source implementation-verification
  pass (exFAT mount semantics, `runuser` exit-code propagation, the PowerShell storage-cmdlet null/settle
  edge cases). Net: the mock-untestable real-backend + guest-side seams were hardened against the exact
  fake≠real defects that would otherwise have surfaced only on a costly live run.

## Unreleased

- Initial public-ready cut: risk-tiered engine (Tier 0/1 mock-proven), host-verified fail-closed seal
  gate, disk-passing workload model, cold-VHDX→quarantine routing (Tier ≥ 2 sink is a NotImplemented stub
  this round), two worked example profiles, full Pester suite.
- Live end-to-end acceptance on real Hyper-V: pending (operator-run, elevated — see
  `docs/live-smoke-test.md`).
