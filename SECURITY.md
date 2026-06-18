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
