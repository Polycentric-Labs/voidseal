# Changelog

## How this was built

Every Hyper-V call goes through one seam with a real factory and a fake factory that share a
manifest-enforced method set, so the whole engine is unit-tested with no elevation and no real VM
(909 Pester tests (907 passed, 2 skipped), plus 56 pytest tests for the guest and host helpers). The recurring failure mode
that design guards against, a fake that accepts what real Hyper-V rejects, is treated as the first
bug class to rule out.

The workload path passes inputs and outputs on attached data disks rather than over a live
host-to-guest channel: the guest self-powers-off and the host classifies the run from what it reads
back off the detached disk. That works identically at every tier, including fully air-gapped.

`CONTRIBUTING.md` and `AGENTS.md` carry the discipline that follows from that design.
`SECURITY.md` and `docs/threat-model.md` carry what it does and does not guarantee, including the
places where a check is an argument rather than a measurement.

## Unreleased

- Initial public-ready cut: risk-tiered engine (Tier 0/1 mock-proven), host-verified fail-closed seal
  gate, disk-passing workload model, cold-VHDX to quarantine routing (the Tier >= 2 sink is a
  `NotImplemented` stub in v1), four example profiles (`firefox`, `ralph`, `builder`,
  `example-skeleton`), full Pester and pytest suites.
- Sensitivity Gate: an offline screener plus a host-side regenerator that partitions extracted
  artifacts into released and held, with enum-only verdicts that hold anything not provably safe.
- Release Governor: a per-profile per-day release rate cap backed by an append-only ledger.
- Tier-1 builder VM and the `builder` profile; `Get-VoidsealGoldenImage.ps1` and
  `Test-VoidsealPrereqs.ps1`; the user-space outbox transport for Raw OUTPUT disks.
- Seal network-adapter policy: one predicate (`Get-SealNicPolicy`) now drives the Provisioner,
  `Lock-Sandbox` and `Assert-Sealed`. Tier 0, Tier >= 2 and every `Network='None'` processor seal with
  zero adapters, host-verified. The processor check previously read a descriptor field production never
  wrote, so it could not fire, and a Tier-1 processor was certified with a connected NIC. The gate also
  refuses any GPU partition adapter or Discrete Device Assignment device at every tier, and the fake
  backend now models the default adapter real `New-VM` creates. Not yet exercised live.
- Seal coverage: `Lock-Sandbox` now also turns off the Time Synchronization, Key-Value Pair Exchange,
  Backup (VSS) and Heartbeat integration services, and `Assert-Sealed` reads each back from the host,
  matched by component GUID rather than the localized display name, refusing when one is on or
  unreadable. Shutdown stays on because the engine's `StopVM` calls ask the guest to shut down through
  it, and disabling Time Synchronization does not stop the guest reading the host-paced reference TSC
  page. The gate also refuses a pipe path on COM2, automatic checkpoints, and any existing checkpoint;
  the new `GetAutomaticCheckpoints` read backs the last two, and `GetComPort` now throws on a failed read
  instead of returning "no port". Not yet exercised live.
- Seal fixes from a review of the network-adapter policy: a Tier-1 NIC must now be the VM's only NIC and
  sit on the switch `New-SandboxVM` recorded for it, so a NIC re-pointed at another Internal switch no
  longer certifies; a network-adapter read that returns nothing refuses instead of certifying at Tier 1;
  the Tier-1 allow-list matches only the exact `Internal+Allowlist` label and refuses any other Tier-1
  label; and `Get-SealNicPolicy` moved to `scripts/lib/SealPolicy.ps1` so the Sealer loads without the
  Provisioner.
- Live acceptance status: the **Tier-0 `firefox` disk round-trip ran end-to-end on real Hyper-V**,
  first with the legacy exFAT OUTPUT disk (2026-06-25) and then with the current user-space outbox
  transport (2026-07-21). The **Tier-1 `ralph` live run is still pending** (operator-run, elevated; see
  `docs/live-smoke-test.md`). Tier 2 and Tier 3 are scaffold-only and have had no live run.
