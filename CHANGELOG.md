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
- Live acceptance status: the **Tier-0 `firefox` disk round-trip ran end-to-end on real Hyper-V**,
  first with the legacy exFAT OUTPUT disk (2026-06-25) and then with the current user-space outbox
  transport (2026-07-21). The **Tier-1 `ralph` live run is still pending** (operator-run, elevated; see
  `docs/live-smoke-test.md`). Tier 2 and Tier 3 are scaffold-only and have had no live run.
- Guest sizing and a host free-RAM gate: a workload profile may set `Memory` and `Cpu` (bounded to
  512MB..64GB and 1..32 at load, for tiers and workloads alike) plus optional `CpuMaximumPercent` and
  `CpuRelativeWeight` caps that reach `Set-VMProcessor`. `New-SandboxVM` refuses, before it creates
  anything, when the host's free RAM is below the guest's memory plus `-HostMemoryMarginBytes` (default
  2GB) or cannot be read. Backend additions: `SetProcessor` `Maximum`/`RelativeWeight` and
  `GetHostMemory`.
- Configurable sandbox storage root: `-StorageRoot` on `Invoke-Voidseal`, `Invoke-BuilderVM` and
  `New-SandboxVM`, then the `VOIDSEAL_STORAGE_ROOT` environment variable, then the existing
  `%ProgramData%\Voidseal\sandboxes` default. The root must be an absolute local path (relative, UNC and
  device paths are refused before anything is created), and every disk of a run lands under it.
- Workload deadline from a profile: a workload may set `WorkloadTimeoutSeconds` (60 to 86400).
  `-WorkloadTimeoutSeconds` on `Invoke-Voidseal` and `Invoke-BuilderVM` wins only when explicitly passed,
  then the profile key, then 600.
