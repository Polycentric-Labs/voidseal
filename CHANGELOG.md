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
- Live acceptance status: the **Tier-0 `firefox` disk round-trip ran end-to-end on real Hyper-V**,
  first with the legacy exFAT OUTPUT disk (2026-06-25) and then with the current user-space outbox
  transport (2026-07-21). The **Tier-1 `ralph` live run is still pending** (operator-run, elevated; see
  `docs/live-smoke-test.md`). Tier 2 and Tier 3 are scaffold-only and have had no live run.
- Fixed: the sensitivity screener of a processor profile now runs in the guest, with `--mode` taken
  from `ScreenConfig`. The shared outbox runner had hard-coded `--transport-only`, so the producer
  packed an empty `verdicts.json` and the host gate refused every staged file; no processor run could
  release anything. `Invoke-Voidseal` also refuses a processor whose Inputs lack
  `run_disk_workload.py`, `outbox.py` or `screener.py`, before provisioning. A shared
  `Test-IsProcessorProfile` predicate keeps the guest screening and the host gating in agreement.
- Fixed: the Serial-mode seed now rides a CIDATA data disk that survives the seal, as Disk mode
  already did. It was attached as a DVD and ejected before the guest's only boot, so cloud-init never
  saw it. `Add-SandboxSeed` is removed.
- Fixed: teardown removes the per-VM `<vm>-int` Internal switch the provision created, recorded as
  `CreatedSwitches` on the descriptor. A switch that already existed and was reused is left alone.
- Fixed: the Disk runners' INPUT mount fallback arm is now `mount -o ro LABEL=INPUT`, so INPUT stays
  read-only when the kernel rejects the uid/gid options. `ro` keeps a buggy workload from rewriting
  its inputs; it is not a boundary against a hostile guest.
- Fixed: the outbox reader resolves a real Python interpreter and skips Windows App Execution Alias
  stubs, whose first launch could fail with a misleading `StandardOutputEncoding` error.
- Fixed: `Resolve-PythonExe` also refuses `.bat` and `.cmd` shims, which run through `cmd.exe` and can
  rewrite arguments. On Windows only an `.exe` is accepted; the failure message names each skipped
  alias and shim.
- Fixed: `Invoke-SensitivityGate` Run mode launches the screener with a resolved interpreter instead
  of a bare `python`. `Resolve-PythonExe` moved to `scripts/lib/PythonResolver.ps1`, and the gate takes
  an optional `-PythonExe` that defaults to it. No production caller uses Run mode; tests and manual
  host screening do.
- Fixed: the outbox helper preflight now covers transport-only `OutboxOutput` Disk profiles such as
  `firefox`. A run whose effective Inputs lack `run_disk_workload.py` or `outbox.py` is refused before
  provisioning, naming the missing files, instead of failing later as "outbox header missing".
- Docs: a profile's `Packages` list is declared but nothing installs it, `Mounts` is declared but
  moves no files, and a `StageAssets` ISO is ejected by the seal before the guest's only boot, so only
  Disk-mode `Inputs` reach a running workload. Tests pin each claim against the code, and the
  `Packages` check now matches its key without regard to case, with a planted-reader control.
- Docs: the `ralph` profile's `ExtraAllowlist` comment no longer calls `claude.ai` and
  `storage.googleapis.com` install-time only. They stay reachable for the whole sealed run, and
  `storage.googleapis.com` admits any public bucket, so it is the wider of the two.
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
- Pre-built data disks (`DataDisks`, Disk mode only): carry a directory tree, wheels or model weights
  into a sealed guest. `scripts/New-VoidsealDataDisk.ps1` builds an exFAT VHDX from a directory
  (refusing secret-shaped paths and links in the tree) through the new `CopyDirectoryToVhdx` backend
  method and prints its whole-image SHA-256. `Invoke-Voidseal` refuses bad names, paths that alias the
  storage root, the DEPS disk or the golden parent, and Serial-mode runs before provisioning; verifies
  every disk's hash before attaching any (the DEPS disk now shares that check); records them so
  `Assert-Sealed` accepts them; never deletes them at teardown; and re-hashes them afterwards, setting
  the new `DataDiskChanged` report field on any change. Both Disk-mode runners mount each disk
  read-only at `/mnt/data/<name>` and power off without running the workload if one is missing or
  writable. `Mounts` and `Packages` docs now point here. Mock-tested only; the real disk build, attach
  and re-hash have not run live.
