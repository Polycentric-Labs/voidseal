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
  run's storage root (from `-StorageRoot`, `VOIDSEAL_STORAGE_ROOT` or the default), the DEPS disk or
  the golden parent, and Serial-mode runs before provisioning. It never attaches the original: each run
  copies every data disk, and the processor's DEPS disk, into its own sandbox folder through the new
  `CopyVhdxFile` backend method, verifies each copy's hash before attaching any, and deletes the copies
  at teardown, so Hyper-V metadata updates and guest writes cannot change the original. The cost is one
  copy's worth of free space (counted in the free-space preflight) and copy time per disk per run.
  After teardown each original is re-hashed; a host-side change sets the new `DataDiskChanged` report
  field, and the new `DataDisks` report field lists each disk's name, original, verified hash, working
  copy and changed flag. Both Disk-mode runners mount each disk read-only at `/mnt/data/<name>` and
  power off without running the workload if one is missing or writable. `Mounts` and `Packages` docs
  now point here. Mock-tested only; the real disk build, copy, attach and re-hash have not run live.
- Builder verdict: `Invoke-BuilderVM` no longer reports Success for any clean power-off. After the
  guest powers off and the OUTPUT disk is detached, it reads the guest's `result.exitcode` and
  `deps-manifest.json` and reports Success only when the file reads exactly 0 and the manifest is
  present. A missing, unparsable or non-zero exit code, or a missing manifest, is the new `FetchFailed`
  status, with the reason in `Error` and the code in the new `ExitCode` field; nothing is emitted and
  teardown deletes the disk. A timeout stays `Failed`. The serial `[voidseal-diag]` markers remain the
  second source. The read is a host mount of the guest-written OUTPUT volume (`ReadVhdxFile`), the one
  the builder flow makes; `docs/threat-model.md` records the exposure. Mock-tested only.
- Fixed: the builder's `deps.vhdx` survives teardown. Teardown deletes everything the run created, and
  the finished deps disk was one of those files, so only its hash outlived a run. After the verdict, the
  disk is moved out of the sandbox folder through the new `MoveVhdxFile` backend method (manifest, real
  and fake; the real body is a plain file move with no Hyper-V cmdlet, a rename on one volume and a
  copy, rename and delete across volumes) into `-DepsOutputDir` (default `<ArtifactRoot>\deps`, as
  `deps-<Name>.vhdx`), hashed there, and returned as `DepsDiskPath` and `DepsImageHash`, ready for
  `-Workload.DepsDiskPath` and `-Workload.DepsImageHash` of a later run, which attaches a verified
  working copy of it. `-DepsDiskPath` still names an exact file. A destination inside the storage root,
  a relative or UNC path, a non-`.vhdx` name, or an existing file is refused before the build starts.
  New `-ArtifactRoot` parameter; `WholeImageHash` stays in the result as an alias of `DepsImageHash`.
- Serial seed diagnostics: the Serial baseline and Serial egress seeds now emit the same structural
  `[voidseal-diag]` markers the outbox and builder runners do (device and mount counts, serial-getty
  and package presence, Squid and IPv6 state, the lockdown's REDIRECT return codes), through the same
  `diag()` helper, so a misbehaving ralph seed can be told apart from the serial capture alone. Counts
  and yes/no facts only, never file content or workload names.
- Unknown profile keys are refused. `Import-WorkloadProfile`, `Import-TierProfile` and the hashtable
  path of `Invoke-Voidseal -Profile` now throw on any key outside the documented schema and name it
  (matched case-insensitively), where such a key used to vanish without a word: a typo, or a tier-owned
  key such as `Credentials` set from a workload. The accepted lists are built from the loader's own key
  constants (`Get-ProfileSchemaKeys`), `tier-profiles/SCHEMA.md` now documents the Disk-mode, builder
  and processor keys it had skipped (`WorkloadMode`, `Inputs`, `InputFiles`, `FileSystem`,
  `InputLabel`, `OutputLabel`, `DepsSpec`, `ScreenConfig`, `DepsDiskPath`, `OutboxOutput`), and a drift
  test fails when the file and the loader disagree in either direction. A profile that set a key the
  engine never read now fails to load.
- `ResultInnerName` is a workload-profile key, layered like `Entrypoint`: the profile value names the
  file a transport-only run releases, `-Workload.ResultInnerName` still wins, and the default stays
  `result.html`. The name must be a plain outbox file name; `verdicts.json` and `workload.json` are
  reserved.
