# Changelog

## How this was built

Every Hyper-V call goes through one seam with a real factory and a fake factory that share a
manifest-enforced method set, so the whole engine is unit-tested with no elevation and no real VM
(1519 Pester tests (1517 passed, 2 skipped), plus 185 pytest tests for the guest and host helpers). The recurring failure mode
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
- Builder verdict without a host mount: `Invoke-BuilderVM` no longer reads `result.exitcode` and
  `deps-manifest.json` off the guest-written exFAT deps disk with `ReadVhdxFile` (a read-write
  `Mount-VHD`). The builder gains a second, small Raw verdict disk, sized to the outbox bounds and
  recorded as a run-created disk; the guest packs the two entries into it with the existing outbox
  producer, picks it out as the only whole disk with no partition table and no file system signature,
  and the host reads it with the same user-space outbox reader as every other OUTPUT read. The rules are
  unchanged (exit code exactly `0` and a non-empty manifest for Success, otherwise `FetchFailed`); a
  test pins that `BuilderVM.ps1` never calls `ReadVhdxFile`, `ReadVhdxFileBytes` or `Mount-VHD`. The
  fake backend gains `-SimulateVerdictBlob`. Not yet exercised live.
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
- The entrypoint's exit code now reaches the host for an outbox run. The in-guest runner passes the code it
  captured to `run_disk_workload.py --workload-rc`, which records it in the outbox container as a small
  fixed-name `workload.json` entry (`{"exit_code": N}`, N an integer in 0..255, at most 64 bytes; the container
  format and its bounds are otherwise unchanged, and `verdicts.json` plus `workload.json` now both count toward
  the 256-entry limit). `guest/outbox.py` validates it on both sides, `host/read_outbox.py` hands it to the
  orchestrator as `<out>/workload.json` and never treats it as a candidate, and a staged file may not use the
  name. When the code is non-zero a transport-only run reports `RunResult.Status = 'WorkloadFailed'` with
  `ExitCode` set and releases nothing, where it used to report only a missing `result.html` candidate; a
  processor run still runs its gate exactly as before and reports the same status. A zero code is reported as
  `ExitCode = 0` on success, and an outbox with no recorded code (an older producer) keeps the old success
  behavior with `ExitCode` null. A malformed entry fails the whole read closed, and no message echoes staged
  content.
- Host-enforced Tier-1 egress (`EgressMode='HostProxy'`, now what `tier1.psd1` and so `ralph` use): the
  guest gets one static address in a per-VM /30 (`10.231.0.0/16`, chosen from the VM name; an overlap
  with a host address or NAT network refuses the provision) and no route, NAT or resolver. The host puts
  the gateway address on the VM switch's vEthernet adapter, adds firewall rules on that interface and a
  port ACL on the VM's NIC that leave only TCP from the guest to the proxy port open, and runs
  `scripts/egress/voidseal_egress_proxy.py` there: a standard-library CONNECT proxy that tunnels only
  `<name>:443` for names on the merged `EgressAllowlist`, resolves names itself, refuses answers with
  private or otherwise non-global addresses, and logs one JSON line per connection (never payload) to
  `egress-proxy.log` in the run folder (`report.EgressProxyLog`). `Assert-Sealed` refuses unless the
  gateway address, rules and ACL entries are on the host exactly as recorded and no NAT covers the
  subnet; the proxy starts after the gate and before the guest boots; teardown removes exactly what was
  recorded and reports what it could not. Twelve new backend methods (manifest, real, fake), with the
  real bodies pinned by an out-of-process capture harness. The seed writes a `network-config`, the proxy
  settings, and an in-guest default-DROP that allows only the proxy port. `InGuestSquid` still works for
  a tier that sets it; the builder keeps `SquidSniProxy`. Mock-green only: the first elevated run follows
  `docs/phase-6-live-runbook.md` section 2, which this replaces (no host Squid, no NAT).
- Profile schema: `InputDiskSizeBytes` and `OutputDiskSizeBytes` (data-disk sizes, integers from 64MB to
  2TB, default 1GB each) and `DepsImageHash` (64 hex characters, either case) are now schema keys that
  layer from a workload profile. The engine already read all three from the resolved profile, but the
  unknown-key refusal rejected them at load, so a profile could not set them. Out-of-range sizes and
  malformed hashes are refused at load. Documented in `tier-profiles/SCHEMA.md`.
- Host egress firewall rules now live in the active store like the gateway address, so a crash cannot
  leave rules behind that outlive the address they guard (`New-NetFirewallRule`, and the reads and
  removals, use `-PolicyStore ActiveStore`). `Install-SandboxEgressNetwork` also refuses, before it
  creates anything, when any of the seven `Voidseal-egress-<vm>-*` rules already exists, naming them and
  the removal command. New backend read `GetHostFirewallRuleNames` (manifest, real, fake, parity). Not yet
  run live: the first elevated run must confirm the cmdlet accepts the store
  (`docs/phase-6-live-runbook.md` section 2).
- A Disk-mode workload on a VM that keeps its NIC under `EgressMode='HostProxy'` is now refused by an
  `Invoke-Voidseal` preflight, before anything is created. Previously only the seed builder refused it,
  after the system, INPUT and OUTPUT disks had been created and copied; that check stays as a backstop.
- The seal gate now compares each host firewall rule with its record as parsed address and port sets
  (single addresses, ranges, prefixes, IPv6 in any form, any list order, split or merged ranges), not as
  text, since how Windows renders them was unproven. An address or port the parser cannot read exactly
  (for example `LocalSubnet`, a scope id, or `RPC`) refuses the seal, naming the rule. Added to the
  Phase-6 live checks: readback equals record for all seven rules.
