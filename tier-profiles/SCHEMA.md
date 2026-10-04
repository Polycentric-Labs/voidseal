# Tier-profile & profile schema (the build contract)

> This file is the **interface contract** every `Voidseal` component + every parallel build
> agent MUST target. Tier profiles (`tier{0,1,2,3}.psd1`) define the **isolation contract**;
> workload profiles (`profiles/*.psd1`) layer the **workload shape** over a base tier.

## Unknown keys are refused

Every key a profile file or a `-Profile` hashtable carries must be documented in this file: the
tier-profile table, the workload-profile table, or both. The loader (`Import-TierProfile`,
`Import-WorkloadProfile`, and the hashtable path of `Invoke-Voidseal`) throws on any other key and
names it, so a typo or a key the engine never reads cannot vanish silently. Key names match
case-insensitively, the way the loader reads them. The lists are built from the loader's own key
constants (`Get-ProfileSchemaKeys` in `scripts/lib/ProfileLoader.ps1`), and a drift test fails when this
file and the loader disagree in either direction. Where a key may appear:

* a **workload profile** may carry the keys in the workload table (plus `BaseTier` and `Name`). A
  tier-owned key such as `Credentials`, `Substrate` or `Extraction` is refused there rather than
  dropped, because it was never layered onto the merge;
* a **tier file** or a **`-Profile` hashtable** (a resolved profile) may carry the tier keys and the
  workload keys the engine reads off a resolved profile. `ExtraAllowlist` and `InputFiles` are
  workload-file keys and do not exist on a resolved profile.

## Tier-profile keys (all required unless noted)
| Key | Type | Meaning |
|---|---|---|
| `Tier` | int 0–3 | risk tier |
| `Description` | string | human summary |
| `Substrate` | `'Container'` \| `'HyperV-Gen2'` | what hosts the workload |
| `Network` | string | network posture label |
| `EgressMode` | `'HostProxy'`\|`'InGuestSquid'`\|`'HostEnvoy'`(Phase-1B)\|`'SquidSniProxy'`(builder)\|`'None'` | egress enforcement mechanism |
| `EgressAllowlist` | string[] | FQDNs permitted (empty = none) |
| `BlockProtocols` | string[] | (opt) protocols force-blocked (QUIC/DoH/DoT) |
| `Credentials` | `'None'`\|`'ScopedOnDemand'` | credential posture. **MUST be `'None'` for Tier ≥ 2** |
| `GuestImage` | string | base image id |
| `SecureBootTemplate` | (opt) `'MicrosoftWindows'`\|`'MicrosoftUEFICertificateAuthority'`\|`'OpenSourceShieldedVM'` | (Gen2) `MicrosoftUEFICertificateAuthority` for Debian. Absent = Hyper-V default. Validated when present (an invalid value is a real Set-VMFirmware reject). |
| `Memory`/`Cpu` | string/int | hardware. Bounded at load, for a tier and for a merged workload alike: `Memory` is a size string such as `'4GB'` (or a byte count) from `512MB` to `64GB`; `Cpu` is an integer from 1 to 32. A workload profile may set both (see the workload table) |
| `CpuMaximumPercent` | int 1–100 | (opt) cap on the share of each virtual processor the guest may use (`Set-VMProcessor -Maximum`). Absent = Hyper-V's default, so no cap |
| `CpuRelativeWeight` | int 1–10000 | (opt) scheduling weight against the other VMs on the host (`Set-VMProcessor -RelativeWeight`). Absent = Hyper-V's default |
| `NestedVirt` | bool | (opt) expose virt extensions |
| `ManagementChannel` | `'Com1Serial'`\|`'PSDirect'` | how the host drives the guest. Linux ⇒ `Com1Serial` (PS Direct is Windows-guest-only) |
| `HostChannels` | hashtable | clipboard/shares/guest-services/enhanced-session toggles (all `$false` for VM tiers) |
| `Capture` | hashtable | logging mode + OTLP flag |
| `Extraction` | `'HostReadResultDir'`\|`'ColdVHDX-Quarantine-CDR'` | artifact-exit pattern. **MUST be cold-VHDX for Tier ≥ 2** |
| `Lifecycle` | `'Ephemeral'`\|`'SnapshotRevert'`\|`'CreateDestroy'`\|`'DetonateWipe'` | teardown model |
| `Controls` | string[] | cross-cutting controls applied in guest bootstrap |

## Workload-profile keys
| Key | Type | Meaning |
|---|---|---|
| `BaseTier` | int | which tier profile to inherit |
| `Name` | string | profile id (matches filename) |
| `Packages` | string[] | (opt) **declared but NOT installed.** The loader layers it onto the tier, but no engine code reads it, so no package is installed or staged from this list. What the workload needs must already be in the golden image (a Disk-mode guest runs offline and cannot install anything). The list still records what the workload expects. To carry packages into an offline guest, put the wheels on a data disk (`DataDisks`) and install them from the entrypoint with `pip install --no-index --find-links /mnt/data/<name>` |
| `Mounts` | hashtable | (opt) **declared but NOT wired into the guest**: nothing in the Provisioner or Runner attaches a host-guest bind mount (`docs/live-smoke-test.md` Gap 2). The loader still screens its source keys for secret-shaped paths. Files reach a running workload through Disk-mode `Inputs` (small, flat, written per run) or `DataDisks` (pre-built, hash-verified, any size and tree shape, mounted read-only): a `StageAssets` ISO is ejected by the seal before the guest's only boot, and the seed is built from the profile |
| `DataDisks` | hashtable[] | (opt, Disk mode only) pre-built data disks, each `@{ Name = 'corpus'; Path = 'D:\vs\corpus.vhdx'; ImageHash = '<64 hex>' }`, built with `scripts/New-VoidsealDataDisk.ps1`, which prints the hash. `-Workload.DataDisks` replaces this value entirely (an empty array removes them). `Name` matches `^[a-z0-9]{1,8}$` and is unique; at most 8 disks. `Path` is a local drive-letter `.vhdx` path (no UNC, device or relative path, no alternate data stream), not secret-shaped, and outside the sandbox storage root; it may not be, or resolve through a junction or symbolic link to, the DEPS disk or `-ParentDiskPath`, and a file with a second hard link is refused. `ImageHash` is exactly 64 hex characters. `Invoke-Voidseal` refuses a Serial-mode run or a run with no `Entrypoint` that declares data disks. It never attaches the file named here: it copies each one into the run's own sandbox folder (a per-run **working copy**), refuses an unreadable or differencing original or a copy whose whole-image hash (user space) does not match, all before the first copy is attached, then attaches the copies and records them so `Assert-Sealed` accepts them. Teardown deletes the copies and never touches the originals, so a Hyper-V metadata update or a guest write cannot change the file you built. The cost is disk space and copy time on every run: each copy needs about the original's size free under the storage root (the free-space preflight budgets its virtual size plus 64 MB) and takes as long as a file copy of that size. The guest mounts each copy read-only by the label `VSD<NAME>` at `/mnt/data/<name>` and powers off without running the workload if one is missing or writable. After teardown each ORIGINAL is re-hashed; a change made on the host during the run sets the report's `DataDiskChanged`, and the report's `DataDisks` lists each disk's name, original path, verified hash, working copy and changed flag. A processor's `DepsDiskPath` gets the same working-copy treatment |
| `Entrypoint` | string | workload command run by the Runner |
| `WorkloadMode` | `'Serial'` \| `'Disk'` | (opt, default `'Serial'`) how the workload is delivered: over the COM1 serial seam, or by the seed-injected disk-mode runner with INPUT and OUTPUT data disks. `-Workload.WorkloadMode` wins over it |
| `Inputs` | hashtable | (opt, Disk mode) inner file name to CONTENT, written onto the INPUT data disk. The shipped Disk-mode profiles carry `@{}` and fold real content in at run time |
| `InputFiles` | hashtable | (opt, documentation only) inner file name to host file path: a record of where a live-acceptance step reads the content it folds into `Inputs`. It is accepted so a profile can carry the record, and never layered onto the merged profile |
| `FileSystem` | string | (opt, Disk mode, default `'exFAT'`) the data-disk filesystem: `exFAT`, `FAT32`, `NTFS` or `FAT`. `Raw` is reserved for the engine's outbox OUTPUT disk and is not for a profile to set |
| `InputLabel` / `OutputLabel` | string | (opt, Disk mode, defaults `'INPUT'` / `'OUTPUT'`) data-disk volume labels |
| `DepsSpec` | hashtable | (required when `EgressMode` is `'SquidSniProxy'`, else opt) per-fetcher dependency spec (`Pip`, `Apt`, `HuggingFace`, `Github`) the builder fetches over its Squid SNI egress. The merged `EgressAllowlist` must cover every declared fetcher's representative hosts (the builder rule) |
| `ScreenConfig` | hashtable | (opt, processor only) `mode` (`'aggressive'` default, or `'moderate'`) and `categories` (default none), routing the post-detach Sensitivity Gate. A processor is `Network = 'None'` plus a `ScreenConfig` |
| `DepsDiskPath` | string | (opt) host path to a pre-built `deps.vhdx` a processor run attaches, usually supplied as a `-Workload` override |
| `OutboxOutput` | bool | (opt) opts a non-processor Disk-mode workload into the user-space outbox transport (Raw OUTPUT disk, read with `ReadVhdxRawRegion`, never `Mount-VHD`). Transport only: never paired with `ScreenConfig` |
| `ResultInnerName` | string | (opt, default `'result.html'`) the one staged file a transport-only (`OutboxOutput`) run releases, and the file name the legacy exFAT path reads. Layers like `Entrypoint`: `-Workload.ResultInnerName` wins over the profile value, which wins over the default. A plain file name of 1 to 40 characters from `A-Z a-z 0-9 . _ -`; `verdicts.json` and `workload.json` are the outbox container's own entries and are refused |
| `Memory` / `Cpu` | string / int | (opt) guest sizing for this workload. Layers onto the tier like `Entrypoint`: a workload value replaces the tier's, an omitted key keeps the tier's. Same format and bounds as the tier keys (`Memory` `512MB` to `64GB`, `Cpu` 1 to 32), enforced on the merged profile |
| `CpuMaximumPercent` / `CpuRelativeWeight` | int | (opt) the CPU caps described in the tier table, settable from a workload; the workload value wins over a tier value. Absent from both = no cap |
| `WorkloadTimeoutSeconds` | int 60–86400 | (opt) the overall deadline for the workload run, after which the guest is force-stopped and the run reports Failed. `Invoke-Voidseal -WorkloadTimeoutSeconds` wins only when it is explicitly passed; otherwise this key; otherwise 600. The same precedence applies to `Invoke-BuilderVM`. The bounds are checked at load |
| `ExtraAllowlist` | string[] | (opt) additional FQDNs unioned onto the tier allowlist |
| `StageAssets` | hashtable | (opt) host source path → a free-text pin note (for example a commit SHA; no hash is checked on this path). `Invoke-Voidseal` attaches each key as a read-only ISO before the seal (`Import-SandboxAsset -As Iso`, which fails closed on a missing file), and the seal ejects it before the guest's only boot, so nothing in it reaches a running workload; use Disk-mode `Inputs` for that. Its source keys are still screened by invariant 1 below |
| `SeedIso` | string | (opt) **not read by `Invoke-Voidseal`.** Only `New-CidataSeed` uses it, as the default output path for a `CIDATA` seed ISO built by hand. The engine builds the cloud-init seed itself from the resolved profile, on a recorded `CIDATA` data disk that survives the seal (`New-WorkloadSeedDisk`), for every run that boots a guest: in Serial mode serial-getty autologin on ttyS0 (the Runner's command channel), the run-user and the seed's packages, plus the in-guest egress layer for an `InGuestSquid` profile; in Disk mode the disk-mode runner. A seed DVD would be ejected by the seal before the guest's only boot. |

## Provision-time resource gate (not a loader rule)
Before it creates anything, `New-SandboxVM` reads the host's free physical memory (backend method
`GetHostMemory`) and refuses unless free memory covers the guest's `Memory` plus a margin
(`-HostMemoryMarginBytes`, default 2GB). A host-memory read that throws or returns nothing usable is a
refusal, not a pass. The check lives in the provisioner, not the loader, because it depends on the host
at run time, not on the profile alone.

## Loader invariants (MUST be enforced by `Import-TierProfile` / `Import-WorkloadProfile`; these are must-pass tests)
1. **Secret-shaped-path refusal (a name lint, not a content check):** reject any `Mounts` **or**
   `StageAssets` source key whose path *shape* matches the exclusion list. The authoritative list is
   `$script:SecretLeafGlobs`, `$script:SecretDirSegments` and `$script:SecretDirFilePairs` in
   `scripts/lib/ProfileLoader.ps1`; keep this summary in sync with it. Leaf globs today:
   `.env`, `.env.*`, `*.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.ppk`,
   `*.kdbx`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`, `credentials*.json`,
   `.credentials.json`, `.netrc`, `_netrc`, `.git-credentials`, `.pgpass`, `.my.cnf`, `.npmrc`,
   `.pypirc`, `secrets.yaml`, `secrets.yml`, `*.tfvars`, `*-service-account.json`. Directory segments:
   anything under `.secrets/`, `.ssh/` or `.gnupg/`. Adjacent pairs: `~/.aws/credentials`,
   `~/.aws/config`, `~/.kube/config`, `gh/hosts.yml`, `~/.docker/config.json`. Trailing dots or spaces
   and NTFS alternate-data-stream suffixes are normalized away before matching. The check reads names
   only and never opens a file, so it will not detect a renamed credential. The same patterns refuse
   a secret-shaped `DataDisks` path, and `scripts/New-VoidsealDataDisk.ps1` refuses a source tree
   that contains any secret-shaped path.
2. **Tier ≥ 2 starvation:** if `Tier >= 2`, `Credentials` MUST be `'None'`, `EgressMode` MUST be `'None'`,
   `EgressAllowlist` MUST be empty. Reject otherwise.
3. **Extraction by tier:** `Tier >= 2` ⇒ `Extraction` MUST be `'ColdVHDX-Quarantine-CDR'`.
4. **VM-tier channels:** `Substrate -eq 'HyperV-Gen2'` ⇒ all `HostChannels` values `$false`.
5. **Linux management:** a Linux `GuestImage` ⇒ `ManagementChannel -eq 'Com1Serial'` (not `PSDirect`).
6. **Pre-seal gate (`Assert-Sealed`, runtime):** refuse to certify a VM SEALED if it detects an
   attached secret-shaped volume, a still-attached import DVD, or any passthrough device (a GPU
   partition adapter or a device assigned by Discrete Device Assignment), at **any** tier. The
   **network-adapter** rule follows one predicate, `Get-SealNicPolicy`: only a Tier-1 VM whose `Network`
   is set and is not `'None'` may keep a NIC (on an isolated Internal vSwitch, never the Default Switch);
   Tier 0, Tier >= 2 and every `Network='None'` profile must seal with zero adapters, and a descriptor
   that records no `Network` is refused. The unrecorded-residual-disk refusal is authoritative at
   Tier >= 2 and best-effort below it.

Validation = a Pester test per invariant; a deliberately-violating fixture profile MUST fail closed.
