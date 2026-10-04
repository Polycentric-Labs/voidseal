# Authoring a Workload Profile

> How to point Voidseal at **your own task** without reverse-engineering the shipped examples.
> Modeled on CAPEv2's `packages.rst`: this documents the profile **interface contract** first,
> then gives you one deliberately trivial skeleton to copy. Companion to
> [`tier-profiles/SCHEMA.md`](../tier-profiles/SCHEMA.md) (the terse field reference) and
> [`operator-runbook.md`](operator-runbook.md) (how to actually run a deploy).
>
> Ground truth for every claim below: `scripts/lib/ProfileLoader.ps1` (the loader that enforces
> all of this), `tier-profiles/SCHEMA.md`, and the shipped example profiles
> (`profiles/firefox.psd1`, `profiles/ralph.psd1`, `profiles/builder.psd1`). If this doc and the
> loader ever disagree, the loader is right — please file an issue.

## 1. The two-layer model

Every deploy is built from **two `.psd1` files**, merged by `Import-WorkloadProfile`:

- **A tier profile** (`tier-profiles/tier{0,1,2,3}.psd1`) — the **isolation contract**. It
  declares the substrate, the network posture, the egress mechanism, the credential posture, the
  extraction/teardown model — everything that defines *how much capability the sandbox grants*,
  independent of what you run inside it. You normally **never edit these**; you pick one by
  setting `BaseTier` in your workload profile.
- **A workload profile** (`profiles/<name>.psd1`) — the **workload shape**: what command runs,
  what packages/assets it needs, what (if anything) it mounts or additionally allowlists. This is
  the file **you author**.

`Import-WorkloadProfile -Path profiles/<name>.psd1 -TierProfileDir tier-profiles` does the work:
it loads your workload file, resolves `BaseTier` to `tier-profiles/tier<N>.psd1`, loads *that*
through `Import-TierProfile` (which validates it on its own), then **layers your workload keys
onto the tier profile** and **re-validates the merged result against every loader invariant**
(so a workload profile can never smuggle in a Tier-≥2 credential, a secret-shaped mount, or a
weakened egress mode — see §2.3).

**Which layer owns which field, precisely:** of all the tier-profile fields, a workload profile
can influence a short, fixed list. Two of them touch isolation, and only additively/restrictively:

- `EgressAllowlist` — your workload's `ExtraAllowlist` **unions** onto the tier's
  `EgressAllowlist` (deduped, case-insensitive). You can only *add* hosts, never remove one the
  tier already grants.
- `EgressMode` — a workload MAY override this, but **only** to `'SquidSniProxy'` (the builder
  egress — strictly stricter than every tier's own mode, so it can only *tighten* isolation,
  never weaken it). Any other workload-level `EgressMode` is refused at load time (see
  `profiles/builder.psd1` for the one shipped profile that uses this).

The rest are resource choices, not isolation ones. A workload may set `Memory`, `Cpu`,
`CpuMaximumPercent` and `CpuRelativeWeight` (and its own run deadline, `WorkloadTimeoutSeconds`, §2.2); each replaces the tier's value (a key the workload
omits keeps the tier's), and the bounds in §2.1 apply to the merged result, so a workload cannot
ask for a guest the loader would refuse on a tier.

Every other tier-profile field (`Substrate`, `Network`, `Credentials`, `GuestImage`,
`HostChannels`, `Extraction`, `Lifecycle`, `Controls`, …) is **immutable from the workload
layer**: `Import-WorkloadProfile` refuses a workload key of that name rather than ignoring it,
naming the key in the error. If your task needs a different isolation contract, that's a
**different `BaseTier`**, not a workload-level override.

**Unknown keys are refused.** A key that is not in `tier-profiles/SCHEMA.md` (a typo such as
`Entrypont`, a tier-owned key, a key the engine never reads) makes the loader throw and name it, for
a workload file, a tier file and a hashtable passed as `-Profile` alike. Key names match
case-insensitively. A drift test keeps `SCHEMA.md` and the loader's key lists identical.

## 2. The field contract

Every field below is derived from `scripts/lib/ProfileLoader.ps1` (`$script:TierRequiredKeys`,
`$script:WorkloadRequiredKeys`, the `$script:Enum_*` arrays, `Assert-TierProfileValid`, and the
`Import-WorkloadProfile` merge/layer list) plus the three shipped profiles, which exercise fields
`tier-profiles/SCHEMA.md` doesn't (yet) document — §2.3 flags exactly which ones and why.

### 2.1 Tier-profile fields (own `tier-profiles/tierN.psd1`; read-only from a workload profile)

| Field | Required | Type / enum | What it does | Loader-enforced constraints |
|---|---|---|---|---|
| `Tier` | yes | int, 0–3 | the risk tier; gates every invariant below | must be an int in `0..3` |
| `Description` | yes | string | human summary | presence only |
| `Substrate` | yes | `'Container'` \| `'HyperV-Gen2'` | what hosts the workload | `HyperV-Gen2` ⇒ every `HostChannels` value must be `$false` (invariant 4) |
| `Network` | yes | string label | network posture label, recorded on the sandbox descriptor; with `Tier` it decides whether the VM keeps a NIC (`Get-SealNicPolicy`: only Tier 1 with a label other than `'None'` does) | the literal value `'None'` triggers the **no-NIC processor rule**: `EgressMode` must then be `'None'` and `EgressAllowlist` must be empty; at seal time the adapter is removed and the gate host-verifies that none remains, at any tier |
| `EgressMode` | yes | `'HostProxy'` \| `'InGuestSquid'` \| `'HostEnvoy'` (Phase-1B, unused today) \| `'SquidSniProxy'` (builder) \| `'None'` | egress enforcement mechanism (tier-controlled: a workload may only set `'SquidSniProxy'`). `'HostProxy'` is host-enforced on a Tier-1 Serial VM: the merged allowlist is what the host proxy enforces | `Tier ≥ 2` ⇒ must be `'None'` (invariant 2); `'SquidSniProxy'` ⇒ a non-empty `DepsSpec` is required and the merged allowlist must cover every declared fetcher's hosts (the builder rule) |
| `EgressAllowlist` | yes (may be `@()`) | string[] | FQDNs permitted | every entry is validated against a strict hostname charset (SEC-1 — blocks Squid ACL-injection via newline/quote/whitespace); `Tier ≥ 2` or `Network='None'` ⇒ must be empty |
| `BlockProtocols` | no | string[] | *documents* protocols meant to be force-blocked (QUIC/UDP-443/DoH/DoT) | **not read or enforced by the loader**: purely declarative; the real blocking is "by construction": under `EgressMode='HostProxy'` the host proxy tunnels only CONNECT to port 443 and the host firewall rules and port ACL drop all UDP, and the seed's in-guest firewall ruleset (`SeedBuilder.ps1`) adds a second layer that is defense in depth only (a root guest can disable it; see [`threat-model.md`](threat-model.md)). Neither layer opens those protocols regardless of what this array says |
| `Credentials` | yes | `'None'` \| `'ScopedOnDemand'` | credential posture | `Tier ≥ 2` ⇒ must be `'None'` (invariant 2); **not** overridable from a workload profile at all |
| `GuestImage` | yes | string | base image id | if it matches the Linux regex (`debian\|ubuntu\|alpine\|fedora\|remnux\|linux`) *and* a `ManagementChannel` is declared, that channel must be `'Com1Serial'` (invariant 5 — PowerShell Direct is Windows-guest-only) |
| `SecureBootTemplate` | no | `'MicrosoftWindows'` \| `'MicrosoftUEFICertificateAuthority'` \| `'OpenSourceShieldedVM'` | the `Set-VMFirmware -SecureBootTemplate` value | validated only when present/non-blank — an invalid value fails closed at load instead of surfacing as a live `Set-VMFirmware` reject |
| `Memory` / `Cpu` | yes | string / int | hardware sizing. A workload profile may override both (§2.2) | `Memory` parses as a size (`'4GB'`, `'512MB'`, or a byte count) and sits in `512MB`..`64GB`; `Cpu` is an integer in `1`..`32`. Out-of-range, unparseable, string and fractional values are refused at load |
| `CpuMaximumPercent` | no | int | cap on the share of each virtual processor the guest may use (`Set-VMProcessor -Maximum`) | integer in `1`..`100`; absent means no cap (Hyper-V's default of 100) |
| `CpuRelativeWeight` | no | int | scheduling weight against the other VMs on the host (`Set-VMProcessor -RelativeWeight`) | integer in `1`..`10000`; absent means Hyper-V's default of 100 |
| `NestedVirt` | no | bool | expose virtualization extensions to the guest | none |
| `ManagementChannel` | no | `'Com1Serial'` \| `'PSDirect'` | how the host drives the guest | if present, must be a valid enum member; combines with `GuestImage` for invariant 5 |
| `HostChannels` | yes | hashtable | clipboard/shares/guest-services/enhanced-session toggles | must be a hashtable; see `Substrate` row for the HyperV-Gen2 all-`$false` rule |
| `Capture` | yes | hashtable | logging mode + OTLP flag | presence only |
| `Extraction` | yes | `'HostReadResultDir'` \| `'ColdVHDX-Quarantine-CDR'` | the artifact-exit pattern | `Tier ≥ 2` ⇒ must be `'ColdVHDX-Quarantine-CDR'` (invariant 3) |
| `Lifecycle` | yes | `'Ephemeral'` \| `'SnapshotRevert'` \| `'CreateDestroy'` \| `'DetonateWipe'` | the teardown model | enum membership only |
| `Controls` | yes | string[] | cross-cutting controls applied in guest bootstrap | presence only |

### 2.2 Workload-profile fields (author these in `profiles/<name>.psd1`)

| Field | Required | What it does | Constraints |
|---|---|---|---|
| `BaseTier` | **yes** | int selecting which `tier-profiles/tier<N>.psd1` to inherit | must resolve to an existing tier file |
| `Name` | **yes** | the profile id | convention: matches the filename (minus `.psd1`) |
| `Entrypoint` | **yes** | the command the Runner delivers | **Serial mode** (the default): delivered over the COM1 serial seam to the sealed guest. **Disk mode**: substituted for `__ENTRYPOINT__` in the runner the engine writes into the seed. For an `OutboxOutput` or processor profile (the only Disk shapes `Invoke-Voidseal` accepts) it reads `/mnt/in` and writes its result into `/run/staging/` (`result.html` unless the profile or `-Workload` sets `ResultInnerName`), which the in-guest producer packs into the outbox; `/mnt/out` is never mounted there, and a seed whose `Entrypoint` names it is refused. The entrypoint runs as the non-root sandbox user, which cannot create folders under `/run`: write into `/run/staging` (it already exists) or `/dev/shm`. If it exits non-zero the run reports `WorkloadFailed` with that `ExitCode` and releases nothing (a processor still runs its gate as before) |
| `ResultInnerName` | no (default `'result.html'`) | the one staged file a transport-only (`OutboxOutput`) run releases, and the name the legacy exFAT path reads. Layers like `Entrypoint`: `-Workload.ResultInnerName` wins over the profile value, which wins over the default. Set it in the profile when the entrypoint writes a different file name, so every caller does not need a `-Workload` override | a plain file name, 1 to 40 characters from `A-Z a-z 0-9 . _ -`; `verdicts.json` and `workload.json` (the outbox container's own entries) are refused. The `-Workload` value is held to the same rule |
| `Memory` / `Cpu` | no | size this workload's guest; replaces the tier's `Memory` / `Cpu` | same format and bounds as §2.1 (`512MB`..`64GB`, `1`..`32`), checked on the merged profile. Before the VM is created the provisioner also checks the host: free RAM must cover `Memory` plus a margin (default 2GB, `-HostMemoryMarginBytes`), or the run is refused |
| `CpuMaximumPercent` / `CpuRelativeWeight` | no | the optional CPU caps from §2.1, set for this workload; the workload value wins over a tier value | integers in `1`..`100` and `1`..`10000`; each reaches `Set-VMProcessor` only when set, so an unset cap leaves Hyper-V's default alone |
| `WorkloadTimeoutSeconds` | no (default 600) | the overall deadline for the run: past it the guest is force-stopped and the run reports `Failed`. Use it for a workload that legitimately runs longer than ten minutes (or one you want cut off sooner) | integer in `60`..`86400`, checked at load. `Invoke-Voidseal -WorkloadTimeoutSeconds` beats it, but only when you pass that parameter explicitly (an explicit value, including `0` in a test, always wins); with neither, the engine uses 600 |
| `Packages` | no | **declared but not installed**: a record of the guest packages the workload expects. The loader merges it, but no engine code reads it, so nothing installs these packages | array of strings; put the packages themselves in the golden image (a Disk-mode guest runs offline and cannot install anything), or ship wheels on a data disk (`DataDisks`) and install them from your `Entrypoint` with `pip install --no-index --find-links /mnt/data/<name>` |
| `Mounts` | no | **declared but not wired**: host→guest bind mounts that nothing attaches. The loader screens the field and merges it onto the tier, but no provisioner, runner or backend method reads it (the backend has no 9p, virtiofs or SMB method), so it moves no file in or out in either workload mode. To carry a directory in, build a data disk from it (`DataDisks`, §4 Step 4); that list covers every channel that does carry data | every **source** key is refused if secret-shaped (invariant 1, see §2.3). The screen runs on every profile even though nothing consumes the field at runtime, a deliberate regression guard (see `firefox.psd1`) |
| `ExtraAllowlist` | no | FQDNs unioned onto the tier's `EgressAllowlist` | deduped case-insensitively; each entry still passes the tier's hostname-charset check |
| `StageAssets` | no | host source path → a free-text pin note (for example a commit SHA). `Invoke-Voidseal` attaches each key as a read-only ISO before the seal, and the seal **ejects it before the guest's only boot**, so nothing in it reaches a running workload; use Disk-mode `Inputs` for files | the **key** must exist on the host (the import fails closed on a missing file) and is screened by invariant 1; no hash is checked on this path |
| `SeedIso` | no | **not read by `Invoke-Voidseal`**: only the default output path for `New-CidataSeed` when you build a seed ISO by hand | the engine builds the cloud-init seed itself, from the resolved profile, on a recorded `CIDATA` data disk that survives the seal (see §4 Step 6); a seed DVD would be ejected by the seal before the guest's only boot; not secret-shaped, so a `.iso` path is accepted |
| `WorkloadMode` | no, default `'Serial'` | selects the delivery mechanism: `'Serial'` (COM1 entrypoint delivery) or `'Disk'` (seed-injected disk-mode runner + INPUT/OUTPUT data disks) | listed in `tier-profiles/SCHEMA.md`. `ralph.psd1` uses the implicit `'Serial'` default; `firefox.psd1`/`builder.psd1` set `'Disk'` explicitly |
| `Inputs` | no (Disk-mode) | innerName → CONTENT written onto the INPUT data disk by `New-WorkloadDisks` | ships `@{}` in both shipped Disk-mode profiles — real content is folded in at run/live-acceptance time, not baked into the `.psd1` (a `.psd1` is static data; inlining a whole script as a here-string is unreadable/brittle) |
| `InputFiles` | no (Disk-mode convention) | innerName → **host file path**: a documentation-only convention some Disk-mode profiles use to record where the live-acceptance step should read real file content from | **never layered onto the merged profile**: it is accepted so a profile can carry the record, but it is not in `Import-WorkloadProfile`'s layer list, so nothing reads it at run time. A human (or the live-acceptance script) reads these host files and folds them into `Inputs` manually before deploy; see `firefox.psd1`'s `InputFiles` header comment |
| `FileSystem` | no (Disk-mode; default `'exFAT'`) | the data disk filesystem | validated against the backend's `NewOutputVhdx`-accepted set (`exFAT`/`FAT32`/`NTFS`/`FAT`; `Raw` is also accepted but is engine-reserved for the raw-OUTPUT outbox path — not for a profile to set) |
| `InputLabel` / `OutputLabel` | no (Disk-mode; default `'INPUT'`/`'OUTPUT'`) | data-disk volume labels | none |
| `DepsSpec` | **required iff** `EgressMode='SquidSniProxy'`; otherwise no | per-fetcher (`Pip`/`Apt`/`HuggingFace`/`Github`) dependency spec the **builder** profile fetches over its Squid SNI egress | non-empty hashtable of recognized fetcher names; the merged `EgressAllowlist` must cover every declared fetcher's representative hosts or the loader refuses at load time (the "builder rule") — see `profiles/builder.psd1` |
| `ScreenConfig` | no — **PROCESSOR-only** | `mode` (default `'aggressive'`) + `categories` (default `@()`) that route the post-detach Sensitivity Gate | a "processor" profile is specifically `Network='None'` **plus** a declared `ScreenConfig`; it is never paired with `OutboxOutput=$true` (transport-only profiles are never screened, by design) |
| `DepsDiskPath` | no | host path to a pre-built `deps.vhdx` a processor run attaches | in practice supplied via a `-Workload` runtime override rather than baked into the `.psd1`, since it's produced by a separate builder run |
| `OutboxOutput` | no | opts a non-processor Disk-mode workload into the shared user-space outbox transport (Raw OUTPUT disk; the host reads it via `ReadVhdxRawRegion`, **never** `Mount-VHD`) | transport-only — never paired with `ScreenConfig` (see `firefox.psd1`) |
| `DataDisks` | no (Disk-mode only) | pre-built, hash-verified data disks the guest mounts **read-only** at `/mnt/data/<name>`: bulk input of any size and tree shape, wheels, or model weights. Each entry is `@{ Name; Path; ImageHash }`, printed by `scripts/New-VoidsealDataDisk.ps1`. `-Workload.DataDisks` replaces the profile's list entirely | `Name` matches `^[a-z0-9]{1,8}$`, unique, at most 8 disks; `Path` a local `.vhdx` outside the sandbox storage root, not secret-shaped, never the DEPS disk or the golden parent; `ImageHash` 64 hex characters. Each run attaches a per-run working copy, never your file, and a copy that does not match the hash refuses the run before any data disk is attached. Budget the space and copy time of one copy per disk per run. Full rules: `tier-profiles/SCHEMA.md` |

> **Every field in these tables is also in `tier-profiles/SCHEMA.md`.** The unknown-key refusal made
> that a requirement (a drift test fails when the two lists differ), so the Disk-mode, builder and
> processor fields (`WorkloadMode`, `Inputs`, `InputFiles`, `FileSystem`, `InputLabel`/`OutputLabel`,
> `DepsSpec`, `ScreenConfig`, `DepsDiskPath`, `OutboxOutput`, `ResultInnerName`) are documented there
> as well. This guide's table adds the detail and the reasoning.

**Processor profiles stage three guest helpers.** A processor's seed runs
`python3 /mnt/in/run_disk_workload.py --mode <ScreenConfig.mode>` inside the guest. That script
imports `outbox.py` and runs `screener.py` from its own directory, so all three files from the repo's
`guest/` directory must be in the processor's `Inputs` (or `-Workload.Inputs`). `Invoke-Voidseal`
refuses a processor run that lacks any of them, before anything is provisioned. `ScreenConfig.mode`
must be `'aggressive'` (the default) or `'moderate'`: the seed passes it to the screener on a shell
line, so any other value is refused when the seed is built.

### 2.3 The five loader invariants (fail closed — these THROW, they never warn)

1. **Secret-file mount refusal:** any `Mounts` or `StageAssets` **source** matching a secret-shaped
   pattern (for example `.env`, `.env.*`, `*.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`,
   `credentials*.json`, `.credentials.json`, `.npmrc`, `.pypirc`, `*-service-account.json`,
   anything under a `.secrets/`/`.ssh/` dir, or the adjacent `~/.aws/credentials`,
   `~/.kube/config`, `~/.docker/config.json` pairs; `tier-profiles/SCHEMA.md` has the full list) is
   refused, full stop, regardless of tier. The same patterns refuse a secret-shaped `DataDisks`
   path, and `New-VoidsealDataDisk.ps1` refuses to build a disk from a tree that contains one.
   See `ralph.psd1`'s comment block for the documented workaround: copy the real credential to a
   non-secret-shaped `.token` file and declare *that*. The copy passes the screen, but like every
   `Mounts` entry it never reaches the guest (§2.2).
2. **Tier ≥ 2 starvation** — `Credentials` must be `'None'`, `EgressMode` must be `'None'`,
   `EgressAllowlist` must be empty.
3. **Extraction by tier** — `Tier ≥ 2` ⇒ `Extraction` must be `'ColdVHDX-Quarantine-CDR'`.
4. **VM-tier channels** — `Substrate='HyperV-Gen2'` ⇒ every `HostChannels` value is `$false`.
5. **Linux management** — a Linux `GuestImage` with a declared `ManagementChannel` ⇒ that channel
   is `'Com1Serial'` (PowerShell Direct is Windows-guest-only).

Plus two narrower rules that bind regardless of tier: the **`Network='None'` processor rule**
(§2.1) and the **builder rule** (`EgressMode='SquidSniProxy'` ⇒ `DepsSpec` + allowlist
completeness, §2.2). A deliberately-violating fixture is a Pester test in
`tests/ProfileLoader.Tests.ps1` for every one of these — if you think one is wrong, that's the
place to add a failing test first.

## 3. The lifecycle your profile drives

`Invoke-Voidseal` walks a fixed state machine; here's where each field you authored actually
takes effect:

| State | What happens | Fields in play |
|---|---|---|
| `INIT` | your workload profile loads, merges onto its `BaseTier`, and is re-validated against every invariant above | all of §2.1/§2.2 |
| `PROVISIONED` | `New-SandboxVM` first checks the host has the free RAM for `Memory` (plus the margin), then creates the substrate and applies any CPU caps | `Substrate`, `Memory`, `Cpu`, `CpuMaximumPercent`, `CpuRelativeWeight`, `GuestImage`, `SecureBootTemplate`, `Network` |
| `STAGED` | `Import-SandboxAsset` attaches any `StageAssets` as a read-only ISO (ejected again at `SEALED`, before the guest boots), and `New-WorkloadSeedDisk` builds the cloud-init seed on a `CIDATA` data disk for any run that will boot (Disk mode also builds its INPUT/OUTPUT disks here, then verifies every declared data disk and attaches a per-run working copy of each only if all match) | `StageAssets`, `DataDisks`; the seed comes from the resolved profile |
| `SEALED` | `Lock-Sandbox` ejects import media (any `StageAssets` ISO; the seed disk stays attached) and disconnects host↔guest channels, then `Assert-Sealed` runs as a **hard gate**: if it throws, the deploy aborts *here*, the workload never runs, and the VM is torn down | `HostChannels`, `Network` |
| `RUNNING` | your `Entrypoint` runs in the sealed guest, bounded by the effective deadline (`-WorkloadTimeoutSeconds` if passed, else `WorkloadTimeoutSeconds`, else 600 s). **Serial mode**: `Start-SandboxWorkload` boots the guest and sends the command over the COM1 seam, and the command's stdout and stderr come back the same way into the host-side run capture (there are no data disks, and `Mounts` is not wired); **Disk mode**: the guest boots straight into the seed-injected runner, mounts `INPUT` read-only / `OUTPUT` read-write, runs your `Entrypoint`, writes the result + an exit-code sentinel, and self-powers-off | `Entrypoint` (Serial) or `WorkloadMode`/`Inputs`/`FileSystem`/`InputLabel`/`OutputLabel` (Disk); `WorkloadTimeoutSeconds` for either |
| `CAPTURED` | the run result + host-side capture artifact are recorded | `Capture` |
| `EXTRACTED` | `Export-SandboxArtifact` reads the result out, **one-way OUT** — `HostReadResultDir` (Tier 0/1) just reads what your workload wrote; `ColdVHDX-Quarantine-CDR` (Tier ≥ 2) routes to the quarantine sink (throws — not implemented in v1) | `Extraction` |
| `DESTROYED` | `Remove-Sandbox` tears down per the teardown model; it **always runs**, in a `finally`, so a mid-flow failure never leaves an orphaned VM/disk/switch. Teardown deletes the data disks' working copies (and the DEPS disk's) with the run's other disks; the originals are kept, and once the VM is gone each original is re-hashed, so a change on the host during the run sets the report's `DataDiskChanged` | `Lifecycle`, `DataDisks` |

## 4. Worked walkthrough — authoring a synthetic Tier-0 profile

The example below is **entirely made up** — "summarize a local notes file, offline, on a copy" —
to show the steps without tying them to any real task.

**Step 1 — pick a tier.** The task needs no network and only touches local files ⇒ `BaseTier = 0`
(Tier 0's own `EgressAllowlist` already defaults to empty — offline by default).

**Step 2 — the three required keys.**

```powershell
@{
    BaseTier   = 0
    Name       = 'notes-summarizer'
    Entrypoint = 'python3 /mnt/task/in/summarize.py --in /mnt/task/in/notes.txt --out /mnt/task/out/summary.txt'
}
```

This alone is already a **valid** workload profile — every other field is optional.

**Step 3 — add what your entrypoint needs.** The golden image may not carry Python's stdlib
extras your script needs, or any Python at all, depending on the image. Record those packages in
`Packages`, and know that Voidseal does not install them (no engine code reads the field), so they
must already be in the golden image:

```powershell
Packages = @('python3')
```

**Step 4: wire input/output.** `Mounts` cannot do this: the field is declared but not wired
(§2.2). A `Mounts` block loads clean and passes the secret screen, but nothing attaches it, so the
`/mnt/task/in` and `/mnt/task/out` paths in Step 2 would not exist inside the guest. What does
carry data today:

- **Disk mode** (`WorkloadMode = 'Disk'`) moves files in and out of a running workload, and it is
  the mode with a live round-trip. Before the seal, the engine writes each `Inputs` entry onto an
  INPUT data disk, which the guest's runner mounts at `/mnt/in`; the result comes back on the
  OUTPUT disk through the outbox transport. `Invoke-Voidseal` refuses a Disk-mode profile that sets
  neither `OutboxOutput = $true` nor the processor shape (`Network='None'` plus `ScreenConfig`), so
  start from `firefox.psd1` as §6 describes rather than adding these keys by hand.
- **Data disks** (Disk mode) carry what is too big or too nested for `Inputs`: a whole directory
  tree, wheels, model weights. Build one on the host from a directory, then declare the printed
  entry:

  ```powershell
  pwsh scripts/New-VoidsealDataDisk.ps1 -SourceDir D:\vs\sample-corpus -Path D:\vs\disks\corpus.vhdx -Name corpus
  # prints: DataDisks = @( @{ Name = 'corpus'; Path = 'D:\vs\disks\corpus.vhdx'; ImageHash = '<64 hex>' } )
  ```

  Here `sample-corpus` is a folder of synthetic sample text files. The script refuses a tree that
  holds a secret-shaped file or any junction or symbolic link. At run time the engine copies the
  disk into the run's sandbox folder, refuses the run if the copy does not match the hash, and
  attaches the copy; your file is never attached, so it keeps its hash for the next run. That costs
  one copy's worth of free space and copy time per disk on every run, and teardown deletes the copy.
  The guest mounts it read-only at `/mnt/data/corpus`, and your `Entrypoint` reads it there (for
  example `--corpus /mnt/data/corpus`). If a declared disk does not mount read-only, the guest powers
  off without running the workload. After the run your original is re-hashed; `DataDiskChanged` on
  the report says whether something on the host changed it meanwhile, and `DataDisks` on the report
  lists each disk's original, verified hash and working copy. Pass the list as
  `-Workload @{ DataDisks = @(...) }` to keep host paths out of the `.psd1`. Building the disk needs
  an elevated session (the script mounts the new disk on the host).
- **Serial mode** attaches no data disks, so the engine copies no host file into the guest. The
  `Entrypoint` string arrives over COM1, and the command's stdout and stderr come back in the
  host-side run capture (`run-<timestamp>.json` under the artifact root). On this offline tier,
  anything else the command reads must already be in the golden image.
- **`StageAssets`** is attached as a read-only ISO before the seal, and the seal ejects it before
  the guest's first boot, so it is gone by the time your workload runs.
- **The cloud-init seed** is not a channel for your files in either mode. The engine builds it from
  your profile on a small CIDATA data disk that survives the seal; it carries boot configuration and,
  in Disk mode, the runner plus your `Entrypoint` (Step 6).

For this walkthrough's task, a notes file in and a summary out, that points to Disk mode: build the
profile from §6, put `summarize.py` and a synthetic `notes.txt` in `Inputs`, and read them from
`/mnt/in`. The remaining steps apply to either mode.

**Step 5 — confirm you're staying offline.** Leave `ExtraAllowlist` unset or `@()` — Tier 0's own
allowlist is already empty, so the merged result stays offline.

**Step 6: nothing to add for the seed.** The guest still needs a cloud-init seed on its first boot
(in Serial mode it is what turns on serial-getty autologin on ttyS0, so the Runner finds a shell on
COM1), but `Invoke-Voidseal` builds it for you from the resolved profile, on a small CIDATA data disk
that survives the seal. You do not need `SeedIso`: the engine does not read it. That field only names
where `New-CidataSeed` writes an ISO if you build one by hand (`guest-images/debian-12-cloud.md`).

**Step 7 — sanity-check it loads clean**, without running the full test suite:

```powershell
. .\scripts\lib\ProfileLoader.ps1
Import-WorkloadProfile -Path .\profiles\notes-summarizer.psd1 -TierProfileDir .\tier-profiles | Format-List
```

A throw here names the exact invariant you tripped (fail-closed messages name the violation).

**Step 8 — run it** (matches the README quickstart shape):

```powershell
. .\scripts\Invoke-Voidseal.ps1
Invoke-Voidseal -Tier 0 -Profile notes-summarizer -ParentDiskPath <golden.vhdx> -Destination <out-dir>
```

## 5. The skeleton profile

**Placement decision:** the skeleton ships as **`profiles/example-skeleton.psd1`** — a real,
loadable file next to `firefox.psd1`/`ralph.psd1`/`builder.psd1`, not tucked into `docs/examples/`.

Why this is safe: `tests/Profiles.Tests.ps1` and `tests/ProfileLoader.Tests.ps1` (the two suites
that exercise the shipped profiles) each load profiles **by explicit path** (e.g.
`Import-WorkloadProfile -Path "$PSScriptRoot/../profiles/ralph.psd1" ...`) — neither test file (nor
anything else in `tests/`, `scripts/`, or `.github/`) enumerates the `profiles/` directory or
asserts an exact profile count/set. Adding a fourth profile there breaks nothing — the full Pester
suite stays green (CI runs it on every push/PR).

The skeleton itself is the **minimal valid Tier-0, Serial-mode, offline** shape: just the three
required keys plus the optional fields almost every real task needs (`Packages`,
`ExtraAllowlist`), each carrying a `# <-- EDIT` marker. It is deliberately **not** the
same shape as `firefox.psd1` — see §6.

Its `Mounts` block is labelled declared-only and carries no EDIT marker: the entries show the shape
and give the secret screen something to check, but editing them changes nothing inside the guest
(§2.2). Its `SeedIso` line is unmarked for a similar reason: the engine builds the seed itself and
never reads that path (Step 6).

**Honesty note carried in the file itself:** this Serial-mode skeleton shape has not been
live-run. Only `firefox.psd1`'s Disk-mode Tier-0 shape has a proven live round-trip (see
[`live-smoke-test.md`](live-smoke-test.md)). The skeleton loads clean through the real loader
(mock-verified, like everything else pre-Phase-6) — if you want the fastest path to something
**already** live-validated, use §6 instead.

## 6. Fast path — scaffold from an existing profile

If you'd rather start from something proven end-to-end (mock **and** live) rather than the
from-scratch skeleton above, copy `profiles/firefox.psd1` and strip it down:

1. `Copy-Item profiles/firefox.psd1 profiles/<your-name>.psd1`.
2. Change `Name` to `<your-name>`.
3. Replace the organizer entries in `InputFiles` (and the content your live-acceptance step folds
   into `Inputs`) with your own script(s) + sample/synthetic input data, but keep
   `run_disk_workload.py` and `outbox.py`: the outbox runner runs the first from `/mnt/in`, and it
   needs the second beside it. Never use real personal data by default (see the DATA-ACCESS rule in
   `firefox.psd1`'s header).
4. Change `Entrypoint` to invoke your script: read from `/mnt/in` and write the result into
   `/run/staging/` (`/run/staging/result.html` by default; set `ResultInnerName` in the profile for a
   different name, or override it with `-Workload`, as in `docs/operator-runbook.md` §1.1). The
   sandbox user cannot create folders under `/run`, so use `/run/staging` itself or `/dev/shm` for
   scratch space. `/mnt/out` is never mounted for an outbox profile, and a seed whose `Entrypoint`
   names it is refused.
5. Drop the firefox-specific comments/`ExtraAllowlist` if your task doesn't need them.

This gets you the Disk-mode shape with the INPUT/OUTPUT-disk plumbing, the shared outbox producer
wiring (`OutboxOutput`), and the proven live boot path already worked out — at the cost of more
moving parts than the from-scratch skeleton.

## 7. Common mistakes

- **Trying to change `Credentials`, `Substrate`, `HostChannels`, or `Extraction` from the
  workload layer.** These are tier-owned and the loader refuses them in a workload file; pick a
  different `BaseTier` instead.
- **Misspelling a key, or setting one the engine does not read.** The loader throws on any key
  that is not in `tier-profiles/SCHEMA.md` and names it; it never drops one silently.
- **Setting `EgressMode` to anything other than `'SquidSniProxy'` in a workload profile.** Every
  other `EgressMode` is tier-controlled; the loader refuses any other workload-level override.
- **Mounting a live credential/secret file "just this once."** The loader refuses it by design —
  copy the secret to a non-secret-shaped path first (see §2.3, invariant 1).
- **Pairing `ScreenConfig` with `OutboxOutput=$true`.** These are two different transport
  contracts (screened processor vs. transport-only outbox) — never both.
