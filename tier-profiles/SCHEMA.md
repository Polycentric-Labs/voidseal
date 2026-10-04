# Tier-profile & profile schema (the build contract)

> This file is the **interface contract** every `Voidseal` component + every parallel build
> agent MUST target. Tier profiles (`tier{0,1,2,3}.psd1`) define the **isolation contract**;
> workload profiles (`profiles/*.psd1`) layer the **workload shape** over a base tier.

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
| `Memory`/`Cpu` | string/int | hardware |
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
| `Packages` | string[] | (opt) **declared but NOT installed.** The loader layers it onto the tier, but no engine code reads it, so no package is installed or staged from this list. What the workload needs must already be in the golden image (a Disk-mode guest runs offline and cannot install anything). The list still records what the workload expects |
| `Mounts` | hashtable | (opt) **declared but NOT wired into the guest**: nothing in the Provisioner or Runner attaches a host-guest bind mount (`docs/live-smoke-test.md` Gap 2). The loader still screens its source keys for secret-shaped paths. Files reach a running workload only through Disk-mode `Inputs`: a `StageAssets` ISO is ejected by the seal before the guest's only boot, and the seed is built from the profile |
| `Entrypoint` | string | workload command run by the Runner |
| `ExtraAllowlist` | string[] | (opt) additional FQDNs unioned onto the tier allowlist |
| `StageAssets` | hashtable | (opt) host source path → a free-text pin note (for example a commit SHA; no hash is checked on this path). `Invoke-Voidseal` attaches each key as a read-only ISO before the seal (`Import-SandboxAsset -As Iso`, which fails closed on a missing file), and the seal ejects it before the guest's only boot, so nothing in it reaches a running workload; use Disk-mode `Inputs` for that. Its source keys are still screened by invariant 1 below |
| `SeedIso` | string | (opt) **not read by `Invoke-Voidseal`.** Only `New-CidataSeed` uses it, as the default output path for a `CIDATA` seed ISO built by hand. The engine builds the cloud-init seed itself from the resolved profile, on a recorded `CIDATA` data disk that survives the seal (`New-WorkloadSeedDisk`), for every run that boots a guest: in Serial mode serial-getty autologin on ttyS0 (the Runner's command channel), the run-user and the seed's packages, plus the in-guest egress layer for an `InGuestSquid` profile; in Disk mode the disk-mode runner. A seed DVD would be ejected by the seal before the guest's only boot. |

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
   only and never opens a file, so it will not detect a renamed credential.
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
