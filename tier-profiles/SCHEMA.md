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
| `Packages` | string[] | (opt) extra guest packages staged before seal |
| `Mounts` | hashtable | (opt) **declared but NOT wired into the guest** — nothing in the Provisioner or Runner attaches a host-guest bind mount (`docs/live-smoke-test.md` Gap 2). The loader still screens its source keys for secret-shaped paths. Use `StageAssets`, Disk-mode `Inputs`, or the seed to actually deliver files |
| `Entrypoint` | string | workload command run by the Runner |
| `ExtraAllowlist` | string[] | (opt) additional FQDNs unioned onto the tier allowlist |
| `StageAssets` | hashtable | (opt) weights/caches/repos to pre-pull + hash-pin before seal. This is the delivery field the orchestrator actually imports (`Import-SandboxAsset`), and its source keys are screened by invariant 1 below |
| `SeedIso` | string | (opt) host path to a `CIDATA`-labelled cloud-init NoCloud seed ISO, attached **read-only as a DVD at provision** so the guest configures itself (serial-getty autologin on ttyS0 = the Runner's command channel, run-user, packages) on **first boot**; **ejected as part of the seal** (it is import-only — `Lock-Sandbox` detaches it and `Assert-Sealed` refuses any still-attached import DVD). Not secret-shaped — a `.iso` path is accepted. **DVD-slot caveat:** the backend models a single DVD slot, so the SeedIso takes the boot DVD; a `StageAssets` ISO that must coexist with the seed at boot must instead be a transfer-VHD. |

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
   attached secret-shaped volume or a still-attached import DVD, at **any** tier. The **live-NIC**
   refusal is narrower: it fires at Tier >= 2, or for any profile declaring `Network='None'`, and is
   the reason Tier 0 and Tier 1 get no adapter-count guarantee. The unrecorded-residual-disk refusal
   is authoritative at Tier >= 2 and best-effort below it.

Validation = a Pester test per invariant; a deliberately-violating fixture profile MUST fail closed.
