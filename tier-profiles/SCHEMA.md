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
| `EgressMode` | `'HostProxy'`\|`'NftablesAllowlist'`\|`'HostEnvoy'`(Phase-1B)\|`'None'` | egress enforcement mechanism |
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
| `Mounts` | hashtable | (opt) host→guest mounts. Loader REFUSES secret-shaped paths |
| `Entrypoint` | string | workload command run by the Runner |
| `ExtraAllowlist` | string[] | (opt) additional FQDNs unioned onto the tier allowlist |
| `StageAssets` | hashtable | (opt) weights/caches/repos to pre-pull + hash-pin before seal |
| `SeedIso` | string | (opt) host path to a `CIDATA`-labelled cloud-init NoCloud seed ISO, attached **read-only as a DVD at provision** so the guest configures itself (serial-getty autologin on ttyS0 = the Runner's command channel, run-user, packages) on **first boot**; **ejected as part of the seal** (it is import-only — `Lock-Sandbox` detaches it and `Assert-Sealed` refuses any still-attached import DVD). Not secret-shaped — a `.iso` path is accepted. **DVD-slot caveat:** the backend models a single DVD slot, so the SeedIso takes the boot DVD; a `StageAssets` ISO that must coexist with the seed at boot must instead be a transfer-VHD. |

## Loader invariants (MUST be enforced by `Import-TierProfile` / `Import-WorkloadProfile`; these are must-pass tests)
1. **Secret-file refusal:** reject any `Mounts` source matching the exclusion list:
   `.env`, `.env.*`, `*.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `credentials*.json`,
   `.credentials.json`, `~/.aws/credentials`, `~/.ssh/*`, `~/.kube/config`, `~/.docker/config.json`,
   `.npmrc`, `.pypirc`, `*-service-account.json`, anything under a `.secrets/` dir.
2. **Tier ≥ 2 starvation:** if `Tier >= 2`, `Credentials` MUST be `'None'`, `EgressMode` MUST be `'None'`,
   `EgressAllowlist` MUST be empty. Reject otherwise.
3. **Extraction by tier:** `Tier >= 2` ⇒ `Extraction` MUST be `'ColdVHDX-Quarantine-CDR'`.
4. **VM-tier channels:** `Substrate -eq 'HyperV-Gen2'` ⇒ all `HostChannels` values `$false`.
5. **Linux management:** a Linux `GuestImage` ⇒ `ManagementChannel -eq 'Com1Serial'` (not `PSDirect`).
6. **Pre-seal gate (`Assert-Sealed`, runtime):** refuse to mark a Tier-3 VM SEALED if it detects any
   attached secret volume, 1Password agent, live NIC, or non-empty egress route.

Validation = a Pester test per invariant; a deliberately-violating fixture profile MUST fail closed.
