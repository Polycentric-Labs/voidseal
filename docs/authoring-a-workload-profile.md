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
can influence exactly **two**, and only additively/restrictively:

- `EgressAllowlist` — your workload's `ExtraAllowlist` **unions** onto the tier's
  `EgressAllowlist` (deduped, case-insensitive). You can only *add* hosts, never remove one the
  tier already grants.
- `EgressMode` — a workload MAY override this, but **only** to `'SquidSniProxy'` (the builder
  egress — strictly stricter than every tier's own mode, so it can only *tighten* isolation,
  never weaken it). Any other workload-level `EgressMode` is refused at load time (see
  `profiles/builder.psd1` for the one shipped profile that uses this).

Every other tier-profile field (`Substrate`, `Network`, `Credentials`, `GuestImage`, `Memory`,
`Cpu`, `HostChannels`, `Extraction`, `Lifecycle`, `Controls`, …) is **immutable from the workload
layer** — `Import-WorkloadProfile` simply never copies a workload key of that name onto the
merged result. If your task needs a different isolation contract, that's a **different
`BaseTier`**, not a workload-level override.

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
| `Network` | yes | string label | network posture label | the literal value `'None'` triggers the **no-NIC processor rule**: `EgressMode` must then be `'None'` and `EgressAllowlist` must be empty |
| `EgressMode` | yes | `'HostProxy'` \| `'InGuestSquid'` \| `'HostEnvoy'` (Phase-1B, unused today) \| `'SquidSniProxy'` (builder) \| `'None'` | egress enforcement mechanism | `Tier ≥ 2` ⇒ must be `'None'` (invariant 2); `'SquidSniProxy'` ⇒ a non-empty `DepsSpec` is required and the merged allowlist must cover every declared fetcher's hosts (the builder rule) |
| `EgressAllowlist` | yes (may be `@()`) | string[] | FQDNs permitted | every entry is validated against a strict hostname charset (SEC-1 — blocks Squid ACL-injection via newline/quote/whitespace); `Tier ≥ 2` or `Network='None'` ⇒ must be empty |
| `BlockProtocols` | no | string[] | *documents* protocols meant to be force-blocked (QUIC/UDP-443/DoH/DoT) | **not read or enforced by the loader** — purely declarative; the real blocking is "by construction" in the seed's iptables ruleset (`SeedBuilder.ps1`), which simply never opens those protocols regardless of what this array says |
| `Credentials` | yes | `'None'` \| `'ScopedOnDemand'` | credential posture | `Tier ≥ 2` ⇒ must be `'None'` (invariant 2); **not** overridable from a workload profile at all |
| `GuestImage` | yes | string | base image id | if it matches the Linux regex (`debian\|ubuntu\|alpine\|fedora\|remnux\|linux`) *and* a `ManagementChannel` is declared, that channel must be `'Com1Serial'` (invariant 5 — PowerShell Direct is Windows-guest-only) |
| `SecureBootTemplate` | no | `'MicrosoftWindows'` \| `'MicrosoftUEFICertificateAuthority'` \| `'OpenSourceShieldedVM'` | the `Set-VMFirmware -SecureBootTemplate` value | validated only when present/non-blank — an invalid value fails closed at load instead of surfacing as a live `Set-VMFirmware` reject |
| `Memory` / `Cpu` | yes | string / int | hardware sizing | presence only, no enum |
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
| `Entrypoint` | **yes** | the command the Runner delivers | **Serial mode** (the default): delivered over the COM1 serial seam to the sealed guest. **Disk mode**: injected into the seed's disk-mode runner in place of `__ENTRYPOINT__`; by shipped convention it reads from `/mnt/in` and writes to `/mnt/out/result.html` (the engine's default result inner-name) |
| `Packages` | no | extra guest packages staged **before** the seal, over the still-open pre-seal allowlist window | array of strings |
| `Mounts` | no | host→guest bind mounts (the Serial-mode / legacy delivery mechanism for getting files in/out) | every **source** key is refused if secret-shaped (invariant 1 — see §2.3); the loader screens whatever you declare here even on a Disk-mode profile that doesn't actually consume `Mounts` at runtime (a deliberate regression guard, per `firefox.psd1`) |
| `ExtraAllowlist` | no | FQDNs unioned onto the tier's `EgressAllowlist` | deduped case-insensitively; each entry still passes the tier's hostname-charset check |
| `StageAssets` | no | host source → pin-documentation string; assets pre-pulled and hash-pinned, attached **read-only before the seal** (one-way IN) | the **key** is the host path the Importer attaches (e.g. an ISO); **DVD-slot caveat**: the backend models one DVD slot, so a `StageAssets` ISO competes with `SeedIso` if both must be present at boot — use a transfer-VHD (or Disk-mode `Inputs`) instead when they must coexist |
| `SeedIso` | no | host path to a `CIDATA`-labelled cloud-init NoCloud seed ISO | attached read-only as a DVD at provision; configures first boot (serial-getty autologin on ttyS0, run-user, packages); **ejected as part of the seal** — `Assert-Sealed` refuses a still-attached import DVD; not secret-shaped, so a `.iso` path is accepted |
| `WorkloadMode` | no — default `'Serial'` | selects the delivery mechanism: `'Serial'` (COM1 entrypoint delivery) or `'Disk'` (seed-injected disk-mode runner + INPUT/OUTPUT data disks) | **not yet listed in `tier-profiles/SCHEMA.md`** — ProfileLoader-only today. `ralph.psd1` uses the implicit `'Serial'` default; `firefox.psd1`/`builder.psd1` set `'Disk'` explicitly |
| `Inputs` | no (Disk-mode) | innerName → CONTENT written onto the INPUT data disk by `New-WorkloadDisks` | ships `@{}` in both shipped Disk-mode profiles — real content is folded in at run/live-acceptance time, not baked into the `.psd1` (a `.psd1` is static data; inlining a whole script as a here-string is unreadable/brittle) |
| `InputFiles` | no (Disk-mode convention) | innerName → **host file path** — a documentation-only convention some Disk-mode profiles use to record where the live-acceptance step should read real file content from | **not consumed by the loader at all** — it is absent from `Import-WorkloadProfile`'s merge/layer list, so it never survives into the merged profile. A human (or the live-acceptance script) reads these host files and folds them into `Inputs` manually before deploy — see `firefox.psd1`'s `InputFiles` header comment |
| `FileSystem` | no (Disk-mode; default `'exFAT'`) | the data disk filesystem | validated against the backend's `NewOutputVhdx`-accepted set (`exFAT`/`FAT32`/`NTFS`/`FAT`) |
| `InputLabel` / `OutputLabel` | no (Disk-mode; default `'INPUT'`/`'OUTPUT'`) | data-disk volume labels | none |
| `DepsSpec` | **required iff** `EgressMode='SquidSniProxy'`; otherwise no | per-fetcher (`Pip`/`Apt`/`HuggingFace`/`Github`) dependency spec the **builder** profile fetches over its Squid SNI egress | non-empty hashtable of recognized fetcher names; the merged `EgressAllowlist` must cover every declared fetcher's representative hosts or the loader refuses at load time (the "builder rule") — see `profiles/builder.psd1` |
| `ScreenConfig` | no — **PROCESSOR-only** | `mode` (default `'aggressive'`) + `categories` (default `@()`) that route the post-detach Sensitivity Gate | a "processor" profile is specifically `Network='None'` **plus** a declared `ScreenConfig`; it is never paired with `OutboxOutput=$true` (transport-only profiles are never screened, by design) |
| `DepsDiskPath` | no | host path to a pre-built `deps.vhdx` a processor run attaches | in practice supplied via a `-Workload` runtime override rather than baked into the `.psd1`, since it's produced by a separate builder run |
| `OutboxOutput` | no | opts a non-processor Disk-mode workload into the shared user-space outbox transport (Raw OUTPUT disk; the host reads it via `ReadVhdxRawRegion`, **never** `Mount-VHD`) | transport-only — never paired with `ScreenConfig` (see `firefox.psd1`) |

> **Fields marked "not yet in SCHEMA.md"** (`WorkloadMode`, `Inputs`, `InputFiles`, `FileSystem`,
> `InputLabel`/`OutputLabel`, `DepsSpec`, `ScreenConfig`, `DepsDiskPath`, `OutboxOutput`) are real,
> loader-exercised, test-covered fields — they simply postdate `SCHEMA.md`'s last full pass. This
> guide's table is the accurate superset; treat `SCHEMA.md` as the terser tier-invariant reference
> and this doc + `ProfileLoader.ps1` as the source of truth for the Disk-mode / builder / processor
> fields.

### 2.3 The five loader invariants (fail closed — these THROW, they never warn)

1. **Secret-file mount refusal** — any `Mounts` **source** matching a secret-shaped pattern
   (`.env`, `.env.*`, `*.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`,
   `credentials*.json`, `.credentials.json`, `.npmrc`, `.pypirc`, `*-service-account.json`,
   anything under a `.secrets/`/`.ssh/` dir, or the adjacent `~/.aws/credentials`,
   `~/.kube/config`, `~/.docker/config.json` pairs) is refused — full stop, regardless of tier.
   See `ralph.psd1`'s comment block for the documented workaround (copy the real credential to a
   non-secret-shaped `.token` file, mount *that*, read-only).
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
| `PROVISIONED` | `New-SandboxVM` creates the substrate | `Substrate`, `Memory`, `Cpu`, `GuestImage`, `SecureBootTemplate`, `Network` |
| `STAGED` | `Import-SandboxAsset` attaches any `StageAssets` **read-only, one-way IN** — a no-`StageAssets` profile is a recorded no-op transition | `StageAssets` |
| `SEALED` | `Lock-Sandbox` ejects import media (the `StageAssets` ISO + the `SeedIso` DVD) and disconnects host↔guest channels, then `Assert-Sealed` runs as a **hard gate** — if it throws, the deploy aborts *here*, the workload never runs, and the VM is torn down | `HostChannels`, `Network`, `SeedIso` (must be ejectable) |
| `RUNNING` | `Start-SandboxWorkload` delivers your `Entrypoint` — **Serial mode**: over the COM1 seam to the sealed guest, reading/writing through whatever `Mounts` you declared; **Disk mode**: the guest boots straight into the seed-injected runner, mounts `INPUT` read-only / `OUTPUT` read-write, runs your `Entrypoint`, writes the result + an exit-code sentinel, and self-powers-off | `Entrypoint`, `Mounts` (Serial) or `WorkloadMode`/`Inputs`/`FileSystem`/`InputLabel`/`OutputLabel` (Disk) |
| `CAPTURED` | the run result + host-side capture artifact are recorded | `Capture` |
| `EXTRACTED` | `Export-SandboxArtifact` reads the result out, **one-way OUT** — `HostReadResultDir` (Tier 0/1) just reads what your workload wrote; `ColdVHDX-Quarantine-CDR` (Tier ≥ 2) routes to the quarantine sink (throws — not implemented in v1) | `Extraction` |
| `DESTROYED` | `Remove-Sandbox` tears down per the teardown model — **always runs**, in a `finally`, so a mid-flow failure never leaves an orphaned VM/disk/switch | `Lifecycle` |

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
extras your script needs, or any Python at all, depending on the image:

```powershell
Packages = @('python3')
```

**Step 4 — wire input/output.** Serial mode has no automatic data disks — use `Mounts` to bind a
host directory in (read-only, a **copy** of your real data) and one out:

```powershell
Mounts = @{
    'C:\sandbox\notes-input'  = '/mnt/task/in:ro'
    'C:\sandbox\notes-output' = '/mnt/task/out'
}
```

**Step 5 — confirm you're staying offline.** Leave `ExtraAllowlist` unset or `@()` — Tier 0's own
allowlist is already empty, so the merged result stays offline.

**Step 6 — (usually needed) a seed ISO** so the guest actually has a serial console listening on
first boot — point it at the same cloud-init recipe the shipped profiles use
(`guest-images/debian-12-cloud.md`); you don't normally need a bespoke one per profile:

```powershell
SeedIso = 'C:\sandbox\assets\cidata-seed.iso'
```

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
asserts an exact profile count/set. Adding a fourth file there breaks nothing and, per the same
constraints this task set, was verified by re-running both targeted suites plus the full suite
(see the report for the pasted counts).

The skeleton itself is the **minimal valid Tier-0, Serial-mode, offline** shape: just the three
required keys plus the optional fields almost every real task needs (`Packages`, `Mounts`,
`ExtraAllowlist`, `SeedIso`), each carrying a `# <-- EDIT` marker. It is deliberately **not** the
same shape as `firefox.psd1` — see §6.

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
3. Replace `InputFiles` (and the content your live-acceptance step folds into `Inputs`) with your
   own script(s) + sample/synthetic input data — never real personal data by default (see the
   DATA-ACCESS rule in `firefox.psd1`'s header).
4. Change `Entrypoint` to invoke your script, keeping the `/mnt/in` → `/mnt/out/result.html`
   contract (or pass a different `ResultInnerName` via a `-Workload` override — see
   `docs/operator-runbook.md` §1.1).
5. Drop the firefox-specific comments/`ExtraAllowlist` if your task doesn't need them.

This gets you the Disk-mode shape with the INPUT/OUTPUT-disk plumbing, the shared outbox producer
wiring (`OutboxOutput`), and the proven live boot path already worked out — at the cost of more
moving parts than the from-scratch skeleton.

## 7. Common mistakes

- **Trying to change `Credentials`, `Substrate`, `HostChannels`, or `Extraction` from the
  workload layer.** These are tier-owned and simply never copied onto the merge — pick a
  different `BaseTier` instead.
- **Setting `EgressMode` to anything other than `'SquidSniProxy'` in a workload profile.** Every
  other `EgressMode` is tier-controlled; the loader refuses any other workload-level override.
- **Mounting a live credential/secret file "just this once."** The loader refuses it by design —
  copy the secret to a non-secret-shaped path first (see §2.3, invariant 1).
- **Pairing `ScreenConfig` with `OutboxOutput=$true`.** These are two different transport
  contracts (screened processor vs. transport-only outbox) — never both.
- **Forgetting `SeedIso` on a Serial-mode profile.** Without it, the guest has no serial console
  configured on first boot and Entrypoint delivery times out.
- **A `StageAssets` ISO *and* a `SeedIso` DVD on a Serial-mode profile.** The backend models one
  DVD slot — use a transfer-VHD (or switch to Disk mode) if both must be present at boot.
