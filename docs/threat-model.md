# Voidseal — Threat Model & Scoped Claims

> What Voidseal actually claims to defend against, per tier, and what it explicitly does not — modeled on
> gVisor's `SECURITY.md` (an attacker-prerequisite ladder crossed with a per-surface scope table) and
> bubblewrap's component-vs-product boundary statement. Companion to [`SECURITY.md`](../SECURITY.md) (the
> pointer + the covert-channel/qemu-img risk writeups), [`tier-reference.md`](tier-reference.md) (the tier
> model + P1–P10 rubric), and [`phase-6-live-runbook.md`](phase-6-live-runbook.md) (what Phase 6 adds,
> live, on top of everything described here). Every "IN SCOPE" row below names the exact gate in
> `scripts/lib/Sealer.ps1` or `scripts/lib/ProfileLoader.ps1` that a bug would have to defeat — if you find
> a claim here that doesn't trace to real code, that's a documentation bug; file it.

---

## 1. The claimed boundary (component, not product)

Voidseal's security claim is narrow and specific: the **host-verified, fail-closed `Assert-Sealed` gate**
(`scripts/lib/Sealer.ps1`) — a host-side proof, taken independently of anything the guest reports about
itself, that a VM has been starved of the capabilities its tier says it must not have (network adapters, passthrough devices,
host↔guest channels, residual/secret disks, import media) **before** any untrusted workload is allowed to
run, plus the tier isolation that gate verifies (no NIC at Tier 0, at Tier ≥ 2 and for every processor; exactly one NIC, on the VM's own recorded Internal switch, at Tier 1).

What a workload **does once sealed and running** — whether its own logic is correct, whether it handles the
data it's given safely, whether an agent loop it drives goes off the rails — is **not** something Voidseal
guarantees. That is the calling profile's own model, the same way bubblewrap states plainly that it is a
low-level sandboxing component whose caller must supply the rest of the security posture, not a complete
sandboxing product on its own. Voidseal supervises **capability** (what the guest *can* reach), never
**behavior** (what the guest *chooses* to do with what it can reach) — this is the P1 design principle in
`tier-reference.md`, and it is also exactly where this document's scope line falls: a bug that lets a
workload defeat `Assert-Sealed` or escape its tier's isolation is a Voidseal defect; a workload that
behaves badly *inside* the capability envelope Voidseal actually gave it is not.

---

## 2. Attacker-prerequisite ladder

Scoped to Voidseal, gVisor-style (each rung names a starting capability, not a specific exploit):

| Rung | What the attacker already has | Voidseal's stance |
|---|---|---|
| **Remote** | No local presence at all — only whatever a sealed VM's tier lets its workload reach outbound (e.g. a malicious response served to an allowlisted fetch). | Folds into **GuestUser** below the moment the workload acts on it — Voidseal's design (P1) assumes every workload is a *possible* prompt-injectable insider from the start, so it does not need to reason separately about how a Remote attacker got in. |
| **GuestUser** | Arbitrary code execution inside the guest as the sandboxed, non-root run-user. | **The assumed baseline.** Every tier's isolation is designed against this starting point. |
| **GuestRoot** | Root/Administrator inside the guest. | Still assumed possible; this is the level at which any *in-guest* control (the in-guest lockdown, the ESM facets) is attacker-controlled and can be disabled; see the Tier-1 egress row below. |
| **MaliciousProfile** | No guest code-execution needed — the attack is at profile-authoring time: a crafted `.psd1` tries to smuggle a secret mount, weaken Tier ≥ 2 starvation, widen a builder allowlist, or downgrade `EgressMode`. | **In scope.** `ProfileLoader.ps1`'s `Assert-TierProfileValid` (run on every tier profile and every merged workload) is Voidseal's answer to exactly this rung. |
| **HostOperatorMisconfig** | The human running Voidseal makes an operational mistake — an unpatched host below the Hyper-V CVE floor, elevation granted more broadly than intended, a golden disk pointed at the wrong image. | **Out of scope**, by definition: this is a process/documentation problem, not a code defect, and no automated check can substitute for the operator reading `docs/operator-runbook.md` §0. |
| **HostRoot** | Administrator on the physical host itself, or a Hyper-V hypervisor-boundary compromise (a VM-escape 0-day). | **Out of scope for any sandbox tool.** If the attacker already owns the substrate underneath Voidseal, the sandbox boundary built on top of it is moot — the same floor gVisor, Kata, and Docker's own security model all draw under the host kernel/hypervisor they sit on. |

---

## 3. Per-tier scoped-claims table

Legend: 🟢 **IN SCOPE** (a bug here is a Voidseal defect — see the gate named below the table) · 🟡
**KNOWN LIMITATION, TRACKED** (a real, named gap; not yet closed) · ⚪ **OUT OF SCOPE / HOST MISCONFIG** · ➖
**N/A** (the class doesn't apply at this tier — e.g. no route exists to filter).

| Threat class | T0 | T1 | T2 | T3 |
|---|---|---|---|---|
| **VM-escape** (guest breaks the Hyper-V hypervisor boundary itself) | ⚪ | ⚪ | ⚪ | ⚪ |
| **Live NIC / egress route present at seal time** | 🟢 zero NICs required | 🟢 exactly one NIC, on the VM's own recorded Internal switch (zero NICs for a processor) | 🟢 zero NICs required | 🟢 zero NICs required |
| **Passthrough device present at seal time** (GPU partition adapter, device assigned by DDA) | 🟢 | 🟢 | 🟢 | 🟢 |
| **Egress filtering** (which destinations are reachable through whatever route exists) | ➖ no route exists | 🟢 HostProxy: host-enforced allowlist proxy, gate-verified host objects, mock-green only; residual: CDN-hosted allowed names | ➖ no route exists | ➖ no route exists |
| **Host↔guest channel left ON** (clipboard / shares / guest-services / enhanced-session) | 🟢 | 🟢 | 🟢 | 🟢 |
| **Integration service left ON** (Time Synchronization, Key-Value Pair Exchange, Backup, Heartbeat) | 🟢 | 🟢 | 🟢 | 🟢 |
| **Host time reaching the guest** (reference TSC page, after Time Synchronization is off) | 🟡 | 🟡 | 🟡 | 🟡 |
| **Second serial channel** (a pipe path on COM2) | 🟢 | 🟢 | 🟢 | 🟢 |
| **Checkpoint present, or automatic checkpoints on** | 🟢 | 🟢 | 🟢 | 🟢 |
| **Residual / import / secret-shaped disk left attached** | 🟢 best-effort backstop | 🟢 best-effort backstop | 🟢 structural, authoritative | 🟢 structural, authoritative |
| **Malicious/malformed profile bypassing load-time invariants** | 🟢 | 🟢 | 🟢 | 🟢 |
| **Pre-built data disk** substituted before attach, aliasing a run disk, or written by the guest | 🟢 a verified per-run working copy is attached; the guest can write only to that copy, which teardown deletes | 🟢 same | 🟢 same | 🟢 same |
| **Hostile-output extraction / quarantine** | ➖ not a presumed-hostile tier | ➖ not a presumed-hostile tier | 🟡 designed in scope; sink is a scaffold | 🟡 designed in scope; sink is a scaffold |
| **Host operator error** (unpatched host, wrong parent disk, elevation misuse, etc.) | ⚪ | ⚪ | ⚪ | ⚪ |

### Gate traceability, by class

**VM-escape.** Voidseal orchestrates Hyper-V; it does not implement a hypervisor. A guest that breaks the
VM boundary via a Hyper-V bug is a Hyper-V vulnerability, not a Voidseal defect — the same distinction
bubblewrap draws for the Linux kernel primitives it wraps. Keeping the host patched to the CVE floor
(`docs/operator-runbook.md` §0.2) is the operator's job; Voidseal cannot check whether the physical host
itself is patched.

**Live NIC / egress route present at seal time.**
- **T0, T2, T3, and every processor: IN SCOPE.** `Get-SealNicPolicy` (`scripts/lib/SealPolicy.ps1`)
  returns `NoAdapter` for all of them, and the Provisioner, `Lock-Sandbox` and `Assert-Sealed` all ask it.
  The Provisioner builds no switch, `Lock-Sandbox` removes the one adapter real `New-VM` always creates,
  and `Assert-Sealed` requires the backend's `GetNetworkAdapter` call to return zero adapters, naming the
  reason (processor, Tier ≥ 2, or Tier 0) when it refuses. `New-SandboxVM` records the profile's
  `Network` on the descriptor, and a descriptor that records none is refused before the check runs. Any
  policy value the predicate does not recognize is refused too, and `Lock-Sandbox` removes the adapter
  unless the policy is `IsolatedInternalSwitch`, so a future policy value fails closed in both places. A
  live NIC found at certify time throws and refuses to seal. (Before 2026-10-03 the processor branch
  read a descriptor field production never wrote, and Tier 0 had no adapter check at all.)
- **T1 non-processor: IN SCOPE, narrower.** Tier 1 legitimately keeps a NIC (net-restricted, not
  no-net), and only when its `Network` label is exactly `Internal+Allowlist`. `Assert-Sealed`'s Tier-1
  block requires exactly one NIC, requires its vSwitch to host-verify as `SwitchType='Internal'`, refuses
  the built-in "Default Switch" **by name** (that switch is itself `SwitchType=Internal`), and, since
  2026-10-03, binds the NIC to the VM's **own** switch: its `SwitchName` must equal the `<vm>-int` switch
  `New-SandboxVM` recorded on the descriptor. A Tier-1 VM certified with a second NIC, on an
  External/Private switch, on the Default Switch, or on any Internal switch other than its own is a
  Voidseal defect. A Tier-1 processor is `NoAdapter` like the tiers above: it gets no switch and must
  seal with zero adapters. The by-name Default-Switch refusal matches only the English friendly name,
  but the binding now also refuses a localized Default Switch (it is not the recorded switch); the
  GUID-based refusal (`c08cb7b8-9b3c-408e-8e30-5e16a3aeb444`) stays a Phase-6-live defense in depth
  (`phase-6-live-runbook.md` §4).

**Passthrough device present at seal time.** IN SCOPE, every tier. `Assert-Sealed` reads the backend's
`GetGpuPartitionAdapters` and `GetAssignableDevices` from the host and refuses if either reports any
device. Voidseal never assigns one, so any present was added outside the tool. A device assigned through
Discrete Device Assignment can be a physical NIC that `GetNetworkAdapter` never lists, which is why this
check sits beside the NIC check. Only the count is read, and a read that fails refuses the seal.

**Egress filtering (which destinations are reachable through an existing route).**
- **T0: N/A.** A sealed Tier-0 VM has no network adapter (see the row above), so no route exists to
  filter. `tier0.psd1` still declares `EgressMode='HostProxy'`; the host-proxy machinery runs only for a
  VM that keeps a NIC, so for Tier 0 the setting stays moot unless a future Tier-0 design keeps an adapter.
- **T1: IN SCOPE for the host enforcement, KNOWN LIMITATION for what an allowed name can carry.**
  `tier1.psd1` ships `EgressMode='HostProxy'` (since 2026-10-03). The guest has one static address in a /30
  of its own switch and no route, NAT or resolver. The host puts the gateway address on that switch's
  vEthernet adapter, scopes host firewall rules to the interface and a port ACL to the VM's NIC so that
  the only open path is TCP from the guest's address to the proxy port, and runs
  `scripts/egress/voidseal_egress_proxy.py` there. The proxy accepts only `CONNECT <name>:443` for names on
  the merged `EgressAllowlist`, resolves the name on the host and refuses any answer holding a private,
  loopback, link-local, multicast, reserved or non-global address, then dials the address it chose.
  `Assert-Sealed` refuses unless the gateway address, every firewall rule and every ACL entry are on the
  host exactly as recorded, the record is complete for the VM's address plan, and no NAT covers the
  subnet. A GuestRoot attacker controls only the guest, so none of that is in its reach; a VM certified
  with a missing, disabled or edited rule, an extra ACL entry, or a NAT over its subnet is a Voidseal
  defect. ECH and SNI tricks do not matter here, because the decision is made on the CONNECT name and the
  host-resolved address, not on a ClientHello.

  **The residual (KNOWN LIMITATION):** an allowlist admits names, not parties. A name that fronts a shared
  CDN or a public storage service can carry traffic for parties other than the intended one: ralph's
  `storage.googleapis.com` admits any public bucket, so a guest can read from, or write to, a bucket an
  attacker controls through an allowed name, and the proxy cannot see inside the TLS tunnel to tell. The
  same holds for any name that serves many tenants behind one hostname. The mitigation is a narrow
  allowlist; there is no technical control for it in v1. Byte counts per connection land in the proxy
  log, which helps after the fact but does not prevent anything.

  **Also residual:** Windows Firewall applies a Block over any Allow, so the host rules are one Allow plus
  Blocks shaped around it, not a blanket block. A protocol other than TCP, UDP or ICMP sent to the gateway
  address itself is covered only by the default inbound Block and the port ACL's deny-all, not by a named
  rule. Everything here is mock-green; the first elevated run is the first time any of it meets a real
  host (`phase-6-live-runbook.md` §2 lists the checks).

  The builder is a HostProxy run too (since 2026-10-16): the same host objects, the same gate, the same
  proxy, started by `Invoke-BuilderVM` before the guest boots. The in-guest lockdown every kept-NIC seed
  installs is **defense in depth, not a boundary**: a GuestRoot attacker can remove it, which is why
  nothing that matters depends on it. There is no egress model in which the guest polices itself.
- **T2/T3 — N/A.** No NIC exists once sealed (see the row above), so there is no route for a filtering
  question to apply to.

**Host↔guest channel left ON.** IN SCOPE, every tier. `Assert-Sealed` checks all four channels
(clipboard/shares/guest-services/enhanced-session) through `GetHostChannels`, but only guest-services is
read back from the host (`Get-VMIntegrationService`), failing closed both if it is ON and if its state
cannot be read at all; the real backend reports clipboard, shares and enhanced-session off by
construction, on the argument documented in that function that Hyper-V exposes no per-VM Enhanced
Session signal (see `SECURITY.md`, "Status / honesty"). A channel silently left enabled after
`Lock-Sandbox` runs is a Voidseal defect at any tier.

**Integration service left ON.** IN SCOPE, every tier, since 2026-10-03. Time Synchronization, Key-Value
Pair Exchange, Backup (VSS) and Heartbeat are live VMBus channels the engine never uses. `Lock-Sandbox`
turns each one off and `Assert-Sealed` reads each back from the host, refusing by name when one is on and
failing closed when the host gives no state for it. Unlike clipboard, shares and enhanced-session, these
are real reads, not constants: the real `GetHostChannels` enumerates the VM's services with
`Get-VMIntegrationService` and checks each one's `Enabled`. Services are matched by the component GUID at
the end of their `Id`, because display names are localized; a missing or duplicated match throws.
- **Heartbeat goes off.** Nothing in `scripts/` reads heartbeat state. Boot readiness is a probe over the
  COM1 serial console (`Wait-GuestBootReady`), and Disk-mode completion is the VM's power state
  (`Wait-WorkloadComplete` polls `GetVM` until `Off`).
- **Shutdown stays on.** The engine stops VMs in three places (`Remove-Sandbox`, `Wait-WorkloadComplete`
  on a timeout, and the Serial-mode timeout in `Invoke-Voidseal`), each as `StopVM -Force` without
  `TurnOff`. On real Hyper-V that is `Stop-VM -Force`, which asks the guest to shut down through the
  Shutdown service. Shutdown only carries a host-to-guest request; the guest cannot send data over it.
  Switching those calls to `TurnOff` would let the seal close Shutdown too; that is left as an open choice.
- **Live status:** mock-proven. The component GUIDs and the piped `Enable/Disable-VMIntegrationService`
  calls have not run on a live host. A wrong GUID fails closed: the seal refuses, it never certifies a
  service it could not read.

**Host time reaching the guest.** KNOWN LIMITATION, TRACKED. Turning off Time Synchronization stops the
host pushing time samples over VMBus, but the Hyper-V reference TSC page (the paravirtual clock source a
Linux guest reads through `hyperv_clocksource_tsc_page`) stays available and is paced by the host. The
seal narrows the guest's view of host time; it does not remove it. No per-VM setting is known to close
the page, so the gate has nothing to verify here.

**Second serial channel.** IN SCOPE, every tier, since 2026-10-03. Voidseal wires only COM1, its serial
management channel. `Assert-Sealed` reads COM2 through `GetComPort` and refuses any pipe path, whether or
not the run is serial-managed; a read that throws refuses too. The COM1 liveness check is unchanged.

**Checkpoint present, or automatic checkpoints on.** IN SCOPE, every tier, since 2026-10-03. A checkpoint
holds the VM's state from before the seal, so restoring it would undo the seal without the gate seeing
it, and automatic checkpoints also pin a differencing disk per drive (the RC7 trap). `New-SandboxVM` turns
automatic checkpoints off and the engine never takes a checkpoint, so `Assert-Sealed` refuses either one.
It reads the setting through `GetAutomaticCheckpoints` and the list through `GetCheckpoint`; a throw, a
setting that is not a boolean, or a list that is not a collection refuses. (`Lifecycle='SnapshotRevert'`
is declared in `tier1.psd1` but not wired; wiring it would have to work with this rule.)

**Residual / import / secret-shaped disk left attached.** IN SCOPE, every tier, with a strength gradient
the code itself draws:
- Every tier: any attached disk matching a secret-shaped path (`Test-IsSecretPath` — the same
  single-source-of-truth pattern list `ProfileLoader.ps1` uses at load time: `.env`, `*.pem`, `*.key`,
  `~/.ssh/`, `~/.aws/credentials`, etc.) is refused, and any transfer/import medium the seal should have
  detached but didn't is refused.
- Tier ≥ 2: the **structural, authoritative** rule — the *only* disks allowed to remain attached are the
  recorded system disk and the descriptor's recorded data disks; anything else is refused as a residual,
  independent of whether it happens to be secret-shaped or recorded as import media.
- Tier 0/1: a **best-effort backstop** applies the same "not in the expected set" test, but it can only
  catch what the descriptor didn't record — it is not the authoritative guarantee Tier ≥ 2 gets.

**Malicious/malformed profile bypassing load-time invariants.** IN SCOPE, every tier — this is the
`MaliciousProfile` rung's home gate. `ProfileLoader.ps1`'s `Assert-TierProfileValid` (run on every tier
profile *and* every merged workload) refuses: a secret-shaped `Mounts` source (`Assert-NoSecretMounts`); a
Tier ≥ 2 profile that doesn't set `Credentials='None'` / `EgressMode='None'` / an empty allowlist; a Tier ≥
2 profile that doesn't use `Extraction='ColdVHDX-Quarantine-CDR'`; a `HyperV-Gen2` profile with any
`HostChannels` entry `$true`; a Linux `GuestImage` without `ManagementChannel='Com1Serial'`; a
`Network='None'` processor that still declares egress; a kept-NIC profile (Tier 1,
`Network='Internal+Allowlist'`) that is not `EgressMode='HostProxy'`; a `DepsSpec` (builder) profile
that is not that kept-NIC HostProxy shape, or whose allowlist doesn't cover its fetchers' required hosts;
a workload file that sets `EgressMode` at all; an `EgressAllowlist` entry containing a character outside
the safe hostname charset (the guard against reshaping the host proxy's allowlist arguments); and a
malformed or secret-shaped `DataDisks`
declaration. A profile that got any of these past the loader would
be a Voidseal defect.

**Pre-built data disk.** IN SCOPE, every tier where a Disk-mode run declares `DataDisks`
(`scripts/lib/DataDisks.ps1`). What is enforced, and where it stops:
- **Before anything is provisioned**, `Invoke-Voidseal` refuses a malformed declaration (name outside
  `^[a-z0-9]{1,8}$`, duplicate, more than 8, non-local or secret-shaped path, `ImageHash` not 64 hex
  characters), a Serial-mode run, a run with no `Entrypoint`, and any path under the sandbox storage root
  or equal to the DEPS disk or the golden parent, compared both lexically and after following junctions
  and symbolic links. A data disk file with a second hard link is refused, since the other name could be
  any of those.
- **Before attach**, every declared disk goes through the same `New-VerifiedDiskCopy` as the DEPS disk:
  the original must be readable and not differencing; it is copied into the run's own sandbox folder
  (`CopyVhdxFile`, a plain file copy); and the COPY must pass the same structure check and have a
  whole-image SHA-256 (user space, never `Mount-VHD`) equal to the recorded hash. The copy is what gets
  attached, so the bytes the guest sees are the bytes that were hashed, and nothing outside the run
  folder holds them. All copies are verified before the first is attached, so one bad disk leaves none
  attached and the run never seals. This is tamper evidence for the hand-off from
  `New-VoidsealDataDisk.ps1` (or the builder) to the run, not a statement about where the content came
  from.
- **In the guest**, the runner mounts each disk read-only and refuses to run the workload if one is
  missing or mounted writable. That `ro` mount is not a boundary: the host attach of the copy is
  **read-write** (Hyper-V cannot attach a VHDX read-only, D3), and the in-guest user has passwordless
  sudo, so a hostile guest can remount or write raw blocks. Whatever it writes lands on the working
  copy, which is on `CreatedDisks` and deleted at teardown; it cannot reach the original or a later run.
  The same holds for any metadata Hyper-V itself writes when it opens the file.
- **After the run**, once teardown has removed the VM, every ORIGINAL is re-hashed. This catches a change
  made on the host while the run was going, not anything the guest did. A change, or an original that
  cannot be re-hashed, sets `DataDiskChanged` on the report and warns; it does not fail the run.
  Originals are never attached or deleted, and `Assert-Sealed` accepts only the recorded working copies.
- **Cost and residual:** each run needs one copy's worth of free space per disk under the storage root
  (budgeted in the free-space preflight) and the time to copy it. A change to the original in the window
  between its structure check and the copy is caught by the copy's hash; a change after the copy does
  not affect this run and shows up in `DataDiskChanged`.

**Builder verdict and deps disk.** IN SCOPE (the Tier-1 builder, `scripts/lib/BuilderVM.ps1`).
- **What the host reads from the builder guest.** The builder has two data disks it writes: the exFAT deps
  disk (the OUTPUT disk, which becomes `deps.vhdx`) and a second, small **Raw verdict disk** (a fixed VHDX
  with no partition table and no file system, sized to the outbox bounds of `guest/outbox.py` and recorded
  on the descriptor as a run-created disk, so teardown deletes it). At the end of its run the guest packs
  `result.exitcode` and `deps-manifest.json` into the verdict disk with the same outbox producer every other
  guest uses (`guest/run_disk_workload.py`, no new on-disk format). After power-off and detach,
  `Read-BuilderVerdict` reads that outbox with the shared user-space reader, `Read-OutboxToGateInput`
  (`ReadVhdxRawRegion` plus `host/read_outbox.py`). It uses the two entries only for the Success or
  `FetchFailed` verdict: Success needs the exit code to read exactly `0` and the manifest to be non-empty.
  Anything else, including a missing, truncated or tampered container, fails closed with a fixed reason that
  never repeats guest content. A host-side failure of the read itself (a locked disk, no qemu-img) is not a
  verdict and makes the run `Failed`.
- **Nothing the guest wrote is mounted.** The host never calls `ReadVhdxFile`, `ReadVhdxFileBytes` or
  `Mount-VHD` on a builder disk, so its partition and file system drivers never parse guest-controlled
  metadata (the C1 rule, the same one the structural validator in `Invoke-Voidseal` enforces for every
  other OUTPUT read). `tests/BuilderVM.Tests.ps1` pins that on the AST of `BuilderVM.ps1` and on the call
  log of a run. The deps disk is never read by the host at all: it is only detached, moved and hashed in
  user space. The guest finds the verdict disk by its defining property, the only whole disk with no
  partition table and no file system signature, so the exFAT deps disk, the INPUT disk and the CIDATA seed
  are never mistaken for it, and anything other than exactly one such disk aborts the run before the fetch.
- **What this does not change.** A hostile builder can still write a forged verdict, exactly as before: a
  verdict is the guest's own word, and the integrity check on the artifact is the whole-image hash, not the
  exit code. What changed is the parsing surface the host exposes to that guest, which is now the bounded,
  hash-checked outbox container instead of a mounted volume.
- **What survives.** The finished disk is moved out of the sandbox folder (`MoveVhdxFile`, a plain file move)
  into a destination `Resolve-BuilderDepsDestination` has checked: absolute and local, `.vhdx`, not already
  present, and outside the sandbox storage root both lexically and after following links. Teardown deletes
  only the descriptor's `CreatedDisks`, and the destination is neither on that list nor under the root. The
  hash returned with it is the one a processor run verifies its working copy against (tamper evidence for
  the hand-off, not upstream provenance; see `docs/operator-runbook.md` §0.4).

**Hostile-output extraction / quarantine.**
- **T0/T1 — not applicable in the adversarial sense.** `Extraction='HostReadResultDir'` is a **trusting**
  host read by design, because Tier 0/1 workloads are not presumed hostile at the output stage. (The
  separate, opt-in Sensitivity-Gate/processor path for `Network='None'` + `ScreenConfig` profiles is a
  further refinement described in `SECURITY.md`'s "Release path" section — a policy-enforced regeneration
  control, not a tier-wide guarantee, and out of scope for this table.)
- **T2/T3 — designed in scope, maturity-gated.** `ProfileLoader.ps1` refuses any Tier ≥ 2 profile that
  doesn't declare `Extraction='ColdVHDX-Quarantine-CDR'`, and `Read-WorkloadResult`
  (`scripts/lib/Workload.ps1`) refuses to direct-read a Tier ≥ 2 output disk — an undeterminable tier is
  *also* presumed hostile — routing instead to `Export-ColdVhdxQuarantine` (`scripts/lib/Runner.ps1`),
  which **throws `NotImplemented`** in v1, before any read. The *design* is correctly scoped (never a
  trusting host-read of hostile output); there is simply no live path behind it yet. See §4 below — this
  row is a maturity gap, not a scope gap.

**Host operator error.** OUT OF SCOPE by definition, every tier: an unpatched Hyper-V host below the CVE
floor (`docs/operator-runbook.md` §0.2), elevation/`Hyper-V Administrators` membership misused in a way
that produces a false pass, a golden `-ParentDiskPath` pointed at the wrong image, or Hyper-V's own
hypervisor protections disabled some other way. **Necessary but not sufficient**: every check above assumes
the substrate under it is sound.

---

## 4. Maturity vs. scope (kept separate on purpose)

The table above answers *"if this happened, would it be a Voidseal bug?"* — a scope question. The list
below answers a different question, *"has this actually been exercised?"* — a maturity question. Don't
blend them: something can be correctly scoped as IN SCOPE and still be unproven live.

- **Tier 0/1 provisioning + seal:** mock-proven against a fake Hyper-V backend (1517 passed, 0 failed, 2 skipped, no
  elevation, no real VM). The Tier-0 `firefox` disk round-trip ran end-to-end on real Hyper-V on
  2026-06-25, and again with the user-space outbox transport on 2026-07-21; Tier 1 has not had a live run,
  which remains the operator's own elevated step.
- **Zero-adapter seal and passthrough refusal:** mock-proven only. The real `RemoveNetworkAdapter` (now
  part of every Tier-0 seal) and the two passthrough reads have not run on a live host; the next Tier-0
  `firefox` re-run is their first exercise. Until then, treat them as shape-correct, not live-proven.
- **Integration-service, COM2 and checkpoint checks:** mock-proven only (2026-10-03). The real reads
  (`Get-VMIntegrationService` matched by component GUID, `Get-VMComPort -Number 2`, `Get-VM`'s
  `AutomaticCheckpointsEnabled`, `Get-VMSnapshot`) run here only against stub cmdlets. A live failure
  refuses the seal.
- **Tier-1 HostProxy egress:** mock-proven only. The proxy is tested on loopback sockets with a stub
  resolver; the host bodies (gateway address, firewall rules, port ACL, NAT read, proxy start and stop) run
  against stub cmdlets and a stub child process; the seed is checked as text, with `sh -n` and a YAML
  parse. No real packet has crossed any of it (`phase-6-live-runbook.md` §2).
- **In-guest lockdown and proxy environment (every HostProxy seed, the builder included):** shape-asserted
  only. The mock suite proves the rendered files, runs the runner and lockdown scripts under `sh -n` and
  parses the user-data as YAML; it does not prove that `nftables` installs through the proxy on the real
  image, that `nft` applies the table, or that the fetchers honor the exported variables on a real guest
  (`phase-6-live-runbook.md` §5). The host layers do not depend on any of it.
- **Tier 2/3: scaffold-only.** There is **no shipped `tier-profiles/tier2.psd1` or `tier3.psd1`** — only
  `tier0.psd1` and `tier1.psd1` exist in the repo. The Tier ≥ 2 invariants above are enforced generically
  and unit-tested against inline fixture hashtables (`tests/ProfileLoader.Tests.ps1`), but an operator
  cannot run an end-to-end Tier-2/3 workload today without first authoring their own tier file — and even
  then, the extraction sink throws `NotImplemented`. **No live untrusted-artifact detonation is possible in
  v1**, regardless of what §3 says is correctly *scoped* — maturity gates it shut entirely.
- **qemu-img confinement** (`Invoke-ConfinedQemu`, `scripts/lib/HyperVBackend.ps1`): the confinement *seam*
  is shipped and every native `qemu-img convert` call is routed through it (AST-pinned by test), but v1 is
  a pass-through — no restricted-token/Job-Object/Windows-Sandbox confinement is wired yet. See
  `SECURITY.md`'s qemu-img section and `phase-6-live-runbook.md` §3 for the full writeup.

---

## 5. Reporting

See [`SECURITY.md`](../SECURITY.md#reporting-a-vulnerability) for the reporting channel. If you found a
claim in this document that doesn't trace to the code cited, that is itself a reportable documentation bug
— open it the same way.
