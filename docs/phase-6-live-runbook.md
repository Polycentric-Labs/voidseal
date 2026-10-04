# Phase-6 live runbook — first LIVE Tier-1 builder round-trip

> **Status: PRESCRIBED, NOT YET BUILT / NOT YET LIVE-TESTED.** Every mechanism below is either (a) not yet
> implemented, or (b) implemented mock-green only (fake Hyper-V backend, no elevation, no real VM). Nothing
> in this document has been exercised on real Hyper-V. It consolidates the live-run design that is
> currently scattered across three in-tree synthesis passes so the first live run has one sequence to
> follow, not three docs to cross-reference. Sources cited inline; nothing here is invented — every cmdlet,
> version, and CVE traces to one of (**internal research notes — gitignored, not present in the public
> repo; a reader outside this working tree cannot open these paths**):
> - `_dev/labcoat/PassA-SecurityFrontier/PASSA-SYNTHESIS.md` §Q2 (host egress topology) and §Q3
>   (SNI-splice residuals) — hereafter **Pass A**.
> - `_dev/labcoat/PassB-ClientHVPrimitives/PASSB-SYNTHESIS.md` §Q4 (qemu-img confinement) — hereafter
>   **Pass B**.
> - `.superpowers/sdd/progress.md` §Track and the Phase-6-prep log entries — hereafter **progress.md**.
>
> See also `SECURITY.md` and `docs/operator-runbook.md` for the mock-green engine's current, shipped
> guarantees — this doc is the delta: what Phase 6 adds, live, on top of that.

---

## 1. Scope + safety gate

- **ELEVATED session only** (Hyper-V Administrators group membership plus local administrator for the
  host-side `New-VMSwitch`, `New-NetIPAddress`, `New-NetFirewallRule` and
  `Add-VMNetworkAdapterExtendedAcl` operations HostProxy performs).
- **Allen-run only. NEVER unattended.** This is the first live egress in the project — the host stops
  being a passive test harness and starts making real outbound network decisions on real hardware.
- **Scope: the first LIVE Tier-1 builder round-trip only.** Tier 2 (disposable no-net) and Tier 3
  (airgapped detonation) stay gated behind an explicit, separate verified-isolation green-light — this
  runbook does not arm them (`docs/operator-runbook.md` §3, "Tier 2/3, not armed in v1," is
  unaffected by this doc).
- §2 (host egress) is now built as engine code (2026-10-03, `EgressMode='HostProxy'`) and is mock-green:
  every host call goes through the backend seam and runs in the suite against the fake and against stub
  cmdlets, but none of it has touched a real interface. §3 (qemu-img confinement) is still a native-shim
  mechanism outside the mock-green engine. §4 lists which seal-time assertions are shipped vs. still a
  live-only add.

---

## 2. Host egress enforcement (B': host CONNECT proxy, no NAT)

*Decision of 2026-10-03 (private memo): the earlier plan in this section (a host Squid SNI splice plus
`New-NetNat` plus a host default-DROP) is replaced by B'. B' keeps the property that the host enforces,
drops the NAT and the guest's internet route entirely, and does not depend on SNI, so ECH and SNI spoofing
stop mattering. Implemented in `scripts/lib/HostEgress.ps1`, `scripts/egress/voidseal_egress_proxy.py`,
the HostProxy backend methods in `scripts/lib/HyperVBackend.ps1`, and the HostProxy seed in
`scripts/lib/SeedBuilder.ps1`. Mock-green; not yet run on a live host.*

### 2.1 What the engine does, in order

1. **Plan (New-SandboxVM, before anything is created).** The VM's /30 is taken from a SHA-256 of its name
   inside `10.231.0.0/16`: gateway `.1`, guest `.2`, proxy port `13128`. `Get-NetIPAddress -AddressFamily
   IPv4` and `Get-NetNat` are read; an overlap with any host address or NAT network, or a read that fails,
   refuses the provision. The plan is recorded on the descriptor (`EgressMode`, `Egress`).
2. **Switch.** `New-VMSwitch -SwitchType Internal` named `<vm>-int`, as before (never the Default Switch).
3. **Seed.** The CIDATA disk carries a `network-config` (eth0, the guest address, DHCP off, no route, no
   nameservers), `HTTPS_PROXY`/`https_proxy` with `NO_PROXY` empty, apt's proxy setting with https
   sources, and an in-guest default-DROP (nftables, iptables fallback) that allows only TCP to the proxy
   port and is applied before networking on the guest's only boot.
4. **Seal (Lock-Sandbox).** `New-NetIPAddress -InterfaceAlias 'vEthernet (<vm>-int)' -PolicyStore
   ActiveStore` for the gateway; seven `New-NetFirewallRule -PolicyStore ActiveStore` rules in the group
   `Voidseal egress`, named `Voidseal-egress-<vm>-*` (the active store for the rules too, so neither
   outlives a reboot), all inbound and scoped to that interface (one Allow for TCP from the guest to
   gateway:13128; Blocks for every other TCP port, the proxy port from any other address, UDP, ICMPv4,
   ICMPv6, and every protocol to any local address but the gateway, IPv6 included; Windows lets a Block
   beat any Allow, so the Blocks are shaped around the allowed tuple); three
   `Add-VMNetworkAdapterExtendedAcl` entries (deny inbound and outbound at weight 1, allow stateful
   outbound TCP from the guest to gateway:13128 at weight 100). Before it creates anything, the install
   asks the host (`GetHostFirewallRuleNames`) whether any of the seven rule names already exists and
   refuses if so, naming the rules and the `Remove-NetFirewallRule` command that clears them: a crashed
   run can leave rules behind, and rollback only removes what this run recorded. Each object is recorded
   the moment it exists; a failure rolls back what was created.
5. **Gate (Assert-Sealed).** On top of the one-NIC-on-own-switch rule: the gateway address is on the
   interface with prefix 30, no other host address overlaps the /30, no NAT covers it, every recorded rule
   exists, is enabled and matches its record, the adapter carries exactly the recorded ACL entries, and
   the record is the full set the plan requires. Any failed read refuses.
6. **Proxy (Invoke-Voidseal, after the gate, before StartVM).** `python voidseal_egress_proxy.py
   --listen-host <gateway> --listen-port 13128 --allow ...` as a plain child process; the engine waits for
   its ready file. It exits on its stop file, at the run deadline plus 15 minutes, or when the PowerShell
   process that started it exits. Log: `<ArtifactRoot>\egress-proxy.log`.
7. **Teardown (Remove-Sandbox).** Stop the proxy, stop the VM, remove the ACL entries, the rules and the
   address, remove the VM and the switch. Anything that cannot be removed stays recorded and is named in
   `TeardownStatus`.

**State plainly:** the guest does not police itself in this mode. Its in-guest default-DROP is belt and
braces. What the guest can reach is decided by host objects the gate has read back, and by a proxy that
resolves names itself. The residual is the allowlist itself: an allowed name that fronts a shared CDN or a
public storage service can carry traffic for other parties (`docs/threat-model.md`).

### 2.2 Live checks for the first elevated run

Run the steps by hand in an elevated PowerShell first (`New-SandboxVM`, `New-WorkloadSeedDisk`,
`Lock-Sandbox`, `Assert-Sealed`, then `Start-SandboxEgressProxy` and `Start-SandboxWorkload`), so each
host object can be inspected before the next step. Use a throwaway profile with a short synthetic
allowlist. Every item below is something the mock suite cannot prove.

**Before provisioning**

1. `Get-NetNat` returns without an error (nothing, or a list). An error here refuses every HostProxy
   provision, by design.
2. `Get-NetIPAddress -AddressFamily IPv4` shows nothing inside `10.231.0.0/16`, and no interface prefix
   that covers it (a VPN with a `10.0.0.0/8` interface prefix would refuse every run).
3. `Get-NetFirewallProfile` shows the firewall enabled on every profile, with default inbound action
   Block. HostProxy's leftover-protocol coverage relies on that default.
4. `Resolve-PythonExe` returns a real interpreter, and it runs
   `scripts/egress/voidseal_egress_proxy.py --help`.

**After New-SandboxVM (switch exists)**

5. `Get-NetAdapter -Name 'vEthernet (<vm>-int)'` exists. If it appears only after a delay, the address
   step needs a settle wait; note how long.

**After Lock-Sandbox**

6. `Get-NetIPAddress -InterfaceAlias 'vEthernet (<vm>-int)' -AddressFamily IPv4` shows the gateway with
   `PrefixLength 30`, `PolicyStore ActiveStore`, and `AddressState Preferred` (not Tentative or
   Duplicate). Note whether the APIPA `169.254.x.x` address is still there; the gate ignores it, but
   record it.
7. `Get-NetFirewallRule -Group 'Voidseal egress' -PolicyStore ActiveStore` lists seven rules, all
   `Enabled True`. This is also the first live proof that `New-NetFirewallRule -PolicyStore ActiveStore` is
   accepted and that the rules are visible and removable through the same store; if the cmdlet refuses the
   store, the install fails and rolls back, and the store choice must change. For each, compare
   `Get-NetFirewallPortFilter`, `Get-NetFirewallAddressFilter` and `Get-NetFirewallInterfaceFilter` with
   the record: how an address range renders (`0.0.0.0-10.231.a.b`), whether the IPv6 range
   `::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff` was accepted, how `ICMPv4`/`ICMPv6`/`Any` render as
   `Protocol`, and whether `InterfaceAlias` reads back as the alias. This is the most likely fake versus
   real gap: if `Assert-Sealed` refuses with "differs from its record" or "cannot interpret", capture
   these outputs, because the normalization in the real `GetHostFirewallRule`, or the address and port
   parsing in `HostEgress.ps1` (`ConvertTo-EgressAddressKey`, `ConvertTo-EgressPortKey`), must change, not
   the gate's strictness.
7a. **Readback equals record for all seven rules.** The gate compares each host rule with its record as
   parsed address and port sets (a single address, an `a-b` range, a prefix, IPv6 in any form and any list
   order read as the same set), not as text. Confirm that `Assert-Sealed` certifies, so all seven rules
   (`allow-proxy`, `block-tcp-ports`, `block-proxy-others`, `block-udp`, `block-icmp4`, `block-icmp6`,
   `block-other-local`) read back equal to their records, and write down how Windows rendered each
   `LocalAddress`, `RemoteAddress` and `LocalPort`, especially the mixed IPv4 and IPv6 `LocalAddress` of
   `block-other-local`. A refusal that says "cannot interpret" means Windows used a form the parser does
   not know (a keyword such as `LocalSubnet`, or an IPv6 scope id); capture it and extend the parser
   rather than loosening the comparison.
8. `Get-VMNetworkAdapterExtendedAcl -VMName <vm>` lists three entries. Record how an unset field renders
   (empty, `ANY`, `*`), whether `Protocol` reads `TCP` or `6`, and `Stateful`.
9. `Assert-Sealed` returns `$true`.

**After Start-SandboxEgressProxy**

10. `Get-NetTCPConnection -LocalAddress <gateway> -LocalPort 13128 -State Listen` shows the Python pid,
    and nothing listens on `0.0.0.0:13128`. If the bind failed while the address was still tentative, the
    proxy retries for 15 seconds; note whether it needed to.

**After the guest boots (serial capture attached first, as always)**

11. Serial markers: `egress_lockdown=hostproxy-applied tool=nft rc=0` (or `tool=iptables`),
    `egress_mode=hostproxy guest_addr=1 default_routes=0 nameservers=0 proxy_env=1`, and
    `proxy_reachable=yes`. `guest_addr=1` also proves the NIC is `eth0`; if it is 0, the network-config
    key must change.
12. From the guest (a test entrypoint, run as the sandbox user):
    - `curl -sS -o /dev/null -w '%{http_code}' https://<an allowlisted name>/` succeeds through the proxy.
    - `curl https://<a name not on the list>/` fails with the proxy's 403; the log shows
      `"reason": "not-allowlisted"`.
    - `curl --noproxy '*' https://<any public IP>/` fails at once (no route).
    - `getent hosts <an allowlisted name>` fails (no resolver).
    - `curl -x http://<gateway>:13128 http://<allowlisted name>/` gets 405 (no plain HTTP).
13. With the in-guest layer removed (`sudo nft delete table inet voidseal`, or `sudo iptables -P OUTPUT
    ACCEPT`), so only the host layers stand:
    - TCP to the gateway on other ports (`bash -c 'exec 3<>/dev/tcp/<gateway>/445'`, 135, 3389, 5985)
      fails.
    - `ping <gateway>` gets no reply; UDP to `<gateway>:53` gets no answer.
    - `sudo ip addr add <another address in the /30>/30 dev eth0`, then a connection to the proxy from that
      source address fails (port ACL `LocalIPAddress` and the firewall's guest-only rule).
    - With IPv6 re-enabled in the guest, nothing on the host answers on its link-local address.
14. Optional rebinding probe: temporarily allowlist a public name that resolves to `127.0.0.1` and confirm
    the proxy answers 403 with `"reason": "forbidden-address", "address_class": "loopback"`.
15. `egress-proxy.log` has one JSON line per attempt with name, decision, reason and byte counts, and no
    payload.

**After teardown**

16. `Get-NetFirewallRule -Group 'Voidseal egress' -PolicyStore ActiveStore` is empty (or reports no
    such group), the gateway address is gone, the proxy pid is
    gone, the switch is gone, and `TeardownStatus` starts with `OK`.
17. Crash path: start a run, kill the PowerShell process mid-run, and confirm the proxy exits on its own
    (parent watch). Then clean up by hand: `Get-NetFirewallRule -Group 'Voidseal egress' -PolicyStore
    ActiveStore | Where-Object { $_.Name -like 'Voidseal-egress-<vm>-*' } | Remove-NetFirewallRule`,
    `Remove-NetIPAddress -InterfaceAlias 'vEthernet (<vm>-int)' -IPAddress <gateway>`, and the usual VM
    and switch removal. The address and the rules are both in the active store, so a host reboot clears
    them too. Until they are cleared, a new run of a VM with the same name refuses at the seal, before it
    creates anything: first on the leftover gateway address if that is still there, then on the leftover
    rules, with a message that names them and the removal command. Confirm that refusal, then clean up
    and confirm the next run installs.

The builder (`SquidSniProxy`) is unchanged by B': it still uses its in-guest Squid and has no host
enforcement. Moving it to the host proxy is a follow-up (its Disk-mode runner would need the same proxy
settings and network-config).

---

## 3. qemu-img confinement shim

*Source: Pass B §Q4. This is the real mechanism behind `Invoke-ConfinedQemu` (`scripts/lib/
HyperVBackend.ps1`, the confinement seam — locate by function name; line numbers drift), which today is
a v1 pass-through seam — every native `qemu-img convert` call is routed through it, AST-pinned by test,
but nothing yet confines the child process.*

- **Threat framing (honest, per Pass B):** of the ~12 CVE IDs the fleet initially attached to QEMU's VHDX
  parser, exactly one is genuine — **`CVE-2014-0148`**, and it is a **DoS** (crash/hang, missing BAT
  bounds check), fixed at QEMU 2.0 — NOT an RCE. The real concern for the live convert step is the
  **undiscovered-bug class**: an unpatched memory-safety bug in an offline parser handling adversarial
  bytes. Do not cite or imply a catalogued RCE CVE for qemu-img's VHDX parser; none exists.
- **Version floor = patch-currency, not CVE-derived.** Re-resolve the current stable qemu-img at fire
  time; the floor's justification is "run a currently-patched build," not a specific VHDX-parser CVE fix
  (there is only the one, ancient, DoS fix).
- **Pin qemu-img by SHA-256** (`Resolve-QemuImg -PinnedSha256`; `Resolve-QemuImg` (`scripts/lib/
  HyperVBackend.ps1` — locate by function name; line numbers drift)).
  Pass B prefers **MSYS2 `mingw-w64-x86_64-qemu`** (SHA-256-published, GPG-DB-signed, hash-pinnable). The
  **weilnetz** Windows build is acceptable-by-hash but its Authenticode certificate is **EXPIRED** — do
  **NOT** gate on `Get-AuthenticodeSignature` reporting a `Valid` chain for that build; the SHA-256 pin is
  the real control there, not Authenticode validity. Signature-validity gating only makes sense for the
  MSYS2 route (GPG-DB-signed, not Authenticode).
- **Confine the convert per tier** (Pass B, all four models unanimous on the ranking, matches MS docs):
  - **Tier 0/1** (light reads): a restricted-token + Low-IL (or Job-Object-wrapped) launcher via a **tiny
    native/C# shim** — `CreateRestrictedToken` / Job Object both need P/Invoke, not native PS7. **Job
    Object alone is NOT a security boundary** (resource/teardown only) — it must be paired with a
    restricted/low-IL token.
  - **Tier 2/3** (detonation-output reads): **Windows Sandbox** via a `.wsb` file launched with
    `WindowsSandbox.exe` (no shim needed), or a throwaway Gen2 Hyper-V VM. **Windows Sandbox has
    networking ON by default** — the `.wsb` MUST set `<Networking>Disable</Networking>` (plus read-only
    folder mapping), or the parsing host itself has live egress for a detonation-output parse. Note also
    that `Copy-VMFile` cannot read an offline detached VHDX (it needs a booted guest + Guest Services), so
    the helper-VM pattern must copy the VHDX in and run qemu-img inside the sandbox/VM, not reach out to
    it from the host.
- No confinement mechanism hits a Server/cluster wall: the Win32-API primitives (restricted token / Job
  Object / AppContainer) are available from client-XP onward including Home; Windows Sandbox and the
  Hyper-V helper-VM path need Win11 Pro/Ent/Edu (Home excluded).

---

## 4. Seal-time host assertions to add live

*Source: Pass A §Q2 point 6 ("Seal-time host assertions"), cross-referenced against `progress.md`'s §Track
/ Phase-6-prep entries for shipped-vs-remaining status as of this doc.*

| Assertion | Status |
|---|---|
| Single-NIC invariant, bound to the VM's own switch | **SHIPPED, mock-green (2026-10-03)**: `Assert-Sealed`'s Tier-1 block requires exactly one NIC and that its `SwitchName` equals the descriptor's recorded `SwitchName` (`<vm>-int`); a re-pointed NIC, a second NIC, or a descriptor with no recorded switch is refused |
| Zero adapters for every NoAdapter VM (Tier 0, Tier >= 2, any processor) | **SHIPPED, mock-green**: `Get-SealNicPolicy` plus `Lock-Sandbox` removal plus `Assert-Sealed`'s zero-adapter refusal; the first live exercise is the next Tier-0 run |
| No passthrough device (GPU partition adapter, DDA-assigned device) | **SHIPPED, mock-green**: `Assert-Sealed` reads `GetGpuPartitionAdapters` and `GetAssignableDevices` at every tier |
| NIC's switch `SwitchType == Internal` | **SHIPPED, mock-green** — `Assert-Sealed`'s `SwitchType -ne 'Internal'` refusal in `scripts/lib/Sealer.ps1`'s Tier-1 block — locate by predicate |
| By-name refusal of the built-in "Default Switch" | **SHIPPED, mock-green, this slice** — `Assert-Sealed`'s `$switchName.Trim() -ieq 'Default Switch'` refusal in `scripts/lib/Sealer.ps1`'s Tier-1 block — locate by predicate (commit `3c3a944`) |
| No-uplink (`NetAdapterInterfaceDescription == null`) | live-only addition (not yet asserted) |
| Host-gateway-IP pin | **SHIPPED, mock-green (2026-10-03), HostProxy VMs**: the recorded gateway address must be on `vEthernet (<vm>-int)` with prefix 30, and no other host address may overlap the VM's /30 |
| Recorded host firewall rules and port ACL, exactly as recorded | **SHIPPED, mock-green (2026-10-03), HostProxy VMs**: every recorded rule exists, is enabled and matches; the adapter carries exactly the recorded ACL entries; the record is the full set the address plan requires |
| No NAT covers the VM subnet | **SHIPPED, mock-green (2026-10-03), HostProxy VMs**: `Get-NetNat` read; an overlap or a failed read refuses |
| Whole-host firewall-baseline export/diff | live-only addition (not yet asserted); the per-VM rules above are checked, other rules on the host are not |
| Refuse the Default-Switch by its immutable GUID `c08cb7b8-9b3c-408e-8e30-5e16a3aeb444` | **LIVE Phase-6 addition, tracked, not shipped** — the fake backend does not model a switch `.Id`, so this cannot be mock-verified; the name-based refusal above is the mock-verifiable control this project ships today. The friendly name "Default Switch" can be localized on non-English Windows — the GUID is stable and is the correct control for a non-English host. |

The by-name Default-Switch refusal is real, host-verified, seal-time code today (see `SECURITY.md` and
`docs/operator-runbook.md` for the full writeup of what it does and does not guarantee). It is a
switch-**isolation** control, not egress **filtering**; §2 above is the filtering layer, built and
gate-verified in the mock suite and not yet run live. The GUID-by-Id hardening is the one remaining live addition to the switch-identity
check itself (the switch binding above already refuses a NIC on a localized Default Switch, because that
is not the VM's recorded switch, so the GUID check is now defense in depth). Of the rest of this table, the gateway-IP pin, the recorded rules and ACL,
and the NAT check now ship for HostProxy VMs (mock-green); no-uplink and the whole-host firewall-baseline
diff are still live-only additions.

---

## 5. Live-validation checklist

*Source: `progress.md` — items explicitly logged as LIVE-ONLY-UNPROVEN or Phase-6-deferred across the
Phase-1–5 task rollups. These are mock-green (fake-backend) today; the first live run is what actually
proves them.*

- **I6a — silent-guest `ReadLine` timeout.** The force-stop-on-guest-command-timeout path is mock-verified
  against the fake backend's simulated timeout; the real timeout path against a genuinely silent guest is
  unproven.
- **I2b — real `ERROR_DISK_FULL` HResult classification.** The fail-closed DiskFull-abort path is
  mock-verified via a simulated `IOException`; real-host HResult classification (`0x80070070` /
  `0x80070027`, locale-independent match) is unproven until it fires against a real full disk.
- **I5a/I5b — real qemu-img resolve + confinement.** `Resolve-QemuImg` and `Invoke-ConfinedQemu`'s
  seam-routing are AST-pinned and unit-tested; actually resolving a real qemu-img binary and confining it
  (§3 above) is unproven until Phase 6.
- **Live raw-device path.** In-guest raw-device `dd`, host `New-VHD -Fixed`, and the streaming
  `GetVhdxImageHash` verify-before-attach are mock-verified against the fake backend; the real streaming
  hash and real raw-device transfer are Phase-6-only.
- **SIGKILL-mid-transition.** Fault-injection coverage for a mid-lifecycle SIGKILL is mock-only; real
  process-kill timing against a live guest is unproven.
- **Zero-adapter seal + passthrough reads.** `Lock-Sandbox` now removes the default adapter on every
  Tier-0 seal through the hardened real `RemoveNetworkAdapter` (enumerate, then pipe to
  `Remove-VMNetworkAdapter`), and the gate reads `Get-VMGpuPartitionAdapter` and `Get-VMAssignableDevice`.
  All three are mock-verified only; the next Tier-0 `firefox` re-run is their first live exercise.
  Before that run, in an elevated PowerShell, run `Get-VMGpuPartitionAdapter -VMName <an existing VM>` and
  `Get-VMAssignableDevice -VMName <an existing VM>`. Each should return nothing, not an error. If either
  errors on the host, `Assert-Sealed` refuses every seal (fail closed) until that is resolved.
- **HostProxy, end to end.** Every check in §2.2. Until they pass, the host enforcement is proven in the
  mock suite only.
- **Real Squid domain-ACL packet behavior (builder and InGuestSquid only).** The builder seed's Squid egress config (SEC-2, mock-shipped
  per `progress.md`: default-DROP + minimal allow-list, `BlockProtocols` enforced by construction,
  DoH/DoT/QUIC dropped) is asserted at the level of seed **shape** only — the seed template is correct,
  but no test has observed a real Squid process actually splicing/dropping real packets. The first live
  fetch is what proves the ACL behaves as configured.

Until every item above has been exercised live, treat the mock-green suite as proof of *shape*
correctness, not proof of live behavior.

### Serial capture is mandatory for the live run

Attach the COM1 serial capture **before starting the VM** — it is the project's default live-debug
tool (it pinned both Tier-0 live root causes). For the builder it is the **second** source of fetch
outcome, and the only one that says where the guest stopped. `Invoke-BuilderVM`'s `Status` now carries
the exit code: the runner writes `result.exitcode` to the OUTPUT disk, the host reads it (and
`deps-manifest.json`) after the detach, and `Status='Success'` needs the file to read exactly `0` with
the manifest present. A missing, unparsable or non-zero exit code, or a missing manifest, is
`Status='FetchFailed'` with the reason in `Error` and the code in `ExitCode`; a timeout is `Failed`.
The builder runner narrates structural `[voidseal-diag]` markers to the serial console (mirroring the
OutboxOutput runner's discipline; asserted by `SeedBuilder.Tests.ps1`):

| Marker | What it attributes |
|---|---|
| `squid_active=` | a dead Squid (every fetch becomes an opaque connection failure) |
| `egress_lockdown=v4-applied redirect80_rc= redirect443_rc=` | lockdown applied; an unapplied REDIRECT silently bypasses the domain-ACL |
| `ip6_lockdown=applied\|skipped` | the IPv6 belt-and-braces outcome |
| `ABORT output-not-mounted` / `ABORT input-not-mounted` | the two fail-closed poweroff branches (formerly silent) |
| `output_mounted= owner_sandbox=` / `input_mounted= input_files=` | data-disk mounts + who may write |
| `entrypoint_rc=` | `fetch_deps.py` rc (2 = first failed fetcher; fail-closed) |
| `fetched pip= apt= hf= manifest_present=` | per-fetcher artifact **counts** + the single yes/no of a fully-green fetch (`write_manifest` runs only after all fetchers succeed) |

Read the live verdict off `Status` and `ExitCode` first, and cross-check it against `entrypoint_rc=0`
**and** `manifest_present=yes` on the serial capture: the two sources must agree, and when they do not
(for example `Status='FetchFailed'` with `entrypoint_rc=0`), the capture says which side is wrong.
Markers are structural only (liveness/rc/counts/presence); dependency payload bytes never ride the
console.

The Serial baseline and Serial egress seeds (ralph) emit the same kind of markers, from
`/usr/local/sbin/voidseal-serial-diag` (run last in `runcmd`) and, for egress, from the lockdown script
itself:

| Marker | What it attributes |
|---|---|
| `block_devices= device_mounts= cidata_labeled=` | whether the guest saw the CIDATA disk and how many disks and device mounts it has |
| `sandbox_user=` | the non-root run user exists |
| `serial_getty_active= autologin_dropin= grub_ttyS0_lines= cmdline_ttyS0=` | the COM1 command channel: getty up, autologin drop-in written, console arguments in GRUB and on the running kernel |
| `bwrap_present= ca_certificates=` | the installs that follow `apt-get update` |
| `squid_present= squid_active= egress_unit_enabled= ipv6_disabled= output_policy=` | egress seed only: Squid, the lockdown unit, IPv6 and the OUTPUT chain policy |
| `egress_lockdown=v4-applied redirect80_rc= redirect443_rc=` and `ip6_lockdown=` | egress seed, written when the lockdown unit runs (the next boot), same fields as the builder |
| `failed_units=` | count of failed systemd units |

## 6. Builder output: what a good run leaves

A run that ends `Status='Success'` leaves `deps-<Name>.vhdx` under `-DepsOutputDir` (default
`<ArtifactRoot>\deps`, where `ArtifactRoot` defaults to `<temp>\Voidseal\artifacts\<Name>`), outside
the sandbox folder, so teardown does not delete it. The result carries `DepsDiskPath` and `DepsImageHash`
(taken on that file after the move); pass them as `-Workload.DepsDiskPath` and `-Workload.DepsImageHash`
of the processor run, which attaches a verified working copy and leaves the file in place. The
destination is checked before the build: inside the storage root, relative, UNC, not `.vhdx`, or already
present is refused, so choose a fresh folder per build. After a `FetchFailed` or `Failed` run nothing is
left behind except what the serial capture recorded.
