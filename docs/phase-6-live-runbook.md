# Phase-6 live runbook: the first live Tier-1 builder round trip

> **Status: NOT YET LIVE.** The host egress in section 2 is built and mock-green (fake Hyper-V backend, no
> elevation, no real VM); the qemu-img confinement in section 3 is prescribed, not built. Nothing in this
> document has been exercised on real Hyper-V. It gives the first live run one sequence to follow. The
> design record behind it (the host egress topology, the SNI-splice residuals that retired the earlier
> plan, the qemu-img confinement research and the per-phase progress log) is private and not part of the
> public repo; where this document says "the design record", that is what it means. Nothing here is
> invented: every cmdlet, version and CVE traces to that record or to the code named inline.
>
> See also `SECURITY.md` and `docs/operator-runbook.md` for the mock-green engine's current, shipped
> guarantees; this doc is the delta: what Phase 6 adds, live, on top of that.

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
- §2 (host egress) is built as engine code (`EgressMode='HostProxy'`, the one egress model for a VM that
  keeps its NIC; since 2026-10-16 the builder runs on it too, through `Invoke-BuilderVM`'s seal, gate and
  proxy start) and is mock-green: every host call goes through the backend seam and runs in the suite
  against the fake and against stub cmdlets, but none of it has touched a real interface. §3 (qemu-img
  confinement) is still a native-shim mechanism outside the mock-green engine. §4 lists which seal-time
  assertions are shipped vs. still a live-only add.

---

## 2. Host egress enforcement (B': host CONNECT proxy, no NAT)

*Decision of 2026-10-03 (the design record): the earlier plan in this section (a host SNI-splicing proxy
plus `New-NetNat` plus a host default-DROP) is replaced by B'. B' keeps the property that the host
enforces, drops the NAT and the guest's internet route entirely, and does not depend on SNI, so ECH and SNI
spoofing stop mattering. Implemented in `scripts/lib/HostEgress.ps1`, `scripts/egress/voidseal_egress_proxy.py`,
the HostProxy backend methods in `scripts/lib/HyperVBackend.ps1`, and the HostProxy seeds (Serial and
Disk, the builder among them) in `scripts/lib/SeedBuilder.ps1`. Mock-green; not yet run on a live host.*

### 2.1 What the engine does, in order

1. **Plan (New-SandboxVM, before anything is created).** The VM's /30 is taken from a SHA-256 of its name
   inside `10.231.0.0/16`: gateway `.1`, guest `.2`, proxy port `13128`. `Get-NetIPAddress -AddressFamily
   IPv4` and `Get-NetNat` are read; an overlap with any host address or NAT network, or a read that fails,
   refuses the provision. The plan is recorded on the descriptor (`EgressMode`, `Egress`).
2. **Switch.** `New-VMSwitch -SwitchType Internal` named `<vm>-int`, as before (never the Default Switch).
3. **Seed.** The CIDATA disk carries a `network-config` (eth0, the guest address, DHCP off, no route, no
   nameservers), the proxy settings (the Serial seed: `HTTPS_PROXY`/`https_proxy` with `NO_PROXY` empty;
   the Disk runners, the builder among them: `http_proxy`, `https_proxy` and their uppercase twins to the
   gateway proxy, `no_proxy` for loopback, exported again by the runner before the entrypoint), apt's
   proxy setting with https sources, and an in-guest default-DROP (nftables, iptables fallback) that
   allows only TCP to the proxy port, applied by its unit before the workload runs on the guest's only
   boot. The Disk seeds also install `nftables` through the proxy in cloud-init's package stage.
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
6. **Proxy (Invoke-Voidseal and Invoke-BuilderVM, after the gate, before StartVM).** `python voidseal_egress_proxy.py
   --listen-host <gateway> --listen-port 13128 --allow ...` as a plain child process; the engine waits for
   its ready file. It exits on its stop file, at the run deadline plus 15 minutes, or when the PowerShell
   process that started it exits. Log: `<ArtifactRoot>\egress-proxy.log`.
7. **Teardown (Remove-Sandbox).** Stop the VM, then stop the proxy and remove the ACL entries, the rules
   and the address, then remove the VM, delete the disks the run created and remove the switch. Anything
   that cannot be removed stays recorded and is named in `TeardownStatus`.

**State plainly:** the guest does not police itself in this mode. Its in-guest default-DROP is belt and
braces. What the guest can reach is decided by host objects the gate has read back, and by a proxy that
resolves names itself. The residual is the allowlist itself: an allowed name that fronts a shared CDN or a
public storage service can carry traffic for other parties (`docs/threat-model.md`).

### 2.2 Live checks for the first elevated run

The builder is the headline run: `Invoke-BuilderVM -Profile builder` (the shipped `profiles/builder.psd1`,
or a copy with a shorter `DepsSpec`; pip `urllib3` alone is the smallest) provisions, seeds, seals, gates,
starts the proxy, starts the guest and reads the verdict in one call. To inspect each host object before
the next step, run the same functions by hand in an elevated PowerShell in the order `Invoke-BuilderVM`
uses them (`New-SandboxVM`, `New-WorkloadDisks`, `New-BuilderVerdictDisk`, `New-WorkloadSeedDisk`,
`Lock-Sandbox`, `Assert-Sealed`, `Start-SandboxEgressProxy`, then `StartVM` through the backend). Every
item below is something the mock suite cannot prove.

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

11. Serial markers from the builder runner: `egress_lockdown=hostproxy-applied tool=nft rc=0` (or
    `tool=iptables`; `egress_lockdown=skipped` means neither tool was present, so the nftables install
    through the proxy failed and only the host layers stand), `egress_mode=hostproxy proxy=http://<gateway>:13128
    default_routes=0 nameservers=0 ipv6_disabled=1`, and `egress_unit_enabled=enabled nft_present=yes
    proxy_reachable=yes`. A Serial (ralph) run prints `egress_mode=hostproxy guest_addr=1 default_routes=0
    nameservers=0 proxy_env=1` and `proxy_reachable=yes` from its diag script instead; `guest_addr=1` also
    proves the NIC is `eth0` (if it is 0, the network-config key must change).
11a. First boot with four integration services off. `Lock-Sandbox` turns off Time Synchronization,
    Key-Value Pair Exchange, Backup and Heartbeat, and `Assert-Sealed` refuses a VM with any of them on.
    Neither the mock suite nor any earlier live run has booted a guest that way. Check both effects:
    - **cloud-init NoCloud still completes without KVP.** In the guest, `cloud-init status --long` reads
      `done` and `cloud-id` reads `nocloud` (the CIDATA data disk is the datasource). The journal shows no
      wait on the Azure datasource, which uses Hyper-V KVP: `journalctl -b | grep -i -E
      'azure|kvp|hyperv'`. Note how long first boot took. If it hangs or picks another datasource, pin
      `datasource_list: [ NoCloud ]` in a drop-in under `/etc/cloud/cloud.cfg.d/` of the golden image and
      rebuild it; do not turn KVP back on (the gate would refuse the VM).
    - **The guest clock is sane enough for TLS.** HostProxy tunnels CONNECT to port 443 only, so no NTP
      leaves the guest, and with Time Synchronization off the clock comes from the RTC the VM starts with.
      Compare `date -u` in the guest with `(Get-Date).ToUniversalTime()` on the host (within a few
      seconds), expect `timedatectl` to say `System clock synchronized: no` and `RTC in local TZ: no`, and
      confirm item 12's first `curl` to an allowlisted name verifies its certificate. If the offset equals
      the host's UTC offset, the RTC is being read as local time: fix it in the golden image
      (`timedatectl set-local-rtc 0`, `/etc/adjtime` saying UTC). Record any drift over a long run and
      bound such runs with `-WorkloadTimeoutSeconds`. Do not re-enable Time Synchronization or open UDP
      123 to fix it: the seal verifies the first and the firewall rules block the second, so either would
      be a deliberate design change to record, not a workaround.
12. For the builder, the fetch is the test: `entrypoint_rc=0`, `fetched pip=N apt=N hf=N` with a non-zero
    count for each declared fetcher, `manifest_present=yes`, and `egress-proxy.log` showing one allowed
    CONNECT per name the fetchers used (`pypi.org`, `files.pythonhosted.org`, the Debian mirrors, the
    Hugging Face hosts) and nothing else. From a guest shell (a Serial run's test entrypoint, run as the
    sandbox user):
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

The builder runs on B' too (since 2026-10-16): `Invoke-BuilderVM` seals, gates and starts the proxy
before the guest boots, its seed carries the proxy environment, the apt setting, the lockdown and the
network-config, and `pip download`, `apt-get download` and `huggingface-cli` fetch through the host
proxy. There is no in-guest proxy any more, and no other egress model for a VM that keeps its NIC: the
loader, the seal and the gate each refuse one.

---

## 3. qemu-img confinement shim

*Source: the design record's qemu-img confinement research. This is the real mechanism behind `Invoke-ConfinedQemu` (`scripts/lib/
HyperVBackend.ps1`, the confinement seam — locate by function name; line numbers drift), which today is
a v1 pass-through seam — every native `qemu-img convert` call is routed through it, AST-pinned by test,
but nothing yet confines the child process.*

- **Threat framing (honest, per the design record):** of the ~12 CVE IDs the fleet initially attached to QEMU's VHDX
  parser, exactly one is genuine — **`CVE-2014-0148`**, and it is a **DoS** (crash/hang, missing BAT
  bounds check), fixed at QEMU 2.0 — NOT an RCE. The real concern for the live convert step is the
  **undiscovered-bug class**: an unpatched memory-safety bug in an offline parser handling adversarial
  bytes. Do not cite or imply a catalogued RCE CVE for qemu-img's VHDX parser; none exists.
- **Version floor = patch-currency, not CVE-derived.** Re-resolve the current stable qemu-img at fire
  time; the floor's justification is "run a currently-patched build," not a specific VHDX-parser CVE fix
  (there is only the one, ancient, DoS fix).
- **Pin qemu-img by SHA-256** (`Resolve-QemuImg -PinnedSha256`; `Resolve-QemuImg` (`scripts/lib/
  HyperVBackend.ps1` — locate by function name; line numbers drift)).
  The design record prefers **MSYS2 `mingw-w64-x86_64-qemu`** (SHA-256-published, GPG-DB-signed, hash-pinnable). The
  **weilnetz** Windows build is acceptable-by-hash but its Authenticode certificate is **EXPIRED** — do
  **NOT** gate on `Get-AuthenticodeSignature` reporting a `Valid` chain for that build; the SHA-256 pin is
  the real control there, not Authenticode validity. Signature-validity gating only makes sense for the
  MSYS2 route (GPG-DB-signed, not Authenticode).
- **Confine the convert per tier** (the design record, all four models unanimous on the ranking, matches MS docs):
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

*Source: the design record's seal-time host assertions, cross-referenced against its progress log for
shipped-vs-remaining status as of this doc.*

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

*Source: the design record's progress log, the items logged as live-only-unproven or Phase-6-deferred
across the Phase 1 to 5 task rollups. These are mock-green (fake-backend) today; the first live run is
what actually proves them.*

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
- **Builder raw verdict disk.** The mock proves the shell logic (the raw-disk selection and the pack step
  both run under a POSIX sh in the suite) and the host read against the fake backend. Live, three things are
  unproven: the real `New-VHD -Fixed` of the ~65 MB verdict disk, the guest's `blkid -p` selection picking
  it out among the system, INPUT, exFAT deps and CIDATA disks (watch `verdict_candidates=` and
  `verdict_dev=`), and the real `ReadVhdxRawRegion` read-back of that disk after the detach (watch
  `verdict_head=` against `Status`). Confirm that no `deps-manifest.json` copy is lost: the exFAT deps disk
  keeps its own.
- **In-guest lockdown and proxy environment (every HostProxy seed, the builder included).** Shape-asserted
  only: the suite checks the rendered files as text, runs the runner and lockdown scripts under `sh -n`,
  and parses the user-data as YAML. Whether `nftables` installs through the proxy on the real image,
  whether `nft -f -` applies the table, and whether `pip download`, `apt-get download` and
  `huggingface-cli` honor the exported variables on the real guest are live questions. The host layers
  do not depend on any of it.

Until every item above has been exercised live, treat the mock-green suite as proof of *shape*
correctness, not proof of live behavior.

### Serial capture is mandatory for the live run

Attach the COM1 serial capture **before starting the VM** — it is the project's default live-debug
tool (it pinned both Tier-0 live root causes). For the builder it is the **second** source of fetch
outcome, and the only one that says where the guest stopped. `Invoke-BuilderVM`'s `Status` now carries
the exit code: the runner packs `result.exitcode` and `deps-manifest.json` into a small raw verdict disk
with the outbox producer, the host reads that outbox in user space after the detach (it mounts nothing,
and never reads the deps disk), and `Status='Success'` needs the exit code to read exactly `0` with the
manifest present. A missing or invalid verdict, an unparsable or non-zero exit code, or a missing
manifest, is `Status='FetchFailed'` with the reason in `Error` and the code in `ExitCode`; a timeout, or a
host read that itself fails, is `Failed`.
The builder runner narrates structural `[voidseal-diag]` markers to the serial console (mirroring the
OutboxOutput runner's discipline; asserted by `SeedBuilder.Tests.ps1`):

| Marker | What it attributes |
|---|---|
| `egress_mode=hostproxy proxy= default_routes= nameservers= ipv6_disabled=` | the proxy address the fetchers were given, that no route and no resolver exist, and that IPv6 is off |
| `egress_unit_enabled= nft_present= proxy_reachable=` | the lockdown unit, whether nftables arrived through the proxy, and a TCP connect to the proxy port (a `no` here means every fetch fails before any allowlist decision) |
| `egress-lockdown start mode=hostproxy` / `egress_lockdown=hostproxy-applied tool=nft\|iptables rc=` / `egress_lockdown=skipped` | from the lockdown script, when its unit runs: which tool applied the default-DROP, or that neither was present |
| `ABORT output-not-mounted` / `ABORT input-not-mounted` / `ABORT verdict-candidates-not-1` | the fail-closed poweroff branches (formerly silent); the last means the raw verdict disk could not be picked out |
| `verdict_candidates=` / `verdict_dev=` and `skip <dev> (has partitions\|has a filesystem signature)` | which whole disks the runner considered and the one it chose to pack the verdict into |
| `verdict_producer_rc=` / `verdict_head=` | the producer's exit code, and the container magic read back from the verdict device (`56534f5554425831` = `VSOUTBX1`) |
| `output_mounted= owner_sandbox=` / `input_mounted= input_files=` | data-disk mounts + who may write |
| `entrypoint_rc=` | `fetch_deps.py` rc (2 = first failed fetcher; fail-closed) |
| `fetched pip= apt= hf= manifest_present=` | per-fetcher artifact **counts** + the single yes/no of a fully-green fetch (`write_manifest` runs only after all fetchers succeed) |

Read the live verdict off `Status` and `ExitCode` first, and cross-check it against `entrypoint_rc=0`
**and** `manifest_present=yes` on the serial capture: the two sources must agree, and when they do not
(for example `Status='FetchFailed'` with `entrypoint_rc=0`), the capture says which side is wrong.
Markers are structural only (liveness/rc/counts/presence); dependency payload bytes never ride the
console.

The Serial seeds (ralph: the HostProxy seed) emit the same kind of markers, from
`/usr/local/sbin/voidseal-serial-diag` (run last in `runcmd`) and from the lockdown script itself:

| Marker | What it attributes |
|---|---|
| `block_devices= device_mounts= cidata_labeled=` | whether the guest saw the CIDATA disk and how many disks and device mounts it has |
| `sandbox_user=` | the non-root run user exists |
| `serial_getty_active= autologin_dropin= grub_ttyS0_lines= cmdline_ttyS0=` | the COM1 command channel: getty up, autologin drop-in written, console arguments in GRUB and on the running kernel |
| `bwrap_present= ca_certificates=` | the installs that follow `apt-get update` |
| `egress_mode=hostproxy guest_addr= default_routes= nameservers= proxy_env=` | the static address landed on `eth0`, no route, no resolver, the proxy variable is in `/etc/environment` |
| `egress_unit_enabled= ipv6_disabled= proxy_reachable=` | the lockdown unit, IPv6 off, and a TCP connect to the proxy port |
| `egress-lockdown start mode=hostproxy` / `egress_lockdown=hostproxy-applied tool=nft\|iptables rc=` / `egress_lockdown=skipped` | from the lockdown script (the same block the Disk seeds carry), when its unit runs |
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
