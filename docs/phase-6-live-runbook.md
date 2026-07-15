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

- **ELEVATED session only** (Hyper-V Administrators group membership required for the host-side
  `New-VMSwitch` / `New-NetNat` / `New-NetFirewallRule` operations this runbook prescribes).
- **Allen-run only. NEVER unattended.** This is the first live egress in the project — the host stops
  being a passive test harness and starts making real outbound network decisions on real hardware.
- **Scope: the first LIVE Tier-1 builder round-trip only.** Tier 2 (disposable no-net) and Tier 3
  (airgapped detonation) stay gated behind an explicit, separate verified-isolation green-light — this
  runbook does not arm them (`docs/operator-runbook.md` §3, "Tier 2/3 — not armed this round," is
  unaffected by this doc).
- Nothing in §§2–4 below is implemented as live-enforced code today. §2 (host egress) and §3 (qemu-img
  confinement) are host-side / native-shim mechanisms that sit outside the mock-green PowerShell+Pester
  engine by design (`progress.md`: "host egress enforcement is live-only... qemu confinement REAL shim is
  NOT mock-green"). §4 lists which seal-time assertions are shipped today vs. remain a live-only add.

---

## 2. Host egress enforcement sequence

*Source: Pass A §Q2. Every cmdlet below is marked CONFIRMED in Pass A for Windows 11 client Hyper-V — none
of the fabrication-watch items in Pass A's kill-list (`New-VMSwitch -SwitchType NAT`, `Set-VMFirewall`)
appear here.*

The goal: move egress enforcement to the **host**, so the untrusted Tier-1 guest is no longer the thing
policing its own network access. In sequence:

1. **`New-VMSwitch -SwitchType Internal`** — a dedicated Internal switch, NOT the built-in Default Switch
   (Pass A: `-SwitchType` accepts only `Internal`/`Private`; External is implicit via `-NetAdapterName`).
   Real Tier-1 provisioning already names its switch `"<vm>-int"` (`scripts/lib/Provisioner.ps1`), never
   "Default Switch" — this sequence must preserve that.
2. **Static host-gateway IP** on the switch's `vEthernet (X)` vNIC via `New-NetIPAddress -InterfaceIndex`.
   The builder VM gets exactly one vNIC and one default route: the host gateway IP.
3. **`New-NetNat -InternalIPInterfaceAddressPrefix`** for the builder subnet. NAT is client-supported on
   Win10/11 (not Server-only, Pass A CONFIRMED) and gives reachability only — it is not the filter. There
   is a one-NAT-network-per-host hard limit (Docker Desktop / WSL contend for the slot); detect an
   existing NAT first via **`Get-NetNat`** before creating a new one.
4. **Host default-DROP** on the gateway vNIC via **`New-NetFirewallRule`**: allow ONLY TCP to the Squid
   IP:port; drop UDP/443 (QUIC), UDP/53 (DNS), TCP/853 (DoT), and everything else. This is SEC-2's
   default-DROP moved from the guest to the host (the builder seed's in-guest default-DROP is already
   mock-shipped — `1e6f594` et seq. per `progress.md` — but an in-guest rule is not a containment
   boundary; see the callout below).
5. **Host-run transparent Squid SNI-splice** as the domain-ACL enforcement point, outside the guest trust
   domain: `ssl_bump` peek/splice + `ssl::server_name` (Squid 3.5+, CONFIRMED) for a domain allowlist
   without decryption, plus an explicit-deny `on_unsupported_protocol` terminal rule (Pass A: the real
   actions are `tunnel`/`respond`, not the loose "=terminate" phrasing some models used — the terminal
   rule must be an explicit deny/respond, not a bare "terminate"). Prefer explicit-proxy config in the
   guest + host ACLs blocking all non-proxy 80/443 over transparent TPROXY/NAT redirection (Pass A: TPROXY
   /NAT redirection is fragile on Windows). Pass A §Q3 additionally flags that the splice never validates
   the origin cert, and that ECH (RFC 9849, Proposed Standard) blinds passive SNI inspection for
   ECH-capable clients — so the Squid config must actively strip/deny ECH-bearing ClientHellos, not just
   passively read SNI, to keep the ACL meaningful.
6. **Defense-in-depth**: also set **`Add-VMNetworkAdapterExtendedAcl`** deny-all-except-proxy-IP on the VM
   NIC. This runs at the vSwitch **port** regardless of switch type (L3/L4 5-tuple only, no SNI) — so
   evasion now requires breaking both the vSwitch port ACL and the host firewall, two independent
   controls.

**State plainly (Pass A, direct):** this moves enforcement to the **host** — the guest no longer polices
itself. The in-guest iptables default-DROP and in-guest Squid SNI proxy that the builder seed already
ships (mock-shape today) are belt-and-braces, not the boundary: a compromised guest with code-execution
can flush its own `iptables` rules or kill its own Squid process, so the untrusted principal cannot be
trusted to police itself, by construction (`SECURITY.md` makes the identical point today about the
in-guest layer).

---

## 3. qemu-img confinement shim

*Source: Pass B §Q4. This is the real mechanism behind `Invoke-ConfinedQemu`
(`scripts/lib/HyperVBackend.ps1:673`), which today is a v1 pass-through seam — every native `qemu-img
convert` call is routed through it, AST-pinned by test, but nothing yet confines the child process.*

- **Threat framing (honest, per Pass B):** of the ~12 CVE IDs the fleet initially attached to QEMU's VHDX
  parser, exactly one is genuine — **`CVE-2014-0148`**, and it is a **DoS** (crash/hang, missing BAT
  bounds check), fixed at QEMU 2.0 — NOT an RCE. The real concern for the live convert step is the
  **undiscovered-bug class**: an unpatched memory-safety bug in an offline parser handling adversarial
  bytes. Do not cite or imply a catalogued RCE CVE for qemu-img's VHDX parser; none exists.
- **Version floor = patch-currency, not CVE-derived.** Re-resolve the current stable qemu-img at fire
  time; the floor's justification is "run a currently-patched build," not a specific VHDX-parser CVE fix
  (there is only the one, ancient, DoS fix).
- **Pin qemu-img by SHA-256** (`Resolve-QemuImg -PinnedSha256`, `scripts/lib/HyperVBackend.ps1:614`).
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
| Single-NIC invariant | live-only addition (not yet asserted) |
| NIC's switch `SwitchType == Internal` | **SHIPPED, mock-green** — `Assert-Sealed`, `scripts/lib/Sealer.ps1:720` |
| By-name refusal of the built-in "Default Switch" | **SHIPPED, mock-green, this slice** — `scripts/lib/Sealer.ps1:739` (commit `3c3a944`) |
| No-uplink (`NetAdapterInterfaceDescription == null`) | live-only addition (not yet asserted) |
| Host-gateway-IP pin | live-only addition (not yet asserted) |
| Firewall-baseline export/diff | live-only addition (not yet asserted) |
| Refuse the Default-Switch by its immutable GUID `c08cb7b8-9b3c-408e-8e30-5e16a3aeb444` | **LIVE Phase-6 addition, tracked, not shipped** — the fake backend does not model a switch `.Id`, so this cannot be mock-verified; the name-based refusal above is the mock-verifiable control this project ships today. The friendly name "Default Switch" can be localized on non-English Windows — the GUID is stable and is the correct control for a non-English host. |

The by-name Default-Switch refusal is real, host-verified, seal-time code today (see `SECURITY.md` and
`docs/operator-runbook.md` for the full writeup of what it does and does not guarantee). It is a
switch-**isolation** control, not egress **filtering** — §2 above is the filtering layer, and it remains
entirely live-only. The GUID-by-Id hardening is the one remaining live addition to the switch-identity
check itself; the rest of this table (single-NIC, no-uplink, gateway-IP pin, firewall-baseline diff) are
net-new live-only assertions, none of which exist in the mock-green engine today.

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
- **Real Squid domain-ACL packet behavior.** The builder seed's Squid egress config (SEC-2, mock-shipped
  per `progress.md`: default-DROP + minimal allow-list, `BlockProtocols` enforced by construction,
  DoH/DoT/QUIC dropped) is asserted at the level of seed **shape** only — the seed template is correct,
  but no test has observed a real Squid process actually splicing/dropping real packets. The first live
  fetch is what proves the ACL behaves as configured.

Until every item above has been exercised live, treat the mock-green suite as proof of *shape*
correctness, not proof of live behavior.
