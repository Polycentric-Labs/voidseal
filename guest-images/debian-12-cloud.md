# Guest image recipe — Debian 12 (bookworm) cloud + cloud-init NoCloud

> **This is a RECIPE, not a binary.** It documents how to turn a stock Debian 12 cloud
> image into the `debian-12-cloud` guest the Tier-1 profile names, and how to build the
> first-boot **NoCloud `CIDATA` seed ISO** that provisions it with **no network**.

The Tier-1 isolation contract (`tier-profiles/tier1.psd1`) declares:

```powershell
GuestImage         = 'debian-12-cloud'
SecureBootTemplate = 'MicrosoftUEFICertificateAuthority'
ManagementChannel  = 'Com1Serial'        # PowerShell Direct is Windows-guest-ONLY
```

so the guest must be a **Debian 12 Gen2 VM** that (a) Secure-Boots under the Linux UEFI
CA template, and (b) is reachable over a **COM1 named-pipe serial console** — because the
sealed VM has no NIC and PowerShell Direct does not work against a Linux guest.

---

## 1. Get a Debian 12 cloud `.vhdx`

Debian publishes official **genericcloud** images (cloud-init baked in, no interactive
installer). They ship as `.qcow2`/`.raw`; Hyper-V needs **`.vhdx`**.

1. Download a Debian 12 `genericcloud` image from `https://cloud.debian.org/images/cloud/bookworm/`
   (the `genericcloud` variant — it has `cloud-init` and the `hyperv` kernel modules; the
   `generic` variant also works).
2. Convert to a **fixed or dynamic VHDX** (qemu-img, run on the host or in WSL):
   ```bash
   qemu-img convert -f qcow2 -O vhdx debian-12-genericcloud-amd64.qcow2 debian-12-cloud.vhdx
   ```
   Keep this as the **golden parent disk**; pass its path to `Invoke-Voidseal -ParentDiskPath`
   so each run gets a differencing child (the provisioner builds the system disk from it).
3. **Secure Boot gotcha:** the image must contain **`grub-efi-amd64-signed`**
   (Debian's MS-signed shim/grub). The official cloud images include it; if you rebuild a
   custom image, do **not** strip it with `--no-install-recommends` or Secure Boot fails to
   boot. The provisioner always provisions with **Secure Boot ON** (`SetFirmware` is called
   with `EnableSecureBoot=$true`, hardcoded — there is **no** `Invoke-Voidseal`/`New-SandboxVM`
   CLI flag to turn it off); disabling it for a disposable tier would mean editing the
   profile / provisioner, not passing a parameter. The verified-correct *enabled* path is the
   `MicrosoftUEFICertificateAuthority` template.

> **Fallback path (documented, not preferred):** a Debian **netinst ISO + preseed**
> (`auto=true priority=critical` + `file=/cdrom/preseed.cfg` baked into a remastered ISO)
> is fully hands-off but heavier (runs the full d-i installer). NoCloud is the v1 default.

---

## 2. The NoCloud `CIDATA` seed ISO (first-boot provisioning, no network)

cloud-init's **NoCloud** datasource reads config from a small attached disk/ISO **with no
network access**. The rules that MUST be exact (getting them wrong = the datasource is
silently skipped):

- The ISO's **filesystem volume label is exactly `CIDATA`** (uppercase). This is
  case-sensitive and non-negotiable.
- Filesystem is **iso9660 or vfat**.
- Root-level files: **`meta-data`** (required — holds `instance-id`) and **`user-data`**
  (the cloud-config). Optional: `network-config`, `vendor-data`.

The seed ISO is the natural **one-way IN** channel (a Hyper-V DVD drive is read-only to the
guest), and it is also what the importer uses for asset staging.

### `meta-data`

```yaml
instance-id: vmdeployer-sandbox-001
local-hostname: sandbox
```

### `user-data` (the v1 Tier-1 baseline)

This enables the **COM1 serial console** (the host's command channel), creates a
**non-root run-user**, and installs **bubblewrap** for the in-guest defense-in-depth the
tier-1 control names. Packages/repo for a specific workload (e.g. Ralph) are staged
*before the seal* over the still-open allowlist; this file just brings the guest up.

```yaml
#cloud-config

# --- non-root run-user (the workload never runs as root) ---
users:
  - name: sandbox
    groups: [sudo]
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    lock_passwd: true        # no password login; serial console + key only

# --- COM1 serial-getty so the host named-pipe console gets a login ---
# The host attaches `\\.\pipe\<vm>-com1` via Set-VMComPort; the guest must
# run a getty on ttyS0 for that pipe to reach an interactive login with NO NIC.
write_files:
  - path: /etc/default/grub.d/99-serial.cfg
    content: |
      GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"
      GRUB_TERMINAL="console serial"
      GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"

runcmd:
  # Re-generate grub so the serial console params take effect on next boot.
  - update-grub
  # Enable a login on the COM1 serial line (ttyS0) — the host's command seam.
  - systemctl enable serial-getty@ttyS0.service
  - systemctl start  serial-getty@ttyS0.service
  # Defense-in-depth: bubblewrap present for the native-bwrap control.
  - [ apt-get, update ]
  - [ apt-get, install, -y, bubblewrap, ca-certificates ]

# Tier-1 keeps egress credential-FREE; no secrets are ever written here.
# Packages/repo for a specific workload are staged before the seal, not here.
```

### Build the seed ISO on the host

Use any ISO builder that lets you set the volume label to `CIDATA`. Two common options:

```powershell
# Option A — oscdimg (Windows ADK): -l<LABEL> sets the volume label.
oscdimg.exe -lCIDATA -m -n C:\sandbox\seed-src C:\sandbox\assets\cidata-seed.iso
#   where C:\sandbox\seed-src\ contains: meta-data, user-data [, network-config]
```

```bash
# Option B — genisoimage / mkisofs (WSL or Linux): -V sets the volume label.
genisoimage -output cidata-seed.iso -volid CIDATA -joliet -rock meta-data user-data
```

Attach it read-only to the VM as a DVD drive (`Set-VMDvdDrive`), boot once so cloud-init
consumes it, then it is detached as part of the import-then-seal ritual.

---

## 2a. Disk-mode workload runner

> **This is the `user-data` the seed builder emits for a `WorkloadMode = 'Disk'` profile**
> (`firefox.psd1`). The canonical emitter is **`New-CidataSeed`** (`scripts/lib/SeedBuilder.ps1`,
> dot-sourced by `scripts/Invoke-Voidseal.ps1`): it holds this runner as a template, substitutes the
> profile's `Entrypoint` for `__ENTRYPOINT__`, and writes the `CIDATA` ISO via built-in Windows IMAPI2.
> The block below is the human-readable mirror of that template
> (`SeedBuilder.ps1`'s `$script:CidataDiskRunnerTemplate` is the source of truth that actually ships in a
> seed). It replaces the COM1-serial command channel with the **disk-passing model**: the host creates +
> host-formats two exFAT data disks (label **`INPUT`**, label **`OUTPUT`**), populates `INPUT`
> from the profile's `Inputs`, attaches both **before the seal**, then starts the VM. The guest
> mounts them by LABEL, runs the workload, writes its result + an exit-code sentinel to `OUTPUT`,
> flushes (`umount`), and **self-powers-off**. The host polls `State == Off`, detaches, reads, and
> classifies (`Wait-WorkloadComplete` → `Read-WorkloadResult` in `scripts/lib/Workload.ps1`).
>
> **Live-acceptance updates (2026-06-24 — see `_dev/2026-06-24-live-acceptance-findings.md`):** the
> shipped runner now also (RC2) **creates the non-root `sandbox` user** via a cloud-config `users:` block
> (the golden image has none); (RC4) **mounts robustly** — tries the `uid=/gid=` mount then **falls back
> to a plain `mount LABEL=…`** (the live cloud kernel failed the uid/gid mount where a plain mount
> worked), tracking whether OUTPUT mounted sandbox-owned so it only runs the entrypoint as `sandbox` when
> that user can actually write; and (RC3) **masks `systemd-networkd-wait-online.service`** in `bootcmd`
> (network is disabled, so its ~47 s wait was pure dead time). The block below is a **verbatim** mirror
> of the shipped template as of that update.

### The contract this runner MUST match (engine defaults — do NOT drift)

These names are the **defaults baked into the host engine** — change them only by also changing
the orchestrator / `Read-WorkloadResult` / `New-WorkloadDisks` defaults, or the host classifies
every run as `Failed` (missing sentinel):

| Thing | Exact value | Where the host enforces it |
|---|---|---|
| INPUT disk volume label | `INPUT` | `New-WorkloadDisks` `InputLabel` default; host `Format-Volume` |
| OUTPUT disk volume label | `OUTPUT` | `New-WorkloadDisks` `OutputLabel` default; host `Format-Volume` |
| Result inner filename | `result.html` | `Read-WorkloadResult -ResultInnerName` default; orchestrator default |
| Sentinel inner filename | `result.exitcode` | `Read-WorkloadResult -SentinelInnerName` default; orchestrator default |
| INPUT mountpoint (guest) | `/mnt/in` | this runner (read-only) |
| OUTPUT mountpoint (guest) | `/mnt/out` | this runner (read-write) |
| Filesystem | exFAT (host-pre-formatted) | `New-WorkloadDisks` `FileSystem` default `exFAT` |

The seed builder substitutes the token **`__ENTRYPOINT__`** in the script body below with the
profile's `Entrypoint`. The profile's `Entrypoint` MUST therefore read its inputs from `/mnt/in`
and write its result to `/mnt/out/result.html` (see `profiles/firefox.psd1`), so the host's
`result.html` default finds the file. The sentinel `result.exitcode` is the guest's **last write** —
the host treats its absence as `Failed` (the workload crashed, hung, or never reached the write),
so it is written only *after* the result is on disk.

### `user-data` (the Disk-mode workload runner)

A systemd `Type=oneshot` unit is used (not a bare `runcmd`) for a single explicit `ExecStart` and so
the workload runs exactly once with `TimeoutStartSec=infinity` (the **host** timeout in
`Wait-WorkloadComplete` is the real bound on a hung guest, not a systemd unit timeout). Ordering of
the INPUT/OUTPUT volumes is NOT via `local-fs.target` — those SCSI data disks are not in `/etc/fstab`,
so `local-fs.target` does not cover them. Instead the runner is triggered LATE (`--no-block` from
`runcmd`, i.e. cloud-init's final stage, long after udev has enumerated the disks) and it `udevadm
settle`s before mounting by LABEL; a failed mount still falls through to the host-classified `Failed`
path, never a hang.

```yaml
#cloud-config
network: {config: disabled}
# Voidseal disk-mode workload seed. NO apt / no network — sealed, offline guest. The image already
# contains the runtime (e.g. python3). The workload + its inputs arrive on the INPUT data disk;
# results go to the OUTPUT data disk; the guest self-powers-off and the host reads the result.

# RC2 (2026-06-24 live): the golden image has NO 'sandbox' user and the disk seed never created one,
# so `runuser -u sandbox` / the uid/gid mount options had no user to own the volumes (SBX_UID fell
# back to 0). Create the non-root sandbox user here, identically to the serial baseline.
users:
  - name: sandbox
    groups: [sudo]
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    lock_passwd: true          # no password login anywhere; this is a sealed offline guest

# RC3 (2026-06-24 live): network is {config: disabled} for this sealed offline guest, yet
# systemd-networkd-wait-online.service still blocked ~47s of every boot for a network that never
# comes up — pure dead time. Mask it EARLY (bootcmd runs before systemd brings the unit up) so the
# wait never happens. Network stays disabled; this only removes the pointless wait.
bootcmd:
  - [ systemctl, mask, --now, systemd-networkd-wait-online.service ]

write_files:
  - path: /usr/local/sbin/vmdep-workload
    permissions: '0755'
    content: |
      #!/bin/sh
      # Voidseal disk-mode workload runner: mount the host-pre-formatted exFAT data disks by LABEL,
      # run the workload as the non-root 'sandbox' user (when the volume is sandbox-owned), write
      # result + an exit-code sentinel to the OUTPUT disk, flush (umount), and power off. The host
      # reads result.html + result.exitcode.
      set +e
      SBX_UID=$(id -u sandbox 2>/dev/null || echo 0)
      SBX_GID=$(id -g sandbox 2>/dev/null || echo 0)
      modprobe exfat 2>/dev/null   # host-pre-formatted exFAT; in-kernel since 5.7. No mkfs in guest.
      mkdir -p /mnt/in /mnt/out
      # The INPUT/OUTPUT SCSI data disks are not in fstab; settle udev so mount-by-LABEL resolves.
      udevadm settle 2>/dev/null
      # RC4 (2026-06-24 live): the uid=/gid= mount options give the non-root entrypoint ownership of the
      # exFAT (non-POSIX) volume, BUT on the live cloud kernel that mount FAILED where a PLAIN mount
      # worked (the serial probe proved `mount LABEL=OUTPUT /mnt/out` succeeds). So mount ROBUSTLY: try
      # the uid/gid mount first, and FALL BACK to a plain mount on failure — OUTPUT must always mount so
      # the result + sentinel can be written. Track whether the sandbox-owned (uid/gid) OUTPUT mount won;
      # only then is it safe to run the entrypoint as the non-root sandbox user (else it can't write).
      mount -o ro,uid=$SBX_UID,gid=$SBX_GID LABEL=INPUT  /mnt/in  2>/dev/null || mount LABEL=INPUT  /mnt/in  2>/dev/null
      # OUTPUT: try the sandbox-owning uid/gid mount; record whether IT won (so we only run the
      # entrypoint as the non-root user when it can actually write), then fall back to a plain mount.
      OUT_SANDBOX_OWNED=0
      if mount -o uid=$SBX_UID,gid=$SBX_GID LABEL=OUTPUT /mnt/out 2>/dev/null; then OUT_SANDBOX_OWNED=1; fi
      mountpoint -q /mnt/out || mount LABEL=OUTPUT /mnt/out 2>/dev/null
      # No OUTPUT -> nowhere to write the sentinel -> poweroff (host classifies Failed: no sentinel).
      # The `exit` is LOAD-BEARING: systemd poweroff is async + returns 0, so without it the script
      # would run on against an unmounted /mnt/out and write into the live rootfs during shutdown.
      if ! mountpoint -q /mnt/out; then poweroff; exit 0; fi
      # No INPUT -> the entrypoint (which lives on /mnt/in) can't run; record a determinate non-zero
      # sentinel so the host classifies Failed with a definite code, flush, power off.
      if ! mountpoint -q /mnt/in; then printf '%s' 70 > /mnt/out/result.exitcode; sync; umount /mnt/out 2>/dev/null; poweroff; exit 0; fi
      # Run the workload ONCE. Prefer the unprivileged 'sandbox' user, but ONLY when OUTPUT is
      # sandbox-OWNED (the uid/gid mount won) AND the user exists — otherwise a non-root run could not
      # write to a root-owned plain-mounted /mnt/out. Fall back to root in every other case (v1: the VM
      # boundary is the containment, not the in-guest user — see the live-acceptance findings RC4).
      # The entrypoint writes its OWN result to /mnt/out/result.html (firefox: --out). stdout/stderr
      # go to SEPARATE logs (the host ignores them) — never redirected into result.html (a double-
      # write with the entrypoint's own --out can 0-byte/corrupt the required Netscape-HTML).
      # NOTE: run via sh -c '<entrypoint>', so the entrypoint must contain no single quote.
      if [ "$OUT_SANDBOX_OWNED" = "1" ] && id -u sandbox >/dev/null 2>&1; then
        runuser -u sandbox -- /bin/sh -c '__ENTRYPOINT__' > /mnt/out/stdout.log 2> /mnt/out/stderr.txt
      else
        /bin/sh -c '__ENTRYPOINT__' > /mnt/out/stdout.log 2> /mnt/out/stderr.txt
      fi
      rc=$?
      # Sentinel LAST (root; bypasses the exFAT uid owner) — its presence means the result is on disk.
      printf '%s' "$rc" > /mnt/out/result.exitcode
      sync
      umount /mnt/out
      # ensure the unmount actually completed (flush) before power-off
      i=0; while mountpoint -q /mnt/out && [ $i -lt 10 ]; do sleep 1; umount /mnt/out 2>/dev/null; i=$((i+1)); done
      poweroff

  - path: /etc/systemd/system/vmdep-workload.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Voidseal disk-mode workload
      After=local-fs.target
      [Service]
      Type=oneshot
      ExecStart=/usr/local/sbin/vmdep-workload
      TimeoutStartSec=infinity
      [Install]
      WantedBy=multi-user.target

runcmd:
  - [ systemctl, daemon-reload ]
  # --no-block is LOAD-BEARING: a blocking start would make cloud-final WAIT on a oneshot that ends
  # in poweroff (SIGTERM-ing the very cloud-final blocked on it, racing the result flush). --no-block
  # lets the unit run independently so poweroff is its own last act.
  - [ systemctl, start, --no-block, vmdep-workload.service ]
```

### The mount → run → sentinel → umount → poweroff sequence (what the runner guarantees)

1. `modprobe exfat` self-check (best-effort; the in-kernel `exfat` module also auto-loads on the
   first `mount`, so a failed `modprobe` is not fatal — the `mount` below still tries). On total
   exFAT unavailability the `OUTPUT` mount fails, no sentinel is ever written, and the host classifies
   `Failed` with a clear reason (the design's FAT32 fallback is a one-knob switch on the host
   `FileSystem` default + this not needing any guest change since both are in-kernel).
2. `mount -o ro,uid=…,gid=… LABEL=INPUT /mnt/in || mount LABEL=INPUT /mnt/in` — INPUT is mounted
   **read-only**, *preferring* the `sandbox`-owning `uid=/gid=` form (exFAT is non-POSIX, so ownership is
   a mount option) but **falling back to a plain mount** if the uid/gid form fails on the live kernel
   (RC4). The workload never writes its inputs; it reads a copy and emits a fresh result.
3. OUTPUT mounts **robustly** (RC4): the runner first tries the `sandbox`-owning
   `mount -o uid=…,gid=… LABEL=OUTPUT /mnt/out` and records whether **that** form won
   (`OUT_SANDBOX_OWNED=1`), then `mountpoint -q /mnt/out || mount LABEL=OUTPUT /mnt/out` **falls back to a
   plain mount** so OUTPUT mounts even where the live cloud kernel rejects the uid/gid options. OUTPUT
   must always mount — it is the only place the result + sentinel can be written. If it did not mount at
   all there is nowhere to write the sentinel, so the runner powers off immediately **and `exit`s**
   (systemd `poweroff` is async and returns 0 — without the `exit` the script would run on against an
   unmounted `/mnt/out`); the host (correctly) classifies `Failed` (no sentinel) rather than hanging. A
   failed **INPUT** mount writes a determinate non-zero sentinel (the entrypoint can't run) then powers
   off.
4. Run the workload **exactly once**. The runner runs the entrypoint as the unprivileged `sandbox` user
   (`runuser -u sandbox -- sh -c '__ENTRYPOINT__'`) **only when OUTPUT mounted sandbox-owned AND that
   user exists** (`[ "$OUT_SANDBOX_OWNED" = "1" ] && id -u sandbox`); in every other case — including the
   plain-mount fallback, where `/mnt/out` is root-owned and a non-root run could not write to it — it
   **falls back to a root run** (v1: the VM boundary is the containment, not the in-guest user — see RC4).
   The entrypoint **writes its own** result to `/mnt/out/result.html` (firefox: `--out
   /mnt/out/result.html`); the runner captures stdout/stderr to **separate** `/mnt/out/stdout.log` +
   `/mnt/out/stderr.txt` (the host ignores them) — it does **NOT** redirect stdout into `result.html`,
   which would double-write the file the entrypoint already owns and could 0-byte/corrupt the required
   Netscape-HTML.
5. **Write the sentinel LAST**: `printf '%s' "$rc" > /mnt/out/result.exitcode` (as root — bypasses the
   exFAT uid owner). Writing it after the result guarantees that a present sentinel means the result is
   already on disk. `sync` flushes.
6. **`umount /mnt/out` then verify it actually unmounted** (the bounded retry loop re-tries up to 10×
   at 1 s each). umount-before-poweroff is the design's **durability requirement** — it forces the
   exFAT volume's dirty pages to flush before power is cut, so the host reads a consistent disk.
7. `poweroff` — the guest self-powers-off. Because the unit is started `--no-block` (not synchronously
   from `cloud-final`), this poweroff is the unit's own last act and does not race a blocked
   `cloud-final`. The host learns completion by polling `State == Off` (`Wait-WorkloadComplete`); there
   is no live host↔guest channel after the seal.

### `meta-data` (Disk mode)

Unchanged from §2 — the same `instance-id` / `local-hostname` pair. NoCloud still requires both
`meta-data` and `user-data` at the seed ISO root with the volume label `CIDATA`.

### `ds=nocloud` delivery (boot-speed tunable — not a correctness blocker)

To skip cloud-init's multi-datasource probe (a 2–5 min delay on some boots), pin the datasource on
the **guest kernel cmdline**: `ds=nocloud`. Two delivery paths, both decided **at image-prep** (not
at run time — the sealed guest takes no run-time config beyond the seed):

- **Guest GRUB (baked at image-prep):** append `ds=nocloud` to `GRUB_CMDLINE_LINUX` in
  `/etc/default/grub.d/` and `update-grub`, so every boot of the golden parent disk pins NoCloud.
- **SMBIOS serial (host-set):** Hyper-V can set the SMBIOS system serial to `ds=nocloud;s=...`;
  cloud-init reads `ds=` from SMBIOS. This needs no guest edit but is a Hyper-V firmware tweak.

Either way it is **only a speed tunable**: the host `Wait-WorkloadComplete` timeout bounds even a
slow datasource-probe boot, so getting this wrong slows a run, it does not break one. Lean on the
GRUB-baked path for the golden image; settle empirically on the first live boot.

---

## 3. The Gen2 + Secure Boot + COM1 hardware shape

The provisioner sets this from the tier profile (it goes through the T2 backend, never a
raw cmdlet). For reference, the equivalent raw Hyper-V calls are:

```powershell
# Gen2 VM (UEFI), Linux Secure Boot template, COM1 over a host named pipe.
Set-VMFirmware -VMName $vm -SecureBootTemplate MicrosoftUEFICertificateAuthority
Set-VMComPort  -VMName $vm -Number 1 -Path "\\.\pipe\$vm-com1"   # the serial command seam
# (Tier 1: Internal vSwitch + in-guest nftables; Tier 2/3: NO NIC at all.)
```

The host reads/writes `\\.\pipe\<vm>-com1` with a pipe-aware serial client to drive the
guest — the no-NIC equivalent of PowerShell Direct. Hyper-V **KVP / `hv_utils`** is
optional metadata transport only (not an interactive shell).

---

## 4. Import-then-seal ritual (asset staging)

For one-way asset import on Win11 Pro Hyper-V, the reliable sequence is **VM-off, no active
checkpoints, single-attach VHDX**:

1. (VM off) attach the read-only **`CIDATA` seed ISO** (`Set-VMDvdDrive`) and any inbound
   **transfer-VHDX** (`Add-VMHardDiskDrive`).
2. Boot → cloud-init provisions + the importer stages packages/repo (over the still-open
   allowlist) → `Test-AssetIntegrity` (hash/sig verify in-guest).
3. Shut down → `Remove-VMDvdDrive` / `Remove-VMHardDiskDrive` (detach releases the lock).
4. For sealed tiers: `Lock-Sandbox` removes the NIC + disables host channels, then
   `Assert-Sealed` certifies from the **host** side before the workload runs.

> A `.vhdx` attaches to only one running VM at a time; SCSI hot-add needs Gen2; do
> attach/detach on a VM with no active checkpoints so the seal stays deterministic.

---

## 5. Pins to track (soft — pin at build time)

- Debian point release (bookworm 12.x — track upstream cloud image).
- `cloud-init` version in the image (NoCloud datasource behavior is stable, but pin it).
- `grub-efi-amd64-signed` present (Secure Boot dependency).
- For the Ralph workload specifically: the **`claude` CLI ≥ 2.0.76** + a **pinned
  `frankbria/ralph-claude-code` commit SHA** are staged at run time (see `profiles/ralph.psd1`),
  not baked into this base image.

### Disk-mode organizer-script contract (Firefox, live acceptance)

The Firefox Disk-mode workload's organizer script (`organize_bookmarks.py`) rides the **INPUT data
disk** (it is an `Inputs` entry, host-populated onto the `INPUT`-labelled volume — see §2a and
`profiles/firefox.psd1`), so at run time it is at `/mnt/in/organize_bookmarks.py`. To match the
runner above it **MUST**:

- read its `--profile` from **`/mnt/in`** (where the host populated the sample/synthetic profile);
- write its `--out` to **`/mnt/out/result.html`** (the host's `result.html` default — NOT
  `bookmarks.html`, which was the serial/container-era inner name);
- still emit a first line of exactly `<!DOCTYPE NETSCAPE-Bookmark-file-1>` so the export is
  Firefox-importable, and never touch `logins.json` / `key4.db` / `cookies.sqlite`.

The host source `C:\sandbox\organizer-src\organize_bookmarks.py` (referenced by the live-acceptance
populate step) must be a version aligned to these `/mnt/in` + `/mnt/out/result.html` paths. If the
current copy on disk writes `bookmarks.html` or reads a different mount, the live-acceptance step
must use an aligned copy. (Do not edit files outside the skill dir to make this true — this note is
the requirement the live-acceptance step satisfies; the script itself lives in `C:\sandbox\`.)
