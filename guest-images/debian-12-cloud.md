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
> (`firefox.psd1`). It replaces the COM1-serial command channel with the **disk-passing model**:
> the host creates +
> host-formats two exFAT data disks (label **`INPUT`**, label **`OUTPUT`**), populates `INPUT`
> from the profile's `Inputs`, attaches both **before the seal**, then starts the VM. The guest
> mounts them by LABEL, runs the workload, writes its result + an exit-code sentinel to `OUTPUT`,
> flushes (`umount`), and **self-powers-off**. The host polls `State == Off`, detaches, reads, and
> classifies (`Wait-WorkloadComplete` → `Read-WorkloadResult` in `scripts/lib/Workload.ps1`).

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
# NO package_update / packages / apt — sealed guest, no network. The image already
# contains the workload's runtime (e.g. python3). The workload + its inputs arrive on
# the INPUT data disk; results go to the OUTPUT data disk; the guest self-powers-off.

write_files:
  - path: /usr/local/sbin/vmdep-workload
    permissions: '0755'
    content: |
      #!/bin/sh
      # Voidseal disk-mode workload runner. Mounts the host-pre-formatted exFAT data disks by
      # LABEL, runs the workload AS A NON-ROOT USER, writes result + exit-code sentinel to the OUTPUT
      # disk, flushes (umount), and powers off. The host reads result.html + result.exitcode. The
      # runner itself is root (mount/umount/poweroff need it); only the workload entrypoint drops to
      # the unprivileged 'sandbox' user (created in the image build, §2 above).
      set +e
      # Resolve the unprivileged run-user. If it's missing (misconfigured image), uid/gid fall back
      # to 0 and the entrypoint runs as root below (degraded, but the run still completes) — a missing
      # user must not silently fail the run.
      SBX_UID=$(id -u sandbox 2>/dev/null || echo 0)
      SBX_GID=$(id -g sandbox 2>/dev/null || echo 0)
      modprobe exfat 2>/dev/null   # host-pre-formatted exFAT; in-kernel since 5.7. No mkfs in guest.
      mkdir -p /mnt/in /mnt/out
      # The INPUT/OUTPUT SCSI data disks are not in fstab, so nothing ordered this unit after they were
      # enumerated; settle udev so mount-by-LABEL resolves /dev/disk/by-label reliably on first boot.
      udevadm settle 2>/dev/null
      # exFAT is not POSIX — file ownership comes from the uid=/gid= mount options. Own both volumes by
      # the sandbox user so the non-root entrypoint can read /mnt/in and write /mnt/out. (root still
      # writes the sentinel below regardless — root bypasses the ownership check.)
      mount -o ro,uid=$SBX_UID,gid=$SBX_GID LABEL=INPUT  /mnt/in   2>/dev/null
      mount -o    uid=$SBX_UID,gid=$SBX_GID LABEL=OUTPUT /mnt/out  2>/dev/null
      # If OUTPUT didn't mount there's nowhere to write the sentinel -> power off so the host stops
      # waiting (it classifies Failed: no sentinel). The `exit` is LOAD-BEARING: systemd `poweroff` is
      # ASYNCHRONOUS and returns 0, so WITHOUT it the script would keep running against an unmounted
      # /mnt/out and write into the live rootfs during the shutdown window (undefined behavior).
      if ! mountpoint -q /mnt/out; then poweroff; exit 0; fi
      # If INPUT didn't mount, the workload can't read its inputs (the entrypoint itself lives on
      # /mnt/in). Record a clear non-zero sentinel on OUTPUT so the host classifies Failed with a
      # determinate exit code, flush, and power off.
      if ! mountpoint -q /mnt/in; then printf '%s' 70 > /mnt/out/result.exitcode; sync; umount /mnt/out 2>/dev/null; poweroff; exit 0; fi
      # --- run the workload ONCE, as the unprivileged sandbox user (the seed builder substitutes
      # __ENTRYPOINT__ from the profile). The entrypoint MUST write its own result to
      # /mnt/out/result.html (the firefox organizer does, via --out /mnt/out/result.html). The runner
      # does NOT redirect stdout into result.html: capturing stdout there WHILE the script also opens
      # it via --out is a double-write (undefined order; can 0-byte or corrupt the required Netscape-
      # HTML). stdout/stderr go to SEPARATE logs for diagnosis (the host ignores them). NOTE: the
      # entrypoint is run via `sh -c '<entrypoint>'`, so it must not contain a single quote. ---
      if id -u sandbox >/dev/null 2>&1; then
        runuser -u sandbox -- /bin/sh -c '__ENTRYPOINT__' > /mnt/out/stdout.log 2> /mnt/out/stderr.txt
      else
        # No 'sandbox' user in the image — degrade to a root run (prior behavior) rather than failing.
        /bin/sh -c '__ENTRYPOINT__' > /mnt/out/stdout.log 2> /mnt/out/stderr.txt
      fi
      rc=$?
      # --- write the sentinel LAST, after the result is on disk (root; bypasses the exFAT uid owner) ---
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
  # --no-block is LOAD-BEARING. runcmd runs inside cloud-final.service; a BLOCKING `systemctl start`
  # of this oneshot would make cloud-final WAIT for the unit's ExecStart — which ends in `poweroff`,
  # SIGTERM-ing the very cloud-final that is blocked on it and racing the script's own sync/umount
  # against the systemd shutdown sweep (a truncated/empty result.html risk). --no-block lets the unit
  # run INDEPENDENTLY so poweroff is its own last act, not one cloud-final is synchronously blocked on.
  - [ systemctl, start, --no-block, vmdep-workload.service ]
```

### The mount → run → sentinel → umount → poweroff sequence (what the runner guarantees)

1. `modprobe exfat` self-check (best-effort; the in-kernel `exfat` module also auto-loads on the
   first `mount`, so a failed `modprobe` is not fatal — the `mount` below still tries). On total
   exFAT unavailability the `OUTPUT` mount fails, no sentinel is ever written, and the host classifies
   `Failed` with a clear reason (the design's FAT32 fallback is a one-knob switch on the host
   `FileSystem` default + this not needing any guest change since both are in-kernel).
2. `mount -o ro,uid=…,gid=… LABEL=INPUT /mnt/in` — INPUT is mounted **read-only** and **owned by the
   `sandbox` user** (exFAT is non-POSIX, so ownership is a mount option). The workload never writes its
   inputs; it reads a copy and emits a fresh result.
3. `mount -o uid=…,gid=… LABEL=OUTPUT /mnt/out` — OUTPUT is mounted **read-write**, also owned by
   `sandbox` so the non-root entrypoint can write to it. If it did not mount there is nowhere to write
   the sentinel, so the runner powers off immediately **and `exit`s** (systemd `poweroff` is async and
   returns 0 — without the `exit` the script would run on against an unmounted `/mnt/out`); the host
   (correctly) classifies `Failed` (no sentinel) rather than hanging. A failed **INPUT** mount writes a
   determinate non-zero sentinel (the entrypoint can't run) then powers off.
4. Run the workload **exactly once, as the unprivileged `sandbox` user** (`runuser -u sandbox -- sh -c
   '__ENTRYPOINT__'`; falls back to a root run only if the image has no `sandbox` user). The entrypoint
   **writes its own** result to `/mnt/out/result.html` (firefox: `--out /mnt/out/result.html`); the
   runner captures stdout/stderr to **separate** `/mnt/out/stdout.log` + `/mnt/out/stderr.txt` (the host
   ignores them) — it does **NOT** redirect stdout into `result.html`, which would double-write the file
   the entrypoint already owns and could 0-byte/corrupt the required Netscape-HTML.
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
