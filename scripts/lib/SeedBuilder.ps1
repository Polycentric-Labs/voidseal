<#
.SYNOPSIS
    Voidseal — CIDATA NoCloud seed-ISO builder (the host-side tool that produces the cloud-init seed).

.DESCRIPTION
    Builds the first-boot **NoCloud `CIDATA` seed ISO** a sandbox guest consumes on its FIRST boot.
    Three shapes, selected by the profile's `WorkloadMode` (+ `EgressMode` for the builder variant):

      * DISK-OFFLINE — the disk-passing workload runner (guest-images/debian-12-cloud.md §2a). A
        systemd oneshot mounts the host-pre-formatted exFAT data disks by LABEL (INPUT ro -> /mnt/in,
        OUTPUT rw -> /mnt/out), runs the profile's `Entrypoint` as the non-root `sandbox` user,
        writes `result.html` + the `result.exitcode` sentinel onto OUTPUT, flushes, and self-powers
        off. The seed builder substitutes the profile's `Entrypoint` for the `__ENTRYPOINT__` token.
      * DISK-BUILDER (`WorkloadMode='Disk'` + `EgressMode='SquidSniProxy'`) — the Tier-1 net-restricted
        builder variant: same disk-passing runner PLUS a transparent Squid SNI domain-ACL proxy that
        gatekeeps the guest's 80/443 egress to the `EgressAllowlist` only (substituted into the Squid
        `dstdomain` ACL). Fetches deps over Squid into /mnt/out, writes a manifest, self-powers-off.
      * SERIAL (default) — the §2 baseline: serial-getty AUTOLOGIN on ttyS0 (the Runner's command
        seam, which does NOT authenticate), a non-root run-user, and bubblewrap.

    WHY THIS EXISTS: before this builder there was no code that emitted the disk-mode seed, so the
    on-disk `cidata-seed.iso` was the OLD serial seed — a disk-mode live run would boot to an idle
    login, never run the workload, and the host would (correctly) classify `Failed` (no sentinel).

    DISCIPLINE (mirrors the Hyper-V backend's fake/real injection):
      * Content generation (New-CidataUserData / New-CidataMetaData) is PURE + unit-tested.
      * The ISO write goes through an INJECTABLE writer (`-IsoWriter`). The default is the real
        IMAPI2 (built-in Windows COM) writer `Write-Iso9660Image`; tests inject a fake. So the
        substitution + staging logic is testable with NO IMAPI dependency.

    FAIL-CLOSED: a disk-mode `Entrypoint` is run inside the runner as `sh -c '__ENTRYPOINT__'`. An
    entrypoint containing a single quote (escapes the wrapper) or a newline (breaks the single line)
    or that is blank is REFUSED before any ISO is written.

    LINE ENDINGS: cloud-init user-data embeds a `#!/bin/sh` runner; a CRLF there yields `/bin/sh\r`
    (bad interpreter). Both documents are normalized to LF before they reach the ISO.

    Dot-sourced by scripts/Invoke-Voidseal.ps1 (so `. .\scripts\Invoke-Voidseal.ps1` exposes it).
#>

Set-StrictMode -Version Latest

# --------------------------------------------------------------------------
# Internal: read a field off a profile (hashtable / IDictionary / pscustomobject) with a default.
# --------------------------------------------------------------------------
function Get-SeedProfileField {
    [CmdletBinding()]
    param([AllowNull()] $Profile, [Parameter(Mandatory)] [string] $Name, $Default = $null)
    if ($null -eq $Profile) { return $Default }
    if ($Profile -is [System.Collections.IDictionary]) {
        if ($Profile.Contains($Name) -and $null -ne $Profile[$Name]) { return $Profile[$Name] }
        return $Default
    }
    $p = $Profile.PSObject.Properties[$Name]
    if ($null -ne $p -and $null -ne $p.Value) { return $p.Value }
    return $Default
}

# --------------------------------------------------------------------------
# The DISK-mode workload runner user-data (guest-images/debian-12-cloud.md §2a is its mirror).
# Single-quoted here-string: NOTHING is interpolated by PowerShell ($rc, $SBX_UID, $(...), __ENTRYPOINT__
# all stay literal). The builder substitutes __ENTRYPOINT__ with the profile's Entrypoint.
# --------------------------------------------------------------------------
$script:CidataDiskRunnerTemplate = @'
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
'@

# --------------------------------------------------------------------------
# C1.3: the OutboxOutput disk-mode runner user-data — for a Disk-mode profile that opts into the
# user-space outbox transport (OutboxOutput=$true; firefox post-C1 convergence, see Workload.ps1's
# Raw-OUTPUT predicate). The OUTPUT disk here is Raw (host-formatted with NO filesystem — New-
# WorkloadDisks / NewOutputVhdx FileSystem='Raw'), so unlike CidataDiskRunnerTemplate this runner does
# NOT mount OUTPUT by label (there is nothing to mount). Instead the entrypoint runs into a STAGING
# dir, and the SHARED outbox-producer template (guest/run_disk_workload.py --transport-only) packs
# staging into the memory-safe outbox container (guest/outbox.py) and writes it to the raw OUTPUT
# block device the host later reads USER-SPACE (ReadVhdxRawRegion, never Mount-VHD — Invoke-
# Voidseal.ps1's Read-OutboxToGateInput). --transport-only is LOCKED design (Allen 2026-07-01): this
# profile's result is NOT screened — run_disk_workload.py skips screener.py entirely and packs a
# well-formed placeholder verdicts.json ([]) alongside the result so the SAME container format (and
# the SAME host read path) a processor's screened outbox uses still parses cleanly (guest/outbox.py's
# read_and_verify() unconditionally requires a verdicts.json entry).
#
# run_disk_workload.py + its outbox.py dependency ride the INPUT disk (Inputs/InputFiles), exactly
# like the entrypoint script itself (firefox.psd1's organize_bookmarks.py) — no new delivery
# mechanism; they are read-only-mounted at /mnt/in alongside the workload's own inputs.
#
# RAW-OUTPUT DEVICE IDENTIFICATION: OUTPUT carries no filesystem/label to mount by, so the runner
# identifies it structurally — enumerate the whole-disk block devices, exclude the root/boot disk and
# any INPUT-labelled (exFAT) disk, and take the sole remaining candidate. FAIL-CLOSED: if that does
# not resolve to EXACTLY ONE candidate device, the runner powers off with no outbox written (mirrors
# the "no OUTPUT -> poweroff" guard in the exFAT runner above).
#
# Single-quoted here-string: NOTHING is interpolated by PowerShell ($rc, $(...), __ENTRYPOINT__ all
# stay literal). The builder substitutes __ENTRYPOINT__ with the profile's Entrypoint.
# --------------------------------------------------------------------------
$script:CidataOutboxDiskRunnerTemplate = @'
#cloud-config
network: {config: disabled}
# Voidseal OutboxOutput disk-mode seed (C1.3). NO apt / no network — sealed, offline guest. The
# workload's inputs (+ the shared outbox-producer template) arrive on the INPUT data disk; the
# result is packed into a memory-safe outbox and written to the raw OUTPUT data disk (no filesystem);
# the guest self-powers-off and the host reads the outbox user-space (never Mount-VHD).

users:
  - name: sandbox
    groups: [sudo]
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    lock_passwd: true          # no password login anywhere; this is a sealed offline guest

# Network stays disabled; mask the pointless wait-online delay (same as the exFAT offline runner).
bootcmd:
  - [ systemctl, mask, --now, systemd-networkd-wait-online.service ]

write_files:
  - path: /usr/local/sbin/vmdep-workload
    permissions: '0755'
    content: |
      #!/bin/sh
      # Voidseal OutboxOutput disk-mode runner: mount the host-formatted exFAT INPUT disk read-only,
      # run the entrypoint into a STAGING dir, then hand staging to the shared outbox-producer
      # template (run_disk_workload.py --transport-only), which packs it into the outbox container
      # and writes it to the raw OUTPUT block device. No OUTPUT filesystem is ever mounted/formatted.
      set +e
      # SERIAL DIAGNOSTICS (D4-D live-debug observability). Every fail-closed branch below is otherwise
      # a SILENT `poweroff; exit 0`, and this runner's logs die with the ephemeral rootfs — so the raw-
      # device path's first live test failed with zero guest-side signal. diag() narrates each decision
      # to the serial console (this image boots console=ttyS0 -> host COM1 pipe) so a live capture pins
      # the failing branch. STRUCTURAL ONLY: device nodes, mount y/n, the candidate list + count, the
      # producer exit code, staging file COUNT, and the outbox's 8-byte container magic — NEVER staged
      # file bytes. This runner is SHARED with the processor (screener-governed release); echoing
      # candidate CONTENT here would be a covert guest->host channel bypassing the screener, so diag()
      # is confined to control-flow facts. Never alters control flow: runs under `set +e`, writes to
      # /dev/console (always present) and swallows any error.
      diag() { echo "[voidseal-diag] $*" > /dev/console 2>/dev/null; }
      diag "outbox-runner start"
      SBX_UID=$(id -u sandbox 2>/dev/null || echo 0)
      SBX_GID=$(id -g sandbox 2>/dev/null || echo 0)
      modprobe exfat 2>/dev/null   # host-pre-formatted INPUT is exFAT; in-kernel since 5.7.
      mkdir -p /mnt/in /run/staging
      # The INPUT/OUTPUT SCSI data disks are not in fstab; settle udev so mount-by-LABEL + blkid resolve.
      udevadm settle 2>/dev/null
      mount -o ro,uid=$SBX_UID,gid=$SBX_GID LABEL=INPUT /mnt/in 2>/dev/null || mount LABEL=INPUT /mnt/in 2>/dev/null
      # No INPUT -> the entrypoint (which lives on /mnt/in) AND the producer script cannot run. There
      # is no OUTPUT filesystem to record a determinate sentinel on, so simply power off (the host's
      # outbox read fails closed on a missing/empty raw region — same DENY-on-absence contract).
      if ! mountpoint -q /mnt/in; then diag "ABORT input-not-mounted (LABEL=INPUT did not mount at /mnt/in - exfat module missing on this kernel? label mismatch?)"; poweroff; exit 0; fi
      diag "input_mounted=yes input_files=$(ls -1 /mnt/in 2>/dev/null | wc -l)"
      chown -R "$SBX_UID:$SBX_GID" /run/staging 2>/dev/null
      # --- Identify the raw OUTPUT block device structurally (no filesystem/label to mount by) ---
      # Candidates = every whole-disk block device MINUS the root/boot disk MINUS any exFAT/INPUT-
      # labelled disk. FAIL-CLOSED: anything other than exactly one remaining candidate -> poweroff,
      # no outbox written (mirrors the exFAT runner's "no OUTPUT -> poweroff" guard above).
      ROOT_SRC=$(findmnt -no SOURCE / 2>/dev/null)
      ROOT_DISK=$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null)
      # PKNAME is empty when the root SOURCE is already a whole disk (no partition) — fall back to
      # its own basename so ROOT_DISK is never blank (a blank ROOT_DISK would match nothing below and
      # wrongly leave the root disk itself as an OUTPUT candidate).
      [ -z "$ROOT_DISK" ] && ROOT_DISK=$(basename "$ROOT_SRC")
      INPUT_SRC=$(blkid -L INPUT 2>/dev/null)
      INPUT_DISK=$(lsblk -no PKNAME "$INPUT_SRC" 2>/dev/null)
      [ -z "$INPUT_DISK" ] && [ -n "$INPUT_SRC" ] && INPUT_DISK=$(basename "$INPUT_SRC")
      # Narrate the exclusion inputs + the RAW sd* enumeration — the exact fresh-image unknowns:
      # does `blkid -L INPUT` resolve (so INPUT is excluded)? do the Hyper-V disks enumerate as sd*?
      diag "root_src=$ROOT_SRC root_disk=$ROOT_DISK input_src=$INPUT_SRC input_disk=$INPUT_DISK"
      diag "sysblock_sd=$(ls /sys/block 2>/dev/null | grep '^sd' | tr '\n' ' ')"
      OUT_CANDIDATES=""
      for d in /sys/block/sd*; do
        dev=$(basename "$d")
        [ "$dev" = "$ROOT_DISK" ] && continue
        [ "$dev" = "$INPUT_DISK" ] && continue
        OUT_CANDIDATES="$OUT_CANDIDATES $dev"
      done
      OUT_CANDIDATES=$(echo "$OUT_CANDIDATES" | xargs)   # trim whitespace
      set -- $OUT_CANDIDATES
      diag "out_candidates=[$OUT_CANDIDATES] count=$#"
      if [ "$#" -ne 1 ]; then diag "ABORT output-candidates-not-1 (need exactly one leftover disk after excluding root+INPUT; got $#: [$OUT_CANDIDATES])"; poweroff; exit 0; fi
      OUTPUT_DEV="/dev/$1"
      diag "output_dev=$OUTPUT_DEV"
      # Run the workload ONCE, into staging (not directly onto OUTPUT — there is no OUTPUT mount).
      # NOTE: run via sh -c '<entrypoint>', so the entrypoint must contain no single quote.
      if id -u sandbox >/dev/null 2>&1; then
        runuser -u sandbox -- /bin/sh -c '__ENTRYPOINT__' > /run/stdout.log 2> /run/stderr.txt
      else
        /bin/sh -c '__ENTRYPOINT__' > /run/stdout.log 2> /run/stderr.txt
      fi
      erc=$?
      # staging file COUNT only (never names/bytes) — did the entrypoint actually produce a result?
      diag "entrypoint_rc=$erc staging_count=$(ls -1 /run/staging 2>/dev/null | wc -l)"
      # The shared outbox-producer template packs /run/staging into the outbox container and writes
      # it to the raw OUTPUT device. --transport-only: no screener invocation (LOCKED design) — a
      # well-formed placeholder verdicts.json rides the outbox so the host read path parses cleanly.
      python3 /mnt/in/run_disk_workload.py --staging /run/staging --verdicts /run/verdicts.json --out "$OUTPUT_DEV" --transport-only 2> /run/producer.err
      prc=$?
      diag "producer_rc=$prc"
      # The producer's stderr is FIXED structural strings (run_disk_workload/outbox raise SystemExit /
      # OutboxError with constant messages + logical names, never candidate bytes), so a bounded tail is
      # safe to surface and is the single most useful signal if the raw WRITE itself failed.
      [ "$prc" -ne 0 ] && diag "producer_err=$(tail -c 400 /run/producer.err 2>/dev/null | tr '\n' '|')"
      # Read back ONLY the outbox's 8-byte container magic from the chosen device (VSOUTBX1 = the
      # pack_outbox header) — proves whether a valid outbox actually landed on OUTPUT_DEV (vs. nothing,
      # or the wrong device). 8 bytes = magic only; no record table, no payload.
      diag "output_head=$(dd if=$OUTPUT_DEV bs=8 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n') (want 56534f5554425831 = VSOUTBX1)"
      sync
      diag "sync+poweroff"
      poweroff

  - path: /etc/systemd/system/vmdep-workload.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Voidseal OutboxOutput disk-mode workload
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
'@

# --------------------------------------------------------------------------
# The BUILDER disk-mode runner user-data — Tier-1 builder VM with a transparent Squid SNI proxy.
# LIVE-only (Phase 6) validates the real network config + ssl_bump/SNI peek + CDN-rotation; the mock
# asserts SHAPE only (the Squid ACL contains each allowlist domain + http_access deny all).
# Single-quoted here-string: NOTHING is interpolated by PowerShell. Two placeholders are substituted:
#   __SQUID_ALLOWLIST_ACL__  -> space-joined EgressAllowlist (dstdomain entries)
#   __ENTRYPOINT__           -> the profile Entrypoint (same sh -c guard as the offline runner)
# Squid dstdomain semantics MATCH Test-AllowlistCoversHost: a bare entry (huggingface.co) matches
# exactly; a dotted entry (.hf.co) matches subdomains — the merged allowlist maps 1:1 onto dstdomain.
# --------------------------------------------------------------------------
$script:CidataBuilderRunnerTemplate = @'
#cloud-config
# Voidseal builder disk-mode seed — Tier-1 net-restricted builder VM (Phase 2.2).
# Network is ENABLED; a transparent Squid SNI proxy gatekeeps 80/443 to the EgressAllowlist only
# (default-deny). The workload fetches deps over Squid into /mnt/out, writes a manifest, and powers
# off. The host reads deps-manifest.json from the OUTPUT disk.

# RC2: create the non-root sandbox user (identically to the serial baseline + offline disk runner).
users:
  - name: sandbox
    groups: [sudo]
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    lock_passwd: true          # no password login anywhere; this is a sealed builder guest

# SEC-2/C3: disable IPv6 BEFORE the network comes up. bootcmd runs on every boot, earlier than
# runcmd/network-config — SLAAC/DHCPv6 (both on-by-default on Debian cloud images) never gets a
# chance to bring up a usable IPv6 route, so there is nothing for a malicious dependency to route
# over. This is the PRIMARY control; the ip6tables default-DROP below is belt-and-braces in case
# disable_ipv6 is ever bypassed or a kernel/module quirk re-enables it.
bootcmd:
  - [ sysctl, -w, 'net.ipv6.conf.all.disable_ipv6=1' ]
  - [ sysctl, -w, 'net.ipv6.conf.default.disable_ipv6=1' ]

write_files:
  - path: /etc/sysctl.d/99-voidseal-noipv6.conf
    permissions: '0644'
    content: |
      # SEC-2/C3: IPv6 disabled for this Tier-1 builder guest. Debian cloud images bring IPv6 up by
      # default (SLAAC/DHCPv6); the egress lockdown below is otherwise IPv4-only and a malicious
      # dependency could egress over IPv6 entirely unfiltered. bootcmd applies this at boot (before
      # network-config); this file makes the setting persist/re-apply across `sysctl --system`.
      net.ipv6.conf.all.disable_ipv6 = 1
      net.ipv6.conf.default.disable_ipv6 = 1

  - path: /etc/squid/squid.conf
    permissions: '0644'
    content: |
      # Voidseal Tier-1 builder Squid SNI proxy — transparent intercept on 3129 (HTTP) + 3130 (HTTPS).
      # LIVE-only (Phase 6): real ssl_bump/SNI peek + CDN-rotation resilience unproven in mock tests.
      http_port 3129 intercept
      https_port 3130 intercept ssl-bump
      acl allowed_domains dstdomain __SQUID_ALLOWLIST_ACL__
      ssl_bump peek all
      ssl_bump splice allowed_domains
      ssl_bump terminate all
      http_access allow allowed_domains
      http_access deny all

  - path: /usr/local/sbin/vmdep-builder
    permissions: '0755'
    content: |
      #!/bin/sh
      # Voidseal builder runner: bring up Squid SNI proxy, mount data disks, run the dep-fetch
      # entrypoint as the non-root 'sandbox' user, write result + sentinel to OUTPUT, power off.
      set +e

      # --- Squid transparent proxy setup ---
      systemctl restart squid 2>/dev/null || true
      # --- Egress lockdown: DEFAULT-DROP OUTPUT + a minimal allow-list (SEC-2) ---
      # tier1 BlockProtocols (QUIC/UDP-443, DoH, DoT) is enforced BY CONSTRUCTION: only the flows below are
      # permitted, so QUIC/UDP-443 and DoT/853 are dropped, and DoH (443) hits Squid's domain-ACL (a DoH
      # resolver isn't in the deps allowlist -> denied). DNS/53 is allowed broadly (UDP+TCP): the transparent
      # proxy needs it to resolve the allowlist domains, and the builder carries ZERO personal data (two-VM
      # split) so DNS-tunnel exfil is a non-threat; the Squid domain-ACL is the real fetch control. Squid was
      # started above (network still open); its own egress (uid proxy) to upstream:80/443 rides the 80/443
      # ACCEPTs, and a REDIRECT'd client connection rides '-o lo'. FAIL-CLOSED: if this setup errors partway,
      # the OUTPUT policy stays DROP -> no egress -> the fetch fails cleanly. IPv6 is disabled at boot
      # (bootcmd, pre-network) AND ip6tables default-DROPs below — this lockdown is no longer IPv4-only
      # (SEC-2/C3: an unfiltered IPv6 route was a complete bypass of both this DROP and the Squid ACL).
      # LIVE-ONLY (Phase 6): real packet-drop is unproven in mock - the seed asserts SHAPE only.
      iptables -F OUTPUT 2>/dev/null
      iptables -P OUTPUT DROP
      iptables -A OUTPUT -o lo -j ACCEPT
      iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
      iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
      iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
      iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
      iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
      # Transparent-proxy REDIRECT of outbound 80/443 through Squid (domain-ACL gatekeeps the fetch); the
      # owner-exclusion keeps Squid's OWN upstream egress from being re-redirected.
      iptables -t nat -A OUTPUT -p tcp --dport 80  -m owner ! --uid-owner proxy -j REDIRECT --to-port 3129
      iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner proxy -j REDIRECT --to-port 3130
      # --- IPv6 belt-and-braces (SEC-2/C3): default-DROP OUTPUT over ip6tables too. disable_ipv6 above
      # is the primary control (no IPv6 route should exist at all); this guards the case where it is
      # somehow bypassed. Guarded on `command -v` so a missing ip6tables binary cannot abort this
      # `set +e` script — fail-closed intent: if IPv6 is disabled there is nothing to route anyway, and
      # NO IPv6 egress ACCEPT is opened for 53/80/443 (the builder fetch is IPv4-only through Squid).
      if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -F OUTPUT 2>/dev/null
        ip6tables -P OUTPUT DROP
        ip6tables -A OUTPUT -o lo -j ACCEPT
        ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
      fi

      # --- Mount data disks (same robust pattern as the offline runner) ---
      SBX_UID=$(id -u sandbox 2>/dev/null || echo 0)
      SBX_GID=$(id -g sandbox 2>/dev/null || echo 0)
      modprobe exfat 2>/dev/null
      mkdir -p /mnt/in /mnt/out
      udevadm settle 2>/dev/null
      mount -o ro,uid=$SBX_UID,gid=$SBX_GID LABEL=INPUT  /mnt/in  2>/dev/null || mount LABEL=INPUT  /mnt/in  2>/dev/null
      OUT_SANDBOX_OWNED=0
      if mount -o uid=$SBX_UID,gid=$SBX_GID LABEL=OUTPUT /mnt/out 2>/dev/null; then OUT_SANDBOX_OWNED=1; fi
      mountpoint -q /mnt/out || mount LABEL=OUTPUT /mnt/out 2>/dev/null
      if ! mountpoint -q /mnt/out; then poweroff; exit 0; fi
      if ! mountpoint -q /mnt/in; then printf '%s' 70 > /mnt/out/result.exitcode; sync; umount /mnt/out 2>/dev/null; poweroff; exit 0; fi

      # --- Run the dep-fetch entrypoint ---
      if [ "$OUT_SANDBOX_OWNED" = "1" ] && id -u sandbox >/dev/null 2>&1; then
        runuser -u sandbox -- /bin/sh -c '__ENTRYPOINT__' > /mnt/out/stdout.log 2> /mnt/out/stderr.txt
      else
        /bin/sh -c '__ENTRYPOINT__' > /mnt/out/stdout.log 2> /mnt/out/stderr.txt
      fi
      rc=$?
      printf '%s' "$rc" > /mnt/out/result.exitcode
      sync
      umount /mnt/out
      i=0; while mountpoint -q /mnt/out && [ $i -lt 10 ]; do sleep 1; umount /mnt/out 2>/dev/null; i=$((i+1)); done
      poweroff

  - path: /etc/systemd/system/vmdep-builder.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Voidseal builder dep-fetch workload
      After=network-online.target squid.service
      Wants=network-online.target
      [Service]
      Type=oneshot
      ExecStart=/usr/local/sbin/vmdep-builder
      TimeoutStartSec=infinity
      [Install]
      WantedBy=multi-user.target

runcmd:
  - [ apt-get, install, -y, squid, iptables ]
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, squid.service ]
  - [ systemctl, start, --no-block, vmdep-builder.service ]
'@

# --------------------------------------------------------------------------
# The SERIAL-mode baseline user-data (guest-images/debian-12-cloud.md §2). Single-quoted ($TERM stays
# literal). Brings up serial-getty AUTOLOGIN on ttyS0 (the Runner's non-authenticating command seam).
# --------------------------------------------------------------------------
$script:CidataSerialBaselineTemplate = @'
#cloud-config
# Voidseal serial-mode baseline NoCloud seed. Brings up a Debian Gen2 guest reachable over the COM1
# serial seam with AUTOLOGIN (the Runner's serial client does NOT authenticate, so a password/login
# prompt would make it time out). Non-root run-user + bubblewrap for in-guest defense-in-depth.

users:
  - name: sandbox
    groups: [sudo]
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    lock_passwd: true          # no password login anywhere; serial console + key only

write_files:
  # Serial console params so the kernel + grub talk over ttyS0 (the host pipe).
  - path: /etc/default/grub.d/99-serial.cfg
    content: |
      GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"
      GRUB_TERMINAL="console serial"
      GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"
  # AUTOLOGIN on ttyS0 — the Runner expects an already-logged-in shell (no prompt).
  - path: /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf
    content: |
      [Service]
      ExecStart=
      ExecStart=-/sbin/agetty --autologin sandbox --keep-baud 115200,38400,9600 ttyS0 $TERM

runcmd:
  - update-grub
  - systemctl daemon-reload
  - systemctl enable  serial-getty@ttyS0.service
  - systemctl restart serial-getty@ttyS0.service
  - [ apt-get, update ]
  - [ apt-get, install, -y, bubblewrap, ca-certificates ]

# Tier keeps egress credential-FREE; no secrets are ever written here. Workload packages/repo are
# staged before the seal, not in this base seed.
'@

# --------------------------------------------------------------------------
# The SERIAL + InGuestSquid egress user-data (EG-2, ralph in-guest egress Option A). The serial-getty
# AUTOLOGIN baseline (CidataSerialBaselineTemplate, above — ralph's ttyS0 command channel is
# unchanged) COMPOSED WITH the builder's proven egress fragment (CidataBuilderRunnerTemplate, above:
# IPv6-disable + Squid transparent domain-ACL + iptables default-DROP), ported for a Serial-mode
# profile that declares EgressMode='InGuestSquid'. Single-quoted here-string: nothing is interpolated
# by PowerShell ($TERM in the serial-getty line stays literal, same as the baseline). Only
# __SQUID_ALLOWLIST_ACL__ is substituted (space-joined merged EgressAllowlist).
#
# THIS IS DEFENSE-IN-DEPTH, NOT A BOUNDARY (Pass A / Pass 5): a compromised/root guest can disable its
# own iptables or kill its own Squid. The host-verified boundary is Phase-6 (host-side Internal
# vSwitch + NAT + host default-DROP + host Squid SNI-splice, docs/phase-6-live-runbook.md). The mock
# asserts SHAPE only (Squid ACL contains each allowlist domain; http_access deny all; iptables
# default-DROP; IPv6 disabled) — real packet-drop is a Phase-6 live-validation item, same posture the
# builder's own egress fragment already carries.
# --------------------------------------------------------------------------
$script:CidataSerialEgressTemplate = @'
#cloud-config
# Voidseal Tier-1 (ralph) serial-mode seed WITH in-guest egress (EG-2, Option A). Brings up the same
# COM1 serial command channel as the bare serial baseline (AUTOLOGIN on ttyS0 — the Runner's serial
# client does NOT authenticate) PLUS an in-guest iptables default-DROP + transparent Squid domain-ACL
# over the profile's merged EgressAllowlist, ported from the builder's SquidSniProxy mechanism.
#
# DEFENSE-IN-DEPTH, NOT A BOUNDARY: a compromised/root guest can disable this. The host-verified
# boundary is Phase-6 (host-side NAT/Squid/default-DROP). See docs/tier-reference.md.

users:
  - name: sandbox
    groups: [sudo]
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    lock_passwd: true          # no password login anywhere; serial console + key only

# SEC-2/C3: disable IPv6 BEFORE the network comes up (bootcmd runs earlier than runcmd/network-config)
# — ported verbatim from the builder's egress fragment. Primary control; the ip6tables default-DROP
# in the lockdown script below is belt-and-braces.
bootcmd:
  - [ sysctl, -w, 'net.ipv6.conf.all.disable_ipv6=1' ]
  - [ sysctl, -w, 'net.ipv6.conf.default.disable_ipv6=1' ]

write_files:
  # Serial console params so the kernel + grub talk over ttyS0 (the host pipe). (baseline)
  - path: /etc/default/grub.d/99-serial.cfg
    content: |
      GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"
      GRUB_TERMINAL="console serial"
      GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"
  # AUTOLOGIN on ttyS0 — the Runner expects an already-logged-in shell (no prompt). (baseline)
  - path: /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf
    content: |
      [Service]
      ExecStart=
      ExecStart=-/sbin/agetty --autologin sandbox --keep-baud 115200,38400,9600 ttyS0 $TERM

  - path: /etc/sysctl.d/99-voidseal-noipv6.conf
    permissions: '0644'
    content: |
      # SEC-2/C3: IPv6 disabled for this Tier-1 in-guest egress control. Debian cloud images bring
      # IPv6 up by default (SLAAC/DHCPv6); the lockdown below is otherwise IPv4-only and a semi-
      # trusted agent could egress over IPv6 entirely unfiltered. bootcmd applies this at boot
      # (before network-config); this file makes the setting persist/re-apply across `sysctl --system`.
      net.ipv6.conf.all.disable_ipv6 = 1
      net.ipv6.conf.default.disable_ipv6 = 1

  - path: /etc/squid/squid.conf
    permissions: '0644'
    content: |
      # Voidseal Tier-1 in-guest transparent Squid proxy — intercept on 3129 (HTTP) + 3130 (HTTPS).
      # DEFENSE-IN-DEPTH, NOT A BOUNDARY: a root guest can stop this service. LIVE-only (Phase 6):
      # real ssl_bump/SNI peek + CDN-rotation resilience is unproven in mock tests.
      http_port 3129 intercept
      https_port 3130 intercept ssl-bump
      acl allowed_domains dstdomain __SQUID_ALLOWLIST_ACL__
      ssl_bump peek all
      ssl_bump splice allowed_domains
      ssl_bump terminate all
      http_access allow allowed_domains
      http_access deny all

  # LIVE-ONLY (Phase 6): activation ORDERING vs pre-seal staging is unproven in mock. The lockdown
  # must activate AFTER in-guest package install (deb.debian.org is intentionally NOT in the
  # allowlist) and stay active through the sealed run. The mock asserts SHAPE only; the live
  # ordering + real packet-drop are Phase-6 live-validation items (same posture as the builder runner).
  - path: /usr/local/sbin/voidseal-egress-lockdown
    permissions: '0755'
    content: |
      #!/bin/sh
      # Voidseal Tier-1 (ralph) in-guest egress lockdown: iptables default-DROP OUTPUT with a minimal
      # allow-list (loopback, established, DNS, HTTP/HTTPS transparently redirected to Squid's
      # domain-ACL), ported verbatim from the builder's proven mechanism (SeedBuilder.ps1). Defense-
      # in-depth only: a root guest can flush/disable this. FAIL-CLOSED: if this script errors
      # partway, the OUTPUT policy stays DROP -> no egress -> fails closed, not open.
      set +e
      # Belt-and-braces (mirrors the builder runner): ensure Squid is up before the REDIRECT rules
      # point 80/443 at its ports. The unit's After=squid.service already orders this; the restart
      # guards a squid that failed its own start. `|| true` keeps the fail-closed DROP path intact.
      systemctl restart squid 2>/dev/null || true
      iptables -F OUTPUT 2>/dev/null
      iptables -P OUTPUT DROP
      iptables -A OUTPUT -o lo -j ACCEPT
      iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
      iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
      iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
      iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
      iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
      # Transparent-proxy REDIRECT of outbound 80/443 through Squid (domain-ACL gatekeeps the fetch);
      # the owner-exclusion keeps Squid's OWN upstream egress from being re-redirected.
      iptables -t nat -A OUTPUT -p tcp --dport 80  -m owner ! --uid-owner proxy -j REDIRECT --to-port 3129
      iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner proxy -j REDIRECT --to-port 3130
      # IPv6 belt-and-braces: default-DROP OUTPUT over ip6tables too, guarded so a missing binary
      # cannot abort this `set +e` script. No IPv6 egress ACCEPT is opened for 53/80/443.
      if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -F OUTPUT 2>/dev/null
        ip6tables -P OUTPUT DROP
        ip6tables -A OUTPUT -o lo -j ACCEPT
        ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
      fi

  - path: /etc/systemd/system/voidseal-egress.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Voidseal Tier-1 in-guest egress lockdown (defense-in-depth, NOT a boundary)
      # Match the builder unit's ordering: pull network-online into the boot transaction (After alone
      # does NOT), and order AFTER squid.service so the REDIRECT-to-3129/3130 never goes live before
      # Squid binds those ports (a too-early REDIRECT hits a closed port -> connection refused -> still
      # fail-closed, but ordering after squid avoids the spurious refusal). Mirrors the builder unit.
      After=network-online.target squid.service
      Wants=network-online.target
      [Service]
      Type=oneshot
      ExecStart=/usr/local/sbin/voidseal-egress-lockdown
      [Install]
      WantedBy=multi-user.target

runcmd:
  - update-grub
  - systemctl daemon-reload
  - systemctl enable  serial-getty@ttyS0.service
  - systemctl restart serial-getty@ttyS0.service
  - [ apt-get, update ]
  - [ apt-get, install, -y, squid, iptables ]
  - [ apt-get, install, -y, bubblewrap, ca-certificates ]
  - systemctl enable squid.service
  - systemctl enable voidseal-egress.service

# LIVE-ONLY (Phase 6): voidseal-egress.service is ENABLED here (applies on the NEXT boot / at the
# sealed-run point) but deliberately NOT started inline in runcmd, so the default-DROP does not block
# this guest's OWN pre-seal package install above (deb.debian.org is intentionally NOT in the
# EgressAllowlist). The precise live activation trigger is a Phase-6 live-validation detail; the mock
# asserts the seed SHAPE only.
'@

# --------------------------------------------------------------------------
# Internal: normalize any line endings to LF (cloud-init runs an embedded /bin/sh script; a CRLF
# there yields a `/bin/sh\r` bad-interpreter failure in the guest).
# --------------------------------------------------------------------------
function ConvertTo-LfText {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text)
    return ($Text -replace "`r`n", "`n") -replace "`r", "`n"
}

<#
.SYNOPSIS
    Build the cloud-init `user-data` string for a profile (Disk-mode runner or Serial baseline).
.PARAMETER Profile
    The resolved profile (hashtable). `WorkloadMode='Disk'` selects the disk-mode runner (and the
    profile's `Entrypoint` is substituted for __ENTRYPOINT__); anything else -> the serial baseline.
#>
function New-CidataUserData {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Profile)

    $mode       = [string](Get-SeedProfileField -Profile $Profile -Name 'WorkloadMode'  -Default 'Serial')
    $egressMode = [string](Get-SeedProfileField -Profile $Profile -Name 'EgressMode'    -Default '')

    # FAIL-CLOSED: 'InGuestSquid' is the SERIAL-seed's in-guest egress fragment (below); the Disk-mode
    # branches below it have no idea EgressMode exists and would otherwise silently fall through to a
    # plain disk runner with ZERO egress content for a profile that declared one — the exact
    # "declared but unwired" class this batch retires. Refuse it explicitly instead.
    if ($mode -eq 'Disk' -and $egressMode -eq 'InGuestSquid') {
        throw "New-CidataUserData: 'InGuestSquid' is the SERIAL-seed in-guest egress; a Disk-mode egress profile uses the builder's 'SquidSniProxy' (which carries its DepsSpec rule)."
    }

    if ($mode -eq 'Disk' -and $egressMode -eq 'SquidSniProxy') {
        # Builder path: network-enabled disk-mode seed with a transparent Squid SNI domain-ACL proxy.
        $entrypoint = [string](Get-SeedProfileField -Profile $Profile -Name 'Entrypoint' -Default '')
        # FAIL-CLOSED: same sh -c guard as the offline runner (single quote / newline / blank are refused).
        if ([string]::IsNullOrWhiteSpace($entrypoint)) {
            throw "New-CidataUserData: a builder Disk+SquidSniProxy profile must declare a non-blank Entrypoint."
        }
        if ($entrypoint.Contains("'")) {
            throw "New-CidataUserData: the builder Entrypoint contains a single quote, which would escape the runner's sh -c '...' wrapper. Refuse it."
        }
        if ($entrypoint -match "[\r\n]") {
            throw "New-CidataUserData: the builder Entrypoint is multi-line; the runner invokes it on a single sh -c line. Refuse it."
        }
        $allowlist = Get-SeedProfileField -Profile $Profile -Name 'EgressAllowlist' -Default @()
        if ($null -eq $allowlist -or @($allowlist).Count -eq 0) {
            throw "New-CidataUserData: a builder Disk+SquidSniProxy profile must have a non-empty EgressAllowlist (allowlist is empty — fail-closed)."
        }
        # SEC-1: each allowlist entry's charset (no whitespace/newline/quote) is validated at LOAD time
        # in Assert-TierProfileValid (ProfileLoader.ps1) before it ever reaches here, so a newline-bearing
        # entry cannot inject a directive (e.g. `http_access allow all`) into the dstdomain ACL below.
        $aclLine = ($allowlist -join ' ')
        $ud = $script:CidataBuilderRunnerTemplate.Replace('__ENTRYPOINT__', $entrypoint).Replace('__SQUID_ALLOWLIST_ACL__', $aclLine)
        return (ConvertTo-LfText -Text $ud)
    }

    if ($mode -eq 'Disk') {
        $entrypoint = [string](Get-SeedProfileField -Profile $Profile -Name 'Entrypoint' -Default '')
        # FAIL-CLOSED: the runner invokes the entrypoint as  sh -c '<entrypoint>'  on a single line.
        if ([string]::IsNullOrWhiteSpace($entrypoint)) {
            throw "New-CidataUserData: a Disk-mode profile must declare a non-blank Entrypoint (the disk runner has nothing to run without it)."
        }
        if ($entrypoint.Contains("'")) {
            throw "New-CidataUserData: the Disk-mode Entrypoint contains a single quote, which would escape the runner's sh -c '...' wrapper. Refuse it (use a wrapper script on the INPUT disk instead)."
        }
        if ($entrypoint -match "[\r\n]") {
            throw "New-CidataUserData: the Disk-mode Entrypoint is multi-line; the runner invokes it on a single sh -c line. Refuse it."
        }
        # C1.3: a profile that opts into the user-space outbox transport (OutboxOutput=$true — same
        # predicate as Workload.ps1's Raw-OUTPUT selection) gets the OutboxOutput runner: the OUTPUT
        # disk is Raw (no filesystem), so the entrypoint runs into a staging dir and the shared
        # outbox-producer template (run_disk_workload.py --transport-only) packs + writes the outbox.
        # Everything else (legacy non-outbox Disk profiles) keeps the direct exFAT result.html runner.
        $wantsOutbox = [bool](Get-SeedProfileField -Profile $Profile -Name 'OutboxOutput' -Default $false)
        if ($wantsOutbox) {
            $ud = $script:CidataOutboxDiskRunnerTemplate.Replace('__ENTRYPOINT__', $entrypoint)
            return (ConvertTo-LfText -Text $ud)
        }
        $ud = $script:CidataDiskRunnerTemplate.Replace('__ENTRYPOINT__', $entrypoint)
        return (ConvertTo-LfText -Text $ud)
    }

    # EG-2 (ralph in-guest egress, Option A): a Serial-mode profile that declares EgressMode=
    # 'InGuestSquid' gets the serial baseline COMPOSED WITH the builder's proven egress fragment
    # (iptables default-DROP + transparent Squid domain-ACL over EgressAllowlist). Defense-in-depth
    # only — see CidataSerialEgressTemplate's header comment. Fail-closed on an empty allowlist,
    # mirroring the builder's own SquidSniProxy refusal above.
    if ($mode -ne 'Disk' -and $egressMode -eq 'InGuestSquid') {
        $allowlist = Get-SeedProfileField -Profile $Profile -Name 'EgressAllowlist' -Default @()
        if ($null -eq $allowlist -or @($allowlist).Count -eq 0) {
            throw "New-CidataUserData: a Serial+InGuestSquid profile must have a non-empty EgressAllowlist (fail-closed)."
        }
        # SEC-1: each allowlist entry's charset is validated at LOAD time in Assert-TierProfileValid
        # (ProfileLoader.ps1) before it ever reaches here — same discipline as the builder branch above.
        $aclLine = (@($allowlist) -join ' ')
        $ud = $script:CidataSerialEgressTemplate.Replace('__SQUID_ALLOWLIST_ACL__', $aclLine)
        return (ConvertTo-LfText -Text $ud)
    }

    return (ConvertTo-LfText -Text $script:CidataSerialBaselineTemplate)
}

<#
.SYNOPSIS
    Build the cloud-init `meta-data` string (NoCloud requires instance-id + a hostname).
#>
function New-CidataMetaData {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $InstanceId = 'voidseal-sandbox-001',
        [string] $Hostname   = 'sandbox'
    )
    $md = "instance-id: $InstanceId`nlocal-hostname: $Hostname`n"
    return (ConvertTo-LfText -Text $md)
}

<#
.SYNOPSIS
    The REAL ISO writer — builds an ISO9660+Joliet image labelled <VolumeLabel> from <SourceDir>
    using the built-in Windows IMAPI2 (MsftFileSystemImage) COM API. No ADK / WSL / install needed.
.DESCRIPTION
    Joliet is included so the exact lowercase/hyphenated names `meta-data` + `user-data` survive
    (plain ISO9660 8.3 would uppercase/strip them and cloud-init would not find them). The COM
    result's ImageStream is written to the destination file via a tiny managed helper (no /unsafe).
#>
function Write-Iso9660Image {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $SourceDir,
        [Parameter(Mandatory)] [string] $VolumeLabel,
        [Parameter(Mandatory)] [string] $Destination
    )
    if (-not (Test-Path -LiteralPath $SourceDir -PathType Container)) {
        throw "Write-Iso9660Image: source dir '$SourceDir' does not exist."
    }
    $destDir = Split-Path -Parent $Destination
    if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    # A tiny managed IStream->file copy (avoids the /unsafe compiler option the classic gist uses).
    if (-not ([System.Management.Automation.PSTypeName]'Voidseal.IsoStreamWriter').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
namespace Voidseal {
  public static class IsoStreamWriter {
    public static void Write(string path, object comStream, int blockSize, int totalBlocks) {
      IStream stream = (IStream)comStream;
      using (FileStream fs = File.Open(path, FileMode.Create, FileAccess.Write)) {
        byte[] buf = new byte[blockSize];
        IntPtr pcb = Marshal.AllocHGlobal(4);
        try {
          while (totalBlocks-- > 0) {
            stream.Read(buf, blockSize, pcb);
            int n = Marshal.ReadInt32(pcb);
            if (n <= 0) break;
            fs.Write(buf, 0, n);
          }
          fs.Flush();
        } finally { Marshal.FreeHGlobal(pcb); }
      }
    }
  }
}
'@
    }

    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    try {
        $fsi.FileSystemsToCreate = 3          # ISO9660 (1) | Joliet (2) — preserve exact file names
        $fsi.VolumeName = $VolumeLabel
        $fsi.Root.AddTree($SourceDir, $false) # $false = add the dir's CHILDREN at the ISO root
        $result = $fsi.CreateResultImage()
        try {
            [Voidseal.IsoStreamWriter]::Write($Destination, $result.ImageStream, $result.BlockSize, $result.TotalBlocks)
        }
        finally {
            if ($result) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($result) }
        }
    }
    finally {
        if ($fsi) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($fsi) }
    }
}

<#
.SYNOPSIS
    Build a CIDATA NoCloud seed ISO for a profile.
.DESCRIPTION
    Assembles `meta-data` + `user-data` (New-CidataMetaData / New-CidataUserData) into a fresh
    staging dir and hands it to the (injectable) ISO writer with the volume label CIDATA.
    The Disk-mode entrypoint fail-closed check runs FIRST, so an unsafe entrypoint never reaches the
    ISO writer (no file is produced).
.PARAMETER Profile
    The resolved profile (hashtable). Selects Disk vs Serial; supplies the Entrypoint + (default)
    SeedIso destination.
.PARAMETER Destination
    The output ISO path. Defaults to the profile's `SeedIso`.
.PARAMETER IsoWriter
    The ISO writer scriptblock, invoked as  & $IsoWriter @{ SourceDir; VolumeLabel; Destination }.
    Defaults to the real IMAPI2 writer (Write-Iso9660Image); tests inject a fake.
.PARAMETER WorkDir
    Optional staging root (a fresh subdir is created under it). Defaults under the system temp path.
#>
function New-CidataSeed {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Profile,
        [string] $Destination,
        [scriptblock] $IsoWriter = { param($A) Write-Iso9660Image -SourceDir $A.SourceDir -VolumeLabel $A.VolumeLabel -Destination $A.Destination },
        [string] $WorkDir
    )

    if ([string]::IsNullOrWhiteSpace($Destination)) {
        $Destination = [string](Get-SeedProfileField -Profile $Profile -Name 'SeedIso' -Default '')
    }
    if ([string]::IsNullOrWhiteSpace($Destination)) {
        throw "New-CidataSeed: no -Destination given and the profile declares no SeedIso path."
    }

    # Build the documents FIRST. New-CidataUserData throws (fail-closed) on a bad Disk entrypoint
    # BEFORE we stage anything or call the writer — so a rejected entrypoint produces no ISO.
    $userData = New-CidataUserData -Profile $Profile
    $metaData = New-CidataMetaData

    if ([string]::IsNullOrWhiteSpace($WorkDir)) {
        $WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) 'Voidseal\seed-build'
    }
    $stage = Join-Path $WorkDir ("cidata-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        # LF, no BOM — cloud-init reads these on a Linux guest.
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText((Join-Path $stage 'user-data'), $userData, $enc)
        [System.IO.File]::WriteAllText((Join-Path $stage 'meta-data'), $metaData, $enc)

        & $IsoWriter @{ SourceDir = $stage; VolumeLabel = 'CIDATA'; Destination = $Destination }
    }
    finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }

    return $Destination
}
