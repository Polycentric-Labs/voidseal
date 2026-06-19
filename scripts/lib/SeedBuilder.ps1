<#
.SYNOPSIS
    Voidseal — CIDATA NoCloud seed-ISO builder (the host-side tool that produces the cloud-init seed).

.DESCRIPTION
    Builds the first-boot **NoCloud `CIDATA` seed ISO** a sandbox guest consumes on its FIRST boot.
    Two shapes, selected by the profile's `WorkloadMode`:

      * DISK  — the disk-passing workload runner (guest-images/debian-12-cloud.md §2a). A systemd
        oneshot mounts the host-pre-formatted exFAT data disks by LABEL (INPUT ro -> /mnt/in,
        OUTPUT rw -> /mnt/out), runs the profile's `Entrypoint` as the non-root `sandbox` user,
        writes `result.html` + the `result.exitcode` sentinel onto OUTPUT, flushes, and self-powers
        off. The seed builder substitutes the profile's `Entrypoint` for the `__ENTRYPOINT__` token.
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

write_files:
  - path: /usr/local/sbin/vmdep-workload
    permissions: '0755'
    content: |
      #!/bin/sh
      # Voidseal disk-mode workload runner: mount the host-pre-formatted exFAT data disks by LABEL,
      # run the workload as the non-root 'sandbox' user, write result + an exit-code sentinel to the
      # OUTPUT disk, flush (umount), and power off. The host reads result.html + result.exitcode.
      set +e
      SBX_UID=$(id -u sandbox 2>/dev/null || echo 0)
      SBX_GID=$(id -g sandbox 2>/dev/null || echo 0)
      modprobe exfat 2>/dev/null   # host-pre-formatted exFAT; in-kernel since 5.7. No mkfs in guest.
      mkdir -p /mnt/in /mnt/out
      # The INPUT/OUTPUT SCSI data disks are not in fstab; settle udev so mount-by-LABEL resolves.
      udevadm settle 2>/dev/null
      # exFAT is non-POSIX — ownership comes from the uid=/gid= mount options so the non-root
      # entrypoint can read /mnt/in and write /mnt/out (root still writes the sentinel regardless).
      mount -o ro,uid=$SBX_UID,gid=$SBX_GID LABEL=INPUT  /mnt/in   2>/dev/null
      mount -o    uid=$SBX_UID,gid=$SBX_GID LABEL=OUTPUT /mnt/out  2>/dev/null
      # No OUTPUT -> nowhere to write the sentinel -> poweroff (host classifies Failed: no sentinel).
      # The `exit` is LOAD-BEARING: systemd poweroff is async + returns 0, so without it the script
      # would run on against an unmounted /mnt/out and write into the live rootfs during shutdown.
      if ! mountpoint -q /mnt/out; then poweroff; exit 0; fi
      # No INPUT -> the entrypoint (which lives on /mnt/in) can't run; record a determinate non-zero
      # sentinel so the host classifies Failed with a definite code, flush, power off.
      if ! mountpoint -q /mnt/in; then printf '%s' 70 > /mnt/out/result.exitcode; sync; umount /mnt/out 2>/dev/null; poweroff; exit 0; fi
      # Run the workload ONCE as the unprivileged 'sandbox' user (fall back to root only if absent).
      # The entrypoint writes its OWN result to /mnt/out/result.html (firefox: --out). stdout/stderr
      # go to SEPARATE logs (the host ignores them) — never redirected into result.html (a double-
      # write with the entrypoint's own --out can 0-byte/corrupt the required Netscape-HTML).
      # NOTE: run via sh -c '<entrypoint>', so the entrypoint must contain no single quote.
      if id -u sandbox >/dev/null 2>&1; then
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

    $mode = [string](Get-SeedProfileField -Profile $Profile -Name 'WorkloadMode' -Default 'Serial')

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
        $ud = $script:CidataDiskRunnerTemplate.Replace('__ENTRYPOINT__', $entrypoint)
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
