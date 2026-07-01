#!/usr/bin/env python3
"""Partition detection, forensic mounting, and LVM handling.

Partition exposure strategy
---------------------------
Forensic images are mounted read-only.  To mount an individual partition we
need a block device that maps to that partition's byte range.  The kernel only
creates per-partition nodes (``/dev/loop0p1`` ...) when partition scanning is
available: ``losetup --partscan`` with ``loop.max_part > 0``, or an NBD device
loaded with ``max_part``.  On WSL2 the ``loop`` driver is compiled into the
kernel with ``max_part=0`` and device-mapper (``kpartx``) is frequently
unavailable, so those nodes never appear -- ``fdisk`` still *reads* the table,
but ``/dev/loopNpM`` does not exist and the mount fails with
"special device ... does not exist".

To work regardless of the kernel's partition-scanning support we expose each
partition with its own read-only **offset loop device**::

    losetup --find --show --read-only --offset <start> --sizelimit <size> <backing>

This is core loop-driver functionality, independent of ``loop.max_part`` and
device-mapper.  When kernel-scanned nodes *do* already exist (NBD, or a kernel
with ``max_part`` set) we use them directly instead.  Partition geometry (byte
offset + size) is read straight from the partition table with
``partx``/``sfdisk``/``fdisk`` -- none of which need the nodes to exist.
"""

import re
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from utils import logger, run_command, ensure_mount_dir

# partx/sfdisk report partition START in 512-byte units regardless of the
# drive's logical sector size; sfdisk additionally prints an explicit
# ``sector-size:`` which we honour when present.
_SECTOR = 512


@dataclass
class PartitionInfo:
    """Information about a detected partition.

    ``device`` is the block device that maps to the partition once exposed
    (a kernel-scanned node such as ``/dev/nbd0p1`` or an offset loop device we
    created such as ``/dev/loop7``).  ``backing_loop`` records a loop device
    *we* created so it can be detached on unmount.
    """
    device: str = ""
    number: int = 0
    start_sector: int = 0
    start_bytes: int = 0
    size_bytes: int = 0
    type_hint: str = ""    # MBR type code (e.g. 0x83) or GPT type GUID
    pt_name: str = ""      # GPT partition name (distinct from the FS label)
    filesystem: str = ""   # ntfs, ext4, xfs, ufs, ...
    label: str = ""        # filesystem label (from blkid)
    mount_point: Optional[Path] = None
    mounted: bool = False
    mount_error: Optional[str] = None
    backing_loop: str = ""  # offset loop device we created (for cleanup)


# Forensic mount options per filesystem type
_MOUNT_OPTIONS: Dict[str, str] = {
    "ntfs":  "ro,noatime,noexec,show_sys_files,streams_interface=windows",
    "ext2":  "ro,noatime,noexec,norecovery",
    "ext3":  "ro,noatime,noexec,norecovery",
    "ext4":  "ro,noatime,noexec,norecovery",
    "xfs":   "ro,noatime,noexec,norecovery",
    "btrfs": "ro,noatime,noexec",
    "vfat":  "ro,noatime,noexec",
    "fat32": "ro,noatime,noexec",
    "fat16": "ro,noatime,noexec",
    "exfat": "ro,noatime,noexec",
    "hfsplus": "ro,noatime,noexec",
    "ufs":   "ro,noatime,noexec",
}
_DEFAULT_MOUNT_OPTIONS = "ro,noatime,noexec"

# Pseudo-filesystems that are recognised but never mounted as a data volume.
# (Stored lowercase: blkid TYPE values are lowercased on detection.)
# ``zfs_member`` is a pool member imported with ``zpool import``, not a
# partition we mount directly, so it is handled out-of-band (see mountir.py).
_SKIP_FILESYSTEMS = {
    "swap", "linux_raid_member", "lvm2_member", "crypto_luks", "zfs_member",
}

# Filesystems mounted with a dedicated FUSE *binary* (not a ``mount -t`` helper).
# Each entry is an ordered list of (binary, extra-args) attempts; the binary is
# invoked as ``binary <extra-args> <device> <mount_point>``. These drivers have
# no in-kernel equivalent on the platforms we target, so they are tried before
# the generic ``mount`` attempts.
_FUSE_MOUNTERS: Dict[str, List[Tuple[str, List[str]]]] = {
    "apfs": [("apfs-fuse", ["-o", "ro,allow_other"])],
    "vmfs": [("vmfs-fuse", ["-o", "ro"]), ("vmfs6-fuse", ["-o", "ro"])],
}

# file(1) magic substring (lowercase) -> filesystem type. Last-resort detection
# when blkid and lsblk both come up empty.
_FILE_MAGIC_MAP = [
    ("apfs", "apfs"),                    # check before generic "fat"/"hfs"
    ("apple file system", "apfs"),
    ("refs", "refs"),                    # Windows Resilient File System
    ("ntfs", "ntfs"),
    ("fat (32 bit)", "vfat"),
    ("fat (16 bit)", "vfat"),
    ("fat (12 bit)", "vfat"),
    ("mkdosfs", "vfat"),
    ("exfat", "exfat"),
    ("ext2 filesystem", "ext2"),
    ("ext3 filesystem", "ext3"),
    ("ext4 filesystem", "ext4"),
    ("xfs filesystem", "xfs"),
    ("btrfs", "btrfs"),
    ("apple hfs", "hfsplus"),
    ("hierarchical file system", "hfsplus"),
    ("unix fast file system", "ufs"),    # FreeBSD/NetScaler/pfSense
    ("ufs filesystem", "ufs"),
    ("vmware", "vmfs"),                  # VMware ESXi VMFS datastore
    ("vmfs", "vmfs"),
    ("zfs", "zfs_member"),               # imported via zpool, not mounted directly
    ("iso 9660", "iso9660"),
    ("swap", "swap"),
    ("lvm2", "lvm2_member"),
]


# ---------------------------------------------------------------------------
# Partition-table reading (no scanned nodes required)
# ---------------------------------------------------------------------------
def read_partition_table(source: Union[str, Path]) -> List[PartitionInfo]:
    """Read partition geometry from a block device or image file.

    Tries ``partx`` (libblkid backend: GPT/DOS/BSD/Solaris/etc.), then
    ``sfdisk -d`` (explicit sector size), then ``fdisk -l``.  None of these
    require per-partition device nodes to exist.  Returns the first non-empty
    result, with byte offsets/sizes populated.
    """
    source = str(source)
    for reader in (_read_via_partx, _read_via_sfdisk, _detect_via_fdisk):
        try:
            parts = reader(source)
        except Exception as e:  # a parser must never abort exposure
            logger.debug("partition reader %s failed: %s", reader.__name__, e)
            continue
        if parts:
            logger.debug("Read %d partition(s) from %s via %s",
                         len(parts), source, reader.__name__)
            return parts
    return []


_PAIR_RE = re.compile(r'(\w+)="([^"]*)"')


def _read_via_partx(source: str) -> List[PartitionInfo]:
    """Parse ``partx -b -P`` pairs output into PartitionInfo objects.

    Example line:
        NR="1" START="2048" SECTORS="204800" SIZE="104857600" TYPE="0x7"
    START is in 512-byte sectors; SIZE is in bytes (``-b``).
    """
    result = run_command(
        ["partx", "-b", "-o", "NR,START,SECTORS,SIZE,TYPE,NAME", "-P", source],
        check=False, timeout=30,
    )
    if result.returncode != 0:
        return []

    parts: List[PartitionInfo] = []
    for line in result.stdout.splitlines():
        d = dict(_PAIR_RE.findall(line))
        if "NR" not in d:
            continue
        try:
            number = int(d["NR"])
            start_sector = int(d.get("START", "0") or 0)
            size_bytes = int(d.get("SIZE", "0") or 0)
        except ValueError:
            continue
        if size_bytes <= 0:
            continue
        parts.append(PartitionInfo(
            number=number,
            start_sector=start_sector,
            start_bytes=start_sector * _SECTOR,
            size_bytes=size_bytes,
            type_hint=d.get("TYPE", ""),
            pt_name=d.get("NAME", ""),
        ))
    return parts


def _read_via_sfdisk(source: str) -> List[PartitionInfo]:
    """Parse ``sfdisk -d`` dump output (honours its explicit sector-size)."""
    result = run_command(["sfdisk", "-d", source], check=False, timeout=30)
    if result.returncode != 0:
        return []

    sector_size = _SECTOR
    parts: List[PartitionInfo] = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if line.startswith("sector-size:"):
            try:
                sector_size = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
            continue
        if "start=" not in line:
            continue
        m = re.match(r"^(\S+)\s*:\s*(.+)$", line)
        if not m:
            continue
        dev, rest = m.group(1), m.group(2)
        fields = {k.lower(): v.strip() for k, v in
                  re.findall(r"(\w+)\s*=\s*([^,]+)", rest)}
        try:
            start = int(fields.get("start", "0"))
            size = int(fields.get("size", "0"))
        except ValueError:
            continue
        if size <= 0:
            continue
        num_match = re.search(r"(\d+)$", dev)
        number = int(num_match.group(1)) if num_match else len(parts) + 1
        parts.append(PartitionInfo(
            number=number,
            start_sector=start,
            start_bytes=start * sector_size,
            size_bytes=size * sector_size,
            type_hint=fields.get("type", ""),
            pt_name=fields.get("name", "").strip('"'),
        ))
    return parts


def _detect_via_fdisk(block_device: str) -> List[PartitionInfo]:
    """Parse ``fdisk -l`` output (last-resort; populates byte geometry too)."""
    try:
        result = run_command(["fdisk", "-l", block_device], check=False, timeout=30)
        if result.returncode != 0:
            logger.debug("fdisk failed on %s", block_device)
            return []
    except Exception:
        return []

    partitions: List[PartitionInfo] = []
    in_table = False

    for line in result.stdout.splitlines():
        if line.startswith("Device") and "Start" in line:
            in_table = True
            continue

        if in_table and line.strip():
            parts = line.split()
            if len(parts) >= 3 and parts[0].startswith("/dev/"):
                device = parts[0]
                num_match = re.search(r"p?(\d+)$", device)
                number = int(num_match.group(1)) if num_match else 0

                # Columns are: Device [Boot] Start End Sectors Size ...
                idx = 1
                if len(parts) > idx and parts[idx] == "*":
                    idx = 2
                try:
                    start_sector = int(parts[idx])
                except (ValueError, IndexError):
                    start_sector = 0
                try:
                    sectors = int(parts[idx + 2])
                except (ValueError, IndexError):
                    sectors = 0

                partitions.append(PartitionInfo(
                    device=device,
                    number=number,
                    start_sector=start_sector,
                    start_bytes=start_sector * _SECTOR,
                    size_bytes=sectors * _SECTOR,
                ))
        elif in_table and not line.strip():
            in_table = False

    return partitions


# ---------------------------------------------------------------------------
# Partition exposure (offset loop devices)
# ---------------------------------------------------------------------------
def _is_block_device(path: str) -> bool:
    try:
        return stat.S_ISBLK(Path(path).stat().st_mode)
    except OSError:
        return False


def _scanned_node(backing: str, number: int) -> str:
    """Kernel partition-node name for *backing* (e.g. /dev/loop2 -> .../loop2p1)."""
    name = str(backing)
    if name and name[-1].isdigit():
        return f"{name}p{number}"
    return f"{name}{number}"


def _attach_offset_loop(backing: str, start_bytes: int,
                        size_bytes: int) -> Optional[str]:
    """Attach a read-only loop device windowed to a partition's byte range.

    With ``start_bytes == 0`` and ``size_bytes == 0`` this attaches a whole-disk
    loop (the entire backing), which is what a single-volume image needs.
    """
    cmd = ["losetup", "--find", "--show", "--read-only",
           "--offset", str(start_bytes)]
    if size_bytes > 0:
        cmd += ["--sizelimit", str(size_bytes)]
    cmd.append(str(backing))
    try:
        result = run_command(cmd, timeout=30)
    except Exception as e:
        logger.error("Failed to attach offset loop on %s (offset=%d): %s",
                     backing, start_bytes, e)
        return None
    dev = result.stdout.strip()
    if not dev:
        logger.error("losetup returned empty device for offset loop on %s", backing)
        return None
    return dev


def _backing_size(source: str) -> int:
    """Byte size of a block device or image file (0 when it can't be determined)."""
    try:
        if _is_block_device(source):
            r = run_command(["blockdev", "--getsize64", source],
                            check=False, timeout=10)
            return int(r.stdout.strip() or 0) if r.returncode == 0 else 0
        return Path(source).stat().st_size
    except Exception:
        return 0


def _geometry_ok(p: PartitionInfo, disk_size: int) -> bool:
    """Reject partition geometry that can't physically fit on the disk.

    Tools occasionally misread a filesystem's boot sector (e.g. an NTFS volume's
    ``0x55AA`` signature) as a phantom MBR, yielding partitions whose offset or
    end runs past the end of the media. Those entries are bogus; drop them.
    """
    if p.start_bytes < 0 or p.size_bytes <= 0:
        return False
    if disk_size > 0:
        if p.start_bytes >= disk_size:
            return False
        if p.start_bytes + p.size_bytes > disk_size + _SECTOR:
            return False
    return True


def _whole_volume_fs(backing: str) -> Tuple[str, str]:
    """Detect a filesystem occupying the *whole* backing (a single-volume image).

    Disk images carry a partition table; volume/partition images (common with
    forensic acquisitions of a single NTFS/ext4 volume) put a filesystem at
    offset 0 with no table. ``blkid -p`` reports ``PTTYPE=`` for the former and a
    filesystem ``TYPE=`` for the latter, so it cleanly distinguishes the two.

    Returns ``(fstype, label)`` when the backing is a bare filesystem, else
    ``("", "")`` (including when a partition table is present).
    """
    try:
        r = run_command(["blkid", "-p", "-o", "export", backing],
                        check=False, timeout=10)
        if r.returncode == 0:
            if any(line.startswith("PTTYPE=") for line in r.stdout.splitlines()):
                return "", ""  # partitioned disk -- handled via the table
            fstype, label = _parse_blkid_export(r.stdout)
            if fstype:
                return fstype, label
    except Exception:
        logger.debug("whole-volume blkid probe failed for %s", backing)
    # blkid may not be installed or may miss exotic types; file(1) is a backstop.
    return _detect_fs_via_file(backing), ""


def _expose_whole_disk(backing: str, backing_is_dev: bool, disk_size: int,
                       created: List[str]) -> Tuple[List[PartitionInfo], List[str]]:
    """Expose the entire backing as one device (best-effort fallback).

    Used in --force mode when no usable partition table and no whole-volume
    filesystem could be found (a corrupt table, an exotic container, or raw
    media from an edge device).  We still hand back a block device for the whole
    disk so the analyst can attempt a mount or carve it, rather than aborting.
    """
    device = backing
    if not backing_is_dev:
        loop = _attach_offset_loop(backing, 0, 0)  # whole disk
        if not loop:
            logger.error("Could not attach whole-disk loop for %s", backing)
            return [], created
        device = loop
        created.append(loop)
    logger.warning(
        "No usable partition table on %s - exposing the whole disk for a "
        "best-effort mount/carve (--force)", backing,
    )
    vol = PartitionInfo(
        device=device, number=1, start_bytes=0, size_bytes=disk_size,
        backing_loop="" if backing_is_dev else device,
    )
    _enrich_with_blkid(vol)  # may still name a fs the table reader missed
    return [vol], created


def expose_partitions(backing: Union[str, Path],
                      force: bool = False) -> Tuple[List[PartitionInfo], List[str]]:
    """Read *backing*'s partition table and expose each partition as a device.

    *backing* may be a block device (``/dev/loopN``, ``/dev/nbdN``) or an image
    file (e.g. a FUSE-exposed ``ewf1``).  For each partition we use a
    kernel-scanned node if one already exists; otherwise we create a dedicated
    read-only offset loop device.  Each exposed partition is then probed for its
    filesystem type/label.

    When *force* is set and no usable partition table (and no whole-volume
    filesystem) is found, the entire backing is exposed as a single device so a
    corrupt-table or unfamiliar disk can still be mounted/carved.

    Returns ``(partitions, created_loop_devices)`` where ``created_loop_devices``
    are the offset loops we attached and must detach on unmount.
    """
    backing = str(backing)
    created: List[str] = []
    backing_is_dev = _is_block_device(backing)
    disk_size = _backing_size(backing)

    # 1. Single-volume image: a filesystem occupies the whole backing with no
    #    partition table (e.g. a forensic image of one NTFS/ext4 volume). Mount
    #    the whole thing and ignore any phantom table the boot sector fakes.
    fstype, label = _whole_volume_fs(backing)
    if fstype:
        device = backing
        if not backing_is_dev:
            loop = _attach_offset_loop(backing, 0, 0)  # whole disk
            if not loop:
                logger.error("Could not attach whole-disk loop for %s", backing)
                return [], created
            device = loop
            created.append(loop)
        logger.info("Single-volume image detected on %s (%s)", backing, fstype)
        vol = PartitionInfo(
            device=device, number=1, start_bytes=0, size_bytes=disk_size,
            filesystem=fstype, label=label,
            backing_loop="" if backing_is_dev else device,
        )
        return [vol], created

    # 2. Partitioned disk: read the table and expose each partition. Drop any
    #    entries whose geometry can't fit the media (phantom/misread tables).
    parts = read_partition_table(backing)
    valid = [p for p in parts if _geometry_ok(p, disk_size)]
    if len(valid) != len(parts):
        logger.warning("Ignored %d partition(s) with out-of-range geometry on %s",
                       len(parts) - len(valid), backing)
    if not valid:
        logger.info("No valid partition table found on %s", backing)
        if force:
            return _expose_whole_disk(backing, backing_is_dev, disk_size, created)
        return [], created

    for p in valid:
        device = ""
        if backing_is_dev:
            node = _scanned_node(backing, p.number)
            if _is_block_device(node):
                device = node
                logger.debug("Using kernel-scanned node %s", node)
        if not device:
            loop = _attach_offset_loop(backing, p.start_bytes, p.size_bytes)
            if not loop:
                p.mount_error = "could not expose partition (offset loop failed)"
                logger.warning("Could not expose partition %d on %s",
                               p.number, backing)
                continue
            device = loop
            p.backing_loop = loop
            created.append(loop)
            logger.debug("Exposed partition %d -> %s (offset=%d, size=%d)",
                         p.number, loop, p.start_bytes, p.size_bytes)
        p.device = device
        _enrich_with_blkid(p)

    return valid, created


# Back-compat wrappers ------------------------------------------------------
def detect_partitions(block_device: str) -> List[PartitionInfo]:
    """Expose partitions on an existing block device (drops created-loop list).

    Prefer :func:`expose_partitions` when you need to clean up offset loops.
    """
    parts, _created = expose_partitions(block_device)
    return parts


def detect_partitions_from_raw(
    raw_image_path: Path,
    mount_base: Optional[Path] = None,
) -> Tuple[List[PartitionInfo], List[str]]:
    """Expose partitions from a FUSE-exposed raw image (ewf1, vmdk1, ...).

    Reads the partition table directly from the raw image and windows each
    partition with its own read-only offset loop device -- no whole-disk loop
    or kernel partition scanning required.

    Returns ``(partitions, created_loop_devices)``.
    """
    return expose_partitions(raw_image_path)


# ---------------------------------------------------------------------------
# Filesystem detection
# ---------------------------------------------------------------------------
def _parse_blkid_export(stdout: str) -> Tuple[str, str]:
    """Parse `blkid -o export` / `blkid -p -o export` output -> (type, label)."""
    fstype, label = "", ""
    for line in stdout.splitlines():
        if line.startswith("TYPE="):
            fstype = line.split("=", 1)[1].strip().strip('"').lower()
        elif line.startswith("LABEL=") and not label:
            label = line.split("=", 1)[1].strip().strip('"')
        # PTTYPE= means blkid saw a partition table (whole disk), not a fs.
    return fstype, label


def _detect_fs_via_lsblk(device: str) -> Tuple[str, str]:
    """Fallback filesystem detection via lsblk -> (type, label)."""
    try:
        result = run_command(["lsblk", "-no", "FSTYPE,LABEL", device],
                             check=False, timeout=10)
        if result.returncode != 0:
            return "", ""
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            fstype = parts[0].strip().lower() if parts else ""
            label = parts[1].strip() if len(parts) > 1 else ""
            if fstype:
                return fstype, label
    except Exception:
        logger.debug("lsblk detection failed for %s", device)
    return "", ""


def _detect_fs_via_file(device: str) -> str:
    """Last-resort filesystem detection via file(1) magic."""
    try:
        result = run_command(["file", "-sLb", device], check=False, timeout=15)
        if result.returncode != 0:
            return ""
        out = result.stdout.strip().lower()
        for needle, fstype in _FILE_MAGIC_MAP:
            if needle in out:
                return fstype
    except Exception:
        logger.debug("file(1) detection failed for %s", device)
    return ""


def _enrich_with_blkid(part: PartitionInfo) -> None:
    """Detect filesystem type and label for a partition.

    Freshly-attached loop partitions are not in the blkid cache, so a plain
    ``blkid`` lookup returns nothing. We therefore try several methods in order:

      1. ``blkid -p`` (low-level probe) - bypasses the cache, reads the
         superblock directly. This is the key fix for loop/NBD partitions.
      2. ``blkid`` (cache lookup) - for environments where probe isn't allowed.
      3. ``lsblk`` - reads the kernel/udev view.
      4. ``file(1)`` magic - last resort.

    The first method that yields a filesystem type wins.
    """
    for cmd in (["blkid", "-p", "-o", "export", part.device],
                ["blkid", "-o", "export", part.device]):
        try:
            result = run_command(cmd, check=False, timeout=10)
        except Exception:
            continue
        if result.returncode == 0:
            fstype, label = _parse_blkid_export(result.stdout)
            if fstype:
                part.filesystem = fstype
                if label and not part.label:
                    part.label = label
                return

    fstype, label = _detect_fs_via_lsblk(part.device)
    if fstype:
        part.filesystem = fstype
        if label and not part.label:
            part.label = label
        return

    fstype = _detect_fs_via_file(part.device)
    if fstype:
        part.filesystem = fstype


# ---------------------------------------------------------------------------
# Mounting
# ---------------------------------------------------------------------------
def _short_mount_error(e: Exception) -> str:
    """Pull a concise message out of a failed mount command."""
    if isinstance(e, subprocess.CalledProcessError):
        stderr = (e.stderr or "").strip()
        if stderr:
            return stderr.splitlines()[-1].strip()
        return f"mount exited with code {e.returncode}"
    return str(e)


# Best-effort ("mount anyway") type sweep used in --force mode. Every known
# Linux-mountable filesystem driver is tried read-only, so a volume with a
# missing/wrong type hint, a damaged superblock, or an unfamiliar OS still
# mounts when at all possible -- the scaffold for edge devices and odd disks.
# Kept minimal (``ro`` only) to maximise the chance a stubborn driver accepts
# the mount; the nicer forensic options were already tried by the normal path.
_FORCE_TYPE_SWEEP: List[Tuple[Optional[str], str]] = [
    ("ntfs3", "ro"),
    ("ntfs-3g", "ro,force,show_sys_files,streams_interface=windows"),
    ("ntfs", "ro"),
    ("ext4", "ro,norecovery"),
    ("ext3", "ro,norecovery"),
    ("ext2", "ro"),
    ("xfs", "ro,norecovery"),
    ("btrfs", "ro,norecovery,usebackuproot"),
    ("vfat", "ro"),
    ("exfat", "ro"),
    ("exfat-fuse", "ro"),
    ("hfsplus", "ro,force"),
    ("hfs", "ro"),
    ("ufs", "ro,ufstype=ufs2"),
    ("ufs", "ro,ufstype=44bsd"),
    ("ufs", "ro,ufstype=sun"),
    ("ufs", "ro,ufstype=old"),
    ("iso9660", "ro"),
    (None, "ro"),
]


def _mount_attempts(fs: str, force: bool = False) -> List[Tuple[Optional[str], str]]:
    """Ordered (filesystem-type-or-None, options) attempts for a partition.

    A type of ``None`` lets ``mount`` auto-detect. Every list ends with an
    auto-detect attempt so a partition still mounts when blkid couldn't name
    the type, or when the named driver isn't the one the kernel provides.

    When *force* is set, the detected-type attempts are followed by an
    aggressive "mount anyway" sweep over every known driver (see
    :data:`_FORCE_TYPE_SWEEP`), so a damaged or unrecognised volume still mounts
    regardless of operating system.
    """
    base = _mount_attempts_base(fs)
    if force:
        # De-dup against the attempts already queued for the detected type so we
        # don't repeat identical commands, but keep order (detected type first).
        seen = set(base)
        base = base + [a for a in _FORCE_TYPE_SWEEP if a not in seen]
    return base


def _mount_attempts_base(fs: str) -> List[Tuple[Optional[str], str]]:
    auto = (None, _DEFAULT_MOUNT_OPTIONS)
    if not fs:
        return [auto]
    if fs == "ntfs":
        # The NTFS driver varies by distro: kernel ntfs3, ntfs-3g (FUSE), or the
        # legacy read-only `ntfs`. Try each with options it actually accepts.
        return [
            ("ntfs3", "ro,noatime,noexec"),
            ("ntfs-3g", "ro,noatime,noexec,show_sys_files,streams_interface=windows"),
            ("ntfs", "ro,noatime,noexec"),
            auto,
        ]
    if fs == "ufs":
        # FreeBSD-derived appliances (NetScaler, pfSense, modern FreeBSD) use
        # UFS2; older BSDs use 44bsd; Solaris uses sun. The Linux ufs driver
        # needs the right ``ufstype=`` or the superblock isn't recognised.
        return [
            ("ufs", "ro,noatime,noexec,ufstype=ufs2"),
            ("ufs", "ro,noatime,noexec,ufstype=44bsd"),
            ("ufs", "ro,noatime,noexec,ufstype=sun"),
            ("ufs", "ro,noatime,noexec,ufstype=old"),
            auto,
        ]
    if fs == "hfsplus":
        # Journaled HFS+ volumes that weren't cleanly unmounted need ``force``
        # to mount read-only; try the clean mount first, then force.
        return [
            ("hfsplus", "ro,noatime,noexec"),
            ("hfsplus", "ro,noatime,noexec,force"),
            ("hfs", "ro,noatime,noexec"),
            auto,
        ]
    if fs == "exfat":
        # Kernel exfat (5.4+) is preferred; older systems fall back to the
        # exfat-fuse helper invoked as ``mount -t exfat-fuse``.
        return [
            ("exfat", "ro,noatime,noexec"),
            ("exfat-fuse", "ro,noatime,noexec"),
            auto,
        ]
    return [(fs, _MOUNT_OPTIONS.get(fs, _DEFAULT_MOUNT_OPTIONS)), auto]


def _fuse_mount_commands(fs: str, device: str, mount_point: Path,
                         force: bool = False) -> List[List[str]]:
    """Standalone-FUSE-binary mount commands for *fs*, in priority order.

    Returns an empty list for filesystems mounted via ``mount`` (the usual
    path). For APFS/VMFS the driver is a dedicated binary with no ``mount -t``
    helper, so we build ``binary <args> <device> <mount_point>`` directly.

    In *force* mode every dedicated FUSE driver is offered as a last resort
    (not just the one for the detected type), so an APFS/VMFS volume with a
    missing or wrong type hint can still be tried.
    """
    commands: List[List[str]] = []
    entries = list(_FUSE_MOUNTERS.get(fs, []))
    if force:
        for other_fs, mounters in _FUSE_MOUNTERS.items():
            if other_fs == fs:
                continue
            entries.extend(mounters)
    for binary, args in entries:
        commands.append([binary, *args, device, str(mount_point)])
    return commands


def mount_partition(partition: PartitionInfo, mount_point: Path,
                    force: bool = False) -> PartitionInfo:
    """Mount a single partition read-only with forensic flags.

    Tries the detected filesystem (with driver fallbacks) and finally an
    auto-detected mount, so partitions still mount when blkid couldn't name the
    type. Error-isolating: on failure it sets ``mount_error`` and never raises.

    When *force* is set, a failed standard mount falls through to a "mount
    anyway" sweep over every known driver (see :func:`_mount_attempts`), and all
    dedicated FUSE drivers are tried -- so a damaged or unfamiliar volume mounts
    regardless of operating system whenever the kernel can read it at all.
    """
    if not partition.device:
        partition.mount_error = partition.mount_error or "partition was not exposed"
        return partition

    if partition.filesystem in _SKIP_FILESYSTEMS:
        logger.info("Skipping %s (%s)", partition.device, partition.filesystem)
        return partition

    ensure_mount_dir(mount_point)

    last_error = "unknown filesystem type"
    fuse_error = ""  # FUSE-binary failure: the actionable message for APFS/VMFS

    # 1. Dedicated FUSE binaries (APFS/VMFS) have no kernel/`mount -t` driver,
    #    so try them first when the detected type calls for one. Only the
    #    detected type's own drivers set the reported error; in force mode the
    #    sweep also tries unrelated FUSE drivers, whose failures are just noise.
    primary_fuse = {b for b, _ in _FUSE_MOUNTERS.get(partition.filesystem, [])}
    for cmd in _fuse_mount_commands(partition.filesystem, partition.device,
                                    mount_point, force=force):
        try:
            run_command(cmd, capture=True)
        except FileNotFoundError:
            if cmd[0] in primary_fuse:
                fuse_error = f"{cmd[0]} not installed"
            logger.debug("FUSE mounter missing: %s", cmd[0])
            continue
        except Exception as e:
            if cmd[0] in primary_fuse:
                fuse_error = _short_mount_error(e)
            logger.debug("FUSE mount attempt failed (%s): %s", cmd[0],
                         _short_mount_error(e))
            continue

        partition.mount_point = mount_point
        partition.mounted = True
        logger.info(
            "Mounted %s (%s) -> %s [%s]",
            partition.device, partition.filesystem, mount_point, cmd[0],
        )
        return partition

    # 2. Standard mount with detected-type and driver fallbacks (plus the
    #    aggressive "mount anyway" sweep when force is set).
    for fstype, options in _mount_attempts(partition.filesystem, force=force):
        cmd = ["mount", "-o", options]
        if fstype:
            cmd.extend(["-t", fstype])
        cmd.extend([partition.device, str(mount_point)])
        try:
            run_command(cmd, capture=True)
        except Exception as e:
            last_error = _short_mount_error(e)
            logger.debug(
                "mount attempt failed (%s, -t %s): %s",
                partition.device, fstype or "auto", last_error,
            )
            continue

        partition.mount_point = mount_point
        partition.mounted = True
        if not partition.filesystem and fstype:
            partition.filesystem = fstype
        logger.info(
            "Mounted %s (%s) -> %s [%s]",
            partition.device, partition.filesystem or fstype or "auto",
            mount_point, options,
        )
        return partition

    # The actionable error: the detected type's own FUSE driver failure when it
    # has one (e.g. "vmfs6-fuse not installed"); otherwise the standard-mount
    # error ("bad superblock", ...). fuse_error is only set for the detected
    # type -- not the force-mode sweep of unrelated drivers -- so an irrelevant
    # swept driver can no longer mask the real failure.
    partition.mount_error = fuse_error or last_error
    logger.warning("Failed to mount %s: %s", partition.device, partition.mount_error)
    return partition


def infer_os(partitions: List[PartitionInfo]) -> str:
    """Best-effort guess of the OS in an image from its filesystems/labels.

    Purely advisory - used for the mount summary. Returns "Unknown" when there
    isn't a confident signal.
    """
    fstypes = {p.filesystem for p in partitions if p.filesystem}
    labels = " ".join((p.label or "").lower() for p in partitions)

    if "vmfs" in fstypes:
        return "VMware ESXi (VMFS datastore)"
    if {"ntfs", "refs"} & fstypes:
        return "Windows"
    if {"apfs", "hfsplus", "hfs"} & fstypes:
        return "macOS"
    if "ufs" in fstypes:
        return "BSD/appliance (FreeBSD-based, e.g. NetScaler/pfSense)"
    if "zfs_member" in fstypes:
        return "ZFS appliance/host (Solaris/FreeBSD/Linux)"
    if {"ext2", "ext3", "ext4", "xfs", "btrfs", "lvm2_member"} & fstypes:
        return "Linux"
    if "vfat" in fstypes and ("efi" in labels or "esp" in labels):
        return "Windows/UEFI (EFI system partition only)"
    return "Unknown"


def unmount_partitions(partitions: List[PartitionInfo]) -> int:
    """Unmount all partitions in reverse order.

    Returns:
        Count of failures.
    """
    failures = 0
    for part in reversed(partitions):
        if not part.mounted or not part.mount_point:
            continue
        try:
            run_command(["umount", str(part.mount_point)], capture=False)
            part.mounted = False
            logger.info("Unmounted partition: %s", part.mount_point)
        except Exception as e:
            logger.error("Failed to unmount %s: %s", part.mount_point, e)
            failures += 1
    return failures


# ---------------------------------------------------------------------------
# LVM
# ---------------------------------------------------------------------------
def detect_lvm(devices: Union[str, List[str]]) -> List[str]:
    """Detect LVM volume groups whose physical volumes live on *devices*.

    Accepts a single device path or a list (e.g. the offset loop devices we
    created for each partition).  Matches a PV either exactly or by prefix (so a
    whole-disk device still matches its partition PVs).

    Returns:
        List of volume group names found.
    """
    if isinstance(devices, str):
        devices = [devices]
    device_set = {str(d) for d in devices if d}
    if not device_set:
        return []

    vg_names: List[str] = []
    try:
        result = run_command(["pvs", "--noheadings", "-o", "pv_name,vg_name"],
                             check=False, timeout=15)
        if result.returncode != 0:
            return []

        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            pv_name, vg_name = parts[0], parts[1]
            matched = pv_name in device_set or any(
                pv_name.startswith(d) for d in device_set
            )
            if matched and vg_name and vg_name not in vg_names:
                vg_names.append(vg_name)
                logger.info("Found LVM volume group: %s on %s", vg_name, pv_name)
    except FileNotFoundError:
        logger.debug("pvs not available (lvm2 not installed)")
    except Exception as e:
        logger.debug("LVM detection failed: %s", e)

    return vg_names


def activate_lvm(vg_names: List[str]) -> List[str]:
    """Activate LVM volume groups in read-only mode.

    Returns:
        List of logical volume device paths (e.g., /dev/vg0/lv_root).
    """
    lv_paths = []
    for vg_name in vg_names:
        try:
            run_command(["vgchange", "-ay", "--readonly", vg_name], capture=False)
            logger.info("Activated LVM VG: %s", vg_name)

            result = run_command([
                "lvs", "--noheadings", "-o", "lv_path", vg_name,
            ], check=False)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    lv_path = line.strip()
                    if lv_path:
                        lv_paths.append(lv_path)
                        logger.info("Found LV: %s", lv_path)
        except Exception as e:
            logger.error("Failed to activate LVM VG %s: %s", vg_name, e)

    return lv_paths


def deactivate_lvm(vg_names: List[str]) -> None:
    """Deactivate LVM volume groups."""
    for vg_name in vg_names:
        try:
            run_command(["vgchange", "-an", vg_name], capture=False)
            logger.info("Deactivated LVM VG: %s", vg_name)
        except Exception as e:
            logger.error("Failed to deactivate LVM VG %s: %s", vg_name, e)
