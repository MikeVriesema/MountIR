#!/usr/bin/env python3
"""ZFS storage-pool import/export for forensic read-only access.

A ZFS pool is not mounted like a partition.  The pool spans one or more vdev
devices and is brought online with ``zpool import``; that command then exposes
the pool's datasets, each of which is an independently mountable filesystem.

For forensics we import:

  * ``-o readonly=on`` -- never write to the evidence pool.
  * ``-f``             -- forced: the pool was last touched on a *different*
                          host (the evidence machine), so its hostid won't
                          match and a plain import is refused.
  * ``-N``             -- don't auto-mount datasets at import; we mount them
                          ourselves so partial failures are visible/contained.
  * ``-R <altroot>``   -- alternate root: every dataset's mountpoint is taken
                          relative to ``altroot``, so the evidence filesystem
                          tree is reconstructed *inside* our managed mount
                          directory instead of over the analyst's real ``/``.

This requires the OpenZFS kernel module + userland (``zfsutils-linux``).  On a
stock WSL2 kernel (no loadable-module support) ``zpool import`` fails cleanly:
``scan_pools`` returns nothing and the ``zfs_member`` devices are left intact.
"""

import re
from pathlib import Path
from typing import List, Optional, Tuple

from utils import logger, run_command, tool_exists

# zpool import dry-run lines: "  pool: tank" / "    id: 12345..." / " state: ONLINE"
_POOL_RE = re.compile(r"^\s*pool:\s*(\S+)\s*$")
_ID_RE = re.compile(r"^\s*id:\s*(\d+)\s*$")
_STATE_RE = re.compile(r"^\s*state:\s*(\S+)\s*$")


class PoolCandidate:
    """An importable pool reported by ``zpool import`` (dry run)."""

    __slots__ = ("name", "pool_id", "state")

    def __init__(self, name: str, pool_id: str = "", state: str = ""):
        self.name = name
        self.pool_id = pool_id
        self.state = state

    def __eq__(self, other) -> bool:  # for tests
        return (
            isinstance(other, PoolCandidate)
            and (self.name, self.pool_id, self.state)
            == (other.name, other.pool_id, other.state)
        )

    def __repr__(self) -> str:
        return f"PoolCandidate({self.name!r}, {self.pool_id!r}, {self.state!r})"


def zfs_available() -> bool:
    """True when both ``zpool`` and ``zfs`` are on PATH."""
    return tool_exists("zpool") and tool_exists("zfs")


def parse_import_scan(output: str) -> List[PoolCandidate]:
    """Parse ``zpool import`` (dry-run) text into a list of PoolCandidate.

    Pure/text-only so it is testable without ZFS installed.  Each pool block
    starts at a ``pool:`` line; ``id:`` and ``state:`` belong to the pool block
    most recently opened.
    """
    pools: List[PoolCandidate] = []
    current: Optional[PoolCandidate] = None
    for line in output.splitlines():
        m = _POOL_RE.match(line)
        if m:
            current = PoolCandidate(m.group(1))
            pools.append(current)
            continue
        if current is None:
            continue
        m = _ID_RE.match(line)
        if m:
            current.pool_id = m.group(1)
            continue
        m = _STATE_RE.match(line)
        if m:
            current.state = m.group(1)
    return pools


def parse_zfs_list(output: str) -> List[Tuple[str, str, bool]]:
    """Parse ``zfs list -rH -o name,mountpoint,mounted`` -> [(name, mp, mounted)].

    Tab-separated, one dataset per line.  ``mounted`` is the literal ``yes``.
    """
    rows: List[Tuple[str, str, bool]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        name, mountpoint, mounted = fields[0], fields[1], fields[2]
        rows.append((name.strip(), mountpoint.strip(), mounted.strip() == "yes"))
    return rows


def scan_pools(devices: List[str]) -> List[PoolCandidate]:
    """Dry-run ``zpool import`` restricted to *devices* to find importable pools.

    ``-d <dev>`` is passed once per device so only the evidence vdevs are
    scanned (never the analyst host's own disks).
    """
    devices = [d for d in devices if d]
    if not devices or not zfs_available():
        return []
    cmd = ["zpool", "import"]
    for dev in devices:
        cmd += ["-d", dev]
    try:
        result = run_command(cmd, check=False, timeout=60)
    except FileNotFoundError:
        return []
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("zpool import scan failed: %s", e)
        return []
    # returncode is nonzero when no pools are found; parse stdout regardless.
    return parse_import_scan(result.stdout or "")


def import_pool(candidate: PoolCandidate, altroot: Path,
                devices: List[str], rename_to: str = "") -> str:
    """Import *candidate* read-only under *altroot*.  Returns the effective
    pool name on success, or ``""`` on failure.

    Imports by numeric pool id when known (unambiguous even if a same-named
    pool exists on the analyst host).  ``rename_to`` imports the evidence pool
    under a fresh name to dodge a name collision.
    """
    devices = [d for d in devices if d]
    target = candidate.pool_id or candidate.name
    effective = rename_to or candidate.name

    cmd = ["zpool", "import", "-f", "-o", "readonly=on", "-N", "-R", str(altroot)]
    for dev in devices:
        cmd += ["-d", dev]
    cmd.append(target)
    if rename_to:
        cmd.append(rename_to)

    try:
        run_command(cmd, check=True, capture=True, timeout=120)
    except Exception as e:
        logger.error("zpool import of %s failed: %s", effective, e)
        return ""
    if candidate.state and candidate.state.upper() != "ONLINE":
        logger.warning(
            "Pool %s imported in state %s - some datasets may be incomplete "
            "(missing vdevs across images?)", effective, candidate.state,
        )
    logger.info("Imported ZFS pool %s (read-only) under %s", effective, altroot)
    return effective


def mount_datasets(pool: str) -> List[Tuple[str, str]]:
    """Mount every mountable filesystem dataset of *pool*; return mounted ones.

    ``zfs mount <dataset>`` is a no-op/expected-failure for datasets with
    ``mountpoint=legacy|none`` or ``canmount=off`` -- those are ignored.
    Returns ``[(dataset, mountpoint), ...]`` for datasets that ended up mounted.
    """
    try:
        listing = run_command(
            ["zfs", "list", "-rH", "-o", "name,mountpoint,mounted",
             "-t", "filesystem", pool],
            check=False, timeout=60,
        )
    except Exception as e:
        logger.debug("zfs list failed for %s: %s", pool, e)
        return []
    rows = parse_zfs_list(listing.stdout or "")

    for name, mountpoint, mounted in rows:
        if mounted or mountpoint in ("legacy", "none", "-"):
            continue
        try:
            run_command(["zfs", "mount", name], check=False, capture=True, timeout=60)
        except Exception as e:
            logger.debug("zfs mount %s failed: %s", name, e)

    # Re-read to report what is actually mounted now.
    try:
        listing = run_command(
            ["zfs", "list", "-rH", "-o", "name,mountpoint,mounted",
             "-t", "filesystem", pool],
            check=False, timeout=60,
        )
        rows = parse_zfs_list(listing.stdout or "")
    except Exception:
        pass
    return [(n, mp) for n, mp, m in rows if m and mp not in ("legacy", "none", "-")]


def export_pool(pool: str) -> bool:
    """Export *pool* (unmounts all its datasets and releases its vdevs).

    Tries a plain export first, then ``-f`` for a busy pool.  Returns True on
    success.
    """
    if not zfs_available():
        return False
    for args in (["zpool", "export", pool], ["zpool", "export", "-f", pool]):
        try:
            run_command(args, check=True, capture=True, timeout=60)
            logger.info("Exported ZFS pool %s", pool)
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            logger.debug("%s failed: %s", " ".join(args), e)
    logger.error("Failed to export ZFS pool %s", pool)
    return False
