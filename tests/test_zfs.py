"""Tests for zfs.py - read-only forensic ZFS pool import/export."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import zfs
from zfs import (
    PoolCandidate,
    parse_import_scan,
    parse_zfs_list,
    scan_pools,
    import_pool,
    mount_datasets,
    export_pool,
)


class TestParseImportScan:
    """Parsing `zpool import` dry-run text."""

    SINGLE = (
        "   pool: tank\n"
        "     id: 12345678901234567890\n"
        "  state: ONLINE\n"
        " action: The pool can be imported using its name or numeric identifier.\n"
        " config:\n"
        "        tank        ONLINE\n"
        "          loop3     ONLINE\n"
    )

    def test_single_pool(self):
        pools = parse_import_scan(self.SINGLE)
        assert pools == [PoolCandidate("tank", "12345678901234567890", "ONLINE")]

    def test_multiple_pools(self):
        text = self.SINGLE + (
            "   pool: backup\n"
            "     id: 999\n"
            "  state: DEGRADED\n"
        )
        pools = parse_import_scan(text)
        assert [p.name for p in pools] == ["tank", "backup"]
        assert pools[1].state == "DEGRADED"
        assert pools[1].pool_id == "999"

    def test_empty_output(self):
        assert parse_import_scan("") == []

    def test_id_state_without_pool_ignored(self):
        # Stray fields before any 'pool:' line must not crash or attach.
        assert parse_import_scan("     id: 42\n  state: ONLINE\n") == []


class TestParseZfsList:
    """Parsing tab-separated `zfs list` output."""

    def test_basic(self):
        out = "tank\t/mnt/x/zfs/tank\tyes\ntank/data\t/mnt/x/zfs/tank/data\tyes\n"
        rows = parse_zfs_list(out)
        assert rows == [
            ("tank", "/mnt/x/zfs/tank", True),
            ("tank/data", "/mnt/x/zfs/tank/data", True),
        ]

    def test_unmounted_and_legacy(self):
        out = "tank/iscsi\tlegacy\tno\ntank/none\tnone\tno\n"
        rows = parse_zfs_list(out)
        assert rows[0] == ("tank/iscsi", "legacy", False)
        assert rows[1][2] is False

    def test_blank_and_short_lines_skipped(self):
        assert parse_zfs_list("\nincomplete\t/mp\n") == []


class TestScanPools:
    """scan_pools wiring and guards."""

    def test_no_devices_returns_empty(self):
        assert scan_pools([]) == []

    def test_zfs_unavailable_returns_empty(self):
        with patch("zfs.zfs_available", return_value=False):
            assert scan_pools(["/dev/loop3"]) == []

    def test_scans_listed_devices_only(self):
        scan = MagicMock(returncode=0,
                         stdout="   pool: tank\n     id: 7\n  state: ONLINE\n",
                         stderr="")
        with patch("zfs.zfs_available", return_value=True), \
             patch("zfs.run_command", return_value=scan) as rc:
            pools = scan_pools(["/dev/loop3", "/dev/loop4"])
        assert [p.name for p in pools] == ["tank"]
        cmd = rc.call_args.args[0]
        assert cmd[:2] == ["zpool", "import"]
        # one -d per device, and never a bare directory scan
        assert cmd.count("-d") == 2
        assert "/dev/loop3" in cmd and "/dev/loop4" in cmd

    def test_missing_binary_is_graceful(self):
        with patch("zfs.zfs_available", return_value=True), \
             patch("zfs.run_command", side_effect=FileNotFoundError("zpool")):
            assert scan_pools(["/dev/loop3"]) == []


class TestImportPool:
    """import_pool builds a forensic-safe command and reports the pool name."""

    def _run_ok(self):
        return MagicMock(returncode=0, stdout="", stderr="")

    def test_readonly_forced_altroot_command(self, tmp_path):
        cand = PoolCandidate("tank", "7", "ONLINE")
        with patch("zfs.run_command", return_value=self._run_ok()) as rc:
            name = import_pool(cand, tmp_path / "alt", ["/dev/loop3", "/dev/loop4"])
        assert name == "tank"
        cmd = rc.call_args.args[0]
        assert "readonly=on" in cmd
        assert "-f" in cmd          # forced: evidence came from another host
        assert "-N" in cmd          # don't auto-mount at import
        assert "-R" in cmd and str(tmp_path / "alt") in cmd
        assert cmd[-1] == "7"       # import by numeric id (unambiguous)
        assert cmd.count("-d") == 2

    def test_failure_returns_empty(self, tmp_path):
        cand = PoolCandidate("tank", "7", "ONLINE")
        with patch("zfs.run_command", side_effect=RuntimeError("no module")):
            assert import_pool(cand, tmp_path, ["/dev/loop3"]) == ""

    def test_rename_avoids_collision(self, tmp_path):
        cand = PoolCandidate("tank", "7", "ONLINE")
        with patch("zfs.run_command", return_value=self._run_ok()) as rc:
            name = import_pool(cand, tmp_path, ["/dev/loop3"], rename_to="ev_tank")
        assert name == "ev_tank"
        assert rc.call_args.args[0][-2:] == ["7", "ev_tank"]

    def test_degraded_state_still_imports(self, tmp_path):
        cand = PoolCandidate("tank", "7", "DEGRADED")
        with patch("zfs.run_command", return_value=self._run_ok()):
            assert import_pool(cand, tmp_path, ["/dev/loop3"]) == "tank"


class TestMountDatasets:
    """mount_datasets mounts only mountable filesystem datasets."""

    def test_mounts_unmounted_and_reports(self):
        before = MagicMock(returncode=0, stderr="", stdout=(
            "tank\t/mnt/x/zfs/tank\tno\n"
            "tank/leg\tlegacy\tno\n"
        ))
        after = MagicMock(returncode=0, stderr="", stdout=(
            "tank\t/mnt/x/zfs/tank\tyes\n"
            "tank/leg\tlegacy\tno\n"
        ))
        # list(before) -> mount(tank) -> list(after)
        with patch("zfs.run_command", side_effect=[before, MagicMock(returncode=0), after]) as rc:
            mounted = mount_datasets("tank")
        assert mounted == [("tank", "/mnt/x/zfs/tank")]
        # the legacy dataset must NOT be mounted
        mount_cmds = [c.args[0] for c in rc.call_args_list if c.args[0][:2] == ["zfs", "mount"]]
        assert mount_cmds == [["zfs", "mount", "tank"]]


class TestExportPool:
    """export_pool releases the pool and its vdevs."""

    def test_plain_export_success(self):
        with patch("zfs.zfs_available", return_value=True), \
             patch("zfs.run_command", return_value=MagicMock(returncode=0)) as rc:
            assert export_pool("tank") is True
        assert rc.call_args.args[0] == ["zpool", "export", "tank"]

    def test_falls_back_to_forced_export(self):
        calls = [RuntimeError("busy"), MagicMock(returncode=0)]
        with patch("zfs.zfs_available", return_value=True), \
             patch("zfs.run_command", side_effect=calls) as rc:
            assert export_pool("tank") is True
        assert rc.call_args_list[-1].args[0] == ["zpool", "export", "-f", "tank"]

    def test_unavailable_returns_false(self):
        with patch("zfs.zfs_available", return_value=False):
            assert export_pool("tank") is False

    def test_both_attempts_fail(self):
        with patch("zfs.zfs_available", return_value=True), \
             patch("zfs.run_command", side_effect=RuntimeError("x")):
            assert export_pool("tank") is False
