"""Tests for bootstrap.py - dependency mapping and source builds."""

import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import bootstrap


class TestSystemPackages:
    """The extended filesystem drivers are declared and mapped correctly."""

    @pytest.mark.parametrize("tool,package", [
        ("zpool", "zfsutils-linux"),       # ZFS pools
        ("vmfs-fuse", "vmfs-tools"),       # VMware VMFS5
        ("mount.exfat-fuse", "exfat-fuse"),  # exFAT FUSE fallback
        ("fsck.exfat", "exfatprogs"),      # exFAT userland
        ("fsck.hfsplus", "hfsprogs"),      # macOS HFS+
    ])
    def test_driver_tool_mapped(self, tool, package):
        assert bootstrap.SYSTEM_PACKAGES.get(tool) == package

    def test_missing_packages_dedup_and_map(self):
        # Only zpool is absent -> exactly its package is reported.
        def only_zpool_missing(tool):
            return tool != "zpool"
        with patch("bootstrap.tool_exists", side_effect=only_zpool_missing):
            assert bootstrap.missing_system_packages() == ["zfsutils-linux"]


class TestPrivPrefix:
    """Privilege escalation strategy selection."""

    def test_root_needs_no_prefix(self):
        with patch("bootstrap.is_root", return_value=True):
            assert bootstrap._priv_prefix() == []

    def test_sudo_when_not_root(self):
        with patch("bootstrap.is_root", return_value=False), \
             patch("bootstrap.tool_exists", return_value=True):
            assert bootstrap._priv_prefix() == ["sudo"]

    def test_none_when_no_escalation(self):
        with patch("bootstrap.is_root", return_value=False), \
             patch("bootstrap.tool_exists", return_value=False):
            assert bootstrap._priv_prefix() is None


class TestBuildApfsFuse:
    """apfs-fuse is built from source because it has no apt package."""

    def test_skips_when_already_installed(self):
        with patch("bootstrap.tool_exists", return_value=True), \
             patch("bootstrap.install_system_deps") as deps:
            assert bootstrap.build_apfs_fuse() is True
        deps.assert_not_called()

    def test_fails_without_privilege(self):
        with patch("bootstrap.tool_exists", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=None), \
             patch("bootstrap.install_system_deps") as deps:
            assert bootstrap.build_apfs_fuse(force=True) is False
        deps.assert_not_called()

    def test_build_dep_failure_aborts(self):
        with patch("bootstrap.tool_exists", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.install_system_deps", return_value=False), \
             patch("bootstrap._run") as run:
            assert bootstrap.build_apfs_fuse(force=True) is False
        run.assert_not_called()

    def test_happy_path_clones_and_builds(self, tmp_path):
        with patch("bootstrap._SOURCE_BUILD_ROOT", tmp_path / "src"), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.install_system_deps", return_value=True), \
             patch("bootstrap._run", return_value=True) as run, \
             patch("bootstrap.tool_exists", return_value=True):
            assert bootstrap.build_apfs_fuse(force=True) is True

        cmds = [c.args[0] for c in run.call_args_list]
        clone = next(c for c in cmds if c[:2] == ["git", "clone"])
        assert "--recursive" in clone and bootstrap.APFS_FUSE_REPO in clone
        assert ["cmake", ".."] in cmds
        assert any(c[:1] == ["make"] for c in cmds)

    def test_build_completes_but_binary_absent(self, tmp_path):
        # _run succeeds but the binary never lands on PATH -> reported failure.
        toolchk = iter([False])  # initial check skipped by force; final check False
        with patch("bootstrap._SOURCE_BUILD_ROOT", tmp_path / "src"), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.install_system_deps", return_value=True), \
             patch("bootstrap._run", return_value=True), \
             patch("bootstrap.tool_exists", return_value=False):
            assert bootstrap.build_apfs_fuse(force=True) is False


def _ewfmount_proc(stdout="", stderr=""):
    """A fake CompletedProcess for ``ewfmount -V``."""
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = 0
    return proc


class TestEwfmountVersion:
    """Parsing the installed ewfmount version and the EWF2 capability gate."""

    def test_none_when_tool_absent(self):
        # No ewfmount on PATH or in any known install dir.
        with patch("bootstrap._candidate_ewfmount_paths", return_value=[]):
            assert bootstrap.installed_ewfmount_version() is None

    def test_reports_newest_across_candidates(self):
        # Legacy apt build + source-built modern build present: report the newer.
        versions = {
            "/usr/bin/ewfmount": "20140807",
            "/usr/local/bin/ewfmount": "20240506",
        }
        with patch("bootstrap._candidate_ewfmount_paths",
                   return_value=list(versions)), \
             patch("bootstrap.ewfmount_version_of",
                   side_effect=lambda p: versions[p]):
            assert bootstrap.installed_ewfmount_version() == "20240506"

    def test_best_ewfmount_prefers_newest(self):
        # Even when the legacy build is listed first (PATH/secure_path order),
        # best_ewfmount returns the EWF2-capable one.
        versions = {
            "/usr/bin/ewfmount": "20140807",
            "/usr/local/bin/ewfmount": "20240506",
        }
        with patch("bootstrap._candidate_ewfmount_paths",
                   return_value=list(versions)), \
             patch("bootstrap.ewfmount_version_of",
                   side_effect=lambda p: versions[p]):
            assert bootstrap.best_ewfmount() == "/usr/local/bin/ewfmount"

    def test_best_ewfmount_none_when_absent(self):
        with patch("bootstrap._candidate_ewfmount_paths", return_value=[]), \
             patch("bootstrap.tool_exists", return_value=False):
            assert bootstrap.best_ewfmount() is None

    def test_parses_version_from_stdout(self):
        with patch("bootstrap.tool_exists", return_value=True), \
             patch("bootstrap.subprocess.run",
                   return_value=_ewfmount_proc(stdout="ewfmount 20140807\n")):
            assert bootstrap.installed_ewfmount_version() == "20140807"

    def test_parses_version_from_stderr(self):
        # Some builds print the banner to stderr.
        with patch("bootstrap.tool_exists", return_value=True), \
             patch("bootstrap.subprocess.run",
                   return_value=_ewfmount_proc(stderr="ewfmount 20240506\n")):
            assert bootstrap.installed_ewfmount_version() == "20240506"

    def test_none_on_unparseable_output(self):
        with patch("bootstrap.tool_exists", return_value=True), \
             patch("bootstrap.subprocess.run",
                   return_value=_ewfmount_proc(stdout="something else")):
            assert bootstrap.installed_ewfmount_version() is None

    def test_none_when_invocation_raises(self):
        with patch("bootstrap.tool_exists", return_value=True), \
             patch("bootstrap.subprocess.run", side_effect=FileNotFoundError):
            assert bootstrap.installed_ewfmount_version() is None

    def test_legacy_is_not_modern(self):
        with patch("bootstrap.installed_ewfmount_version", return_value="20140807"):
            assert bootstrap.have_modern_libewf() is False

    def test_pinned_version_is_modern(self):
        with patch("bootstrap.installed_ewfmount_version",
                   return_value=bootstrap.LIBEWF_VERSION):
            assert bootstrap.have_modern_libewf() is True

    def test_newer_than_pin_is_modern(self):
        with patch("bootstrap.installed_ewfmount_version", return_value="20250101"):
            assert bootstrap.have_modern_libewf() is True

    def test_absent_is_not_modern(self):
        with patch("bootstrap.installed_ewfmount_version", return_value=None):
            assert bootstrap.have_modern_libewf() is False


class TestExtractTarball:
    """_extract_tarball returns the archive's single top-level directory."""

    def test_returns_top_level_dir(self, tmp_path):
        # Build a tarball whose members all live under libewf-XX/.
        payload = tmp_path / "libewf-20240506"
        (payload / "sub").mkdir(parents=True)
        (payload / "configure").write_text("#!/bin/sh\n")
        (payload / "sub" / "f.c").write_text("int main(){}\n")
        tarball = tmp_path / "libewf-20240506.tar.gz"
        with tarfile.open(tarball, "w:gz") as tf:
            tf.add(payload, arcname="libewf-20240506")

        dest = tmp_path / "out"
        dest.mkdir()
        result = bootstrap._extract_tarball(tarball, dest)
        assert result == dest / "libewf-20240506"
        assert (result / "configure").exists()

    def test_bad_archive_returns_none(self, tmp_path):
        bogus = tmp_path / "broken.tar.gz"
        bogus.write_bytes(b"not a tarball")
        assert bootstrap._extract_tarball(bogus, tmp_path) is None


class TestBuildLibewf:
    """Modern libewf is built from source to add EWF2 (Ex01/Lx01) support."""

    def test_skips_when_modern_present(self):
        with patch("bootstrap.have_modern_libewf", return_value=True), \
             patch("bootstrap.install_system_deps") as deps:
            assert bootstrap.build_libewf() is True
        deps.assert_not_called()

    def test_fails_without_privilege(self):
        with patch("bootstrap.have_modern_libewf", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=None), \
             patch("bootstrap.install_system_deps") as deps:
            assert bootstrap.build_libewf(force=True) is False
        deps.assert_not_called()

    def test_build_dep_failure_aborts(self):
        with patch("bootstrap.have_modern_libewf", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.install_system_deps", return_value=False), \
             patch("bootstrap._download") as dl:
            assert bootstrap.build_libewf(force=True) is False
        dl.assert_not_called()

    def test_download_failure_aborts(self, tmp_path):
        with patch("bootstrap._SOURCE_BUILD_ROOT", tmp_path / "src"), \
             patch("bootstrap.have_modern_libewf", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.install_system_deps", return_value=True), \
             patch("bootstrap._download", return_value=False), \
             patch("bootstrap._extract_tarball") as extract:
            assert bootstrap.build_libewf(force=True) is False
        extract.assert_not_called()

    def test_happy_path_downloads_configures_installs(self, tmp_path):
        src = tmp_path / "libewf-20240506"
        # have_modern_libewf: top check skipped by force; final check True.
        with patch("bootstrap._SOURCE_BUILD_ROOT", tmp_path / "src"), \
             patch("bootstrap.have_modern_libewf", return_value=True), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.install_system_deps", return_value=True), \
             patch("bootstrap._download", return_value=True) as dl, \
             patch("bootstrap._extract_tarball", return_value=src), \
             patch("bootstrap._run", return_value=True) as run:
            assert bootstrap.build_libewf(force=True) is True

        # The pinned release URL was requested.
        assert bootstrap.LIBEWF_VERSION in dl.call_args.args[0]
        cmds = [c.args[0] for c in run.call_args_list]
        assert ["./configure"] in cmds
        assert ["make", "-j"] in cmds
        assert ["make", "install"] in cmds
        assert ["ldconfig"] in cmds

    def test_build_completes_but_not_modern(self, tmp_path):
        src = tmp_path / "libewf-20240506"
        with patch("bootstrap._SOURCE_BUILD_ROOT", tmp_path / "src"), \
             patch("bootstrap.have_modern_libewf", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.install_system_deps", return_value=True), \
             patch("bootstrap._download", return_value=True), \
             patch("bootstrap._extract_tarball", return_value=src), \
             patch("bootstrap._run", return_value=True):
            # force=True so the top gate is skipped; final gate is False.
            assert bootstrap.build_libewf(force=True) is False

    def test_env_var_overrides_pinned_version(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MOUNTIR_LIBEWF_VERSION", "20250101")
        src = tmp_path / "libewf-20250101"
        with patch("bootstrap._SOURCE_BUILD_ROOT", tmp_path / "src"), \
             patch("bootstrap.have_modern_libewf", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.install_system_deps", return_value=True), \
             patch("bootstrap._download", return_value=True) as dl, \
             patch("bootstrap._extract_tarball", return_value=src), \
             patch("bootstrap._run", return_value=True):
            bootstrap.build_libewf()
        assert "20250101" in dl.call_args.args[0]

    def test_explicit_version_argument_wins(self, tmp_path):
        src = tmp_path / "libewf-20231119"
        with patch("bootstrap._SOURCE_BUILD_ROOT", tmp_path / "src"), \
             patch("bootstrap.have_modern_libewf", return_value=False), \
             patch("bootstrap._priv_prefix", return_value=[]), \
             patch("bootstrap.install_system_deps", return_value=True), \
             patch("bootstrap._download", return_value=True) as dl, \
             patch("bootstrap._extract_tarball", return_value=src), \
             patch("bootstrap._run", return_value=True):
            bootstrap.build_libewf(force=True, version="20231119")
        assert "20231119" in dl.call_args.args[0]
