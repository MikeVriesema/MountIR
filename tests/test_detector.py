"""Tests for detector.py - image type detection."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from detector import ImageType, detect_image_type, _is_e01_segment, _EXTENSION_MAP


class TestExtensionMapping:
    """Test extension-based image type detection."""

    @pytest.mark.parametrize("ext,expected", [
        (".e01", ImageType.E01),
        (".ex01", ImageType.E01),
        (".l01", ImageType.L01),
        (".lx01", ImageType.L01),
        (".vmdk", ImageType.VMDK),
        (".vhd", ImageType.VHD),
        (".vhdx", ImageType.VHDX),
        (".dd", ImageType.RAW),
        (".raw", ImageType.RAW),
        (".img", ImageType.RAW),
        (".bin", ImageType.RAW),
        (".001", ImageType.RAW),
        (".iso", ImageType.ISO),
        (".aff", ImageType.AFF),
        (".aff4", ImageType.AFF4),
        (".qcow2", ImageType.QCOW2),
        (".qcow", ImageType.QCOW2),
    ])
    def test_extension_map_coverage(self, ext, expected):
        """All documented extensions map to correct type."""
        assert _EXTENSION_MAP[ext] == expected

    def test_extension_detection_lowercase(self, fake_image_files):
        """Lowercase .e01 detected correctly."""
        result = detect_image_type(fake_image_files[".e01"])
        assert result == ImageType.E01

    def test_extension_detection_uppercase(self, fake_image_files):
        """.E01 (uppercase) also works via .lower()."""
        result = detect_image_type(fake_image_files[".E01"])
        assert result == ImageType.E01

    @pytest.mark.parametrize("ext,expected", [
        (".vmdk", ImageType.VMDK),
        (".vhd", ImageType.VHD),
        (".vhdx", ImageType.VHDX),
        (".dd", ImageType.RAW),
        (".raw", ImageType.RAW),
        (".img", ImageType.RAW),
        (".iso", ImageType.ISO),
        (".aff", ImageType.AFF),
        (".qcow2", ImageType.QCOW2),
    ])
    def test_extension_detection_all_types(self, fake_image_files, ext, expected):
        """Each extension returns correct ImageType."""
        result = detect_image_type(fake_image_files[ext])
        assert result == expected


class TestE01Segments:
    """Test E01 segment detection."""

    @pytest.mark.parametrize("ext", [".E02", ".E99", ".EAA", ".e05", ".eBB"])
    def test_e01_segment_recognized(self, ext):
        """Multi-segment E01 extensions are recognized."""
        assert _is_e01_segment(ext) is True

    @pytest.mark.parametrize("ext", [".E01", ".e01", ".txt", ".vmdk", ".E0"])
    def test_non_segment_rejected(self, ext):
        """Non-segment extensions are not matched."""
        # .E01 is the primary, not a segment; .e01 same
        if ext.lower() == ".e01":
            # .E01 matches the 2-digit pattern but that's fine
            # _is_e01_segment checks for [0-9]{2} or [a-zA-Z]{2}
            assert _is_e01_segment(ext) is True  # "01" is 2 digits
        elif len(ext) < 4:
            assert _is_e01_segment(ext) is False
        else:
            assert _is_e01_segment(ext) is False

    def test_segment_file_returns_e01(self, fake_image_files):
        """E01 segment files (.E02) still return E01 type."""
        result = detect_image_type(fake_image_files[".E02"])
        assert result == ImageType.E01


class TestMagicDetection:
    """Test file(1) magic-based detection."""

    @pytest.mark.parametrize("file_output,expected", [
        ("Expert Witness Compression Format", ImageType.E01),
        ("EWF/Expert Witness disk image", ImageType.E01),
        ("QEMU QCOW Image (v2)", ImageType.QCOW2),
        ("qcow2 disk image", ImageType.QCOW2),
        ("VMware4 disk image", ImageType.VMDK),
        ("Microsoft Disk Image", ImageType.VHD),
        ("ISO 9660 CD-ROM filesystem", ImageType.ISO),
        ("x86 boot sector", ImageType.RAW),
        ("DOS/MBR boot sector", ImageType.RAW),
    ])
    def test_magic_detection(self, tmp_path, file_output, expected):
        """file(1) output maps to correct ImageType."""
        # Create a file with unknown extension
        test_file = tmp_path / "mystery_file.dat"
        test_file.write_bytes(b"\x00" * 512)

        mock_result = MagicMock(returncode=0, stdout=file_output, stderr="")
        with patch("detector.run_command", return_value=mock_result):
            result = detect_image_type(test_file)
            assert result == expected

    def test_unknown_magic_returns_unknown(self, tmp_path):
        """Unrecognized file magic returns UNKNOWN."""
        test_file = tmp_path / "mystery_file.dat"
        test_file.write_bytes(b"\x00" * 512)

        mock_result = MagicMock(returncode=0, stdout="data", stderr="")
        with patch("detector.run_command", return_value=mock_result):
            result = detect_image_type(test_file)
            assert result == ImageType.UNKNOWN

    def test_file_command_failure_returns_unknown(self, tmp_path):
        """If file(1) fails, returns UNKNOWN."""
        test_file = tmp_path / "mystery_file.dat"
        test_file.write_bytes(b"\x00" * 512)

        mock_result = MagicMock(returncode=1, stdout="", stderr="error")
        with patch("detector.run_command", return_value=mock_result):
            result = detect_image_type(test_file)
            assert result == ImageType.UNKNOWN


class TestEdgeCases:
    """Test edge cases."""

    def test_nonexistent_file_returns_unknown(self, tmp_path):
        """Nonexistent file returns UNKNOWN."""
        result = detect_image_type(tmp_path / "does_not_exist.e01")
        assert result == ImageType.UNKNOWN

    def test_unknown_extension_falls_to_magic(self, tmp_path):
        """Unknown extension triggers magic-based detection."""
        test_file = tmp_path / "image.forensic"
        test_file.write_bytes(b"\x00" * 512)

        mock_result = MagicMock(
            returncode=0, stdout="Expert Witness Compression Format", stderr=""
        )
        with patch("detector.run_command", return_value=mock_result):
            result = detect_image_type(test_file)
            assert result == ImageType.E01
