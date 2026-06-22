"""Tests for mountir.py - CLI argument parsing and helpers."""

import io
import json
import sys
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mountir import build_parser, MOUNTIR_VERSION, _apply_json_input


class TestBuildParser:
    """Test argument parser construction."""

    def test_mount_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["mount", "/evidence/disk.E01"])
        assert args.command == "mount"
        assert args.image_path == "/evidence/disk.E01"
        assert args.mount_base == "/mnt/mountir"
        assert args.case_id == ""
        assert args.no_partitions is False
        assert args.verbose is False
        assert args.json is False

    def test_mount_with_all_options(self):
        parser = build_parser()
        args = parser.parse_args([
            "mount", "/evidence/disk.vmdk",
            "--mount-base", "/mnt/case001",
            "--case-id", "IR-2026-001",
            "--no-partitions",
            "--maelstrom",
            "--maelstrom-profiles", "eventlogs", "registry",
            "-v", "--json",
        ])
        assert args.image_path == "/evidence/disk.vmdk"
        assert args.mount_base == "/mnt/case001"
        assert args.case_id == "IR-2026-001"
        assert args.no_partitions is True
        assert args.maelstrom is True
        assert args.maelstrom_profiles == ["eventlogs", "registry"]
        assert args.verbose is True
        assert args.json is True

    def test_mount_with_json_input(self):
        parser = build_parser()
        args = parser.parse_args(["mount", "--json-input", "request.json"])
        assert args.json_input == "request.json"

    def test_mount_with_stdin_json(self):
        parser = build_parser()
        args = parser.parse_args(["mount", "--json-input", "-"])
        assert args.json_input == "-"

    def test_unmount_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["unmount", "EV_abc123"])
        assert args.command == "unmount"
        assert args.mount_point == "EV_abc123"

    def test_unmount_all(self):
        parser = build_parser()
        args = parser.parse_args(["unmount", "--all"])
        assert args.command == "unmount"
        assert args.all is True

    def test_list_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["list"])
        assert args.command == "list"

    def test_list_with_json(self):
        parser = build_parser()
        args = parser.parse_args(["list", "--json"])
        assert args.json is True

    def test_check_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["check"])
        assert args.command == "check"

    def test_no_command(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.command is None


class TestVersion:
    """Test version output."""

    def test_version_string(self):
        assert MOUNTIR_VERSION == "1.0.0"

    def test_version_flag(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0


class TestApplyJsonInput:
    """Test _apply_json_input() helper."""

    def test_json_from_file(self, tmp_path):
        """Parse JSON from a file."""
        json_file = tmp_path / "request.json"
        json_file.write_text(json.dumps({
            "image_path": "/evidence/disk.E01",
            "case_id": "IR-2026-001",
            "mount_base": "/mnt/custom",
            "mount_options": {"no_partitions": True},
            "maelstrom_callback": {
                "enabled": True,
                "profiles": ["eventlogs"],
                "output": "/evidence/collected",
            },
        }))

        args = Namespace(json_input=str(json_file))
        _apply_json_input(args)

        assert args.image_path == "/evidence/disk.E01"
        assert args.case_id == "IR-2026-001"
        assert args.mount_base == "/mnt/custom"
        assert args.no_partitions is True
        assert args.maelstrom is True
        assert args.maelstrom_profiles == ["eventlogs"]
        assert args.maelstrom_output == "/evidence/collected"

    def test_json_from_stdin(self):
        """Parse JSON from stdin."""
        json_data = json.dumps({
            "image_path": "/evidence/disk.vmdk",
            "case_id": "CASE-002",
        })

        args = Namespace(json_input="-")
        with patch("sys.stdin", io.StringIO(json_data)):
            _apply_json_input(args)

        assert args.image_path == "/evidence/disk.vmdk"
        assert args.case_id == "CASE-002"

    def test_json_minimal(self, tmp_path):
        """JSON with only required fields."""
        json_file = tmp_path / "minimal.json"
        json_file.write_text(json.dumps({
            "image_path": "/evidence/disk.dd",
        }))

        args = Namespace(json_input=str(json_file))
        _apply_json_input(args)

        assert args.image_path == "/evidence/disk.dd"
