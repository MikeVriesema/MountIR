#!/usr/bin/env python3
"""MountIR image type detection via file extension and magic bytes."""

import subprocess
from enum import Enum
from pathlib import Path
from typing import Optional

from utils import logger, run_command


class ImageType(str, Enum):
    """Supported disk image formats."""
    E01 = "e01"
    L01 = "l01"
    VMDK = "vmdk"
    VHD = "vhd"
    VHDX = "vhdx"
    RAW = "raw"       # dd, raw, img, bin, 001
    ISO = "iso"
    AFF = "aff"
    AFF4 = "aff4"
    QCOW2 = "qcow2"
    SPLIT_RAW = "split_raw"  # .001/.002/.003 multi-segment raw
    VDI = "vdi"
    OVA = "ova"
    DMG = "dmg"
    SPARSEIMAGE = "sparseimage"
    XVA = "xva"
    UNKNOWN = "unknown"


# Human-readable list of supported formats (used in CLI messages/help).
SUPPORTED_FORMATS = (
    "E01/L01, Ex01/Lx01, DD/Raw/IMG, VMDK, VHD/VHDX, QCOW2, ISO, AFF, "
    "AFF4, VDI, OVA, DMG, sparseimage, XVA, split-raw"
)

# Extension -> ImageType mapping.
# Ex01/Lx01 are EnCase EWF version 2 containers; ewfmount handles them with
# the same code path as E01/L01, so they map onto the same ImageType.
_EXTENSION_MAP = {
    ".e01": ImageType.E01,
    ".ex01": ImageType.E01,   # EWF2 (EnCase v7+)
    ".l01": ImageType.L01,
    ".lx01": ImageType.L01,    # EWF2 logical evidence
    ".vmdk": ImageType.VMDK,
    ".vhd": ImageType.VHD,
    ".vhdx": ImageType.VHDX,
    ".dd": ImageType.RAW,
    ".raw": ImageType.RAW,
    ".img": ImageType.RAW,
    ".bin": ImageType.RAW,
    ".001": ImageType.RAW,       # May be upgraded to SPLIT_RAW below
    ".iso": ImageType.ISO,
    ".aff": ImageType.AFF,
    ".aff4": ImageType.AFF4,
    ".qcow2": ImageType.QCOW2,
    ".qcow": ImageType.QCOW2,
    ".vdi": ImageType.VDI,
    ".ova": ImageType.OVA,
    ".dmg": ImageType.DMG,
    ".sparseimage": ImageType.SPARSEIMAGE,
    ".sparsebundle": ImageType.SPARSEIMAGE,
    ".xva": ImageType.XVA,
}

# Multi-segment E01 extensions: .E02-.E99, .EAA-.EZZ
# We recognise these so we can point the user to .E01
_E01_SEGMENT_PATTERN = None  # compiled on first use


def _is_e01_segment(ext: str) -> bool:
    """Check if an extension looks like an E01 segment (.E02-.E99, .EAA-.EZZ)."""
    import re
    global _E01_SEGMENT_PATTERN
    if _E01_SEGMENT_PATTERN is None:
        _E01_SEGMENT_PATTERN = re.compile(
            r"^\.[eE]([0-9]{2}|[a-zA-Z]{2})$"
        )
    return bool(_E01_SEGMENT_PATTERN.match(ext))


def detect_image_type(image_path: Path) -> ImageType:
    """Detect image type from extension first, then file(1) magic.

    Args:
        image_path: Path to the disk image file.

    Returns:
        Detected ImageType, or ImageType.UNKNOWN.
    """
    if not image_path.exists():
        logger.error("Image file does not exist: %s", image_path)
        return ImageType.UNKNOWN

    # --- Extension-based detection ---
    ext = image_path.suffix.lower()
    if ext in _EXTENSION_MAP:
        detected = _EXTENSION_MAP[ext]

        # Special case: .001 may be a split raw if .002 sibling exists
        if ext == ".001" and detected == ImageType.RAW:
            sibling_002 = image_path.parent / f"{image_path.stem}.002"
            if sibling_002.exists():
                logger.debug(
                    "Found .002 sibling for %s — treating as SPLIT_RAW",
                    image_path.name,
                )
                return ImageType.SPLIT_RAW

        logger.debug("Detected %s from extension '%s'", detected.value, ext)
        return detected

    # Check for E01 segment files
    if _is_e01_segment(ext):
        logger.warning(
            "File appears to be an E01 segment (%s). "
            "Please provide the first segment (.E01).",
            ext,
        )
        return ImageType.E01

    # --- Magic-based detection using file(1) ---
    magic_type = _detect_by_magic(image_path)
    if magic_type is not None:
        logger.debug("Detected %s from file magic", magic_type.value)
        return magic_type

    logger.warning("Could not determine image type for: %s", image_path)
    return ImageType.UNKNOWN


def _detect_by_magic(image_path: Path) -> Optional[ImageType]:
    """Use the `file` command to detect image type from magic bytes."""
    try:
        result = run_command(
            ["file", "--brief", str(image_path)],
            check=False,
            timeout=30,
        )
        if result.returncode != 0:
            return None

        output = result.stdout.strip().lower()
        logger.debug("file(1) output: %s", output)

        # EWF / Expert Witness (covers EWF v1 E01/L01 and EWF v2 Ex01/Lx01)
        if "expert witness" in output or "ewf" in output:
            return ImageType.E01

        # QCOW
        if "qemu qcow" in output or "qcow2" in output:
            return ImageType.QCOW2

        # VMware
        if "vmware" in output or "vmdk" in output:
            return ImageType.VMDK

        # Microsoft Disk Image (VHD)
        if "microsoft disk image" in output:
            return ImageType.VHD

        # ISO 9660
        if "iso 9660" in output:
            return ImageType.ISO

        # Raw disk image indicators
        if "x86 boot sector" in output:
            return ImageType.RAW
        if "dos/mbr boot sector" in output:
            return ImageType.RAW

        # AFF
        if "aff " in output or "advanced forensic" in output:
            return ImageType.AFF

        # AFF4 (uses ZIP container with AFF4 metadata)
        if "aff4" in output:
            return ImageType.AFF4

        # VDI (VirtualBox)
        if "virtualbox" in output or "vdi " in output:
            return ImageType.VDI

        # OVA (TAR archive containing OVF + VMDK)
        if "posix tar" in output or "tar archive" in output:
            # Could be OVA or XVA — extension already handled above,
            # but if we're here, extension didn't match.
            pass

        # DMG (Apple Disk Image)
        if "apple" in output and "disk image" in output:
            return ImageType.DMG

        # XVA (Xen Virtual Appliance) — typically a tar
        if "xen" in output and "virtual" in output:
            return ImageType.XVA

    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug("file(1) command not available or timed out")

    return None
