#!/usr/bin/env python3
"""Handler for E01/L01 and Ex01/Lx01 (EnCase/EWF) disk images using ewfmount.

ewfmount transparently handles both EWF version 1 (E01/L01) and EWF version 2
(Ex01/Lx01) containers, so a single handler covers all four extensions.
"""

from pathlib import Path
from typing import List

from handlers.base import BaseHandler, MountResult
from utils import logger, run_command, fuse_unmount


class EwfHandler(BaseHandler):
    """Mount E01/L01/Ex01/Lx01 images via ewfmount (FUSE).

    ewfmount creates a FUSE mount point containing a raw device file
    (typically 'ewf1') that represents the uncompressed disk image.
    """

    @property
    def format_name(self) -> str:
        return "E01/EWF (incl. Ex01)"

    @property
    def required_tools(self) -> List[str]:
        return ["ewfmount"]

    def mount(self, image_path: Path, mount_point: Path) -> MountResult:
        """Mount E01/L01 image via ewfmount.

        Creates a FUSE mount exposing the raw image at <mount_point>/ewf1.
        ewfmount automatically handles multi-segment images (.E01,.E02,...).
        """
        try:
            run_command(["ewfmount", str(image_path), str(mount_point)], capture=False)
        except Exception as e:
            return MountResult(success=False, error=str(e))

        # Find the raw image file (typically ewf1)
        raw_path = mount_point / "ewf1"
        if not raw_path.exists():
            # Some versions use different naming
            candidates = list(mount_point.iterdir())
            if candidates:
                raw_path = candidates[0]
                logger.debug("EWF raw image at non-standard path: %s", raw_path)
            else:
                return MountResult(
                    success=False,
                    mount_point=mount_point,
                    error="ewfmount succeeded but no raw image found",
                )

        logger.info(
            "Mounted %s -> %s (raw: %s)",
            image_path.name, mount_point, raw_path.name,
        )
        return MountResult(
            success=True,
            mount_point=mount_point,
            raw_image_path=raw_path,
        )

    def unmount(self, mount_result: MountResult) -> bool:
        """Unmount the ewfmount FUSE filesystem."""
        if mount_result.mount_point:
            return fuse_unmount(mount_result.mount_point)
        return True
