"""Optional snapshot-push camera support.

Two sources, in order of preference:
  * ``snapshot_url`` — fetch a JPEG from a local streamer (ustreamer, mjpg-streamer,
    OctoPrint ``/webcam/?action=snapshot``). Works on a Pi or Windows, no extra deps.
  * ``device_index`` — grab a frame directly from a capture device via OpenCV
    (requires ``opencv-python``). Handy for a USB/CSI camera with no streamer.

Frames are pushed *outbound* to the server, so a camera on the printer's
(separate) network is viewable remotely without any inbound ports.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

from .config import CameraConfig

log = logging.getLogger("printqueue.camera")


class Camera:
    def __init__(self, cfg: CameraConfig, verify_tls: bool = True):
        self.cfg = cfg
        self.verify_tls = verify_tls
        self._cv = None  # lazy OpenCV capture

    def capture(self) -> Optional[bytes]:
        if not self.cfg.enabled:
            return None
        if self.cfg.snapshot_url:
            return self._from_url()
        if self.cfg.device_index is not None:
            return self._from_device()
        return None

    def _from_url(self) -> Optional[bytes]:
        try:
            r = requests.get(self.cfg.snapshot_url, timeout=8, verify=self.verify_tls)
            if r.status_code == 200 and r.content:
                return r.content
            log.warning("snapshot_url returned %s", r.status_code)
        except Exception as e:
            log.warning("snapshot_url fetch failed: %s", e)
        return None

    def _from_device(self) -> Optional[bytes]:
        try:
            import cv2  # type: ignore
        except ImportError:
            log.warning("device_index set but opencv-python is not installed")
            return None
        try:
            if self._cv is None:
                self._cv = cv2.VideoCapture(self.cfg.device_index)
            ok, frame = self._cv.read()
            if not ok:
                return None
            ok, buf = cv2.imencode(".jpg", frame)
            return buf.tobytes() if ok else None
        except Exception as e:
            log.warning("device capture failed: %s", e)
            return None
