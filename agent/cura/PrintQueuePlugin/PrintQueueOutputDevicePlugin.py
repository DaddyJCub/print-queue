"""
Print Queue output device for Cura.

Registers a "Send to LK5 Pro" entry in Cura's save/print button. When clicked it
grabs the freshly-sliced G-code from the scene, uploads it to the print-queue
``/api/printer-agent/v1/print`` endpoint (which stores it and enqueues a job),
and the agent next to the printer starts the print. One click, no file export.

Configuration lives in ``config.json`` next to this file:

    {
      "server_url": "https://print.jcubhub.com",
      "ingest_token": "<from Admin > Printer Agents>",
      "printer_code": "LK5_PRO",
      "agent_id": ""          // optional; blank = newest online agent for printer_code
    }
"""

import json
import os
import threading
import urllib.request
import uuid

from UM.Application import Application
from UM.Logger import Logger
from UM.Message import Message
from UM.OutputDevice import OutputDeviceError
from UM.OutputDevice.OutputDevice import OutputDevice
from UM.OutputDevice.OutputDevicePlugin import OutputDevicePlugin

CONFIG_FILENAME = "config.json"


class PrintQueueOutputDevicePlugin(OutputDevicePlugin):
    """Adds/removes the Print Queue output device with Cura's lifecycle."""

    def start(self):
        self.getOutputDeviceManager().addOutputDevice(PrintQueueDevice())

    def stop(self):
        self.getOutputDeviceManager().removeOutputDevice("print_queue")


class PrintQueueDevice(OutputDevice):
    def __init__(self):
        super().__init__("print_queue")
        self._config = _load_config()
        printer = (self._config.get("printer_code") or "LK5 Pro")
        self.setName("Print Queue")
        self.setShortDescription("Send to %s" % printer)          # button label
        self.setDescription("Send sliced G-code to the print queue (%s)" % printer)
        self.setIconName("print")
        self.setPriority(2)

    def requestWrite(self, nodes, file_name=None, limit_mimetypes=None,
                     file_handler=None, filter_by_machine=False, **kwargs):
        """Called when the user picks "Send to ..." in Cura."""
        if not self._config.get("server_url") or not self._config.get("ingest_token"):
            Message(
                "Print Queue is not configured. Edit config.json in the plugin folder "
                "(set server_url and ingest_token), then restart Cura.",
                title="Print Queue", lifetime=0,
            ).show()
            raise OutputDeviceError.WriteRequestFailedError("Print Queue not configured")

        gcode = _get_scene_gcode()
        if not gcode:
            Message("No sliced G-code found — slice the model first.",
                    title="Print Queue").show()
            raise OutputDeviceError.WriteRequestFailedError("No g-code to send")

        name = (file_name or "cura_print") + ".gcode"
        self.writeStarted.emit(self)

        progress = Message("Uploading to print queue…", title="Print Queue",
                           progress=-1, dismissable=False, lifetime=0)
        progress.show()

        # Upload off the UI thread; report back via callLater on the main thread.
        threading.Thread(
            target=self._upload_worker,
            args=(gcode.encode("utf-8"), name, progress),
            daemon=True,
        ).start()

    # ── worker ────────────────────────────────────────────────────
    def _upload_worker(self, gcode_bytes, name, progress_message):
        try:
            payload = self._post(gcode_bytes, name)
            msg = payload.get("message", "Print queued.")
            self._finish(progress_message, success=True, text=msg)
        except Exception as e:
            Logger.log("e", "Print Queue upload failed: %s", e)
            self._finish(progress_message, success=False, text=str(e))

    def _post(self, gcode_bytes, name):
        cfg = self._config
        boundary = "----PrintQueueBoundary" + uuid.uuid4().hex
        parts = [
            ("--%s\r\n" % boundary).encode(),
            ('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % name).encode(),
            b"Content-Type: text/plain.gcode\r\n\r\n", gcode_bytes, b"\r\n",
        ]
        for field in ("agent_id", "printer_code"):
            value = cfg.get(field)
            if value:
                parts += [
                    ("--%s\r\n" % boundary).encode(),
                    ('Content-Disposition: form-data; name="%s"\r\n\r\n' % field).encode(),
                    str(value).encode(), b"\r\n",
                ]
        parts.append(("--%s--\r\n" % boundary).encode())
        body = b"".join(parts)

        url = cfg["server_url"].rstrip("/") + "/api/printer-agent/v1/print"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "multipart/form-data; boundary=%s" % boundary)
        req.add_header("X-Ingest-Token", cfg["ingest_token"])
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _finish(self, progress_message, success, text):
        def show():
            progress_message.hide()
            Message(text, title="Print Queue",
                    lifetime=0 if not success else 10).show()
            if success:
                self.writeSuccess.emit(self)
            else:
                self.writeError.emit(self)
            self.writeFinished.emit(self)
        Application.getInstance().callLater(show)


def _load_config():
    path = os.path.join(os.path.dirname(__file__), CONFIG_FILENAME)
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _get_scene_gcode():
    """Return the sliced G-code string, or ''.

    Uses Cura's GCodeWriter plugin (the same path as "Save to File"), which is
    the robust, version-stable way to obtain the active build plate's G-code —
    identical bytes to what you'd export by hand. Falls back to reading the
    scene's gcode_dict directly if the writer is unavailable.
    """
    # Preferred: GCodeWriter plugin.
    try:
        from io import StringIO
        from UM.PluginRegistry import PluginRegistry

        writer = PluginRegistry.getInstance().getPluginObject("GCodeWriter")
        stream = StringIO()
        if writer is not None and writer.write(stream, None):
            text = stream.getvalue()
            if text:
                return text
    except Exception as e:
        Logger.log("w", "GCodeWriter path failed, falling back: %s", e)

    # Fallback: read the scene gcode_dict directly.
    try:
        from cura.CuraApplication import CuraApplication
        app = CuraApplication.getInstance()
        scene = app.getController().getScene()
        gcode_dict = getattr(scene, "gcode_dict", None)
        if not gcode_dict:
            return ""
        try:
            active = app.getMultiBuildPlateModel().activeBuildPlate
        except Exception:
            active = 0
        gcode_list = gcode_dict.get(active) or gcode_dict.get(0)
        return "".join(gcode_list) if gcode_list else ""
    except Exception as e:
        Logger.log("e", "Could not read scene g-code: %s", e)
        return ""
