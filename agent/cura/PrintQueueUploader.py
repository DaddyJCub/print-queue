# PrintQueueUploader — Cura post-processing script
#
# Auto-uploads the sliced G-code to the print-queue the moment you slice, so it
# appears in the queue ready to "Send to LK5". You still slice exactly as today;
# this just saves the manual file upload.
#
# INSTALL
#   1. In Cura: Help > Show Configuration Folder, then copy this file into the
#      "scripts" subfolder.
#   2. Restart Cura.
#   3. Extensions > Post Processing > Modify G-Code > Add a script >
#      "Print Queue Uploader".
#   4. Fill in the Server URL and the Ingest Token (Admin panel > Printer Agents
#      shows the ingest token).
#
# The upload is best-effort: if it fails (offline, etc.) slicing still succeeds
# and a warning is shown; you can always upload the .gcode manually.

import json
import urllib.request
import uuid

from UM.Logger import Logger
from UM.Message import Message
from ..Script import Script


class PrintQueueUploader(Script):
    def getSettingDataString(self):
        return json.dumps({
            "name": "Print Queue Uploader",
            "key": "PrintQueueUploader",
            "metadata": {},
            "version": 2,
            "settings": {
                "server_url": {
                    "label": "Server URL",
                    "description": "Base URL of the print-queue server.",
                    "type": "str",
                    "default_value": "https://print.jcubhub.com"
                },
                "ingest_token": {
                    "label": "Ingest Token",
                    "description": "Token from Admin > Printer Agents.",
                    "type": "str",
                    "default_value": ""
                },
                "filename_prefix": {
                    "label": "Filename Prefix",
                    "description": "Optional prefix added to the uploaded file name.",
                    "type": "str",
                    "default_value": ""
                }
            }
        })

    def execute(self, data):
        server_url = self.getSettingValueByKey("server_url").rstrip("/")
        token = self.getSettingValueByKey("ingest_token").strip()
        prefix = self.getSettingValueByKey("filename_prefix").strip()

        if not token:
            Message("Print Queue: no ingest token set — skipping upload.",
                    title="Print Queue Uploader").show()
            return data

        gcode = "".join(data).encode("utf-8")
        name = "{}{}.gcode".format(prefix, uuid.uuid4().hex[:8])

        # Build a multipart/form-data body by hand (no external deps in Cura's runtime).
        boundary = "----PrintQueueBoundary" + uuid.uuid4().hex
        body = b"".join([
            ("--%s\r\n" % boundary).encode(),
            ('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % name).encode(),
            b"Content-Type: text/plain.gcode\r\n\r\n",
            gcode,
            ("\r\n--%s--\r\n" % boundary).encode(),
        ])

        url = server_url + "/api/printer-agent/v1/ingest/gcode"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "multipart/form-data; boundary=%s" % boundary)
        req.add_header("X-Ingest-Token", token)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            Message("Uploaded to print queue as %s" % payload.get("file_name", name),
                    title="Print Queue Uploader").show()
        except Exception as e:
            Logger.log("e", "Print Queue upload failed: %s", e)
            Message("Upload failed: %s\nYou can upload the .gcode manually." % e,
                    title="Print Queue Uploader").show()

        return data
