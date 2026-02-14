import json

try:
    import urequests as requests
except Exception:
    import requests  # type: ignore


class ApiClient:
    def __init__(self, base_url, device_id, claim_code):
        self.base_url = base_url.rstrip("/")
        self.device_id = device_id
        self.claim_code = claim_code
        self.device_token = None

    def set_token(self, token):
        self.device_token = token

    def _post_json(self, path, payload, use_bearer=True):
        headers = {"Content-Type": "application/json"}
        if use_bearer and self.device_token:
            headers["Authorization"] = "Bearer " + self.device_token

        url = self.base_url + path
        resp = requests.post(url, data=json.dumps(payload), headers=headers)
        status = resp.status_code
        body_text = resp.text
        resp.close()

        data = None
        if body_text:
            try:
                data = json.loads(body_text)
            except Exception:
                data = {"raw": body_text}
        return status, data

    def _get_json(self, path, use_bearer=True):
        headers = {}
        if use_bearer and self.device_token:
            headers["Authorization"] = "Bearer " + self.device_token

        url = self.base_url + path
        resp = requests.get(url, headers=headers)
        status = resp.status_code
        body_text = resp.text
        resp.close()

        data = None
        if body_text:
            try:
                data = json.loads(body_text)
            except Exception:
                data = {"raw": body_text}
        return status, data

    def _get_bytes(self, path, use_bearer=True):
        headers = {}
        if use_bearer and self.device_token:
            headers["Authorization"] = "Bearer " + self.device_token

        url = self.base_url + path
        resp = requests.get(url, headers=headers)
        status = resp.status_code
        data = resp.content
        resp.close()
        return status, data

    def provision(self, fw_version, app_version):
        payload = {
            "device_id": self.device_id,
            "claim_code": self.claim_code,
            "fw_version": fw_version,
            "app_version": app_version,
        }
        return self._post_json("/api/printellect/device/v1/provision", payload, use_bearer=False)

    def heartbeat(self, fw_version, app_version, rssi=None, reset_event=None):
        payload = {
            "fw_version": fw_version,
            "app_version": app_version,
            "rssi": rssi,
        }
        if reset_event:
            payload["reset_event"] = reset_event
        return self._post_json("/api/printellect/device/v1/heartbeat", payload, use_bearer=True)

    def next_command(self):
        return self._get_json("/api/printellect/device/v1/commands/next", use_bearer=True)

    def command_status(self, cmd_id, status, error=None):
        payload = {"status": status}
        if error:
            payload["error"] = error
        return self._post_json("/api/printellect/device/v1/commands/%s/status" % cmd_id, payload, use_bearer=True)

    def state_update(self, state):
        return self._post_json("/api/printellect/device/v1/state", state, use_bearer=True)

    def update_status(self, status, progress=0, version=None, error=None):
        payload = {"status": status, "progress": progress}
        if version:
            payload["version"] = version
        if error:
            payload["error"] = error
        return self._post_json("/api/printellect/device/v1/update/status", payload, use_bearer=True)

    def boot_ok(self, version):
        payload = {"version": version}
        return self._post_json("/api/printellect/device/v1/boot-ok", payload, use_bearer=True)

    def latest_release(self, channel="stable"):
        return self._get_json("/api/printellect/device/v1/releases/latest?channel=%s" % channel, use_bearer=True)

    def release_manifest(self, version):
        return self._get_json("/api/printellect/device/v1/releases/%s/manifest" % version, use_bearer=True)

    def release_file(self, version, file_path):
        safe = str(file_path).lstrip("/")
        return self._get_bytes("/api/printellect/device/v1/releases/%s/files/%s" % (version, safe), use_bearer=True)
