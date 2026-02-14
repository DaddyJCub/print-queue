try:
    import hashlib
except Exception:
    import uhashlib as hashlib  # type: ignore

import os

from lib.file_store import read_json, write_json


class OtaManager:
    """Staged app-code OTA manager with rollback metadata hooks."""

    def __init__(
        self,
        api,
        app_state_path="/app_state.json",
        current_dir="/current",
        prev_dir="/prev",
        next_dir="/next",
    ):
        self.api = api
        self.app_state_path = app_state_path
        self.current_dir = current_dir
        self.prev_dir = prev_dir
        self.next_dir = next_dir

    def boot_guard(self, max_failures=3):
        state = read_json(self.app_state_path, default={}) or {}
        pending = state.get("pending_version")
        if not pending:
            state["boot_fail_count"] = 0
            write_json(self.app_state_path, state)
            return None

        fail_count = int(state.get("boot_fail_count", 0)) + 1
        state["boot_fail_count"] = fail_count
        write_json(self.app_state_path, state)

        if fail_count >= max_failures:
            self.rollback_to_previous()
            state = read_json(self.app_state_path, default={}) or {}
            state["pending_version"] = None
            state["boot_fail_count"] = 0
            write_json(self.app_state_path, state)
            return "rollback"
        return "pending"

    def check_latest(self, channel="stable"):
        status, data = self.api.latest_release(channel=channel)
        if status != 200:
            return None
        return data

    def apply_update(self, version_or_latest="latest", channel="stable"):
        version, manifest = self._resolve_manifest(version_or_latest, channel)
        files = manifest.get("files", [])
        if not isinstance(files, list) or not files:
            raise Exception("manifest files missing")

        self.api.update_status("downloading", progress=1, version=version)
        self._rm_tree(self.next_dir)
        self._mkdirp(self.next_dir)

        total = len(files)
        for idx, item in enumerate(files):
            rel_path = str(item.get("path") or "").strip().lstrip("/")
            expected_sha = str(item.get("sha256") or "").strip().lower()
            if not rel_path:
                raise Exception("invalid manifest file path")

            status, body = self.api.release_file(version, rel_path)
            if status != 200:
                raise Exception("release file download failed for " + rel_path)

            actual_sha = self._sha256_hex(body)
            if expected_sha and actual_sha != expected_sha:
                raise Exception("sha256 mismatch for " + rel_path)

            out_path = self.next_dir + "/" + rel_path
            self._mkdirp(self._dirname(out_path))
            with open(out_path, "wb") as fh:
                fh.write(body)

            progress = 1 + int((idx + 1) * 69 / total)
            self.api.update_status("downloading", progress=progress, version=version)

        self.api.update_status("applying", progress=75, version=version)
        self._rotate_dirs()

        state = read_json(self.app_state_path, default={}) or {}
        state["pending_version"] = version
        write_json(self.app_state_path, state)

        self.api.update_status("applying", progress=95, version=version)
        return version

    def confirm_pending_boot(self):
        state = read_json(self.app_state_path, default={}) or {}
        pending = state.get("pending_version")
        if not pending:
            return None

        status, _ = self.api.boot_ok(pending)
        if status != 200:
            return None

        state["last_good_version"] = pending
        state["pending_version"] = None
        state["boot_fail_count"] = 0
        write_json(self.app_state_path, state)
        self.api.update_status("success", progress=100, version=pending)
        return pending

    def mark_boot_failure(self, error_message):
        state = read_json(self.app_state_path, default={}) or {}
        fail_count = int(state.get("boot_fail_count", 0)) + 1
        state["boot_fail_count"] = fail_count
        write_json(self.app_state_path, state)
        self.api.update_status("failed", progress=0, error=str(error_message))

    def rollback_to_previous(self):
        self._rm_tree(self.current_dir)
        if self._exists(self.prev_dir):
            os.rename(self.prev_dir, self.current_dir)
        self.api.update_status("rollback", progress=100)

    def _resolve_manifest(self, version_or_latest, channel):
        if version_or_latest == "latest":
            status, data = self.api.latest_release(channel=channel)
            if status != 200 or not data:
                raise Exception("latest release unavailable")
            version = str(data.get("version") or "").strip()
            manifest = data.get("manifest") or {}
            if not version:
                raise Exception("latest release missing version")
            return version, manifest

        version = str(version_or_latest).strip()
        status, data = self.api.release_manifest(version)
        if status != 200 or not data:
            raise Exception("release manifest unavailable")
        manifest = data.get("manifest") or {}
        return version, manifest

    def _rotate_dirs(self):
        self._rm_tree(self.prev_dir)
        if self._exists(self.current_dir):
            os.rename(self.current_dir, self.prev_dir)
        os.rename(self.next_dir, self.current_dir)

    def _sha256_hex(self, payload):
        digest = hashlib.sha256()
        digest.update(payload)
        return "".join("{:02x}".format(b) for b in digest.digest())

    def _exists(self, path):
        try:
            os.stat(path)
            return True
        except Exception:
            return False

    def _is_dir(self, path):
        try:
            return os.stat(path)[0] & 0x4000 != 0
        except Exception:
            return False

    def _listdir(self, path):
        try:
            return os.listdir(path)
        except Exception:
            return []

    def _mkdirp(self, path):
        if not path:
            return
        parts = [p for p in path.split("/") if p]
        cur = ""
        for part in parts:
            cur += "/" + part
            if not self._exists(cur):
                os.mkdir(cur)

    def _rm_tree(self, path):
        if not self._exists(path):
            return
        if not self._is_dir(path):
            os.remove(path)
            return
        for name in self._listdir(path):
            self._rm_tree(path + "/" + name)
        os.rmdir(path)

    def _dirname(self, path):
        if "/" not in path:
            return ""
        return path.rsplit("/", 1)[0]
