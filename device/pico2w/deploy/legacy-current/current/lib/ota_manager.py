try:
    import hashlib
except Exception:
    import uhashlib as hashlib  # type: ignore

import os

from lib.file_store import read_json, write_json


ROOT_MAIN_SHIM = """\
\"\"\"
main.py — Pico root main shim.
\"\"\"

try:
    from main import run as _run
except Exception:
    _run = None

if _run:
    _run()
"""


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
            self._safe_update_status(
                "rollback",
                progress=100,
                result={
                    "stage": "boot_guard",
                    "reason": "max_boot_failures",
                    "fail_count": fail_count,
                },
            )
            return "rollback"
        return "pending"

    def check_latest(self, channel="stable"):
        status, data = self.api.latest_release(channel=channel)
        if status != 200:
            return None
        return data

    def ensure_layout_compatibility(self):
        self._migrate_legacy_layout()

    def apply_update(self, version_or_latest="latest", channel="stable"):
        version, manifest = self._resolve_manifest(version_or_latest, channel)
        files = manifest.get("files", [])
        if not isinstance(files, list) or not files:
            raise Exception("manifest files missing")

        preflight = self._preflight_check(version, manifest, files)
        if not preflight.get("ok"):
            msg = preflight.get("error") or "ota preflight failed"
            self._safe_update_status(
                "failed",
                progress=0,
                version=version,
                error=msg,
                result={"stage": "preflight", "checks": preflight},
            )
            raise Exception(msg)

        self._safe_update_status(
            "downloading",
            progress=1,
            version=version,
            result={"stage": "preflight", "checks": preflight},
        )
        self._rm_tree(self.next_dir)
        self._mkdirp(self.next_dir)

        total = len(files)
        downloaded_paths = []
        for idx, item in enumerate(files):
            manifest_path = self._sanitize_manifest_path(item.get("path"))
            rel_path = self._normalize_release_path(item.get("path"))
            expected_sha = str(item.get("sha256") or "").strip().lower()
            if not manifest_path or not rel_path:
                raise Exception("invalid manifest file path")

            status, body = self.api.release_file(version, manifest_path)
            if status != 200:
                raise Exception("release file download failed for " + manifest_path)

            actual_sha = self._sha256_hex(body)
            if expected_sha and actual_sha != expected_sha:
                raise Exception("sha256 mismatch for " + rel_path)

            out_path = self.next_dir + "/" + rel_path
            self._mkdirp(self._dirname(out_path))
            with open(out_path, "wb") as fh:
                fh.write(body)
            downloaded_paths.append(rel_path)

            progress = 1 + int((idx + 1) * 69 / total)
            self._safe_update_status("downloading", progress=progress, version=version)

        staged = self._verify_staged_release(manifest, downloaded_paths)
        if not staged.get("ok"):
            msg = staged.get("error") or "staged release verification failed"
            self._safe_update_status(
                "failed",
                progress=0,
                version=version,
                error=msg,
                result={"stage": "verify_staged", "checks": staged},
            )
            self._rm_tree(self.next_dir)
            raise Exception(msg)

        self._safe_update_status(
            "applying",
            progress=75,
            version=version,
            result={"stage": "verify_staged", "checks": staged},
        )
        self._rotate_dirs()
        self._migrate_legacy_layout()

        post_apply = self._verify_runtime_layout(manifest=manifest)
        if not post_apply.get("ok"):
            msg = post_apply.get("error") or "post-apply verification failed"
            self.rollback_to_previous()
            self._safe_update_status(
                "failed",
                progress=0,
                version=version,
                error=msg,
                result={"stage": "post_apply_verify", "checks": post_apply},
            )
            raise Exception(msg)

        state = read_json(self.app_state_path, default={}) or {}
        state["pending_version"] = version
        write_json(self.app_state_path, state)

        self._safe_update_status(
            "applying",
            progress=95,
            version=version,
            result={"stage": "ready_to_reboot", "checks": post_apply},
        )
        return version

    def confirm_pending_boot(self):
        state = read_json(self.app_state_path, default={}) or {}
        pending = state.get("pending_version")
        if not pending:
            return None

        verify = self._verify_runtime_layout(manifest=None)
        if not verify.get("ok"):
            msg = verify.get("error") or "post-boot verification failed"
            self.mark_boot_failure(msg, result={"stage": "confirm_pending_boot", "checks": verify})
            return None

        status, _ = self.api.boot_ok(pending)
        if status != 200:
            return None

        state["last_good_version"] = pending
        state["pending_version"] = None
        state["boot_fail_count"] = 0
        write_json(self.app_state_path, state)
        self._safe_update_status(
            "success",
            progress=100,
            version=pending,
            result={"stage": "boot_confirmed", "checks": verify},
        )
        return pending

    def mark_boot_failure(self, error_message, result=None):
        state = read_json(self.app_state_path, default={}) or {}
        fail_count = int(state.get("boot_fail_count", 0)) + 1
        state["boot_fail_count"] = fail_count
        write_json(self.app_state_path, state)
        self._safe_update_status(
            "failed",
            progress=0,
            error=str(error_message),
            result=result or {"stage": "boot_failure", "fail_count": fail_count},
        )

    def rollback_to_previous(self):
        self._rm_tree(self.current_dir)
        if self._exists(self.prev_dir):
            os.rename(self.prev_dir, self.current_dir)
        self._migrate_legacy_layout()
        self._safe_update_status("rollback", progress=100, result={"stage": "rollback_to_previous"})

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

    def _preflight_check(self, version, manifest, files):
        checks = {
            "version": version,
            "file_count": len(files or []),
            "has_statvfs": hasattr(os, "statvfs"),
            "required_bytes": 0,
            "free_bytes": None,
            "writable": False,
            "required_paths_ok": False,
        }

        total_size = 0
        for item in files:
            try:
                total_size += int(item.get("size") or 0)
            except Exception:
                continue
        # Reserve headroom for extraction and state writes.
        checks["required_bytes"] = int(total_size + 128 * 1024)

        if hasattr(os, "statvfs"):
            try:
                stat = os.statvfs("/")
                block_size = int(stat[0])
                free_blocks = int(stat[3])
                free_bytes = block_size * free_blocks
                checks["free_bytes"] = free_bytes
                if free_bytes < checks["required_bytes"]:
                    checks["ok"] = False
                    checks["error"] = "insufficient free space"
                    return checks
            except Exception:
                # Keep going even when statvfs is unavailable/broken.
                pass

        checks["writable"] = self._check_writable()
        if not checks["writable"]:
            checks["ok"] = False
            checks["error"] = "filesystem not writable"
            return checks

        required_paths = self._required_paths_from_manifest(manifest)
        manifest_paths = set()
        for item in files:
            rel = self._normalize_release_path(item.get("path"))
            if rel:
                manifest_paths.add(rel)
        missing = [p for p in required_paths if p not in manifest_paths]
        checks["required_paths_ok"] = len(missing) == 0
        checks["missing_required_paths"] = missing
        if missing:
            checks["ok"] = False
            checks["error"] = "manifest missing required files"
            return checks

        checks["ok"] = True
        return checks

    def _verify_staged_release(self, manifest, downloaded_paths):
        checks = {
            "downloaded_count": len(downloaded_paths or []),
            "required_paths_ok": False,
            "entrypoint_ok": False,
        }
        downloaded = set(downloaded_paths or [])

        required_paths = self._required_paths_from_manifest(manifest)
        missing = [p for p in required_paths if p not in downloaded]
        checks["required_paths_ok"] = len(missing) == 0
        checks["missing_required_paths"] = missing
        if missing:
            checks["ok"] = False
            checks["error"] = "staged release missing required files"
            return checks

        entrypoint = str(manifest.get("entrypoint") or "main.py").strip().lstrip("/") or "main.py"
        entrypoint = self._normalize_release_path(entrypoint)
        checks["entrypoint"] = entrypoint
        checks["entrypoint_ok"] = bool(entrypoint and entrypoint in downloaded)
        if not checks["entrypoint_ok"]:
            checks["ok"] = False
            checks["error"] = "entrypoint missing from staged release"
            return checks

        checks["ok"] = True
        return checks

    def _verify_runtime_layout(self, manifest=None):
        checks = {
            "current_exists": self._exists(self.current_dir),
            "main_exists": self._exists(self.current_dir + "/main.py"),
            "lib_exists": self._exists(self.current_dir + "/lib"),
            "lib_init_exists": self._exists(self.current_dir + "/lib/__init__.py"),
            "entrypoint_callable": False,
        }
        if not checks["current_exists"] or not checks["main_exists"] or not checks["lib_exists"]:
            checks["ok"] = False
            checks["error"] = "required runtime paths missing"
            return checks

        required_paths = self._required_paths_from_manifest(manifest or {})
        missing_runtime = []
        for rel in required_paths:
            if not self._exists(self.current_dir + "/" + rel):
                missing_runtime.append(rel)
        checks["required_paths_ok"] = len(missing_runtime) == 0
        checks["missing_required_paths"] = missing_runtime
        if missing_runtime:
            checks["ok"] = False
            checks["error"] = "runtime missing required files"
            return checks

        try:
            with open(self.current_dir + "/main.py", "r") as fh:
                src = fh.read()
        except Exception:
            src = ""
        checks["entrypoint_callable"] = ("def run(" in src) or ("def main(" in src)
        if not checks["entrypoint_callable"]:
            checks["ok"] = False
            checks["error"] = "main.py missing run/main entrypoint"
            return checks

        checks["ok"] = True
        return checks

    def _required_paths_from_manifest(self, manifest):
        safety = manifest.get("safety") if isinstance(manifest, dict) else None
        required_paths = []
        if isinstance(safety, dict) and isinstance(safety.get("required_paths"), list):
            for raw in safety.get("required_paths") or []:
                rel = self._normalize_release_path(raw)
                if rel:
                    required_paths.append(rel)
        if not required_paths:
            required_paths = [
                "main.py",
                "lib/api_client.py",
                "lib/command_runner.py",
                "lib/hardware.py",
                "lib/ota_manager.py",
                "lib/__init__.py",
            ]
        # preserve order, unique
        out = []
        seen = set()
        for rel in required_paths:
            if rel in seen:
                continue
            seen.add(rel)
            out.append(rel)
        return out

    def _migrate_legacy_layout(self):
        # Keep root /main.py stable so legacy boot.py can always hand off to /current.
        root_main = "/main.py"
        if not self._exists(root_main):
            try:
                with open(root_main, "w") as fh:
                    fh.write(ROOT_MAIN_SHIM)
            except Exception:
                pass

        # Ensure /current/lib package import works with "from lib.*".
        lib_init = self.current_dir + "/lib/__init__.py"
        if not self._exists(lib_init):
            self._mkdirp(self.current_dir + "/lib")
            try:
                with open(lib_init, "w") as fh:
                    fh.write("# lib package\n")
            except Exception:
                pass

    def _normalize_release_path(self, raw_path):
        rel = str(raw_path or "").strip().replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        rel = rel.lstrip("/")
        if rel.startswith("current/"):
            rel = rel[len("current/") :]
        # Reject parent traversal paths.
        if not rel or "/../" in ("/" + rel + "/") or rel.startswith("../"):
            return ""
        return rel

    def _sanitize_manifest_path(self, raw_path):
        rel = str(raw_path or "").strip().replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        rel = rel.lstrip("/")
        if not rel or "/../" in ("/" + rel + "/") or rel.startswith("../"):
            return ""
        return rel

    def _check_writable(self):
        test_path = "/.ota_write_test.tmp"
        try:
            with open(test_path, "w") as fh:
                fh.write("ok")
            os.remove(test_path)
            return True
        except Exception:
            try:
                os.remove(test_path)
            except Exception:
                pass
            return False

    def _rotate_dirs(self):
        self._rm_tree(self.prev_dir)
        if self._exists(self.current_dir):
            os.rename(self.current_dir, self.prev_dir)
        os.rename(self.next_dir, self.current_dir)

    def _safe_update_status(self, status, progress=0, version=None, error=None, result=None):
        try:
            self.api.update_status(status, progress=progress, version=version, error=error, result=result)
        except Exception:
            pass

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
