"""OTA self-update: fetch an agent bundle, verify it, and swap the package.

The bundle is a .zip containing a ``printqueue_agent/`` directory. We download
it, verify the SHA-256 (when provided), extract to a temp dir, sanity-check it,
back up the live package, then copy the new files in place. The caller restarts
the process afterwards so the new code takes effect.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import tempfile
import zipfile

log = logging.getLogger("printqueue.update")


def package_dir() -> str:
    """Directory of the installed printqueue_agent package."""
    return os.path.dirname(os.path.abspath(__file__))


def download_and_apply(client, bundle_url: str, expected_sha: str | None) -> None:
    work = tempfile.mkdtemp(prefix="pq_update_")
    bundle = os.path.join(work, "bundle.zip")
    try:
        client.download_bundle(bundle_url, bundle)

        if expected_sha:
            actual = _sha256(bundle)
            if actual.lower() != expected_sha.lower():
                raise RuntimeError(f"Bundle checksum mismatch (expected {expected_sha}, got {actual})")

        extract = os.path.join(work, "extract")
        os.makedirs(extract, exist_ok=True)
        with zipfile.ZipFile(bundle) as zf:
            _safe_extract(zf, extract)

        new_pkg = _find_package(extract)
        if not new_pkg or not os.path.isfile(os.path.join(new_pkg, "__init__.py")):
            raise RuntimeError("Bundle does not contain a valid printqueue_agent package")

        _swap_package(new_pkg, package_dir())
        log.info("Agent package updated; restart pending")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_extract(zf: zipfile.ZipFile, dest: str) -> None:
    dest_abs = os.path.abspath(dest)
    for member in zf.namelist():
        target = os.path.abspath(os.path.join(dest, member))
        if not target.startswith(dest_abs + os.sep) and target != dest_abs:
            raise RuntimeError(f"Unsafe path in bundle: {member}")
    zf.extractall(dest)


def _find_package(root: str) -> str | None:
    """Locate the printqueue_agent directory within the extracted tree."""
    for dirpath, dirnames, _ in os.walk(root):
        if os.path.basename(dirpath) == "printqueue_agent":
            return dirpath
        if "printqueue_agent" in dirnames:
            return os.path.join(dirpath, "printqueue_agent")
    return None


def _swap_package(new_pkg: str, live_pkg: str) -> None:
    """Back up the live package and copy new files over it."""
    backup = live_pkg + ".bak"
    shutil.rmtree(backup, ignore_errors=True)
    shutil.copytree(live_pkg, backup)
    try:
        for name in os.listdir(new_pkg):
            src = os.path.join(new_pkg, name)
            dst = os.path.join(live_pkg, name)
            if os.path.isdir(src):
                shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
    except Exception:
        # Roll back from the backup on any failure.
        log.exception("Update failed; rolling back")
        for name in os.listdir(backup):
            src = os.path.join(backup, name)
            dst = os.path.join(live_pkg, name)
            try:
                if os.path.isdir(src):
                    shutil.rmtree(dst, ignore_errors=True)
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
            except Exception:
                pass
        raise
