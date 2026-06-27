"""HTTP client for the print-queue printer-agent API.

Every call is *outbound* from the agent to the server, so the printer's network
needs no inbound ports. The agent authenticates with a bearer token obtained by
provisioning once with its claim code.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import requests

log = logging.getLogger("printqueue.client")


class ServerError(Exception):
    pass


class PrintQueueClient:
    def __init__(self, base_url: str, agent_id: str, claim_code: str, *,
                 verify_tls: bool = True, timeout: float = 30.0):
        self.base = base_url.rstrip("/")
        self.api = f"{self.base}/api/printer-agent/v1"
        self.agent_id = agent_id
        self.claim_code = claim_code
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._token: Optional[str] = None
        self._session = requests.Session()

    # ── auth ──────────────────────────────────────────────────────
    @property
    def _headers(self) -> Dict[str, str]:
        if not self._token:
            raise ServerError("Not provisioned yet")
        return {"Authorization": f"Bearer {self._token}"}

    def provision(self, agent_version: str) -> Dict[str, Any]:
        """Exchange the claim code for a bearer token. Idempotent (re-provision rotates the token)."""
        r = self._session.post(
            f"{self.api}/provision",
            json={"agent_id": self.agent_id, "claim_code": self.claim_code, "agent_version": agent_version},
            verify=self.verify_tls, timeout=self.timeout,
        )
        if r.status_code != 200:
            raise ServerError(f"provision failed: {r.status_code} {r.text}")
        data = r.json()
        self._token = data["agent_token"]
        log.info("Provisioned as %s (printer_code=%s)", self.agent_id, data.get("printer_code"))
        return data

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Wrapper that re-provisions on 401 (token revoked/expired)."""
        url = f"{self.api}{path}"
        timeout = kwargs.pop("timeout", self.timeout)  # callers may override (long-poll)
        r = self._session.request(method, url, headers=self._headers,
                                  verify=self.verify_tls, timeout=timeout, **kwargs)
        if r.status_code == 401:
            log.warning("401 from server — re-provisioning")
            self._token = None
            self.provision(kwargs.pop("_agent_version", "unknown") or "unknown")
            r = self._session.request(method, url, headers=self._headers,
                                      verify=self.verify_tls, timeout=timeout, **kwargs)
        return r

    # ── lifecycle ─────────────────────────────────────────────────
    def heartbeat(self, agent_version: str, printer_status: Dict[str, Any]) -> None:
        r = self._request("POST", "/heartbeat", json={"agent_version": agent_version, "printer": printer_status})
        if r.status_code != 200:
            raise ServerError(f"heartbeat failed: {r.status_code} {r.text}")

    def next_job(self) -> Optional[Dict[str, Any]]:
        """Claim the next queued job, or None if the queue is empty."""
        r = self._request("GET", "/jobs/next")
        if r.status_code == 204:
            return None
        if r.status_code != 200:
            raise ServerError(f"jobs/next failed: {r.status_code} {r.text}")
        return r.json()

    def download_job_file(self, job_id: str, dest_path: str) -> None:
        r = self._request("GET", f"/jobs/{job_id}/file", stream=True)
        if r.status_code != 200:
            raise ServerError(f"download failed: {r.status_code} {r.text}")
        with open(dest_path, "wb") as fh:
            for chunk in r.iter_content(chunk_size=64 * 1024):
                if chunk:
                    fh.write(chunk)

    def update_job(self, job_id: str, status: str, *, progress: Optional[int] = None,
                   error: Optional[str] = None, result: Optional[Dict[str, Any]] = None) -> None:
        body: Dict[str, Any] = {"status": status}
        if progress is not None:
            body["progress"] = progress
        if error is not None:
            body["error"] = error
        if result is not None:
            body["result"] = result
        r = self._request("POST", f"/jobs/{job_id}/status", json=body)
        if r.status_code != 200:
            raise ServerError(f"update_job failed: {r.status_code} {r.text}")

    def next_command(self) -> Optional[Dict[str, Any]]:
        """Claim the next queued management command, or None."""
        r = self._request("GET", "/commands/next")
        if r.status_code == 204:
            return None
        if r.status_code != 200:
            raise ServerError(f"commands/next failed: {r.status_code} {r.text}")
        return r.json()

    def next_event(self, timeout_s: int = 20, want_jobs: bool = True) -> Optional[Dict[str, Any]]:
        """Long-poll for the next command or job. Returns None on timeout (204).

        The HTTP read timeout is given a margin over the server's hold window so
        the server, not the client, ends the long-poll.
        """
        params = {"timeout_s": int(timeout_s), "want_jobs": 1 if want_jobs else 0}
        r = self._request("GET", "/events/next", params=params, timeout=timeout_s + 15)
        if r.status_code == 204:
            return None
        if r.status_code != 200:
            raise ServerError(f"events/next failed: {r.status_code} {r.text}")
        return r.json()

    def update_command(self, cmd_id: str, status: str, *,
                       result: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> None:
        body: Dict[str, Any] = {"status": status}
        if result is not None:
            body["result"] = result
        if error is not None:
            body["error"] = error
        r = self._request("POST", f"/commands/{cmd_id}/status", json=body)
        if r.status_code != 200:
            raise ServerError(f"update_command failed: {r.status_code} {r.text}")

    def download_bundle(self, bundle_url: str, dest_path: str) -> None:
        """Download an OTA agent bundle (bundle_url is a server-relative path)."""
        url = f"{self.base}{bundle_url}" if bundle_url.startswith("/") else bundle_url
        r = self._session.get(url, headers=self._headers, verify=self.verify_tls, timeout=180, stream=True)
        if r.status_code != 200:
            raise ServerError(f"bundle download failed: {r.status_code} {r.text}")
        with open(dest_path, "wb") as fh:
            for chunk in r.iter_content(chunk_size=64 * 1024):
                if chunk:
                    fh.write(chunk)

    def upload_snapshot(self, jpeg_bytes: bytes) -> None:
        r = self._request("POST", "/snapshot", data=jpeg_bytes,
                          headers={**self._headers, "Content-Type": "image/jpeg"})
        if r.status_code != 200:
            raise ServerError(f"snapshot failed: {r.status_code} {r.text}")

    # ── local device UI self-update helpers ──────────────────────
    def self_update_state(self) -> Dict[str, Any]:
        r = self._request("GET", "/self/update-state")
        if r.status_code != 200:
            raise ServerError(f"self/update-state failed: {r.status_code} {r.text}")
        return r.json()

    def self_update(self) -> Dict[str, Any]:
        r = self._request("POST", "/self/update")
        if r.status_code != 200:
            raise ServerError(f"self/update failed: {r.status_code} {r.text}")
        return r.json()

    def self_update_verification(self, cmd_ids: str) -> Dict[str, Any]:
        r = self._request("GET", "/self/update-verification", params={"cmd_ids": cmd_ids})
        if r.status_code != 200:
            raise ServerError(f"self/update-verification failed: {r.status_code} {r.text}")
        return r.json()
