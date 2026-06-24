"""HTTP client for the Printables public GraphQL API.

Network boundary for the Printables integration. The schema below was verified
live against ``https://api.printables.com/graphql/`` (see
``docs/printables-integration.md``). No client-side provider JS is executed
(SEC-004); we only issue documented GraphQL operations.

The functions accept an optional ``transport`` so tests can inject an
``httpx.MockTransport`` without any extra dependency or live network call
(TASK-003).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("printables")

PRINTABLES_GRAPHQL_URL = "https://api.printables.com/graphql/"

# SEC-002: connect 10s, read 20s, plus a response-size ceiling.
DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=20.0, write=20.0, pool=10.0)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # metadata payloads are tiny; 5MB is generous

_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "PrintQueue/1.0 (+https://github.com/DaddyJCub/print-queue)",
    "Origin": "https://www.printables.com",
    "Referer": "https://www.printables.com/",
}

# ── GraphQL operations (verified field shapes) ──────────────────────────────

MODEL_QUERY = """
query PrintQueueModel($id: ID!) {
  print(id: $id) {
    id
    name
    summary
    description
    filesCount
    excludeCommercialUsage
    premium
    price
    license { name abbreviation }
    user { publicUsername }
    stls { id name fileSize folder }
    gcodes { id name fileSize folder }
    slas { id name fileSize folder }
    otherFiles { id name fileSize folder fileFormat }
    downloadPacks { id name fileSize fileType }
  }
}
""".strip()

DOWNLOAD_MUTATION = """
mutation PrintQueueDownload($printId: ID!, $source: DownloadSourceEnum!, $files: [DownloadFileInput]) {
  getDownloadLink(printId: $printId, source: $source, files: $files) {
    ok
    errors { field messages }
    output {
      link
      ttl
      count
      files { id link ttl fileType }
    }
  }
}
""".strip()


# ── Error taxonomy (PAT-001: deterministic error classes) ───────────────────

class PrintablesError(Exception):
    """Base class for all Printables integration failures."""


class PrintablesUnavailable(PrintablesError):
    """Transient/provider problem (timeout, network error, 5xx)."""


class PrintablesNotFound(PrintablesError):
    """Model id is invalid or the model does not exist."""


class PrintablesResponseError(PrintablesError):
    """The provider responded but the payload was unusable (GraphQL errors,
    oversized body, malformed JSON)."""


def _post(payload: Dict[str, Any], *, transport: Optional[httpx.BaseTransport] = None) -> Dict[str, Any]:
    """POST a GraphQL operation and return the ``data`` object.

    Raises the appropriate ``PrintablesError`` subclass on any failure.
    """
    try:
        with httpx.Client(
            timeout=DEFAULT_TIMEOUT,
            transport=transport,
            follow_redirects=False,
        ) as client:
            resp = client.post(PRINTABLES_GRAPHQL_URL, json=payload, headers=_HEADERS)
    except httpx.TimeoutException as exc:
        raise PrintablesUnavailable("Printables request timed out") from exc
    except httpx.HTTPError as exc:
        raise PrintablesUnavailable(f"Printables request failed: {exc}") from exc

    if resp.status_code >= 500:
        raise PrintablesUnavailable(f"Printables returned HTTP {resp.status_code}")

    body = resp.content or b""
    if len(body) > MAX_RESPONSE_BYTES:
        raise PrintablesResponseError("Printables response exceeded size limit")

    try:
        data = resp.json()
    except Exception as exc:  # noqa: BLE001 - any decode error is a response error
        raise PrintablesResponseError("Printables returned invalid JSON") from exc

    if resp.status_code >= 400:
        # 4xx with a JSON body usually carries GraphQL validation errors.
        errors = data.get("errors") if isinstance(data, dict) else None
        detail = _format_graphql_errors(errors) if errors else f"HTTP {resp.status_code}"
        raise PrintablesResponseError(f"Printables error: {detail}")

    if isinstance(data, dict) and data.get("errors"):
        raise PrintablesResponseError(
            f"Printables GraphQL error: {_format_graphql_errors(data['errors'])}"
        )

    return (data.get("data") if isinstance(data, dict) else None) or {}


def _format_graphql_errors(errors: Any) -> str:
    try:
        return "; ".join(str(e.get("message")) for e in errors[:3])
    except Exception:  # noqa: BLE001
        return "unknown GraphQL error"


def fetch_printables_model(print_id: str, *, transport: Optional[httpx.BaseTransport] = None) -> Dict[str, Any]:
    """Fetch the ``print(id)`` metadata payload for a Printables model.

    Returns the raw ``print`` object (pass to ``printables_parser`` for
    normalization). Raises ``PrintablesNotFound`` when the model is missing.
    """
    pid = str(print_id or "").strip()
    if not pid.isdigit():
        raise PrintablesNotFound("Invalid Printables model id")

    data = _post(
        {"query": MODEL_QUERY, "variables": {"id": pid}, "operationName": "PrintQueueModel"},
        transport=transport,
    )
    model = data.get("print")
    if not model:
        raise PrintablesNotFound(f"Printables model {pid} not found")
    return model


def get_download_links(
    print_id: str,
    files: List[Dict[str, Any]],
    *,
    source: str = "model_detail",
    transport: Optional[httpx.BaseTransport] = None,
) -> List[Dict[str, Any]]:
    """Resolve time-limited direct download links for the given files.

    ``files`` is a list of ``{"fileType": "stl", "ids": ["123", ...]}`` groups
    (DownloadFileInput). Returns the ``output.files`` list, each entry being
    ``{"id", "link", "ttl", "fileType"}``. Used only in ``direct_import`` mode.
    """
    pid = str(print_id or "").strip()
    if not pid.isdigit():
        raise PrintablesNotFound("Invalid Printables model id")
    if not files:
        return []

    data = _post(
        {
            "query": DOWNLOAD_MUTATION,
            "variables": {"printId": pid, "source": source, "files": files},
            "operationName": "PrintQueueDownload",
        },
        transport=transport,
    )
    result = data.get("getDownloadLink") or {}
    if not result.get("ok"):
        raise PrintablesResponseError(
            f"Printables download link request failed: {result.get('errors')}"
        )
    output = result.get("output") or {}
    return output.get("files") or []


def download_file(url: str, *, max_bytes: int, transport: Optional[httpx.BaseTransport] = None) -> bytes:
    """Stream a resolved download link into memory with a hard size cap.

    Enforces ``max_bytes`` (SEC-002) so a malicious/oversized link cannot
    exhaust memory. Returns the file bytes.
    """
    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT, transport=transport, follow_redirects=True) as client:
            with client.stream("GET", url, headers={"User-Agent": _HEADERS["User-Agent"]}) as resp:
                if resp.status_code >= 400:
                    raise PrintablesUnavailable(f"Download failed: HTTP {resp.status_code}")
                chunks = bytearray()
                for chunk in resp.iter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > max_bytes:
                        raise PrintablesResponseError("Downloaded file exceeded size limit")
                return bytes(chunks)
    except (PrintablesError,):
        raise
    except httpx.TimeoutException as exc:
        raise PrintablesUnavailable("Printables download timed out") from exc
    except httpx.HTTPError as exc:
        raise PrintablesUnavailable(f"Printables download failed: {exc}") from exc
