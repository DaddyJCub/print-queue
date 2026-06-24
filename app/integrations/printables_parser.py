"""URL parsing and file-candidate normalization for Printables.

This module is provider-specific but has no network or framework dependencies,
so it is trivially unit-testable. The network client lives in
``printables_client.py``.

Candidate JSON contract (PAT-001) — each normalized candidate is a flat dict:

    {
        "provider":        "printables",
        "source_id":       "258431",          # Printables model (print) id
        "file_id":         "1207177",         # provider file id
        "file_type":       "stl",             # stl|gcode|sla|other|pack
        "name":            "Rugged Box.stl",
        "size_bytes":      196684,
        "folder":          "Size 120 x 70...", # may be null
        "attachment_mode": "direct"           # direct|package|reference-only
    }
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional

PROVIDER = "printables"

# SEC-001: strict host allowlist.
ALLOWED_HOSTS = {"printables.com", "www.printables.com"}

# Attachment / feasibility classes (TASK-004).
ATTACH_DIRECT = "direct"            # individual file with a direct download link
ATTACH_PACKAGE = "package"          # only a packaged (zip) download is available
ATTACH_REFERENCE = "reference-only"  # cannot retrieve binary (premium/paid model)

# Maps the GraphQL list field on ``print`` to the DownloadFileTypeEnum value.
# Order here defines the deterministic candidate ordering between groups.
_LIST_TO_TYPE = (
    ("stls", "stl"),
    ("gcodes", "gcode"),
    ("slas", "sla"),
    ("otherFiles", "other"),
    ("downloadPacks", "pack"),
)

_VALID_FILE_TYPES = {ft for _, ft in _LIST_TO_TYPE}


def parse_printables_url(url: str) -> str:
    """Validate a Printables model URL and return its numeric model (print) id.

    Accepts the public model URL shapes, e.g.::

        https://www.printables.com/model/258431-rugged-box-parametric
        https://www.printables.com/model/258431-rugged-box-parametric/files
        https://printables.com/en/model/258431

    Raises ``ValueError`` for unsupported hosts or unparseable paths (REQ-002).
    """
    if not url or not isinstance(url, str):
        raise ValueError("Missing Printables URL.")

    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https://")

    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise ValueError(
            "Unsupported host. Only printables.com model links are supported."
        )

    segments = [seg for seg in parsed.path.split("/") if seg]
    try:
        model_idx = segments.index("model")
    except ValueError:
        raise ValueError(
            "Not a Printables model URL (expected /model/{id}-{slug})."
        )

    if model_idx + 1 >= len(segments):
        raise ValueError("Printables model URL is missing the model id.")

    slug = segments[model_idx + 1]
    match = re.match(r"^(\d+)", slug)
    if not match:
        raise ValueError("Could not parse a Printables model id from the URL.")

    return match.group(1)


def _is_reference_only_model(model: Dict[str, Any]) -> bool:
    """Premium / paid models cannot be downloaded without a purchase, so they
    are treated as reference-only regardless of fetch mode (LEG-002)."""
    if model.get("premium"):
        return True
    price = model.get("price")
    if price in (None, "", 0, "0"):
        return False
    try:
        return float(price) > 0
    except (TypeError, ValueError):
        # Unknown/garbled price -> be conservative.
        return True


def _candidate_name(entry: Dict[str, Any], file_type: str, file_id: str) -> str:
    name = (entry.get("name") or "").strip()
    if name:
        return name
    if file_type == "pack":
        kind = (entry.get("fileType") or "").replace("_", " ").strip().title()
        return f"{kind or 'Download'} (pack)"
    return f"{file_type}-{file_id}"


def normalize_file_candidates(model_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten a Printables ``print`` payload into deterministic candidates.

    Handles all payload variants: per-type file lists (``stls``/``gcodes``/
    ``slas``/``otherFiles``), package-only (``downloadPacks``), and empty file
    results (returns ``[]``).
    """
    model = model_payload or {}
    reference_only = _is_reference_only_model(model)
    source_id = str(model.get("id") or "")

    candidates: List[Dict[str, Any]] = []
    for list_key, file_type in _LIST_TO_TYPE:
        for entry in (model.get(list_key) or []):
            file_id = str(entry.get("id") or "").strip()
            if not file_id:
                continue

            if reference_only:
                attachment_mode = ATTACH_REFERENCE
            elif file_type == "pack":
                attachment_mode = ATTACH_PACKAGE
            else:
                attachment_mode = ATTACH_DIRECT

            try:
                size_bytes = int(entry.get("fileSize") or 0)
            except (TypeError, ValueError):
                size_bytes = 0

            candidates.append(
                {
                    "provider": PROVIDER,
                    "source_id": source_id,
                    "file_id": file_id,
                    "file_type": file_type,
                    "name": _candidate_name(entry, file_type, file_id),
                    "size_bytes": size_bytes,
                    "folder": (entry.get("folder") or "").strip() or None,
                    "attachment_mode": attachment_mode,
                }
            )

    return candidates


def supports_direct_asset_download(candidate: Dict[str, Any]) -> bool:
    """Feasibility gate (TASK-004): can this candidate be fetched as a binary?"""
    return (candidate or {}).get("attachment_mode") == ATTACH_DIRECT


def model_summary(model_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the deterministic model-metadata block returned to the client."""
    model = model_payload or {}
    license_obj = model.get("license") or {}
    user_obj = model.get("user") or {}
    return {
        "provider": PROVIDER,
        "source_id": str(model.get("id") or ""),
        "title": (model.get("name") or "").strip(),
        "summary": (model.get("summary") or "").strip(),
        "description": model.get("description") or "",
        "files_count": int(model.get("filesCount") or 0),
        "license": (license_obj.get("name") or "").strip() or None,
        "license_abbreviation": (license_obj.get("abbreviation") or "").strip() or None,
        "author": (user_obj.get("publicUsername") or "").strip() or None,
        "premium": bool(model.get("premium")),
        "exclude_commercial_usage": bool(model.get("excludeCommercialUsage")),
        "reference_only": _is_reference_only_model(model),
    }
