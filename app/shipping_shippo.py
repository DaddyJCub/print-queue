import os
from typing import Any, Dict, Optional

import httpx


SHIPPO_API_BASE = "https://api.goshippo.com"


def map_shippo_tracking_status(status: Optional[str]) -> str:
    """Map Shippo tracking status values into internal shipping status values."""
    value = (status or "").strip().upper()
    mapping = {
        "PRE_TRANSIT": "PRE_TRANSIT",
        "TRANSIT": "IN_TRANSIT",
        "IN_TRANSIT": "IN_TRANSIT",
        "OUT_FOR_DELIVERY": "OUT_FOR_DELIVERY",
        "DELIVERED": "DELIVERED",
        "RETURNED": "RETURNED",
        "FAILURE": "EXCEPTION",
        "UNKNOWN": "LABEL_PURCHASED",
        "AVAILABLE_FOR_PICKUP": "IN_TRANSIT",
    }
    return mapping.get(value, "IN_TRANSIT" if value else "LABEL_PURCHASED")


class ShippoClient:
    """Small Shippo API client used by admin and webhook shipping flows."""

    def __init__(self, api_key: Optional[str] = None, timeout: float = 20.0):
        key = api_key or os.getenv("SHIPPO_API_KEY", "")
        if not key:
            raise RuntimeError("SHIPPO_API_KEY is not configured")
        self._headers = {
            "Authorization": f"ShippoToken {key}",
            "Content-Type": "application/json",
        }
        self._timeout = timeout

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{SHIPPO_API_BASE}{path}"
        try:
            with httpx.Client(timeout=self._timeout, headers=self._headers) as client:
                response = client.request(method, url, json=payload)
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text if exc.response is not None else str(exc)
            raise RuntimeError(f"Shippo API error: {detail}") from exc
        except Exception as exc:
            raise RuntimeError(f"Shippo request failed: {exc}") from exc

        try:
            return response.json()
        except Exception:
            return {}

    def validate_address(self, address: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(address)
        payload["validate"] = True
        return self._request("POST", "/addresses/", payload)

    def create_shipment_and_rates(
        self,
        address_from: Dict[str, Any],
        address_to: Dict[str, Any],
        parcel: Dict[str, Any],
        metadata: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "address_from": address_from,
            "address_to": address_to,
            "parcels": [parcel],
            "async": False,
        }
        if metadata:
            payload["metadata"] = metadata
        return self._request("POST", "/shipments/", payload)

    def buy_label(self, rate_id: str, metadata: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "rate": rate_id,
            "label_file_type": "PDF_4x6",
            "async": False,
        }
        if metadata:
            payload["metadata"] = metadata
        return self._request("POST", "/transactions/", payload)

    def get_tracking(self, carrier: str, tracking_number: str) -> Dict[str, Any]:
        # Shippo supports this as GET /tracks/{carrier}/{tracking_number}
        return self._request("GET", f"/tracks/{carrier}/{tracking_number}")
