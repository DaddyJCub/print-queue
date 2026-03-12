"""USPS v3 API client – address validation, rates, label purchase, tracking.

This replaces the Shippo integration with the free USPS REST API at apis.usps.com.
Supports both the production and test (TEM) environments.

Setup:
  1. Create a USPS Business Account at https://cop.usps.com
  2. Register an app and retrieve Consumer Key (client_id) + Consumer Secret (client_secret)
  3. Store credentials in admin settings or env vars (USPS_CLIENT_ID / USPS_CLIENT_SECRET)
  4. For label purchasing: enroll in USPS Ship and obtain an EPS account number
"""

import base64
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx


# ---------------------------------------------------------------------------
# Status mapping – USPS statusCategory → internal shipping statuses
# ---------------------------------------------------------------------------

def map_usps_tracking_status(status_category: Optional[str]) -> str:
    """Map a USPS tracking *statusCategory* to an internal shipping status."""
    value = (status_category or "").strip()
    mapping = {
        "Pre-Shipment": "PRE_TRANSIT",
        "Accepted": "PRE_TRANSIT",
        "In Transit": "IN_TRANSIT",
        "In-Transit": "IN_TRANSIT",
        "Out for Delivery": "OUT_FOR_DELIVERY",
        "Delivered": "DELIVERED",
        "Alert": "EXCEPTION",
        "Return to Sender": "RETURNED",
        "Returned": "RETURNED",
    }
    # Try exact match first, then case-insensitive
    if value in mapping:
        return mapping[value]
    for k, v in mapping.items():
        if value.lower() == k.lower():
            return v
    return "IN_TRANSIT" if value else "PRE_TRANSIT"


# ---------------------------------------------------------------------------
# USPS API Client
# ---------------------------------------------------------------------------

class USPSClient:
    """Thin wrapper around the USPS v3 REST API."""

    PROD_TOKEN_URL = "https://apis.usps.com/oauth2/v3/token"
    PROD_BASE_URL = "https://apis.usps.com"
    TEST_TOKEN_URL = "https://apis-tem.usps.com/oauth2/v3/token"
    TEST_BASE_URL = "https://apis-tem.usps.com"

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        *,
        use_test_env: bool = False,
        timeout: float = 25.0,
    ):
        self._client_id = client_id or os.getenv("USPS_CLIENT_ID", "")
        self._client_secret = client_secret or os.getenv("USPS_CLIENT_SECRET", "")
        if not self._client_id or not self._client_secret:
            raise RuntimeError("USPS API credentials (client_id / client_secret) are not configured")
        self._timeout = timeout
        self._use_test = use_test_env
        self._token: Optional[str] = None
        self._token_expires_at: float = 0
        self._base_url = self.TEST_BASE_URL if use_test_env else self.PROD_BASE_URL
        self._token_url = self.TEST_TOKEN_URL if use_test_env else self.PROD_TOKEN_URL

    # -- authentication -------------------------------------------------------

    def _ensure_token(self) -> str:
        """Obtain or refresh OAuth2 bearer token (client-credentials grant)."""
        if self._token and time.time() < self._token_expires_at - 120:
            return self._token
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                self._token_url,
                json={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
        self._token = data["access_token"]
        self._token_expires_at = time.time() + int(data.get("expires_in", 28799))
        return self._token

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        token = self._ensure_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
        try:
            with httpx.Client(timeout=self._timeout, headers=headers) as client:
                response = client.request(method, f"{self._base_url}{path}", **kwargs)
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text if exc.response is not None else str(exc)
            raise RuntimeError(f"USPS API error ({exc.response.status_code}): {detail}") from exc
        except Exception as exc:
            raise RuntimeError(f"USPS request failed: {exc}") from exc
        return response

    # -- address validation ---------------------------------------------------

    def validate_address(
        self,
        street: str,
        city: str,
        state: str,
        zip_code: str = "",
        secondary: str = "",
    ) -> Dict[str, Any]:
        """Validate / normalise a US address via the USPS Addresses v3 API.

        Returns the full USPS response dict.  Key fields for callers:
          - address.streetAddress, city, state, ZIPCode, ZIPPlus4
          - additionalInfo.DPVConfirmation  ('Y' = valid delivery point)
          - matches[0].code  ('31' = exact match)
        """
        params: Dict[str, str] = {
            "streetAddress": street,
            "state": state,
        }
        if city:
            params["city"] = city
        if zip_code:
            params["ZIPCode"] = zip_code
        if secondary:
            params["secondaryAddress"] = secondary
        resp = self._request("GET", "/addresses/v3/address", params=params)
        return resp.json()

    def is_address_valid(self, result: Dict[str, Any]) -> bool:
        """Convenience: inspect a validate_address result and return True if deliverable."""
        info = result.get("additionalInfo") or {}
        dpv = (info.get("DPVConfirmation") or "").upper()
        return dpv in ("Y", "S", "D")

    # -- rates / pricing ------------------------------------------------------

    def get_rates(
        self,
        origin_zip: str,
        dest_zip: str,
        weight_oz: float,
        length_in: float = 0,
        width_in: float = 0,
        height_in: float = 0,
        mail_classes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Fetch USPS rates for a domestic package.

        Uses POST /prices/v3/base-rates-list/search which returns all
        eligible products for the given origin/dest/dimensions.
        """
        weight_lb = round(weight_oz / 16.0, 4)
        payload: Dict[str, Any] = {
            "originZIPCode": origin_zip.strip()[:5],
            "destinationZIPCode": dest_zip.strip()[:5],
            "weight": weight_lb,
            "length": round(length_in, 2) if length_in else 1,
            "width": round(width_in, 2) if width_in else 1,
            "height": round(height_in, 2) if height_in else 1,
            "mailClasses": mail_classes or [
                "PRIORITY_MAIL",
                "USPS_GROUND_ADVANTAGE",
                "PRIORITY_MAIL_EXPRESS",
                "FIRST_CLASS_MAIL",
            ],
            "priceType": "RETAIL",
        }
        resp = self._request("POST", "/prices/v3/base-rates-list/search", json=payload)
        return resp.json()

    def normalize_rates(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Flatten the USPS rates response into a simple list for UI display.

        Each item has: provider, service_name, amount, mail_class, rate_indicator,
        delivery_days (if available).
        """
        results: List[Dict[str, Any]] = []
        for rate_opt in raw.get("rateOptions", []):
            # totalBasePrice is the rate
            price = rate_opt.get("totalBasePrice") or rate_opt.get("price")
            if not price and rate_opt.get("rates"):
                for r in rate_opt["rates"]:
                    price = price or r.get("price")
            results.append({
                "provider": "USPS",
                "mail_class": rate_opt.get("mailClass", ""),
                "rate_indicator": rate_opt.get("rateIndicator", ""),
                "service_name": _format_mail_class(rate_opt.get("mailClass", "")),
                "amount": str(price) if price is not None else "—",
                "description": rate_opt.get("description", ""),
                "delivery_days": rate_opt.get("deliveryDays"),
            })
        results.sort(key=lambda r: float(r["amount"]) if r["amount"] not in ("—", "") else 999)
        return results

    # -- tracking -------------------------------------------------------------

    def get_tracking(self, tracking_number: str) -> Dict[str, Any]:
        """Query USPS tracking status for a single tracking number.

        Returns the full USPS tracking response with statusCategory,
        status, trackingEvents, etc.
        """
        resp = self._request(
            "GET",
            f"/tracking/v3/tracking/{tracking_number.strip()}",
            params={"expand": "DETAIL"},
        )
        return resp.json()

    # -- labels ---------------------------------------------------------------

    def get_payment_token(
        self,
        crid: str,
        mid: str,
        account_number: str,
        account_type: str = "EPS",
    ) -> str:
        """Obtain a payment authorization token required for label creation."""
        payload = {
            "roles": [
                {
                    "roleName": "PAYER",
                    "CRID": crid,
                    "MID": mid,
                    "accountType": account_type,
                    "accountNumber": account_number,
                },
                {
                    "roleName": "LABEL_OWNER",
                    "CRID": crid,
                    "MID": mid,
                    "accountType": account_type,
                    "accountNumber": account_number,
                },
            ]
        }
        resp = self._request("POST", "/payments/v3/payment-authorization", json=payload)
        data = resp.json()
        return data.get("paymentAuthorizationToken") or data.get("paymentToken") or ""

    def create_label(
        self,
        from_address: Dict[str, str],
        to_address: Dict[str, str],
        weight_oz: float,
        length_in: float,
        width_in: float,
        height_in: float,
        mail_class: str = "PRIORITY_MAIL",
        payment_token: str = "",
        image_type: str = "PDF",
    ) -> Dict[str, Any]:
        """Purchase a USPS label.

        Returns a dict with:
          - tracking_number
          - postage (cost)
          - label_bytes  (raw PDF/image bytes, base64 decoded)
          - raw_response (the full JSON metadata)
        """
        weight_lb = round(weight_oz / 16.0, 4)
        payload = {
            "imageInfo": {"imageType": image_type, "labelType": "4X6LABEL"},
            "toAddress": {
                "firstName": to_address.get("first_name", to_address.get("name", "").split()[0] if to_address.get("name") else ""),
                "lastName": to_address.get("last_name", " ".join(to_address.get("name", "").split()[1:]) if to_address.get("name") else ""),
                "streetAddress": to_address.get("street1", ""),
                "secondaryAddress": to_address.get("street2", ""),
                "city": to_address.get("city", ""),
                "state": to_address.get("state", ""),
                "ZIPCode": to_address.get("zip", ""),
            },
            "fromAddress": {
                "firstName": from_address.get("first_name", from_address.get("name", "").split()[0] if from_address.get("name") else ""),
                "lastName": from_address.get("last_name", " ".join(from_address.get("name", "").split()[1:]) if from_address.get("name") else ""),
                "streetAddress": from_address.get("street1", ""),
                "secondaryAddress": from_address.get("street2", ""),
                "city": from_address.get("city", ""),
                "state": from_address.get("state", ""),
                "ZIPCode": from_address.get("zip", ""),
            },
            "packageDescription": {
                "mailClass": mail_class,
                "rateIndicator": "SP",
                "weight": weight_lb,
                "weightUOM": "lb",
                "length": round(length_in, 2),
                "width": round(width_in, 2),
                "height": round(height_in, 2),
                "dimensionsUOM": "in",
                "processingCategory": "MACHINABLE",
                "destinationEntryFacilityType": "NONE",
            },
        }
        extra_headers: Dict[str, str] = {}
        if payment_token:
            extra_headers["X-Payment-Authorization-Token"] = payment_token

        resp = self._request(
            "POST",
            "/labels/v3/label",
            json=payload,
            headers=extra_headers,
        )

        # USPS returns a multipart response or JSON with labelImage
        result: Dict[str, Any] = {
            "tracking_number": None,
            "postage": None,
            "label_bytes": None,
            "raw_response": {},
        }
        content_type = resp.headers.get("content-type", "")
        if "application/json" in content_type:
            data = resp.json()
            result["raw_response"] = data
            result["tracking_number"] = data.get("trackingNumber")
            result["postage"] = data.get("postage")
            # Label image may be in labelImage field as base64
            if data.get("labelImage"):
                try:
                    result["label_bytes"] = base64.b64decode(data["labelImage"])
                except Exception:
                    pass
        else:
            # Try to parse anyway
            try:
                data = resp.json()
                result["raw_response"] = data
                result["tracking_number"] = data.get("trackingNumber")
                result["postage"] = data.get("postage")
            except Exception:
                result["raw_response"] = {"raw_text": resp.text[:2000]}
            # Check for binary content
            if resp.content and len(resp.content) > 500:
                result["label_bytes"] = resp.content

        return result

    def cancel_label(self, tracking_number: str) -> bool:
        """Cancel a previously purchased label (refund request)."""
        try:
            self._request("DELETE", f"/labels/v3/label/{tracking_number.strip()}")
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_mail_class(mail_class: str) -> str:
    """Convert a USPS mailClass enum to a human-friendly name."""
    names = {
        "PRIORITY_MAIL": "USPS Priority Mail",
        "PRIORITY_MAIL_EXPRESS": "USPS Priority Mail Express",
        "USPS_GROUND_ADVANTAGE": "USPS Ground Advantage",
        "FIRST_CLASS_MAIL": "USPS First-Class Mail",
        "PARCEL_SELECT": "USPS Parcel Select",
        "MEDIA_MAIL": "USPS Media Mail",
        "LIBRARY_MAIL": "USPS Library Mail",
    }
    return names.get(mail_class, mail_class.replace("_", " ").title())


def usps_tracking_url(tracking_number: str) -> str:
    """Build a USPS.com tracking URL for the given tracking number."""
    return f"https://tools.usps.com/go/TrackConfirmAction?tLabels={tracking_number.strip()}"


def save_label_pdf(request_id: str, label_bytes: bytes, base_dir: str = "local_data/labels") -> str:
    """Persist label PDF bytes to local storage and return the file path."""
    Path(base_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{request_id}.pdf"
    filepath = os.path.join(base_dir, filename)
    with open(filepath, "wb") as f:
        f.write(label_bytes)
    return filepath
