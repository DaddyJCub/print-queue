"""
Stripe Checkout payment processing for Printellect.

Provides Stripe Checkout Session creation for store items, rush fees, and quotes.
Webhook handling for payment confirmation. Graceful degradation when Stripe is
not configured.
"""

import asyncio
import os
import json
import uuid
import secrets
import logging
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List

import hashlib

from fastapi import APIRouter, Request, Depends, Form, UploadFile, File
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse

from app.main import (
    db,
    now_iso,
    get_setting,
    get_bool_setting,
    BASE_URL,
    APP_TITLE,
    APP_VERSION,
    templates,
    require_admin,
    send_email,
    build_email_html,
    send_push_notification_to_admins,
    parse_email_list,
    UPLOAD_DIR,
    MAX_UPLOAD_MB,
    ALLOWED_EXTS,
    safe_ext,
    parse_3d_file_metadata,
    safe_json_dumps,
    get_printer_suggestions,
    calculate_rush_price,
    verify_turnstile,
)
from app.models import AuditAction, AssignmentRole
from app.auth import (
    is_feature_enabled,
    log_audit,
    create_request_assignment,
    get_current_user,
    get_current_account,
    ensure_account_for_user,
)

logger = logging.getLogger("printellect.payments")


def _log_ctx(payment_id: Optional[str] = None, payment_type: Optional[str] = None, **kw) -> str:
    """Build a consistent log prefix for payment operations."""
    parts = []
    if payment_id:
        parts.append(f"payment={payment_id[:12]}")
    if payment_type:
        parts.append(f"type={payment_type}")
    for k, v in kw.items():
        parts.append(f"{k}={v}")
    return f"[{' '.join(parts)}]" if parts else "[payments]"


def _stripe_secret_key() -> str:
    """Get Stripe secret key from DB setting or env var."""
    return (get_setting("stripe_secret_key", "").strip() or os.getenv("STRIPE_SECRET_KEY", "").strip())


def _stripe_publishable_key() -> str:
    """Get Stripe publishable key from DB setting or env var."""
    return (get_setting("stripe_publishable_key", "").strip() or os.getenv("STRIPE_PUBLISHABLE_KEY", "").strip())


def _stripe_webhook_secret() -> str:
    """Get Stripe webhook secret from DB setting or env var."""
    return (get_setting("stripe_webhook_secret", "").strip() or os.getenv("STRIPE_WEBHOOK_SECRET", "").strip())


router = APIRouter()

# ─────────────────────────── STRIPE CLIENT ────────────────────────────────────

_stripe = None
_stripe_configured_key = None


def _get_stripe():
    """Lazy-load and configure the stripe module."""
    global _stripe, _stripe_configured_key
    key = _stripe_secret_key()
    if not key:
        return None
    # Re-configure if key changed (e.g. updated via admin UI)
    if _stripe is not None and _stripe_configured_key == key:
        return _stripe
    import stripe
    stripe.api_key = key
    _stripe = stripe
    _stripe_configured_key = key
    return _stripe


def is_stripe_configured() -> bool:
    """Check if Stripe keys are set."""
    return bool(_stripe_secret_key() and _stripe_publishable_key())


def is_payments_enabled() -> bool:
    """Check if both Stripe is configured AND the feature flag is on."""
    return is_stripe_configured() and is_feature_enabled("store_payments")


async def _get_authenticated_account_id(request: Request) -> Optional[str]:
    """
    Resolve the currently authenticated account ID for both auth systems.

    Priority:
    1) unified session cookie ("session") -> accounts.id
    2) legacy user_session cookie -> map user email to accounts.id
    """
    account = await get_current_account(request)
    if account:
        return account.id

    user = await get_current_user(request)
    if not user:
        return None

    conn = db()
    try:
        row = conn.execute(
            "SELECT id FROM accounts WHERE LOWER(email) = LOWER(?)",
            (user.email.strip(),),
        ).fetchone()
    finally:
        conn.close()
    if row:
        return row["id"]

    # Last resort for legacy sessions: create/link the unified Account record.
    account = ensure_account_for_user(user)
    if account:
        return account.id

    logger.warning("Could not resolve account for legacy user during checkout", extra={"email": user.email})
    return None



# ─────────────────────────── CHECKOUT SESSION CREATORS ────────────────────────


def create_store_item_checkout(
    item: dict,
    requester_name: str,
    requester_email: str,
    colors: str,
    notes: str,
    account_id: Optional[str] = None,
    embedded: bool = False,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Create Stripe Checkout Session for a store item purchase.

    When embedded=False (default): returns (checkout_url, payment_id).
    When embedded=True: returns (client_secret, payment_id).
    On failure: returns (None, error_message).
    """
    stripe = _get_stripe()
    if not stripe:
        return None, "Payments not configured"

    payment_id = str(uuid.uuid4())
    now = now_iso()
    price_cents = item["price_cents"]

    conn = db()
    conn.execute(
        """INSERT INTO payments (id, created_at, updated_at, payment_type, store_item_id,
            account_id, amount_cents, currency, status, payer_email, payer_name, description, metadata)
        VALUES (?, ?, ?, 'store_item', ?, ?, ?, 'usd', 'pending', ?, ?, ?, ?)""",
        (
            payment_id, now, now, item["id"], account_id, price_cents,
            requester_email.strip().lower(), requester_name.strip(),
            f"Store item: {item['name']}",
            json.dumps({"colors": colors, "notes": notes, "item_name": item["name"]}),
        ),
    )
    conn.commit()
    conn.close()

    session_params = {
        "payment_method_types": ["card"],
        "line_items": [{
            "price_data": {
                "currency": "usd",
                "product_data": {
                    "name": item["name"],
                    "description": f"3D Print - {item.get('material', '')}",
                },
                "unit_amount": price_cents,
            },
            "quantity": 1,
        }],
        "mode": "payment",
        "customer_email": requester_email.strip().lower(),
        "metadata": {
            "payment_id": payment_id,
            "payment_type": "store_item",
            "store_item_id": item["id"],
            "requester_name": requester_name.strip(),
        },
    }

    if embedded:
        session_params["ui_mode"] = "embedded"
        session_params["return_url"] = f"{BASE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}"
    else:
        session_params["success_url"] = f"{BASE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}"
        session_params["cancel_url"] = f"{BASE_URL}/store?payment_cancelled=1"

    try:
        session = stripe.checkout.Session.create(**session_params)
    except Exception as e:
        logger.error(f"{_log_ctx(payment_id, 'store_item')} Stripe session creation failed: {e}")
        conn = db()
        conn.execute(
            "UPDATE payments SET status = 'failed', updated_at = ? WHERE id = ?",
            (now_iso(), payment_id),
        )
        conn.commit()
        conn.close()
        return None, str(e)

    conn = db()
    conn.execute(
        "UPDATE payments SET stripe_checkout_session_id = ?, updated_at = ? WHERE id = ?",
        (session.id, now_iso(), payment_id),
    )
    conn.commit()
    conn.close()

    logger.info(f"{_log_ctx(payment_id, 'store_item', session=session.id)} Checkout session created")
    return (session.client_secret if embedded else session.url), payment_id


def create_rush_fee_checkout(
    rush_price_cents: int,
    requester_name: str,
    requester_email: str,
    print_name: str,
    form_data: Dict[str, Any],
    file_ids: List[str],
    account_id: Optional[str] = None,
    embedded: bool = False,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Create Stripe Checkout Session for a rush fee.

    form_data contains all the request form fields needed to create the request
    after payment succeeds. file_ids lists files already saved to disk.

    When embedded=False (default): returns (checkout_url, payment_id).
    When embedded=True: returns (client_secret, payment_id).
    On failure: returns (None, error_message).
    """
    stripe = _get_stripe()
    if not stripe:
        return None, "Payments not configured"

    payment_id = str(uuid.uuid4())
    now = now_iso()

    metadata_json = json.dumps({
        "form_data": form_data,
        "file_ids": file_ids,
    })

    conn = db()
    conn.execute(
        """INSERT INTO payments (id, created_at, updated_at, payment_type,
            account_id, amount_cents, currency, status, payer_email, payer_name, description, metadata)
        VALUES (?, ?, ?, 'rush_fee', ?, ?, 'usd', 'pending', ?, ?, ?, ?)""",
        (
            payment_id, now, now, account_id, rush_price_cents,
            requester_email.strip().lower(), requester_name.strip(),
            f"Rush fee for: {print_name}",
            metadata_json,
        ),
    )
    conn.commit()
    conn.close()

    session_params = {
        "payment_method_types": ["card"],
        "line_items": [{
            "price_data": {
                "currency": "usd",
                "product_data": {
                    "name": f"Rush Fee - {print_name}",
                    "description": "Priority processing for your 3D print request",
                },
                "unit_amount": rush_price_cents,
            },
            "quantity": 1,
        }],
        "mode": "payment",
        "customer_email": requester_email.strip().lower(),
        "metadata": {
            "payment_id": payment_id,
            "payment_type": "rush_fee",
        },
    }

    if embedded:
        session_params["ui_mode"] = "embedded"
        session_params["return_url"] = f"{BASE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}"
    else:
        session_params["success_url"] = f"{BASE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}"
        session_params["cancel_url"] = f"{BASE_URL}/?payment_cancelled=1"

    try:
        session = stripe.checkout.Session.create(**session_params)
    except Exception as e:
        logger.error(f"{_log_ctx(payment_id, 'rush_fee')} Stripe session creation failed: {e}")
        conn = db()
        conn.execute(
            "UPDATE payments SET status = 'failed', updated_at = ? WHERE id = ?",
            (now_iso(), payment_id),
        )
        conn.commit()
        conn.close()
        return None, str(e)

    conn = db()
    conn.execute(
        "UPDATE payments SET stripe_checkout_session_id = ?, updated_at = ? WHERE id = ?",
        (session.id, now_iso(), payment_id),
    )
    conn.commit()
    conn.close()

    logger.info(f"{_log_ctx(payment_id, 'rush_fee', session=session.id)} Checkout session created")
    return (session.client_secret if embedded else session.url), payment_id


def create_quote_checkout(
    request_id: str,
    amount_cents: int,
    request_dict: dict,
    embedded: bool = False,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Create Stripe Checkout Session for an admin-set quote on a request.

    When embedded=False (default): returns (checkout_url, payment_id).
    When embedded=True: returns (client_secret, payment_id).
    On failure: returns (None, error_message).
    """
    stripe = _get_stripe()
    if not stripe:
        return None, "Payments not configured"

    payment_id = str(uuid.uuid4())
    now = now_iso()

    payer_email = (request_dict.get("requester_email") or "").strip().lower()
    payer_name = (request_dict.get("requester_name") or "").strip()
    print_name = request_dict.get("print_name") or request_id[:8]

    conn = db()
    conn.execute(
        """INSERT INTO payments (id, created_at, updated_at, payment_type, request_id,
            account_id, amount_cents, currency, status, payer_email, payer_name, description, metadata)
        VALUES (?, ?, ?, 'quote', ?, ?, ?, 'usd', 'pending', ?, ?, ?, '{}')""",
        (
            payment_id, now, now, request_id,
            request_dict.get("account_id"),
            amount_cents,
            payer_email, payer_name,
            f"Quote for: {print_name}",
        ),
    )
    conn.commit()
    conn.close()

    access_token = request_dict.get("access_token", "")

    session_params = {
        "payment_method_types": ["card"],
        "line_items": [{
            "price_data": {
                "currency": "usd",
                "product_data": {
                    "name": f"Print Quote - {print_name}",
                    "description": f"3D print request {request_id[:8]}",
                },
                "unit_amount": amount_cents,
            },
            "quantity": 1,
        }],
        "mode": "payment",
        "customer_email": payer_email if payer_email else None,
        "metadata": {
            "payment_id": payment_id,
            "payment_type": "quote",
            "request_id": request_id,
        },
    }

    if embedded:
        session_params["ui_mode"] = "embedded"
        session_params["return_url"] = f"{BASE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}"
    else:
        session_params["success_url"] = f"{BASE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}"
        session_params["cancel_url"] = f"{BASE_URL}/open/{request_id}?token={access_token}&payment_cancelled=1"

    try:
        session = stripe.checkout.Session.create(**session_params)
    except Exception as e:
        logger.error(f"{_log_ctx(payment_id, 'quote', request=request_id[:12])} Stripe session creation failed: {e}")
        conn = db()
        conn.execute(
            "UPDATE payments SET status = 'failed', updated_at = ? WHERE id = ?",
            (now_iso(), payment_id),
        )
        conn.commit()
        conn.close()
        return None, str(e)

    conn = db()
    conn.execute(
        "UPDATE payments SET stripe_checkout_session_id = ?, updated_at = ? WHERE id = ?",
        (session.id, now_iso(), payment_id),
    )
    conn.commit()
    conn.close()

    logger.info(f"{_log_ctx(payment_id, 'quote', session=session.id, request=request_id[:12])} Checkout session created")
    return (session.client_secret if embedded else session.url), payment_id


# ─────────────────────────── LOOKUP HELPERS ───────────────────────────────────


def get_payment_by_id(payment_id: str) -> Optional[dict]:
    conn = db()
    row = conn.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_payment_by_session_id(session_id: str) -> Optional[dict]:
    conn = db()
    row = conn.execute(
        "SELECT * FROM payments WHERE stripe_checkout_session_id = ?", (session_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_existing_quote_checkout_url(request_id: str) -> Optional[str]:
    """Check for a reusable pending quote checkout session to avoid creating duplicates."""
    conn = db()
    row = conn.execute(
        """SELECT * FROM payments
           WHERE request_id = ? AND payment_type = 'quote' AND status = 'pending'
             AND stripe_checkout_session_id IS NOT NULL
           ORDER BY created_at DESC LIMIT 1""",
        (request_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    stripe = _get_stripe()
    if not stripe:
        return None
    try:
        session = stripe.checkout.Session.retrieve(row["stripe_checkout_session_id"])
        if session.status == "open":
            return session.url
    except Exception:
        pass
    return None


def get_existing_quote_checkout_secret(request_id: str) -> Optional[str]:
    """Check for a reusable pending quote checkout session and return its client_secret."""
    conn = db()
    row = conn.execute(
        """SELECT * FROM payments
           WHERE request_id = ? AND payment_type = 'quote' AND status = 'pending'
             AND stripe_checkout_session_id IS NOT NULL
           ORDER BY created_at DESC LIMIT 1""",
        (request_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    stripe = _get_stripe()
    if not stripe:
        return None
    try:
        session = stripe.checkout.Session.retrieve(row["stripe_checkout_session_id"])
        if session.status == "open":
            return session.client_secret
    except Exception:
        pass
    return None


def _reset_stripe_cache():
    """Reset cached Stripe module so it picks up new keys."""
    global _stripe, _stripe_configured_key
    _stripe = None
    _stripe_configured_key = None


# ─────────────────────────── WEBHOOK ──────────────────────────────────────────


def verify_webhook_signature(payload: bytes, sig_header: str):
    """Verify Stripe webhook signature and return the event object."""
    stripe = _get_stripe()
    webhook_secret = _stripe_webhook_secret()
    if not stripe or not webhook_secret:
        return None
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
        return event
    except Exception as e:
        logger.warning(f"[payments] Webhook signature verification failed: {e}")
        return None


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Stripe webhook endpoint. Verifies signature, then processes the event."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    if not _stripe_webhook_secret():
        logger.error("[payments] Webhook received but STRIPE_WEBHOOK_SECRET not configured")
        return JSONResponse({"error": "Webhook not configured"}, status_code=503)

    event = verify_webhook_signature(payload, sig_header)
    if not event:
        return JSONResponse({"error": "Invalid signature"}, status_code=400)

    event_type = event.get("type", "")
    event_data = event.get("data", {}).get("object", {})
    event_id = event.get("id", "")

    logger.info(f"[payments] Webhook received: {event_type} event={event_id}")

    if event_type == "checkout.session.completed":
        result = _handle_checkout_completed(event_data)
        return JSONResponse(result)

    if event_type == "checkout.session.expired":
        result = _handle_checkout_expired(event_data)
        return JSONResponse(result)

    if event_type == "charge.refunded":
        result = _handle_charge_refunded(event_data)
        return JSONResponse(result)

    return JSONResponse({"ok": True, "ignored": event_type})


# ─────────────────────────── WEBHOOK HANDLERS ─────────────────────────────────


def _handle_checkout_completed(session: dict) -> dict:
    """Process a checkout.session.completed event."""
    metadata = session.get("metadata") or {}
    payment_id = metadata.get("payment_id")
    payment_type = metadata.get("payment_type")

    if not payment_id:
        return {"ok": True, "ignored": "no_payment_id_in_metadata"}

    conn = db()
    payment = conn.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
    if not payment:
        conn.close()
        return {"ok": True, "ignored": "payment_not_found"}

    if payment["status"] == "completed":
        conn.close()
        return {"ok": True, "duplicate": True}

    # Atomically claim this payment for fulfillment to prevent double-processing
    result = conn.execute(
        "UPDATE payments SET status = 'fulfilling', updated_at = ? WHERE id = ? AND status = 'pending'",
        (now_iso(), payment_id),
    )
    conn.commit()
    if result.rowcount != 1:
        conn.close()
        return {"ok": True, "duplicate": True}

    now = now_iso()

    try:
        if payment_type == "store_item":
            _fulfill_store_item_payment(conn, payment, now)
        elif payment_type == "rush_fee":
            _fulfill_rush_fee_payment(conn, payment, now)
        elif payment_type == "quote":
            _fulfill_quote_payment(conn, payment, now)
    except Exception as e:
        logger.error(f"{_log_ctx(payment_id, payment_type)} Fulfillment error: {e}", exc_info=True)
        conn.execute(
            """UPDATE payments SET status = 'fulfillment_error', updated_at = ?,
                stripe_payment_intent_id = ?, stripe_event_id = ?
            WHERE id = ?""",
            (now, session.get("payment_intent"), session.get("id"), payment_id),
        )
        conn.commit()
        conn.close()
        return {"ok": False, "error": str(e)}

    # Only mark completed after fulfillment succeeds
    conn.execute(
        """UPDATE payments SET status = 'completed', updated_at = ?,
            stripe_payment_intent_id = ?, stripe_event_id = ?
        WHERE id = ?""",
        (now, session.get("payment_intent"), session.get("id"), payment_id),
    )
    conn.commit()
    conn.close()

    log_audit(
        action=AuditAction.PAYMENT_COMPLETED,
        actor_type="system",
        target_type="payment",
        target_id=payment_id,
        details={"payment_type": payment_type, "amount_cents": payment["amount_cents"]},
    )

    return {"ok": True, "action": f"fulfilled_{payment_type}"}


def _handle_checkout_expired(session: dict) -> dict:
    """Mark expired checkout sessions."""
    metadata = session.get("metadata") or {}
    payment_id = metadata.get("payment_id")
    if not payment_id:
        return {"ok": True, "ignored": "no_payment_id"}

    conn = db()
    conn.execute(
        "UPDATE payments SET status = 'expired', updated_at = ? WHERE id = ? AND status = 'pending'",
        (now_iso(), payment_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "action": "expired"}


def _handle_charge_refunded(charge: dict) -> dict:
    """Process a charge.refunded event from Stripe."""
    payment_intent_id = charge.get("payment_intent")
    if not payment_intent_id:
        return {"ok": True, "ignored": "no_payment_intent"}

    conn = db()
    payment = conn.execute(
        "SELECT * FROM payments WHERE stripe_payment_intent_id = ?",
        (payment_intent_id,),
    ).fetchone()
    if not payment:
        conn.close()
        return {"ok": True, "ignored": "payment_not_found"}

    if payment["status"] in ("refunded", "partially_refunded"):
        conn.close()
        return {"ok": True, "duplicate": True}

    now = now_iso()
    refund_amount = charge.get("amount_refunded", 0)
    is_partial = refund_amount < charge.get("amount", 0)
    new_status = "partially_refunded" if is_partial else "refunded"

    conn.execute(
        "UPDATE payments SET status = ?, updated_at = ? WHERE id = ?",
        (new_status, now, payment["id"]),
    )
    conn.commit()
    conn.close()

    log_audit(
        action=AuditAction.PAYMENT_REFUNDED,
        actor_type="system",
        target_type="payment",
        target_id=payment["id"],
        details={
            "refund_amount_cents": refund_amount,
            "is_partial": is_partial,
            "stripe_charge_id": charge.get("id"),
        },
    )

    admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
    if admin_emails:
        subject = f"[{APP_TITLE}] Payment {'partially ' if is_partial else ''}refunded ({payment['id'][:8]})"
        text = (
            f"Payment {payment['id'][:8]} has been {'partially ' if is_partial else ''}refunded.\n\n"
            f"Refund amount: ${refund_amount / 100:.2f}\n"
            f"Original amount: ${payment['amount_cents'] / 100:.2f}\n"
            f"Payer: {payment['payer_name']} ({payment['payer_email']})\n"
        )
        html = build_email_html(
            title=f"Payment {'partially ' if is_partial else ''}refunded",
            subtitle=f"${refund_amount / 100:.2f} refunded",
            rows=[
                ("Payer", f"{payment['payer_name']} ({payment['payer_email']})"),
                ("Refund Amount", f"${refund_amount / 100:.2f}"),
                ("Original Amount", f"${payment['amount_cents'] / 100:.2f}"),
                ("Payment ID", payment["id"][:8]),
            ],
        )
        send_email(admin_emails, subject, text, html)

    logger.info(f"{_log_ctx(payment['id'])} Refund processed: amount={refund_amount}, partial={is_partial}")
    return {"ok": True, "action": "refunded"}


# ─────────────────────────── FULFILLMENT ──────────────────────────────────────


def _fulfill_store_item_payment(conn, payment, now: str):
    """Create the print request after successful store item payment."""
    # Idempotency guard: skip if request already created for this payment
    existing = conn.execute(
        "SELECT id FROM requests WHERE payment_id = ?", (payment["id"],)
    ).fetchone()
    if existing:
        logger.info(f"{_log_ctx(payment['id'], 'store_item')} Already fulfilled: request={existing['id']}")
        return

    meta = json.loads(payment["metadata"] or "{}")
    item = conn.execute(
        "SELECT * FROM store_items WHERE id = ?", (payment["store_item_id"],)
    ).fetchone()
    if not item:
        logger.error(f"{_log_ctx(payment['id'], 'store_item')} Store item {payment['store_item_id']} not found")
        return

    rid = str(uuid.uuid4())
    access_token = secrets.token_urlsafe(32)

    conn.execute(
        """INSERT INTO requests (
            id, created_at, updated_at, requester_name, requester_email,
            printer, material, colors, link_url, notes, print_name,
            status, access_token, priority, print_time_minutes,
            store_item_id, payment_id, account_id, fulfillment_method
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            rid, now, now,
            payment["payer_name"], payment["payer_email"],
            "ANY", item["material"],
            meta.get("colors", "") or item["colors"] or "",
            item["link_url"],
            meta.get("notes") or None,
            item["name"],
            "NEW", access_token, 3,
            item["estimated_time_minutes"],
            item["id"], payment["id"],
            payment["account_id"],
            "pickup",
        ),
    )

    # Copy store item files to the new request
    store_files = conn.execute(
        "SELECT original_filename, stored_filename, size_bytes, sha256 FROM store_item_files WHERE store_item_id = ?",
        (item["id"],),
    ).fetchall()
    for f in store_files:
        conn.execute(
            """INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), rid, now, f["original_filename"], f["stored_filename"], f["size_bytes"], f["sha256"]),
        )

    conn.execute(
        """INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), rid, now, None, "NEW",
         f"Store item request (paid ${payment['amount_cents'] / 100:.2f})"),
    )

    # Update payment with the new request_id
    conn.execute("UPDATE payments SET request_id = ? WHERE id = ?", (rid, payment["id"]))

    # Link request to account if present
    if payment["account_id"]:
        create_request_assignment(conn, rid, payment["account_id"], AssignmentRole.REQUESTER)

    # Notify admin
    admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
    if admin_emails and get_bool_setting("admin_email_on_submit", True):
        subject = f"[{APP_TITLE}] New paid store order ({rid[:8]})"
        text = (
            f"New store item order (PAID ${payment['amount_cents'] / 100:.2f})\n\n"
            f"Item: {item['name']}\n"
            f"Requester: {payment['payer_name']} ({payment['payer_email']})\n"
            f"Request ID: {rid[:8]}\n\n"
            f"View: {BASE_URL}/admin/request/{rid}"
        )
        html = build_email_html(
            title="New paid store order",
            subtitle=f"${payment['amount_cents'] / 100:.2f} paid via Stripe",
            rows=[
                ("Item", item["name"]),
                ("Requester", f"{payment['payer_name']} ({payment['payer_email']})"),
                ("Amount", f"${payment['amount_cents'] / 100:.2f}"),
                ("Request ID", rid[:8]),
            ],
            cta_url=f"{BASE_URL}/admin/request/{rid}",
            cta_label="View Request",
        )
        send_email(admin_emails, subject, text, html)

    try:
        send_push_notification_to_admins(
            title=f"New paid store order - ${payment['amount_cents'] / 100:.2f}",
            body=f"{item['name']} from {payment['payer_name']}",
            url=f"/admin/request/{rid}",
        )
    except Exception:
        pass

    logger.info(f"{_log_ctx(payment['id'], 'store_item', request=rid[:12])} Fulfilled: item={item['name']}")


def _fulfill_rush_fee_payment(conn, payment, now: str):
    """Create the rush-priority request after successful payment."""
    # Idempotency guard: skip if request already created for this payment
    existing = conn.execute(
        "SELECT id FROM requests WHERE payment_id = ?", (payment["id"],)
    ).fetchone()
    if existing:
        logger.info(f"{_log_ctx(payment['id'], 'rush_fee')} Already fulfilled: request={existing['id']}")
        return

    meta = json.loads(payment["metadata"] or "{}")
    form_data = meta.get("form_data", {})
    file_ids = meta.get("file_ids", [])

    rid = str(uuid.uuid4())
    access_token = secrets.token_urlsafe(32)

    rush_note = f"RUSH REQUEST (${payment['amount_cents'] / 100:.2f} paid via Stripe) - Priority processing"

    conn.execute(
        """INSERT INTO requests (
            id, created_at, updated_at, requester_name, requester_email,
            print_name, printer, material, colors, link_url, notes,
            status, priority, admin_notes, access_token, account_id,
            fulfillment_method, payment_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            rid, now, now,
            form_data.get("requester_name", payment["payer_name"]),
            form_data.get("requester_email", payment["payer_email"]),
            form_data.get("print_name", ""),
            form_data.get("printer", "ANY"),
            form_data.get("material", "PLA"),
            form_data.get("colors", ""),
            form_data.get("link_url") or None,
            form_data.get("notes") or None,
            "NEW", 1, rush_note, access_token,
            payment["account_id"],
            form_data.get("fulfillment_method", "pickup"),
            payment["id"],
        ),
    )

    # Link uploaded files to this request
    if file_ids:
        for fid in file_ids:
            conn.execute(
                "UPDATE files SET request_id = ? WHERE id = ? AND request_id IS NULL",
                (rid, fid),
            )

    conn.execute(
        """INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), rid, now, None, "NEW",
         f"Rush request submitted (${payment['amount_cents'] / 100:.2f} paid)"),
    )

    conn.execute("UPDATE payments SET request_id = ? WHERE id = ?", (rid, payment["id"]))

    if payment["account_id"]:
        create_request_assignment(conn, rid, payment["account_id"], AssignmentRole.REQUESTER)

    # Handle shipping if form_data contains shipping fields
    fd = form_data
    if fd.get("fulfillment_method") == "shipping" and fd.get("ship_address_line1"):
        from app.main import get_setting as _gs
        def _to_float(v, d):
            try:
                return float(v)
            except Exception:
                return d
        conn.execute(
            """INSERT INTO request_shipping (
                id, request_id, created_at, updated_at, shipping_status,
                recipient_name, recipient_phone, address_line1, address_line2,
                city, state, postal_code, country, service_preference,
                package_weight_oz, package_length_in, package_width_in, package_height_in
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(uuid.uuid4()), rid, now, now, "REQUESTED",
                (fd.get("ship_recipient_name") or fd.get("requester_name", "")).strip(),
                (fd.get("ship_recipient_phone") or "").strip() or None,
                (fd.get("ship_address_line1") or "").strip(),
                (fd.get("ship_address_line2") or "").strip() or None,
                (fd.get("ship_city") or "").strip(),
                (fd.get("ship_state") or "").strip(),
                (fd.get("ship_postal_code") or "").strip(),
                (fd.get("ship_country") or "US").strip().upper(),
                (fd.get("ship_service_preference") or "").strip() or None,
                _to_float(_gs("shipping_default_weight_oz", "16"), 16.0),
                _to_float(_gs("shipping_default_length_in", "8"), 8.0),
                _to_float(_gs("shipping_default_width_in", "6"), 6.0),
                _to_float(_gs("shipping_default_height_in", "4"), 4.0),
            ),
        )

    # Notify admin
    admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
    if admin_emails and get_bool_setting("admin_email_on_submit", True):
        subject = f"[{APP_TITLE}] Rush request - PAID ({rid[:8]})"
        text = (
            f"New RUSH request (${payment['amount_cents'] / 100:.2f} paid)\n\n"
            f"Print: {form_data.get('print_name', 'N/A')}\n"
            f"Requester: {payment['payer_name']} ({payment['payer_email']})\n"
            f"Request ID: {rid[:8]}\n\n"
            f"View: {BASE_URL}/admin/request/{rid}"
        )
        html = build_email_html(
            title="Rush request - PAID",
            subtitle=f"${payment['amount_cents'] / 100:.2f} paid via Stripe",
            rows=[
                ("Print", form_data.get("print_name", "N/A")),
                ("Requester", f"{payment['payer_name']} ({payment['payer_email']})"),
                ("Rush Fee", f"${payment['amount_cents'] / 100:.2f}"),
                ("Request ID", rid[:8]),
            ],
            cta_url=f"{BASE_URL}/admin/request/{rid}",
            cta_label="View Request",
        )
        send_email(admin_emails, subject, text, html)

    try:
        send_push_notification_to_admins(
            title=f"Rush request - ${payment['amount_cents'] / 100:.2f} paid",
            body=f"{form_data.get('print_name', 'N/A')} from {payment['payer_name']}",
            url=f"/admin/request/{rid}",
        )
    except Exception:
        pass

    logger.info(f"{_log_ctx(payment['id'], 'rush_fee', request=rid[:12])} Fulfilled")


def _fulfill_quote_payment(conn, payment, now: str):
    """Mark the quoted request as paid."""
    rid = payment["request_id"]
    if not rid:
        logger.error(f"{_log_ctx(payment['id'], 'quote')} Missing request_id")
        return

    # Idempotency guard: skip if quote already marked as paid
    req_row = conn.execute("SELECT quote_paid_at FROM requests WHERE id = ?", (rid,)).fetchone()
    if req_row and req_row["quote_paid_at"]:
        logger.info(f"{_log_ctx(payment['id'], 'quote', request=rid[:12])} Already fulfilled")
        return

    conn.execute(
        """UPDATE requests SET quote_paid_at = ?, payment_id = ?, updated_at = ?
        WHERE id = ?""",
        (now, payment["id"], now, rid),
    )

    conn.execute(
        """INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), rid, now, "NEW", "NEW",
         f"Quote payment received (${payment['amount_cents'] / 100:.2f})"),
    )

    # Notify admin that payment was received
    admin_emails = parse_email_list(get_setting("admin_notify_emails", ""))
    if admin_emails:
        subject = f"[{APP_TITLE}] Quote paid ({rid[:8]})"
        text = (
            f"Quote payment received: ${payment['amount_cents'] / 100:.2f}\n\n"
            f"Requester: {payment['payer_name']} ({payment['payer_email']})\n"
            f"Request ID: {rid[:8]}\n\n"
            f"View: {BASE_URL}/admin/request/{rid}"
        )
        html = build_email_html(
            title="Quote paid",
            subtitle=f"${payment['amount_cents'] / 100:.2f} received",
            rows=[
                ("Requester", f"{payment['payer_name']} ({payment['payer_email']})"),
                ("Amount", f"${payment['amount_cents'] / 100:.2f}"),
                ("Request ID", rid[:8]),
            ],
            cta_url=f"{BASE_URL}/admin/request/{rid}",
            cta_label="View Request",
        )
        send_email(admin_emails, subject, text, html)

    try:
        send_push_notification_to_admins(
            title=f"Quote paid - ${payment['amount_cents'] / 100:.2f}",
            body=f"Request {rid[:8]} from {payment['payer_name']}",
            url=f"/admin/request/{rid}",
        )
    except Exception:
        pass

    logger.info(f"{_log_ctx(payment['id'], 'quote', request=rid[:12])} Fulfilled: ${payment['amount_cents'] / 100:.2f}")


# ─────────────────────────── ADMIN ROUTES ────────────────────────────────────


@router.get("/admin/payments", response_class=HTMLResponse)
def admin_payments_list(
    request: Request,
    status: str = "",
    payment_type: str = "",
    page: int = 1,
    _=Depends(require_admin),
):
    """Admin payments dashboard."""
    conn = db()

    # Summary stats
    total_revenue = conn.execute(
        "SELECT COALESCE(SUM(amount_cents), 0) FROM payments WHERE status = 'completed'"
    ).fetchone()[0]
    pending_count = conn.execute(
        "SELECT COUNT(*) FROM payments WHERE status = 'pending'"
    ).fetchone()[0]
    completed_count = conn.execute(
        "SELECT COUNT(*) FROM payments WHERE status = 'completed'"
    ).fetchone()[0]
    refunded_count = conn.execute(
        "SELECT COUNT(*) FROM payments WHERE status IN ('refunded', 'partially_refunded')"
    ).fetchone()[0]

    # Build query with filters
    where_clauses = []
    params: list = []
    if status:
        where_clauses.append("status = ?")
        params.append(status)
    if payment_type:
        where_clauses.append("payment_type = ?")
        params.append(payment_type)

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    per_page = 50
    offset = (page - 1) * per_page
    total = conn.execute(f"SELECT COUNT(*) FROM payments{where_sql}", params).fetchone()[0]
    payments = conn.execute(
        f"SELECT * FROM payments{where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()
    conn.close()

    return templates.TemplateResponse("admin_payments.html", {
        "request": request,
        "payments": [dict(p) for p in payments],
        "stats": {
            "total_revenue_cents": total_revenue,
            "pending_count": pending_count,
            "completed_count": completed_count,
            "refunded_count": refunded_count,
        },
        "filters": {"status": status, "payment_type": payment_type},
        "page": page,
        "total": total,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
        "active_page": "payments",
        "version": APP_VERSION,
    })


@router.post("/admin/request/{rid}/refund")
def admin_refund_payment(
    request: Request,
    rid: str,
    _=Depends(require_admin),
):
    """Initiate a Stripe refund for a completed payment on this request."""
    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
    if not req:
        conn.close()
        return RedirectResponse(url=f"/admin/request/{rid}", status_code=303)

    payment = None
    if req["payment_id"]:
        payment = conn.execute("SELECT * FROM payments WHERE id = ?", (req["payment_id"],)).fetchone()
    conn.close()

    if not payment or payment["status"] != "completed":
        return RedirectResponse(url=f"/admin/request/{rid}?refund_error=no_payment", status_code=303)

    if not payment["stripe_payment_intent_id"]:
        return RedirectResponse(url=f"/admin/request/{rid}?refund_error=no_intent", status_code=303)

    stripe = _get_stripe()
    if not stripe:
        return RedirectResponse(url=f"/admin/request/{rid}?refund_error=not_configured", status_code=303)

    try:
        stripe.Refund.create(payment_intent=payment["stripe_payment_intent_id"])
    except Exception as e:
        logger.error(f"{_log_ctx(payment['id'])} Admin refund failed: {e}")
        return RedirectResponse(url=f"/admin/request/{rid}?refund_error=stripe_error", status_code=303)

    # Update local status immediately (webhook will also fire)
    conn = db()
    conn.execute(
        "UPDATE payments SET status = 'refunded', updated_at = ? WHERE id = ?",
        (now_iso(), payment["id"]),
    )
    conn.commit()
    conn.close()

    log_audit(
        action=AuditAction.PAYMENT_REFUNDED,
        actor_type="admin",
        target_type="payment",
        target_id=payment["id"],
        details={"refund_amount_cents": payment["amount_cents"], "request_id": rid},
    )

    return RedirectResponse(url=f"/admin/request/{rid}?refunded=1", status_code=303)


@router.post("/admin/payments/{payment_id}/refund")
def admin_refund_payment_by_id(
    request: Request,
    payment_id: str,
    _=Depends(require_admin),
):
    """Initiate a Stripe refund for a completed payment (from payments dashboard)."""
    conn = db()
    payment = conn.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
    conn.close()

    if not payment or payment["status"] != "completed":
        return RedirectResponse(url="/admin/payments?refund_error=no_payment", status_code=303)

    if not payment["stripe_payment_intent_id"]:
        return RedirectResponse(url="/admin/payments?refund_error=no_intent", status_code=303)

    stripe = _get_stripe()
    if not stripe:
        return RedirectResponse(url="/admin/payments?refund_error=not_configured", status_code=303)

    try:
        stripe.Refund.create(payment_intent=payment["stripe_payment_intent_id"])
    except Exception as e:
        logger.error(f"{_log_ctx(payment['id'])} Admin refund failed: {e}")
        return RedirectResponse(url="/admin/payments?refund_error=stripe_error", status_code=303)

    conn = db()
    conn.execute(
        "UPDATE payments SET status = 'refunded', updated_at = ? WHERE id = ?",
        (now_iso(), payment["id"]),
    )
    conn.commit()
    conn.close()

    log_audit(
        action=AuditAction.PAYMENT_REFUNDED,
        actor_type="admin",
        target_type="payment",
        target_id=payment["id"],
        details={"refund_amount_cents": payment["amount_cents"], "request_id": payment["request_id"]},
    )

    return RedirectResponse(url="/admin/payments?refunded=1", status_code=303)


# ─────────────────────────── EMBEDDED CHECKOUT API ────────────────────────────


@router.get("/api/payments/config")
def api_payments_config():
    """Return Stripe publishable key for client-side initialization."""
    if not is_payments_enabled():
        return JSONResponse({"enabled": False})
    return JSONResponse({
        "enabled": True,
        "publishable_key": _stripe_publishable_key(),
    })


@router.post("/api/payments/store-checkout/{item_id}")
async def api_store_checkout(
    request: Request,
    item_id: str,
    requester_name: str = Form(...),
    requester_email: str = Form(...),
    colors: str = Form(""),
    notes: str = Form(""),
):
    """Create embedded checkout session for a store item purchase."""
    if not is_payments_enabled():
        return JSONResponse({"error": "Payments not enabled"}, status_code=400)

    conn = db()
    item = conn.execute("SELECT * FROM store_items WHERE id = ? AND is_active = 1", (item_id,)).fetchone()
    conn.close()

    if not item:
        return JSONResponse({"error": "Item not found"}, status_code=404)
    if not item["price_cents"] or item["price_cents"] <= 0:
        return JSONResponse({"error": "Item has no price"}, status_code=400)

    # Require authenticated account (supports legacy + unified sessions)
    account_id = await _get_authenticated_account_id(request)
    if not account_id:
        return JSONResponse({"error": "auth_required"}, status_code=401)

    client_secret, result = create_store_item_checkout(
        item=dict(item),
        requester_name=requester_name,
        requester_email=requester_email,
        colors=colors,
        notes=notes,
        account_id=account_id,
        embedded=True,
    )
    if not client_secret:
        return JSONResponse({"error": result or "Checkout creation failed"}, status_code=500)

    return JSONResponse({"clientSecret": client_secret})


@router.post("/api/payments/rush-checkout")
async def api_rush_checkout(
    request: Request,
    requester_name: str = Form(...),
    requester_email: str = Form(...),
    print_name: str = Form(""),
    printer: str = Form("ANY"),
    material: str = Form("PLA"),
    colors: str = Form(""),
    link_url: str = Form(""),
    notes: str = Form(""),
    fulfillment_method: str = Form("pickup"),
    ship_recipient_name: str = Form(""),
    ship_recipient_phone: str = Form(""),
    ship_address_line1: str = Form(""),
    ship_address_line2: str = Form(""),
    ship_city: str = Form(""),
    ship_state: str = Form(""),
    ship_postal_code: str = Form(""),
    ship_country: str = Form("US"),
    ship_service_preference: str = Form(""),
    turnstile_token: Optional[str] = Form(None, alias="cf-turnstile-response"),
    upload: List[UploadFile] = File(default=[]),
):
    """Create embedded checkout session for a rush fee payment."""
    if not is_payments_enabled():
        return JSONResponse({"error": "Payments not enabled"}, status_code=400)

    # Require authenticated account (supports legacy + unified sessions)
    account_id = await _get_authenticated_account_id(request)
    if not account_id:
        return JSONResponse({"error": "auth_required"}, status_code=401)

    # Turnstile verification
    client_ip = request.client.host if request.client else None
    if not await verify_turnstile(turnstile_token or "", client_ip):
        return JSONResponse({"error": "Bot verification failed"}, status_code=403)

    # Calculate rush price
    printer_suggestions = get_printer_suggestions()
    queue_size = printer_suggestions.get("total_queue", 0)
    rush_pricing = calculate_rush_price(queue_size, requester_name)
    rush_price_cents = round(rush_pricing["final_price"] * 100)
    if rush_price_cents <= 0:
        return JSONResponse({"error": "Invalid rush price"}, status_code=400)

    # Save uploaded files (without request_id — linked later by webhook)
    uploaded_file_ids = []
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    valid_files = [f for f in upload if f.filename and f.size and f.size > 0]
    if valid_files:
        conn = db()
        for file in valid_files:
            ext = safe_ext(file.filename)
            if ext not in ALLOWED_EXTS:
                conn.close()
                return JSONResponse({"error": f"File '{file.filename}' not allowed."}, status_code=400)
            data = await file.read()
            if len(data) > max_bytes:
                conn.close()
                return JSONResponse({"error": f"File '{file.filename}' too large."}, status_code=400)
            stored = f"{uuid.uuid4()}{ext}"
            out_path = os.path.join(UPLOAD_DIR, stored)
            sha = hashlib.sha256(data).hexdigest()
            with open(out_path, "wb") as f:
                f.write(data)
            file_metadata = await asyncio.get_event_loop().run_in_executor(None, parse_3d_file_metadata, out_path, file.filename)
            file_metadata_json = safe_json_dumps(file_metadata) if file_metadata else None
            fid = str(uuid.uuid4())
            conn.execute(
                """INSERT INTO files (id, created_at, original_filename, stored_filename, size_bytes, sha256, file_metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (fid, now_iso(), file.filename, stored, len(data), sha, file_metadata_json),
            )
            uploaded_file_ids.append(fid)
        conn.commit()
        conn.close()

    rush_form_data = {
        "requester_name": requester_name.strip(),
        "requester_email": requester_email.strip(),
        "print_name": print_name.strip(),
        "printer": printer,
        "material": material,
        "colors": colors.strip(),
        "link_url": link_url.strip(),
        "notes": notes or "",
        "fulfillment_method": fulfillment_method,
        "ship_recipient_name": ship_recipient_name.strip(),
        "ship_recipient_phone": ship_recipient_phone.strip(),
        "ship_address_line1": ship_address_line1.strip(),
        "ship_address_line2": ship_address_line2.strip(),
        "ship_city": ship_city.strip(),
        "ship_state": ship_state.strip(),
        "ship_postal_code": ship_postal_code.strip(),
        "ship_country": (ship_country or "US").strip(),
        "ship_service_preference": ship_service_preference.strip(),
    }

    client_secret, result = create_rush_fee_checkout(
        rush_price_cents=rush_price_cents,
        requester_name=requester_name.strip(),
        requester_email=requester_email.strip(),
        print_name=print_name.strip(),
        form_data=rush_form_data,
        file_ids=uploaded_file_ids,
        account_id=account_id,
        embedded=True,
    )
    if not client_secret:
        return JSONResponse({"error": result or "Checkout creation failed"}, status_code=500)

    return JSONResponse({"clientSecret": client_secret})


@router.post("/api/payments/quote-checkout/{request_id}")
async def api_quote_checkout(
    request: Request,
    request_id: str,
    token: str = Form(...),
):
    """Create embedded checkout session for a quote payment."""
    if not is_payments_enabled():
        return JSONResponse({"error": "Payments not enabled"}, status_code=400)

    # Require authenticated account (supports legacy + unified sessions)
    account_id = await _get_authenticated_account_id(request)
    if not account_id:
        return JSONResponse({"error": "auth_required"}, status_code=401)

    conn = db()
    req = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
    conn.close()

    if not req:
        return JSONResponse({"error": "Request not found"}, status_code=404)
    if req["access_token"] != token:
        return JSONResponse({"error": "Invalid token"}, status_code=403)
    if not req["quote_amount_cents"] or req["quote_amount_cents"] <= 0:
        return JSONResponse({"error": "No quote set"}, status_code=400)
    if req["quote_paid_at"]:
        return JSONResponse({"error": "Quote already paid"}, status_code=400)

    # Try to reuse existing session
    existing_secret = get_existing_quote_checkout_secret(request_id)
    if existing_secret:
        return JSONResponse({"clientSecret": existing_secret})

    client_secret, result = create_quote_checkout(
        request_id=request_id,
        amount_cents=req["quote_amount_cents"],
        request_dict=dict(req),
        embedded=True,
    )
    if not client_secret:
        return JSONResponse({"error": result or "Checkout creation failed"}, status_code=500)

    return JSONResponse({"clientSecret": client_secret})
