"""
Stripe Checkout payment processing for Printellect.

Provides Stripe Checkout Session creation for store items, rush fees, and quotes.
Webhook handling for payment confirmation. Graceful degradation when Stripe is
not configured.
"""

import os
import json
import uuid
import secrets
import logging
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.main import (
    db,
    now_iso,
    get_setting,
    get_bool_setting,
    BASE_URL,
    APP_TITLE,
    send_email,
    build_email_html,
    send_push_notification_to_admins,
    parse_email_list,
)
from app.models import AuditAction, AssignmentRole
from app.auth import is_feature_enabled, log_audit, create_request_assignment

logger = logging.getLogger("printellect.payments")

# Environment variables -- only source from env, never store in DB
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

router = APIRouter()

# ─────────────────────────── STRIPE CLIENT ────────────────────────────────────

_stripe = None


def _get_stripe():
    """Lazy-load and configure the stripe module."""
    global _stripe
    if _stripe is not None:
        return _stripe
    if not STRIPE_SECRET_KEY:
        return None
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
    _stripe = stripe
    return _stripe


def is_stripe_configured() -> bool:
    """Check if Stripe keys are set."""
    return bool(STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY)


def is_payments_enabled() -> bool:
    """Check if both Stripe is configured AND the feature flag is on."""
    return is_stripe_configured() and is_feature_enabled("store_payments")


# ─────────────────────────── CHECKOUT SESSION CREATORS ────────────────────────


def create_store_item_checkout(
    item: dict,
    requester_name: str,
    requester_email: str,
    colors: str,
    notes: str,
    account_id: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Create Stripe Checkout Session for a store item purchase.

    Returns (checkout_url, payment_id) on success, (None, error_message) on failure.
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

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
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
            mode="payment",
            success_url=f"{BASE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}/store?payment_cancelled=1",
            customer_email=requester_email.strip().lower(),
            metadata={
                "payment_id": payment_id,
                "payment_type": "store_item",
                "store_item_id": item["id"],
                "requester_name": requester_name.strip(),
            },
        )
    except Exception as e:
        logger.error(f"[PAYMENTS] Stripe session creation failed: {e}")
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

    return session.url, payment_id


def create_rush_fee_checkout(
    rush_price_cents: int,
    requester_name: str,
    requester_email: str,
    print_name: str,
    form_data: Dict[str, Any],
    file_ids: List[str],
    account_id: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Create Stripe Checkout Session for a rush fee.

    form_data contains all the request form fields needed to create the request
    after payment succeeds. file_ids lists files already saved to disk.

    Returns (checkout_url, payment_id) on success, (None, error_message) on failure.
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

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
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
            mode="payment",
            success_url=f"{BASE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}/?payment_cancelled=1",
            customer_email=requester_email.strip().lower(),
            metadata={
                "payment_id": payment_id,
                "payment_type": "rush_fee",
            },
        )
    except Exception as e:
        logger.error(f"[PAYMENTS] Stripe rush session creation failed: {e}")
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

    return session.url, payment_id


def create_quote_checkout(
    request_id: str,
    amount_cents: int,
    request_dict: dict,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Create Stripe Checkout Session for an admin-set quote on a request.

    Returns (checkout_url, payment_id) on success, (None, error_message) on failure.
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

    try:
        access_token = request_dict.get("access_token", "")
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
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
            mode="payment",
            success_url=f"{BASE_URL}/payment/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{BASE_URL}/open/{request_id}?token={access_token}&payment_cancelled=1",
            customer_email=payer_email if payer_email else None,
            metadata={
                "payment_id": payment_id,
                "payment_type": "quote",
                "request_id": request_id,
            },
        )
    except Exception as e:
        logger.error(f"[PAYMENTS] Stripe quote session creation failed: {e}")
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

    return session.url, payment_id


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


# ─────────────────────────── WEBHOOK ──────────────────────────────────────────


def verify_webhook_signature(payload: bytes, sig_header: str):
    """Verify Stripe webhook signature and return the event object."""
    stripe = _get_stripe()
    if not stripe or not STRIPE_WEBHOOK_SECRET:
        return None
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        return event
    except Exception as e:
        logger.warning(f"[PAYMENTS] Webhook signature verification failed: {e}")
        return None


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Stripe webhook endpoint. Verifies signature, then processes the event."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    if not STRIPE_WEBHOOK_SECRET:
        logger.error("[PAYMENTS] Webhook received but STRIPE_WEBHOOK_SECRET not configured")
        return JSONResponse({"error": "Webhook not configured"}, status_code=503)

    event = verify_webhook_signature(payload, sig_header)
    if not event:
        return JSONResponse({"error": "Invalid signature"}, status_code=400)

    event_type = event.get("type", "")
    event_data = event.get("data", {}).get("object", {})

    logger.info(f"[PAYMENTS] Webhook received: {event_type}")

    if event_type == "checkout.session.completed":
        result = _handle_checkout_completed(event_data)
        return JSONResponse(result)

    if event_type == "checkout.session.expired":
        result = _handle_checkout_expired(event_data)
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

    now = now_iso()

    conn.execute(
        """UPDATE payments SET status = 'completed', updated_at = ?,
            stripe_payment_intent_id = ?, stripe_event_id = ?
        WHERE id = ?""",
        (now, session.get("payment_intent"), session.get("id"), payment_id),
    )

    try:
        if payment_type == "store_item":
            _fulfill_store_item_payment(conn, payment, now)
        elif payment_type == "rush_fee":
            _fulfill_rush_fee_payment(conn, payment, now)
        elif payment_type == "quote":
            _fulfill_quote_payment(conn, payment, now)
    except Exception as e:
        logger.error(f"[PAYMENTS] Fulfillment error for {payment_id}: {e}", exc_info=True)
        conn.commit()
        conn.close()
        return {"ok": False, "error": str(e)}

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


# ─────────────────────────── FULFILLMENT ──────────────────────────────────────


def _fulfill_store_item_payment(conn, payment, now: str):
    """Create the print request after successful store item payment."""
    meta = json.loads(payment["metadata"] or "{}")
    item = conn.execute(
        "SELECT * FROM store_items WHERE id = ?", (payment["store_item_id"],)
    ).fetchone()
    if not item:
        logger.error(f"[PAYMENTS] Store item {payment['store_item_id']} not found for payment {payment['id']}")
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

    logger.info(f"[PAYMENTS] Store item fulfilled: payment={payment['id']}, request={rid}")


def _fulfill_rush_fee_payment(conn, payment, now: str):
    """Create the rush-priority request after successful payment."""
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

    logger.info(f"[PAYMENTS] Rush fee fulfilled: payment={payment['id']}, request={rid}")


def _fulfill_quote_payment(conn, payment, now: str):
    """Mark the quoted request as paid."""
    rid = payment["request_id"]
    if not rid:
        logger.error(f"[PAYMENTS] Quote payment {payment['id']} has no request_id")
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

    logger.info(f"[PAYMENTS] Quote fulfilled: payment={payment['id']}, request={rid}")
