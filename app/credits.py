"""
Credits / Rewards system.

Gated behind the `store_rewards` feature flag AND the `credits_enabled` setting.
Provides atomic grant/spend operations, transaction logging, auto-grant scheduling,
and credit-based checkout endpoints.
"""

import uuid
import logging
import asyncio
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers (imports from main to avoid circular deps at module level)
# ---------------------------------------------------------------------------

def _db():
    from app.main import db
    return db()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_tables_ensured = False

def _ensure_tables():
    """Create credit tables if they don't exist yet (self-healing)."""
    global _tables_ensured
    if _tables_ensured:
        return
    try:
        conn = _db()
        conn.execute("""
        CREATE TABLE IF NOT EXISTS credit_transactions (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            amount INTEGER NOT NULL,
            balance_after INTEGER NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            reference_id TEXT,
            created_at TEXT NOT NULL,
            created_by_account_id TEXT,
            FOREIGN KEY(account_id) REFERENCES accounts(id)
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_credit_tx_account ON credit_transactions(account_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_credit_tx_created ON credit_transactions(created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_credit_tx_type ON credit_transactions(type);")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS credit_auto_grants (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL UNIQUE,
            amount INTEGER NOT NULL,
            is_active INTEGER DEFAULT 1,
            last_granted_at TEXT,
            created_at TEXT NOT NULL,
            created_by_account_id TEXT,
            FOREIGN KEY(account_id) REFERENCES accounts(id)
        );
        """)
        conn.commit()
        conn.close()
        _tables_ensured = True
    except Exception as e:
        logger.warning(f"[CREDITS] Failed to ensure tables: {e}")


def _get_setting(key, default=None):
    from app.main import get_setting
    return get_setting(key, default)


def _get_bool_setting(key, default=False):
    from app.main import get_bool_setting
    return get_bool_setting(key, default)


# ---------------------------------------------------------------------------
# Feature gate
# ---------------------------------------------------------------------------

def is_credits_enabled() -> bool:
    """Credits are enabled when the store_rewards feature flag is on."""
    from app.auth import is_feature_enabled
    return is_feature_enabled("store_rewards")


# ---------------------------------------------------------------------------
# Resolve user → account ID (dual-table bridge)
# ---------------------------------------------------------------------------

def resolve_account_id(email: str) -> str | None:
    """Map a user email to the corresponding accounts.id.

    The legacy ``users`` table and the unified ``accounts`` table have
    different IDs for the same person.  All credit operations live on the
    ``accounts`` table, so callers that only have a ``User`` object must
    resolve the matching account ID via email first.
    """
    if not email:
        return None
    conn = _db()
    row = conn.execute(
        "SELECT id FROM accounts WHERE LOWER(email) = LOWER(?)", (email,)
    ).fetchone()
    conn.close()
    return row["id"] if row else None


# ---------------------------------------------------------------------------
# Balance
# ---------------------------------------------------------------------------

def get_balance(account_id: str) -> int:
    """Read current credit balance from accounts table."""
    conn = _db()
    row = conn.execute("SELECT credits FROM accounts WHERE id = ?", (account_id,)).fetchone()
    conn.close()
    return (row["credits"] or 0) if row else 0


# ---------------------------------------------------------------------------
# Grant credits (admin or auto)
# ---------------------------------------------------------------------------

def grant_credits(
    account_id: str,
    amount: int,
    tx_type: str,
    description: str = "",
    reference_id: str = None,
    granted_by: str = None,
) -> dict:
    """
    Add credits to an account. Returns the transaction dict.
    tx_type: 'admin_grant' | 'auto_grant' | 'refund'
    """
    if amount <= 0:
        raise ValueError("Grant amount must be positive")

    _ensure_tables()
    conn = _db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE accounts SET credits = credits + ? WHERE id = ?",
            (amount, account_id),
        )
        row = conn.execute("SELECT credits FROM accounts WHERE id = ?", (account_id,)).fetchone()
        balance_after = row["credits"] if row else amount

        tx_id = str(uuid.uuid4())
        now = _now()
        conn.execute(
            """INSERT INTO credit_transactions
               (id, account_id, amount, balance_after, type, description, reference_id, created_at, created_by_account_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tx_id, account_id, amount, balance_after, tx_type, description, reference_id, now, granted_by),
        )
        conn.commit()
        logger.info(f"[CREDITS] Granted {amount} to {account_id} (type={tx_type}, balance={balance_after})")
        return {"id": tx_id, "amount": amount, "balance_after": balance_after}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Spend credits (atomic, prevents negative balance)
# ---------------------------------------------------------------------------

def spend_credits(
    account_id: str,
    amount: int,
    tx_type: str,
    description: str = "",
    reference_id: str = None,
) -> dict | None:
    """
    Deduct credits atomically. Returns transaction dict on success, None if insufficient.
    tx_type: 'store_redemption' | 'rush_redemption' | 'request_redemption'
    """
    if amount <= 0:
        raise ValueError("Spend amount must be positive")

    _ensure_tables()
    conn = _db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE accounts SET credits = credits - ? WHERE id = ? AND credits >= ?",
            (amount, account_id, amount),
        )
        if cur.rowcount == 0:
            conn.rollback()
            return None  # Insufficient credits

        row = conn.execute("SELECT credits FROM accounts WHERE id = ?", (account_id,)).fetchone()
        balance_after = row["credits"] if row else 0

        tx_id = str(uuid.uuid4())
        now = _now()
        conn.execute(
            """INSERT INTO credit_transactions
               (id, account_id, amount, balance_after, type, description, reference_id, created_at, created_by_account_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
            (tx_id, account_id, -amount, balance_after, tx_type, description, reference_id, now),
        )
        conn.commit()
        logger.info(f"[CREDITS] Spent {amount} from {account_id} (type={tx_type}, balance={balance_after})")
        return {"id": tx_id, "amount": -amount, "balance_after": balance_after}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Refund
# ---------------------------------------------------------------------------

def refund_credits(account_id: str, amount: int, original_reference_id: str = None) -> dict:
    """Refund credits back to an account."""
    return grant_credits(
        account_id, amount, "refund",
        description="Credit refund",
        reference_id=original_reference_id,
    )


# ---------------------------------------------------------------------------
# Transaction history
# ---------------------------------------------------------------------------

def get_transactions(account_id: str, limit: int = 50, offset: int = 0) -> list:
    """Get recent credit transactions for a user."""
    _ensure_tables()
    conn = _db()
    rows = conn.execute(
        """SELECT * FROM credit_transactions
           WHERE account_id = ?
           ORDER BY created_at DESC
           LIMIT ? OFFSET ?""",
        (account_id, limit, offset),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_transactions(limit: int = 100) -> list:
    """Get recent transactions across all users (admin view)."""
    _ensure_tables()
    conn = _db()
    rows = conn.execute(
        """SELECT ct.*, a.name as display_name, a.email
           FROM credit_transactions ct
           LEFT JOIN accounts a ON ct.account_id = a.id
           ORDER BY ct.created_at DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Auto-grant management
# ---------------------------------------------------------------------------

def get_all_auto_grants() -> list:
    """List all auto-grant rules with account info."""
    conn = _db()
    rows = conn.execute(
        """SELECT cag.*, a.name as display_name, a.email
           FROM credit_auto_grants cag
           LEFT JOIN accounts a ON cag.account_id = a.id
           ORDER BY cag.created_at DESC""",
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_auto_grant(account_id: str, amount: int, created_by: str) -> str:
    """Create or update an auto-grant rule for a user. Returns the rule id."""
    conn = _db()
    now = _now()
    existing = conn.execute(
        "SELECT id FROM credit_auto_grants WHERE account_id = ?", (account_id,)
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE credit_auto_grants SET amount = ?, is_active = 1, created_by_account_id = ? WHERE account_id = ?",
            (amount, created_by, account_id),
        )
        rule_id = existing["id"]
    else:
        rule_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO credit_auto_grants (id, account_id, amount, is_active, created_at, created_by_account_id)
               VALUES (?, ?, ?, 1, ?, ?)""",
            (rule_id, account_id, amount, now, created_by),
        )
    conn.commit()
    conn.close()
    logger.info(f"[CREDITS] Auto-grant set: {amount}/month for {account_id}")
    return rule_id


def remove_auto_grant(rule_id: str) -> bool:
    """Delete an auto-grant rule."""
    conn = _db()
    cur = conn.execute("DELETE FROM credit_auto_grants WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Process auto-grants (called by scheduler or manual trigger)
# ---------------------------------------------------------------------------

def process_auto_grants() -> int:
    """
    Grant credits to all active auto-grant rules.
    Skips rules already granted this calendar month.
    Returns count of grants processed.
    """
    now = _now()
    current_month = now[:7]  # "YYYY-MM"

    conn = _db()
    rules = conn.execute(
        "SELECT * FROM credit_auto_grants WHERE is_active = 1"
    ).fetchall()
    conn.close()

    granted_count = 0
    for rule in rules:
        rule = dict(rule)
        # Skip if already granted this month
        if rule.get("last_granted_at") and rule["last_granted_at"][:7] == current_month:
            continue

        try:
            grant_credits(
                account_id=rule["account_id"],
                amount=rule["amount"],
                tx_type="auto_grant",
                description=f"Monthly auto-grant ({rule['amount']} credits)",
            )
            # Update last_granted_at
            conn2 = _db()
            conn2.execute(
                "UPDATE credit_auto_grants SET last_granted_at = ? WHERE id = ?",
                (now, rule["id"]),
            )
            conn2.commit()
            conn2.close()
            granted_count += 1
        except Exception as e:
            logger.error(f"[CREDITS] Auto-grant failed for {rule['account_id']}: {e}")

    if granted_count:
        logger.info(f"[CREDITS] Auto-grants processed: {granted_count}/{len(rules)}")
    return granted_count


# ---------------------------------------------------------------------------
# Background scheduler for auto-grants
# ---------------------------------------------------------------------------

_scheduler_running = False


async def _auto_grant_loop():
    """Background loop that checks once per hour if auto-grants should run."""
    global _scheduler_running
    while _scheduler_running:
        try:
            day_setting = int(_get_setting("credits_auto_grant_day", "1"))
            today = datetime.now(timezone.utc).day
            if today == day_setting and is_credits_enabled():
                process_auto_grants()
        except Exception as e:
            logger.error(f"[CREDITS] Scheduler error: {e}")

        await asyncio.sleep(3600)  # Check every hour


def start_credit_grant_scheduler():
    """Start the background credit auto-grant scheduler in a daemon thread."""
    global _scheduler_running
    if _scheduler_running:
        return

    _scheduler_running = True

    def run_async():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_auto_grant_loop())

    thread = threading.Thread(target=run_async, daemon=True)
    thread.start()
    logger.info("[CREDITS] Auto-grant scheduler started")


# ---------------------------------------------------------------------------
# Credit price helpers
# ---------------------------------------------------------------------------

def get_credit_price_for_item(item) -> int | None:
    """Get the credit price for a store item, or None if not redeemable."""
    if not is_credits_enabled():
        return None
    price = item.get("credit_price") if isinstance(item, dict) else getattr(item, "credit_price", None)
    return price if price and price > 0 else None


def get_rush_credit_cost() -> int:
    """Get the credit cost for rush orders."""
    return int(_get_setting("credits_per_rush", "1"))


def get_request_credit_cost() -> int:
    """Get the credit cost for custom print requests."""
    return int(_get_setting("credits_per_custom_request", "1"))


# ---------------------------------------------------------------------------
# API: Credit-based store checkout
# ---------------------------------------------------------------------------

@router.post("/api/credits/store-checkout/{item_id}")
async def api_credit_store_checkout(request: Request, item_id: str,
                                     requester_name: str = Form(...),
                                     requester_email: str = Form(...),
                                     colors: str = Form(""),
                                     notes: str = Form("")):
    """Purchase a store item using credits instead of payment."""
    from app.auth import get_current_user

    if not is_credits_enabled():
        return JSONResponse({"error": "Credits are not enabled"}, status_code=400)

    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "auth_required"}, status_code=401)

    conn = _db()
    item = conn.execute("SELECT * FROM store_items WHERE id = ? AND is_active = 1", (item_id,)).fetchone()
    if not item:
        conn.close()
        return JSONResponse({"error": "Item not found"}, status_code=404)
    item = dict(item)
    conn.close()

    credit_price = get_credit_price_for_item(item)
    if not credit_price:
        return JSONResponse({"error": "This item cannot be purchased with credits"}, status_code=400)

    # Resolve users.id → accounts.id (dual-table bridge)
    acct_id = resolve_account_id(user.email) or user.id

    # Atomic spend
    try:
        tx = spend_credits(
            account_id=acct_id,
            amount=credit_price,
            tx_type="store_redemption",
            description=f"Store item: {item['name']}",
            reference_id=item_id,
        )
    except Exception as e:
        logger.error(f"[CREDITS] Store checkout failed: {e}")
        return JSONResponse({"error": f"Credit transaction failed: {e}"}, status_code=500)
    if tx is None:
        return JSONResponse({"error": "insufficient_credits", "needed": credit_price, "balance": get_balance(acct_id)}, status_code=400)

    # Create the print request (same as free store item flow)
    import secrets as _secrets
    rid = str(uuid.uuid4())
    created = _now()
    access_token = _secrets.token_urlsafe(32)

    try:
        conn = _db()
        conn.execute("""
            INSERT INTO requests (
                id, created_at, updated_at, requester_name, requester_email,
                printer, material, colors, link_url, notes, print_name,
                status, access_token, priority, print_time_minutes, store_item_id, account_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rid, created, created,
            requester_name.strip(), requester_email.strip().lower(),
            "ANY",
            item.get("material", "") or "",
            colors.strip() or item.get("colors", "") or "",
            item.get("link_url", "") or "",
            notes.strip() or None,
            item["name"],
            "NEW",
            access_token,
            0,
            item.get("estimated_time_minutes"),
            item_id,
            user.id,
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"[CREDITS] Store checkout request creation failed: {e}")
        # Refund the spent credits
        try:
            refund_credits(acct_id, credit_price, original_reference_id=item_id)
            logger.info(f"[CREDITS] Auto-refunded {credit_price} credits to {acct_id}")
        except Exception as re:
            logger.error(f"[CREDITS] Auto-refund also failed: {re}")
        return JSONResponse({"error": f"Failed to create request: {e}"}, status_code=500)

    logger.info(f"[CREDITS] Store purchase: {item['name']} by {user.id} for {credit_price} credits (request={rid})")

    return JSONResponse({
        "success": True,
        "credits_spent": credit_price,
        "balance": tx["balance_after"],
        "redirect": f"/my/{rid}?token={access_token}",
    })


# ---------------------------------------------------------------------------
# API: Credit-based rush checkout
# ---------------------------------------------------------------------------

@router.post("/api/credits/rush-checkout")
async def api_credit_rush_checkout(
    request: Request,
    requester_name: str = Form(...),
    requester_email: str = Form(...),
    print_name: str = Form(""),
    printer: str = Form("ANY"),
    material: str = Form("PLA"),
    colors: str = Form(""),
    link_url: str = Form(""),
    notes: str = Form(""),
    special_notes: str = Form(""),
):
    """Submit a rush request using credits instead of payment."""
    from app.auth import get_current_user

    if not is_credits_enabled():
        return JSONResponse({"error": "Credits are not enabled"}, status_code=400)

    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "auth_required"}, status_code=401)

    rush_cost = get_rush_credit_cost()

    # Resolve users.id → accounts.id (dual-table bridge)
    acct_id = resolve_account_id(user.email) or user.id

    try:
        tx = spend_credits(
            account_id=acct_id,
            amount=rush_cost,
            tx_type="rush_redemption",
            description=f"Rush fee: {print_name or 'Custom request'}",
        )
    except Exception as e:
        logger.error(f"[CREDITS] Rush checkout failed: {e}")
        return JSONResponse({"error": f"Credit transaction failed: {e}"}, status_code=500)
    if tx is None:
        return JSONResponse({"error": "insufficient_credits", "needed": rush_cost, "balance": get_balance(acct_id)}, status_code=400)

    # Create the rush request
    import secrets as _secrets
    rid = str(uuid.uuid4())
    created = _now()
    access_token = _secrets.token_urlsafe(32)

    conn = _db()
    conn.execute("""
        INSERT INTO requests (
            id, created_at, updated_at, requester_name, requester_email,
            printer, material, colors, link_url, notes, print_name,
            status, access_token, priority, special_notes, is_rush, account_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    """, (
        rid, created, created,
        requester_name.strip(), requester_email.strip().lower(),
        printer, material,
        colors.strip() or "",
        link_url.strip() or "",
        notes.strip() or None,
        print_name.strip(),
        "NEW",
        access_token,
        1,  # Rush = high priority
        special_notes.strip() or None,
        user.id,
    ))
    conn.commit()
    conn.close()

    logger.info(f"[CREDITS] Rush purchase by {user.id} for {rush_cost} credits (request={rid})")

    return JSONResponse({
        "success": True,
        "credits_spent": rush_cost,
        "balance": tx["balance_after"],
        "redirect": f"/my/{rid}?token={access_token}",
    })


# ---------------------------------------------------------------------------
# API: Credit-based custom request
# ---------------------------------------------------------------------------

@router.post("/api/credits/request-checkout")
async def api_credit_request_checkout(
    request: Request,
    requester_name: str = Form(...),
    requester_email: str = Form(...),
    print_name: str = Form(""),
    printer: str = Form("ANY"),
    material: str = Form("PLA"),
    colors: str = Form(""),
    link_url: str = Form(""),
    notes: str = Form(""),
    special_notes: str = Form(""),
):
    """Submit a custom print request using credits."""
    from app.auth import get_current_user

    if not is_credits_enabled():
        return JSONResponse({"error": "Credits are not enabled"}, status_code=400)

    user = await get_current_user(request)
    if not user:
        return JSONResponse({"error": "auth_required"}, status_code=401)

    request_cost = get_request_credit_cost()

    # Resolve users.id → accounts.id (dual-table bridge)
    acct_id = resolve_account_id(user.email) or user.id

    try:
        tx = spend_credits(
            account_id=acct_id,
            amount=request_cost,
            tx_type="request_redemption",
            description=f"Custom request: {print_name or 'Print request'}",
        )
    except Exception as e:
        logger.error(f"[CREDITS] Request checkout failed: {e}")
        return JSONResponse({"error": f"Credit transaction failed: {e}"}, status_code=500)
    if tx is None:
        return JSONResponse({"error": "insufficient_credits", "needed": request_cost, "balance": get_balance(acct_id)}, status_code=400)

    import secrets as _secrets
    rid = str(uuid.uuid4())
    created = _now()
    access_token = _secrets.token_urlsafe(32)

    conn = _db()
    conn.execute("""
        INSERT INTO requests (
            id, created_at, updated_at, requester_name, requester_email,
            printer, material, colors, link_url, notes, print_name,
            status, access_token, priority, special_notes, account_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rid, created, created,
        requester_name.strip(), requester_email.strip().lower(),
        printer, material,
        colors.strip() or "",
        link_url.strip() or "",
        notes.strip() or None,
        print_name.strip(),
        "NEW",
        access_token,
        0,
        special_notes.strip() or None,
        user.id,
    ))
    conn.commit()
    conn.close()

    logger.info(f"[CREDITS] Request purchase by {user.id} for {request_cost} credits (request={rid})")

    return JSONResponse({
        "success": True,
        "credits_spent": request_cost,
        "balance": tx["balance_after"],
        "redirect": f"/my/{rid}?token={access_token}",
    })
