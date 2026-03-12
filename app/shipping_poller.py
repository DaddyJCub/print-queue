"""USPS tracking poll worker.

Periodically queries the USPS v3 Tracking API for all active shipments
(both purchased labels AND manually entered tracking numbers).

This replaces the need for Shippo webhooks — USPS has no webhook support,
so we poll at a configurable interval (default: 30 minutes).
"""

import asyncio
import json
import os
import threading
import traceback
from datetime import datetime
from typing import Optional


def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def start_usps_tracking_poller():
    """Start the USPS tracking poll worker in a background daemon thread."""
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_usps_tracking_poll_loop())

    thread = threading.Thread(target=_run, daemon=True, name="usps-tracking-poller")
    thread.start()
    print("[USPS-POLL] Tracking poller started")


async def _usps_tracking_poll_loop():
    """Main async loop — polls USPS tracking for all active shipments."""
    # Import lazily to avoid circular imports at module load
    from app.main import db, get_setting, get_bool_setting
    from app.shipping_usps import USPSClient, map_usps_tracking_status

    # Wait 60s after startup before first poll
    await asyncio.sleep(60)

    while True:
        try:
            poll_minutes = int(get_setting("usps_tracking_poll_minutes", "30") or "30")
            if poll_minutes < 5:
                poll_minutes = 5

            client_id = get_setting("usps_client_id", "").strip() or os.getenv("USPS_CLIENT_ID", "").strip()
            client_secret = get_setting("usps_client_secret", "").strip() or os.getenv("USPS_CLIENT_SECRET", "").strip()

            if not client_id or not client_secret:
                # USPS not configured — sleep and retry later
                await asyncio.sleep(poll_minutes * 60)
                continue

            test_mode = get_bool_setting("usps_test_mode", True)
            client = USPSClient(
                client_id=client_id,
                client_secret=client_secret,
                use_test_env=test_mode,
            )

            # Query all shipments with active tracking (not delivered/cancelled/returned)
            conn = db()
            active_statuses = (
                "REQUESTED", "ADDRESS_VALIDATED", "QUOTED",
                "LABEL_PURCHASED", "PRE_TRANSIT", "IN_TRANSIT",
                "OUT_FOR_DELIVERY", "EXCEPTION",
            )
            placeholders = ",".join("?" for _ in active_statuses)
            rows = conn.execute(
                f"""SELECT rs.request_id, rs.tracking_number, rs.shipping_status, rs.tracking_status,
                           rs.usps_last_polled_at, rs.carrier, r.requester_email, r.print_name
                    FROM request_shipping rs
                    JOIN requests r ON r.id = rs.request_id
                    WHERE rs.tracking_number IS NOT NULL
                      AND rs.tracking_number != ''
                      AND rs.shipping_status IN ({placeholders})
                    ORDER BY rs.updated_at ASC""",
                active_statuses,
            ).fetchall()
            conn.close()

            polled_count = 0
            updated_count = 0

            for row in rows:
                tracking_num = row["tracking_number"]
                rid = row["request_id"]
                old_status = row["shipping_status"]

                try:
                    tracking_data = client.get_tracking(tracking_num)
                except Exception as exc:
                    print(f"[USPS-POLL] Error querying tracking {tracking_num[:8]}...: {exc}")
                    continue

                polled_count += 1

                # Extract status
                status_category = tracking_data.get("statusCategory") or ""
                new_internal_status = map_usps_tracking_status(status_category)

                # Extract estimated delivery
                est_delivery = tracking_data.get("expectedDeliveryDate") or tracking_data.get("estimatedDeliveryDate")

                # Determine if status actually changed
                status_changed = new_internal_status != old_status

                now = _now_iso()
                conn = db()

                # Always update last polled time
                update_fields = "usps_last_polled_at = ?"
                update_values = [now]

                if status_changed:
                    update_fields += ", shipping_status = ?, tracking_status = ?, updated_at = ?"
                    update_values.extend([new_internal_status, new_internal_status, now])

                if est_delivery:
                    update_fields += ", estimated_delivery_date = ?"
                    update_values.append(str(est_delivery))

                if new_internal_status == "DELIVERED":
                    update_fields += ", delivered_at = COALESCE(delivered_at, ?)"
                    update_values.append(now)

                update_values.append(rid)
                conn.execute(
                    f"UPDATE request_shipping SET {update_fields} WHERE request_id = ?",
                    update_values,
                )

                if status_changed:
                    import uuid
                    conn.execute(
                        """INSERT INTO request_shipping_events
                           (id, request_id, created_at, event_type, shipping_status, provider, message, payload_json)
                           VALUES (?, ?, ?, 'tracking_poll', ?, 'usps', ?, ?)""",
                        (
                            str(uuid.uuid4()),
                            rid,
                            now,
                            new_internal_status,
                            f"USPS tracking updated: {old_status} → {new_internal_status}",
                            json.dumps({"statusCategory": status_category, "status": tracking_data.get("status", "")}),
                        ),
                    )
                    updated_count += 1

                    # Notify requester
                    if get_bool_setting("shipping_notify_requester_updates", True):
                        req_row = conn.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
                        ship_row = conn.execute("SELECT * FROM request_shipping WHERE request_id = ?", (rid,)).fetchone()
                        if req_row and ship_row:
                            try:
                                from app.api_builds import _notify_requester_shipping_status
                                _notify_requester_shipping_status(dict(req_row), dict(ship_row), new_internal_status)
                            except Exception as notify_exc:
                                print(f"[USPS-POLL] Notification error for {rid[:8]}: {notify_exc}")

                    # Notify admins on exceptions
                    if new_internal_status == "EXCEPTION" and get_bool_setting("shipping_notify_admin_exceptions", True):
                        try:
                            from app.main import send_push_notification_to_admins
                            send_push_notification_to_admins(
                                title="Shipping Exception",
                                body=f"Tracking {tracking_num}: {tracking_data.get('status', 'exception detected')}",
                                url=f"/admin/request/{rid}#shipping",
                            )
                        except Exception:
                            pass

                    # Send LED notification to Printellect device
                    try:
                        from app.printellect import notify_device_shipping_status
                        req_email = row["requester_email"]
                        if req_email:
                            notify_device_shipping_status(req_email, new_internal_status)
                    except Exception:
                        pass

                conn.commit()
                conn.close()

                # Small delay between API calls to be respectful
                await asyncio.sleep(2)

            if polled_count > 0:
                print(f"[USPS-POLL] Polled {polled_count} tracking numbers, {updated_count} status updates")

        except Exception as exc:
            print(f"[USPS-POLL] Poll cycle error: {exc}")
            traceback.print_exc()

        # Sleep until next poll cycle
        try:
            from app.main import get_setting as gs
            interval = int(gs("usps_tracking_poll_minutes", "30") or "30")
        except Exception:
            interval = 30
        if interval < 5:
            interval = 5
        await asyncio.sleep(interval * 60)
