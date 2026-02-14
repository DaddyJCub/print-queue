import hashlib
import secrets
import sqlite3
import uuid
from typing import Optional


def claim_hash(claim_code: str) -> str:
    return "sha256:" + hashlib.sha256(claim_code.encode("utf-8")).hexdigest()


def verify_claim_code(claim_code: str, stored_hash: Optional[str]) -> bool:
    if not claim_code or not stored_hash:
        return False
    expected = claim_hash(claim_code)
    if stored_hash.startswith("sha256:"):
        return secrets.compare_digest(expected, stored_hash)
    return secrets.compare_digest(claim_code, stored_hash)


def token_hash(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_device_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def rotate_and_issue_device_token(
    conn: sqlite3.Connection,
    *,
    device_id: str,
    issued_at: str,
) -> str:
    token = generate_device_token(32)
    token_id = str(uuid.uuid4())
    conn.execute("UPDATE device_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL", (issued_at, device_id))
    conn.execute(
        "INSERT INTO device_tokens (id, device_id, token_hash, created_at, last_used_at) VALUES (?, ?, ?, ?, ?)",
        (token_id, device_id, token_hash(token), issued_at, issued_at),
    )
    return token
