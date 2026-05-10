import json
import uuid
from io import BytesIO

from tests.conftest import get_test_db
from app.payments import _validate_unclaimed_uploaded_file_ids as _payments_validate_unclaimed
from app.credits import _validate_unclaimed_uploaded_file_ids as _credits_validate_unclaimed


def _latest_request_id_for_email(email: str) -> str | None:
    conn = get_test_db()
    row = conn.execute(
        "SELECT id FROM requests WHERE requester_email = ? ORDER BY created_at DESC LIMIT 1",
        (email,),
    ).fetchone()
    conn.close()
    return row["id"] if row else None


def test_chunked_upload_lifecycle_and_submit_linking(client):
    file_bytes = b"solid cube\nendsolid cube\n"

    init_resp = client.post(
        "/submit/upload-chunked/init",
        json={"filename": "chunked_model.stl", "size_bytes": len(file_bytes)},
    )
    assert init_resp.status_code == 200
    init_payload = init_resp.json()
    assert init_payload.get("ok") is True
    upload_id = init_payload["upload_id"]

    chunk_resp = client.post(
        "/submit/upload-chunked/chunk",
        data={"upload_id": upload_id, "chunk_index": "0"},
        files={"chunk": ("chunked_model.stl", BytesIO(file_bytes), "application/octet-stream")},
    )
    assert chunk_resp.status_code == 200

    complete_resp = client.post(
        "/submit/upload-chunked/complete",
        data={"upload_id": upload_id},
    )
    assert complete_resp.status_code == 200
    complete_payload = complete_resp.json()
    assert complete_payload.get("ok") is True
    file_id = complete_payload["file_id"]

    conn = get_test_db()
    pre_file = conn.execute(
        "SELECT id, request_id, original_filename FROM files WHERE id = ?",
        (file_id,),
    ).fetchone()
    conn.close()
    assert pre_file is not None
    assert pre_file["request_id"] in (None, "")
    assert pre_file["original_filename"] == "chunked_model.stl"

    requester_email = "chunked-link@example.com"
    submit_resp = client.post(
        "/submit",
        data={
            "requester_name": "Chunked Linker",
            "requester_email": requester_email,
            "print_name": "Chunked Submit",
            "printer": "ANY",
            "material": "PLA",
            "colors": "Blue",
            "uploaded_file_ids_json": json.dumps([file_id]),
        },
        follow_redirects=False,
    )
    assert submit_resp.status_code in (200, 303)

    rid = _latest_request_id_for_email(requester_email)
    assert rid is not None

    conn = get_test_db()
    linked_file = conn.execute(
        "SELECT request_id FROM files WHERE id = ?",
        (file_id,),
    ).fetchone()
    conn.close()
    assert linked_file is not None
    assert linked_file["request_id"] == rid


def test_submit_rejects_unknown_preuploaded_file_id(client):
    unknown_file_id = str(uuid.uuid4())

    resp = client.post(
        "/submit",
        data={
            "requester_name": "Unknown File",
            "requester_email": "unknown-file@example.com",
            "print_name": "Broken Reference",
            "printer": "ANY",
            "material": "PLA",
            "colors": "Black",
            "uploaded_file_ids_json": json.dumps([unknown_file_id]),
        },
    )

    assert resp.status_code in (200, 400)
    assert "re-upload" in resp.text.lower() or "not found" in resp.text.lower()


def test_chunk_endpoint_rejects_out_of_order_chunks(client):
    init_resp = client.post(
        "/submit/upload-chunked/init",
        json={"filename": "order_test.stl", "size_bytes": 30 * 1024 * 1024},
    )
    assert init_resp.status_code == 200
    upload_id = init_resp.json()["upload_id"]

    out_of_order = client.post(
        "/submit/upload-chunked/chunk",
        data={"upload_id": upload_id, "chunk_index": "1"},
        files={"chunk": ("order_test.stl", BytesIO(b"partial"), "application/octet-stream")},
    )

    assert out_of_order.status_code == 409
    assert "Expected chunk 0" in out_of_order.text


def test_unclaimed_file_validators_accept_empty_request_id_placeholder(client):
    file_id = str(uuid.uuid4())
    stored = f"{uuid.uuid4()}.stl"
    conn = get_test_db()
    conn.execute(
        """INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes)
           VALUES (?, ?, datetime('now'), ?, ?, ?)""",
        (file_id, "", "placeholder.stl", stored, 12),
    )
    conn.commit()
    conn.close()

    assert _payments_validate_unclaimed([file_id]) is True
    assert _credits_validate_unclaimed([file_id]) is True
