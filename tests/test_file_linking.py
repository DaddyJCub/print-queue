"""
Tests for file linking (G-code ↔ model file associations) and file management.

Covers:
- File-to-file linking (G-code to STL/3MF source model)
- File unlinking
- Validation (self-link, non-existent target, cross-request)
- File type categorization in template context
- File upload with linking
- UI elements (linked model column, file type icons)
"""
import os
import uuid
import pytest

from tests.conftest import (
    create_test_request,
    assert_html_contains,
    assert_redirect_to,
    get_test_db,
    now_iso,
    UPLOAD_DIR,
)


def create_test_file(request_id: str, filename: str = "test_model.stl",
                     size_bytes: int = 1024, build_id: str = None,
                     linked_file_id: str = None) -> str:
    """Create a test file entry in the database. Returns file_id."""
    conn = get_test_db()
    file_id = str(uuid.uuid4())
    stored = f"{uuid.uuid4()}.{filename.rsplit('.', 1)[-1]}"
    now = now_iso()
    
    conn.execute("""
        INSERT INTO files (id, request_id, created_at, original_filename,
                          stored_filename, size_bytes, build_id, linked_file_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (file_id, request_id, now, filename, stored, size_bytes,
          build_id, linked_file_id))
    conn.commit()
    conn.close()
    
    # Create a dummy file on disk so download/preview works
    file_path = os.path.join(str(UPLOAD_DIR), stored)
    with open(file_path, "wb") as f:
        f.write(b"\x00" * size_bytes)
    
    return file_id


class TestFileLinking:
    """Tests for linking G-code files to their source model files."""
    
    def test_link_gcode_to_stl(self, admin_client):
        """Should be able to link a G-code file to an STL model."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        stl_id = create_test_file(rid, "model.stl")
        gcode_id = create_test_file(rid, "model.gcode")
        
        resp = admin_client.post(
            f"/admin/request/{rid}/file/{gcode_id}/link",
            data={"linked_file_id": stl_id},
            follow_redirects=False,
        )
        assert_redirect_to(resp, f"/admin/request/{rid}")
        
        # Verify in DB
        conn = get_test_db()
        row = conn.execute("SELECT linked_file_id FROM files WHERE id = ?", (gcode_id,)).fetchone()
        conn.close()
        assert row["linked_file_id"] == stl_id
    
    def test_link_gcode_to_3mf(self, admin_client):
        """Should be able to link a G-code file to a 3MF model."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        mf_id = create_test_file(rid, "design.3mf")
        gcode_id = create_test_file(rid, "design.gcode")
        
        resp = admin_client.post(
            f"/admin/request/{rid}/file/{gcode_id}/link",
            data={"linked_file_id": mf_id},
            follow_redirects=False,
        )
        assert_redirect_to(resp, f"/admin/request/{rid}")
        
        conn = get_test_db()
        row = conn.execute("SELECT linked_file_id FROM files WHERE id = ?", (gcode_id,)).fetchone()
        conn.close()
        assert row["linked_file_id"] == mf_id
    
    def test_unlink_file(self, admin_client):
        """Should be able to unlink a file by submitting empty linked_file_id."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        stl_id = create_test_file(rid, "model.stl")
        gcode_id = create_test_file(rid, "model.gcode", linked_file_id=stl_id)
        
        # Verify link exists
        conn = get_test_db()
        row = conn.execute("SELECT linked_file_id FROM files WHERE id = ?", (gcode_id,)).fetchone()
        assert row["linked_file_id"] == stl_id
        conn.close()
        
        # Unlink
        resp = admin_client.post(
            f"/admin/request/{rid}/file/{gcode_id}/link",
            data={"linked_file_id": ""},
            follow_redirects=False,
        )
        assert_redirect_to(resp, f"/admin/request/{rid}")
        
        conn = get_test_db()
        row = conn.execute("SELECT linked_file_id FROM files WHERE id = ?", (gcode_id,)).fetchone()
        conn.close()
        assert row["linked_file_id"] is None
    
    def test_cannot_link_file_to_itself(self, admin_client):
        """Linking a file to itself should return 400."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        file_id = create_test_file(rid, "model.gcode")
        
        resp = admin_client.post(
            f"/admin/request/{rid}/file/{file_id}/link",
            data={"linked_file_id": file_id},
            follow_redirects=False,
        )
        assert resp.status_code == 400
    
    def test_cannot_link_to_nonexistent_file(self, admin_client):
        """Linking to a non-existent file should return 404."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        gcode_id = create_test_file(rid, "model.gcode")
        fake_id = str(uuid.uuid4())
        
        resp = admin_client.post(
            f"/admin/request/{rid}/file/{gcode_id}/link",
            data={"linked_file_id": fake_id},
            follow_redirects=False,
        )
        assert resp.status_code == 404
    
    def test_cannot_link_to_file_in_different_request(self, admin_client):
        """Linking to a file in a different request should return 404."""
        data1 = create_test_request(status="APPROVED", print_name="Request 1")
        data2 = create_test_request(status="APPROVED", print_name="Request 2")
        
        stl_id = create_test_file(data2["request_id"], "other_model.stl")
        gcode_id = create_test_file(data1["request_id"], "model.gcode")
        
        resp = admin_client.post(
            f"/admin/request/{data1['request_id']}/file/{gcode_id}/link",
            data={"linked_file_id": stl_id},
            follow_redirects=False,
        )
        assert resp.status_code == 404
    
    def test_link_nonexistent_source_file(self, admin_client):
        """Linking from a non-existent file should return 404."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        stl_id = create_test_file(rid, "model.stl")
        fake_id = str(uuid.uuid4())
        
        resp = admin_client.post(
            f"/admin/request/{rid}/file/{fake_id}/link",
            data={"linked_file_id": stl_id},
            follow_redirects=False,
        )
        assert resp.status_code == 404
    
    def test_link_nonexistent_request(self, admin_client):
        """Linking files in a non-existent request should return 404."""
        fake_rid = str(uuid.uuid4())
        fake_fid = str(uuid.uuid4())
        
        resp = admin_client.post(
            f"/admin/request/{fake_rid}/file/{fake_fid}/link",
            data={"linked_file_id": str(uuid.uuid4())},
            follow_redirects=False,
        )
        assert resp.status_code == 404
    
    def test_link_requires_auth(self, client):
        """File link route should require admin authentication."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        file_id = create_test_file(rid, "model.gcode")
        
        resp = client.post(
            f"/admin/request/{rid}/file/{file_id}/link",
            data={"linked_file_id": str(uuid.uuid4())},
            follow_redirects=False,
        )
        # Should redirect to login or return 401/403
        assert resp.status_code in (302, 303, 401, 403)


class TestFileTypeCategories:
    """Tests for file type categorization in the request detail view."""
    
    def test_request_detail_shows_file_type_icons(self, admin_client):
        """Request detail page should show file type icons (model/gcode/other)."""
        data = create_test_request(status="APPROVED", with_builds=1)
        rid = data["request_id"]
        
        create_test_file(rid, "model.stl")
        create_test_file(rid, "sliced.gcode")
        create_test_file(rid, "readme.zip")
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        # Check for file type icons
        assert "🔷" in resp.text  # Model icon
        assert "⚙️" in resp.text  # Gcode icon
        assert "📄" in resp.text  # Other icon
    
    def test_request_detail_shows_link_button_for_unlinked_gcode(self, admin_client):
        """Unlinked G-code files should have a 'Link to model' button."""
        data = create_test_request(status="APPROVED", with_builds=1)
        rid = data["request_id"]
        
        stl_id = create_test_file(rid, "model.stl")
        gcode_id = create_test_file(rid, "sliced.gcode")
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        # Should have a link form for the gcode file
        assert f"/file/{gcode_id}/link" in resp.text
        # Should show the link-to-model button
        assert "Link to model" in resp.text
        # The model file should appear as an option
        assert "model.stl" in resp.text
    
    def test_linked_gcode_nested_under_model(self, admin_client):
        """A linked G-code should appear nested under its model file."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        stl_id = create_test_file(rid, "fancy_model.stl")
        gcode_id = create_test_file(rid, "output.gcode", linked_file_id=stl_id)
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        # Both files should appear
        assert "fancy_model.stl" in resp.text
        assert "output.gcode" in resp.text
        # Should show linked indicator
        assert "linked" in resp.text


class TestFilesUIElements:
    """Tests for the redesigned files table UI."""
    
    def test_files_card_renders(self, admin_client):
        """Files section should render with file cards."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        create_test_file(rid, "part.stl")
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        assert "Files" in resp.text
        assert "part.stl" in resp.text
        assert "KB" in resp.text
    
    def test_file_size_displays_mb_for_large_files(self, admin_client):
        """Large files should show size in MB rather than KB."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        create_test_file(rid, "big_model.stl", size_bytes=5_242_880)  # 5MB
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        assert "MB" in resp.text
    
    def test_empty_files_shows_message(self, admin_client):
        """Empty files section should show appropriate message."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        assert "No files uploaded" in resp.text
    
    def test_file_count_in_header(self, admin_client):
        """Files header should show count of files."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        create_test_file(rid, "a.stl")
        create_test_file(rid, "b.gcode")
        create_test_file(rid, "c.3mf")
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        assert "(3)" in resp.text
    
    def test_download_and_delete_buttons_present(self, admin_client):
        """Each file should have download and delete actions."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        fid = create_test_file(rid, "test.stl")
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        # Download link
        assert f"/file/{fid}" in resp.text
        # Delete form
        assert f"/file/{fid}/delete" in resp.text


class TestBuildsUIElements:
    """Tests for the redesigned builds section UI."""
    
    def test_builds_header_shows_count(self, admin_client):
        """Builds header should show the build count."""
        data = create_test_request(status="APPROVED", with_builds=3)
        rid = data["request_id"]
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        assert "Builds" in resp.text
        assert "(3)" in resp.text
    
    def test_builds_show_status_pills(self, admin_client):
        """Each build should display a compact status pill."""
        data = create_test_request(status="PRINTING", with_builds=2)
        rid = data["request_id"]
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        assert "PRINTING" in resp.text or "QUEUED" in resp.text
    
    def test_builds_inline_actions(self, admin_client):
        """Builds should have inline action buttons on the same row."""
        data = create_test_request(status="PRINTING", with_builds=2)
        rid = data["request_id"]
        bid = data["build_ids"][0]
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        # Should have complete/fail buttons for printing build
        assert f"/admin/build/{bid}/complete" in resp.text
        assert f"/admin/build/{bid}/fail" in resp.text
    
    def test_builds_expandable_edit(self, admin_client):
        """Each build should have an expandable edit section."""
        data = create_test_request(status="APPROVED", with_builds=1)
        rid = data["request_id"]
        bid = data["build_ids"][0]
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        assert "Edit" in resp.text
        assert f"/admin/build/{bid}/update" in resp.text
    
    def test_no_builds_shows_placeholder(self, admin_client):
        """When no builds exist, should show a placeholder message."""
        data = create_test_request(status="NEW")
        rid = data["request_id"]
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        assert "Builds will be created" in resp.text
    
    def test_assigned_files_show_type_icons(self, admin_client):
        """Files assigned to builds should show type icons in build card."""
        data = create_test_request(status="APPROVED", with_builds=1)
        rid = data["request_id"]
        bid = data["build_ids"][0]
        
        create_test_file(rid, "model.stl", build_id=bid)
        create_test_file(rid, "print.gcode", build_id=bid)
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        assert "model.stl" in resp.text
        assert "print.gcode" in resp.text


class TestFileUpload:
    """Tests for file upload with the new UI."""
    
    def test_upload_form_present(self, admin_client):
        """Upload form should be visible on request page."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        resp = admin_client.get(f"/admin/request/{rid}", follow_redirects=True)
        assert resp.status_code == 200
        assert "Upload" in resp.text
        assert f"/admin/request/{rid}/add-file" in resp.text
    
    def test_upload_stl_file(self, admin_client):
        """Should be able to upload an STL file."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        # Create a minimal STL-like file
        stl_content = b"solid test\nendsolid test\n"
        
        resp = admin_client.post(
            f"/admin/request/{rid}/add-file",
            files={"upload": ("test_part.stl", stl_content, "application/octet-stream")},
            follow_redirects=False,
        )
        assert_redirect_to(resp, f"/admin/request/{rid}")
        
        # Verify file was created in DB
        conn = get_test_db()
        files = conn.execute("SELECT * FROM files WHERE request_id = ?", (rid,)).fetchall()
        conn.close()
        assert len(files) == 1
        assert files[0]["original_filename"] == "test_part.stl"
    
    def test_upload_gcode_file(self, admin_client):
        """Should be able to upload a G-code file."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        
        gcode_content = b"; G-code test\nG28\nG1 X10 Y10 Z0.2 F3000\n"
        
        resp = admin_client.post(
            f"/admin/request/{rid}/add-file",
            files={"upload": ("output.gcode", gcode_content, "application/octet-stream")},
            follow_redirects=False,
        )
        assert_redirect_to(resp, f"/admin/request/{rid}")
        
        conn = get_test_db()
        files = conn.execute("SELECT * FROM files WHERE request_id = ?", (rid,)).fetchall()
        conn.close()
        assert len(files) == 1
        assert files[0]["original_filename"] == "output.gcode"


class TestLinkedFileMigration:
    """Tests for the linked_file_id database column."""
    
    def test_linked_file_id_column_exists(self, admin_client):
        """The linked_file_id column should exist in the files table."""
        conn = get_test_db()
        cols = conn.execute("PRAGMA table_info(files)").fetchall()
        col_names = {c[1] for c in cols}
        conn.close()
        assert "linked_file_id" in col_names
    
    def test_linked_file_id_defaults_to_null(self, admin_client):
        """New files should have linked_file_id = NULL by default."""
        data = create_test_request(status="APPROVED")
        rid = data["request_id"]
        fid = create_test_file(rid, "test.stl")
        
        conn = get_test_db()
        row = conn.execute("SELECT linked_file_id FROM files WHERE id = ?", (fid,)).fetchone()
        conn.close()
        assert row["linked_file_id"] is None


class TestBuildCascade:
    """Tests for build assignment cascading to linked G-code files."""

    def test_assign_model_cascades_to_linked_gcode(self, admin_client):
        """Assigning a model to a build should also assign its linked G-code."""
        data = create_test_request(status="APPROVED", with_builds=2)
        rid = data["request_id"]
        build_id = data["build_ids"][0]

        stl_id = create_test_file(rid, "model.stl")
        gcode_id = create_test_file(rid, "model.gcode", linked_file_id=stl_id)

        resp = admin_client.post(
            f"/admin/request/{rid}/file/{stl_id}/assign-build",
            data={"build_id": build_id},
            follow_redirects=False,
        )
        assert_redirect_to(resp, f"/admin/request/{rid}")

        conn = get_test_db()
        gcode_row = conn.execute("SELECT build_id FROM files WHERE id = ?", (gcode_id,)).fetchone()
        conn.close()
        assert gcode_row["build_id"] == build_id

    def test_unassign_model_cascades_to_linked_gcode(self, admin_client):
        """Unassigning a model from a build should also unassign linked G-code."""
        data = create_test_request(status="APPROVED", with_builds=1)
        rid = data["request_id"]
        build_id = data["build_ids"][0]

        stl_id = create_test_file(rid, "model.stl", build_id=build_id)
        gcode_id = create_test_file(rid, "model.gcode", build_id=build_id, linked_file_id=stl_id)

        resp = admin_client.post(
            f"/admin/request/{rid}/file/{stl_id}/assign-build",
            data={"build_id": ""},
            follow_redirects=False,
        )
        assert_redirect_to(resp, f"/admin/request/{rid}")

        conn = get_test_db()
        gcode_row = conn.execute("SELECT build_id FROM files WHERE id = ?", (gcode_id,)).fetchone()
        conn.close()
        assert gcode_row["build_id"] is None

    def test_link_gcode_inherits_model_build(self, admin_client):
        """Linking a G-code to a model should copy the model's build assignment."""
        data = create_test_request(status="APPROVED", with_builds=1)
        rid = data["request_id"]
        build_id = data["build_ids"][0]

        stl_id = create_test_file(rid, "model.stl", build_id=build_id)
        gcode_id = create_test_file(rid, "output.gcode")

        resp = admin_client.post(
            f"/admin/request/{rid}/file/{gcode_id}/link",
            data={"linked_file_id": stl_id},
            follow_redirects=False,
        )
        assert_redirect_to(resp, f"/admin/request/{rid}")

        conn = get_test_db()
        gcode_row = conn.execute("SELECT build_id FROM files WHERE id = ?", (gcode_id,)).fetchone()
        conn.close()
        assert gcode_row["build_id"] == build_id

    def test_link_gcode_to_unassigned_model_keeps_null(self, admin_client):
        """Linking G-code to a model with no build should not set a build."""
        data = create_test_request(status="APPROVED", with_builds=1)
        rid = data["request_id"]

        stl_id = create_test_file(rid, "model.stl")  # no build
        gcode_id = create_test_file(rid, "output.gcode")

        resp = admin_client.post(
            f"/admin/request/{rid}/file/{gcode_id}/link",
            data={"linked_file_id": stl_id},
            follow_redirects=False,
        )
        assert_redirect_to(resp, f"/admin/request/{rid}")

        conn = get_test_db()
        gcode_row = conn.execute("SELECT build_id FROM files WHERE id = ?", (gcode_id,)).fetchone()
        conn.close()
        assert gcode_row["build_id"] is None
