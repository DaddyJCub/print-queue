"""
Mock Moonraker Server for Local Development

A lightweight FastAPI server that mimics the Moonraker API endpoints used
by the print-queue app's send-to-printer feature. Runs on port 7125
(Moonraker's default port).

Usage:
    uvicorn scripts.dev.mock_moonraker:app --host 127.0.0.1 --port 7125

Endpoints mocked:
    POST /server/files/upload       - Accept G-code uploads
    GET  /server/files/metadata     - Return fake metadata (multi-color aware)
    POST /printer/gcode/script      - Accept PRINT_ZCOLOR and other gcode
    POST /printer/print/start       - Accept print start
    GET  /printer/objects/query      - Return idle printer status
    GET  /printer/info              - Return printer info
    GET  /server/files/list         - List uploaded files
"""

import os
import json
import time
from datetime import datetime

from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import JSONResponse

app = FastAPI(title="Mock Moonraker", version="0.1.0")

# In-memory store for uploaded files
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
UPLOAD_DIR = os.path.join(ROOT_DIR, "mock_gcodes")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Track uploaded files and their metadata
uploaded_files: dict = {}
gcode_log: list = []


def make_metadata(filename: str, file_size: int = 0) -> dict:
    """Generate fake metadata for an uploaded file.
    
    Files with 'multi' or 'ams' in the name get multi-color metadata.
    Files with 'honeycomb' in the name get the same metadata as the real test file.
    """
    base = {
        "filename": filename,
        "size": file_size,
        "modified": time.time(),
        "slicer": "OrcaSlicer",
        "slicer_version": "2.2.0",
        "estimated_time": 6200,
        "filament_total": 12500.0,
        "filament_weight_total": 37.5,
        "thumbnails": [
            {
                "width": 32,
                "height": 32,
                "size": 1024,
                "relative_path": f".thumbs/{filename}-32x32.png",
            },
            {
                "width": 300,
                "height": 300,
                "size": 24000,
                "relative_path": f".thumbs/{filename}-300x300.png",
            },
        ],
    }
    
    name_lower = filename.lower()
    
    # Multi-color detection: files with these keywords get multi-tool metadata
    if any(kw in name_lower for kw in ("multi", "ams", "honeycomb", "4color", "multicolor")):
        base.update({
            "filament_type": "PLA",
            "filament_name": "Bambu PLA Basic;Bambu PLA Basic;Bambu PLA Basic;Bambu PLA Basic",
            "filament_colors": ["#161616", "#F72224", "#FFFFFF", "#FFFFFF"],
            "referenced_tools": [0, 1, 2, 3],
            "filament_change_count": 47,
            "filament_total": 28000.0,
            "filament_weight_total": 84.0,
        })
        print(f"  📋 Metadata: MULTI-COLOR (4 tools, 47 changes)")
    else:
        base.update({
            "filament_type": "PLA",
            "filament_name": "Bambu PLA Basic",
            "filament_colors": ["#161616"],
            "referenced_tools": [0],
            "filament_change_count": 0,
        })
        print(f"  📋 Metadata: SINGLE-COLOR (1 tool)")
    
    return base


# ── File Upload ──────────────────────────────────────────────────────────

@app.post("/server/files/upload")
async def upload_file(request: Request):
    """Accept G-code file uploads (multipart form)."""
    form = await request.form()
    
    file_field = form.get("file")
    print_flag = form.get("print", "false")
    
    if not isinstance(file_field, UploadFile):
        return JSONResponse({"error": "No file provided"}, status_code=400)
    
    filename = file_field.filename or "upload.gcode"
    content = await file_field.read()
    file_size = len(content)
    
    # Save to mock directory
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(content)
    
    # Generate and store metadata
    metadata = make_metadata(filename, file_size)
    uploaded_files[filename] = metadata
    
    print(f"📥 UPLOAD: {filename} ({file_size:,} bytes) print={print_flag}")
    
    if str(print_flag).lower() == "true":
        print(f"  ⚠️  print=true requested — ZMOD would intercept this with action:prompt dialog")
    
    return JSONResponse(
        {"item": {"path": filename, "root": "gcodes"}, "action": {"action": "create_file"}},
        status_code=201,
    )


# ── File Metadata ────────────────────────────────────────────────────────

@app.get("/server/files/metadata")
async def get_metadata(filename: str = ""):
    """Return file metadata (slicer info, colors, tools)."""
    if not filename:
        return JSONResponse({"error": "filename required"}, status_code=400)
    
    # Use stored metadata if file was uploaded, otherwise generate fresh
    if filename in uploaded_files:
        meta = uploaded_files[filename]
    else:
        meta = make_metadata(filename, 0)
    
    print(f"📋 METADATA: {filename} → {len(meta.get('referenced_tools', []))} tools, colors={meta.get('filament_colors', [])}")
    return JSONResponse({"result": meta})


# ── G-code Execution ─────────────────────────────────────────────────────

@app.post("/printer/gcode/script")
async def run_gcode(request: Request):
    """Accept G-code commands (including PRINT_ZCOLOR from our app)."""
    body = await request.json()
    script = body.get("script", "")
    
    gcode_log.append({"script": script, "time": datetime.now().isoformat()})
    
    if "PRINT_ZCOLOR" in script:
        print(f"🎯 PRINT_ZCOLOR received: {script}")
        print(f"   ✅ This bypasses ZMOD's interactive material prompt!")
        # Parse the command for display
        parts = script.split()
        params = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = v.strip('"')
        if params:
            print(f"   📄 File: {params.get('FILENAME', '?')}")
            print(f"   🔧 Leveling: {'ON' if params.get('LEVELING') == '1' else 'OFF'}")
            for t in ['T0', 'T1', 'T2', 'T3']:
                if t in params:
                    print(f"   🎨 {t} → AMS slot {params[t]}")
    else:
        print(f"⚙️  GCODE: {script}")
    
    return JSONResponse({"result": "ok"})


# ── Print Control ────────────────────────────────────────────────────────

@app.post("/printer/print/start")
async def start_print(request: Request):
    """Accept print start (fallback when PRINT_ZCOLOR fails)."""
    body = await request.json()
    filename = body.get("filename", "?")
    print(f"▶️  START_PRINT: {filename}")
    print(f"   ⚠️  Note: ZMOD would intercept this with its material prompt")
    return JSONResponse({"result": "ok"})


# ── Printer Status ───────────────────────────────────────────────────────

@app.get("/printer/objects/query")
async def query_objects():
    """Return idle printer status (objects query)."""
    return JSONResponse({
        "result": {
            "status": {
                "print_stats": {
                    "state": "standby",
                    "filename": "",
                    "total_duration": 0,
                    "print_duration": 0,
                    "filament_used": 0,
                    "message": "",
                    "info": {"total_layer": None, "current_layer": None},
                },
                "virtual_sdcard": {
                    "progress": 0,
                    "is_active": False,
                    "file_position": 0,
                },
                "extruder": {
                    "temperature": 24.8,
                    "target": 0,
                    "power": 0,
                },
                "heater_bed": {
                    "temperature": 23.5,
                    "target": 0,
                    "power": 0,
                },
                "toolhead": {
                    "position": [0, 0, 0, 0],
                    "homed_axes": "",
                },
                "display_status": {
                    "progress": 0,
                    "message": "",
                },
                "gcode_move": {
                    "speed_factor": 1.0,
                    "extrude_factor": 1.0,
                },
            }
        }
    })


@app.get("/printer/info")
async def printer_info():
    """Return printer info."""
    return JSONResponse({
        "result": {
            "hostname": "mock-ad5x",
            "software_version": "v0.12.0-300-mock",
            "cpu_info": "Mock Klipper on localhost",
            "state": "ready",
            "state_message": "Printer is ready (mock)",
        }
    })


# ── File Listing ─────────────────────────────────────────────────────────

@app.get("/server/files/list")
async def list_files(root: str = "gcodes"):
    """List uploaded files."""
    files = []
    for fname, meta in uploaded_files.items():
        files.append({
            "path": fname,
            "modified": meta.get("modified", time.time()),
            "size": meta.get("size", 0),
        })
    return JSONResponse({"result": files})


# ── Debug Endpoints ──────────────────────────────────────────────────────

@app.get("/mock/status")
async def mock_status():
    """Debug: show mock server state."""
    return JSONResponse({
        "uploaded_files": list(uploaded_files.keys()),
        "gcode_log": gcode_log[-20:],
        "upload_dir": UPLOAD_DIR,
    })


@app.get("/mock/log")
async def mock_log():
    """Debug: show gcode command log."""
    return JSONResponse({"commands": gcode_log})


# ── Startup Banner ───────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    print("=" * 60)
    print("  🌙 Mock Moonraker Server")
    print("  Simulates Moonraker API for local development")
    print("=" * 60)
    print()
    print("  Endpoints:")
    print("    POST /server/files/upload      — Accept G-code uploads")
    print("    GET  /server/files/metadata     — Return file metadata")
    print("    POST /printer/gcode/script      — Accept PRINT_ZCOLOR etc.")
    print("    POST /printer/print/start       — Start print (fallback)")
    print("    GET  /printer/objects/query      — Printer status")
    print("    GET  /printer/info              — Printer info")
    print()
    print("  Debug:")
    print("    GET  /mock/status               — Show uploaded files")
    print("    GET  /mock/log                  — Show gcode command log")
    print()
    print("  To test multi-color detection, upload a file with")
    print("  'multi', 'ams', or 'honeycomb' in the filename.")
    print()
    print("  Configure in Printellect:")
    print("    1. Admin → Features → Enable 'Moonraker AD5X'")
    print("    2. Admin → Settings → Set Moonraker URL to:")
    print("       http://localhost:7125")
    print("=" * 60)
