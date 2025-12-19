"""
Demo Mode - Fake Data Generator for Local Testing

This module provides comprehensive fake data for testing the print queue application.
Enable by setting DEMO_MODE=true environment variable.

Usage:
    from app.demo_data import seed_demo_data, reset_demo_data, DEMO_MODE
    
    if DEMO_MODE:
        seed_demo_data()  # Populate with fake data on startup
"""

import os
import uuid
import random
import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# Demo mode flag - enabled via environment variable
DEMO_MODE = os.getenv("DEMO_MODE", "").lower() in ("true", "1", "yes", "demo")

# ─────────────────────────── DEMO PRINTER STATUS ───────────────────────────

# Fake printer status data - simulates real printers
DEMO_PRINTER_STATUS: Dict[str, Dict[str, Any]] = {
    "ADVENTURER_4": {
        "status": "BUILDING",
        "raw_status": "BUILDING_FROM_SD",
        "temp": "210",
        "target_temp": "210",
        "healthy": True,
        "is_printing": True,
        "progress": 67,
        "current_file": "dragon_figurine.gcode",
        "current_layer": 134,
        "total_layers": 200,
        "camera_url": None,  # Will be populated dynamically
    },
    "AD5X": {
        "status": "READY",
        "raw_status": "READY",
        "temp": "25",
        "target_temp": "0",
        "healthy": True,
        "is_printing": False,
        "progress": None,
        "current_file": None,
        "current_layer": None,
        "total_layers": None,
        "camera_url": None,
    },
}

# Printer job info for demo
DEMO_PRINTER_JOBS: Dict[str, Dict[str, Any]] = {
    "ADVENTURER_4": {
        "status": "printing",
        "machine_status": "BUILDING_FROM_SD",
        "file_name": "dragon_figurine.gcode",
        "progress": 67,
        "layer_info": "Layer 134/200",
        "current_layer": 134,
        "total_layers": 200,
        "temp": "210°C / 210°C",
        "elapsed": "1h 23m",
        "remaining_estimate": "~42 minutes",
        "started_at": None,  # Will be set dynamically
    },
    "AD5X": {
        "status": "idle",
        "machine_status": "READY",
        "file_name": None,
        "progress": None,
        "layer_info": None,
        "current_layer": None,
        "total_layers": None,
        "temp": "25°C / 0°C",
        "elapsed": None,
        "remaining_estimate": None,
        "started_at": None,
    },
}


def get_demo_printer_status(printer_code: str) -> Optional[Dict[str, Any]]:
    """Get demo printer status - returns fake data for UI testing"""
    if not DEMO_MODE:
        return None
    
    status = DEMO_PRINTER_STATUS.get(printer_code)
    if status:
        # Add some randomization to make it feel "live"
        result = status.copy()
        if result.get("is_printing"):
            # Slowly increment progress (simulates printing)
            base_progress = 67
            time_offset = (datetime.utcnow().minute % 10) * 3  # Changes every minute
            result["progress"] = min(99, base_progress + time_offset)
            result["current_layer"] = int(result["total_layers"] * result["progress"] / 100)
        return result
    return None


def get_demo_printer_job(printer_code: str) -> Optional[Dict[str, Any]]:
    """Get demo printer job info"""
    if not DEMO_MODE:
        return None
    
    job = DEMO_PRINTER_JOBS.get(printer_code)
    if job:
        result = job.copy()
        if result.get("status") == "printing":
            # Dynamic timing
            result["started_at"] = (datetime.utcnow() - timedelta(hours=1, minutes=23)).isoformat()
            # Update progress to match status
            base_progress = 67
            time_offset = (datetime.utcnow().minute % 10) * 3
            result["progress"] = min(99, base_progress + time_offset)
            result["current_layer"] = int(200 * result["progress"] / 100)
            result["layer_info"] = f"Layer {result['current_layer']}/200"
        return result
    return None


def get_demo_all_printers_status() -> Dict[str, Dict[str, Any]]:
    """Get status of all demo printers"""
    if not DEMO_MODE:
        return {}
    
    result = {}
    for printer_code in DEMO_PRINTER_STATUS.keys():
        status = get_demo_printer_status(printer_code)
        if status:
            result[printer_code] = status
    return result


# ─────────────────────────── DEMO REQUEST TEMPLATES ───────────────────────────

DEMO_REQUEST_TEMPLATES = [
    {
        "name": "Quick PLA Print",
        "requester_name": "",
        "requester_email": "",
        "printer": "ANY",
        "material": "PLA",
        "colors": "Black",
        "notes": "Standard quality is fine",
    },
    {
        "name": "High Quality Gift",
        "requester_name": "",
        "requester_email": "",
        "printer": "ADVENTURER_4",
        "material": "PLA",
        "colors": "White",
        "notes": "This is a gift - please use highest quality settings",
    },
    {
        "name": "Flexible Part (TPU)",
        "requester_name": "",
        "requester_email": "",
        "printer": "ANY",
        "material": "TPU",
        "colors": "Black",
        "notes": "Needs to be flexible - TPU required",
    },
]


# ─────────────────────────── DEMO EMAIL TOKENS ───────────────────────────

def generate_demo_email_token(email: str) -> Dict[str, Any]:
    """Generate a demo email lookup token"""
    now = datetime.utcnow()
    return {
        "id": str(uuid.uuid4()),
        "email": email,
        "token": secrets.token_urlsafe(32),
        "short_code": f"{random.randint(100000, 999999)}",
        "created_at": now.isoformat(timespec="seconds") + "Z",
        "expires_at": (now + timedelta(days=7)).isoformat(timespec="seconds") + "Z",
    }


# ─────────────────────────── FAKE DATA GENERATORS ───────────────────────────

# Realistic names for demo
DEMO_NAMES = [
    "Alex Johnson", "Sam Williams", "Jordan Taylor", "Casey Brown", "Morgan Davis",
    "Riley Garcia", "Drew Martinez", "Jamie Anderson", "Quinn Thomas", "Avery Wilson",
    "Blake Robinson", "Cameron Clark", "Dakota Lewis", "Emerson Lee", "Finley Walker",
    "Harper Young", "Hayden King", "Kennedy Wright", "Logan Scott", "Parker Green",
]

# Email domains for demo
DEMO_DOMAINS = ["gmail.com", "outlook.com", "yahoo.com", "university.edu", "company.com"]

# Print names for demo requests
DEMO_PRINT_NAMES = [
    "Dragon Figurine", "Phone Stand", "Cable Organizer", "Plant Pot", "Desk Nameplate",
    "Headphone Hook", "Key Holder", "Lamp Shade", "Gear Set", "Chess Pieces",
    "Bookmark", "Pencil Holder", "Coaster Set", "Wall Hook", "Tool Organizer",
    "Miniature Castle", "Robot Arm", "Fidget Cube", "Photo Frame", "Drawer Handle",
    "Soap Dish", "Toothbrush Holder", "Curtain Ring", "Door Stop", "Cable Clip",
]

# Notes templates for variety
DEMO_NOTES_TEMPLATES = [
    "Please print in {color} if possible.",
    "Need this for a class project due next week.",
    "Can you make it as strong as possible? It will hold some weight.",
    "First time requesting a print, let me know if you need any changes!",
    "This is a gift, so quality matters more than speed.",
    "I've printed this before, same settings should work.",
    "",  # Empty notes are common
    "Would prefer matte finish if available.",
    "Scaling to 150% of original size please.",
    "Part of a multi-piece project, more prints coming soon!",
]

DEMO_COLORS = [
    "Black", "White", "Gray", "Red", "Blue", "Green", "Yellow", "Orange",
    "Purple", "Pink", "Gold", "Silver", "Natural", "Transparent"
]

DEMO_ADMIN_NOTES = [
    "", "", "",  # Most have no admin notes
    "Check layer adhesion carefully",
    "Customer is a regular - priority service",
    "Complex geometry, may need supports",
    "Previous print had issues, reprinting",
    "Rush request - see priority",
]

# Store item templates
DEMO_STORE_ITEMS = [
    {
        "name": "Articulated Dragon",
        "description": "A fully articulated dragon that moves! Print-in-place design, no assembly required.",
        "category": "Toys & Games",
        "material": "PLA",
        "colors": "Any",
        "estimated_time_minutes": 180,
    },
    {
        "name": "Phone Stand (Adjustable)",
        "description": "Universal phone stand with adjustable viewing angle. Works with all phone sizes.",
        "category": "Practical",
        "material": "PETG",
        "colors": "Black, White, Gray",
        "estimated_time_minutes": 45,
    },
    {
        "name": "Desk Cable Organizer",
        "description": "Keep your desk tidy with this modular cable management system. Holds 6 cables.",
        "category": "Practical",
        "material": "PLA",
        "colors": "Black, White",
        "estimated_time_minutes": 60,
    },
    {
        "name": "Geometric Planter",
        "description": "Modern geometric design planter for small succulents. Includes drainage hole.",
        "category": "Home & Garden",
        "material": "PLA",
        "colors": "White, Terracotta, Green",
        "estimated_time_minutes": 120,
    },
    {
        "name": "Flexi Rex",
        "description": "Adorable flexible T-Rex toy. Print-in-place articulation.",
        "category": "Toys & Games",
        "material": "TPU",
        "colors": "Any",
        "estimated_time_minutes": 90,
    },
    {
        "name": "Headphone Stand",
        "description": "Minimalist headphone stand for your desk setup. Sturdy two-piece design.",
        "category": "Practical",
        "material": "PLA",
        "colors": "Black, White, Wood PLA",
        "estimated_time_minutes": 150,
    },
    {
        "name": "Lithophane Photo Frame",
        "description": "Custom lithophane photo frame - send us your image! Looks amazing with backlighting.",
        "category": "Gifts",
        "material": "PLA",
        "colors": "White only",
        "estimated_time_minutes": 240,
    },
    {
        "name": "Miniature Chess Set",
        "description": "Complete chess set with board. Great travel size!",
        "category": "Toys & Games",
        "material": "PLA",
        "colors": "Black/White",
        "estimated_time_minutes": 300,
    },
]

# Feedback templates
DEMO_FEEDBACK = [
    {"type": "bug", "message": "The file upload sometimes shows 0% for a long time before jumping to 100%", "status": "new"},
    {"type": "feature", "message": "Would be nice to have email notifications when my print is ready", "status": "resolved"},
    {"type": "bug", "message": "On mobile, the navigation menu is hard to tap", "status": "in_progress"},
    {"type": "feature", "message": "Can you add a dark mode option?", "status": "new"},
    {"type": "general", "message": "Love this service! The dragon print came out amazing!", "status": "resolved"},
]


def generate_email(name: str) -> str:
    """Generate a realistic email from a name"""
    parts = name.lower().split()
    domain = random.choice(DEMO_DOMAINS)
    formats = [
        f"{parts[0]}.{parts[-1]}@{domain}",
        f"{parts[0]}{parts[-1][0]}@{domain}",
        f"{parts[0]}_{parts[-1]}@{domain}",
        f"{parts[0]}{random.randint(1, 99)}@{domain}",
    ]
    return random.choice(formats)


def generate_demo_request(
    created_days_ago: int,
    status: str,
    printer: str = "ANY",
    material: str = "PLA",
    with_builds: bool = False,
    num_builds: int = 1
) -> Dict[str, Any]:
    """Generate a single demo request with realistic data"""
    
    name = random.choice(DEMO_NAMES)
    email = generate_email(name)
    colors = random.choice(DEMO_COLORS)
    print_name = random.choice(DEMO_PRINT_NAMES)
    notes = random.choice(DEMO_NOTES_TEMPLATES).format(color=colors.lower())
    
    created_at = datetime.utcnow() - timedelta(days=created_days_ago, hours=random.randint(0, 23))
    updated_at = created_at + timedelta(hours=random.randint(1, 48))
    
    # Ensure updated_at doesn't exceed now
    if updated_at > datetime.utcnow():
        updated_at = datetime.utcnow()
    
    request_id = str(uuid.uuid4())
    access_token = secrets.token_urlsafe(32)
    
    request = {
        "id": request_id,
        "created_at": created_at.isoformat(timespec="seconds") + "Z",
        "updated_at": updated_at.isoformat(timespec="seconds") + "Z",
        "requester_name": name,
        "requester_email": email,
        "printer": printer,
        "material": material,
        "colors": colors,
        "link_url": "",
        "notes": notes,
        "status": status,
        "priority": random.choice([1, 2, 3, 3, 3, 4, 5]),  # Weighted toward normal priority
        "admin_notes": random.choice(DEMO_ADMIN_NOTES),
        "print_name": print_name if status not in ["NEW", "NEEDS_INFO"] else "",
        "access_token": access_token,
        "total_builds": num_builds,
        "completed_builds": 0,
        "failed_builds": 0,
    }
    
    # Add timing info for printing/done requests
    if status in ["PRINTING", "IN_PROGRESS"]:
        printing_started = updated_at - timedelta(minutes=random.randint(10, 120))
        request["printing_started_at"] = printing_started.isoformat(timespec="seconds") + "Z"
        request["print_time_minutes"] = random.choice([30, 45, 60, 90, 120, 180, 240])
        request["slicer_estimate_minutes"] = request["print_time_minutes"]
    
    if status in ["DONE", "PICKED_UP"]:
        request["print_time_minutes"] = random.choice([30, 45, 60, 90, 120, 180])
        request["completed_builds"] = num_builds
    
    return request


def generate_demo_build(
    request_id: str,
    build_number: int,
    status: str,
    printer: Optional[str] = None
) -> Dict[str, Any]:
    """Generate a build record for multi-build requests"""
    
    now = datetime.utcnow()
    created_at = now - timedelta(days=random.randint(0, 7))
    
    build = {
        "id": str(uuid.uuid4()),
        "request_id": request_id,
        "build_number": build_number,
        "status": status,
        "printer": printer or random.choice(["ADVENTURER_4", "AD5X"]),
        "material": random.choice(["PLA", "PETG"]),
        "print_name": f"Part {build_number}",
        "print_time_minutes": random.randint(30, 180),
        "created_at": created_at.isoformat(timespec="seconds") + "Z",
        "updated_at": now.isoformat(timespec="seconds") + "Z",
    }
    
    if status == "PRINTING":
        build["started_at"] = (now - timedelta(minutes=random.randint(10, 60))).isoformat(timespec="seconds") + "Z"
        build["progress"] = random.randint(10, 90)
        build["total_layers"] = random.randint(100, 500)
    
    if status == "COMPLETED":
        build["started_at"] = (now - timedelta(hours=2)).isoformat(timespec="seconds") + "Z"
        build["completed_at"] = (now - timedelta(minutes=random.randint(5, 30))).isoformat(timespec="seconds") + "Z"
        build["progress"] = 100
    
    return build


def generate_demo_file(request_id: str, build_id: Optional[str] = None) -> Dict[str, Any]:
    """Generate a fake file record"""
    
    extensions = [".stl", ".3mf", ".gcode", ".obj"]
    filenames = [
        "model", "part1", "print", "design", "project", "custom_piece",
        "dragon", "phone_stand", "bracket", "holder", "case", "mount"
    ]
    
    filename = f"{random.choice(filenames)}{random.choice(extensions)}"
    
    return {
        "id": str(uuid.uuid4()),
        "request_id": request_id,
        "build_id": build_id,
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "original_filename": filename,
        "stored_filename": f"{uuid.uuid4()}_{filename}",
        "size_bytes": random.randint(10000, 50000000),
        "sha256": secrets.token_hex(32),
    }


def generate_status_event(
    request_id: str,
    from_status: Optional[str],
    to_status: str,
    created_at: datetime
) -> Dict[str, Any]:
    """Generate a status change event"""
    
    comments = {
        "NEW": None,
        "NEEDS_INFO": "Please provide more details about the dimensions needed.",
        "APPROVED": "Looks good! Adding to queue.",
        "IN_PROGRESS": None,
        "PRINTING": "Started printing on Adventurer 4",
        "DONE": "Print complete! Ready for pickup.",
        "PICKED_UP": None,
        "REJECTED": "Sorry, this design isn't printable without modifications.",
        "CANCELLED": "Cancelled per requester",
    }
    
    return {
        "id": str(uuid.uuid4()),
        "request_id": request_id,
        "created_at": created_at.isoformat(timespec="seconds") + "Z",
        "from_status": from_status,
        "to_status": to_status,
        "comment": comments.get(to_status, ""),
    }


def generate_print_history_entry(printer: str, material: str) -> Dict[str, Any]:
    """Generate a print history entry for ETA learning"""
    
    started = datetime.utcnow() - timedelta(days=random.randint(1, 30))
    duration = random.randint(20, 300)
    
    return {
        "id": str(uuid.uuid4()),
        "request_id": str(uuid.uuid4()),
        "printer": printer,
        "material": material,
        "print_name": random.choice(DEMO_PRINT_NAMES),
        "started_at": started.isoformat(timespec="seconds") + "Z",
        "completed_at": (started + timedelta(minutes=duration)).isoformat(timespec="seconds") + "Z",
        "duration_minutes": duration,
        "estimated_minutes": duration + random.randint(-20, 20),
        "total_layers": random.randint(100, 800),
        "file_name": f"demo_print_{random.randint(1, 100)}.gcode",
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }


# ─────────────────────────── DATABASE SEEDING ───────────────────────────

def seed_demo_data(db_func, force: bool = False):
    """
    Seed the database with demo data.
    
    Args:
        db_func: Function that returns a database connection (from main.py)
        force: If True, reset and reseed even if data exists
    """
    if not DEMO_MODE and not force:
        return
    
    conn = db_func()
    cur = conn.cursor()
    
    # Check if already seeded (look for demo marker in settings)
    existing = cur.execute("SELECT value FROM settings WHERE key = 'demo_seeded'").fetchone()
    if existing and not force:
        print("[DEMO] Database already seeded, skipping...")
        conn.close()
        return
    
    print("[DEMO] Seeding database with demo data...")
    
    now = datetime.utcnow()
    now_iso = now.isoformat(timespec="seconds") + "Z"
    
    # ── Seed Requests ──
    demo_requests = [
        # New requests (waiting for review)
        generate_demo_request(0, "NEW", "ANY", "PLA"),
        generate_demo_request(1, "NEW", "ADVENTURER_4", "PETG"),
        generate_demo_request(0, "NEW", "ANY", "ABS"),
        
        # Needs info
        generate_demo_request(2, "NEEDS_INFO", "ANY", "PLA"),
        
        # Approved (in queue)
        generate_demo_request(3, "APPROVED", "AD5X", "PLA"),
        generate_demo_request(2, "APPROVED", "ANY", "PETG"),
        generate_demo_request(4, "APPROVED", "ADVENTURER_4", "PLA"),
        
        # Currently printing
        generate_demo_request(1, "PRINTING", "ADVENTURER_4", "PLA"),
        generate_demo_request(2, "PRINTING", "AD5X", "PETG"),
        
        # Recently completed
        generate_demo_request(5, "DONE", "ADVENTURER_4", "PLA"),
        generate_demo_request(4, "DONE", "AD5X", "PLA"),
        generate_demo_request(6, "DONE", "ADVENTURER_4", "PETG"),
        
        # Picked up
        generate_demo_request(7, "PICKED_UP", "AD5X", "PLA"),
        generate_demo_request(10, "PICKED_UP", "ADVENTURER_4", "PLA"),
        
        # Multi-build request example
        generate_demo_request(3, "IN_PROGRESS", "ANY", "PLA", with_builds=True, num_builds=4),
    ]
    
    for req in demo_requests:
        try:
            cur.execute("""
                INSERT INTO requests (
                    id, created_at, updated_at, requester_name, requester_email,
                    printer, material, colors, link_url, notes, status,
                    priority, admin_notes, print_name, access_token,
                    total_builds, completed_builds, failed_builds,
                    print_time_minutes, slicer_estimate_minutes, printing_started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                req["id"], req["created_at"], req["updated_at"],
                req["requester_name"], req["requester_email"],
                req["printer"], req["material"], req["colors"],
                req.get("link_url", ""), req.get("notes", ""), req["status"],
                req.get("priority", 3), req.get("admin_notes", ""),
                req.get("print_name", ""), req["access_token"],
                req.get("total_builds", 1), req.get("completed_builds", 0), req.get("failed_builds", 0),
                req.get("print_time_minutes"), req.get("slicer_estimate_minutes"),
                req.get("printing_started_at")
            ))
            
            # Add a demo file for each request
            demo_file = generate_demo_file(req["id"])
            cur.execute("""
                INSERT INTO files (id, request_id, created_at, original_filename, stored_filename, size_bytes, sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                demo_file["id"], demo_file["request_id"], demo_file["created_at"],
                demo_file["original_filename"], demo_file["stored_filename"],
                demo_file["size_bytes"], demo_file["sha256"]
            ))
            
            # Add status history
            status_event = generate_status_event(req["id"], None, "NEW", datetime.fromisoformat(req["created_at"].replace("Z", "+00:00")))
            cur.execute("""
                INSERT INTO status_events (id, request_id, created_at, from_status, to_status, comment)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                status_event["id"], status_event["request_id"], status_event["created_at"],
                status_event["from_status"], status_event["to_status"], status_event["comment"]
            ))
            
        except Exception as e:
            print(f"[DEMO] Error inserting request: {e}")
    
    # ── Seed Builds for multi-build request ──
    multi_build_request = next((r for r in demo_requests if r.get("total_builds", 1) > 1), None)
    if multi_build_request:
        build_statuses = ["COMPLETED", "COMPLETED", "PRINTING", "PENDING"]
        for i, status in enumerate(build_statuses, 1):
            build = generate_demo_build(multi_build_request["id"], i, status)
            try:
                cur.execute("""
                    INSERT INTO builds (
                        id, request_id, build_number, status, printer, material,
                        print_name, print_time_minutes, started_at, completed_at, progress,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    build["id"], build["request_id"], build["build_number"], build["status"],
                    build.get("printer"), build.get("material"), build.get("print_name"),
                    build.get("print_time_minutes"), build.get("started_at"), build.get("completed_at"),
                    build.get("progress"), build["created_at"], build["updated_at"]
                ))
            except Exception as e:
                print(f"[DEMO] Error inserting build: {e}")
    
    # ── Seed Store Items ──
    for item in DEMO_STORE_ITEMS:
        try:
            item_id = str(uuid.uuid4())
            cur.execute("""
                INSERT INTO store_items (
                    id, name, description, category, material, colors,
                    estimated_time_minutes, is_active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """, (
                item_id, item["name"], item["description"], item["category"],
                item["material"], item["colors"], item["estimated_time_minutes"],
                now_iso, now_iso
            ))
        except Exception as e:
            print(f"[DEMO] Error inserting store item: {e}")
    
    # ── Seed Print History (for ETA learning) ──
    for _ in range(20):
        printer = random.choice(["ADVENTURER_4", "AD5X"])
        material = random.choice(["PLA", "PETG", "ABS"])
        entry = generate_print_history_entry(printer, material)
        try:
            cur.execute("""
                INSERT INTO print_history (
                    id, request_id, printer, material, print_name,
                    started_at, completed_at, duration_minutes, estimated_minutes,
                    total_layers, file_name, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry["id"], entry["request_id"], entry["printer"], entry["material"],
                entry["print_name"], entry["started_at"], entry["completed_at"],
                entry["duration_minutes"], entry["estimated_minutes"],
                entry["total_layers"], entry["file_name"], entry["created_at"]
            ))
        except Exception as e:
            print(f"[DEMO] Error inserting print history: {e}")
    
    # ── Seed Feedback ──
    for fb in DEMO_FEEDBACK:
        try:
            name = random.choice(DEMO_NAMES)
            cur.execute("""
                INSERT INTO feedback (id, type, name, email, message, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()), fb["type"], name, generate_email(name),
                fb["message"], fb["status"], now_iso
            ))
        except Exception as e:
            print(f"[DEMO] Error inserting feedback: {e}")
    
    # ── Seed Request Templates ──
    for tmpl in DEMO_REQUEST_TEMPLATES:
        try:
            cur.execute("""
                INSERT INTO request_templates (
                    id, name, requester_name, requester_email, printer, material, colors, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()), tmpl["name"], tmpl.get("requester_name", ""),
                tmpl.get("requester_email", ""), tmpl.get("printer", "ANY"),
                tmpl.get("material", "PLA"), tmpl.get("colors", ""),
                tmpl.get("notes", ""), now_iso, now_iso
            ))
        except Exception as e:
            print(f"[DEMO] Error inserting template: {e}")
    
    # ── Seed Email Lookup Tokens (for demo "My Requests" access) ──
    # Create tokens for a few demo emails so users can test the my-requests flow
    demo_emails = list(set(req["requester_email"] for req in demo_requests[:5]))
    for email in demo_emails:
        try:
            token_data = generate_demo_email_token(email)
            cur.execute("""
                INSERT INTO email_lookup_tokens (id, email, token, short_code, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                token_data["id"], token_data["email"], token_data["token"],
                token_data["short_code"], token_data["created_at"], token_data["expires_at"]
            ))
        except Exception as e:
            print(f"[DEMO] Error inserting email token: {e}")
    
    # ── Seed Demo Users ──
    # Create sample user accounts for testing the user management features
    demo_users = [
        {
            "id": str(uuid.uuid4()),
            "email": "demo.user@example.com",
            "name": "Demo User",
            "status": "active",
            "email_verified": 1,
            "total_requests": 12,
            "total_prints": 8,
            "credits": 25,
        },
        {
            "id": str(uuid.uuid4()),
            "email": "new.user@example.com", 
            "name": "New User",
            "status": "unverified",
            "email_verified": 0,
            "total_requests": 0,
            "total_prints": 0,
            "credits": 0,
        },
        {
            "id": str(uuid.uuid4()),
            "email": "frequent.printer@university.edu",
            "name": "Alex Chen",
            "status": "active",
            "email_verified": 1,
            "total_requests": 45,
            "total_prints": 42,
            "credits": 100,
        },
        {
            "id": str(uuid.uuid4()),
            "email": "suspended.user@example.com",
            "name": "Suspended User",
            "status": "suspended",
            "email_verified": 1,
            "total_requests": 3,
            "total_prints": 1,
            "credits": 0,
        },
        {
            "id": str(uuid.uuid4()),
            "email": "regular.customer@gmail.com",
            "name": "Jordan Smith",
            "status": "active",
            "email_verified": 1,
            "total_requests": 8,
            "total_prints": 7,
            "credits": 15,
        },
    ]
    
    # Link some demo users to demo request emails
    # This allows testing the migration flow
    for req in demo_requests[:3]:
        demo_users.append({
            "id": str(uuid.uuid4()),
            "email": req["requester_email"],
            "name": req["requester_name"],
            "status": "active",
            "email_verified": 1,
            "total_requests": random.randint(1, 5),
            "total_prints": random.randint(0, 3),
            "credits": random.randint(0, 20),
        })
    
    user_count = 0
    for user in demo_users:
        try:
            created = (now - timedelta(days=random.randint(1, 90))).isoformat(timespec="seconds") + "Z"
            cur.execute("""
                INSERT INTO users (
                    id, email, name, status, email_verified, 
                    total_requests, total_prints, credits,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user["id"], user["email"], user["name"], user["status"],
                user["email_verified"], user["total_requests"], user["total_prints"],
                user["credits"], created, now_iso
            ))
            user_count += 1
        except Exception as e:
            # Skip if user already exists (e.g., duplicate email)
            if "UNIQUE constraint" not in str(e):
                print(f"[DEMO] Error inserting user: {e}")
    
    # ── Seed Request Messages (for two-way communication demo) ──
    # Add some demo messages to the NEEDS_INFO request
    needs_info_req = next((r for r in demo_requests if r["status"] == "NEEDS_INFO"), None)
    if needs_info_req:
        demo_messages = [
            {"sender_type": "admin", "message": "Could you clarify what size you need? The model can be scaled."},
            {"sender_type": "requester", "message": "I need it to be about 10cm tall. Is that possible?"},
            {"sender_type": "admin", "message": "Absolutely! I'll scale it to 10cm. Expect about 2 hours print time."},
        ]
        msg_time = datetime.fromisoformat(needs_info_req["created_at"].replace("Z", "+00:00"))
        for i, msg in enumerate(demo_messages):
            msg_time = msg_time + timedelta(hours=i+1)
            try:
                cur.execute("""
                    INSERT INTO request_messages (id, request_id, created_at, sender_type, message, is_read)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()), needs_info_req["id"],
                    msg_time.isoformat(timespec="seconds") + "Z",
                    msg["sender_type"], msg["message"],
                    1 if msg["sender_type"] == "admin" else 0
                ))
            except Exception as e:
                print(f"[DEMO] Error inserting message: {e}")
    
    # ── Mark as seeded ──
    try:
        cur.execute("""
            INSERT OR REPLACE INTO settings (key, value, updated_at)
            VALUES ('demo_seeded', 'true', ?)
        """, (now_iso,))
    except:
        pass
    
    conn.commit()
    conn.close()
    
    print(f"[DEMO] ✓ Seeded {len(demo_requests)} requests, {len(DEMO_STORE_ITEMS)} store items, {len(DEMO_REQUEST_TEMPLATES)} templates, {user_count} users, 20 print history entries")


def reset_demo_data(db_func):
    """
    Clear all data and reseed with fresh demo data.
    Only works in DEMO_MODE.
    """
    if not DEMO_MODE:
        print("[DEMO] Reset only available in DEMO_MODE")
        return False
    
    conn = db_func()
    cur = conn.cursor()
    
    print("[DEMO] Clearing all data...")
    
    # Clear all tables (order matters for foreign keys)
    tables = [
        "build_snapshots", "build_status_events", "builds",
        "status_events", "files", "request_messages", "push_subscriptions",
        "email_lookup_tokens", "store_item_files", "store_items",
        "print_history", "request_templates", "feedback", "requests", 
        "user_sessions", "users", "settings"
    ]
    
    for table in tables:
        try:
            cur.execute(f"DELETE FROM {table}")
        except Exception as e:
            print(f"[DEMO] Could not clear {table}: {e}")
    
    conn.commit()
    conn.close()
    
    # Reseed
    seed_demo_data(db_func, force=True)
    
    return True


def get_demo_status() -> Dict[str, Any]:
    """Return demo mode status information"""
    return {
        "demo_mode": DEMO_MODE,
        "message": "Demo mode is active. Data will reset on restart." if DEMO_MODE else "Demo mode is disabled.",
        "features": [
            "Fake requests in various statuses",
            "Pre-populated store items",
            "Print history for ETA learning",
            "Sample feedback entries",
        ] if DEMO_MODE else []
    }
