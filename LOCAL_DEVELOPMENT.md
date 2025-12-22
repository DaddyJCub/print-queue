# Local Development & Demo Mode Guide

This guide explains how to run the Print Queue app locally for testing and development.

## Quick Start

### Normal Mode (empty database)
```powershell
.\run_local.ps1
```

### Demo Mode (pre-populated with fake data)
```powershell
.\run_local.ps1 -Demo
```

Or using Command Prompt:
```cmd
run_local.bat demo
```

## What You Get

### Normal Mode
- Empty database at `local_data/app.db`
- Fresh start for manual testing
- Good for testing new features from scratch

### Demo Mode
- Separate database at `local_data/demo.db`
- **No real printer polling** - fake printer data is used
- Pre-populated with:
  - **15+ requests** in various statuses (NEW, APPROVED, PRINTING, DONE, etc.)
  - **8 store items** (ready-to-print designs)
  - **20 print history entries** (for ETA learning)
  - **5 feedback entries** (bug reports, suggestions)
  - **3 request templates** (for quick form filling)
  - **Demo messages** (two-way communication example)
  - **Multi-build request** example
  - Realistic names, emails, and notes
- **Simulated printers:**
  - ADVENTURER_4: Actively "printing" at ~67% progress
  - AD5X: Idle/ready status

## URLs & Access

| URL | Description |
|-----|-------------|
| http://localhost:3000 | Main site |
| http://localhost:3000/admin | Admin dashboard |
| http://localhost:3000/admin/store | Store management |
| http://localhost:3000/store | Public store |

**Admin Password:** `admin` (for local development only)

## Manual Startup (Alternative)

If the PowerShell script doesn't work due to execution policy restrictions, you can start the server manually:

```powershell
cd "E:\Github\Print Request\print-queue"
$env:DB_PATH = "$PWD\local_data\demo.db"
$env:UPLOAD_DIR = "$PWD\local_uploads"
$env:BASE_URL = "http://localhost:3000"
$env:ADMIN_PASSWORD = "admin"
$env:DEMO_MODE = "true"
& ".\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 3000
```

For normal mode (non-demo), omit `DEMO_MODE` and use `app.db`:
```powershell
$env:DB_PATH = "$PWD\local_data\app.db"
# Remove or unset: $env:DEMO_MODE
```

## Demo Mode API

### Check Demo Status
```bash
GET /api/demo/status
```
Returns whether demo mode is active.

### Reset Demo Data
```bash
POST /api/demo/reset
```
Requires admin authentication. Clears all data and reseeds with fresh demo data.

Example with curl:
```bash
curl -X POST http://localhost:3000/api/demo/reset -H "Cookie: admin_pw=admin"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMO_MODE` | `false` | Enable demo mode (`true`, `1`, `yes`, or `demo`) |
| `DB_PATH` | `/data/app.db` | SQLite database path |
| `UPLOAD_DIR` | `/uploads` | File upload directory |
| `BASE_URL` | `http://localhost:3000` | Base URL for links |
| `ADMIN_PASSWORD` | (required) | Admin dashboard password |

## Adding Demo Data for New Features

When adding new features, update `app/demo_data.py` to include sample data:

### 1. Add to Generators
If your feature uses new data structures, add generator functions:

```python
def generate_my_new_thing() -> Dict[str, Any]:
    """Generate a demo instance of MyNewThing"""
    return {
        "id": str(uuid.uuid4()),
        "name": random.choice(["Example 1", "Example 2"]),
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        # ... more fields
    }
```

### 2. Add to Seed Function
Insert demo data in `seed_demo_data()`:

```python
# ── Seed MyNewThings ──
for i in range(5):
    thing = generate_my_new_thing()
    try:
        cur.execute("""
            INSERT INTO my_new_things (id, name, created_at)
            VALUES (?, ?, ?)
        """, (thing["id"], thing["name"], thing["created_at"]))
    except Exception as e:
        print(f"[DEMO] Error inserting my_new_thing: {e}")
```

### 3. Add to Reset Function
Add the table to the clear list in `reset_demo_data()`:

```python
tables = [
    # ... existing tables ...
    "my_new_things",  # Add your new table
]
```

### 4. Add Sample Templates
If your feature has common patterns, add them to the templates:

```python
DEMO_MY_THINGS = [
    {"name": "Common Example", "type": "standard"},
    {"name": "Edge Case", "type": "special"},
]
```

## Testing Checklist

When testing new features locally:

- [ ] Works in normal mode (empty DB)
- [ ] Works in demo mode (pre-populated)
- [ ] Demo data covers main use cases
- [ ] Demo data includes edge cases
- [ ] Reset endpoint properly clears new data
- [ ] No hardcoded production values

## Troubleshooting

### Server won't start
- Check Python is installed: `python --version`
- Ensure `.venv` exists or let the script create it
- Check port 3000 isn't in use

### Demo data not showing
- Ensure `DEMO_MODE=true` is set
- Check for errors in terminal output
- Try resetting: `POST /api/demo/reset`

### Printer errors in logs
- Expected locally - printers aren't accessible from your network
- These warnings can be safely ignored for UI testing

## File Structure

```
print-queue/
├── run_local.ps1        # PowerShell start script
├── run_local.bat        # CMD start script
├── .env.local           # Example environment config
├── local_data/          # Local databases (gitignored)
│   ├── app.db          # Normal mode database
│   └── demo.db         # Demo mode database
├── local_uploads/       # Local file uploads (gitignored)
└── app/
    ├── main.py          # Main application
    └── demo_data.py     # Demo data generators
```
