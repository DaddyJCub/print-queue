# Local Development Script for Print Queue App
# Run this script from the print-queue directory

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Print Queue - Local Development" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.10+ from https://python.org" -ForegroundColor Yellow
    exit 1
}

# Show Python version
Write-Host "Using Python: " -NoNewline
python --version

# Check if virtual environment exists
$venvPath = ".\venv"
if (-not (Test-Path $venvPath)) {
    Write-Host ""
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# Install/update dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet

# Create local data directories
$dataDir = ".\local_data"
$uploadsDir = ".\local_uploads"

if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir | Out-Null
    Write-Host "Created: $dataDir" -ForegroundColor Green
}

if (-not (Test-Path $uploadsDir)) {
    New-Item -ItemType Directory -Path $uploadsDir | Out-Null
    Write-Host "Created: $uploadsDir" -ForegroundColor Green
}

# Set environment variables for local development
$env:DB_PATH = "$PWD\local_data\app.db"
$env:UPLOAD_DIR = "$PWD\local_uploads"
$env:BASE_URL = "http://localhost:3000"
$env:ADMIN_PASSWORD = "admin"  # Simple password for local testing

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Environment Configuration:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DB_PATH:      $env:DB_PATH" -ForegroundColor Gray
Write-Host "  UPLOAD_DIR:   $env:UPLOAD_DIR" -ForegroundColor Gray
Write-Host "  BASE_URL:     $env:BASE_URL" -ForegroundColor Gray
Write-Host "  ADMIN_PASSWORD: admin" -ForegroundColor Gray
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Starting server at:" -ForegroundColor Green
Write-Host "  http://localhost:3000" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Run the app with auto-reload for development
uvicorn app.main:app --host 127.0.0.1 --port 3000 --reload
