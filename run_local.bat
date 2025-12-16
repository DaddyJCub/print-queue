@echo off
REM Local Development Script for Print Queue App
REM Run this from the print-queue directory
REM
REM Usage:
REM   run_local.bat          - Normal mode
REM   run_local.bat demo     - Demo mode with fake data

set DEMO_FLAG=%1

echo ========================================
echo   Print Queue - Local Development
if /i "%DEMO_FLAG%"=="demo" echo   [DEMO MODE ENABLED]
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

echo Using Python:
python --version

REM Check if virtual environment exists
if not exist ".venv" (
    echo.
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat

REM Install/update dependencies
echo Installing dependencies...
pip install -r requirements.txt --quiet

REM Create local data directories
if not exist "local_data" (
    mkdir local_data
    echo Created: local_data
)

if not exist "local_uploads" (
    mkdir local_uploads
    echo Created: local_uploads
)

REM Set environment variables for local development
set DB_PATH=%CD%\local_data\app.db
set UPLOAD_DIR=%CD%\local_uploads
set BASE_URL=http://localhost:3000
set ADMIN_PASSWORD=admin

REM Enable demo mode if "demo" argument is passed
if /i "%DEMO_FLAG%"=="demo" (
    set DEMO_MODE=true
    set DB_PATH=%CD%\local_data\demo.db
)

echo.
echo ========================================
echo   Environment Configuration:
echo ========================================
echo   DB_PATH:        %DB_PATH%
echo   UPLOAD_DIR:     %UPLOAD_DIR%
echo   BASE_URL:       %BASE_URL%
echo   ADMIN_PASSWORD: admin
if /i "%DEMO_FLAG%"=="demo" echo   DEMO_MODE:      true (fake data enabled)
echo.
echo ========================================
echo   Starting server at:
echo   http://localhost:3000
if /i "%DEMO_FLAG%"=="demo" (
    echo   Admin: http://localhost:3000/admin/queue
    echo   Reset Demo: POST /api/demo/reset
)
echo ========================================
echo.
echo Press Ctrl+C to stop the server
echo.

REM Run the app with auto-reload for development
uvicorn app.main:app --host 127.0.0.1 --port 3000 --reload
