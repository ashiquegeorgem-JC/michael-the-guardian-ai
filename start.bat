@echo off
TITLE MICHAEL - The Guardian AI
echo =====================================================================
echo  MICHAEL - The Guardian AI
echo  Intelligent Log Analysis and Anomaly Detection Platform
echo  Tagline: "Intelligence That Watches. AI That Protects."
echo =====================================================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.10+.
    pause
    exit /b 1
)

:: Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH. Please install Node.js 18+.
    pause
    exit /b 1
)

echo [1/3] Setting up Python Backend Virtualenv...
cd /d "%~dp0backend"
if not exist "venv" (
    echo Creating Python virtual environment...
    python -m venv venv
)
call venv\Scripts\activate.bat
echo Installing backend dependencies...
pip install -r requirements.txt --quiet

echo.
echo [2/3] Starting FastAPI Backend on http://localhost:8000 ...
if exist "venv\Scripts\activate.bat" (
    start "MICHAEL Backend (FastAPI)" cmd /k "call venv\Scripts\activate.bat && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
) else (
    start "MICHAEL Backend (FastAPI)" cmd /k "python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
)

echo.
echo [3/3] Starting Next.js Frontend on http://localhost:3000 ...
cd /d "%~dp0frontend"
start "MICHAEL Frontend (Next.js)" cmd /k "npm run dev"

echo.
echo =====================================================================
echo  All services launched successfully!
echo   - Web Console:  http://localhost:3000
echo   - API Server:   http://localhost:8000
echo   - Swagger Docs: http://localhost:8000/api/docs
echo =====================================================================
echo.
pause
