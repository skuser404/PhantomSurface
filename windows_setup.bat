@echo off
echo ============================================
echo PhantomSurface Windows Setup
echo ============================================
echo.

echo [1/6] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found!
    echo.
    echo Please install Python from: https://www.python.org/downloads/
    echo IMPORTANT: Check "Add Python to PATH" during installation!
    echo.
    pause
    exit /b 1
)
python --version
echo Python found!
echo.

echo [2/6] Creating virtual environment...
if exist venv (
    echo Virtual environment already exists, skipping...
) else (
    python -m venv venv
    echo Virtual environment created!
)
echo.

echo [3/6] Activating virtual environment...
call venv\Scripts\activate.bat
echo.

echo [4/6] Upgrading pip...
python -m pip install --upgrade pip --quiet
echo Pip upgraded!
echo.

echo [5/6] Installing dependencies...
pip install -r requirements.txt
echo Dependencies installed!
echo.

echo [6/6] Checking Nmap installation...
nmap --version >nul 2>&1
if errorlevel 1 (
    echo WARNING: Nmap not found!
    echo Please download from: https://nmap.org/download.html
    echo.
) else (
    nmap --version
    echo Nmap found!
)
echo.

echo ============================================
echo Setup Complete!
echo ============================================
echo.
echo To use PhantomSurface:
echo.
echo 1. Activate virtual environment:
echo    venv\Scripts\activate.bat
echo.
echo 2. Run CLI scan:
echo    python src\main.py --target example.com --scan-type quick
echo.
echo 3. Or start web dashboard:
echo    python src\dashboard.py
echo    Then open: http://localhost:5000
echo.
pause