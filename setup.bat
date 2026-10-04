@echo off
title TraceX Setup

echo ==========================================
echo          TraceX - Setup
echo ==========================================
echo.

echo Checking Python installation...
python --version

if errorlevel 1 (
    echo.
    echo ERROR: Python was not found.
    echo Please install Python 3.11 or newer and try again.
    echo.
    pause
    exit /b 1
)

echo.
echo Creating virtual environment...

if not exist ".venv" (
    python -m venv .venv
)

echo.
echo Activating virtual environment...
call .venv\Scripts\activate.bat

echo.
echo Upgrading pip...
python -m pip install --upgrade pip

echo.
echo Installing TraceX dependencies...
python -m pip install -r requirements.txt

echo.
echo ==========================================
echo       TraceX setup completed!
echo ==========================================
echo.
echo You can now run TraceX using:
echo TraceX.bat
echo.

pause