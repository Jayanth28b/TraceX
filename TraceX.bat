@echo off
title TraceX - AI-Assisted Digital Forensics

echo ==========================================
echo              TraceX
echo      AI-Assisted Digital Forensics
echo ==========================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo ERROR: TraceX is not set up yet.
    echo.
    echo Please run setup.bat first.
    echo.
    pause
    exit /b 1
)

echo Starting TraceX...
echo.

call .venv\Scripts\activate.bat

python run_tracex.py

echo.
echo TraceX has stopped.
pause