@REM SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
@REM
@REM SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

@echo off
REM Particle Masterserver - Installer (Windows)
REM Creates an isolated virtual environment and installs the hash-locked runtime.
REM Run this once (or again after requirements.txt changes). Use start.bat to run the server.

cd /d "%~dp0"

echo.
echo ======================================
echo Particle Masterserver - Installer
echo ======================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.11+ from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

echo Creating isolated Python environment...
python -m venv .venv
if errorlevel 1 goto :pipfail
echo Installing hash-verified dependencies...
.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements.lock
if errorlevel 1 goto :pipfail

echo.
echo ======================================
echo Install complete.
echo Run start.bat to launch the server.
echo ======================================
echo.
pause
exit /b 0

:pipfail
echo.
echo Dependency installation failed. Check the output above.
pause
exit /b 1
