@REM SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
@REM
@REM SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

@echo off
REM Particle Masterserver - Launcher (Windows)
REM Runs the server with the network-plan-recommended uvicorn flags
REM (single worker, capped frame size, no access log), using the system
REM Python (no virtual environment). Override the bind address/port with
REM the PARTICLE_HOST / PARTICLE_PORT env vars.

cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Run install.bat first, or install Python 3.11+ from https://www.python.org/
    echo.
    pause
    exit /b 1
)

if "%PARTICLE_HOST%"=="" set PARTICLE_HOST=127.0.0.1
if "%PARTICLE_PORT%"=="" set PARTICLE_PORT=8080

echo.
echo ======================================
echo Particle Masterserver
echo Listening on %PARTICLE_HOST%:%PARTICLE_PORT%
echo (Ctrl+C to stop)
echo ======================================
echo.

python -m uvicorn app.main:app ^
    --host %PARTICLE_HOST% --port %PARTICLE_PORT% ^
    --workers 1 --ws websockets ^
    --ws-max-size 65536 --ws-ping-interval 25 --ws-ping-timeout 20 ^
    --limit-concurrency 128 --no-access-log

if errorlevel 1 (
    echo.
    echo Server exited with an error. If this is a missing-module error, run install.bat first.
    pause
)
