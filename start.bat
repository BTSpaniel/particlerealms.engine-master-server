@REM SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
@REM
@REM SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

@echo off
REM Particle Masterserver - Launcher (Windows)
REM Runs the server with the network-plan-recommended uvicorn flags
REM (single worker, capped frame size, no access log), using the isolated
REM environment created by install.bat. Override the bind address/port with
REM the PARTICLE_HOST / PARTICLE_PORT env vars.

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Error: .venv\Scripts\python.exe is unavailable
    echo Run install.bat first.
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

.venv\Scripts\python.exe -m uvicorn app.main:app ^
    --host %PARTICLE_HOST% --port %PARTICLE_PORT% ^
    --workers 1 --ws websockets ^
    --ws-max-size 65536 --ws-max-queue 16 --ws-ping-interval 25 --ws-ping-timeout 20 ^
    --ws-per-message-deflate false --limit-concurrency 192 ^
    --backlog 256 ^
    --proxy-headers --forwarded-allow-ips 127.0.0.1 ^
    --timeout-graceful-shutdown 20 --no-server-header --no-access-log

if errorlevel 1 (
    echo.
    echo Server exited with an error. If this is a missing-module error, run install.bat first.
    pause
)
