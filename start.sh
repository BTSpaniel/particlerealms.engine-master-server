#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

# Particle Masterserver - Launcher (Linux/macOS)
# Runs the server with the network-plan-recommended uvicorn flags
# (single worker, capped frame size, no access log), using the isolated
# environment created by install.sh. Override the bind address/port with
# the PARTICLE_HOST / PARTICLE_PORT env vars.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON_BIN="${PARTICLE_VENV_PYTHON:-.venv/bin/python}"

if [[ ! -x "$PYTHON_BIN" ]]; then
    echo "Error: '$PYTHON_BIN' is unavailable. Run ./install.sh first."
    exit 1
fi

PARTICLE_HOST="${PARTICLE_HOST:-127.0.0.1}"
PARTICLE_PORT="${PARTICLE_PORT:-8080}"

echo
echo "======================================"
echo "Particle Masterserver"
echo "Listening on ${PARTICLE_HOST}:${PARTICLE_PORT}"
echo "(Ctrl+C to stop)"
echo "======================================"
echo

exec "$PYTHON_BIN" -m uvicorn app.main:app \
    --host "$PARTICLE_HOST" --port "$PARTICLE_PORT" \
    --workers 1 --ws websockets \
    --ws-max-size 65536 --ws-max-queue 16 --ws-ping-interval 25 --ws-ping-timeout 20 \
    --ws-per-message-deflate false --limit-concurrency 192 \
    --backlog 256 \
    --proxy-headers --forwarded-allow-ips 127.0.0.1 \
    --timeout-graceful-shutdown 20 --no-server-header --no-access-log
