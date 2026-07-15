#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

# Particle Masterserver - Installer (Linux/macOS)
# Installs dependencies directly with the system Python (no virtual environment).
# Run this once (or again after requirements.txt changes). Use ./start.sh to run the server.
set -euo pipefail
cd "$(dirname "$0")"

echo
echo "======================================"
echo "Particle Masterserver - Installer"
echo "======================================"
echo

PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Error: '$PYTHON_BIN' not found on PATH."
    echo "Install Python 3.11+ (e.g. 'sudo apt install python3') and try again,"
    echo "or set PYTHON_BIN=/path/to/python3 and re-run."
    exit 1
fi

echo "Installing dependencies..."
if ! "$PYTHON_BIN" -m pip install --upgrade pip 2>/tmp/particle-pip-err.$$ || \
   ! "$PYTHON_BIN" -m pip install -r requirements.txt 2>>/tmp/particle-pip-err.$$; then
    if grep -qi "externally-managed-environment" /tmp/particle-pip-err.$$ 2>/dev/null; then
        echo
        echo "System Python is externally-managed (PEP 668) — retrying with"
        echo "--break-system-packages instead of creating a virtual environment."
        echo
        "$PYTHON_BIN" -m pip install --upgrade pip --break-system-packages
        "$PYTHON_BIN" -m pip install -r requirements.txt --break-system-packages
    else
        cat /tmp/particle-pip-err.$$ >&2
        rm -f /tmp/particle-pip-err.$$
        exit 1
    fi
fi
rm -f /tmp/particle-pip-err.$$

echo
echo "======================================"
echo "Install complete."
echo "Run ./start.sh to launch the server."
echo "======================================"
echo
