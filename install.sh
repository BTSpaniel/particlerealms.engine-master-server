#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

# Particle Masterserver - Installer (Linux/macOS)
# Creates an isolated virtual environment and installs the hash-locked runtime.
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

echo "Creating isolated Python environment..."
"$PYTHON_BIN" -m venv .venv
echo "Installing hash-verified dependencies..."
ARCH="$(uname -m)"
PYTHON_VERSION="$(.venv/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
LOCK_ARGS=(-r requirements.lock)
if [[ "$ARCH" == "aarch64" ]]; then
    case "$PYTHON_VERSION" in
        3.12)
            LOCK_ARGS=(-r requirements-pi.lock)
            ;;
        3.13)
            LOCK_ARGS=(-r requirements.lock -r requirements-pi313-uvloop.lock)
            ;;
        *)
            echo "Error: no hash lock is available for Linux aarch64 CPython $PYTHON_VERSION."
            echo "Use CPython 3.12 or 3.13; refusing an unverified dependency install."
            exit 1
            ;;
    esac
fi
.venv/bin/python -m pip install --require-hashes --only-binary=:all: "${LOCK_ARGS[@]}"

echo
echo "======================================"
echo "Install complete."
echo "Run ./start.sh to launch the server."
echo "======================================"
echo
