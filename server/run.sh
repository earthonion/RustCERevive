#!/bin/bash
# Quick server launcher

cd "$(dirname "$0")"

echo "=== RustCERevive Server ==="
echo "Starting server on port 28915..."
echo "Press Ctrl+C to stop"
echo ""

python3 rust_console_server.py
