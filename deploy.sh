#!/bin/bash
# RustCERevive - Quick deployment script

set -e

PS4_IP="192.168.0.103"
FTP_PORT="2121"
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "=== RustCERevive Deployment ==="
echo "Project: $PROJECT_ROOT"
echo ""

# Build plugin
echo "[1/2] Building plugin..."
cd "$PROJECT_ROOT/plugin/rust_psn_bypass"
make

# Deploy to PS4
echo "[2/2] Deploying to PS4 at $PS4_IP..."
PLUGIN_PRX="$PROJECT_ROOT/bin/plugins/prx_final/rust_psn_bypass.prx"

if [ ! -f "$PLUGIN_PRX" ]; then
    echo "❌ Error: Plugin not found at $PLUGIN_PRX"
    exit 1
fi

echo "Uploading $(basename "$PLUGIN_PRX") ($(du -h "$PLUGIN_PRX" | cut -f1))..."
curl -T "$PLUGIN_PRX" "ftp://$PS4_IP:$FTP_PORT/data/GoldHEN/plugins/rust_psn_bypass.prx"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "Next steps:"
echo "  1. Restart Rust Console Edition on PS4"
echo "  2. Run: cd server && ./run.sh"
echo "  3. Game will connect to your custom server"
