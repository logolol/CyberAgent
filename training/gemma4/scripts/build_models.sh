#!/bin/bash
# Build CyberAgent-Gemma4 models from Modelfiles
# Run: ./build_models.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODELFILE_DIR="$SCRIPT_DIR/../modelfiles"

echo "=== Building CyberAgent-Gemma4 Models ==="
echo "Base model: gemma4:e4b (8B Q4_K_M)"
echo ""

# Build pentest model
echo "[1/2] Building cyberagent-gemma4:pentest..."
ollama create cyberagent-gemma4:pentest -f "$MODELFILE_DIR/Modelfile.pentest"
echo "✓ cyberagent-gemma4:pentest created"

# Build reasoning model
echo "[2/2] Building cyberagent-gemma4:reasoning..."
ollama create cyberagent-gemma4:reasoning -f "$MODELFILE_DIR/Modelfile.reasoning"
echo "✓ cyberagent-gemma4:reasoning created"

echo ""
echo "=== Models Built Successfully ==="
ollama list | grep "cyberagent-gemma4"

echo ""
echo "Test commands:"
echo "  ollama run cyberagent-gemma4:pentest 'vsftpd 2.3.4 on port 21. Exploit?'"
echo "  ollama run cyberagent-gemma4:reasoning 'Plan attack on target with SSH, HTTP, SMB open'"
