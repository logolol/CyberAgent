#!/usr/bin/env bash
# CyberAgent RAG Database Update Script
# Run manually when you want to update ExploitDB/CVE/MITRE data
# DO NOT run automatically — it's SLOW and downloads GBs of data!

echo "[*] Start RAG Database Update: $(date)"

echo "[*] Updating ExploitDB LOCAL database only (no papers)..."
# Update ONLY the exploit database, NOT the 2.5GB papers archive
if command -v searchsploit &> /dev/null; then
    echo "[i] Running: apt update && apt install --only-upgrade exploitdb"
    sudo apt update -qq
    sudo apt install -y --only-upgrade exploitdb 2>&1 | grep -E "(upgraded|installed|newest)"
    echo "[*] ExploitDB update complete (papers NOT downloaded)"
else
    echo "[!] searchsploit not found. Install exploitdb package."
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [ -f ".venv/bin/activate" ]; then
    echo "[*] Activating virtual environment..."
    source .venv/bin/activate
else
    echo "[!] Warning: No .venv found in $(pwd)! Using system python."
fi

echo "[*] Ingesting ExploitDB, CVEs, MITRE into ChromaDB..."
python3 knowledge_base/ingest_all.py --force

echo "[*] Creating update marker..."
touch memory/.last_rag_update

echo "[*] RAG Database Update Complete: $(date)"
