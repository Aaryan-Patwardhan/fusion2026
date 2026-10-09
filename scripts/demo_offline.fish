#!/usr/bin/env fish
# Hyron AI — Demo Script (Strictly Offline / Cached Mode)
# Fish-compatible execution for venue Wi-Fi failure

echo "=== Hyron AI (CSB-03) Offline Demo Launcher ==="

# 1. Setup virtual environment if missing
if not test -d .venv
    echo "[1/4] Creating virtual environment (.venv)..."
    python3 -m venv .venv
end

# 2. Activate virtual environment
source .venv/bin/activate.fish

# 3. Ensure dependencies are installed
if not python -c "import networkx, fastapi, cvss, watchdog" 2>/dev/null
    echo "[2/4] Installing backend requirements..."
    pip install -q -r backend/requirements.txt
else
    echo "[2/4] Dependencies already satisfied."
end

# 4. Check for corpus
if not test -d corpus; or test (count corpus/*/package-lock.json) -eq 0
    echo "Error: 'corpus' folder missing or empty."
    echo "Tip: Run once with network to generate corpus: python -m backend.make_corpus 10"
    exit 1
end

# 5. Check for local cache file
if not test -f .osv_cache.json
    echo "Error: Local cache file '.osv_cache.json' missing."
    echo "Tip: Run online once to populate cache: python -m backend.main corpus/*/package-lock.json"
    exit 1
end

# 6. Execute offline scan pipeline
echo "[3/4] Executing scan in OFFLINE mode (using .osv_cache.json only)..."
env OFFLINE=1 python -m backend.main corpus/*/package-lock.json

echo ""
echo "========================================================"
echo " Hyron AI Dashboard & API running in OFFLINE mode!"
echo " URL: http://localhost:8000"
echo " Interactive Docs: http://localhost:8000/docs"
echo " Press Ctrl+C to quit."
echo "========================================================"
env OFFLINE=1 uvicorn backend.main:app --port 8000
