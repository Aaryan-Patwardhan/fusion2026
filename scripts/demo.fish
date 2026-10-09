#!/usr/bin/env fish
# Hyron AI — Demo Script (Online with Automatic Offline Fallback)
# Fish-compatible execution for demo day

echo "=== Hyron AI (CSB-03) Demo Launcher ==="

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

# 4. Generate corpus if missing
if not test -d corpus; or test (count corpus/*/package-lock.json) -eq 0
    echo "[3/4] Generating sample project corpus..."
    python -m backend.make_corpus 10
else
    echo "[3/4] Sample corpus found."
end

# 5. Run the scan pipeline (try online, fallback to cache)
echo "[4/4] Executing vulnerability scan..."
python -m backend.main corpus/*/package-lock.json
if test $status -ne 0
    echo "Network request failed. Using local cache (.osv_cache.json)..."
    env OFFLINE=1 python -m backend.main corpus/*/package-lock.json
end

echo ""
echo "========================================================"
echo " Hyron AI Dashboard & API is ready!"
echo " URL: http://localhost:8000"
echo " Interactive Docs: http://localhost:8000/docs"
echo " Press Ctrl+C to quit."
echo "========================================================"
uvicorn backend.main:app --port 8000
