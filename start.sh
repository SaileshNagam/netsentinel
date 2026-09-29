#!/bin/bash
set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$PROJECT_ROOT/../tools/env.sh"

echo "=================================================================="
echo " Starting NetSentinel Platform"
echo " Agentic Network Access Monitoring & Rogue Device Detection"
echo "=================================================================="

# 1. Start Backend in background
echo "[+] Launching NetSentinel FastAPI Core on http://127.0.0.1:8000 ..."
export PYTHONPATH="$PROJECT_ROOT/backend"
"$PROJECT_ROOT/backend/.venv/bin/uvicorn" app.main:app --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

# Wait for backend to report healthy
sleep 2

# 2. Start Frontend
echo "[+] Launching SOC Frontend on http://127.0.0.1:3000 ..."
cd "$PROJECT_ROOT/frontend"
npm run dev -- --host 127.0.0.1 --port 3000 &
FRONTEND_PID=$!

echo "=================================================================="
echo " NetSentinel is ARMED and RUNNING"
echo " SOC Dashboard: http://127.0.0.1:3000"
echo " API Docs:      http://127.0.0.1:8000/docs"
echo "=================================================================="

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true" EXIT
wait
