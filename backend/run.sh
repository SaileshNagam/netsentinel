#!/bin/bash
source /Users/apple/.gemini/antigravity/scratch/tools/env.sh
export PYTHONPATH=/Users/apple/.gemini/antigravity/scratch/netsentinel/backend
exec /Users/apple/.gemini/antigravity/scratch/netsentinel/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
