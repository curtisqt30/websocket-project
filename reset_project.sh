#!/usr/bin/env bash
set -euo pipefail

echo "[INFO] Cleaning up runtime data..."
sudo rm -rf flask_session uploads chat_logs

# key‑generation blocks (unchanged) …

echo "[INFO] Testing Nginx config..."
sudo nginx -t && sudo systemctl restart nginx

echo "[INFO] Clearing anything bound to port 5000..."
sudo fuser -k 5000/tcp 2>/dev/null || true

echo "[INFO] Stopping old Flask (if any)..."
pkill -f 'python3 app.py' 2>/dev/null || true

echo "[INFO] Starting Flask inside tmux..."
tmux kill-session -t curtisconnect 2>/dev/null || true
tmux new-session -d -s curtisconnect \
  "cd $(pwd) && $(which python3) app.py"

echo "[SUCCESS] Server up – view logs with:  tmux attach -t curtisconnect"
