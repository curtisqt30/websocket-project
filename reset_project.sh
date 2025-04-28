#!/bin/bash

echo "[INFO] Cleaning up old session data, chat_logs, and uploaded files..."
sudo rm -rf flask_session uploads chat_logs

# Only delete and regenerate keys if missing
if [ ! -f private_key.pem ]; then
    echo "[INFO] Generating RSA keys..."
    python3 -c 'from app import generate_rsa_keys; generate_rsa_keys()'
    chmod 600 private_key.pem public_key.pem
else
    echo "[INFO] RSA keys already exist. Skipping regeneration."
fi

# Only delete and regenerate Log AES key if missing
if [ ! -f log_aes_key.bin ]; then
    echo "[INFO] Generating Log AES key..."
    openssl rand -out log_aes_key.bin 32
    chmod 600 log_aes_key.bin
else
    echo "[INFO] Log AES key already exists. Skipping regeneration."
fi

# Ensure Nginx test only runs if necessary
echo "[INFO] Testing Nginx configuration..."
if sudo nginx -t; then
    echo "[SUCCESS] Nginx configuration is valid."
    sudo systemctl restart nginx
else
    echo "[ERROR] Nginx configuration is invalid. Please check your config."
    exit 1
fi

echo "[INFO] Stopping Python processes..."
sudo pkill -f python || echo "[INFO] No active Python processes found."

echo "[INFO] Starting Flask application inside tmux session..."
tmux kill-session -t curtisconnect 2>/dev/null || true
tmux new-session -d -s curtisconnect "cd $(pwd) && sudo $(which python3) app.py"

echo "[INFO] Project reset successfully."
