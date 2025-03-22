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

echo "[INFO] Starting Flask application..."
sudo $(which python3) app.py
