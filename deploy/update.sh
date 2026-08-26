#!/bin/bash
set -e

APP_NAME="flask-assets"
APP_DIR="/opt/$APP_NAME"

echo "=== Updating IT Asset Manager ==="

cd $APP_DIR/app
sudo -u $APP_NAME git pull origin main
sudo -u $APP_NAME $APP_DIR/venv/bin/pip install -r requirements.txt

sudo systemctl restart flask-assets

echo "=== Update complete! App restarted. ==="
