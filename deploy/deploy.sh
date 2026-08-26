#!/bin/bash
set -e

APP_NAME="flask-assets"
APP_DIR="/opt/$APP_NAME"
REPO="https://github.com/fkeita82/Asset.git"
DOMAIN="dexisit-asset.tech"

echo "=== IT Asset Manager Deployment ==="
echo "Domain: $DOMAIN"
echo ""

# 1. System updates and dependencies
echo "[1/8] Installing system dependencies..."
sudo apt update -y
sudo apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx mysql-server git

# 2. Create system user
echo "[2/8] Creating system user..."
if ! id "$APP_NAME" &>/dev/null; then
    sudo adduser --system --group --home /opt/$APP_NAME $APP_NAME
fi

# 3. Clone/update app
echo "[3/8] Deploying app files..."
sudo mkdir -p $APP_DIR
if [ -d "$APP_DIR/app/.git" ]; then
    cd $APP_DIR/app
    sudo -u $APP_NAME git pull origin main
else
    sudo -u $APP_NAME git clone $REPO $APP_DIR/app
fi

# 4. Setup virtual environment
echo "[4/8] Setting up Python environment..."
if [ ! -d "$APP_DIR/venv" ]; then
    sudo -u $APP_NAME python3 -m venv $APP_DIR/venv
    sudo -u $APP_NAME $APP_DIR/venv/bin/pip install --upgrade pip
fi
sudo -u $APP_NAME $APP_DIR/venv/bin/pip install -r $APP_DIR/app/requirements.txt

# 5. MySQL setup
echo "[5/8] Configuring MySQL..."
sudo systemctl enable --now mysql

# Create database and user if they don't exist
sudo mysql -u root <<-EOSQL
    CREATE DATABASE IF NOT EXISTS flask_assets_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE USER IF NOT EXISTS 'flask_assets_user'@'localhost' IDENTIFIED BY 'flask_assets_password';
    GRANT ALL PRIVILEGES ON flask_assets_db.* TO 'flask_assets_user'@'localhost';
    FLUSH PRIVILEGES;
EOSQL

# 6. Environment file
echo "[6/8] Setting up environment..."
if [ ! -f "$APP_DIR/.env" ]; then
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sudo -u $APP_NAME tee $APP_DIR/.env > /dev/null <<EOF
SECRET_KEY=$SECRET_KEY
DATABASE_URL=mysql+pymysql://flask_assets_user:flask_assets_password@localhost/flask_assets_db
SSO_ENABLED=false
EOF
    sudo chmod 600 $APP_DIR/.env
    echo "Created .env with new SECRET_KEY"
else
    echo ".env already exists, skipping"
fi

# 7. Initialize database tables
echo "[7/8] Initializing database..."
cd $APP_DIR/app
sudo -u $APP_NAME $APP_DIR/venv/bin/python -c "
from app import app
from models import db
with app.app_context():
    db.create_all()
    print('Database tables created')
"

# 8. Configure services
echo "[8/8] Configuring Nginx and systemd..."

# Gunicorn config
sudo -u $APP_NAME cp $APP_DIR/app/deploy/gunicorn.conf.py $APP_DIR/gunicorn.conf.py

# systemd service
sudo cp $APP_DIR/app/deploy/flask-assets.service /etc/systemd/system/flask-assets.service
sudo systemctl daemon-reload

# Nginx config
sudo cp $APP_DIR/app/deploy/flask-assets.nginx /etc/nginx/sites-available/flask-assets
sudo ln -sf /etc/nginx/sites-available/flask-assets /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Log directory
sudo mkdir -p /var/log/flask-assets
sudo chown $APP_NAME:www-data /var/log/flask-assets

# Start app
sudo systemctl enable --now flask-assets

echo ""
echo "=== Deployment Complete ==="
echo "App is running at: http://$DOMAIN"
echo ""
echo "Next steps:"
echo "  1. Point DNS A record for $DOMAIN to this server IP"
echo "  2. Run: sudo certbot --nginx -d $DOMAIN"
echo "  3. Import your data: sudo -u $APP_NAME $APP_DIR/venv/bin/python $APP_DIR/app/deploy/migrate_data.py"
echo ""
echo "Useful commands:"
echo "  sudo systemctl restart flask-assets   # Restart app"
echo "  sudo journalctl -u flask-assets -f    # View logs"
echo "  sudo systemctl reload nginx           # Reload Nginx"
