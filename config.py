import os
import secrets
import tempfile

basedir = os.path.abspath(os.path.dirname(__file__))

# Local dev uses temp dir (matches previous behavior)
db_dir = os.path.join(tempfile.gettempdir(), 'it_asset_manager')
os.makedirs(db_dir, exist_ok=True)


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(db_dir, 'assets.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = 'FLASK_DEBUG' not in os.environ
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = __import__('datetime').timedelta(minutes=30)

    # SSO Settings
    SSO_ENABLED = os.environ.get('SSO_ENABLED', 'false').lower() == 'true'
    SSO_PROVIDER = os.environ.get('SSO_PROVIDER', '')  # 'okta' or 'entra'

    # Okta Settings
    OKTA_CLIENT_ID = os.environ.get('OKTA_CLIENT_ID', '')
    OKTA_CLIENT_SECRET = os.environ.get('OKTA_CLIENT_SECRET', '')
    OKTA_DOMAIN = os.environ.get('OKTA_DOMAIN', '')  # e.g., 'yourorg.okta.com'
    OKTA_AUTH_SERVER = os.environ.get('OKTA_AUTH_SERVER', 'default')

    # Entra ID (Azure AD) Settings
    ENTRA_CLIENT_ID = os.environ.get('ENTRA_CLIENT_ID', '')
    ENTRA_CLIENT_SECRET = os.environ.get('ENTRA_CLIENT_SECRET', '')
    ENTRA_TENANT_ID = os.environ.get('ENTRA_TENANT_ID', '')
