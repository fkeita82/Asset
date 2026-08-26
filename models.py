import json
import secrets
from datetime import datetime, timezone, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# ─── Permission constants ───────────────────────────────────────────

PERM_GROUPS = {
    'Assets': ['asset.view', 'asset.create', 'asset.edit', 'asset.delete', 'asset.import', 'asset.export'],
    'Employees': ['employee.view', 'employee.create', 'employee.edit', 'employee.delete', 'employee.import'],
    'Projects': ['project.view', 'project.create', 'project.edit', 'project.delete', 'project.import'],
    'Administration': ['user.manage', 'audit.view', 'role.manage'],
}

PERM_LABELS = {
    'asset.view': 'View Assets',
    'asset.create': 'Create Assets',
    'asset.edit': 'Edit Assets',
    'asset.delete': 'Delete Assets',
    'asset.import': 'Import Assets',
    'asset.export': 'Export Assets',
    'employee.view': 'View Employees',
    'employee.create': 'Create Employees',
    'employee.edit': 'Edit Employees',
    'employee.delete': 'Delete Employees',
    'employee.import': 'Import Employees',
    'project.view': 'View Projects',
    'project.create': 'Create Projects',
    'project.edit': 'Edit Projects',
    'project.delete': 'Delete Projects',
    'project.import': 'Import Projects',
    'user.manage': 'Manage Users',
    'audit.view': 'View Audit Log',
    'role.manage': 'Manage Roles',
}

ALL_PERMISSIONS = [p for perms in PERM_GROUPS.values() for p in perms]

ROLE_DEFAULT_PERMISSIONS = {
    'Admin': ALL_PERMISSIONS,
    'Editor': [p for p in ALL_PERMISSIONS if p not in ('user.manage', 'audit.view', 'role.manage')],
    'Viewer': ['asset.view', 'employee.view', 'project.view'],
}


# ─── Models ─────────────────────────────────────────────────────────

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    label = db.Column(db.String(100))
    permissions = db.Column(db.Text)  # JSON list of permission strings
    is_system = db.Column(db.Boolean, default=False)

    def get_permissions(self):
        return json.loads(self.permissions) if self.permissions else []

    def set_permissions(self, perms_list):
        self.permissions = json.dumps(list(set(perms_list)))

    def __repr__(self):
        return self.name


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=True)
    name = db.Column(db.String(200))
    role = db.Column(db.String(20), default='Viewer')
    extra_permissions = db.Column(db.Text, default='[]')  # JSON list
    is_active = db.Column(db.Boolean, default=True)
    sso_provider = db.Column(db.String(50), nullable=True)  # 'okta' or 'entra'
    sso_provider_user_id = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_extra_permissions(self):
        return json.loads(self.extra_permissions) if self.extra_permissions else []

    def set_extra_permissions(self, perms_list):
        self.extra_permissions = json.dumps(list(set(perms_list)))

    def has_permission(self, perm):
        role = Role.query.filter_by(name=self.role).first()
        if role and perm in role.get_permissions():
            return True
        if perm in self.get_extra_permissions():
            return True
        return False

    def __repr__(self):
        return self.username


class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(200))

    @staticmethod
    def get(key, default=None):
        s = Setting.query.filter_by(key=key).first()
        return s.value if s else default

    @staticmethod
    def set(key, value, description=None):
        s = Setting.query.filter_by(key=key).first()
        if s:
            s.value = value
            if description:
                s.description = description
        else:
            s = Setting(key=key, value=value, description=description)
            db.session.add(s)
        db.session.commit()

    @staticmethod
    def get_bool(key, default=False):
        val = Setting.get(key)
        if val is None:
            return default
        return val.lower() in ('true', '1', 'yes', 'on')


class Invite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(200))
    role = db.Column(db.String(20), default='Viewer')
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.token:
            self.token = secrets.token_hex(32)
        if not self.expires_at:
            self.expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    def is_expired(self):
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self):
        return not self.is_used and not self.is_expired()


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    username = db.Column(db.String(80))
    action = db.Column(db.String(50), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)
    entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='audit_logs')

    def __repr__(self):
        return f'[{self.timestamp}] {self.username} {self.action} {self.entity_type}'


class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False, default='')
    last_name = db.Column(db.String(100), nullable=False, default='')
    email = db.Column(db.String(200))
    department = db.Column(db.String(100))
    phone = db.Column(db.String(50))
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=True)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    assets = db.relationship('Asset', backref='assigned_employee', lazy='dynamic')
    assigned_project = db.relationship('Project', backref='employees')

    @property
    def name(self):
        return f'{self.first_name} {self.last_name}'.strip()

    @property
    def project_name(self):
        return self.assigned_project.name if self.assigned_project else None

    def __repr__(self):
        return self.name


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    department = db.Column(db.String(100))
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(50), default='Active')
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    assets = db.relationship('Asset', backref='project', lazy='dynamic')

    STATUSES = ['Active', 'Completed', 'On Hold', 'Cancelled']

    def __repr__(self):
        return self.name


class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)
    sub_category = db.Column(db.String(50), nullable=False)
    serial_number = db.Column(db.String(100), nullable=False)
    asset_tag_id = db.Column(db.String(100), unique=True, nullable=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=True)
    warranty_expiration = db.Column(db.Date, nullable=True)
    purchase_date = db.Column(db.Date, nullable=True)
    manufacturer = db.Column(db.String(100))
    model = db.Column(db.String(100))
    location = db.Column(db.String(200))
    department = db.Column(db.String(100))
    status = db.Column(db.String(50), default='In-Storage')
    is_archived = db.Column(db.Boolean, default=False, index=True)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    CATEGORIES = {
        'Workstation': ['Laptop', 'Desktop'],
        'Network Device': ['Router', 'Switch'],
        'Printer': ['Printer'],
        'Monitor': ['Monitor'],
        'Docking Station': ['Docking Station'],
    }

    STATUSES = ['In-Storage', 'Assigned', 'Deployed', 'In Repair', 'Retired', 'Disposed']

    @property
    def assigned_user(self):
        return self.assigned_employee.name if self.assigned_employee else None

    @property
    def project_name(self):
        return self.project.name if self.project else None

    def __repr__(self):
        return f'<Asset {self.asset_tag_id or "no tag"} - {self.sub_category}>'

    def to_dict(self):
        return {
            'id': self.id,
            'category': self.category,
            'sub_category': self.sub_category,
            'serial_number': self.serial_number,
            'asset_tag_id': self.asset_tag_id,
            'assigned_user': self.assigned_user,
            'employee_id': self.employee_id,
            'project_id': self.project_id,
            'warranty_expiration': self.warranty_expiration.isoformat() if self.warranty_expiration else '',
            'purchase_date': self.purchase_date.isoformat() if self.purchase_date else '',
            'manufacturer': self.manufacturer,
            'model': self.model,
            'location': self.location,
            'department': self.department,
            'status': self.status,
            'is_archived': self.is_archived,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else '',
            'updated_at': self.updated_at.isoformat() if self.updated_at else '',
        }
