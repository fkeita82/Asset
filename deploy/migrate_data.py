"""
SQLite to MySQL data migration script.
Run this on the VPS after deploying the app.

Usage:
    cd /opt/flask-assets/app
    sudo -u flask-assets ../venv/bin/python deploy/migrate_data.py
"""
import sqlite3
import os
import sys

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from models import db, Asset, Employee, Project, User, Role, Setting

SQLITE_PATH = os.path.join(os.path.expanduser('~'), 'assets_backup.db')


def migrate():
    if not os.path.exists(SQLITE_PATH):
        print(f"ERROR: SQLite database not found at {SQLITE_PATH}")
        print("Please upload your local assets.db to the VPS first:")
        print(f"  scp <local_path>/assets.db user@server:{SQLITE_PATH}")
        return

    print(f"Reading from: {SQLITE_PATH}")
    print(f"Writing to: MySQL (flask_assets_db)")
    print()

    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    with app.app_context():
        # Migrate Roles
        cur.execute("SELECT * FROM role")
        roles = cur.fetchall()
        for r in roles:
            existing = Role.query.filter_by(name=r['name']).first()
            if not existing:
                role = Role(name=r['name'], label=r['label'], permissions=r['permissions'], is_system=bool(r['is_system']))
                db.session.add(role)
                print(f"  Role: {r['name']}")
        db.session.flush()

        # Migrate Users
        cur.execute("SELECT * FROM user")
        users = cur.fetchall()
        for u in users:
            existing = User.query.filter_by(username=u['username']).first()
            if not existing:
                user = User(
                    username=u['username'],
                    email=u['email'],
                    name=u['name'],
                    role=u['role'],
                    is_active=bool(u['is_active']),
                    password_hash=u['password_hash'],
                    extra_permissions=u['extra_permissions'] or '[]',
                    sso_provider=u['sso_provider'],
                    sso_provider_user_id=u['sso_provider_user_id'],
                )
                db.session.add(user)
                print(f"  User: {u['username']}")
        db.session.flush()

        # Migrate Projects
        cur.execute("SELECT * FROM project")
        projects = cur.fetchall()
        for p in projects:
            existing = Project.query.filter_by(name=p['name']).first()
            if not existing:
                proj = Project(
                    name=p['name'],
                    description=p['description'],
                    department=p['department'],
                    start_date=p['start_date'],
                    end_date=p['end_date'],
                    status=p['status'],
                    notes=p['notes'],
                )
                db.session.add(proj)
                print(f"  Project: {p['name']}")
        db.session.flush()

        # Migrate Employees
        cur.execute("SELECT * FROM employee")
        employees = cur.fetchall()
        emp_id_map = {}
        for e in employees:
            existing = Employee.query.filter_by(
                first_name=e['first_name'], last_name=e['last_name'], email=e['email']
            ).first()
            if not existing:
                emp = Employee(
                    first_name=e['first_name'],
                    last_name=e['last_name'],
                    email=e['email'],
                    department=e['department'],
                    phone=e['phone'],
                    notes=e['notes'],
                )
                # Map project
                if e['project_id']:
                    old_proj = cur.execute("SELECT name FROM project WHERE id=?", (e['project_id'],)).fetchone()
                    if old_proj:
                        new_proj = Project.query.filter_by(name=old_proj['name']).first()
                        if new_proj:
                            emp.project_id = new_proj.id
                db.session.add(emp)
                db.session.flush()
                emp_id_map[e['id']] = emp.id
                print(f"  Employee: {e['first_name']} {e['last_name']}")
            else:
                emp_id_map[e['id']] = existing.id

        # Migrate Assets
        cur.execute("SELECT * FROM asset")
        assets = cur.fetchall()
        for a in assets:
            existing = Asset.query.filter_by(serial_number=a['serial_number']).first()
            if not existing:
                asset = Asset(
                    category=a['category'],
                    sub_category=a['sub_category'],
                    serial_number=a['serial_number'],
                    asset_tag_id=a['asset_tag_id'],
                    warranty_expiration=a['warranty_expiration'],
                    purchase_date=a['purchase_date'],
                    manufacturer=a['manufacturer'],
                    model=a['model'],
                    location=a['location'],
                    department=a['department'],
                    status=a['status'],
                    is_archived=bool(a['is_archived']),
                    notes=a['notes'],
                )
                # Map employee
                if a['employee_id'] and a['employee_id'] in emp_id_map:
                    asset.employee_id = emp_id_map[a['employee_id']]
                # Map project
                if a['project_id']:
                    old_proj = cur.execute("SELECT name FROM project WHERE id=?", (a['project_id'],)).fetchone()
                    if old_proj:
                        new_proj = Project.query.filter_by(name=old_proj['name']).first()
                        if new_proj:
                            asset.project_id = new_proj.id
                db.session.add(asset)
                print(f"  Asset: {a['asset_tag_id'] or a['serial_number']}")

        db.session.commit()
        print()
        print(f"Migration complete!")
        print(f"  Roles: {Role.query.count()}")
        print(f"  Users: {User.query.count()}")
        print(f"  Projects: {Project.query.count()}")
        print(f"  Employees: {Employee.query.count()}")
        print(f"  Assets: {Asset.query.count()}")

    conn.close()


if __name__ == '__main__':
    migrate()
