import csv
import io
import os
import smtplib
from io import BytesIO
from datetime import datetime
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort, session, g
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_babel import Babel, gettext as _, lazy_gettext as _l
from werkzeug.middleware.proxy_fix import ProxyFix
from authlib.integrations.flask_client import OAuth
from sqlalchemy import func
from config import Config
from models import (db, Asset, Employee, Project, User, AuditLog, Role, Setting, Invite,
                    ALL_PERMISSIONS, PERM_GROUPS, PERM_LABELS,
                    ROLE_DEFAULT_PERMISSIONS)
from forms import (AssetForm, EmployeeForm, ProjectForm, AssetImportForm,
                   EmployeeImportForm, ProjectImportForm, LoginForm, UserForm,
                   PasswordChangeForm, RoleForm, InviteForm, AcceptInviteForm)

app = Flask(__name__)
app.config.from_object(Config)
app.config['LANGUAGES'] = {'en': 'English', 'fr': 'Francais'}
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
db.init_app(app)

oauth = OAuth(app)


def get_locale():
    if 'language' in session:
        return session['language']
    return request.accept_languages.best_match(app.config['LANGUAGES'].keys())


babel = Babel(app, locale_selector=get_locale)


@app.before_request
def before_request():
    g.locale = get_locale()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'


def escape_like(value):
    """Escape special characters for LIKE queries."""
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def seed_roles():
    if not Role.query.first():
        for name, perms in ROLE_DEFAULT_PERMISSIONS.items():
            role = Role(name=name, label=name, is_system=True)
            role.set_permissions(perms)
            db.session.add(role)
        db.session.commit()


def seed_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', name='Administrator', role='Admin')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()


with app.app_context():
    db.create_all()
    seed_roles()
    seed_admin()


# --- OAuth / SSO Setup ---

if app.config.get('OKTA_CLIENT_ID'):
    oauth.register(
        name='okta',
        client_id=app.config['OKTA_CLIENT_ID'],
        client_secret=app.config['OKTA_CLIENT_SECRET'],
        server_metadata_url=f'https://{app.config["OKTA_DOMAIN"]}/oauth2/{app.config["OKTA_AUTH_SERVER"]}/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )

if app.config.get('ENTRA_CLIENT_ID'):
    oauth.register(
        name='entra',
        client_id=app.config['ENTRA_CLIENT_ID'],
        client_secret=app.config['ENTRA_CLIENT_SECRET'],
        server_metadata_url=f'https://login.microsoftonline.com/{app.config["ENTRA_TENANT_ID"]}/v2.0/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )


@app.route('/set_language/<language>')
def set_language(language):
    if language in app.config['LANGUAGES']:
        session['language'] = language
    return redirect(request.referrer or url_for('index'))


def log_audit(action, entity_type, entity_id=None, details=None):
    log = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        username=current_user.username if current_user.is_authenticated else 'system',
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details,
    )
    db.session.add(log)


def permission_required(*perms):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            for perm in perms:
                if not current_user.has_permission(perm):
                    abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.context_processor
def inject_globals():
    def has_perm(perm):
        return current_user.is_authenticated and current_user.has_permission(perm)
    return {
        'now': datetime.now,
        'has_perm': has_perm,
        'PERM_GROUPS': PERM_GROUPS,
        'PERM_LABELS': PERM_LABELS,
        'ALL_PERMISSIONS': ALL_PERMISSIONS,
    }


# --- Auth ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data) and user.is_active:
            login_user(user)
            log_audit('login', 'User', user.id, f'User {user.username} logged in')
            db.session.commit()
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Invalid username or password.', 'danger')

    sso_enabled = is_sso_enabled()
    return render_template('login.html', form=form, sso_enabled=sso_enabled)


@app.route('/login/sso/okta')
def login_okta():
    okta_id = Setting.get('okta_client_id') or app.config.get('OKTA_CLIENT_ID')
    if not okta_id:
        flash('Okta SSO is not configured.', 'danger')
        return redirect(url_for('login'))

    okta_secret = Setting.get('okta_client_secret') or app.config.get('OKTA_CLIENT_SECRET')
    okta_domain = Setting.get('okta_domain') or app.config.get('OKTA_DOMAIN')
    okta_server = Setting.get('okta_auth_server') or app.config.get('OKTA_AUTH_SERVER', 'default')

    if not okta_domain:
        flash('Okta domain is not configured.', 'danger')
        return redirect(url_for('login'))

    oauth.register(
        name='okta',
        client_id=okta_id,
        client_secret=okta_secret,
        server_metadata_url=f'https://{okta_domain}/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )

    redirect_uri = url_for('sso_callback', provider='okta', _external=True)
    return oauth.okta.authorize_redirect(redirect_uri)


@app.route('/login/sso/entra')
def login_entra():
    entra_id = Setting.get('entra_client_id') or app.config.get('ENTRA_CLIENT_ID')
    if not entra_id:
        flash('Entra ID SSO is not configured.', 'danger')
        return redirect(url_for('login'))

    entra_secret = Setting.get('entra_client_secret') or app.config.get('ENTRA_CLIENT_SECRET')
    entra_tenant = Setting.get('entra_tenant_id') or app.config.get('ENTRA_TENANT_ID')

    if not entra_tenant:
        flash('Entra ID tenant is not configured.', 'danger')
        return redirect(url_for('login'))

    oauth.register(
        name='entra',
        client_id=entra_id,
        client_secret=entra_secret,
        server_metadata_url=f'https://login.microsoftonline.com/{entra_tenant}/v2.0/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )

    redirect_uri = url_for('sso_callback', provider='entra', _external=True)
    return oauth.entra.authorize_redirect(redirect_uri)


@app.route('/login/sso/callback/<provider>')
def sso_callback(provider):
    if provider == 'okta':
        token = oauth.okta.authorize_access_token()
        userinfo = token.get('userinfo')
    elif provider == 'entra':
        token = oauth.entra.authorize_access_token()
        resp = oauth.entra.get('https://graph.microsoft.com/v1.0/me', token=token)
        userinfo = resp.json()
    else:
        flash('Unknown SSO provider.', 'danger')
        return redirect(url_for('login'))

    if not userinfo:
        flash('SSO authentication failed.', 'danger')
        return redirect(url_for('login'))

    email = userinfo.get('email') or userinfo.get('preferred_username', '')
    name = userinfo.get('name', '')
    provider_user_id = userinfo.get('sub') or userinfo.get('oid', '')

    user = User.query.filter_by(email=email).first()
    if not user:
        username = email.split('@')[0] if email else f'{provider}_{provider_user_id[:8]}'
        base_username = username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f'{base_username}{counter}'
            counter += 1
        user = User(
            username=username,
            email=email,
            name=name,
            role='Viewer',
            sso_provider=provider,
            sso_provider_user_id=provider_user_id,
        )
        db.session.add(user)
        db.session.flush()
        log_audit('sso_create', 'User', user.id, f'SSO auto-created user {user.username} via {provider}')
    else:
        user.sso_provider = provider
        user.sso_provider_user_id = provider_user_id
        if name:
            user.name = name

    login_user(user)
    log_audit('sso_login', 'User', user.id, f'User {user.username} logged in via {provider} SSO')
    db.session.commit()

    next_page = request.args.get('next')
    return redirect(next_page or url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html', form=form)
        current_user.set_password(form.new_password.data)
        log_audit('change_password', 'User', current_user.id, 'User changed own password')
        db.session.commit()
        flash('Password changed successfully.', 'success')
        return redirect(url_for('index'))
    return render_template('change_password.html', form=form)


# --- Dashboard ---

@app.route('/')
@login_required
def index():
    category_counts = dict(
        db.session.query(Asset.category, func.count(Asset.id))
        .filter(Asset.is_archived == False)
        .group_by(Asset.category).all()
    )
    sub_counts = dict(
        db.session.query(Asset.sub_category, func.count(Asset.id))
        .filter(Asset.is_archived == False)
        .group_by(Asset.sub_category).all()
    )
    status_counts = dict(
        db.session.query(Asset.status, func.count(Asset.id))
        .filter(Asset.is_archived == False)
        .group_by(Asset.status).all()
    )
    stats = {
        'total': Asset.query.filter(Asset.is_archived == False).count(),
        'workstations': category_counts.get('Workstation', 0),
        'laptops': sub_counts.get('Laptop', 0),
        'desktops': sub_counts.get('Desktop', 0),
        'network': category_counts.get('Network Device', 0),
        'printers': category_counts.get('Printer', 0),
        'monitors': category_counts.get('Monitor', 0),
        'docking_stations': category_counts.get('Docking Station', 0),
        'in_storage': status_counts.get('In-Storage', 0),
        'assigned': status_counts.get('Assigned', 0),
        'deployed': status_counts.get('Deployed', 0),
        'in_repair': status_counts.get('In Repair', 0),
        'retired': status_counts.get('Retired', 0),
        'disposed': status_counts.get('Disposed', 0),
        'archived': Asset.query.filter(Asset.is_archived == True).count(),
        'employees': Employee.query.count(),
        'projects': Project.query.count(),
    }
    recent = Asset.query.filter(Asset.is_archived == False).order_by(Asset.updated_at.desc()).limit(5).all()
    return render_template('index.html', stats=stats, recent=recent)


# --- Assets ---

@app.route('/assets')
@login_required
def list_assets():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    category = request.args.get('category', '')
    sub_category = request.args.get('type', '')
    status = request.args.get('status', '')
    project_id = request.args.get('project', 0, type=int)

    query = Asset.query.filter(Asset.is_archived == False)
    if search:
        like = f'%{escape_like(search)}%'
        query = query.outerjoin(Employee).outerjoin(Project).filter(
            db.or_(
                Asset.serial_number.like(like, escape='\\'),
                Asset.asset_tag_id.like(like, escape='\\'),
                Asset.manufacturer.like(like, escape='\\'),
                Asset.model.like(like, escape='\\'),
                Asset.location.like(like, escape='\\'),
                Asset.department.like(like, escape='\\'),
                Employee.first_name.like(like, escape='\\'),
                Employee.last_name.like(like, escape='\\'),
                Project.name.like(like, escape='\\'),
            )
        )
    if category:
        query = query.filter_by(category=category)
    if sub_category:
        query = query.filter_by(sub_category=sub_category)
    if status:
        query = query.filter_by(status=status)
    if project_id:
        query = query.filter_by(project_id=project_id)

    query = query.order_by(Asset.updated_at.desc())
    pagination = query.paginate(page=page, per_page=150, error_out=False)
    assets = pagination.items

    projects = Project.query.order_by(Project.name).all()
    types = sorted(set(s for subs in Asset.CATEGORIES.values() for s in subs))

    return render_template('assets.html',
                           assets=assets,
                           pagination=pagination,
                           search=search,
                           filter_category=category,
                           filter_type=sub_category,
                           filter_status=status,
                           filter_project=project_id,
                           projects=projects,
                           types=types)


def _set_asset_form_choices(form):
    form.employee_id.choices = [(0, '-- Unassigned --')] + [
        (e.id, e.name) for e in Employee.query.order_by(Employee.first_name, Employee.last_name).all()
    ]
    form.project_id.choices = [(0, '-- None --')] + [
        (p.id, p.name) for p in Project.query.order_by(Project.name).all()
    ]


def _set_sub_category_choices(form, category):
    subs = Asset.CATEGORIES.get(category, [])
    form.sub_category.choices = [(s, s) for s in subs]


@app.route('/assets/new', methods=['GET', 'POST'])
@login_required
@permission_required('asset.create')
def new_asset():
    form = AssetForm()
    _set_asset_form_choices(form)
    cat = request.form.get('category', '') if request.method == 'POST' else ''
    _set_sub_category_choices(form, cat)
    if form.validate_on_submit():
        asset = Asset(
            category=form.category.data,
            sub_category=form.sub_category.data,
            serial_number=form.serial_number.data,
            asset_tag_id=form.asset_tag_id.data or None,
            employee_id=form.employee_id.data or None,
            project_id=form.project_id.data or None,
            warranty_expiration=form.warranty_expiration.data,
            purchase_date=form.purchase_date.data,
            manufacturer=form.manufacturer.data,
            model=form.model.data,
            location=form.location.data,
            department=form.department.data,
            status=form.status.data,
            notes=form.notes.data,
        )
        if form.status.data == 'Disposed':
            asset.is_archived = True
            asset.employee_id = None
            asset.project_id = None
        db.session.add(asset)
        log_audit('create', 'Asset', asset.id, f'Created Asset {asset.asset_tag_id or "(no tag)"} ({asset.sub_category})')
        db.session.commit()
        flash('Asset added successfully.', 'success')
        return redirect(url_for('list_assets'))
    return render_template('asset_form.html', form=form, title='New Asset')


@app.route('/assets/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('asset.edit')
def edit_asset(id):
    asset = db.session.get(Asset, id) or abort(404)
    form = AssetForm(obj=asset)
    _set_asset_form_choices(form)
    cat = request.form.get('category') if request.method == 'POST' else asset.category
    _set_sub_category_choices(form, cat)
    if form.validate_on_submit():
        form.populate_obj(asset)
        asset.asset_tag_id = form.asset_tag_id.data or None
        asset.employee_id = form.employee_id.data or None
        asset.project_id = form.project_id.data or None
        if form.status.data == 'Disposed' and not asset.is_archived:
            asset.is_archived = True
            asset.employee_id = None
            asset.project_id = None
            flash('Asset was auto-archived due to Disposed status.', 'info')
        log_audit('update', 'Asset', asset.id, f'Updated Asset {asset.asset_tag_id or "(no tag)"}')
        db.session.commit()
        flash('Asset updated successfully.', 'success')
        return redirect(url_for('list_assets'))
    return render_template('asset_form.html', form=form, title='Edit Asset', asset=asset)


@app.route('/assets/<int:id>/delete', methods=['POST'])
@login_required
@permission_required('asset.delete')
def delete_asset(id):
    asset = db.session.get(Asset, id) or abort(404)
    tag = asset.asset_tag_id
    log_audit('delete', 'Asset', asset.id, f'Deleted Asset {tag}')
    db.session.delete(asset)
    db.session.commit()
    flash('Asset deleted.', 'success')
    return redirect(url_for('list_assets'))


@app.route('/assets/bulk-delete', methods=['POST'])
@login_required
@permission_required('asset.delete')
def bulk_delete_assets():
    ids = request.form.getlist('asset_id', type=int)
    if not ids:
        flash('No assets selected.', 'warning')
        return redirect(url_for('list_assets'))
    count = Asset.query.filter(Asset.id.in_(ids)).delete(synchronize_session=False)
    log_audit('bulk_delete', 'Asset', None, f'Bulk deleted {count} asset(s)')
    db.session.commit()
    flash(f'Deleted {count} asset(s).', 'success')
    return redirect(url_for('list_assets'))


@app.route('/assets/bulk-update', methods=['GET', 'POST'])
@login_required
@permission_required('asset.edit')
def bulk_update_assets():
    if request.method == 'POST':
        ids = request.form.getlist('asset_id')
        updated = 0
        new_status = request.form.get('new_status', '').strip()
        new_location = request.form.get('new_location', '').strip()
        new_department = request.form.get('new_department', '').strip()
        new_project_id = request.form.get('new_project_id', type=int)
        new_employee_id = request.form.get('new_employee_id', type=int)
        for aid in ids:
            asset = db.session.get(Asset, int(aid))
            if not asset:
                continue
            if new_status:
                asset.status = new_status
                if new_status == 'Disposed':
                    asset.is_archived = True
                    asset.employee_id = None
                    asset.project_id = None
            if new_location:
                asset.location = new_location
            if new_department:
                asset.department = new_department
            if new_project_id:
                asset.project_id = new_project_id
            if new_employee_id:
                asset.employee_id = new_employee_id
            updated += 1
        if updated:
            log_audit('bulk_update', 'Asset', None, f'Bulk updated {updated} asset(s)')
            db.session.commit()
            flash(f'Updated {updated} asset(s).', 'success')
        return redirect(url_for('list_assets'))
    ids = request.args.getlist('asset_id', type=int)
    if not ids:
        flash('No assets selected.', 'warning')
        return redirect(url_for('list_assets'))
    assets = Asset.query.filter(Asset.id.in_(ids)).order_by(Asset.asset_tag_id).all()
    projects = Project.query.order_by(Project.name).all()
    employees = Employee.query.order_by(Employee.first_name, Employee.last_name).all()
    return render_template('bulk_update_assets.html', assets=assets, projects=projects, employees=employees)


@app.route('/assets/<int:id>')
@login_required
def view_asset(id):
    asset = db.session.get(Asset, id) or abort(404)
    return render_template('asset_detail.html', asset=asset)


@app.route('/api/subcategories')
@login_required
def subcategories():
    category = request.args.get('category', '')
    subs = Asset.CATEGORIES.get(category, [])
    return jsonify(subs)


# --- Archive ---

@app.route('/assets/<int:id>/archive', methods=['POST'])
@login_required
@permission_required('asset.edit')
def archive_asset(id):
    asset = db.session.get(Asset, id) or abort(404)
    asset.is_archived = True
    asset.employee_id = None
    asset.project_id = None
    log_audit('archive', 'Asset', asset.id, f'Archived Asset {asset.asset_tag_id or "(no tag)"}')
    db.session.commit()
    flash('Asset archived.', 'success')
    return redirect(url_for('list_assets'))


@app.route('/assets/bulk-archive', methods=['POST'])
@login_required
@permission_required('asset.edit')
def bulk_archive_assets():
    ids = request.form.getlist('asset_id', type=int)
    if not ids:
        flash('No assets selected.', 'warning')
        return redirect(url_for('list_assets'))
    count = Asset.query.filter(Asset.id.in_(ids)).update(
        {Asset.is_archived: True, Asset.employee_id: None, Asset.project_id: None},
        synchronize_session=False
    )
    log_audit('bulk_archive', 'Asset', None, f'Bulk archived {count} asset(s)')
    db.session.commit()
    flash(f'Archived {count} asset(s).', 'success')
    return redirect(url_for('list_assets'))


@app.route('/archive')
@login_required
@permission_required('asset.view')
def list_archive():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    category = request.args.get('category', '')
    sub_category = request.args.get('type', '')

    query = Asset.query.filter(Asset.is_archived == True)
    if search:
        like = f'%{escape_like(search)}%'
        query = query.outerjoin(Employee).outerjoin(Project).filter(
            db.or_(
                Asset.serial_number.like(like, escape='\\'),
                Asset.asset_tag_id.like(like, escape='\\'),
                Asset.manufacturer.like(like, escape='\\'),
                Asset.model.like(like, escape='\\'),
                Employee.first_name.like(like, escape='\\'),
                Employee.last_name.like(like, escape='\\'),
            )
        )
    if category:
        query = query.filter_by(category=category)
    if sub_category:
        query = query.filter_by(sub_category=sub_category)

    query = query.order_by(Asset.updated_at.desc())
    pagination = query.paginate(page=page, per_page=50, error_out=False)
    assets = pagination.items
    return render_template('archive.html',
                           assets=assets,
                           pagination=pagination,
                           search=search,
                           filter_category=category,
                           filter_type=sub_category)


@app.route('/assets/<int:id>/restore', methods=['POST'])
@login_required
@permission_required('asset.edit')
def restore_asset(id):
    asset = db.session.get(Asset, id) or abort(404)
    asset.is_archived = False
    log_audit('restore', 'Asset', asset.id, f'Restored Asset {asset.asset_tag_id or "(no tag)"}')
    db.session.commit()
    flash('Asset restored.', 'success')
    return redirect(url_for('list_archive'))


@app.route('/assets/<int:id>/permanent-delete', methods=['POST'])
@login_required
@permission_required('asset.delete')
def permanent_delete_asset(id):
    asset = db.session.get(Asset, id) or abort(404)
    tag = asset.asset_tag_id
    log_audit('permanent_delete', 'Asset', asset.id, f'Permanently deleted Asset {tag}')
    db.session.delete(asset)
    db.session.commit()
    flash('Asset permanently deleted.', 'success')
    return redirect(url_for('list_archive'))


@app.route('/assets/bulk-permanent-delete', methods=['POST'])
@login_required
@permission_required('asset.delete')
def bulk_permanent_delete_assets():
    ids = request.form.getlist('asset_id', type=int)
    if not ids:
        flash('No assets selected.', 'warning')
        return redirect(url_for('list_archive'))
    count = Asset.query.filter(Asset.id.in_(ids)).delete(synchronize_session=False)
    log_audit('bulk_permanent_delete', 'Asset', None, f'Bulk permanently deleted {count} asset(s)')
    db.session.commit()
    flash(f'Permanently deleted {count} asset(s).', 'success')
    return redirect(url_for('list_archive'))


# --- Employees ---

@app.route('/employees')
@login_required
def list_employees():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    project_id = request.args.get('project', 0, type=int)
    query = Employee.query.outerjoin(Project)
    if search:
        like = f'%{escape_like(search)}%'
        query = query.filter(
            db.or_(
                Employee.first_name.like(like, escape='\\'),
                Employee.last_name.like(like, escape='\\'),
                Employee.email.like(like, escape='\\'),
                Employee.department.like(like, escape='\\'),
                Project.name.like(like, escape='\\'),
            )
        )
    if project_id:
        query = query.filter(Employee.project_id == project_id)
    query = query.order_by(Employee.first_name, Employee.last_name)
    pagination = query.paginate(page=page, per_page=50, error_out=False)
    employees = pagination.items
    projects = Project.query.order_by(Project.name).all()
    return render_template('employees.html', employees=employees, pagination=pagination, search=search, filter_project=project_id, projects=projects)


@app.route('/employees/new', methods=['GET', 'POST'])
@login_required
@permission_required('employee.create')
def new_employee():
    form = EmployeeForm()
    form.project_id.choices = [(0, '-- None --')] + [
        (p.id, p.name) for p in Project.query.order_by(Project.name).all()
    ]
    if form.validate_on_submit():
        employee = Employee(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            department=form.department.data,
            phone=form.phone.data,
            project_id=form.project_id.data or None,
            notes=form.notes.data,
        )
        db.session.add(employee)
        log_audit('create', 'Employee', employee.id, f'Created Employee {employee.name}')
        db.session.commit()
        flash('Employee added successfully.', 'success')
        return redirect(url_for('list_employees'))
    return render_template('employee_form.html', form=form, title='New Employee')


@app.route('/employees/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('employee.edit')
def edit_employee(id):
    employee = db.session.get(Employee, id) or abort(404)
    form = EmployeeForm(obj=employee)
    form.project_id.choices = [(0, '-- None --')] + [
        (p.id, p.name) for p in Project.query.order_by(Project.name).all()
    ]
    if form.validate_on_submit():
        form.populate_obj(employee)
        employee.project_id = form.project_id.data or None
        log_audit('update', 'Employee', employee.id, f'Updated Employee {employee.name}')
        db.session.commit()
        flash('Employee updated successfully.', 'success')
        return redirect(url_for('list_employees'))
    return render_template('employee_form.html', form=form, title='Edit Employee', employee=employee)


@app.route('/employees/<int:id>/delete', methods=['POST'])
@login_required
@permission_required('employee.delete')
def delete_employee(id):
    employee = db.session.get(Employee, id) or abort(404)
    asset_count = employee.assets.count()
    if asset_count > 0:
        flash(f'Cannot delete {employee.name}: they have {asset_count} asset(s) assigned. Reassign assets first.', 'danger')
        return redirect(url_for('list_employees'))
    name = employee.name
    log_audit('delete', 'Employee', employee.id, f'Deleted Employee {name}')
    db.session.delete(employee)
    db.session.commit()
    flash('Employee deleted.', 'success')
    return redirect(url_for('list_employees'))


@app.route('/employees/bulk-delete', methods=['POST'])
@login_required
@permission_required('employee.delete')
def bulk_delete_employees():
    ids = request.form.getlist('employee_id', type=int)
    if not ids:
        flash('No employees selected.', 'warning')
        return redirect(url_for('list_employees'))
    deleted = 0
    skipped = 0
    for eid in ids:
        emp = db.session.get(Employee, eid)
        if not emp:
            continue
        if emp.assets.count() > 0:
            skipped += 1
            continue
        db.session.delete(emp)
        deleted += 1
    log_audit('bulk_delete', 'Employee', None, f'Bulk deleted {deleted} employee(s), {skipped} skipped (have assets)')
    db.session.commit()
    msg = f'Deleted {deleted} employee(s).'
    if skipped:
        msg += f' {skipped} skipped (still have assets assigned).'
    flash(msg, 'success' if deleted else 'warning')
    return redirect(url_for('list_employees'))


@app.route('/employees/bulk-update', methods=['GET', 'POST'])
@login_required
@permission_required('employee.edit')
def bulk_update_employees():
    if request.method == 'POST':
        ids = request.form.getlist('emp_id')
        updated = 0
        new_department = request.form.get('new_department', '').strip()
        new_project_id = request.form.get('new_project_id', type=int)
        for eid in ids:
            emp = db.session.get(Employee, int(eid))
            if not emp:
                continue
            if new_department:
                emp.department = new_department
            if new_project_id:
                emp.project_id = new_project_id
            updated += 1
        if updated:
            log_audit('bulk_update', 'Employee', None, f'Bulk updated {updated} employee(s)')
            db.session.commit()
            flash(f'Updated {updated} employee(s).', 'success')
        return redirect(url_for('list_employees'))
    ids = request.args.getlist('employee_id', type=int)
    if not ids:
        flash('No employees selected.', 'warning')
        return redirect(url_for('list_employees'))
    employees = Employee.query.filter(Employee.id.in_(ids)).order_by(Employee.first_name, Employee.last_name).all()
    projects = Project.query.order_by(Project.name).all()
    return render_template('bulk_update_employees.html', employees=employees, projects=projects)


@app.route('/employees/<int:id>')
@login_required
def view_employee(id):
    employee = db.session.get(Employee, id) or abort(404)
    assets = employee.assets.order_by(Asset.updated_at.desc()).all()
    return render_template('employee_detail.html', employee=employee, assets=assets)


@app.route('/employees/import', methods=['GET', 'POST'])
@login_required
@permission_required('employee.import')
def import_employees():
    form = EmployeeImportForm()
    if form.validate_on_submit():
        f = form.csv_file.data
        stream = io.StringIO(f.stream.read().decode('utf-8-sig'), newline=None)
        reader = csv.DictReader(stream)
        added = 0
        errors = []
        for i, row in enumerate(reader, start=2):
            fn = row.get('First Name', '').strip()
            ln = row.get('Last Name', '').strip()
            if not fn and not ln:
                full = row.get('Name', '').strip()
                if not full:
                    errors.append(f'Row {i}: missing Name or First/Last Name')
                    continue
                parts = full.split(' ', 1)
                fn = parts[0]
                ln = parts[1] if len(parts) > 1 else ''
            if Employee.query.filter_by(first_name=fn, last_name=ln).first():
                errors.append(f'Row {i}: "{fn} {ln}" already exists')
                continue
            emp = Employee(
                first_name=fn,
                last_name=ln,
                email=row.get('Email', '').strip() or None,
                department=row.get('Department', '').strip() or None,
                phone=row.get('Phone', '').strip() or None,
                notes=row.get('Notes', '').strip() or None,
            )
            db.session.add(emp)
            added += 1
        log_audit('import', 'Employee', None, f'Imported {added} employee(s) from CSV')
        db.session.commit()
        msg = f'Imported {added} employee(s).'
        if errors:
            msg += f' {len(errors)} error(s): ' + '; '.join(errors[:5])
            if len(errors) > 5:
                msg += f' (+{len(errors)-5} more)'
        flash(msg, 'success' if not errors else 'warning')
        return redirect(url_for('list_employees'))
    return render_template('import_employees.html', form=form)


@app.route('/employees/bulk-edit', methods=['GET', 'POST'])
@login_required
@permission_required('employee.edit')
def bulk_edit_employees():
    if request.method == 'POST':
        ids = request.form.getlist('emp_id')
        updated = 0
        deleted = 0
        for eid in ids:
            emp = db.session.get(Employee, int(eid))
            if not emp:
                continue
            if request.form.get(f'delete_{eid}'):
                asset_count = emp.assets.count()
                if asset_count > 0:
                    flash(f'Cannot delete {emp.name}: they have {asset_count} asset(s).', 'danger')
                    continue
                db.session.delete(emp)
                deleted += 1
                continue
            emp.email = request.form.get(f'email_{eid}', '').strip() or None
            emp.phone = request.form.get(f'phone_{eid}', '').strip() or None
            emp.department = request.form.get(f'department_{eid}', '').strip() or None
            pid = request.form.get(f'project_{eid}', type=int)
            emp.project_id = pid or None
            updated += 1
        if updated or deleted:
            log_audit('bulk_update', 'Employee', None, f'Bulk updated {updated}, deleted {deleted} employee(s)')
            db.session.commit()
            flash(f'Updated {updated} employee(s), deleted {deleted}.', 'success')
        return redirect(url_for('list_employees'))
    employees = Employee.query.order_by(Employee.first_name, Employee.last_name).all()
    projects = Project.query.order_by(Project.name).all()
    return render_template('bulk_edit_employees.html', employees=employees, projects=projects)


@app.route('/employees/merge-duplicates', methods=['GET', 'POST'])
@login_required
@permission_required('employee.edit')
def merge_duplicates():
    if request.method == 'POST':
        master_id = request.form.get('master_id', type=int)
        merge_ids = request.form.getlist('merge_ids', type=int)
        if not master_id or not merge_ids:
            flash('Select a master and at least one duplicate to merge.', 'danger')
            return redirect(url_for('merge_duplicates'))
        master = db.session.get(Employee, master_id)
        if not master:
            flash('Master employee not found.', 'danger')
            return redirect(url_for('merge_duplicates'))
        merged = 0
        for eid in merge_ids:
            if eid == master_id:
                continue
            dup = db.session.get(Employee, eid)
            if not dup:
                continue
            dup.assets.update({'employee_id': master_id})
            db.session.delete(dup)
            merged += 1
        log_audit('merge', 'Employee', master_id, f'Merged {merged} duplicate(s) into {master.name}')
        db.session.commit()
        flash(f'Merged {merged} duplicate(s) into {master.name}.', 'success')
        return redirect(url_for('list_employees'))

    dupes = (db.session.query(Employee.first_name, Employee.last_name)
             .group_by(Employee.first_name, Employee.last_name)
             .having(db.func.count(Employee.id) > 1)
             .all())
    groups = []
    for fn, ln in dupes:
        emps = Employee.query.filter_by(first_name=fn, last_name=ln).order_by(Employee.id).all()
        groups.append(emps)
    return render_template('merge_duplicates.html', groups=groups)


# --- Projects ---

@app.route('/projects')
@login_required
def list_projects():
    search = request.args.get('search', '').strip()
    query = Project.query
    if search:
        like = f'%{search}%'
        query = query.filter(
            db.or_(
                Project.name.like(like),
                Project.department.like(like),
                Project.description.like(like),
            )
        )
    projects = query.order_by(Project.name).all()
    return render_template('projects.html', projects=projects, search=search)


@app.route('/projects/new', methods=['GET', 'POST'])
@login_required
@permission_required('project.create')
def new_project():
    form = ProjectForm()
    if form.validate_on_submit():
        project = Project(
            name=form.name.data,
            description=form.description.data,
            department=form.department.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            status=form.status.data,
            notes=form.notes.data,
        )
        db.session.add(project)
        log_audit('create', 'Project', project.id, f'Created Project {project.name}')
        db.session.commit()
        flash('Project added successfully.', 'success')
        return redirect(url_for('list_projects'))
    return render_template('project_form.html', form=form, title='New Project')


@app.route('/projects/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('project.edit')
def edit_project(id):
    project = db.session.get(Project, id) or abort(404)
    form = ProjectForm(obj=project)
    if form.validate_on_submit():
        form.populate_obj(project)
        log_audit('update', 'Project', project.id, f'Updated Project {project.name}')
        db.session.commit()
        flash('Project updated successfully.', 'success')
        return redirect(url_for('list_projects'))
    return render_template('project_form.html', form=form, title='Edit Project', project=project)


@app.route('/projects/<int:id>/delete', methods=['POST'])
@login_required
@permission_required('project.delete')
def delete_project(id):
    project = db.session.get(Project, id) or abort(404)
    asset_count = project.assets.count()
    if asset_count > 0:
        flash(f'Cannot delete "{project.name}": {asset_count} asset(s) are linked. Remove project from assets first.', 'danger')
        return redirect(url_for('list_projects'))
    name = project.name
    log_audit('delete', 'Project', project.id, f'Deleted Project {name}')
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted.', 'success')
    return redirect(url_for('list_projects'))


@app.route('/projects/<int:id>')
@login_required
def view_project(id):
    project = db.session.get(Project, id) or abort(404)
    assets = project.assets.order_by(Asset.updated_at.desc()).all()
    return render_template('project_detail.html', project=project, assets=assets)


@app.route('/projects/import', methods=['GET', 'POST'])
@login_required
@permission_required('project.import')
def import_projects():
    form = ProjectImportForm()
    if form.validate_on_submit():
        f = form.csv_file.data
        stream = io.StringIO(f.stream.read().decode('utf-8-sig'), newline=None)
        reader = csv.DictReader(stream)
        added = 0
        errors = []
        for i, row in enumerate(reader, start=2):
            name = row.get('Name', '').strip()
            if not name:
                errors.append(f'Row {i}: missing Name')
                continue
            if Project.query.filter_by(name=name).first():
                errors.append(f'Row {i}: "{name}" already exists')
                continue
            try:
                start = None
                if row.get('Start Date', '').strip():
                    start = datetime.strptime(row['Start Date'].strip(), '%Y-%m-%d').date()
            except ValueError:
                start = None
            try:
                end = None
                if row.get('End Date', '').strip():
                    end = datetime.strptime(row['End Date'].strip(), '%Y-%m-%d').date()
            except ValueError:
                end = None
            project = Project(
                name=name,
                description=row.get('Description', '').strip() or None,
                department=row.get('Department', '').strip() or None,
                start_date=start,
                end_date=end,
                status=row.get('Status', '').strip() or 'Active',
                notes=row.get('Notes', '').strip() or None,
            )
            db.session.add(project)
            added += 1
        log_audit('import', 'Project', None, f'Imported {added} project(s) from CSV')
        db.session.commit()
        msg = f'Imported {added} project(s).'
        if errors:
            msg += f' {len(errors)} error(s): ' + '; '.join(errors[:5])
            if len(errors) > 5:
                msg += f' (+{len(errors)-5} more)'
        flash(msg, 'success' if not errors else 'warning')
        return redirect(url_for('list_projects'))
    return render_template('import_projects.html', form=form)


# --- Import / Export ---

@app.route('/export/csv')
@login_required
@permission_required('asset.export')
def export_csv():
    search = request.args.get('search', '').strip()
    category = request.args.get('category', '')
    sub_category = request.args.get('type', '')
    status_filter = request.args.get('status', '')
    project_id = request.args.get('project', 0, type=int)

    query = Asset.query.outerjoin(Employee).outerjoin(Project)
    if search:
        like = f'%{search}%'
        query = query.filter(
            db.or_(
                Asset.serial_number.like(like),
                Asset.asset_tag_id.like(like),
                Employee.first_name.like(like),
                Employee.last_name.like(like),
                Project.name.like(like),
                Asset.manufacturer.like(like),
                Asset.model.like(like),
                Asset.location.like(like),
                Asset.department.like(like),
            )
        )
    if category:
        query = query.filter_by(category=category)
    if sub_category:
        query = query.filter_by(sub_category=sub_category)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if project_id:
        query = query.filter_by(project_id=project_id)

    assets = query.order_by(Asset.asset_tag_id).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Asset Tag ID', 'Category', 'Type', 'Serial Number', 'Assigned User',
        'Project', 'Manufacturer', 'Model', 'Status', 'Location', 'Department',
        'Purchase Date', 'Warranty Expiration', 'Notes',
    ])
    for a in assets:
        writer.writerow([
            a.asset_tag_id, a.category, a.sub_category, a.serial_number,
            a.assigned_user or '', a.project_name or '', a.manufacturer, a.model, a.status,
            a.location, a.department,
            a.purchase_date.strftime('%Y-%m-%d') if a.purchase_date else '',
            a.warranty_expiration.strftime('%Y-%m-%d') if a.warranty_expiration else '',
            a.notes or '',
        ])

    output.seek(0)
    return send_file(
        BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'assets_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
    )


@app.route('/import/csv', methods=['GET', 'POST'])
@login_required
@permission_required('asset.import')
def import_csv():
    form = AssetImportForm()
    if form.validate_on_submit():
        f = form.csv_file.data
        stream = io.StringIO(f.stream.read().decode('utf-8-sig'), newline=None)
        reader = csv.DictReader(stream)
        added = 0
        updated = 0
        errors = []
        for i, row in enumerate(reader, start=2):
            serial = row.get('Serial Number', '').strip()
            category = row.get('Category', '').strip()
            sub = row.get('Type', '').strip()
            if not all([serial, category, sub]):
                errors.append(f'Row {i}: missing required fields (Serial, Category, Type)')
                continue
            tag = row.get('Asset Tag ID', '').strip() or None
            existing = Asset.query.filter_by(serial_number=serial).first()
            if tag and existing and existing.asset_tag_id != tag and Asset.query.filter_by(asset_tag_id=tag).first():
                errors.append(f'Row {i}: Asset Tag ID "{tag}" already used by another asset')
                continue
            emp_name = row.get('Assigned User', '').strip()
            emp_id = None
            if emp_name:
                parts = emp_name.split(' ', 1)
                fn = parts[0]
                ln = parts[1] if len(parts) > 1 else ''
                emp = Employee.query.filter_by(first_name=fn, last_name=ln).first()
                if not emp:
                    emp = Employee(first_name=fn, last_name=ln)
                    db.session.add(emp)
                    db.session.flush()
                emp_id = emp.id
            proj_name = row.get('Project', '').strip()
            proj_id = None
            if proj_name:
                proj = Project.query.filter_by(name=proj_name).first()
                if not proj:
                    proj = Project(name=proj_name)
                    db.session.add(proj)
                    db.session.flush()
                proj_id = proj.id
            try:
                warranty = None
                if row.get('Warranty Expiration', '').strip():
                    warranty = datetime.strptime(row['Warranty Expiration'].strip(), '%Y-%m-%d').date()
            except ValueError:
                warranty = None
            try:
                purchase = None
                if row.get('Purchase Date', '').strip():
                    purchase = datetime.strptime(row['Purchase Date'].strip(), '%Y-%m-%d').date()
            except ValueError:
                purchase = None
            status_val = row.get('Status', '').strip() or 'In-Storage'
            is_disposed = status_val == 'Disposed'
            if existing:
                existing.asset_tag_id = tag
                existing.category = category
                existing.sub_category = sub
                existing.employee_id = None if is_disposed else emp_id
                existing.project_id = None if is_disposed else proj_id
                existing.manufacturer = row.get('Manufacturer', '').strip() or None
                existing.model = row.get('Model', '').strip() or None
                existing.status = status_val
                existing.location = row.get('Location', '').strip() or None
                existing.department = row.get('Department', '').strip() or None
                existing.purchase_date = purchase
                existing.warranty_expiration = warranty
                existing.notes = row.get('Notes', '').strip() or None
                if is_disposed and not existing.is_archived:
                    existing.is_archived = True
                updated += 1
            else:
                asset = Asset(
                    asset_tag_id=tag,
                    serial_number=serial,
                    category=category,
                    sub_category=sub,
                    employee_id=None if is_disposed else emp_id,
                    project_id=None if is_disposed else proj_id,
                    manufacturer=row.get('Manufacturer', '').strip() or None,
                    model=row.get('Model', '').strip() or None,
                    status=status_val,
                    location=row.get('Location', '').strip() or None,
                    department=row.get('Department', '').strip() or None,
                    purchase_date=purchase,
                    warranty_expiration=warranty,
                    notes=row.get('Notes', '').strip() or None,
                    is_archived=is_disposed,
                )
                db.session.add(asset)
                added += 1
        log_audit('import', 'Asset', None, f'Imported {added} new, updated {updated} asset(s) from CSV')
        db.session.commit()
        msg = f'Imported {added} new asset(s), updated {updated} existing.'
        if errors:
            msg += f' {len(errors)} error(s): ' + '; '.join(errors[:5])
            if len(errors) > 5:
                msg += f' (+{len(errors)-5} more)'
        flash(msg, 'success' if not errors else 'warning')
        return redirect(url_for('list_assets'))
    return render_template('import.html', form=form)


# --- CSV Templates ---

@app.route('/templates/assets.csv')
@login_required
def asset_template():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Asset Tag ID', 'Category', 'Type', 'Serial Number', 'Assigned User',
                     'Manufacturer', 'Model', 'Status', 'Location', 'Department',
                     'Purchase Date', 'Warranty Expiration', 'Notes'])
    writer.writerow(['', 'Workstation', 'Laptop', '', '', '', '', 'In-Storage', '', '', '', '', ''])
    output.seek(0)
    return send_file(
        BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='asset_import_template.csv',
    )


@app.route('/templates/employees.csv')
@login_required
def employee_template():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['First Name', 'Last Name', 'Email', 'Department', 'Phone', 'Notes'])
    writer.writerow(['', '', '', '', '', ''])
    output.seek(0)
    return send_file(
        BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='employee_import_template.csv',
    )


# --- Role Management ---

@app.route('/roles')
@login_required
@permission_required('role.manage')
def list_roles():
    roles = Role.query.order_by(Role.name).all()
    return render_template('roles.html', roles=roles)


@app.route('/roles/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('role.manage')
def edit_role(id):
    role = db.session.get(Role, id) or abort(404)
    form = RoleForm()
    if form.validate_on_submit():
        selected = request.form.getlist('permissions')
        role.set_permissions(selected)
        log_audit('update', 'Role', role.id, f'Updated permissions for role {role.name}')
        db.session.commit()
        flash(f'Permissions for "{role.name}" updated successfully.', 'success')
        return redirect(url_for('list_roles'))
    return render_template('role_form.html', form=form, role=role)


# --- User Management ---

@app.route('/users')
@login_required
@permission_required('user.manage')
def list_users():
    users = User.query.order_by(User.username).all()
    return render_template('users.html', users=users)


@app.route('/users/new', methods=['GET', 'POST'])
@login_required
@permission_required('user.manage')
def new_user():
    form = UserForm()
    if form.validate_on_submit():
        try:
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already taken.', 'danger')
                return render_template('user_form.html', form=form, title='New User')
            if form.email.data and User.query.filter_by(email=form.email.data).first():
                flash('Email already registered.', 'danger')
                return render_template('user_form.html', form=form, title='New User')
            extra = request.form.getlist('extra_permissions')
            user = User(
                username=form.username.data,
                email=form.email.data or None,
                name=form.name.data,
                role=form.role.data,
            )
            user.set_password(form.password.data or 'changeme')
            user.set_extra_permissions(extra)
            db.session.add(user)
            db.session.flush()
            log_audit('create', 'User', user.id, f'Created User {user.username} ({user.role})')
            db.session.commit()
            flash('User created successfully.', 'success')
            return redirect(url_for('list_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'danger')
    return render_template('user_form.html', form=form, title='New User')


@app.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('user.manage')
def edit_user(id):
    user = db.session.get(User, id) or abort(404)
    form = UserForm(obj=user)
    if form.validate_on_submit():
        if form.username.data != user.username and User.query.filter_by(username=form.username.data).first():
            flash('Username already taken.', 'danger')
            return render_template('user_form.html', form=form, title='Edit User', user=user)
        if form.email.data and form.email.data != user.email and User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return render_template('user_form.html', form=form, title='Edit User', user=user)
        user.username = form.username.data
        user.email = form.email.data or None
        user.name = form.name.data
        user.role = form.role.data
        extra = request.form.getlist('extra_permissions')
        user.set_extra_permissions(extra)
        if form.password.data:
            user.set_password(form.password.data)
        log_audit('update', 'User', user.id, f'Updated User {user.username} ({user.role})')
        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('list_users'))
    return render_template('user_form.html', form=form, title='Edit User', user=user)


# --- Audit Log ---

@app.route('/audit-log')
@login_required
@permission_required('audit.view')
def audit_log():
    page = request.args.get('page', 1, type=int)
    action = request.args.get('action', '')
    entity = request.args.get('entity', '')

    query = AuditLog.query
    if action:
        query = query.filter_by(action=action)
    if entity:
        query = query.filter_by(entity_type=entity)
    query = query.order_by(AuditLog.timestamp.desc())
    pagination = query.paginate(page=page, per_page=50, error_out=False)
    logs = pagination.items

    actions = db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()
    entities = db.session.query(AuditLog.entity_type).distinct().order_by(AuditLog.entity_type).all()

    return render_template('audit_log.html',
                           logs=logs,
                           pagination=pagination,
                           filter_action=action,
                           filter_entity=entity,
                           actions=[a[0] for a in actions],
                           entities=[e[0] for e in entities])


# --- Settings ---

def is_sso_enabled():
    return Setting.get_bool('sso_enabled', False)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
@permission_required('user.manage')
def settings():
    if request.method == 'POST':
        Setting.set('sso_enabled', request.form.get('sso_enabled', 'false'))
        Setting.set('sso_provider', request.form.get('sso_provider', ''))
        Setting.set('okta_client_id', request.form.get('okta_client_id', ''))
        Setting.set('okta_client_secret', request.form.get('okta_client_secret', ''))
        Setting.set('okta_domain', request.form.get('okta_domain', ''))
        Setting.set('okta_auth_server', request.form.get('okta_auth_server', 'default'))
        Setting.set('entra_client_id', request.form.get('entra_client_id', ''))
        Setting.set('entra_client_secret', request.form.get('entra_client_secret', ''))
        Setting.set('entra_tenant_id', request.form.get('entra_tenant_id', ''))
        Setting.set('smtp_host', request.form.get('smtp_host', ''))
        Setting.set('smtp_port', request.form.get('smtp_port', '587'))
        Setting.set('smtp_user', request.form.get('smtp_user', ''))
        smtp_pass = request.form.get('smtp_password', '')
        if smtp_pass:
            Setting.set('smtp_password', smtp_pass)
        Setting.set('smtp_from_name', request.form.get('smtp_from_name', 'IT Asset Manager'))
        flash('Settings saved.', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html',
        sso_enabled=Setting.get_bool('sso_enabled', False),
        sso_provider=Setting.get('sso_provider', ''),
        okta_client_id=Setting.get('okta_client_id', ''),
        okta_client_secret=Setting.get('okta_client_secret', ''),
        okta_domain=Setting.get('okta_domain', ''),
        okta_auth_server=Setting.get('okta_auth_server', 'default'),
        entra_client_id=Setting.get('entra_client_id', ''),
        entra_client_secret=Setting.get('entra_client_secret', ''),
        entra_tenant_id=Setting.get('entra_tenant_id', ''),
        smtp_host=Setting.get('smtp_host', ''),
        smtp_port=Setting.get('smtp_port', '587'),
        smtp_user=Setting.get('smtp_user', ''),
        smtp_password=Setting.get('smtp_password', ''),
        smtp_from_name=Setting.get('smtp_from_name', 'IT Asset Manager'),
    )


# --- Email Service ---

def send_invite_email(to_email, name, invite_url):
    smtp_host = Setting.get('smtp_host')
    smtp_port = int(Setting.get('smtp_port', '587'))
    smtp_user = Setting.get('smtp_user')
    smtp_password = Setting.get('smtp_password')
    from_name = Setting.get('smtp_from_name', 'IT Asset Manager')

    if not all([smtp_host, smtp_user, smtp_password]):
        return False, 'SMTP not configured'

    msg = MIMEMultipart()
    msg['From'] = f'{from_name} <{smtp_user}>'
    msg['To'] = to_email
    msg['Subject'] = f'You\'re invited to {from_name}'

    msg.attach(MIMEText(f'''
Hello {name},

You have been invited to access the IT Asset Manager.

Click the link below to set your password and activate your account:

{invite_url}

This link expires in 7 days.

If you did not expect this invitation, please ignore this email.
''', 'plain'))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        return True, 'Email sent'
    except Exception as e:
        return False, str(e)


# --- User Invites ---

@app.route('/users/invite', methods=['GET', 'POST'])
@login_required
@permission_required('user.manage')
def invite_user():
    form = InviteForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('A user with this email already exists.', 'danger')
            return render_template('invite_form.html', form=form, title='Invite User')

        existing_invite = Invite.query.filter_by(email=form.email.data, is_used=False).first()
        if existing_invite and not existing_invite.is_expired():
            flash('An active invite already exists for this email.', 'warning')
            return render_template('invite_form.html', form=form, title='Invite User')

        invite = Invite(
            email=form.email.data,
            name=form.name.data,
            role=form.role.data,
        )
        db.session.add(invite)
        db.session.commit()

        invite_url = url_for('accept_invite', token=invite.token, _external=True)

        success, message = send_invite_email(invite.email, invite.name, invite_url)
        if success:
            flash(f'Invite sent to {invite.email}.', 'success')
        else:
            flash(f'Email could not be sent: {message}. Share this link manually:', 'warning')
            flash(invite_url, 'info')

        log_audit('invite_user', 'User', invite.id, f'Invited {invite.email} as {invite.role}')
        db.session.commit()
        return redirect(url_for('list_users'))

    return render_template('invite_form.html', form=form, title='Invite User')


@app.route('/invite/<token>')
def accept_invite(token):
    invite = Invite.query.filter_by(token=token).first()
    if not invite:
        flash('Invalid invitation link.', 'danger')
        return redirect(url_for('login'))

    if not invite.is_valid():
        flash('This invitation has expired or already been used.', 'danger')
        return redirect(url_for('login'))

    form = AcceptInviteForm()
    if form.validate_on_submit():
        user = User(
            username=invite.email.split('@')[0],
            email=invite.email,
            name=invite.name,
            role=invite.role,
        )
        user.set_password(form.password.data)

        base_username = user.username
        counter = 1
        while User.query.filter_by(username=user.username).first():
            user.username = f'{base_username}{counter}'
            counter += 1

        db.session.add(user)
        invite.is_used = True
        log_audit('accept_invite', 'User', user.id, f'{user.username} accepted invitation')
        db.session.commit()

        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('accept_invite.html', form=form, invite=invite)


# --- Error Handlers ---

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG', '0') == '1')
