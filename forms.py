from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, SelectField, DateField, TextAreaField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Optional, Email, EqualTo, Length, ValidationError


class PasswordStrength:
    """Validate password strength with minimum requirements."""
    def __init__(self, min_length=8, require_upper=True, require_lower=True,
                 require_digit=True, require_special=False):
        self.min_length = min_length
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digit = require_digit
        self.require_special = require_special

    def __call__(self, form, field):
        if not field.data:
            return
        password = field.data
        errors = []
        if len(password) < self.min_length:
            errors.append(f'at least {self.min_length} characters')
        if self.require_upper and not any(c.isupper() for c in password):
            errors.append('an uppercase letter')
        if self.require_lower and not any(c.islower() for c in password):
            errors.append('a lowercase letter')
        if self.require_digit and not any(c.isdigit() for c in password):
            errors.append('a digit')
        if self.require_special and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            errors.append('a special character')
        if errors:
            raise ValidationError('Password must contain ' + ', '.join(errors) + '.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), PasswordStrength()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')])
    submit = SubmitField('Change Password')


class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[Optional(), Email()])
    name = StringField('Full Name', validators=[Optional()])
    password = PasswordField('Password', validators=[Optional(), PasswordStrength()])
    role = SelectField('Role', choices=[
        ('Viewer', 'Viewer'),
        ('Editor', 'Editor'),
        ('Admin', 'Admin'),
    ], default='Viewer')
    submit = SubmitField('Save')


class RoleForm(FlaskForm):
    submit = SubmitField('Save Permissions')


class AssetForm(FlaskForm):
    category = SelectField('Category', choices=[
        ('', '-- Select --'),
        ('Workstation', 'Workstation'),
        ('Network Device', 'Network Device'),
        ('Printer', 'Printer'),
        ('Monitor', 'Monitor'),
        ('Docking Station', 'Docking Station'),
    ], validators=[DataRequired()])
    sub_category = SelectField('Type', choices=[('', '-- Select category first --')], validators=[DataRequired()])
    serial_number = StringField('Serial Number', validators=[DataRequired()])
    asset_tag_id = StringField('Asset Tag ID')
    employee_id = SelectField('Assigned User', coerce=int, validators=[Optional()])
    project_id = SelectField('Project', coerce=int, validators=[Optional()])
    warranty_expiration = DateField('Warranty Expiration', validators=[Optional()], format='%Y-%m-%d')
    purchase_date = DateField('Purchase Date', validators=[Optional()], format='%Y-%m-%d')
    manufacturer = StringField('Manufacturer', validators=[Optional()])
    model = StringField('Model', validators=[Optional()])
    location = StringField('Location', validators=[Optional()])
    department = StringField('Department', validators=[Optional()])
    status = SelectField('Status', choices=[
        ('In-Storage', 'In-Storage'),
        ('Assigned', 'Assigned'),
        ('Deployed', 'Deployed'),
        ('In Repair', 'In Repair'),
        ('Retired', 'Retired'),
        ('Disposed', 'Disposed'),
    ], default='In-Storage')
    notes = TextAreaField('Notes', validators=[Optional()])
    submit = SubmitField('Save')


class EmployeeForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[Optional(), Email()])
    department = StringField('Department', validators=[Optional()])
    phone = StringField('Phone', validators=[Optional()])
    project_id = SelectField('Project', coerce=int, validators=[Optional()])
    notes = TextAreaField('Notes', validators=[Optional()])
    submit = SubmitField('Save')


class ProjectForm(FlaskForm):
    name = StringField('Project Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    department = StringField('Department', validators=[Optional()])
    start_date = DateField('Start Date', validators=[Optional()], format='%Y-%m-%d')
    end_date = DateField('End Date', validators=[Optional()], format='%Y-%m-%d')
    status = SelectField('Status', choices=[
        ('Active', 'Active'),
        ('Completed', 'Completed'),
        ('On Hold', 'On Hold'),
        ('Cancelled', 'Cancelled'),
    ], default='Active')
    notes = TextAreaField('Notes', validators=[Optional()])
    submit = SubmitField('Save')


class AssetImportForm(FlaskForm):
    csv_file = FileField('CSV File', validators=[
        FileRequired(),
        FileAllowed(['csv'], 'CSV files only'),
    ])
    submit = SubmitField('Import')


class EmployeeImportForm(FlaskForm):
    csv_file = FileField('CSV File', validators=[
        FileRequired(),
        FileAllowed(['csv'], 'CSV files only'),
    ])
    submit = SubmitField('Import')


class ProjectImportForm(FlaskForm):
    csv_file = FileField('CSV File', validators=[
        FileRequired(),
        FileAllowed(['csv'], 'CSV files only'),
    ])
    submit = SubmitField('Import')


class InviteForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    name = StringField('Full Name', validators=[DataRequired()])
    role = SelectField('Role', choices=[
        ('Viewer', 'Viewer'),
        ('Editor', 'Editor'),
        ('Admin', 'Admin'),
    ], default='Viewer')
    submit = SubmitField('Send Invite')


class AcceptInviteForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), PasswordStrength()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Set Password & Activate Account')
