import os
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, current_app, send_from_directory, session
import flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, UserMixin, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import urlparse, quote_plus
from functools import wraps
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, IntegerField, MultipleFileField
from wtforms.widgets import TextArea as TextAreaWidget
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, Optional, NumberRange, InputRequired
import logging
from markupsafe import escape, Markup
import re
import uuid
from flask_mail import Mail, Message
import sys
from importlib.metadata import version, PackageNotFoundError

from itertools import groupby
from datetime import date


# Twilio Integration
from twilio.rest import Client as TwilioClient
from twilio.base.exceptions import TwilioRestException

# --- Global Constants for Form Choices ---
AWS_SERVICE_CHOICES = [
    ('', '--- Select AWS Service (if AWS) ---'),
    ('EC2', 'EC2 - Elastic Compute Cloud'), ('S3', 'S3 - Simple Storage Service'),
    ('RDS', 'RDS - Relational Database Service'), ('Lambda', 'Lambda - Serverless Compute'),
    ('VPC', 'VPC - Virtual Private Cloud'), ('Route53', 'Route 53 - DNS Service'),
    ('IAM', 'IAM - Identity & Access Management'), ('CloudFront', 'CloudFront - CDN'),
    ('Other', 'Other AWS Service'),
]
TICKET_STATUS_CHOICES = [('Open', 'Open'), ('In Progress', 'In Progress'), ('On Hold', 'On Hold'), ('Resolved', 'Resolved'), ('Closed', 'Closed')]
TICKET_PRIORITY_CHOICES = [('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High'), ('Urgent', 'Urgent')]

def to_snake_case(name):
    name = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', name)
    name = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name).lower()
    if name.endswith("_option"): name = name[:-7]
    elif name.endswith("option"): name = name[:-6]
    return name

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ticket-cms-agent-views-final-key-secure'
    MYSQL_USER = os.environ.get('MYSQL_USER_TICKET_CMS') or 'ticket_user'
    _raw_mysql_password = os.environ.get('MYSQL_PASSWORD_TICKET_CMS') or 'Jodha@123'
    MYSQL_PASSWORD_ENCODED = quote_plus(_raw_mysql_password) if _raw_mysql_password else ''
    MYSQL_HOST = os.environ.get('MYSQL_HOST_TICKET_CMS') or 'localhost'
    MYSQL_DB = os.environ.get('MYSQL_DB_TICKET_CMS') or 'ticket_cms_db'
    MYSQL_CHARSET = 'utf8mb4'
    APPLICATION_ROOT = '/'

    if not all([MYSQL_USER, _raw_mysql_password, MYSQL_HOST, MYSQL_DB]):
        print("FATAL ERROR: Missing critical MySQL configuration.")
        SQLALCHEMY_DATABASE_URI = None
    else:
        SQLALCHEMY_DATABASE_URI = (
            f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD_ENCODED}@"
            f"{MYSQL_HOST}/{MYSQL_DB}?charset={MYSQL_CHARSET}"
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = os.environ.get('SQLALCHEMY_ECHO', 'False').lower() in ['true', '1', 't']

    MAIL_SERVER = os.environ.get('MAIL_SERVER_TICKET_CMS') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT_TICKET_CMS') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS_TICKET_CMS', 'true').lower() in ['true', '1', 't']
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL_TICKET_CMS', 'false').lower() in ['true', '1', 't']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME_TICKET_CMS') or 'monish.jodha@cloudkeeper.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD_TICKET_CMS') or 'tuvljncwusoodplx'
    MAIL_DEFAULT_SENDER_EMAIL = os.environ.get('MAIL_DEFAULT_SENDER_EMAIL_TICKET_CMS') or MAIL_USERNAME
    MAIL_DEFAULT_SENDER = ('TicketSys Admin', MAIL_DEFAULT_SENDER_EMAIL or 'noreply@example.com') # Added default
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL_TICKET_CMS')

    IMAP_SERVER = os.environ.get('IMAP_SERVER_TICKET_CMS_FETCH') or 'imap.gmail.com'
    IMAP_USERNAME = os.environ.get('IMAP_USERNAME_TICKET_CMS_FETCH')
    IMAP_PASSWORD = os.environ.get('IMAP_PASSWORD_TICKET_CMS_FETCH') or 'placeholder16apppass'
    IMAP_MAILBOX_FOLDER = os.environ.get('IMAP_MAILBOX_FOLDER_TICKET_CMS_FETCH') or 'INBOX'
    EMAIL_TICKET_DEFAULT_CATEGORY_NAME = os.environ.get('EMAIL_TICKET_DEFAULT_CATEGORY_NAME') or 'General Inquiry'
    EMAIL_TICKET_DEFAULT_SEVERITY_NAME = os.environ.get('EMAIL_TICKET_DEFAULT_SEVERITY_NAME') or 'Severity 3 (Medium)'

    BASE_URL = os.environ.get('BASE_URL') or 'http://localhost:5000'
    _parsed_base = urlparse(BASE_URL)
    SERVER_NAME = os.environ.get('SERVER_NAME') or _parsed_base.netloc
    parsed_path = _parsed_base.path.strip()
    # APPLICATION_ROOT = os.environ.get('APPLICATION_ROOT') or (parsed_path if parsed_path.startswith('/') else '/') # Already set
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME') or _parsed_base.scheme or 'http'

    # UPLOAD_FOLDER: Check environment variable. If not set, default to 'uploads' dir in project.
    # The error "/path/to/your/uploads" strongly suggests the ENV VAR is set to this literal string.
    _default_upload_folder = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', _default_upload_folder)
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'log', 'csv'}
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH') or 16 * 1000 * 1000)

    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID_TICKET_CMS')
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN_TICKET_CMS')
    TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER_TICKET_CMS')
    EMERGENCY_CALL_RECIPIENT_PHONE_NUMBER = os.environ.get('EMERGENCY_CALL_RECIPIENT_PHONE_NUMBER_TICKET_CMS')
    SEVERITIES_FOR_CALL_ALERT = ["Severity 1 (Critical)", "Severity 2 (High)"]

app = Flask(__name__)
app.config.from_object(Config)
app.jinja_env.add_extension('jinja2.ext.do')

# Logging setup
logging.basicConfig(level=logging.INFO) # Basic config for root logger
app.logger.setLevel(logging.INFO) # Flask app logger level

app.logger.info(f"--- App Initialization ---")
app.logger.info(f"Configured UPLOAD_FOLDER: {app.config['UPLOAD_FOLDER']}")
if app.config['UPLOAD_FOLDER'] == "/path/to/your/uploads":
    app.logger.warning("UPLOAD_FOLDER is set to '/path/to/your/uploads'. This is a placeholder and likely incorrect. "
                       "Please unset the UPLOAD_FOLDER environment variable or set it to a valid writable path.")

# Ensure upload folder exists (moved here to run once after config)
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        app.logger.info(f"Upload folder ensured/created: {app.config['UPLOAD_FOLDER']}")
    except OSError as e:
        app.logger.error(f"Could not create upload folder {app.config['UPLOAD_FOLDER']}: {e}. Check permissions and path.")
        # This error might prevent app from fully working if uploads are critical.

if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError("SQLALCHEMY_DATABASE_URI is not configured. Application cannot start.")

csrf = CSRFProtect(app)
mail = Mail(app)
db = SQLAlchemy(app) # Initialize db after app and config

# nl2br filter
def nl2br_filter(value):
    if not isinstance(value, str): value = str(value)
    escaped_value = escape(value)
    br_value = re.sub(r'(\r\n|\r|\n)', '<br>\n', escaped_value)
    return Markup(br_value)
app.jinja_env.filters['nl2br'] = nl2br_filter

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- Models (Interaction model included here) ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default='client', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tickets_created = db.relationship('Ticket', foreign_keys='Ticket.created_by_id', backref='creator', lazy='dynamic')
    tickets_assigned = db.relationship('Ticket', foreign_keys='Ticket.assigned_to_id', backref='assignee', lazy='dynamic')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash or "", password)
    @property
    def is_admin(self): return self.role == 'admin'
    @property
    def is_agent(self): return self.role == 'agent'
    @property
    def is_client(self): return self.role == 'client'
    def __repr__(self): return f'<User {self.username} ({self.role})>'

class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    tickets = db.relationship('Ticket', backref='category_ref', lazy='dynamic')
    def __repr__(self): return f'<Category {self.name}>'

class CloudProviderOption(db.Model):
    __tablename__ = 'cloud_provider_options'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    def __repr__(self): return f'<CloudProviderOption {self.name}>'

class SeverityOption(db.Model):
    __tablename__ = 'severity_options'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    description = db.Column(db.String(100), nullable=True)
    order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    def __repr__(self): return f'<SeverityOption {self.name}>'

class EnvironmentOption(db.Model):
    __tablename__ = 'environment_options'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    def __repr__(self): return f'<EnvironmentOption {self.name}>'

class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open', nullable=False)
    priority = db.Column(db.String(20), default='Medium', nullable=False)
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, index=True, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=True)
    cloud_provider = db.Column(db.String(50), nullable=True)
    severity = db.Column(db.String(50), nullable=True)
    aws_service = db.Column(db.String(100), nullable=True)
    aws_account_id = db.Column(db.String(20), nullable=True)
    environment = db.Column(db.String(50), nullable=True)
    comments = db.relationship('Comment', backref='ticket_ref', lazy='dynamic', cascade="all, delete-orphan")
    def __repr__(self): return f'<Ticket {self.id}: {self.title}>'

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    is_internal = db.Column(db.Boolean, default=False)
    def __repr__(self): return f'<Comment {self.id} on Ticket {self.ticket_id}>'

class Attachment(db.Model):
    __tablename__ = 'attachments'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    content_type = db.Column(db.String(100), nullable=True)
    ticket = db.relationship('Ticket', backref=db.backref('ticket_attachments', lazy='dynamic', cascade="all, delete-orphan"))
    uploader = db.relationship('User', backref='uploaded_attachments_ref')
    def __repr__(self): return f'<Attachment {self.filename} for Ticket {self.ticket_id}>'

class Interaction(db.Model):
    __tablename__ = 'interactions'
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    interaction_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    details = db.Column(db.JSON, nullable=True)
    ticket = db.relationship('Ticket', backref=db.backref('interactions_rel', lazy='dynamic', cascade="all, delete-orphan"))
    user = db.relationship('User', backref='interactions_rel')
    def __repr__(self): return f'<Interaction {self.id} on Ticket {self.ticket_id} - {self.interaction_type}>'

# --- Forms (definition remains the same) ---
# ... (LoginForm, AdminUserForm, etc. ... All form classes are here) ...
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=64)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AdminUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password (leave blank to keep current)', validators=[Optional(), Length(min=6)])
    password2 = PasswordField('Confirm Password', validators=[EqualTo('password', message='Passwords must match if new password provided.')])
    role = SelectField('Role', choices=[('client', 'Client'), ('agent', 'Agent'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Save User')

class UserSelfRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email Address', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create Account')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('That username is already taken. Please choose a different one.')
    def validate_email(self, email_field):
        email_data = email_field.data.lower()
        if User.query.filter_by(email=email_data).first():
            raise ValidationError('That email address is already registered.')

class CreateTicketForm(FlaskForm):
    title = StringField('Subject*', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description*', validators=[DataRequired()])
    category = SelectField('Issue Category*', coerce=int, validators=[InputRequired(message="Category is required.")])
    cloud_provider = SelectField('Cloud Provider', coerce=str, validators=[Optional()])
    severity = SelectField('Severity Level*', coerce=str, validators=[InputRequired(message="Severity is required.")])
    aws_service = SelectField('AWS Service (if AWS selected)', choices=AWS_SERVICE_CHOICES, validators=[Optional()])
    aws_account_id = StringField('AWS Account ID', validators=[Optional(), Length(max=12)])
    environment = SelectField('Environment', coerce=str, validators=[Optional()])
    additional_recipients = StringField('Additional Email Recipients (comma-separated)', widget=TextAreaWidget(), validators=[Optional()])
    attachments = MultipleFileField('Attachments', validators=[Optional()])
    submit = SubmitField('Submit Ticket')

    def validate_additional_recipients(form, field):
        if field.data:
            emails = [email.strip() for email in field.data.split(',') if email.strip()]
            for email_str in emails:
                if '@' not in email_str or '.' not in email_str.split('@')[1]:
                    raise ValidationError(f"Invalid email address format: {email_str}")

class CommentForm(FlaskForm):
    content = TextAreaField('Your Comment', validators=[DataRequired()])
    is_internal = BooleanField('Internal Note (Agents/Admins Only)')
    submit = SubmitField('Add Comment')

class AgentUpdateTicketForm(FlaskForm):
    status = SelectField('Status', choices=TICKET_STATUS_CHOICES, validators=[DataRequired()])
    priority = SelectField('Priority', choices=TICKET_PRIORITY_CHOICES, validators=[DataRequired()])
    assigned_to_id = SelectField('Assign To Agent', coerce=int, validators=[Optional()])
    category_id = SelectField('Category', coerce=int, validators=[Optional()])
    cloud_provider = SelectField('Cloud Provider', coerce=str, validators=[Optional()])
    severity = SelectField('Severity', coerce=str, validators=[Optional()])
    aws_service = SelectField('AWS Service', choices=AWS_SERVICE_CHOICES, validators=[Optional()])
    aws_account_id = StringField('AWS Account ID', validators=[Optional(), Length(max=12)])
    environment = SelectField('Environment', coerce=str, validators=[Optional()])
    submit = SubmitField('Update Ticket')

class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired(), Length(max=50)])
    description = StringField('Description', validators=[Optional(), Length(max=200)])
    submit = SubmitField('Save Category')

class CloudProviderOptionForm(FlaskForm):
    name = StringField('Cloud Provider Name', validators=[DataRequired(), Length(max=50)])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Cloud Provider')

class SeverityOptionForm(FlaskForm):
    name = StringField('Severity Name', validators=[DataRequired(), Length(max=50)])
    description = StringField('Description (Optional)', validators=[Optional(), Length(max=100)])
    order = IntegerField('Sort Order (Optional, e.g., 1, 2)', validators=[Optional(), NumberRange(min=0)])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Severity')

class EnvironmentOptionForm(FlaskForm):
    name = StringField('Environment Name', validators=[DataRequired(), Length(max=50)])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Environment')

class ShareCredentialsForm(FlaskForm):
    recipient_email = StringField('Recipient Email', validators=[DataRequired(), Email()])


# --- Flask-Login, Context Processors, Decorators (remains the same) ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "Please log in to access this page."

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

@app.context_processor
def inject_global_vars(): return {'current_year': datetime.utcnow().year, 'app': app}

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Admin access is required to view this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def agent_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not (current_user.is_agent or current_user.is_admin):
            flash('Agent or Admin access is required to view this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helper functions for dynamic choices (remains the same) ---
def get_active_cloud_provider_choices():
    return [('', '--- Select Cloud Provider ---')] + [(p.name, p.name) for p in CloudProviderOption.query.filter_by(is_active=True).order_by(CloudProviderOption.name).all()]
def get_active_severity_choices():
    return [('', '--- Select Severity* ---')] + [(opt.name, opt.name) for opt in SeverityOption.query.filter_by(is_active=True).order_by(SeverityOption.order, SeverityOption.name).all()]
def get_active_environment_choices():
    return [('', '--- Select Environment ---')] + [(opt.name, opt.name) for opt in EnvironmentOption.query.filter_by(is_active=True).order_by(EnvironmentOption.name).all()]

# Interaction Log Helper
def log_interaction(ticket_id, interaction_type, user_id=None, details=None, timestamp_override=None, commit_now=False):
    actual_user_id = user_id
    if actual_user_id is None and current_user and current_user.is_authenticated:
        actual_user_id = current_user.id
    interaction_timestamp = timestamp_override if timestamp_override else datetime.utcnow()
    interaction = Interaction(ticket_id=ticket_id, user_id=actual_user_id, interaction_type=interaction_type, details=details or {}, timestamp=interaction_timestamp)
    db.session.add(interaction)
    if commit_now:
        try: db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Failed to commit interaction log: {e}")

# Twilio Helper (remains the same)
def trigger_priority_call_alert(ticket, old_severity=None):
    # ... (implementation as before) ...
    account_sid = app.config.get('TWILIO_ACCOUNT_SID')
    auth_token = app.config.get('TWILIO_AUTH_TOKEN')
    twilio_phone_number = app.config.get('TWILIO_PHONE_NUMBER')
    recipient_phone_number = app.config.get('EMERGENCY_CALL_RECIPIENT_PHONE_NUMBER')
    alert_severities = app.config.get('SEVERITIES_FOR_CALL_ALERT', [])
    new_severity = ticket.severity

    if not all([account_sid, auth_token, twilio_phone_number, recipient_phone_number]):
        app.logger.warning(f"Twilio credentials or recipient number not fully configured. Skipping call alert for ticket #{ticket.id}.")
        return
    if new_severity not in alert_severities:
        app.logger.info(f"Ticket #{ticket.id} new severity '{new_severity}' does not trigger call alert. Skipping.")
        return
    if old_severity is not None and old_severity == new_severity and new_severity in alert_severities:
        app.logger.info(f"Ticket #{ticket.id} severity '{new_severity}' remains unchanged and high. No new call alert needed.")
        return
    app.logger.info(f"Ticket #{ticket.id} severity change triggers call alert. Old: '{old_severity}', New: '{new_severity}'.")
    try:
        client = TwilioClient(account_sid, auth_token)
        sanitized_title = re.sub(r'[^\w\s,.-]', '', ticket.title)
        if old_severity is None or old_severity not in alert_severities: alert_reason = "created"
        else: alert_reason = f"updated from {old_severity} to {new_severity}"
        message_to_say = (f"Hello. This is an urgent alert from the Ticket System. A high priority ticket, number {ticket.id}, has been {alert_reason}. Severity is now {new_severity}. Subject: {sanitized_title}. Please check the system immediately.")
        twiml_instruction = f'<Response><Say>{escape(message_to_say)}</Say></Response>'
        call = client.calls.create(twiml=twiml_instruction, to=recipient_phone_number, from_=twilio_phone_number)
        app.logger.info(f"Twilio call initiated for ticket #{ticket.id} to {recipient_phone_number}. Call SID: {call.sid}")
        flash(f'High priority ticket #{ticket.id} alert ({alert_reason}): Call initiated to {recipient_phone_number}.', 'info')
    except TwilioRestException as e:
        app.logger.error(f"Twilio API error for ticket #{ticket.id}: {e}")
        flash(f'Error initiating Twilio call for ticket #{ticket.id}: {e.message}', 'danger')
    except Exception as e:
        app.logger.error(f"Unexpected error during Twilio call for ticket #{ticket.id}: {e}")
        flash(f'An unexpected error occurred while trying to initiate a call for ticket #{ticket.id}.', 'danger')

# --- Routes (updated sections are marked) ---
@app.route('/')
@app.route('/index')
def index():
    # ... (same as before) ...
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template('index.html', title='Welcome')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (same as before) ...
    app.logger.info(f"--- Login Route (Top) --- Accessed /login. current_user: {current_user}, is_authenticated: {current_user.is_authenticated}")
    app.logger.info(f"--- Login Route (Top) --- Session contents: {dict(session)}")
    if current_user.is_authenticated:
        next_page = request.args.get('next')
        app.logger.info(f"--- Login Route --- User '{current_user.username}' is already authenticated. 'next' page: {next_page}")
        is_safe_next = False
        actual_app_root = app.config.get('APPLICATION_ROOT', '/')
        app.logger.info(f"--- Login Route --- Evaluating 'next_page': '{next_page}', actual_app_root_from_config: '{actual_app_root}'")
        if next_page:
            if not ('://' in next_page or next_page.startswith('//')):
                if next_page.startswith(actual_app_root): is_safe_next = True
        app.logger.info(f"--- Login Route --- is_safe_next determination: {is_safe_next}")
        if is_safe_next:
            app.logger.info(f"--- Login Route --- Redirecting authenticated user '{current_user.username}' to safe 'next' page: {next_page}")
            return redirect(next_page)
        else:
            if next_page: app.logger.warning(f"--- Login Route --- Unsafe or non-matching 'next' page ('{next_page}') for authenticated user '{current_user.username}' with app_root '{actual_app_root}'. Redirecting to dashboard.")
            else: app.logger.info(f"--- Login Route --- No 'next' page for authenticated user '{current_user.username}'. Redirecting to dashboard.")
            return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            app.logger.info(f"--- Login Route --- Attempting to log in user: {user.username} (ID: {user.id})")
            login_user(user, remember=form.remember_me.data)
            app.logger.info(f"--- Login Route --- User '{user.username}' successfully logged in. current_user after login: {current_user.username}")
            app.logger.info(f"--- Login Route --- Session contents after login_user: {dict(session)}")
            next_page_after_login = request.args.get('next')
            app.logger.info(f"--- Login Route --- Login successful. 'next' page: {next_page_after_login}")
            is_safe_next_after_login = False
            actual_app_root_after_login = app.config.get('APPLICATION_ROOT', '/')
            app.logger.info(f"--- Login Route --- Evaluating 'next_page_after_login': '{next_page_after_login}', actual_app_root_from_config: '{actual_app_root_after_login}'")
            if next_page_after_login:
                if not ('://' in next_page_after_login or next_page_after_login.startswith('//')):
                    if next_page_after_login.startswith(actual_app_root_after_login): is_safe_next_after_login = True
            app.logger.info(f"--- Login Route --- is_safe_next_after_login determination: {is_safe_next_after_login}")
            if is_safe_next_after_login:
                app.logger.info(f"--- Login Route --- Redirecting newly logged in user '{user.username}' to safe 'next' page: {next_page_after_login}")
                return redirect(next_page_after_login)
            else:
                if next_page_after_login: app.logger.warning(f"--- Login Route --- Unsafe or non-matching 'next' page ('{next_page_after_login}') after login for '{user.username}' with app_root '{actual_app_root_after_login}'. Redirecting to dashboard.")
                else: app.logger.info(f"--- Login Route --- No 'next' page after login for '{user.username}'. Redirecting to dashboard.")
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            app.logger.warning(f"--- Login Route --- Failed login attempt for username: {form.username.data}")
    app.logger.info("--- Login Route --- Rendering login page for unauthenticated user.")
    return render_template('login.html', title='Login', form=form)

@app.route('/logout') # ... (same as before) ...
@login_required
def logout():
    app.logger.info(f"User '{current_user.username}' logged out.")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.after_request # ... (same as before) ...
def add_header(response):
    if '/static/' not in request.path:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@app.route('/register/client', methods=['GET', 'POST']) # ... (same as before) ...
def register_client():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = UserSelfRegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data.lower(), role='client')
        user.set_password(form.password.data)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Client account created successfully! Please log in.', 'success')
            app.logger.info(f"New client registered: {user.username}")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error during registration. Please try again.', 'danger')
            app.logger.error(f"Client registration error: {e}")
    return render_template('register_user.html', title='Register as Client', form=form, registration_type='Client', info_text='Submit and track your support tickets.')

@app.route('/register/agent', methods=['GET', 'POST']) # ... (same as before) ...
@admin_required
def register_agent():
    form = UserSelfRegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data.lower(), role='agent')
        user.set_password(form.password.data)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Agent account created successfully!', 'success')
            app.logger.info(f"New agent '{user.username}' registered by admin '{current_user.username}'.")
            return redirect(url_for('admin_user_list'))
        except Exception as e:
            db.session.rollback()
            flash('Error during agent registration. Please try again.', 'danger')
            app.logger.error(f"Admin agent registration error: {e}")
    return render_template('register_user.html', title='Register New Agent', form=form, registration_type='Agent', info_text='Register new support agents to assist clients.')

@app.route('/dashboard') # ... (same as before) ...
@login_required
def dashboard():
    if not current_user.is_authenticated:
        app.logger.warning(f"Unauthenticated access to /dashboard despite @login_required. Current_user: {current_user}")
        return redirect(url_for('login', next=request.url))
    app.logger.info(f"Dashboard accessed by: {current_user.username if current_user.is_authenticated else 'Anonymous'}")
    if current_user.is_admin:
        stats = {'total_tickets': Ticket.query.count(), 'open_tickets': Ticket.query.filter_by(status='Open').count(), 'inprogress_tickets': Ticket.query.filter_by(status='In Progress').count(), 'resolved_tickets': Ticket.query.filter_by(status='Resolved').count(), 'total_users': User.query.count()}
        return render_template('dashboard.html', title='Admin Dashboard', **stats)
    elif current_user.is_agent:
        agent_data = {'my_assigned_tickets': Ticket.query.filter_by(assigned_to_id=current_user.id).filter(Ticket.status.notin_(['Resolved', 'Closed'])).order_by(Ticket.updated_at.desc()).all(), 'unassigned_tickets': Ticket.query.filter_by(assigned_to_id=None, status='Open').order_by(Ticket.created_at.desc()).limit(10).all()}
        return render_template('dashboard.html', title='Agent Dashboard', **agent_data)
    else:
        my_tickets = Ticket.query.filter_by(created_by_id=current_user.id).order_by(Ticket.updated_at.desc()).limit(10).all()
        return render_template('dashboard.html', title='My Dashboard', my_tickets=my_tickets)

@app.route('/tickets/new', methods=['GET', 'POST'])
@login_required
def create_ticket():
    # ... (form setup as before) ...
    form = CreateTicketForm()
    form.category.choices = [(0, '--- Select Issue Category* ---')] + [(c.id, c.name) for c in Category.query.order_by('name').all()]
    form.cloud_provider.choices = get_active_cloud_provider_choices()
    form.severity.choices = get_active_severity_choices()
    form.environment.choices = get_active_environment_choices()
    if not form.category.choices[1:]: flash("Critical: No categories defined. Contact admin.", "danger")
    if not form.severity.choices[1:]: flash("Critical: No severity levels defined. Contact admin.", "danger")

    if form.validate_on_submit():
        # ... (attachment handling as before) ...
        uploaded_files_info = []
        if form.attachments.data:
            for file_storage in form.attachments.data:
                if file_storage and file_storage.filename:
                    if allowed_file(file_storage.filename):
                        filename = secure_filename(file_storage.filename)
                        unique_suffix = uuid.uuid4().hex[:8]
                        stored_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{unique_suffix}_{filename}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
                        try:
                            file_storage.save(file_path)
                            uploaded_files_info.append({'original_filename': filename, 'stored_filename': stored_filename, 'content_type': file_storage.content_type})
                        except Exception as e:
                            app.logger.error(f"Failed to save attachment {filename}: {e}")
                            form.attachments.errors.append(f"Could not save file: {filename}")
                    else:
                        form.attachments.errors.append(f"File type not allowed: {file_storage.filename}")
        if form.attachments.errors: flash('Error with attachments. Please correct and try again.', 'danger')
        else:
            ticket_creator = current_user
            ticket = Ticket(title=form.title.data, description=form.description.data, created_by_id=ticket_creator.id, category_id=form.category.data, cloud_provider=form.cloud_provider.data or None, severity=form.severity.data, aws_service=form.aws_service.data if form.cloud_provider.data == 'AWS' and form.aws_service.data else None, aws_account_id=form.aws_account_id.data or None, environment=form.environment.data or None)
            db.session.add(ticket)
            try:
                db.session.flush() # Get ticket.id
                for file_info in uploaded_files_info:
                    attachment = Attachment(filename=file_info['original_filename'], stored_filename=file_info['stored_filename'], ticket_id=ticket.id, uploaded_by_id=ticket_creator.id, content_type=file_info['content_type'])
                    db.session.add(attachment)

                if ticket.id: # Log TICKET_CREATED interaction
                    log_interaction(ticket.id, 'TICKET_CREATED', user_id=ticket_creator.id, details={'title': ticket.title}, timestamp_override=ticket.created_at)

                db.session.commit()
                flash('Ticket created successfully!', 'success')
                # ... (email notifications and Twilio alert as before) ...
                try: # Email notifications
                    ticket_submitter_for_email = ticket_creator
                    admin_and_agent_emails = list(set(([app.config['ADMIN_EMAIL']] if app.config['ADMIN_EMAIL'] else []) + [user.email for user in User.query.filter(User.role.in_(['admin', 'agent'])).all() if user.email]))
                    if admin_and_agent_emails:
                        email_body_admin = render_template('email/new_ticket_admin_notification.txt', ticket=ticket, submitter=ticket_submitter_for_email, ticket_url=url_for('view_ticket', ticket_id=ticket.id, _external=True))
                        msg_admin = Message(subject=f"New Ticket Submitted: #{ticket.id} - {ticket.title}", recipients=admin_and_agent_emails, body=email_body_admin)
                        mail.send(msg_admin)
                    additional_emails = [email.strip() for email in (form.additional_recipients.data or "").split(',') if email.strip()]
                    creator_and_additional_emails = list(set(additional_emails + ([ticket_submitter_for_email.email] if ticket_submitter_for_email.email else [])))
                    if creator_and_additional_emails:
                        email_body_recipient = render_template('email/ticket_info_recipient.txt', ticket=ticket, submitter=ticket_submitter_for_email, ticket_url=url_for('view_ticket', ticket_id=ticket.id, _external=True))
                        msg_additional = Message(subject=f"Confirmation: Your Ticket #{ticket.id} - {ticket.title}", recipients=creator_and_additional_emails, body=email_body_recipient)
                        mail.send(msg_additional)
                except Exception as e:
                    app.logger.error(f"Failed to send email notifications for ticket #{ticket.id}: {e}")
                trigger_priority_call_alert(ticket, old_severity=None)
                return redirect(url_for('view_ticket', ticket_id=ticket.id))
            except Exception as e:
                db.session.rollback()
                flash(f'Database error: Could not save ticket. {str(e)[:150]}', 'danger')
    elif request.method == 'POST': flash('Please correct the errors in the form.', 'danger')
    return render_template('client/create_ticket.html', title='Submit New Support Request', form=form)

@app.route('/tickets/my') # ... (same as before) ...
@login_required
def my_tickets():
    tickets = Ticket.query.filter_by(created_by_id=current_user.id).order_by(Ticket.updated_at.desc()).all()
    return render_template('client/my_tickets.html', title='My Submitted Tickets', tickets=tickets)

# ... (imports and other parts of app.py) ...

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if not (current_user.is_admin or current_user.is_agent or ticket.created_by_id == current_user.id):
        flash('You do not have permission to view this ticket.', 'danger')
        return redirect(url_for('dashboard'))

    comment_form = CommentForm()
    agent_update_form = None
    attachments = ticket.ticket_attachments.order_by(Attachment.uploaded_at.desc()).all()
    is_privileged_user = current_user.is_agent or current_user.is_admin # Already here, good!

    # ... (agent_update_form and comment_form setup as before) ...
    if is_privileged_user:
        agent_update_form = AgentUpdateTicketForm(obj=None) # Initialize empty
        # Populate choices for the agent_update_form
        agent_choices = [(u.id, u.username) for u in User.query.filter(User.role.in_(['agent', 'admin'])).order_by('username').all()]
        cat_choices = [(c.id, c.name) for c in Category.query.order_by('name').all()]
        
        agent_update_form.assigned_to_id.choices = [(0, '--- Unassign/Select Agent ---')] + agent_choices
        agent_update_form.category_id.choices = [(0, '--- No Category ---')] + cat_choices # Ensure 'No Category' or similar is value 0 or empty
        agent_update_form.cloud_provider.choices = get_active_cloud_provider_choices()
        agent_update_form.severity.choices = get_active_severity_choices() # Ensure placeholder is value ''
        agent_update_form.environment.choices = get_active_environment_choices() # Ensure placeholder is value ''
        # AWS Service choices are static in the form definition

        if request.method == 'GET': 
            agent_update_form.status.data = ticket.status
            agent_update_form.priority.data = ticket.priority
            agent_update_form.assigned_to_id.data = ticket.assigned_to_id or 0
            agent_update_form.category_id.data = ticket.category_id or 0
            agent_update_form.cloud_provider.data = ticket.cloud_provider or ''
            agent_update_form.severity.data = ticket.severity or ''
            agent_update_form.aws_service.data = ticket.aws_service or ''
            agent_update_form.aws_account_id.data = ticket.aws_account_id or ''
            agent_update_form.environment.data = ticket.environment or ''

    if not is_privileged_user and hasattr(comment_form, 'is_internal'):
        delattr(comment_form, 'is_internal')


    if request.method == 'POST':
        if 'submit_comment' in request.form and comment_form.validate_on_submit():
            # ... (comment submission logic as before, including log_interaction for COMMENT_ADDED) ...
            is_internal_comment = is_privileged_user and hasattr(comment_form, 'is_internal') and comment_form.is_internal.data
            comment = Comment(content=comment_form.content.data, user_id=current_user.id, ticket_id=ticket.id, is_internal=is_internal_comment)
            db.session.add(comment)
            db.session.flush() 
            log_interaction(ticket.id, 'COMMENT_ADDED', user_id=current_user.id, details={'comment_id': comment.id, 'is_internal': is_internal_comment})
            db.session.commit()
            flash('Your comment has been added.', 'success')
            return redirect(url_for('view_ticket', ticket_id=ticket.id, _anchor='comments_section'))
        
        elif 'submit_update' in request.form and is_privileged_user and agent_update_form and agent_update_form.validate_on_submit():
            # Store old values for comparison and logging
            old_values = {
                'status': ticket.status,
                'priority': ticket.priority,
                'assigned_to_id': ticket.assigned_to_id,
                'assignee_name': ticket.assignee.username if ticket.assignee else "Unassigned",
                'category_id': ticket.category_id,
                'category_name': ticket.category_ref.name if ticket.category_ref else "None",
                'cloud_provider': ticket.cloud_provider or "None", # Handle None for display
                'severity': ticket.severity or "None",
                'aws_service': ticket.aws_service or "None",
                'aws_account_id': ticket.aws_account_id or "None",
                'environment': ticket.environment or "None"
            }

            # Apply updates from form
            ticket.status = agent_update_form.status.data
            ticket.priority = agent_update_form.priority.data
            ticket.assigned_to_id = agent_update_form.assigned_to_id.data if agent_update_form.assigned_to_id.data != 0 else None
            ticket.category_id = agent_update_form.category_id.data if agent_update_form.category_id.data != 0 else None
            
            # For optional fields, use .data or None to avoid empty strings if not desired
            ticket.cloud_provider = agent_update_form.cloud_provider.data if agent_update_form.cloud_provider.data else None
            ticket.severity = agent_update_form.severity.data if agent_update_form.severity.data else None
            ticket.aws_service = agent_update_form.aws_service.data if ticket.cloud_provider == 'AWS' and agent_update_form.aws_service.data else None
            ticket.aws_account_id = agent_update_form.aws_account_id.data if agent_update_form.aws_account_id.data else None
            ticket.environment = agent_update_form.environment.data if agent_update_form.environment.data else None
            
            # Log interactions for changes
            if ticket.status != old_values['status']:
                log_interaction(ticket.id, 'STATUS_CHANGE', user_id=current_user.id, 
                                details={'old_value': old_values['status'], 'new_value': ticket.status, 'field_display_name': 'Status'})
            
            if ticket.priority != old_values['priority']:
                log_interaction(ticket.id, 'PRIORITY_CHANGE', user_id=current_user.id,
                                details={'old_value': old_values['priority'], 'new_value': ticket.priority, 'field_display_name': 'Priority'})

            if ticket.assigned_to_id != old_values['assigned_to_id']:
                new_assignee_name = ticket.assignee.username if ticket.assignee else "Unassigned"
                log_interaction(ticket.id, 'ASSIGNMENT_CHANGE', user_id=current_user.id,
                                details={'old_value': old_values['assignee_name'], 'new_value': new_assignee_name, 'field_display_name': 'Assignee'})
            
            if ticket.category_id != old_values['category_id']:
                new_category_name = ticket.category_ref.name if ticket.category_ref else "None"
                log_interaction(ticket.id, 'CATEGORY_CHANGE', user_id=current_user.id,
                                details={'old_value': old_values['category_name'], 'new_value': new_category_name, 'field_display_name': 'Category'})

            if (ticket.cloud_provider or "None") != old_values['cloud_provider']: # Compare with "None" if None
                log_interaction(ticket.id, 'CLOUD_PROVIDER_CHANGE', user_id=current_user.id,
                                details={'old_value': old_values['cloud_provider'], 'new_value': ticket.cloud_provider or "None", 'field_display_name': 'Cloud Provider'})

            if (ticket.severity or "None") != old_values['severity']:
                log_interaction(ticket.id, 'SEVERITY_CHANGE', user_id=current_user.id,
                                details={'old_value': old_values['severity'], 'new_value': ticket.severity or "None", 'field_display_name': 'Severity'})
            
            if (ticket.aws_service or "None") != old_values['aws_service']:
                log_interaction(ticket.id, 'AWS_SERVICE_CHANGE', user_id=current_user.id,
                                details={'old_value': old_values['aws_service'], 'new_value': ticket.aws_service or "None", 'field_display_name': 'AWS Service'})

            if (ticket.aws_account_id or "None") != old_values['aws_account_id']:
                log_interaction(ticket.id, 'AWS_ACCOUNT_ID_CHANGE', user_id=current_user.id,
                                details={'old_value': old_values['aws_account_id'], 'new_value': ticket.aws_account_id or "None", 'field_display_name': 'AWS Account ID'})
            
            if (ticket.environment or "None") != old_values['environment']:
                log_interaction(ticket.id, 'ENVIRONMENT_CHANGE', user_id=current_user.id,
                                details={'old_value': old_values['environment'], 'new_value': ticket.environment or "None", 'field_display_name': 'Environment'})

            try:
                db.session.commit()
                flash('Ticket details updated successfully.', 'success')
                trigger_priority_call_alert(ticket, old_values['severity'] if old_values['severity'] != "None" else None) # Pass actual old severity
                return redirect(url_for('view_ticket', ticket_id=ticket.id))
            except Exception as e:
                db.session.rollback()
                flash(f'Database error during ticket update: {str(e)[:150]}', 'danger')
                app.logger.error(f"Ticket update DB error for #{ticket.id}: {e}", exc_info=True)
        
        # ... (error handling for forms as before) ...

    # ... (comment fetching as before) ...
    comments_query = ticket.comments
    if not is_privileged_user: # Client view
        comments_query = comments_query.filter_by(is_internal=False)
    comments = comments_query.order_by(Comment.created_at.asc()).all()
    
    # Interaction History Logic (only if privileged user)
    sorted_interaction_dates = []
    interactions_by_date = {}
    today_date_obj = None
    yesterday_date_obj = None

    if is_privileged_user: # Only process and pass interactions for privileged users
        raw_interactions = ticket.interactions_rel.order_by(Interaction.timestamp.desc()).all()
        processed_interactions = []
        
        for interaction in raw_interactions:
            actor_name = "System"
            if interaction.user:
                actor_name = interaction.user.username
            elif interaction.interaction_type == 'TICKET_CREATED' and ticket.creator:
                 actor_name = ticket.creator.username

            p_interaction = {
                'obj': interaction,
                'actor_name': actor_name,
                'timestamp_obj': interaction.timestamp,
                'time_str': interaction.timestamp.strftime('%H:%M'),
                'date_str_short': interaction.timestamp.strftime('%b %d'),
                'datetime_str_full': interaction.timestamp.strftime('%b %d, %Y %H:%M:%S'),
                'message': "",
                'title_for_display': actor_name
            }
            details = interaction.details or {}

            # Generic field change message constructor
            field_display_name = details.get('field_display_name')
            if field_display_name: # For generic property changes
                old_val_display = details.get('old_value', "not set")
                new_val_display = details.get('new_value', "not set")
                if old_val_display == "None" and new_val_display == "None":
                     p_interaction['message'] = f"verified <strong>{field_display_name}</strong> (remained not set)."
                elif old_val_display == "None":
                     p_interaction['message'] = f"set <strong>{field_display_name}</strong> to <strong>{new_val_display}</strong>."
                elif new_val_display == "None":
                     p_interaction['message'] = f"cleared <strong>{field_display_name}</strong> (was <strong>{old_val_display}</strong>)."
                else:
                    p_interaction['message'] = f"changed <strong>{field_display_name}</strong> from <strong>{old_val_display}</strong> to <strong>{new_val_display}</strong>."
            
            # Specific interaction types override generic message if needed
            if interaction.interaction_type == 'TICKET_CREATED':
                p_interaction['title_for_display'] = details.get('title', ticket.title)
                p_interaction['message'] = f"created this ticket."
            elif interaction.interaction_type == 'COMMENT_ADDED':
                comment = Comment.query.get(details.get('comment_id'))
                comment_type = "internal" if details.get('is_internal') else "public"
                p_interaction['message'] = f"added a {comment_type} comment."
                if comment: # Security: only show preview if current user can see it
                    is_viewable_by_current_user = not comment.is_internal or (comment.is_internal and is_privileged_user)
                    if is_viewable_by_current_user:
                        p_interaction['comment_preview'] = comment.content
            elif interaction.interaction_type == 'ASSIGNMENT_CHANGE': # Already handled by generic if field_display_name is 'Assignee'
                # If you want a more specific message for assignment, handle it here explicitly
                # This is because the values 'old_assignee_name' and 'new_assignee_name' might not be in details.get('old_value')
                 old_name = details.get('old_value', "Unassigned") # Use 'old_value' as per generic logic
                 new_name = details.get('new_value', "Unassigned") # Use 'new_value'
                 p_interaction['message'] = f"changed assignment from <strong>{old_name}</strong> to <strong>{new_name}</strong>."

            elif interaction.interaction_type == 'ARTICLE_VIEWED':
                p_interaction['title_for_display'] = "Viewed article"
                p_interaction['message'] = f"<strong>{details.get('article_title', 'Unknown Article')}</strong>"
                if details.get('source'):
                    p_interaction['message'] += f" <span class='text-muted small'>via {details.get('source')}</span>"
            
            # Fallback if no specific message was constructed but it wasn't a generic field change
            if not p_interaction['message'] and not field_display_name:
                 p_interaction['message'] = f"performed action: {interaction.interaction_type}. Details: {details}"


            processed_interactions.append(p_interaction)

        interactions_by_date = {k: sorted(list(g), key=lambda i: i['timestamp_obj'], reverse=True) 
                                for k, g in groupby(processed_interactions, key=lambda i: i['timestamp_obj'].date())}
        
        sorted_interaction_dates = sorted(interactions_by_date.keys(), reverse=True)
        today_date_obj = date.today() 
        yesterday_date_obj = today_date_obj - timedelta(days=1)
    
    # ... (logging for debug as before) ...
    app.logger.info(f"--- Interaction History Debug for Ticket ID: {ticket_id} ---")
    if is_privileged_user:
        app.logger.info(f"User is privileged. Number of raw_interactions: {len(raw_interactions if 'raw_interactions' in locals() else [])}")
        app.logger.info(f"Number of processed_interactions: {len(processed_interactions if 'processed_interactions' in locals() else [])}")
        app.logger.info(f"Number of sorted_interaction_dates: {len(sorted_interaction_dates)}")
        if sorted_interaction_dates:
            app.logger.info(f"First date group: {sorted_interaction_dates[0]}")
            first_group_interactions = interactions_by_date.get(sorted_interaction_dates[0])
            app.logger.info(f"Interactions in first date group: {len(first_group_interactions) if first_group_interactions else 0}")
            if first_group_interactions:
                app.logger.info(f"Content of first interaction in first group: {first_group_interactions[0]}")
        else:
            app.logger.info("No interaction dates to display (sorted_interaction_dates is empty).")
        app.logger.info(f"today_date object being passed to template: {today_date_obj}")
        app.logger.info(f"yesterday_date object being passed to template: {yesterday_date_obj}")
    else:
        app.logger.info("User is not privileged. Interaction history will not be processed or shown.")
    app.logger.info(f"--- End Interaction History Debug ---")


    return render_template('client/view_ticket.html', title=f'Ticket #{ticket.id}: {ticket.title}', ticket=ticket,
                           comments=comments, comment_form=comment_form, 
                           agent_update_form=agent_update_form, 
                           attachments=attachments,
                           is_privileged_user=is_privileged_user, 
                           # Interaction history data (will be empty lists/None if not privileged)
                           sorted_interaction_dates=sorted_interaction_dates,
                           interactions_by_date=interactions_by_date,
                           today_date=today_date_obj, 
                           yesterday_date=yesterday_date_obj)

@app.route('/uploads/<filename>') # ... (same as before) ...
@login_required
def uploaded_file(filename):
    attachment = Attachment.query.filter_by(stored_filename=filename).first_or_404()
    ticket = attachment.ticket
    if not (current_user.is_admin or current_user.is_agent or current_user.id == attachment.uploaded_by_id or current_user.id == ticket.created_by_id or (ticket.assigned_to_id and current_user.id == ticket.assigned_to_id)):
        flash("You do not have permission to download this file.", "danger"); return redirect(request.referrer or url_for('dashboard'))
    try:
        upload_dir = app.config['UPLOAD_FOLDER']
        if not os.path.isabs(upload_dir): upload_dir = os.path.join(current_app.root_path, upload_dir)
        return send_from_directory(upload_dir, attachment.stored_filename, as_attachment=True, download_name=attachment.filename)
    except FileNotFoundError:
        app.logger.error(f"Physical file not found: {attachment.stored_filename}")
        flash("File not found on server. Please contact support.", "danger"); return redirect(request.referrer or url_for('dashboard'))

@app.route('/agent/tickets/') # ... (agent_ticket_list, assign_ticket_to_me updated for interactions) ...
@app.route('/agent/tickets/view/<view_name>')
@agent_required
def agent_ticket_list(view_name=None):
    # ... (same logic as before) ...
    page = request.args.get('page', 1, type=int); query = Ticket.query; list_title = "Agent Tickets"
    if view_name is None: view_name = 'my_unsolved'
    if view_name == 'my_unsolved': query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status.notin_(['Resolved', 'Closed'])); list_title = "Your Unsolved Tickets"
    elif view_name == 'unassigned': query = query.filter(Ticket.assigned_to_id.is_(None), Ticket.status == 'Open'); list_title = "Unassigned Open Tickets"
    elif view_name == 'all_unsolved': query = query.filter(Ticket.status.notin_(['Resolved', 'Closed'])); list_title = "All Unsolved Tickets"
    elif view_name == 'recently_updated': list_title = "Recently Updated Tickets"
    elif view_name == 'pending': query = query.filter(Ticket.status == 'On Hold'); list_title = "Pending (On Hold) Tickets"
    elif view_name == 'recently_solved': query = query.filter(Ticket.status == 'Resolved'); list_title = "Recently Solved Tickets"
    elif view_name == 'current_tasks': query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status == 'In Progress'); list_title = "Your Current In-Progress Tickets"
    else: flash(f"Unknown ticket view: '{view_name}'.", "warning"); query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status.notin_(['Resolved', 'Closed'])); list_title = "Your Unsolved Tickets"; view_name = 'my_unsolved'
    if view_name in ['recently_updated', 'recently_solved', 'all_unsolved', 'unassigned', 'pending']: ordered_query = query.order_by(Ticket.updated_at.desc())
    else: priority_order = db.case({'Urgent': 1, 'High': 2, 'Medium': 3, 'Low': 4}, value=Ticket.priority, else_=5); ordered_query = query.order_by(priority_order.asc(), Ticket.updated_at.desc())
    tickets_pagination = ordered_query.paginate(page=page, per_page=10, error_out=False)
    return render_template('agent/ticket_list.html', title=list_title, tickets_pagination=tickets_pagination, current_view=view_name)


@app.route('/ticket/<int:ticket_id>/assign_to_me')
@agent_required
def assign_ticket_to_me(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.assigned_to_id is None or ticket.assigned_to_id != current_user.id:
        old_assignee_id = ticket.assigned_to_id; old_assignee_name = ticket.assignee.username if ticket.assignee else None
        old_status = ticket.status; status_changed = False
        ticket.assigned_to_id = current_user.id
        if ticket.status == 'Open': ticket.status = 'In Progress'; status_changed = True
        log_interaction(ticket.id, 'ASSIGNMENT_CHANGE', user_id=current_user.id, details={'old_assignee_id': old_assignee_id, 'old_assignee_name': old_assignee_name, 'new_assignee_id': ticket.assigned_to_id, 'new_assignee_name': current_user.username})
        if status_changed: log_interaction(ticket.id, 'STATUS_CHANGE', user_id=current_user.id, details={'old_status': old_status, 'new_status': ticket.status})
        db.session.commit()
        flash(f'Ticket #{ticket.id} has been assigned to you.', 'success')
    # ... (rest of logic as before) ...
    elif ticket.assigned_to_id == current_user.id: flash(f'Ticket #{ticket.id} is already assigned to you.', 'info')
    else: flash(f'Ticket #{ticket.id} is already assigned to another agent ({ticket.assignee.username if ticket.assignee else "Unknown"}).', 'warning')
    return redirect(request.referrer or url_for('agent_ticket_list', view_name='unassigned'))

# --- Admin Routes (admin_delete_user updated for interactions, others same) ---
@app.route('/admin/users') # ... (admin_user_list)
@admin_required
def admin_user_list():
    users = User.query.order_by(User.username).all()
    share_form = ShareCredentialsForm()
    return render_template('admin/user_list.html', title='Manage Users', users=users, share_form=share_form)

@app.route('/admin/user/new', methods=['GET', 'POST']) # ... (admin_create_edit_user)
@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_user(user_id=None):
    user_to_edit = User.query.get_or_404(user_id) if user_id else None
    form = AdminUserForm(obj=user_to_edit if request.method == 'GET' and user_to_edit else None)
    legend = 'Create New User' if not user_to_edit else f'Edit User: {user_to_edit.username}'
    original_password_validators = list(form.password.validators); original_password2_validators = list(form.password2.validators)
    if not user_to_edit:
        form.password.validators = [DataRequired(message="Password is required for new users.")] + [v for v in original_password_validators if not isinstance(v, Optional)]
        form.password2.validators = [DataRequired(message="Please confirm the password.")] + [v for v in original_password2_validators if not isinstance(v, Optional)]
    else:
        form.password.validators = [Optional()] + [v for v in original_password_validators if not isinstance(v, (DataRequired, Optional))]
        form.password2.validators = [EqualTo('password', message='Passwords must match if new password provided.')] + [Optional()] + [v for v in original_password2_validators if not isinstance(v, (DataRequired, Optional, EqualTo))]
    if form.validate_on_submit():
        is_new_user = (user_to_edit is None); user = user_to_edit or User()
        potential_username_conflict = User.query.filter(User.username == form.username.data, User.id != (user.id if user.id else -1)).first()
        if potential_username_conflict: form.username.errors.append('This username is already taken.')
        potential_email_conflict = User.query.filter(User.email == form.email.data.lower(), User.id != (user.id if user.id else -1)).first()
        if potential_email_conflict: form.email.errors.append('This email address is already registered.')
        if not is_new_user and form.password.data and not form.password2.data: form.password2.errors.append("Please confirm the new password if you are changing it.")
        if not form.errors:
            user.username = form.username.data; user.email = form.email.data.lower(); user.role = form.role.data
            if form.password.data: user.set_password(form.password.data)
            if is_new_user: db.session.add(user)
            try:
                db.session.commit()
                flash(f'User "{user.username}" has been {"created" if is_new_user else "updated"} successfully.', 'success')
                return redirect(url_for('admin_user_list'))
            except Exception as e:
                db.session.rollback(); flash(f'Database error: Could not save user. {str(e)}', 'danger')
    return render_template('admin/create_edit_user.html', title=legend, form=form, legend=legend, user=user_to_edit)


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id: flash('You cannot delete your own account.', 'danger')
    elif user_to_delete.is_admin and User.query.filter_by(role='admin').count() <= 1: flash('Cannot delete the only remaining administrator account.', 'danger')
    else:
        deleted_username = user_to_delete.username
        try:
            Ticket.query.filter_by(assigned_to_id=user_id).update({'assigned_to_id': None})
            Attachment.query.filter_by(uploaded_by_id=user_id).delete(synchronize_session='fetch')
            Comment.query.filter_by(user_id=user_id).delete(synchronize_session='fetch')
            Interaction.query.filter_by(user_id=user_id).update({'user_id': None}, synchronize_session='fetch') # Anonymize interactions
            db.session.delete(user_to_delete)
            db.session.commit()
            flash(f'User "{deleted_username}" deleted. Associated interactions anonymized.', 'success')
        except Exception as e: db.session.rollback(); flash(f'Error deleting user: {e}', 'danger')
    return redirect(url_for('admin_user_list'))

@app.route('/admin/user/<int:user_id>/share_credentials', methods=['POST']) # ... (admin_share_credentials)
@admin_required
def admin_share_credentials(user_id):
    user_to_share = User.query.get_or_404(user_id); admin_user = current_user
    form = ShareCredentialsForm(request.form)
    if form.validate():
        recipient_email = form.recipient_email.data
        subject = f"Account Information for Ticket System: {user_to_share.username}"
        body_text = render_template('email/share_credentials_email.txt', user_being_shared=user_to_share, admin_user=admin_user)
        msg = Message(subject, recipients=[recipient_email], body=body_text)
        try:
            mail.send(msg); flash(f'Account info for "{user_to_share.username}" sent to {recipient_email}.', 'success')
        except Exception as e: flash(f'Failed to send email: {e}', 'danger')
    else:
        for field_name, errors in form.errors.items():
            label = getattr(getattr(form, field_name), 'label', None); label_text = label.text if label else field_name.replace("_", " ").title()
            flash(f"Error in sharing form ({label_text}): {', '.join(errors)}", 'danger')
    return redirect(url_for('admin_user_list'))

# ... (all _admin_list_options, _admin_create_edit_option, _admin_delete_option helpers and specific option routes are the same) ...
def _admin_list_options(model_class, template_name, title, order_by_attr='name'):
    items = model_class.query.order_by(getattr(model_class, order_by_attr)).all()
    model_name_slug = to_snake_case(model_class.__name__)
    return render_template(template_name, title=title, items=items, model_name=model_name_slug)
def _admin_create_edit_option(model_class, form_class, list_url_func_name, item_id=None):
    item = model_class.query.get_or_404(item_id) if item_id else None
    form = form_class(obj=item if request.method == 'GET' and item else None)
    type_name_raw = model_class.__name__.replace("Option",""); type_name_display = " ".join(re.findall('[A-Z][^A-Z]*', type_name_raw) or [type_name_raw])
    legend = f'New {type_name_display}' if not item else f'Edit {type_name_display}: {getattr(item, "name", "Item")}'
    if form.validate_on_submit():
        is_new = (item is None); option_instance = item or model_class()
        existing_item_with_name = model_class.query.filter(model_class.name == form.name.data, model_class.id != (option_instance.id if option_instance.id else -1)).first()
        if existing_item_with_name: form.name.errors.append('This name already exists.')
        if not form.errors:
            form.populate_obj(option_instance)
            if is_new: db.session.add(option_instance)
            try: db.session.commit(); flash(f'{type_name_display} "{option_instance.name}" saved.', 'success'); return redirect(url_for(list_url_func_name))
            except Exception as e: db.session.rollback(); flash(f'DB error: {e}', 'danger')
    return render_template('admin/create_edit_option.html', title=legend, form=form, legend=legend,item_type_name=type_name_display, list_url=url_for(list_url_func_name))
def _admin_delete_option(model_class, item_id, list_url_func_name, related_ticket_attr=None):
    item = model_class.query.get_or_404(item_id); item_name = getattr(item, "name", "Item")
    type_name_raw = model_class.__name__.replace("Option",""); type_name_display = " ".join(re.findall('[A-Z][^A-Z]*', type_name_raw) or [type_name_raw])
    can_delete = True
    if related_ticket_attr:
        query_filter = (Ticket.category_id == item.id) if related_ticket_attr == 'category_id' and hasattr(Ticket, 'category_id') else (getattr(Ticket, related_ticket_attr) == item.name if hasattr(Ticket, related_ticket_attr) else None)
        if query_filter is not None and Ticket.query.filter(query_filter).first(): can_delete = False; flash(f'Cannot delete "{item_name}", associated with tickets.', 'danger')
    if can_delete:
        try: db.session.delete(item); db.session.commit(); flash(f'{type_name_display} "{item_name}" deleted.', 'success')
        except Exception as e: db.session.rollback(); flash(f'Error deleting: {e}', 'danger')
    return redirect(url_for(list_url_func_name))

@app.route('/admin/categories')
@admin_required
def admin_category_list(): return _admin_list_options(Category, 'admin/list_options.html', 'Manage Categories')
@app.route('/admin/category/new', methods=['GET', 'POST'])
@app.route('/admin/category/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_category(item_id=None): return _admin_create_edit_option(Category, CategoryForm, 'admin_category_list', item_id)
@app.route('/admin/category/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_category(item_id): return _admin_delete_option(Category, item_id, 'admin_category_list', 'category_id')

@app.route('/admin/cloud_providers')
@admin_required
def admin_cloud_provider_list(): return _admin_list_options(CloudProviderOption, 'admin/list_options.html', 'Manage Cloud Providers')
@app.route('/admin/cloud_provider/new', methods=['GET', 'POST'])
@app.route('/admin/cloud_provider/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_cloud_provider(item_id=None): return _admin_create_edit_option(CloudProviderOption, CloudProviderOptionForm, 'admin_cloud_provider_list', item_id)
@app.route('/admin/cloud_provider/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_cloud_provider(item_id): return _admin_delete_option(CloudProviderOption, item_id, 'admin_cloud_provider_list', 'cloud_provider')

@app.route('/admin/severities')
@admin_required
def admin_severity_list(): return _admin_list_options(SeverityOption, 'admin/list_options.html', 'Manage Severity Levels', 'order')
@app.route('/admin/severity/new', methods=['GET', 'POST'])
@app.route('/admin/severity/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_severity(item_id=None): return _admin_create_edit_option(SeverityOption, SeverityOptionForm, 'admin_severity_list', item_id)
@app.route('/admin/severity/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_severity(item_id): return _admin_delete_option(SeverityOption, item_id, 'admin_severity_list', 'severity')

@app.route('/admin/environments')
@admin_required
def admin_environment_list(): return _admin_list_options(EnvironmentOption, 'admin/list_options.html', 'Manage Environments')
@app.route('/admin/environment/new', methods=['GET', 'POST'])
@app.route('/admin/environment/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_environment(item_id=None): return _admin_create_edit_option(EnvironmentOption, EnvironmentOptionForm, 'admin_environment_list', item_id)
@app.route('/admin/environment/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_environment(item_id): return _admin_delete_option(EnvironmentOption, item_id, 'admin_environment_list', 'environment')

@app.route('/admin/tickets') # ... (admin_all_tickets)
@admin_required
def admin_all_tickets():
    page = request.args.get('page', 1, type=int); filters = {k: v for k, v in request.args.items() if k != 'page' and v}; query = Ticket.query
    if filters.get('status'): query = query.filter(Ticket.status == filters['status'])
    if filters.get('priority'): query = query.filter(Ticket.priority == filters['priority'])
    if filters.get('category_id') and filters['category_id'] != '0': query = query.filter(Ticket.category_id == int(filters['category_id']))
    assignee_id_filter = filters.get('assigned_to_id')
    if assignee_id_filter:
        if assignee_id_filter == '0' or assignee_id_filter.lower() == 'none': query = query.filter(Ticket.assigned_to_id.is_(None))
        elif assignee_id_filter.isdigit(): query = query.filter(Ticket.assigned_to_id == int(assignee_id_filter))
    tickets_pagination = query.order_by(Ticket.updated_at.desc()).paginate(page=page, per_page=10, error_out=False)
    categories_for_filter = Category.query.order_by('name').all(); agents_for_filter = User.query.filter(User.role.in_(['agent', 'admin'])).order_by('username').all()
    return render_template('admin/all_tickets.html', title='All Tickets Overview', tickets_pagination=tickets_pagination, statuses=TICKET_STATUS_CHOICES, priorities=TICKET_PRIORITY_CHOICES, categories=categories_for_filter, agents=agents_for_filter, current_filters=filters)


# --- CLI Commands (init-db updated) ---
@app.cli.command('init-db')
def init_db_command():
    """Drops and recreates all database tables. For MySQL, temporarily disables FK checks."""
    try:
        with app.app_context():
            engine = db.engine # Get the SQLAlchemy engine
            
            if engine.name == 'mysql': # Check if the dialect is MySQL
                app.logger.info("MySQL detected. Attempting to disable FOREIGN_KEY_CHECKS.")
                with engine.connect() as connection:
                    connection.execute(db.text('SET FOREIGN_KEY_CHECKS = 0;'))
                    # Need to commit this change if using transactional DDL or some connection settings
                    if hasattr(connection, 'commit'): connection.commit() 
                    app.logger.info("MySQL: FOREIGN_KEY_CHECKS temporarily disabled.")
            
            app.logger.info("Dropping all tables...")
            db.drop_all()
            app.logger.info("All tables dropped successfully.")

            app.logger.info("Creating all tables...")
            db.create_all()
            app.logger.info("All tables created successfully.")

            if engine.name == 'mysql':
                app.logger.info("Attempting to re-enable FOREIGN_KEY_CHECKS for MySQL.")
                with engine.connect() as connection:
                    connection.execute(db.text('SET FOREIGN_KEY_CHECKS = 1;'))
                    if hasattr(connection, 'commit'): connection.commit()
                    app.logger.info("MySQL: FOREIGN_KEY_CHECKS re-enabled.")
        
        print('Database tables dropped and recreated successfully.')
        app.logger.info('Database tables dropped and recreated successfully via CLI.')
    except Exception as e:
        app.logger.error(f"Error during init-db CLI command: {e}", exc_info=True)
        print(f"Error during init-db: {e}")
        # Attempt to re-enable FK checks if an error occurred after disabling them
        if 'engine' in locals() and engine.name == 'mysql':
            try:
                with app.app_context(): # Need app context for db.engine
                    with db.engine.connect() as connection:
                        connection.execute(db.text('SET FOREIGN_KEY_CHECKS = 1;'))
                        if hasattr(connection, 'commit'): connection.commit()
                        app.logger.info("MySQL: FOREIGN_KEY_CHECKS re-enabled after error during init-db.")
            except Exception as fk_e:
                app.logger.error(f"Failed to re-enable FOREIGN_KEY_CHECKS after error: {fk_e}")

# ... (imports and other parts of app.py remain the same) ...

@app.cli.command('create-initial-data')
def create_initial_data_command():
    with app.app_context():
        # User creation
        users_data = [
            {'username': 'admin', 'email': os.environ.get('ADMIN_USER_EMAIL', 'monish.jodha@cloudkeeper.com'), 'role': 'admin', 'password': os.environ.get('ADMIN_USER_PASSWORD', 'adminpass')},
            {'username': 'agent', 'email': os.environ.get('AGENT_USER_EMAIL', 'monish.jodha+1@cloudkeeper.com'), 'role': 'agent', 'password': os.environ.get('AGENT_USER_PASSWORD', 'agentpass')},
            {'username': 'client', 'email': os.environ.get('CLIENT_USER_EMAIL', 'monish.jodha+2@cloudkeeper.com'), 'role': 'client', 'password': os.environ.get('CLIENT_USER_PASSWORD', 'clientpass')}
        ]
        print("Attempting to create initial users...")
        for u_data in users_data:
            # Check if user exists by username OR email to prevent duplicates
            existing_user = User.query.filter((User.username == u_data['username']) | (User.email == u_data['email'])).first()
            if not existing_user:
                user = User(username=u_data['username'], email=u_data['email'], role=u_data['role'])
                user.set_password(u_data['password'])
                db.session.add(user)
                print(f"  User '{u_data['username']}' with email '{u_data['email']}' created.")
            else:
                print(f"  Skipping user creation for '{u_data['username']}' (or email '{u_data['email']}'), already exists.")
        
        # Options creation (Categories, Cloud Providers, Environments)
        print("\nEnsuring default options (Categories, Cloud Providers, Environments)...")
        options_map = {
            Category: ['Technical Support', 'Billing Inquiry', 'General Question', 'Feature Request'],
            CloudProviderOption: ['AWS', 'Azure', 'GCP', 'On-Premise', 'Other'],
            EnvironmentOption: ['Production', 'Staging', 'Development', 'Test', 'QA', 'UAT']
        }
        for model_class, names in options_map.items():
            created_count = 0
            for name_val in names:
                if not model_class.query.filter_by(name=name_val).first():
                    instance_args = {'name': name_val}
                    if hasattr(model_class, 'is_active'): # Only add is_active if the model supports it
                        instance_args['is_active'] = True
                    # For Category model, if it has 'description' and it's not explicitly set,
                    # you might want to add a default description or leave it as is.
                    # Example: if model_class == Category and 'description' not in instance_args:
                    #    instance_args['description'] = "Default description for " + name_val
                    
                    db.session.add(model_class(**instance_args))
                    created_count +=1
            if created_count > 0: print(f"  Added {created_count} new default {model_class.__name__}(s).")
            else: print(f"  Default {model_class.__name__}s already exist or no new ones needed.")

        # Severity Levels creation
        print("\nEnsuring default Severity Levels...")
        severities_data = [
            {'name': 'Severity 1 (Critical)', 'o': 1, 'd': 'Critical impact, system down or major functionality unusable.'},
            {'name': 'Severity 2 (High)', 'o': 2, 'd': 'Significant impact, core functionality impaired or severely degraded.'},
            {'name': 'Severity 3 (Medium)', 'o': 3, 'd': 'Moderate impact, non-critical functionality affected or minor issues.'},
            {'name': 'Severity 4 (Low)', 'o': 4, 'd': 'Minor impact, cosmetic issue, question, or documentation error.'}
        ]
        created_severity_count = 0
        for sev_data in severities_data:
            if not SeverityOption.query.filter_by(name=sev_data['name']).first():
                db.session.add(SeverityOption(name=sev_data['name'], order=sev_data['o'], description=sev_data['d'], is_active=True))
                created_severity_count +=1
        if created_severity_count > 0: print(f"  Added {created_severity_count} new default Severity Levels.")
        else: print(f"  Default Severity Levels already exist or no new ones needed.")
        
        # Commit users, options, and severities before creating dependent ticket/interactions
        try:
            db.session.commit()
            print("\nUsers, options, and severities committed successfully.")
        except Exception as e:
            db.session.rollback()
            print(f"\nError committing users/options/severities: {e}")
            app.logger.error(f"Error committing initial base data: {e}", exc_info=True)
            return # Stop if base data fails

        # Dummy ticket and interactions
        client_user = User.query.filter_by(role='client').first()
        admin_user = User.query.filter_by(role='admin').first()
        
        if not client_user or not admin_user:
            print("\nSkipping dummy ticket/interactions: Default client or admin user not found.")
            return

        first_ticket = Ticket.query.order_by(Ticket.id.asc()).first()

        if not first_ticket: # Create a dummy ticket if none exist
            print("\nNo existing tickets found. Creating a dummy ticket for interaction testing...")
            dummy_category = Category.query.filter_by(name='Technical Support').first()
            if not dummy_category: # Failsafe if default categories weren't created
                dummy_category = Category(name="Technical Support", description="Default technical support category")
                db.session.add(dummy_category)
            
            dummy_severity = SeverityOption.query.filter_by(name='Severity 3 (Medium)').first()
            if not dummy_severity: # Failsafe
                dummy_severity = SeverityOption(name='Severity 3 (Medium)', order=3, description="Default medium severity")
                db.session.add(dummy_severity)
            
            db.session.flush() # Get IDs if new category/severity were added

            first_ticket = Ticket(
                title="Sample Initial Ticket for Interaction Demo",
                description="This is a test ticket created to demonstrate the interaction history feature. It will have several simulated events.",
                created_by_id=client_user.id,
                category_id=dummy_category.id,
                severity=dummy_severity.name,
                status='Open' # Start with Open
            )
            db.session.add(first_ticket)
            try:
                db.session.flush() # Get ID for first_ticket
                log_interaction(
                    ticket_id=first_ticket.id,
                    interaction_type='TICKET_CREATED',
                    user_id=client_user.id,
                    details={'title': first_ticket.title},
                    timestamp_override=first_ticket.created_at
                )
                db.session.commit() # Commit the new ticket and its creation interaction
                print(f"  Created dummy ticket #{first_ticket.id} and logged its creation.")
            except Exception as e:
                db.session.rollback()
                print(f"  Error creating dummy ticket or logging its creation: {e}")
                app.logger.error(f"Dummy ticket creation error: {e}", exc_info=True)
                return # Stop if dummy ticket creation fails
        
        # Add dummy interactions for the first_ticket
        if first_ticket: # Should always be true if we reached here
            print(f"\nAdding dummy interactions for ticket #{first_ticket.id}...")
            # Ensure base TICKET_CREATED exists (might be redundant if just created)
            if not Interaction.query.filter_by(ticket_id=first_ticket.id, interaction_type='TICKET_CREATED').first():
                 log_interaction(first_ticket.id, 'TICKET_CREATED', user_id=first_ticket.created_by_id, details={'title': first_ticket.title}, timestamp_override=first_ticket.created_at)

            current_ts = first_ticket.created_at # Start timestamp for subsequent events

            # Status change to "New" - simulated to happen yesterday
            status_new_ts = datetime.utcnow() - timedelta(days=1, hours=datetime.utcnow().hour - 9, minutes=datetime.utcnow().minute - 8) # Yesterday 09:08
            if status_new_ts <= current_ts : status_new_ts = current_ts + timedelta(minutes=10) # Ensure it's after creation
            
            original_status_before_new = first_ticket.status
            first_ticket.status = 'New' # Update ticket object's status in memory
            log_interaction(first_ticket.id, 'STATUS_CHANGE', user_id=admin_user.id, details={'old_status': original_status_before_new, 'new_status': 'New'}, timestamp_override=status_new_ts)
            current_ts = status_new_ts
            print(f"  Logged STATUS_CHANGE to 'New' at {current_ts.strftime('%Y-%m-%d %H:%M:%S')}")

            # Article Views (simulated "May 20" type events - make them after "New" status, but before "In Progress")
            article_view_time_1 = current_ts + timedelta(minutes=30) # e.g., Yesterday 09:38
            article_view_time_2 = current_ts + timedelta(minutes=32) # e.g., Yesterday 09:40
            log_interaction(first_ticket.id, 'ARTICLE_VIEWED', user_id=client_user.id, details={'article_title': 'How do I publish my content?', 'source': 'Help Center'}, timestamp_override=article_view_time_1)
            log_interaction(first_ticket.id, 'ARTICLE_VIEWED', user_id=client_user.id, details={'article_title': 'How do I publish my content?', 'source': 'Help Center'}, timestamp_override=article_view_time_2)
            current_ts = article_view_time_2
            print(f"  Logged ARTICLE_VIEWED at {article_view_time_1.strftime('%Y-%m-%d %H:%M:%S')} and {article_view_time_2.strftime('%Y-%m-%d %H:%M:%S')}")

            # Status change to "In Progress" - simulated to happen "Today" (this will be the top group in image)
            status_in_progress_ts = datetime.utcnow() - timedelta(hours=datetime.utcnow().hour - 17, minutes=datetime.utcnow().minute - 41, seconds=5) # Today 17:41:05
            if status_in_progress_ts <= current_ts : status_in_progress_ts = current_ts + timedelta(hours=1) # Ensure it's after article views
            if status_in_progress_ts > datetime.utcnow(): status_in_progress_ts = datetime.utcnow() - timedelta(minutes=30) # Ensure it's in the past

            original_status_before_in_progress = first_ticket.status
            first_ticket.status = 'In Progress' # Update ticket object's status
            log_interaction(first_ticket.id, 'STATUS_CHANGE', user_id=admin_user.id, details={'old_status': original_status_before_in_progress, 'new_status': 'In Progress'}, timestamp_override=status_in_progress_ts)
            current_ts = status_in_progress_ts
            print(f"  Logged STATUS_CHANGE to 'In Progress' at {current_ts.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Very Recent - Another Article View (after "In Progress")
            very_recent_article_time = current_ts + timedelta(minutes=10) 
            if very_recent_article_time > datetime.utcnow(): very_recent_article_time = datetime.utcnow() - timedelta(minutes=5) # Ensure it's in the past
            log_interaction(first_ticket.id, 'ARTICLE_VIEWED', user_id=client_user.id, details={'article_title': 'Understanding In Progress state', 'source': 'KB Article'}, timestamp_override=very_recent_article_time)
            print(f"  Logged ARTICLE_VIEWED at {very_recent_article_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            print(f"  Finished adding dummy interactions for ticket #{first_ticket.id}.")
            # Commit all interactions and ticket status updates for this ticket
            try:
                db.session.add(first_ticket) # Ensure ticket status change is staged
                db.session.commit()
                print(f"  Committed interactions and status updates for ticket #{first_ticket.id}.")
            except Exception as e:
                db.session.rollback()
                print(f"  Error committing interactions for ticket #{first_ticket.id}: {e}")
                app.logger.error(f"Interaction commit error: {e}", exc_info=True)

        else:
            print("\nSkipping dummy interactions: First ticket, client or admin user not found.")
        
        print("\nInitial data creation process finished.")
# ... (the rest of app.py, including if __name__ == '__main__': block) ...

if __name__ == '__main__':
    # UPLOAD_FOLDER check at startup, using app.root_path for more robust relative path resolution
    upload_folder_path_at_startup = app.config.get('UPLOAD_FOLDER')
    app.logger.info(f"Startup: Initial UPLOAD_FOLDER from config: {upload_folder_path_at_startup}")

    if not os.path.isabs(upload_folder_path_at_startup):
        # If it's relative, make it relative to the app's root path
        upload_folder_path_at_startup = os.path.join(app.root_path, upload_folder_path_at_startup)
        app.config['UPLOAD_FOLDER'] = upload_folder_path_at_startup # Update config
        app.logger.info(f"Startup: UPLOAD_FOLDER resolved to absolute: {upload_folder_path_at_startup}")

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            app.logger.info(f"Startup: Upload folder ensured/created at: {app.config['UPLOAD_FOLDER']}")
        except OSError as e:
            app.logger.critical(f"CRITICAL: Could not create upload folder {app.config['UPLOAD_FOLDER']}: {e}. Check path and permissions.", exc_info=True)
            # sys.exit(1) # Consider exiting if uploads are essential

    app.run(debug=True, host='0.0.0.0', port=5000)