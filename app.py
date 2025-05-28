import os
from datetime import datetime, timedelta # Added timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, current_app, send_from_directory, session
import flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, UserMixin, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import urlparse, quote_plus # quote_plus for password encoding
from functools import wraps
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, IntegerField, MultipleFileField
from wtforms.widgets import TextArea as TextAreaWidget
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, Optional, NumberRange, InputRequired
import logging
from markupsafe import escape, Markup
import re # Ensure re is imported
import uuid
from flask_mail import Mail, Message
import sys
import logging
from importlib.metadata import version, PackageNotFoundError


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

# --- Helper function to convert CamelCase to snake_case ---
def to_snake_case(name):
    name = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', name)
    name = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name).lower()
    # Specific replacements for this application's model naming convention
    if name.endswith("_option"): # e.g. cloud_provider_option -> cloud_provider
        name = name[:-7]
    elif name.endswith("option"): # Should be caught by above, but as fallback
        name = name[:-6]
    return name

# --- Configuration ---
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ticket-cms-agent-views-final-key-secure'
    MYSQL_USER = os.environ.get('MYSQL_USER_TICKET_CMS') or 'ticket_user'
    _raw_mysql_password = os.environ.get('MYSQL_PASSWORD_TICKET_CMS') or 'Jodha@123'
    MYSQL_PASSWORD_ENCODED = quote_plus(_raw_mysql_password) if _raw_mysql_password else ''
    MYSQL_HOST = os.environ.get('MYSQL_HOST_TICKET_CMS') or 'localhost'
    MYSQL_DB = os.environ.get('MYSQL_DB_TICKET_CMS') or 'ticket_cms_db'
    MYSQL_CHARSET = 'utf8mb4'
    APPLICATION_ROOT = '/'  # <--- TEMPORARILY HARDCODE THIS


    if not all([MYSQL_USER, _raw_mysql_password, MYSQL_HOST, MYSQL_DB]):
        print("FATAL ERROR: Missing critical MySQL configuration. Set environment variables or defaults in Config.")
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
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME_TICKET_CMS')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD_TICKET_CMS')
    MAIL_DEFAULT_SENDER_EMAIL = os.environ.get('MAIL_DEFAULT_SENDER_EMAIL_TICKET_CMS')
    MAIL_DEFAULT_SENDER = ('TicketSys Admin', MAIL_DEFAULT_SENDER_EMAIL or 'noreply@example.com')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL_TICKET_CMS')
    
    IMAP_SERVER = os.environ.get('IMAP_SERVER_TICKET_CMS_FETCH') or 'imap.gmail.com'
    IMAP_USERNAME = os.environ.get('IMAP_USERNAME_TICKET_CMS_FETCH')
    IMAP_PASSWORD = os.environ.get('IMAP_PASSWORD_TICKET_CMS_FETCH') or 'placeholder16apppass' # Corrected Placeholder
    IMAP_MAILBOX_FOLDER = os.environ.get('IMAP_MAILBOX_FOLDER_TICKET_CMS_FETCH') or 'INBOX'
    EMAIL_TICKET_DEFAULT_CATEGORY_NAME = os.environ.get('EMAIL_TICKET_DEFAULT_CATEGORY_NAME') or 'General Inquiry'
    EMAIL_TICKET_DEFAULT_SEVERITY_NAME = os.environ.get('EMAIL_TICKET_DEFAULT_SEVERITY_NAME') or 'Severity 3 (Medium)'
    
    BASE_URL = os.environ.get('BASE_URL') or 'http://localhost:5000'
    _parsed_base = urlparse(BASE_URL)

    SERVER_NAME = os.environ.get('SERVER_NAME') or _parsed_base.netloc

    # Ensure APPLICATION_ROOT is a valid path only
    parsed_path = _parsed_base.path.strip()
    APPLICATION_ROOT = os.environ.get('APPLICATION_ROOT') or (parsed_path if parsed_path.startswith('/') else '/')

    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME') or _parsed_base.scheme or 'http'


    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'log', 'csv'}
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH') or 16 * 1000 * 1000)

    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID_TICKET_CMS')
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN_TICKET_CMS')
    TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER_TICKET_CMS')
    EMERGENCY_CALL_RECIPIENT_PHONE_NUMBER = os.environ.get('EMERGENCY_CALL_RECIPIENT_PHONE_NUMBER_TICKET_CMS')
    SEVERITIES_FOR_CALL_ALERT = ["Severity 1 (Critical)", "Severity 2 (High)"]

app = Flask(__name__)
app.config.from_object(Config)

app.logger.info(f"--- App Start --- FLASK_VERSION: {flask.__version__}")

#  ADD OR ENSURE THESE LOGS ARE PRESENT AND EARLY
app.logger.info(f"--- App Start --- PYTHON_VERSION: {sys.version}") # Add sys import: import sys
from importlib.metadata import version, PackageNotFoundError

try:
    flask_version = version("flask")
except PackageNotFoundError:
    flask_version = "unknown"

try:
    flask_login_version = version("flask-login")
except PackageNotFoundError:
    flask_login_version = "unknown"

app.logger.info(f"--- App Start --- FLASK_VERSION: {flask_version}")
app.logger.info(f"--- App Start --- FLASK_LOGIN_VERSION: {flask_login_version}")
app.logger.info(f"--- App Start --- FLASK_LOGIN_VERSION: {LoginManager.__version__ if hasattr(LoginManager, '__version__') else 'N/A'}") # Check if LoginManager has __version__
app.logger.info(f"--- App Start --- FLASK_ENV from app.config: '{app.config.get('ENV', app.config.get('FLASK_ENV'))}'")
app.logger.info(f"--- App Start --- DEBUG from app.config: {app.config.get('DEBUG')}")
app.logger.info(f"--- App Start --- SECRET_KEY set in app.config: {bool(app.config.get('SECRET_KEY'))}")
app.logger.info(f"--- App Start --- RAW BASE_URL from app.config: '{app.config.get('BASE_URL')}'")
app.logger.info(f"--- App Start --- RAW SERVER_NAME from app.config: '{app.config.get('SERVER_NAME')}'")
app.logger.info(f"--- App Start --- RAW APPLICATION_ROOT from app.config: '{app.config.get('APPLICATION_ROOT')}'") # <<< THE MOST IMPORTANT ONE
app.logger.info(f"--- App Start --- RAW PREFERRED_URL_SCHEME from app.config: '{app.config.get('PREFERRED_URL_SCHEME')}'")


# ... rest of app initialization

# Post-config adjustments for MAIL_DEFAULT_SENDER
if not app.config['MAIL_DEFAULT_SENDER_EMAIL']:
    app.logger.warning("MAIL_DEFAULT_SENDER_EMAIL is not set in environment. Defaulting sender email to 'noreply@example.com'.")
    # This reassignment ensures the tuple structure if it was somehow modified, though unlikely with current Config.
    app.config['MAIL_DEFAULT_SENDER'] = ('TicketSys Admin', 'noreply@example.com')
elif isinstance(app.config['MAIL_DEFAULT_SENDER'], tuple) and \
     app.config['MAIL_DEFAULT_SENDER'][1] != app.config['MAIL_DEFAULT_SENDER_EMAIL'] and \
     app.config['MAIL_DEFAULT_SENDER_EMAIL'] is not None:
    app.config['MAIL_DEFAULT_SENDER'] = ('TicketSys Admin', app.config['MAIL_DEFAULT_SENDER_EMAIL'])


if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError("SQLALCHEMY_DATABASE_URI is not configured. Application cannot start.")

csrf = CSRFProtect(app)
mail = Mail(app)
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'])
        app.logger.info(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")
    except OSError as e:
        app.logger.error(f"Could not create upload folder {app.config['UPLOAD_FOLDER']}: {e}")

def nl2br_filter(value):
    if not isinstance(value, str): value = str(value)
    escaped_value = escape(value)
    br_value = re.sub(r'(\r\n|\r|\n)', '<br>\n', escaped_value)
    return Markup(br_value)
app.jinja_env.filters['nl2br'] = nl2br_filter

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

db = SQLAlchemy(app)

# --- Models ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default='client', nullable=False) # Roles: client, agent, admin
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

# --- Forms ---
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
    # InputRequired is better for select fields with a "placeholder" option like 0 or ''
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
    
    # Redundant if InputRequired is used correctly with placeholder choice values (0 for int, '' for str)
    # def validate_category(self, field):
    #     if field.data == 0 and any(isinstance(v, (DataRequired, InputRequired)) for v in field.validators): 
    #         raise ValidationError("Category is a required field.")

    # def validate_severity(self, field):
    #     if not field.data and any(isinstance(v, (DataRequired, InputRequired)) for v in field.validators): 
    #         raise ValidationError("Severity is a required field.")

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

# --- Flask-Login, Context Processors, Decorators ---
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

# --- Helper functions for dynamic choices ---
def get_active_cloud_provider_choices():
    return [('', '--- Select Cloud Provider ---')] + [(p.name, p.name) for p in CloudProviderOption.query.filter_by(is_active=True).order_by(CloudProviderOption.name).all()]
def get_active_severity_choices():
    return [('', '--- Select Severity* ---')] + [(opt.name, opt.name) for opt in SeverityOption.query.filter_by(is_active=True).order_by(SeverityOption.order, SeverityOption.name).all()]
def get_active_environment_choices():
    return [('', '--- Select Environment ---')] + [(opt.name, opt.name) for opt in EnvironmentOption.query.filter_by(is_active=True).order_by(EnvironmentOption.name).all()]

# --- Twilio Helper Function ---
def trigger_priority_call_alert(ticket, old_severity=None):
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

    # If severity was already high and remains high (even if different high, e.g. High -> Urgent), still alert if old_severity != new_severity
    # If old_severity == new_severity AND it's an alertable severity, then skip (no change)
    if old_severity is not None and old_severity == new_severity and new_severity in alert_severities:
        app.logger.info(f"Ticket #{ticket.id} severity '{new_severity}' remains unchanged and high. No new call alert needed.")
        return
    
    app.logger.info(f"Ticket #{ticket.id} severity change triggers call alert. Old: '{old_severity}', New: '{new_severity}'.")
    
    try:
        client = TwilioClient(account_sid, auth_token)
        sanitized_title = re.sub(r'[^\w\s,.-]', '', ticket.title)
        
        if old_severity is None or old_severity not in alert_severities:
            alert_reason = "created"
        else: # It was already an alertable severity, or changed from one to another
            alert_reason = f"updated from {old_severity} to {new_severity}"

        message_to_say = (
            f"Hello. This is an urgent alert from the Ticket System. "
            f"A high priority ticket, number {ticket.id}, has been {alert_reason}. "
            f"Severity is now {new_severity}. "
            f"Subject: {sanitized_title}. "
            f"Please check the system immediately."
        )
        twiml_instruction = f'<Response><Say>{escape(message_to_say)}</Say></Response>'
        call = client.calls.create(
            twiml=twiml_instruction,
            to=recipient_phone_number,
            from_=twilio_phone_number
        )
        app.logger.info(f"Twilio call initiated for ticket #{ticket.id} to {recipient_phone_number}. Call SID: {call.sid}")
        flash(f'High priority ticket #{ticket.id} alert ({alert_reason}): Call initiated to {recipient_phone_number}.', 'info')
    except TwilioRestException as e:
        app.logger.error(f"Twilio API error for ticket #{ticket.id}: {e}")
        flash(f'Error initiating Twilio call for ticket #{ticket.id}: {e.message}', 'danger')
    except Exception as e:
        app.logger.error(f"Unexpected error during Twilio call for ticket #{ticket.id}: {e}")
        flash(f'An unexpected error occurred while trying to initiate a call for ticket #{ticket.id}.', 'danger')

# --- Routes ---
@app.route('/')
@app.route('/index')
def index():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template('index.html', title='Welcome')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (initial logging as before) ...
    app.logger.info(f"--- Login Route (Top) --- Accessed /login. current_user: {current_user}, is_authenticated: {current_user.is_authenticated}")
    app.logger.info(f"--- Login Route (Top) --- Session contents: {dict(session)}")

    if current_user.is_authenticated:
        next_page = request.args.get('next')
        app.logger.info(f"--- Login Route --- User '{current_user.username}' is already authenticated. 'next' page: {next_page}")

        is_safe_next = False
        # Directly get the configured APPLICATION_ROOT
        # It SHOULD be a path like '/' or '/myapp/'
        actual_app_root = app.config.get('APPLICATION_ROOT', '/') 
        app.logger.info(f"--- Login Route --- Evaluating 'next_page': '{next_page}', actual_app_root_from_config: '{actual_app_root}'")

        if next_page:
            # Ensure next_page itself is a path and not a full URL for this check
            if not ('://' in next_page or next_page.startswith('//')):
                # A "safe" next_page should start with the application root path.
                # Example: if app_root is '/myapp/', next_page '/myapp/tickets/new' is safe.
                # Example: if app_root is '/', next_page '/tickets/new' is safe.
                if next_page.startswith(actual_app_root):
                    is_safe_next = True
        
        app.logger.info(f"--- Login Route --- is_safe_next determination: {is_safe_next}")

        if is_safe_next:
            app.logger.info(f"--- Login Route --- Redirecting authenticated user '{current_user.username}' to safe 'next' page: {next_page}")
            return redirect(next_page)
        else:
            if next_page:
                app.logger.warning(f"--- Login Route --- Unsafe or non-matching 'next' page ('{next_page}') for authenticated user '{current_user.username}' with app_root '{actual_app_root}'. Redirecting to dashboard.")
            else:
                app.logger.info(f"--- Login Route --- No 'next' page for authenticated user '{current_user.username}'. Redirecting to dashboard.")
            return redirect(url_for('dashboard'))

    # ... (rest of the login form processing for unauthenticated users, use similar safe next logic) ...
    form = LoginForm()
    if form.validate_on_submit():
        # ... (user loading and password check) ...
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            # ... (login_user call and logging) ...
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
                    if next_page_after_login.startswith(actual_app_root_after_login):
                        is_safe_next_after_login = True
            
            app.logger.info(f"--- Login Route --- is_safe_next_after_login determination: {is_safe_next_after_login}")
            
            if is_safe_next_after_login:
                app.logger.info(f"--- Login Route --- Redirecting newly logged in user '{user.username}' to safe 'next' page: {next_page_after_login}")
                return redirect(next_page_after_login)
            else:
                if next_page_after_login:
                    app.logger.warning(f"--- Login Route --- Unsafe or non-matching 'next' page ('{next_page_after_login}') after login for '{user.username}' with app_root '{actual_app_root_after_login}'. Redirecting to dashboard.")
                else:
                    app.logger.info(f"--- Login Route --- No 'next' page after login for '{user.username}'. Redirecting to dashboard.")
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            app.logger.warning(f"--- Login Route --- Failed login attempt for username: {form.username.data}")
            
    app.logger.info("--- Login Route --- Rendering login page for unauthenticated user.")
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
@login_required
def logout():
    app.logger.info(f"User '{current_user.username}' logged out.")
    logout_user() # This invalidates the Flask-Login session
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache-clearInspire disabling caching.
    """
    if '/static/' not in request.path: # Don't add to static files
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0' # Or '-1'
    return response

@app.route('/register/client', methods=['GET', 'POST'])
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

@app.route('/register/agent', methods=['GET', 'POST'])
def register_agent():
    form = UserSelfRegistrationForm()

    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data.lower(),
            role='agent'  # hardcoded as agent
        )
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

    return render_template(
        'register_user.html',
        title='Register New Agent',
        form=form,
        registration_type='Agent',
        info_text='Register new support agents to assist clients.'
    )



@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_authenticated:
        app.logger.warning(f"Unauthenticated access to /dashboard despite @login_required. Current_user: {current_user}")
        return redirect(url_for('login', next=request.url))

    app.logger.info(f"Dashboard accessed by: {current_user.username if current_user.is_authenticated else 'Anonymous'}") 
    if current_user.is_admin:
        stats = {
            'total_tickets': Ticket.query.count(),
            'open_tickets': Ticket.query.filter_by(status='Open').count(),
            'inprogress_tickets': Ticket.query.filter_by(status='In Progress').count(),
            'resolved_tickets': Ticket.query.filter_by(status='Resolved').count(),
            'total_users': User.query.count()
        }
        return render_template('dashboard.html', title='Admin Dashboard', **stats)
    elif current_user.is_agent:
        agent_data = {
            'my_assigned_tickets': Ticket.query.filter_by(assigned_to_id=current_user.id).filter(Ticket.status.notin_(['Resolved', 'Closed'])).order_by(Ticket.updated_at.desc()).all(),
            'unassigned_tickets': Ticket.query.filter_by(assigned_to_id=None, status='Open').order_by(Ticket.created_at.desc()).limit(10).all()
        }
        return render_template('dashboard.html', title='Agent Dashboard', **agent_data)
    else: # Client dashboard
        my_tickets = Ticket.query.filter_by(created_by_id=current_user.id).order_by(Ticket.updated_at.desc()).limit(10).all()
        return render_template('dashboard.html', title='My Dashboard', my_tickets=my_tickets)

@app.route('/tickets/new', methods=['GET', 'POST'])
@login_required # RESTORE THIS!
def create_ticket():
    # DETAILED LOGGING AT THE START OF THE ROUTE
    app.logger.info(f"--- Create Ticket Route (Top) --- Accessed /tickets/new.")
    app.logger.info(f"--- Create Ticket Route (Top) --- current_user: {current_user}, is_authenticated: {current_user.is_authenticated}")
    app.logger.info(f"--- Create Ticket Route (Top) --- Session contents: {dict(session)}")

    # # If, despite @login_required, we somehow get an AnonymousUser, this will catch it early
    # if not current_user.is_authenticated:
    #     app.logger.error("--- Create Ticket Route --- CRITICAL: Unauthenticated user accessed route despite @login_required. This should not happen. Redirecting to login.")
    #     return redirect(url_for('login', next=request.url))


    form = CreateTicketForm()
    # ... (rest of your create_ticket function is fine)
    form.category.choices = [(0, '--- Select Issue Category* ---')] + [(c.id, c.name) for c in Category.query.order_by('name').all()]
    form.cloud_provider.choices = get_active_cloud_provider_choices() 
    form.severity.choices = get_active_severity_choices() 
    form.environment.choices = get_active_environment_choices()

    if not form.category.choices[1:]:
        flash("Critical: No categories defined. Contact admin.", "danger")
    if not form.severity.choices[1:]:
        flash("Critical: No severity levels defined. Contact admin.", "danger")

    if form.validate_on_submit():
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
                            uploaded_files_info.append({
                                'original_filename': filename,
                                'stored_filename': stored_filename,
                                'content_type': file_storage.content_type
                            })
                        except Exception as e:
                            app.logger.error(f"Failed to save attachment {filename}: {e}")
                            form.attachments.errors.append(f"Could not save file: {filename}")
                            flash(f"Error saving attachment {filename}. Please try again.", "danger")
                    else:
                        form.attachments.errors.append(f"File type not allowed: {file_storage.filename}")
                        flash(f"File type not allowed for {file_storage.filename}.", "danger")
        
        if form.attachments.errors:
            pass 
        else:
            ticket = Ticket(
                title=form.title.data,
                description=form.description.data,
                created_by_id=current_user.id, # This line would fail if current_user is Anonymous
                category_id=form.category.data, 
                cloud_provider=form.cloud_provider.data or None,
                severity=form.severity.data, 
                aws_service=form.aws_service.data if form.cloud_provider.data == 'AWS' and form.aws_service.data else None,
                aws_account_id=form.aws_account_id.data or None,
                environment=form.environment.data or None,
            )
            db.session.add(ticket)
            try:
                db.session.flush() 
                for file_info in uploaded_files_info:
                    attachment = Attachment(
                        filename=file_info['original_filename'],
                        stored_filename=file_info['stored_filename'],
                        ticket_id=ticket.id,
                        uploaded_by_id=current_user.id,
                        content_type=file_info['content_type']
                    )
                    db.session.add(attachment)
                db.session.commit()
                flash('Ticket created successfully!', 'success')
                app.logger.info(f"Ticket #{ticket.id} created by {current_user.username} with severity '{ticket.severity}'")
                
                try:
                    recipients_admin_agent = list(set(
                        ([app.config['ADMIN_EMAIL']] if app.config['ADMIN_EMAIL'] else []) + 
                        [user.email for user in User.query.filter(User.role.in_(['admin', 'agent'])).all() if user.email]
                    ))
                    if recipients_admin_agent:
                        msg_admin = Message(
                            f"New Ticket Submitted: #{ticket.id} - {ticket.title}",
                            recipients=[r for r in recipients_admin_agent if r], 
                            body=render_template('email/new_ticket_admin_notification.txt', ticket=ticket, user=current_user,
                                                 ticket_url=url_for('view_ticket', ticket_id=ticket.id, _external=True))
                        )
                        mail.send(msg_admin)
                    additional_emails = [email.strip() for email in (form.additional_recipients.data or "").split(',') if email.strip()]
                    creator_and_additional_emails = list(set(additional_emails + ([current_user.email] if current_user.email else [])))
                    if creator_and_additional_emails:
                        msg_additional = Message(
                            f"Confirmation: Your Ticket #{ticket.id} - {ticket.title}",
                            recipients=[r for r in creator_and_additional_emails if r],
                            body=render_template('email/ticket_info_recipient.txt', ticket=ticket, submitter=current_user,
                                                 ticket_url=url_for('view_ticket', ticket_id=ticket.id, _external=True))
                        )
                        mail.send(msg_additional)
                except Exception as e:
                    app.logger.error(f"Failed to send email notifications for ticket #{ticket.id}: {e}")
                
                trigger_priority_call_alert(ticket, old_severity=None) 
                return redirect(url_for('view_ticket', ticket_id=ticket.id))
            except Exception as e:
                db.session.rollback()
                flash(f'Database error: Could not save ticket. {str(e)[:150]}', 'danger')
                app.logger.error(f"Ticket save DB error: {e}")
                for file_info in uploaded_files_info:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_info['stored_filename']))
                    except OSError: pass 
    elif request.method == 'POST':
        flash('Please correct the errors in the form.', 'danger')
    return render_template('client/create_ticket.html', title='Submit New Support Request', form=form)

@app.route('/tickets/my')
@login_required
def my_tickets():
    tickets = Ticket.query.filter_by(created_by_id=current_user.id).order_by(Ticket.updated_at.desc()).all()
    return render_template('client/my_tickets.html', title='My Submitted Tickets', tickets=tickets)

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if not (current_user.is_admin or current_user.is_agent or \
            ticket.created_by_id == current_user.id or \
            (ticket.assigned_to_id and ticket.assigned_to_id == current_user.id) ):
        flash('You do not have permission to view this ticket.', 'danger')
        return redirect(url_for('dashboard'))

    comment_form = CommentForm()
    agent_update_form = None
    attachments = ticket.ticket_attachments.order_by(Attachment.uploaded_at.desc()).all()

    if current_user.is_agent or current_user.is_admin:
        agent_update_form = AgentUpdateTicketForm(obj=None) # Don't pass obj on POST, it gets data from request.form
        agent_choices = [(u.id, u.username) for u in User.query.filter(User.role.in_(['agent', 'admin'])).order_by('username').all()]
        cat_choices = [(c.id, c.name) for c in Category.query.order_by('name').all()]
        
        agent_update_form.assigned_to_id.choices = [(0, '--- Unassign/Select Agent ---')] + agent_choices
        agent_update_form.category_id.choices = [(0, '--- No Category ---')] + cat_choices # Assuming 0 is not a valid ID
        agent_update_form.cloud_provider.choices = get_active_cloud_provider_choices()
        agent_update_form.severity.choices = get_active_severity_choices()
        agent_update_form.environment.choices = get_active_environment_choices()

        if request.method == 'GET': 
            agent_update_form.status.data = ticket.status
            agent_update_form.priority.data = ticket.priority
            agent_update_form.assigned_to_id.data = ticket.assigned_to_id or 0 # 0 for placeholder
            agent_update_form.category_id.data = ticket.category_id or 0 # 0 for placeholder
            agent_update_form.cloud_provider.data = ticket.cloud_provider or '' # '' for placeholder
            agent_update_form.severity.data = ticket.severity or '' # '' for placeholder
            agent_update_form.aws_service.data = ticket.aws_service or ''
            agent_update_form.aws_account_id.data = ticket.aws_account_id or ''
            agent_update_form.environment.data = ticket.environment or ''

    if request.method == 'POST':
        if 'submit_comment' in request.form and comment_form.validate_on_submit():
            is_internal_comment = hasattr(comment_form, 'is_internal') and \
                                  comment_form.is_internal.data and \
                                  (current_user.is_agent or current_user.is_admin)
            comment = Comment(content=comment_form.content.data, user_id=current_user.id, ticket_id=ticket.id, is_internal=is_internal_comment)
            db.session.add(comment)
            ticket.updated_at = datetime.utcnow()
            db.session.commit()
            flash('Your comment has been added.', 'success')
            app.logger.info(f"Comment added to ticket #{ticket.id} by {current_user.username}")
            return redirect(url_for('view_ticket', ticket_id=ticket.id, _anchor='comments_section'))
        
        elif 'submit_update' in request.form and agent_update_form and agent_update_form.validate_on_submit():
            old_severity_on_update = ticket.severity 
            ticket.status = agent_update_form.status.data
            ticket.priority = agent_update_form.priority.data
            ticket.assigned_to_id = agent_update_form.assigned_to_id.data if agent_update_form.assigned_to_id.data != 0 else None
            ticket.category_id = agent_update_form.category_id.data if agent_update_form.category_id.data != 0 else None
            ticket.cloud_provider = agent_update_form.cloud_provider.data or None
            ticket.severity = agent_update_form.severity.data or None 
            ticket.aws_service = agent_update_form.aws_service.data if agent_update_form.cloud_provider.data == 'AWS' and agent_update_form.aws_service.data else None
            ticket.aws_account_id = agent_update_form.aws_account_id.data or None
            ticket.environment = agent_update_form.environment.data or None
            ticket.updated_at = datetime.utcnow()
            try:
                db.session.commit()
                flash('Ticket details updated successfully.', 'success')
                app.logger.info(f"Ticket #{ticket.id} updated by {current_user.username}. Old severity: '{old_severity_on_update}', New severity: '{ticket.severity}'.")
                trigger_priority_call_alert(ticket, old_severity=old_severity_on_update)
                return redirect(url_for('view_ticket', ticket_id=ticket.id))
            except Exception as e:
                db.session.rollback()
                flash(f'Database error during ticket update: {str(e)[:150]}', 'danger')
                app.logger.error(f"Ticket update DB error for #{ticket.id}: {e}")
        elif 'submit_update' in request.form and agent_update_form and not agent_update_form.validate_on_submit():
             flash('Error updating ticket. Please check agent form fields.', 'danger')
        elif 'submit_comment' in request.form and not comment_form.validate_on_submit():
            flash('Error adding comment. Please check comment field.', 'danger')


    comments_query = ticket.comments
    if not (current_user.is_agent or current_user.is_admin): # Client view
        comments_query = comments_query.filter_by(is_internal=False)
        if hasattr(comment_form, 'is_internal'): 
            delattr(comment_form, 'is_internal') # Remove internal toggle for clients
            
    comments = comments_query.order_by(Comment.created_at.asc()).all()
    
    return render_template('client/view_ticket.html', title=f'Ticket #{ticket.id}: {ticket.title}', ticket=ticket,
                           comments=comments, comment_form=comment_form, agent_update_form=agent_update_form, attachments=attachments)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    attachment = Attachment.query.filter_by(stored_filename=filename).first_or_404()
    ticket = attachment.ticket
    if not (current_user.is_admin or current_user.is_agent or \
            current_user.id == attachment.uploaded_by_id or \
            current_user.id == ticket.created_by_id or \
            (ticket.assigned_to_id and current_user.id == ticket.assigned_to_id)):
        flash("You do not have permission to download this file.", "danger")
        return redirect(request.referrer or url_for('dashboard'))
    try:
        upload_dir = app.config['UPLOAD_FOLDER']
        # Ensure upload_dir is absolute for send_from_directory robustness
        if not os.path.isabs(upload_dir):
            upload_dir = os.path.join(current_app.root_path, upload_dir)

        return send_from_directory(
            upload_dir, attachment.stored_filename,
            as_attachment=True, download_name=attachment.filename
        )
    except FileNotFoundError:
        app.logger.error(f"Physical file not found: {attachment.stored_filename} (orig: {attachment.filename}) for ticket {ticket.id} in dir {upload_dir if 'upload_dir' in locals() else app.config['UPLOAD_FOLDER']}")
        flash("File not found on server. Please contact support.", "danger")
        return redirect(request.referrer or url_for('dashboard'))

@app.route('/agent/tickets/')
@app.route('/agent/tickets/view/<view_name>')
@agent_required
def agent_ticket_list(view_name=None):
    page = request.args.get('page', 1, type=int)
    query = Ticket.query 
    list_title = "Agent Tickets"
    if view_name is None: view_name = 'my_unsolved'

    app.logger.debug(f"Agent ticket list for view: {view_name} by {current_user.username}")

    if view_name == 'my_unsolved':
        query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status.notin_(['Resolved', 'Closed']))
        list_title = "Your Unsolved Tickets"
    elif view_name == 'unassigned':
        query = query.filter(Ticket.assigned_to_id.is_(None), Ticket.status == 'Open')
        list_title = "Unassigned Open Tickets"
    elif view_name == 'all_unsolved':
        query = query.filter(Ticket.status.notin_(['Resolved', 'Closed']))
        list_title = "All Unsolved Tickets"
    elif view_name == 'recently_updated':
        list_title = "Recently Updated Tickets" # Order applied below
    elif view_name == 'pending':
        query = query.filter(Ticket.status == 'On Hold')
        list_title = "Pending (On Hold) Tickets"
    elif view_name == 'recently_solved':
        query = query.filter(Ticket.status == 'Resolved')
        list_title = "Recently Solved Tickets" # Order applied below
    elif view_name == 'current_tasks':
        query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status == 'In Progress')
        list_title = "Your Current In-Progress Tickets"
    else: 
        flash(f"Unknown ticket view: '{view_name}'. Defaulting to your unsolved tickets.", "warning")
        query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status.notin_(['Resolved', 'Closed']))
        list_title = "Your Unsolved Tickets"
        view_name = 'my_unsolved'
    
    if view_name in ['recently_updated', 'recently_solved', 'all_unsolved', 'unassigned', 'pending']:
        ordered_query = query.order_by(Ticket.updated_at.desc())
    else: # my_unsolved, current_tasks, and default
        priority_order = db.case(
            {'Urgent': 1, 'High': 2, 'Medium': 3, 'Low': 4},
            value=Ticket.priority, else_=5 # Default for any other priority string
        )
        ordered_query = query.order_by(priority_order.asc(), Ticket.updated_at.desc())
        
    tickets_pagination = ordered_query.paginate(page=page, per_page=10, error_out=False)
    return render_template('agent/ticket_list.html', title=list_title,
                           tickets_pagination=tickets_pagination,
                           current_view=view_name)

@app.route('/ticket/<int:ticket_id>/assign_to_me')
@agent_required
def assign_ticket_to_me(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.assigned_to_id is None or ticket.assigned_to_id != current_user.id:
        ticket.assigned_to_id = current_user.id
        if ticket.status == 'Open': ticket.status = 'In Progress'
        ticket.updated_at = datetime.utcnow()
        db.session.commit()
        flash(f'Ticket #{ticket.id} has been assigned to you.', 'success')
        app.logger.info(f"Ticket #{ticket.id} self-assigned to agent: {current_user.username}")
    elif ticket.assigned_to_id == current_user.id:
         flash(f'Ticket #{ticket.id} is already assigned to you.', 'info')
    else: # ticket.assigned_to_id is not None and ticket.assigned_to_id != current_user.id
        flash(f'Ticket #{ticket.id} is already assigned to another agent ({ticket.assignee.username if ticket.assignee else "Unknown"}).', 'warning')
    return redirect(request.referrer or url_for('agent_ticket_list', view_name='unassigned'))

# --- Admin Routes ---
@app.route('/admin/users')
@admin_required
def admin_user_list():
    users = User.query.order_by(User.username).all()
    share_form = ShareCredentialsForm()
    return render_template('admin/user_list.html', title='Manage Users', users=users, share_form=share_form)

@app.route('/admin/user/new', methods=['GET', 'POST']) # For creating any type of user by admin
@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_user(user_id=None):
    user_to_edit = User.query.get_or_404(user_id) if user_id else None
    form = AdminUserForm(obj=user_to_edit if request.method == 'GET' and user_to_edit else None)
    legend = 'Create New User' if not user_to_edit else f'Edit User: {user_to_edit.username}'

    # Adjust password validators: required for new user, optional for edit
    original_password_validators = list(form.password.validators) # Make copies
    original_password2_validators = list(form.password2.validators)

    if not user_to_edit: # New user
        form.password.validators = [DataRequired(message="Password is required for new users.")] + [v for v in original_password_validators if not isinstance(v, Optional)]
        form.password2.validators = [DataRequired(message="Please confirm the password.")] + [v for v in original_password2_validators if not isinstance(v, Optional)]
    else: # Editing existing user - ensure Optional is there, DataRequired is not
        form.password.validators = [Optional()] + [v for v in original_password_validators if not isinstance(v, (DataRequired, Optional))]
        form.password2.validators = [EqualTo('password', message='Passwords must match if new password provided.')] + [Optional()] + [v for v in original_password2_validators if not isinstance(v, (DataRequired, Optional, EqualTo))]


    if form.validate_on_submit():
        is_new_user = (user_to_edit is None)
        user = user_to_edit or User()
        
        # Check for username uniqueness (if changed or new)
        potential_username_conflict = User.query.filter(User.username == form.username.data, User.id != (user.id if user.id else -1)).first()
        if potential_username_conflict:
            form.username.errors.append('This username is already taken.')
        
        # Check for email uniqueness (if changed or new)
        potential_email_conflict = User.query.filter(User.email == form.email.data.lower(), User.id != (user.id if user.id else -1)).first()
        if potential_email_conflict:
            form.email.errors.append('This email address is already registered.')
        
        # If new password provided for edit, but not confirmed
        if not is_new_user and form.password.data and not form.password2.data:
             form.password2.errors.append("Please confirm the new password if you are changing it.")

        if not form.errors: # If no errors after custom checks
            user.username = form.username.data
            user.email = form.email.data.lower()
            user.role = form.role.data
            if form.password.data: # Only set password if a new one is provided
                user.set_password(form.password.data)
            
            if is_new_user: db.session.add(user)
            
            try:
                db.session.commit()
                flash(f'User "{user.username}" has been {"created" if is_new_user else "updated"} successfully.', 'success')
                app.logger.info(f"User '{user.username}' {'created' if is_new_user else 'updated'} by admin {current_user.username}")
                return redirect(url_for('admin_user_list'))
            except Exception as e:
                db.session.rollback()
                flash(f'Database error: Could not save user. {str(e)}', 'danger')
                app.logger.error(f"Admin user save error for '{form.username.data}': {e}")
    
    return render_template('admin/create_edit_user.html', title=legend, form=form, legend=legend, user=user_to_edit)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id: flash('You cannot delete your own account.', 'danger')
    elif user_to_delete.is_admin and User.query.filter_by(role='admin').count() <= 1:
        flash('Cannot delete the only remaining administrator account.', 'danger')
    else:
        deleted_username = user_to_delete.username
        try:
            # Reassign or nullify tickets assigned to the user being deleted
            Ticket.query.filter_by(assigned_to_id=user_id).update({'assigned_to_id': None})
            # Delete associated attachments and comments by this user
            Attachment.query.filter_by(uploaded_by_id=user_id).delete(synchronize_session='fetch')
            Comment.query.filter_by(user_id=user_id).delete(synchronize_session='fetch')
            
            db.session.delete(user_to_delete)
            db.session.commit()
            flash(f'User "{deleted_username}" and their associated non-ticket data (comments, assignments) have been deleted. Tickets created by this user remain but are unassigned if they were assigned this user.', 'success')
            app.logger.info(f"User '{deleted_username}' (ID:{user_id}) deleted by admin {current_user.username}")
        except Exception as e:
            db.session.rollback(); flash(f'Error deleting user "{deleted_username}": {e}', 'danger')
            app.logger.error(f"Error deleting user ID {user_id} ('{deleted_username}'): {e}")
    return redirect(url_for('admin_user_list'))

@app.route('/admin/user/<int:user_id>/share_credentials', methods=['POST'])
@admin_required
def admin_share_credentials(user_id):
    user = User.query.get_or_404(user_id)
    form = ShareCredentialsForm(request.form) # Bind data from request.form
    if form.validate(): # Validates recipient_email
        recipient_email = form.recipient_email.data
        subject = f"Account Information: {user.username} for Ticket System"
        # Emphasize password security - do not send password.
        body_text = (f"Hello,\n\nHere is the account information for user '{user.username}':\n"
                     f"Username: {user.username}\n"
                     f"IMPORTANT: For security reasons, the password cannot be directly shared. "
                     f"If a password reset is needed, please use the system's password reset functionality "
                     f"or have an administrator set a temporary password for the user.\n\n"
                     f"Regards,\nThe Ticket System Admin")
        msg = Message(subject, recipients=[recipient_email], body=body_text)
        try:
            mail.send(msg)
            flash(f'Account details (excluding password) for "{user.username}" have been sent to {recipient_email}.', 'success')
            app.logger.info(f"Credentials info (no password) for '{user.username}' shared with '{recipient_email}' by admin {current_user.username}")
        except Exception as e: 
            flash(f'Failed to send email: {e}', 'danger')
            app.logger.error(f"Email send failure for sharing credentials of '{user.username}': {e}")
    else:
        for field_name, errors in form.errors.items(): 
            field_label = getattr(getattr(form, field_name), 'label', None)
            label_text = field_label.text if field_label else field_name.replace("_", " ").title()
            flash(f"Error in sharing form ({label_text}): {', '.join(errors)}", 'danger')
    return redirect(url_for('admin_user_list'))

# --- Admin Option Management Helper Functions ---
def _admin_list_options(model_class, template_name, title, order_by_attr='name'):
    items = model_class.query.order_by(getattr(model_class, order_by_attr)).all()
    model_name_slug = to_snake_case(model_class.__name__) # Corrected slug generation
    return render_template(template_name, title=title, items=items, model_name=model_name_slug)

def _admin_create_edit_option(model_class, form_class, list_url_func_name, item_id=None):
    item = model_class.query.get_or_404(item_id) if item_id else None
    form = form_class(obj=item if request.method == 'GET' and item else None)
    
    type_name_raw = model_class.__name__.replace("Option","")
    type_name_display = " ".join(re.findall('[A-Z][^A-Z]*', type_name_raw) or [type_name_raw]) # Converts CamelCase to "Spaced Words"
    
    legend = f'New {type_name_display}' if not item else f'Edit {type_name_display}: {getattr(item, "name", "Item")}'
    
    if form.validate_on_submit():
        is_new = (item is None)
        option_instance = item or model_class()
        
        # Check for name uniqueness (if changed or new)
        existing_item_with_name = model_class.query.filter(
            model_class.name == form.name.data, 
            model_class.id != (option_instance.id if option_instance.id else -1) # Exclude self if editing
        ).first()

        if existing_item_with_name:
            form.name.errors.append('This name already exists. Please choose a different one.')
        
        if not form.errors:
            form.populate_obj(option_instance)
            if is_new: db.session.add(option_instance)
            try:
                db.session.commit()
                flash(f'{type_name_display} "{option_instance.name}" has been saved successfully.', 'success')
                app.logger.info(f"{type_name_display} '{option_instance.name}' {'created' if is_new else 'updated'} by {current_user.username}")
                return redirect(url_for(list_url_func_name))
            except Exception as e:
                db.session.rollback(); flash(f'Database error: Could not save {type_name_display.lower()}. Error: {str(e)}', 'danger')
                app.logger.error(f"{type_name_display} save error: {e}")
                
    template_path = 'admin/create_edit_option.html' 
    return render_template(template_path, title=legend, form=form, legend=legend,
                           item_type_name=type_name_display, list_url=url_for(list_url_func_name))

def _admin_delete_option(model_class, item_id, list_url_func_name, related_ticket_attr=None):
    item = model_class.query.get_or_404(item_id)
    item_name = getattr(item, "name", "Item")
    type_name_raw = model_class.__name__.replace("Option","")
    type_name_display = " ".join(re.findall('[A-Z][^A-Z]*', type_name_raw) or [type_name_raw])

    can_delete = True
    if related_ticket_attr:
        query_filter = None
        if related_ticket_attr == 'category_id' and hasattr(Ticket, 'category_id'): # Direct ID FK
            query_filter = (Ticket.category_id == item.id)
        elif hasattr(Ticket, related_ticket_attr): # String-based FKs like Ticket.severity == SeverityOption.name
            query_filter = (getattr(Ticket, related_ticket_attr) == item.name)
        
        if query_filter is not None and Ticket.query.filter(query_filter).first():
            can_delete = False
        
        if not can_delete:
             flash(f'Cannot delete "{item_name}" as it is currently associated with existing tickets. Consider deactivating it instead (if applicable).', 'danger')

    if can_delete:
        try:
            db.session.delete(item); db.session.commit()
            flash(f'{type_name_display} "{item_name}" has been deleted.', 'success')
            app.logger.info(f"{type_name_display} '{item_name}' (ID:{item_id}) deleted by {current_user.username}")
        except Exception as e:
            db.session.rollback(); flash(f'Error deleting {type_name_display.lower()}: {e}', 'danger')
            app.logger.error(f"Error deleting {type_name_display} ID {item_id}: {e}")
    return redirect(url_for(list_url_func_name))

# --- Specific Admin Option Routes ---

# Category Routes
@app.route('/admin/categories')
@admin_required
def admin_category_list():
    return _admin_list_options(Category, 'admin/list_options.html', 'Manage Categories')

@app.route('/admin/category/new', methods=['GET', 'POST'])
@app.route('/admin/category/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_category(item_id=None):
    return _admin_create_edit_option(Category, CategoryForm, 'admin_category_list', item_id)

@app.route('/admin/category/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_category(item_id):
    return _admin_delete_option(Category, item_id, 'admin_category_list', 'category_id')

# Cloud Provider Routes
@app.route('/admin/cloud_providers')
@admin_required
def admin_cloud_provider_list():
    return _admin_list_options(CloudProviderOption, 'admin/list_options.html', 'Manage Cloud Providers')

@app.route('/admin/cloud_provider/new', methods=['GET', 'POST'])
@app.route('/admin/cloud_provider/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_cloud_provider(item_id=None):
    return _admin_create_edit_option(CloudProviderOption, CloudProviderOptionForm, 'admin_cloud_provider_list', item_id)

@app.route('/admin/cloud_provider/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_cloud_provider(item_id):
    return _admin_delete_option(CloudProviderOption, item_id, 'admin_cloud_provider_list', 'cloud_provider')

# Severity Routes
@app.route('/admin/severities')
@admin_required
def admin_severity_list():
    return _admin_list_options(SeverityOption, 'admin/list_options.html', 'Manage Severity Levels', 'order')

@app.route('/admin/severity/new', methods=['GET', 'POST'])
@app.route('/admin/severity/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_severity(item_id=None):
    return _admin_create_edit_option(SeverityOption, SeverityOptionForm, 'admin_severity_list', item_id)

@app.route('/admin/severity/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_severity(item_id):
    return _admin_delete_option(SeverityOption, item_id, 'admin_severity_list', 'severity')

# Environment Routes
@app.route('/admin/environments')
@admin_required
def admin_environment_list():
    return _admin_list_options(EnvironmentOption, 'admin/list_options.html', 'Manage Environments')

@app.route('/admin/environment/new', methods=['GET', 'POST'])
@app.route('/admin/environment/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_environment(item_id=None):
    return _admin_create_edit_option(EnvironmentOption, EnvironmentOptionForm, 'admin_environment_list', item_id)

@app.route('/admin/environment/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_environment(item_id):
    return _admin_delete_option(EnvironmentOption, item_id, 'admin_environment_list', 'environment')

@app.route('/admin/tickets')
@admin_required
def admin_all_tickets():
    page = request.args.get('page', 1, type=int)
    filters = {k: v for k, v in request.args.items() if k != 'page' and v} # Store active filters
    query = Ticket.query

    if filters.get('status'): query = query.filter(Ticket.status == filters['status'])
    if filters.get('priority'): query = query.filter(Ticket.priority == filters['priority'])
    if filters.get('category_id') and filters['category_id'] != '0': # Assuming '0' is for 'All Categories'
        query = query.filter(Ticket.category_id == int(filters['category_id']))
    
    assignee_id_filter = filters.get('assigned_to_id')
    if assignee_id_filter:
        if assignee_id_filter == '0' or assignee_id_filter.lower() == 'none': # For "Unassigned"
            query = query.filter(Ticket.assigned_to_id.is_(None))
        elif assignee_id_filter.isdigit(): # Specific agent ID
             query = query.filter(Ticket.assigned_to_id == int(assignee_id_filter))

    tickets_pagination = query.order_by(Ticket.updated_at.desc()).paginate(page=page, per_page=10, error_out=False)
    
    # For filter dropdowns
    categories_for_filter = Category.query.order_by('name').all()
    agents_for_filter = User.query.filter(User.role.in_(['agent', 'admin'])).order_by('username').all()
    
    return render_template('admin/all_tickets.html', title='All Tickets Overview',
                           tickets_pagination=tickets_pagination,
                           statuses=TICKET_STATUS_CHOICES, priorities=TICKET_PRIORITY_CHOICES,
                           categories=categories_for_filter, agents=agents_for_filter,
                           current_filters=filters) # Pass current filters back to template

# --- CLI Commands ---
@app.cli.command('init-db')
def init_db_command():
    """Drops and recreates all database tables."""
    try:
        with app.app_context():
            db.drop_all()
            db.create_all()
        print('Database tables dropped and recreated successfully.')
        app.logger.info('Database tables dropped and recreated successfully via CLI.')
    except Exception as e:
        print(f"Error during init-db: {e}")
        app.logger.error(f"Error during init-db CLI command: {e}")

@app.cli.command('create-initial-data')
def create_initial_data_command():
    """Creates initial users, categories, severities, etc."""
    with app.app_context():
        users_data = [
            {'username': 'admin', 'email': os.environ.get('ADMIN_USER_EMAIL', 'admin@example.com'), 'role': 'admin', 'password': os.environ.get('ADMIN_USER_PASSWORD', 'adminpass')},
            {'username': 'agent', 'email': os.environ.get('AGENT_USER_EMAIL', 'agent@example.com'), 'role': 'agent', 'password': os.environ.get('AGENT_USER_PASSWORD', 'agentpass')},
            {'username': 'client', 'email': os.environ.get('CLIENT_USER_EMAIL', 'client@example.com'), 'role': 'client', 'password': os.environ.get('CLIENT_USER_PASSWORD', 'clientpass')}
        ]
        print("Attempting to create initial users...")
        for u_data in users_data:
            existing_user_by_username = User.query.filter_by(username=u_data['username']).first()
            existing_user_by_email = User.query.filter_by(email=u_data['email']).first()
            if not existing_user_by_username and not existing_user_by_email:
                user = User(username=u_data['username'], email=u_data['email'], role=u_data['role'])
                user.set_password(u_data['password'])
                db.session.add(user)
                print(f"  User '{u_data['username']}' with email '{u_data['email']}' created.")
            else:
                skipped_by = []
                if existing_user_by_username: skipped_by.append(f"username '{u_data['username']}' (found as '{existing_user_by_username.username}')")
                if existing_user_by_email: skipped_by.append(f"email '{u_data['email']}' (found as '{existing_user_by_email.email}')")
                print(f"  Skipping user creation for '{u_data['username']}' due to existing: {', '.join(skipped_by)}.")
        
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
                    if hasattr(model_class, 'is_active'): instance_args['is_active'] = True
                    db.session.add(model_class(**instance_args))
                    created_count +=1
            if created_count > 0: print(f"  Added {created_count} new default {model_class.__name__}(s).")
            else: print(f"  Default {model_class.__name__}s already exist or no new ones needed.")

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
        
        try:
            db.session.commit()
            print("\nInitial data committed successfully.")
            app.logger.info("Initial data (users, options, severities) created/verified via CLI.")
        except Exception as e:
            db.session.rollback()
            print(f"\nError committing initial data: {e}")
            app.logger.error(f"Error committing initial data via CLI: {e}")
            
if __name__ == '__main__':
    # Ensure UPLOAD_FOLDER is absolute and exists
    upload_folder_path = app.config['UPLOAD_FOLDER']
    if not os.path.isabs(upload_folder_path):
        # If UPLOAD_FOLDER was relative from env var or default, make it relative to app root
        upload_folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), upload_folder_path)
        app.config['UPLOAD_FOLDER'] = upload_folder_path # Update config with absolute path

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'])
            app.logger.info(f"Upload folder created at startup: {app.config['UPLOAD_FOLDER']}")
        except OSError as e:
            app.logger.critical(f"CRITICAL FAILURE: Could not create upload folder {app.config['UPLOAD_FOLDER']}: {e}. Application may not work correctly.")
            # Depending on severity, you might want to sys.exit(1) here if uploads are critical.
    
    app.run(debug=True, host='0.0.0.0', port=5000)