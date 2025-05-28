
import os
from datetime import datetime, timedelta # Added timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, current_app, send_from_directory
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
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, Optional, NumberRange
import logging
from markupsafe import escape, Markup
import re
import uuid
from flask_mail import Mail, Message

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

# --- Configuration ---
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ticket-cms-agent-views-final-key-secure' # MUST BE SET IN .ENV FOR PRODUCTION
    MYSQL_USER = os.environ.get('MYSQL_USER_TICKET_CMS') or 'ticket_user'
    _raw_mysql_password = os.environ.get('MYSQL_PASSWORD_TICKET_CMS') or 'Jodha@123'
    MYSQL_PASSWORD_ENCODED = quote_plus(_raw_mysql_password) if _raw_mysql_password else ''
    MYSQL_HOST = os.environ.get('MYSQL_HOST_TICKET_CMS') or 'localhost'
    MYSQL_DB = os.environ.get('MYSQL_DB_TICKET_CMS') or 'ticket_cms_db'
    MYSQL_CHARSET = 'utf8mb4'

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
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME_TICKET_CMS') # Set in .env
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD_TICKET_CMS') # Set in .env (16 char app pass, no spaces)
    MAIL_DEFAULT_SENDER_EMAIL = os.environ.get('MAIL_DEFAULT_SENDER_EMAIL_TICKET_CMS') # Set in .env
    MAIL_DEFAULT_SENDER = ('TicketSys Admin', MAIL_DEFAULT_SENDER_EMAIL or 'noreply@example.com')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL_TICKET_CMS') # Set in .env
    
    # --- Email Fetching Configuration (IMAP for email_processor.py) ---
    IMAP_SERVER = os.environ.get('IMAP_SERVER_TICKET_CMS_FETCH') or 'imap.gmail.com'
    IMAP_USERNAME = os.environ.get('IMAP_USERNAME_TICKET_CMS_FETCH') # Set in .env
    IMAP_PASSWORD = os.environ.get('IMAP_PASSWORD_TICKET_CMS_FETCH') or 'placeholder16apppass' # Set in .env (16 char app pass, no spaces). Default is a placeholder.
    IMAP_MAILBOX_FOLDER = os.environ.get('IMAP_MAILBOX_FOLDER_TICKET_CMS_FETCH') or 'INBOX'
    EMAIL_TICKET_DEFAULT_CATEGORY_NAME = os.environ.get('EMAIL_TICKET_DEFAULT_CATEGORY_NAME') or 'General Inquiry'
    EMAIL_TICKET_DEFAULT_SEVERITY_NAME = os.environ.get('EMAIL_TICKET_DEFAULT_SEVERITY_NAME') or 'Severity 3 (Medium)'
    
    # BASE_URL must be a clean URL like 'http://localhost:5000' in .env or here
    BASE_URL = os.environ.get('BASE_URL') or 'http://localhost:5000'
    
    # These are derived from BASE_URL if not set directly. url_for(_external=True) relies on them.
    _parsed_base = urlparse(BASE_URL)
    SERVER_NAME = os.environ.get('SERVER_NAME') or _parsed_base.netloc
    APPLICATION_ROOT = os.environ.get('APPLICATION_ROOT') or _parsed_base.path.rstrip('/') or '/'
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME') or _parsed_base.scheme or 'http'

    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'log', 'csv'}
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH') or 16 * 1000 * 1000) # 16MB

    # --- Twilio Configuration for Voice Calls ---
    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID_TICKET_CMS')
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN_TICKET_CMS')
    TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER_TICKET_CMS')
    EMERGENCY_CALL_RECIPIENT_PHONE_NUMBER = os.environ.get('EMERGENCY_CALL_RECIPIENT_PHONE_NUMBER_TICKET_CMS')
    SEVERITIES_FOR_CALL_ALERT = ["Severity 1 (Critical)", "Severity 2 (High)"]

app = Flask(__name__)
app.config.from_object(Config)

# Critical check after config load
if not app.config['MAIL_DEFAULT_SENDER_EMAIL']:
    app.logger.warning("MAIL_DEFAULT_SENDER_EMAIL is not set. Email sending might fail or use a generic sender.")
    app.config['MAIL_DEFAULT_SENDER'] = ('TicketSys Admin', 'noreply@example.com') # Fallback tuple
elif isinstance(app.config['MAIL_DEFAULT_SENDER'], tuple) and app.config['MAIL_DEFAULT_SENDER'][1] != app.config['MAIL_DEFAULT_SENDER_EMAIL']:
    # Ensure tuple uses the email from env var if MAIL_DEFAULT_SENDER_EMAIL is set
    app.config['MAIL_DEFAULT_SENDER'] = ('TicketSys Admin', app.config['MAIL_DEFAULT_SENDER_EMAIL'])


if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError("SQLALCHEMY_DATABASE_URI is not configured. Application cannot start.")

csrf = CSRFProtect(app)
mail = Mail(app)
logging.basicConfig(level=logging.INFO) # Default logging
app.logger.setLevel(logging.INFO) # Flask app logger

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'])
        app.logger.info(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")
    except OSError as e:
        app.logger.error(f"Could not create upload folder {app.config['UPLOAD_FOLDER']}: {e}")
        # Depending on requirements, you might want to raise an error here if uploads are critical

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
    order = db.Column(db.Integer, default=0) # For sorting severity levels
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
    email = StringField('Email Address (@cloudkeeper.com domain for example)', validators=[DataRequired(), Email(), Length(max=120)]) # Adjust domain validation as needed
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
        # Example domain validation, adjust or remove as needed
        # if not email_data.endswith('@cloudkeeper.com'):
        #     raise ValidationError('Please use your company email address (e.g., @cloudkeeper.com).')

class CreateTicketForm(FlaskForm):
    title = StringField('Subject*', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description*', validators=[DataRequired()])
    category = SelectField('Issue Category*', coerce=int, validators=[DataRequired(message="Category is required.")])
    cloud_provider = SelectField('Cloud Provider', coerce=str, validators=[Optional()])
    severity = SelectField('Severity Level*', coerce=str, validators=[DataRequired(message="Severity is required.")])
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

# --- Flask-Login, Context Processors, Decorators ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "Please log in to access this page."

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

@app.context_processor
def inject_global_vars(): return {'current_year': datetime.utcnow().year}

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
def trigger_priority_call_alert(ticket):
    account_sid = app.config.get('TWILIO_ACCOUNT_SID')
    auth_token = app.config.get('TWILIO_AUTH_TOKEN')
    twilio_phone_number = app.config.get('TWILIO_PHONE_NUMBER')
    recipient_phone_number = app.config.get('EMERGENCY_CALL_RECIPIENT_PHONE_NUMBER')

    if not all([account_sid, auth_token, twilio_phone_number, recipient_phone_number]):
        app.logger.warning(f"Twilio credentials or recipient number not fully configured. Skipping call alert for ticket #{ticket.id}.")
        return

    try:
        client = TwilioClient(account_sid, auth_token)
        sanitized_title = re.sub(r'[^\w\s,.-]', '', ticket.title) # Basic sanitization
        message_to_say = (
            f"Hello. This is an urgent alert from the Ticket System. "
            f"A new high priority ticket, number {ticket.id}, has been created. "
            f"Severity is {ticket.severity}. "
            f"Subject: {sanitized_title}. "
            f"Please check the system immediately."
        )
        twiml_instruction = f'<Response><Say>{escape(message_to_say)}</Say></Response>' # Ensure message is XML-safe
        call = client.calls.create(
            twiml=twiml_instruction,
            to=recipient_phone_number,
            from_=twilio_phone_number
        )
        app.logger.info(f"Twilio call initiated for ticket #{ticket.id} to {recipient_phone_number}. Call SID: {call.sid}")
        # Flash message is okay here as it's tied to user action (ticket creation)
        flash(f'High priority ticket #{ticket.id} alert: Call initiated to {recipient_phone_number}.', 'info')
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
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '': # Security: prevent open redirect
                next_page = url_for('dashboard')
            flash(f'Logged in successfully as {user.username}.', 'success')
            app.logger.info(f"User '{user.username}' logged in.")
            return redirect(next_page)
        else:
            flash('Invalid username or password.', 'danger')
            app.logger.warning(f"Failed login attempt for username: {form.username.data}")
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    app.logger.info(f"User '{current_user.username}' logged out.")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

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
@admin_required # Agent registration should ideally be admin controlled.
def register_agent():
    form = UserSelfRegistrationForm()
    # Remove specific email domain validation for admin creating agents, or adjust as needed
    if hasattr(form, 'validate_email'):
        # Simple example: remove the domain check validator if it exists
        form.email.validators = [v for v in form.email.validators if getattr(v, '__name__', '') != 'validate_email_domain'] # pseudo-code, adjust to actual validator removal

    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data.lower(), role='agent')
        user.set_password(form.password.data)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Agent account created successfully!', 'success')
            app.logger.info(f"New agent '{user.username}' registered by admin '{current_user.username}'.")
            return redirect(url_for('admin_user_list')) # Redirect admin to user list
        except Exception as e:
            db.session.rollback()
            flash('Error during agent registration. Please try again.', 'danger')
            app.logger.error(f"Admin agent registration error: {e}")
    return render_template('admin/create_edit_user.html', title='Register New Agent', form=form, legend='Register New Agent', user=None, registration_type='Agent')


@app.route('/dashboard')
@login_required
def dashboard():
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
@login_required
def create_ticket():
    form = CreateTicketForm()
    form.category.choices = [(0, '--- Select Issue Category* ---')] + [(c.id, c.name) for c in Category.query.order_by('name').all()]
    form.cloud_provider.choices = get_active_cloud_provider_choices()
    form.severity.choices = get_active_severity_choices()
    form.environment.choices = get_active_environment_choices()

    if not form.category.choices[1:] and any(isinstance(v, DataRequired) for v in form.category.validators):
        flash("Critical: No categories defined. Contact admin.", "danger")
    if not form.severity.choices[1:] and any(isinstance(v, DataRequired) for v in form.severity.validators):
        flash("Critical: No severity levels defined. Contact admin.", "danger")

    if form.validate_on_submit():
        category_id_val = form.category.data if form.category.data and form.category.data != 0 else None
        # Re-validate required selects if default chosen, as coerce=int might pass 0
        if not category_id_val and any(isinstance(v, DataRequired) for v in form.category.validators):
             form.category.errors.append("Category is a required field.")
        if not form.severity.data and any(isinstance(v, DataRequired) for v in form.severity.validators): # Severity is string based ''
             form.severity.errors.append("Severity is a required field.")
        
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
                    else:
                        form.attachments.errors.append(f"File type not allowed: {file_storage.filename}")
        
        if not form.errors: # Check form errors again
            ticket = Ticket(
                title=form.title.data,
                description=form.description.data,
                created_by_id=current_user.id,
                category_id=category_id_val,
                cloud_provider=form.cloud_provider.data or None,
                severity=form.severity.data or None,
                aws_service=form.aws_service.data if form.cloud_provider.data == 'AWS' and form.aws_service.data else None,
                aws_account_id=form.aws_account_id.data or None,
                environment=form.environment.data or None,
                # Default status and priority are set in model
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
                app.logger.info(f"Ticket #{ticket.id} created by {current_user.username}")

                # --- Email Notifications ---
                try:
                    recipients_admin_agent = list(set(
                        [app.config['ADMIN_EMAIL']] + 
                        [user.email for user in User.query.filter(User.role.in_(['admin', 'agent'])).all() if user.email]
                    ))
                    if recipients_admin_agent:
                        msg_admin = Message(
                            f"New Ticket Submitted: #{ticket.id} - {ticket.title}",
                            recipients=[r for r in recipients_admin_agent if r], # Filter out None emails
                            body=render_template('email/new_ticket_admin_notification.txt', ticket=ticket, user=current_user,
                                                 ticket_url=url_for('view_ticket', ticket_id=ticket.id, _external=True))
                        )
                        mail.send(msg_admin)
                    
                    additional_emails = [email.strip() for email in (form.additional_recipients.data or "").split(',') if email.strip()]
                    # Also notify the ticket creator
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
                
                if ticket.severity in app.config.get('SEVERITIES_FOR_CALL_ALERT', []):
                    trigger_priority_call_alert(ticket)

                return redirect(url_for('view_ticket', ticket_id=ticket.id))
            except Exception as e:
                db.session.rollback()
                flash(f'Database error: Could not save ticket. {str(e)[:150]}', 'danger')
                app.logger.error(f"Ticket save DB error: {e}")
                for file_info in uploaded_files_info: # Cleanup
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
        agent_update_form = AgentUpdateTicketForm(obj=ticket if request.method == 'GET' else None)
        agent_choices = [(u.id, u.username) for u in User.query.filter(User.role.in_(['agent', 'admin'])).order_by('username').all()]
        cat_choices = [(c.id, c.name) for c in Category.query.order_by('name').all()]
        
        agent_update_form.assigned_to_id.choices = [(0, '--- Unassign/Select Agent ---')] + agent_choices
        agent_update_form.category_id.choices = [(0, '--- No Category ---')] + cat_choices
        agent_update_form.cloud_provider.choices = get_active_cloud_provider_choices()
        agent_update_form.severity.choices = get_active_severity_choices()
        agent_update_form.environment.choices = get_active_environment_choices()

        if request.method == 'GET':
             # Pre-populate form fields directly from ticket object
            agent_update_form.status.data = ticket.status
            agent_update_form.priority.data = ticket.priority
            agent_update_form.assigned_to_id.data = ticket.assigned_to_id or 0
            agent_update_form.category_id.data = ticket.category_id or 0
            agent_update_form.cloud_provider.data = ticket.cloud_provider or ''
            agent_update_form.severity.data = ticket.severity or ''
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
            db.session.commit()
            flash('Ticket details updated successfully.', 'success')
            app.logger.info(f"Ticket #{ticket.id} updated by {current_user.username}")
            return redirect(url_for('view_ticket', ticket_id=ticket.id))
        
        elif request.method == 'POST':
             flash('There was an error with your submission. Please check the form.', 'danger')

    comments_query = ticket.comments
    if not (current_user.is_agent or current_user.is_admin): # Clients don't see internal comments
        comments_query = comments_query.filter_by(is_internal=False)
        if hasattr(comment_form, 'is_internal'):
            del comment_form.is_internal # Remove toggle for clients
            
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
        # Ensure UPLOAD_FOLDER path is absolute for send_from_directory
        upload_dir = app.config['UPLOAD_FOLDER']
        if not os.path.isabs(upload_dir):
            upload_dir = os.path.join(app.root_path, upload_dir)

        return send_from_directory(
            upload_dir,
            attachment.stored_filename,
            as_attachment=True,
            download_name=attachment.filename
        )
    except FileNotFoundError:
        app.logger.error(f"Physical file not found: {attachment.stored_filename} for ticket {ticket.id}")
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

    if view_name == 'my_unsolved':
        query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status.notin_(['Resolved', 'Closed']))
        list_title = "Your Unsolved Tickets"
    elif view_name == 'unassigned':
        query = query.filter(Ticket.assigned_to_id.is_(None), Ticket.status == 'Open')
        list_title = "Unassigned Open Tickets"
    # Add other views as in original
    elif view_name == 'all_unsolved':
        query = query.filter(Ticket.status.notin_(['Resolved', 'Closed']))
        list_title = "All Unsolved Tickets"
    elif view_name == 'recently_updated':
        list_title = "Recently Updated Tickets" # Ordering applied below
    elif view_name == 'pending':
        query = query.filter(Ticket.status == 'On Hold')
        list_title = "Pending (On Hold) Tickets"
    elif view_name == 'recently_solved':
        query = query.filter(Ticket.status == 'Resolved')
        list_title = "Recently Solved Tickets" # Ordering applied below
    elif view_name == 'current_tasks':
        query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status == 'In Progress')
        list_title = "Your Current In-Progress Tickets"
    else: # Default fallback
        flash(f"Unknown ticket view: '{view_name}'. Defaulting to your unsolved tickets.", "warning")
        query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status.notin_(['Resolved', 'Closed']))
        list_title = "Your Unsolved Tickets"
        view_name = 'my_unsolved'
    
    if view_name in ['recently_updated', 'recently_solved', 'all_unsolved', 'unassigned', 'pending']:
        ordered_query = query.order_by(Ticket.updated_at.desc())
    else:
        priority_order = db.case(
            {'Urgent': 1, 'High': 2, 'Medium': 3, 'Low': 4},
            value=Ticket.priority, else_=5
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
    else:
        flash(f'Ticket #{ticket.id} is already assigned.', 'warning')
    return redirect(request.referrer or url_for('agent_ticket_list', view_name='unassigned'))


# --- Admin Routes ---
@app.route('/admin/users')
@admin_required
def admin_user_list():
    users = User.query.order_by(User.username).all()
    share_form = ShareCredentialsForm()
    return render_template('admin/user_list.html', title='Manage Users', users=users, share_form=share_form)

@app.route('/admin/user/new', methods=['GET', 'POST'])
@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_user(user_id=None):
    user_to_edit = User.query.get_or_404(user_id) if user_id else None
    form = AdminUserForm(obj=user_to_edit if request.method == 'GET' and user_to_edit else None)
    legend = 'Create New User' if not user_to_edit else f'Edit User: {user_to_edit.username}'

    # Adjust password validators
    if not user_to_edit: # New user
        form.password.validators.insert(0, DataRequired(message="Password is required for new users."))
        form.password2.validators.insert(0, DataRequired(message="Please confirm the password."))
    else: # Editing existing user
        # For edit, password is optional. If not DataRequired, it's already Optional or similar.
        # Ensure password2 matches if password is provided
        pass

    if form.validate_on_submit():
        is_new_user = (user_to_edit is None)
        user = user_to_edit or User()

        # Uniqueness checks
        if (is_new_user or user.username != form.username.data) and \
           User.query.filter(User.username == form.username.data, User.id != (user.id if user.id else -1)).first():
            form.username.errors.append('This username is already taken.')
        if (is_new_user or user.email != form.email.data.lower()) and \
           User.query.filter(User.email == form.email.data.lower(), User.id != (user.id if user.id else -1)).first():
            form.email.errors.append('This email address is already registered.')
        
        if not is_new_user and form.password.data and not form.password2.data:
             form.password2.errors.append("Please confirm the new password.")

        if not form.errors:
            user.username = form.username.data
            user.email = form.email.data.lower()
            user.role = form.role.data
            if form.password.data:
                user.set_password(form.password.data)
            
            if is_new_user: db.session.add(user)
            
            try:
                db.session.commit()
                flash(f'User "{user.username}" {"created" if is_new_user else "updated"}.', 'success')
                return redirect(url_for('admin_user_list'))
            except Exception as e:
                db.session.rollback()
                flash('Database error: Could not save user.', 'danger')
                app.logger.error(f"Admin user save error for '{form.username.data}': {e}")
    
    return render_template('admin/create_edit_user.html', title=legend, form=form, legend=legend, user=user_to_edit)


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id: flash('Cannot delete self.', 'danger')
    elif user.is_admin and User.query.filter_by(role='admin').count() <= 1:
        flash('Cannot delete the only admin.', 'danger')
    else:
        try:
            # Handle related items before deleting user
            Ticket.query.filter_by(assigned_to_id=user_id).update({'assigned_to_id': None})
            # Decide on created_by_id tickets (usually keep, or set to a generic deleted user ID)
            Attachment.query.filter_by(uploaded_by_id=user_id).delete(synchronize_session='fetch')
            Comment.query.filter_by(user_id=user_id).delete(synchronize_session='fetch')
            
            db.session.delete(user)
            db.session.commit()
            flash(f'User "{user.username}" deleted.', 'success')
        except Exception as e:
            db.session.rollback(); flash(f'Error deleting user: {e}', 'danger')
    return redirect(url_for('admin_user_list'))

@app.route('/admin/user/<int:user_id>/share_credentials', methods=['POST'])
@admin_required
def admin_share_credentials(user_id):
    user = User.query.get_or_404(user_id)
    form = ShareCredentialsForm(request.form)
    if form.validate():
        # SECURITY WARNING: Sending passwords in email is highly discouraged.
        # Implement a password reset link flow instead for production.
        subject = f"Account Info: {user.username}"
        body = f"Username: {user.username}\nThis is a system-generated message. Password sharing is not secure."
        # For demo, actual password sending is omitted.
        msg = Message(subject, recipients=[form.recipient_email.data], body=body)
        try:
            # mail.send(msg) # Uncomment if you implement a secure way or accept risk for demo
            flash(f'Credentials info for "{user.username}" (simulated) sent to {form.recipient_email.data}.', 'info')
        except Exception as e: flash(f'Email send failed: {e}', 'danger')
    else:
        for field, errors in form.errors.items(): flash(f"Error ({field}): {', '.join(errors)}", 'danger')
    return redirect(url_for('admin_user_list'))

# Generic CRUD for Options
def _admin_list_options(model_class, template_name, title, order_by_attr='name'):
    items = model_class.query.order_by(getattr(model_class, order_by_attr)).all()
    return render_template(template_name, title=title, items=items, model_name=model_class.__name__.lower().replace("option",""))
def _admin_create_edit_option(model_class, form_class, list_url_func_name, item_id=None):
    item = model_class.query.get_or_404(item_id) if item_id else None
    form = form_class(obj=item if request.method == 'GET' and item else None)
    type_name = model_class.__name__.replace("Option","")
    legend = f'New {type_name}' if not item else f'Edit: {getattr(item, "name", "Item")}'
    
    if form.validate_on_submit():
        is_new = (item is None)
        option = item or model_class()
        
        if (is_new or option.name != form.name.data) and \
           model_class.query.filter(model_class.name == form.name.data, model_class.id != (option.id if option.id else -1)).first():
            form.name.errors.append('This name already exists.')
        else:
            form.populate_obj(option)
            if is_new: db.session.add(option)
            try:
                db.session.commit()
                flash(f'{type_name} "{option.name}" saved.', 'success')
                return redirect(url_for(list_url_func_name))
            except Exception as e:
                db.session.rollback(); flash(f'DB error saving {type_name.lower()}.', 'danger')
                
    template_path = 'admin/create_edit_option.html'
    return render_template(template_path, title=legend, form=form, legend=legend,
                           item_type_name=type_name.capitalize(), list_url=url_for(list_url_func_name))
def _admin_delete_option(model_class, item_id, list_url_func_name, related_ticket_attr=None):
    item = model_class.query.get_or_404(item_id)
    item_name = getattr(item, "name", "Item")
    can_delete = True
    if related_ticket_attr:
        # Check if used in tickets (example for string-based FKs, adjust for ID FKs)
        if hasattr(Ticket, related_ticket_attr):
            if related_ticket_attr == 'category_id' and Ticket.query.filter_by(category_id=item.id).first():
                can_delete = False
            elif Ticket.query.filter(getattr(Ticket, related_ticket_attr) == item.name).first(): # For string name fields
                can_delete = False
        if not can_delete:
             flash(f'Cannot delete "{item_name}" as it is used by tickets. Deactivate instead.', 'danger')

    if can_delete:
        try:
            db.session.delete(item); db.session.commit()
            flash(f'{model_class.__name__.replace("Option","")} "{item_name}" deleted.', 'success')
        except Exception as e:
            db.session.rollback(); flash(f'Error deleting: {e}', 'danger')
    return redirect(url_for(list_url_func_name))

# Category Routes
@app.route('/admin/categories')
@admin_required
def admin_category_list():
    return _admin_list_options(Category, 'admin/list_options.html', 'Manage Categories')

# Corrected: All @app.route decorators first, then other decorators
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
    # ... (rest of the function is fine)
    page = request.args.get('page', 1, type=int)
    filters = {k: v for k, v in request.args.items() if k != 'page' and v}
    query = Ticket.query
    # Apply filters (simplified example)
    if filters.get('status'): query = query.filter(Ticket.status == filters['status'])
    # ... add more filters ...
    tickets_pagination = query.order_by(Ticket.updated_at.desc()).paginate(page=page, per_page=10, error_out=False)
    # Pass filter choices to template
    categories_for_filter = Category.query.order_by('name').all()
    agents_for_filter = User.query.filter(User.role.in_(['agent', 'admin'])).order_by('username').all()
    return render_template('admin/all_tickets.html', title='All Tickets Overview',
                           tickets_pagination=tickets_pagination,
                           statuses=TICKET_STATUS_CHOICES, priorities=TICKET_PRIORITY_CHOICES,
                           categories=categories_for_filter, agents=agents_for_filter,
                           current_filters=filters)


# --- CLI Commands ---
@app.cli.command('init-db')
def init_db_command():
    """Drops and recreates all database tables."""
    try:
        with app.app_context(): # Ensure commands run within app context
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
            {'username': 'admin', 'email': (os.environ.get('ADMIN_EMAIL_TICKET_CMS') or 'admin@example.com'), 'role': 'admin', 'password': 'adminpass'},
            {'username': 'agent1', 'email': 'agent1@example.com', 'role': 'agent', 'password': 'agentpass'},
            {'username': 'client1', 'email': 'client1@example.com', 'role': 'client', 'password': 'clientpass'}
        ]
        for u_data in users_data:
            if not User.query.filter((User.username == u_data['username']) | (User.email == u_data['email'])).first():
                user = User(username=u_data['username'], email=u_data['email'], role=u_data['role'])
                user.set_password(u_data['password'])
                db.session.add(user)
        
        options_map = {
            Category: ['Technical Support', 'Billing Inquiry', 'General Question', 'Feature Request'],
            CloudProviderOption: ['AWS', 'Azure', 'GCP', 'On-Premise', 'Other'],
            EnvironmentOption: ['Production', 'Staging', 'Development', 'Test', 'QA', 'UAT']
        }
        for model_class, names in options_map.items():
            for name_val in names:
                if not model_class.query.filter_by(name=name_val).first():
                    db.session.add(model_class(name=name_val, is_active=True))

        severities_data = [
            {'name': 'Severity 1 (Critical)', 'o': 1, 'd': 'Critical impact.'},
            {'name': 'Severity 2 (High)', 'o': 2, 'd': 'Significant impact.'},
            {'name': 'Severity 3 (Medium)', 'o': 3, 'd': 'Moderate impact.'},
            {'name': 'Severity 4 (Low)', 'o': 4, 'd': 'Minor impact.'}
        ]
        for sev_data in severities_data:
            if not SeverityOption.query.filter_by(name=sev_data['name']).first():
                db.session.add(SeverityOption(name=sev_data['name'], order=sev_data['o'], description=sev_data['d'], is_active=True))
        
        try:
            db.session.commit()
            print("Initial data (users, categories, severities) created successfully.")
            app.logger.info("Initial data created via CLI.")
        except Exception as e:
            db.session.rollback()
            print(f"Error committing initial data: {e}")
            app.logger.error(f"Error committing initial data via CLI: {e}")
            
if __name__ == '__main__':
    # Ensure UPLOAD_FOLDER exists when running directly (already handled at top for import-time)
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'])
        except OSError as e:
            app.logger.critical(f"CRITICAL: Could not create upload folder {app.config['UPLOAD_FOLDER']}: {e}. Application may not function correctly.")
            # sys.exit(1) # Optionally exit if upload folder is absolutely critical at startup

    app.run(debug=True, host='0.0.0.0', port=5000) # debug=False for production