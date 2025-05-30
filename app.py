import os
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, current_app, send_from_directory, session
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
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, Optional, NumberRange, InputRequired, Regexp
import logging
from markupsafe import escape, Markup
import re
import uuid
from flask_mail import Mail, Message
import sys
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

REQUEST_CALL_BACK_CHOICES = [('', '-'), ('Yes', 'Yes'), ('No', 'No')]
EFFORT_CHOICES = [
    ('', '-'), ('0', 'Not Applicable (0 min)'),
    ('15', '15 min'), ('30', '30 min'), ('45', '45 min'),
    ('60', '1 hour (60 min)'), ('90', '1.5 hours (90 min)'), ('120', '2 hours (120 min)'),
    ('180', '3 hours (180 min)'), ('240', '4 hours (240 min)'), ('300', '5 hours (300 min)'),
    ('360', '6 hours (360 min)'), ('420', '7 hours (420 min)'), ('480', '8 hours (1 day)'),
    ('960', '16 hours (2 days)'), ('1440', '24 hours (3 days)')
]

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
    MAIL_DEFAULT_SENDER = ('TicketSys Admin', MAIL_DEFAULT_SENDER_EMAIL or 'noreply@example.com')
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
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME') or _parsed_base.scheme or 'http'

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

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

app.logger.info(f"--- App Initialization ---")
app.logger.info(f"Configured UPLOAD_FOLDER: {app.config['UPLOAD_FOLDER']}")
if app.config['UPLOAD_FOLDER'] == "/path/to/your/uploads":
    app.logger.warning("UPLOAD_FOLDER is set to '/path/to/your/uploads'. This is a placeholder and likely incorrect. "
                       "Please unset the UPLOAD_FOLDER environment variable or set it to a valid writable path.")

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        app.logger.info(f"Upload folder ensured/created: {app.config['UPLOAD_FOLDER']}")
    except OSError as e:
        app.logger.error(f"Could not create upload folder {app.config['UPLOAD_FOLDER']}: {e}. Check permissions and path.")

if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise RuntimeError("SQLALCHEMY_DATABASE_URI is not configured. Application cannot start.")

csrf = CSRFProtect(app)
mail = Mail(app)
db = SQLAlchemy(app)

def nl2br_filter(value):
    if not isinstance(value, str): value = str(value)
    escaped_value = escape(value)
    br_value = re.sub(r'(\r\n|\r|\n)', '<br>\n', escaped_value)
    return Markup(br_value)
app.jinja_env.filters['nl2br'] = nl2br_filter

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- Models ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default='client', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization_options.id'), nullable=True)
    organization = db.relationship('OrganizationOption', backref='users')
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
    def get_organization_name(self): return self.organization.name if self.organization else None
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

class OrganizationOption(db.Model):
    __tablename__ = 'organization_options'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    # tickets = db.relationship('Ticket', backref='organization_option_ref', lazy='dynamic') # Handled by Ticket.organization_option_ref
    def __repr__(self): return f'<OrganizationOption {self.name}>'

class FormTypeOption(db.Model):
    __tablename__ = 'form_type_options'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    tickets = db.relationship('Ticket', backref='form_type_option_ref', lazy='dynamic')
    def __repr__(self): return f'<FormTypeOption {self.name}>'

class APNOpportunityOption(db.Model):
    __tablename__ = 'apn_opportunity_options'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    tickets = db.relationship('Ticket', backref='apn_opportunity_option_ref', lazy='dynamic')
    def __repr__(self): return f'<APNOpportunityOption {self.name}>'

class SupportModalOption(db.Model):
    __tablename__ = 'support_modal_options'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    tickets = db.relationship('Ticket', backref='support_modal_option_ref', lazy='dynamic')
    def __repr__(self): return f'<SupportModalOption {self.name}>'

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
    organization_id = db.Column(db.Integer, db.ForeignKey('organization_options.id'), nullable=True)
    form_type_id = db.Column(db.Integer, db.ForeignKey('form_type_options.id'), nullable=True)
    tags = db.Column(db.Text, nullable=True)
    additional_email_recipients = db.Column(db.Text, nullable=True)
    request_call_back = db.Column(db.String(10), nullable=True)
    contact_details = db.Column(db.String(255), nullable=True)
    aws_support_case_id = db.Column(db.String(50), nullable=True)
    effort_required_to_resolve_min = db.Column(db.Integer, nullable=True)
    customer_name = db.Column(db.String(100), nullable=True)
    apn_opportunity_id = db.Column(db.Integer, db.ForeignKey('apn_opportunity_options.id'), nullable=True)
    apn_opportunity_description = db.Column(db.Text, nullable=True)
    support_modal_id = db.Column(db.Integer, db.ForeignKey('support_modal_options.id'), nullable=True)
    first_response_at = db.Column(db.DateTime, nullable=True)
    first_response_duration_minutes = db.Column(db.Integer, nullable=True)
    comments = db.relationship('Comment', backref='ticket_ref', lazy='dynamic', cascade="all, delete-orphan")
    cloud_provider_obj = db.relationship('CloudProviderOption', foreign_keys=[cloud_provider], primaryjoin='Ticket.cloud_provider == CloudProviderOption.name', viewonly=True)
    severity_obj = db.relationship('SeverityOption', foreign_keys=[severity], primaryjoin='Ticket.severity == SeverityOption.name', viewonly=True)
    environment_obj = db.relationship('EnvironmentOption', foreign_keys=[environment], primaryjoin='Ticket.environment == EnvironmentOption.name', viewonly=True)
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
    organization_id = SelectField('Organization (Optional)', coerce=int, validators=[Optional()])
    submit = SubmitField('Save User')

class UserSelfRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email Address', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create Account')
    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first(): raise ValidationError('Username taken.')
    def validate_email(self, email_field):
        if User.query.filter_by(email=email_field.data.lower()).first(): raise ValidationError('Email registered.')

class CreateTicketForm(FlaskForm):
    title = StringField('Subject*', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description*', validators=[DataRequired()])
    organization_id = SelectField('Organization', coerce=int, validators=[Optional()])
    form_type_id = SelectField('Form Type', coerce=int, validators=[Optional()])
    tags = StringField('Tags (comma-separated)', validators=[Optional(), Length(max=255)])
    category = SelectField('Issue Category*', coerce=int, validators=[InputRequired(message="Category is required.")])
    cloud_provider = SelectField('Cloud Provider', coerce=str, validators=[Optional()])
    severity = SelectField('Severity Level*', coerce=str, validators=[InputRequired(message="Severity is required.")])
    aws_service = SelectField('AWS Service (if AWS)', choices=AWS_SERVICE_CHOICES, validators=[Optional()])
    aws_account_id = StringField('AWS Account ID', validators=[
        Optional(), 
        Length(min=12, max=12, message="AWS Account ID must be 12 digits if provided."),
        Regexp(r'^\d{12}$', message="AWS Account ID must consist of 12 digits if provided.")
    ])
    environment = SelectField('Environment', coerce=str, validators=[Optional()])
    request_call_back = SelectField('Request Call Back?', choices=REQUEST_CALL_BACK_CHOICES, validators=[Optional()])
    contact_details = StringField('Contact Details for Callback', validators=[Optional(), Length(max=255)])
    customer_name = StringField('Customer Company Name*', validators=[DataRequired(), Length(max=100)])
    support_modal_id = SelectField('Support Modals by Plan', coerce=int, validators=[Optional()])
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
    organization_id = SelectField('Organization', coerce=int, validators=[Optional()])
    form_type_id = SelectField('Form Type', coerce=int, validators=[Optional()])
    tags = StringField('Tags (comma-separated)', validators=[Optional(), Length(max=255)])
    category_id = SelectField('Category', coerce=int, validators=[Optional()])
    cloud_provider = SelectField('Cloud Provider', coerce=str, validators=[Optional()])
    severity = SelectField('Severity', coerce=str, validators=[Optional()])
    aws_service = SelectField('AWS Service', choices=AWS_SERVICE_CHOICES, validators=[Optional()])
    aws_account_id = StringField('AWS Account ID', validators=[
        Optional(), 
        Length(min=12, max=12, message="AWS Account ID must be 12 digits if provided."),
        Regexp(r'^\d{12}$', message="AWS Account ID must consist of 12 digits if provided.")
    ])
    environment = SelectField('Environment', coerce=str, validators=[Optional()])
    request_call_back = SelectField('Request Call Back?', choices=REQUEST_CALL_BACK_CHOICES, validators=[Optional()])
    contact_details = StringField('Contact Details for Callback', validators=[Optional(), Length(max=255)])
    aws_support_case_id = StringField('AWS Support Case ID', validators=[Optional(), Length(max=50)])
    effort_required_to_resolve_min = SelectField('Effort (min)', coerce=str, choices=EFFORT_CHOICES, validators=[Optional()])
    customer_name = StringField('Customer Company Name', validators=[Optional(), Length(max=100)])
    apn_opportunity_id = SelectField('APN Opportunities', coerce=int, validators=[Optional()])
    apn_opportunity_description = TextAreaField('APN Opportunities Description', validators=[Optional()])
    support_modal_id = SelectField('Support Modals by Plan', coerce=int, validators=[Optional()])
    additional_email_recipients = StringField('Additional Email Recipients (comma-separated)', widget=TextAreaWidget(), validators=[Optional()])
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
    order = IntegerField('Sort Order (Optional)', validators=[Optional(), NumberRange(min=0)])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Severity')

class EnvironmentOptionForm(FlaskForm):
    name = StringField('Environment Name', validators=[DataRequired(), Length(max=50)])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Environment')

class OrganizationOptionForm(FlaskForm):
    name = StringField('Organization Name', validators=[DataRequired(), Length(max=100)])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Organization')

class FormTypeOptionForm(FlaskForm):
    name = StringField('Form Type Name', validators=[DataRequired(), Length(max=50)])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Form Type')

class APNOpportunityOptionForm(FlaskForm):
    name = StringField('APN Opportunity Name', validators=[DataRequired(), Length(max=100)])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save APN Opportunity')

class SupportModalOptionForm(FlaskForm):
    name = StringField('Support Modal Name', validators=[DataRequired(), Length(max=100)])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save Support Modal')

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
def inject_global_vars():
    return {
        'current_year': datetime.utcnow().year,
        'app': app,
        'to_snake_case': to_snake_case,
        'EFFORT_CHOICES': EFFORT_CHOICES
    }

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
DOMAIN_TO_ORGANIZATION_MAP = {
    'cloudkeeper.com': 'CloudKeeper (CK)',
    # Add more: 'example.com': 'Example Corp'
}

def get_organization_by_email_domain(email):
    if '@' not in email: return None
    domain = email.split('@')[-1].lower()
    org_name_from_map = DOMAIN_TO_ORGANIZATION_MAP.get(domain)
    if org_name_from_map:
        return OrganizationOption.query.filter_by(name=org_name_from_map, is_active=True).first()
    return None

def get_active_choices(model_class, placeholder_text_id_0=None, placeholder_text_str_empty=None, order_by_attr='name'):
    query = model_class.query.filter_by(is_active=True).order_by(getattr(model_class, order_by_attr))
    choices = []
    if placeholder_text_id_0: choices.append((0, placeholder_text_id_0))
    elif placeholder_text_str_empty: choices.append(('', placeholder_text_str_empty))
    if placeholder_text_id_0: choices.extend([(opt.id, opt.name) for opt in query.all()])
    else: choices.extend([(opt.name, opt.name) for opt in query.all()])
    return choices

def get_active_category_choices():
    return [(0, '--- Select Issue Category* ---')] + [(c.id, c.name) for c in Category.query.order_by('name').all()]
def get_active_cloud_provider_choices():
    return get_active_choices(CloudProviderOption, placeholder_text_str_empty='--- Select Cloud Provider ---')
def get_active_severity_choices():
    return get_active_choices(SeverityOption, placeholder_text_str_empty='--- Select Severity* ---', order_by_attr='order')
def get_active_environment_choices():
    return get_active_choices(EnvironmentOption, placeholder_text_str_empty='--- Select Environment ---')
def get_active_organization_choices():
    return get_active_choices(OrganizationOption, placeholder_text_id_0='--- Select Organization ---')
def get_active_form_type_choices():
    return get_active_choices(FormTypeOption, placeholder_text_id_0='--- Select Form Type ---')
def get_active_apn_opportunity_choices():
    return get_active_choices(APNOpportunityOption, placeholder_text_id_0='--- Select APN Opportunity* ---')
def get_active_support_modal_choices():
    return get_active_choices(SupportModalOption, placeholder_text_id_0='--- Select Support Modal ---')

# --- Interaction Log Helper ---
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
            app.logger.error(f"Failed to commit interaction log for ticket {ticket_id}: {e}", exc_info=True)

# --- Twilio Helper ---
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
    if old_severity is not None and old_severity == new_severity and new_severity in alert_severities:
        if old_severity in alert_severities:
            app.logger.info(f"Ticket #{ticket.id} severity '{new_severity}' remains unchanged and high. No new call alert needed.")
            return
    app.logger.info(f"Ticket #{ticket.id} severity change triggers call alert. Old: '{old_severity}', New: '{new_severity}'.")
    try:
        client = TwilioClient(account_sid, auth_token)
        sanitized_title = re.sub(r'[^\w\s,.-]', '', ticket.title)
        if old_severity is None or old_severity not in alert_severities: alert_reason = "created or escalated"
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
        app.logger.error(f"Unexpected error during Twilio call for ticket #{ticket.id}: {e}", exc_info=True)
        flash(f'An unexpected error occurred while trying to initiate a call for ticket #{ticket.id}.', 'danger')

# --- Routes ---
@app.route('/')
@app.route('/index')
def index():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template('index.html', title='Welcome')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        next_page = request.args.get('next')
        if next_page and not (next_page.startswith('//') or '://' in next_page):
             return redirect(next_page)
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if next_page and not (next_page.startswith('//') or '://' in next_page):
                 return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.after_request
def add_header(response):
    if '/static/' not in request.path:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@app.route('/register/client', methods=['GET', 'POST'])
def register_client():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = UserSelfRegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data.lower(), role='client')
        user.set_password(form.password.data)
        organization = get_organization_by_email_domain(user.email)
        if organization:
            user.organization_id = organization.id
            app.logger.info(f"User '{user.username}' auto-assigned to org '{organization.name}'.")
        else:
            app.logger.info(f"No org found for domain of '{user.email}'.")
        db.session.add(user)
        try:
            db.session.commit()
            flash('Client account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error during registration. Please try again.', 'danger')
            app.logger.error(f"Client registration error: {e}", exc_info=True)
    return render_template('register_user.html', title='Register as Client', form=form, registration_type='Client', info_text='Submit and track your support tickets.')

@app.route('/register/agent', methods=['GET', 'POST'])
@admin_required
def register_agent():
    form = UserSelfRegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data.lower(), role='agent')
        user.set_password(form.password.data)
        # Admin might assign org here if needed, or via user edit page
        db.session.add(user)
        try:
            db.session.commit()
            flash('Agent account created successfully!', 'success')
            return redirect(url_for('admin_user_list'))
        except Exception as e:
            db.session.rollback()
            flash('Error during agent registration. Please try again.', 'danger')
            app.logger.error(f"Admin agent registration error: {e}", exc_info=True)
    return render_template('register_user.html', title='Register New Agent', form=form, registration_type='Agent', info_text='Register new support agents to assist clients.')

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
    else:
        my_tickets = Ticket.query.filter_by(created_by_id=current_user.id).order_by(Ticket.updated_at.desc()).limit(10).all()
        return render_template('dashboard.html', title='My Dashboard', my_tickets=my_tickets)

@app.route('/tickets/new', methods=['GET', 'POST'])
@login_required
def create_ticket():
    form = CreateTicketForm()
    form.category.choices = get_active_category_choices()
    form.cloud_provider.choices = get_active_cloud_provider_choices()
    form.severity.choices = get_active_severity_choices()
    form.environment.choices = get_active_environment_choices()
    form.form_type_id.choices = get_active_form_type_choices()
    form.support_modal_id.choices = get_active_support_modal_choices()

    user_organization_object = current_user.organization
    user_organization_name_for_template = user_organization_object.name if user_organization_object else None

    if current_user.is_client and user_organization_object:
        form.organization_id.choices = [(user_organization_object.id, user_organization_object.name)]
        if request.method == 'GET': # Pre-fill only on GET
            form.organization_id.data = user_organization_object.id
    else:
        form.organization_id.choices = get_active_organization_choices()

    if not form.category.choices[1:]: flash("Critical: No categories defined. Contact admin.", "danger")
    if not form.severity.choices[1:]: flash("Critical: No severity levels defined. Contact admin.", "danger")

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
                        try: file_storage.save(file_path); uploaded_files_info.append({'original_filename': filename, 'stored_filename': stored_filename, 'content_type': file_storage.content_type})
                        except Exception as e: app.logger.error(f"Failed to save attachment {filename}: {e}", exc_info=True); form.attachments.errors.append(f"Could not save file: {filename}")
                    else: form.attachments.errors.append(f"File type not allowed: {file_storage.filename}")
        if form.attachments.errors: flash('Error with attachments. Please correct and try again.', 'danger')
        else:
            ticket_creator = current_user
            ticket_org_id_to_save = None
            if current_user.is_client and current_user.organization_id:
                ticket_org_id_to_save = current_user.organization_id
            elif form.organization_id.data and form.organization_id.data != 0:
                ticket_org_id_to_save = form.organization_id.data
            
            ticket = Ticket(
                title=form.title.data, description=form.description.data, created_by_id=ticket_creator.id,
                organization_id=ticket_org_id_to_save,
                form_type_id=form.form_type_id.data if form.form_type_id.data != 0 else None,
                tags=form.tags.data.strip() if form.tags.data else None,
                category_id=form.category.data if form.category.data != 0 else None,
                cloud_provider=form.cloud_provider.data or None, 
                severity=form.severity.data or None, 
                aws_service=form.aws_service.data if form.cloud_provider.data == 'AWS' and form.aws_service.data else None, 
                aws_account_id=form.aws_account_id.data.strip() if form.aws_account_id.data else None,
                environment=form.environment.data or None,
                request_call_back=form.request_call_back.data or None,
                contact_details=form.contact_details.data.strip() if form.contact_details.data else None,
                customer_name=form.customer_name.data.strip(),
                support_modal_id=form.support_modal_id.data if form.support_modal_id.data != 0 else None,
                additional_email_recipients=form.additional_recipients.data.strip() if form.additional_recipients.data else None
            )
            db.session.add(ticket)
            try:
                db.session.flush()
                for file_info in uploaded_files_info:
                    attachment = Attachment(filename=file_info['original_filename'], stored_filename=file_info['stored_filename'], ticket_id=ticket.id, uploaded_by_id=ticket_creator.id,content_type=file_info['content_type'])
                    db.session.add(attachment)
                log_interaction(ticket.id, 'TICKET_CREATED', user_id=ticket_creator.id, details={'title': ticket.title}, timestamp_override=ticket.created_at)
                db.session.commit()
                flash('Ticket created successfully!', 'success')
                try:
                    admin_and_agent_emails = list(set(([app.config['ADMIN_EMAIL']] if app.config['ADMIN_EMAIL'] else []) + [user.email for user in User.query.filter(User.role.in_(['admin', 'agent'])).all() if user.email]))
                    if admin_and_agent_emails: mail.send(Message(subject=f"New Ticket Submitted: #{ticket.id} - {ticket.title}", recipients=admin_and_agent_emails, body=render_template('email/new_ticket_admin_notification.txt', ticket=ticket, submitter=ticket_creator, ticket_url=url_for('view_ticket', ticket_id=ticket.id, _external=True))))
                    additional_emails_from_ticket = [email.strip() for email in (ticket.additional_email_recipients or "").split(',') if email.strip()]
                    creator_and_additional_emails = list(set(additional_emails_from_ticket + ([ticket_creator.email] if ticket_creator.email else [])))
                    if creator_and_additional_emails: mail.send(Message(subject=f"Confirmation: Your Ticket #{ticket.id} - {ticket.title}", recipients=creator_and_additional_emails, body=render_template('email/ticket_info_recipient.txt', ticket=ticket, submitter=ticket_creator, ticket_url=url_for('view_ticket', ticket_id=ticket.id, _external=True))))
                except Exception as e: app.logger.error(f"Failed to send email notifications for ticket #{ticket.id}: {e}", exc_info=True)
                trigger_priority_call_alert(ticket, old_severity=None)
                return redirect(url_for('view_ticket', ticket_id=ticket.id))
            except Exception as e: db.session.rollback(); flash(f'Database error: {str(e)[:150]}', 'danger'); app.logger.error(f"Ticket creation error: {e}", exc_info=True)
    elif request.method == 'POST': flash('Please correct the errors in the form.', 'danger')
    return render_template('client/create_ticket.html', title='Submit New Support Request', form=form, user_organization_name=user_organization_name_for_template)

@app.route('/tickets/my')
@login_required
def my_tickets():
    tickets = Ticket.query.filter_by(created_by_id=current_user.id).order_by(Ticket.updated_at.desc()).all()
    return render_template('client/my_tickets.html', title='My Submitted Tickets', tickets=tickets)

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
    is_privileged_user = current_user.is_agent or current_user.is_admin

    if is_privileged_user:
        agent_update_form = AgentUpdateTicketForm(obj=None)
        agent_choices = [(u.id, u.username) for u in User.query.filter(User.role.in_(['agent', 'admin'])).order_by('username').all()]
        agent_update_form.assigned_to_id.choices = [(0, '--- Unassign/Select Agent ---')] + agent_choices
        agent_update_form.category_id.choices = get_active_category_choices()
        agent_update_form.cloud_provider.choices = get_active_cloud_provider_choices()
        agent_update_form.severity.choices = get_active_severity_choices()
        agent_update_form.environment.choices = get_active_environment_choices()
        agent_update_form.organization_id.choices = get_active_organization_choices()
        agent_update_form.form_type_id.choices = get_active_form_type_choices()
        agent_update_form.apn_opportunity_id.choices = get_active_apn_opportunity_choices()
        agent_update_form.support_modal_id.choices = get_active_support_modal_choices()

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
            agent_update_form.organization_id.data = ticket.organization_id or 0
            agent_update_form.form_type_id.data = ticket.form_type_id or 0
            agent_update_form.tags.data = ticket.tags or ''
            agent_update_form.additional_email_recipients.data = ticket.additional_email_recipients or ''
            agent_update_form.request_call_back.data = ticket.request_call_back or ''
            agent_update_form.contact_details.data = ticket.contact_details or ''
            agent_update_form.aws_support_case_id.data = ticket.aws_support_case_id or ''
            agent_update_form.effort_required_to_resolve_min.data = str(ticket.effort_required_to_resolve_min) if ticket.effort_required_to_resolve_min is not None else ''
            agent_update_form.customer_name.data = ticket.customer_name or ''
            agent_update_form.apn_opportunity_id.data = ticket.apn_opportunity_id or 0
            agent_update_form.apn_opportunity_description.data = ticket.apn_opportunity_description or ''
            agent_update_form.support_modal_id.data = ticket.support_modal_id or 0

    if request.method == 'POST':
        if 'submit_comment' in request.form and comment_form.validate_on_submit():
            is_internal_comment = is_privileged_user and hasattr(comment_form, 'is_internal') and comment_form.is_internal.data
            comment = Comment(content=comment_form.content.data, user_id=current_user.id, ticket_id=ticket.id, is_internal=is_internal_comment)
            db.session.add(comment); db.session.flush() 
            log_interaction(ticket.id, 'COMMENT_ADDED', user_id=current_user.id, details={'comment_id': comment.id, 'is_internal': is_internal_comment})
            if not is_internal_comment and is_privileged_user and not ticket.first_response_at:
                ticket.first_response_at = comment.created_at
                if ticket.created_at: ticket.first_response_duration_minutes = int((ticket.first_response_at - ticket.created_at).total_seconds() / 60)
                log_interaction(ticket.id, 'FIRST_RESPONSE_RECORDED', user_id=current_user.id, details={'responded_at': ticket.first_response_at.isoformat() if ticket.first_response_at else None, 'duration_minutes': ticket.first_response_duration_minutes})
            db.session.commit(); flash('Your comment has been added.', 'success')
            return redirect(url_for('view_ticket', ticket_id=ticket.id, _anchor='comments_section'))
        
        elif 'submit_update' in request.form and is_privileged_user and agent_update_form and agent_update_form.validate_on_submit():
            old_values = {
                'status': ticket.status, 'priority': ticket.priority,
                'assignee_name': ticket.assignee.username if ticket.assignee else "Unassigned",
                'category_name': ticket.category_ref.name if ticket.category_ref else "None",
                'cloud_provider': ticket.cloud_provider or "None", 'severity': ticket.severity or "None",
                'aws_service': ticket.aws_service or "None", 'aws_account_id': ticket.aws_account_id or "None",
                'environment': ticket.environment or "None",
                'organization_name': ticket.organization_option_ref.name if ticket.organization_option_ref else "None",
                'form_type_name': ticket.form_type_option_ref.name if ticket.form_type_option_ref else "None",
                'tags': ticket.tags or "None",
                'additional_email_recipients': ticket.additional_email_recipients or "None",
                'request_call_back': ticket.request_call_back or "None",
                'contact_details': ticket.contact_details or "None",
                'aws_support_case_id': ticket.aws_support_case_id or "None",
                'effort_required_to_resolve_min': str(ticket.effort_required_to_resolve_min) if ticket.effort_required_to_resolve_min is not None else "None",
                'customer_name': ticket.customer_name or "None",
                'apn_opportunity_name': ticket.apn_opportunity_option_ref.name if ticket.apn_opportunity_option_ref else "None",
                'apn_opportunity_description': ticket.apn_opportunity_description or "None",
                'support_modal_name': ticket.support_modal_option_ref.name if ticket.support_modal_option_ref else "None",
            }
            old_severity_for_alert_trigger = ticket.severity
            ticket.status = agent_update_form.status.data; ticket.priority = agent_update_form.priority.data
            ticket.assigned_to_id = agent_update_form.assigned_to_id.data if agent_update_form.assigned_to_id.data != 0 else None
            ticket.category_id = agent_update_form.category_id.data if agent_update_form.category_id.data != 0 else None
            ticket.organization_id = agent_update_form.organization_id.data if agent_update_form.organization_id.data != 0 else None
            ticket.form_type_id = agent_update_form.form_type_id.data if agent_update_form.form_type_id.data != 0 else None
            ticket.apn_opportunity_id = agent_update_form.apn_opportunity_id.data if agent_update_form.apn_opportunity_id.data != 0 else None
            ticket.support_modal_id = agent_update_form.support_modal_id.data if agent_update_form.support_modal_id.data != 0 else None
            effort_str_val = agent_update_form.effort_required_to_resolve_min.data
            if effort_str_val and effort_str_val != '':
                try: ticket.effort_required_to_resolve_min = int(effort_str_val)
                except ValueError: agent_update_form.effort_required_to_resolve_min.errors.append("Invalid selection for effort.")
            else: ticket.effort_required_to_resolve_min = None
            ticket.cloud_provider = agent_update_form.cloud_provider.data or None; ticket.severity = agent_update_form.severity.data or None
            ticket.aws_service = agent_update_form.aws_service.data if ticket.cloud_provider == 'AWS' and agent_update_form.aws_service.data else None
            ticket.aws_account_id = agent_update_form.aws_account_id.data.strip() if agent_update_form.aws_account_id.data else None
            ticket.environment = agent_update_form.environment.data or None; ticket.tags = agent_update_form.tags.data.strip() if agent_update_form.tags.data else None
            ticket.additional_email_recipients = agent_update_form.additional_email_recipients.data.strip() if agent_update_form.additional_email_recipients.data else None
            ticket.request_call_back = agent_update_form.request_call_back.data or None; ticket.contact_details = agent_update_form.contact_details.data.strip() if agent_update_form.contact_details.data else None
            ticket.aws_support_case_id = agent_update_form.aws_support_case_id.data.strip() if agent_update_form.aws_support_case_id.data else None
            ticket.customer_name = agent_update_form.customer_name.data.strip() if agent_update_form.customer_name.data else None
            ticket.apn_opportunity_description = agent_update_form.apn_opportunity_description.data.strip() if agent_update_form.apn_opportunity_description.data else None
            
            changed_fields_map_display = {
                'Status': (old_values['status'], ticket.status), 'Priority': (old_values['priority'], ticket.priority),
                'Assignee': (old_values['assignee_name'], ticket.assignee.username if ticket.assignee else "Unassigned"),
                'Category': (old_values['category_name'], ticket.category_ref.name if ticket.category_ref else "None"),
                'Cloud Provider': (old_values['cloud_provider'], ticket.cloud_provider or "None"), 'Severity': (old_values['severity'], ticket.severity or "None"),
                'AWS Service': (old_values['aws_service'], ticket.aws_service or "None"), 'AWS Account ID': (old_values['aws_account_id'], ticket.aws_account_id or "None"),
                'Environment': (old_values['environment'], ticket.environment or "None"),
                'Organization': (old_values['organization_name'], ticket.organization_option_ref.name if ticket.organization_option_ref else "None"),
                'Form Type': (old_values['form_type_name'], ticket.form_type_option_ref.name if ticket.form_type_option_ref else "None"),
                'Tags': (old_values['tags'], ticket.tags or "None"),
                'Additional Email Recipients': (old_values['additional_email_recipients'], ticket.additional_email_recipients or "None"),
                'Request Call Back': (old_values['request_call_back'], ticket.request_call_back or "None"),
                'Contact Details': (old_values['contact_details'], ticket.contact_details or "None"),
                'AWS Support Case ID': (old_values['aws_support_case_id'], ticket.aws_support_case_id or "None"),
                'Effort (min)': (old_values['effort_required_to_resolve_min'], str(ticket.effort_required_to_resolve_min) if ticket.effort_required_to_resolve_min is not None else "None"),
                'Customer Name': (old_values['customer_name'], ticket.customer_name or "None"),
                'APN Opportunity': (old_values['apn_opportunity_name'], ticket.apn_opportunity_option_ref.name if ticket.apn_opportunity_option_ref else "None"),
                'APN Opportunity Description': (old_values['apn_opportunity_description'], ticket.apn_opportunity_description or "None"),
                'Support Modal': (old_values['support_modal_name'], ticket.support_modal_option_ref.name if ticket.support_modal_option_ref else "None"),
            }
            for field_name, (old_val, new_val) in changed_fields_map_display.items():
                if old_val != new_val:
                    interaction_type_suffix = field_name.upper().replace(" ", "_").replace("(", "").replace(")", "") + "_CHANGE"
                    log_interaction(ticket.id, interaction_type_suffix, user_id=current_user.id, details={'old_value': old_val, 'new_value': new_val, 'field_display_name': field_name})
            if agent_update_form.errors: flash('Error updating ticket. Please check the form.', 'danger')
            else:
                try:
                    db.session.commit(); flash('Ticket details updated successfully.', 'success'); trigger_priority_call_alert(ticket, old_severity_for_alert_trigger)
                    return redirect(url_for('view_ticket', ticket_id=ticket.id))
                except Exception as e: db.session.rollback(); flash(f'Database error during ticket update: {str(e)[:150]}', 'danger'); app.logger.error(f"Ticket update DB error for #{ticket.id}: {e}", exc_info=True)
        elif request.method == 'POST' and (comment_form.errors or (agent_update_form and agent_update_form.errors)): flash('Please correct the errors in the form.', 'danger')

    comments_query = ticket.comments
    if not is_privileged_user: comments_query = comments_query.filter_by(is_internal=False)
    comments = comments_query.order_by(Comment.created_at.asc()).all()
    sorted_interaction_dates = []; interactions_by_date = {}; today_date_obj = None; yesterday_date_obj = None
    if is_privileged_user:
        raw_interactions = ticket.interactions_rel.order_by(Interaction.timestamp.desc()).all(); processed_interactions = []
        for interaction in raw_interactions:
            actor_name = "System";
            if interaction.user: actor_name = interaction.user.username
            elif interaction.interaction_type == 'TICKET_CREATED' and ticket.creator: actor_name = ticket.creator.username
            p_interaction = {'obj': interaction, 'actor_name': actor_name, 'timestamp_obj': interaction.timestamp, 'time_str': interaction.timestamp.strftime('%H:%M'), 'date_str_short': interaction.timestamp.strftime('%b %d'), 'datetime_str_full': interaction.timestamp.strftime('%b %d, %Y %H:%M:%S'), 'message': "", 'title_for_display': actor_name}
            details = interaction.details or {}; field_display_name = details.get('field_display_name')
            if field_display_name: 
                old_val_display = details.get('old_value', "not set"); new_val_display = details.get('new_value', "not set")
                if old_val_display == "None" and new_val_display == "None": p_interaction['message'] = f"verified <strong>{field_display_name}</strong> (remained not set)."
                elif old_val_display == "None" or old_val_display == "not set": p_interaction['message'] = f"set <strong>{field_display_name}</strong> to <strong>{new_val_display}</strong>."
                elif new_val_display == "None" or new_val_display == "not set": p_interaction['message'] = f"cleared <strong>{field_display_name}</strong> (was <strong>{old_val_display}</strong>)."
                else: p_interaction['message'] = f"changed <strong>{field_display_name}</strong> from <strong>{old_val_display}</strong> to <strong>{new_val_display}</strong>."
            if interaction.interaction_type == 'TICKET_CREATED': p_interaction['message'] = f"created this ticket."
            elif interaction.interaction_type == 'COMMENT_ADDED':
                comment_obj = Comment.query.get(details.get('comment_id')); comment_type = "internal" if details.get('is_internal') else "public"; p_interaction['message'] = f"added a {comment_type} comment."
                if comment_obj and (not comment_obj.is_internal or is_privileged_user): p_interaction['comment_preview'] = comment_obj.content
            elif interaction.interaction_type == 'FIRST_RESPONSE_RECORDED': duration_min = details.get('duration_minutes', 'N/A'); p_interaction['message'] = f"logged the first agent response. Duration: {duration_min} minutes."
            if not p_interaction['message'] and not field_display_name: p_interaction['message'] = f"performed action: {interaction.interaction_type}. Details: {details}"
            processed_interactions.append(p_interaction)
        interactions_by_date = {k: sorted(list(g), key=lambda i: i['timestamp_obj'], reverse=True) for k, g in groupby(processed_interactions, key=lambda i: i['timestamp_obj'].date())}
        sorted_interaction_dates = sorted(interactions_by_date.keys(), reverse=True); today_date_obj = date.today(); yesterday_date_obj = today_date_obj - timedelta(days=1)
    return render_template('client/view_ticket.html', title=f'Ticket #{ticket.id}: {ticket.title}', ticket=ticket, comments=comments, comment_form=comment_form, agent_update_form=agent_update_form, attachments=attachments, is_privileged_user=is_privileged_user, sorted_interaction_dates=sorted_interaction_dates, interactions_by_date=interactions_by_date, today_date=today_date_obj, yesterday_date=yesterday_date_obj)

@app.route('/uploads/<filename>')
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
    except FileNotFoundError: app.logger.error(f"Physical file not found: {attachment.stored_filename} in directory {upload_dir}"); flash("File not found on server. Please contact support.", "danger"); return redirect(request.referrer or url_for('dashboard'))

@app.route('/agent/tickets/')
@app.route('/agent/tickets/view/<view_name>')
@agent_required
def agent_ticket_list(view_name=None):
    page = request.args.get('page', 1, type=int); query = Ticket.query; list_title = "Agent Tickets"
    if view_name is None: view_name = 'my_unsolved'
    if view_name == 'my_unsolved': query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status.notin_(['Resolved', 'Closed'])); list_title = "Your Unsolved Tickets"
    elif view_name == 'unassigned': query = query.filter(Ticket.assigned_to_id.is_(None), Ticket.status == 'Open'); list_title = "Unassigned Open Tickets"
    elif view_name == 'all_unsolved': query = query.filter(Ticket.status.notin_(['Resolved', 'Closed'])); list_title = "All Unsolved Tickets"
    elif view_name == 'recently_updated': list_title = "Recently Updated Tickets"
    elif view_name == 'pending': query = query.filter(Ticket.status == 'On Hold'); list_title = "Pending (On Hold) Tickets"
    elif view_name == 'recently_solved': query = query.filter(Ticket.status == 'Resolved'); list_title = "Recently Solved Tickets"
    elif view_name == 'current_tasks': query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status == 'In Progress'); list_title = "Your Current In-Progress Tickets"
    else: flash(f"Unknown ticket view: '{view_name}'. Defaulting to 'Your Unsolved Tickets'.", "warning"); query = query.filter(Ticket.assigned_to_id == current_user.id, Ticket.status.notin_(['Resolved', 'Closed'])); list_title = "Your Unsolved Tickets"; view_name = 'my_unsolved'
    if view_name in ['recently_updated', 'recently_solved', 'all_unsolved', 'unassigned', 'pending']: ordered_query = query.order_by(Ticket.updated_at.desc())
    else: priority_order = db.case({'Urgent': 1, 'High': 2, 'Medium': 3, 'Low': 4}, value=Ticket.priority, else_=5); ordered_query = query.order_by(priority_order.asc(), Ticket.updated_at.desc())
    tickets_pagination = ordered_query.paginate(page=page, per_page=10, error_out=False)
    return render_template('agent/ticket_list.html', title=list_title, tickets_pagination=tickets_pagination, current_view=view_name)

@app.route('/ticket/<int:ticket_id>/assign_to_me')
@agent_required
def assign_ticket_to_me(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.assigned_to_id is None or ticket.assigned_to_id != current_user.id:
        old_assignee_name = ticket.assignee.username if ticket.assignee else "Unassigned"; old_status = ticket.status; status_changed = False
        ticket.assigned_to_id = current_user.id
        if ticket.status == 'Open': ticket.status = 'In Progress'; status_changed = True
        log_interaction(ticket.id, 'ASSIGNMENT_CHANGE', user_id=current_user.id, details={'old_value': old_assignee_name, 'new_value': current_user.username, 'field_display_name': 'Assignee'})
        if status_changed: log_interaction(ticket.id, 'STATUS_CHANGE', user_id=current_user.id, details={'old_value': old_status, 'new_value': ticket.status, 'field_display_name': 'Status'})
        db.session.commit(); flash(f'Ticket #{ticket.id} has been assigned to you.', 'success')
    elif ticket.assigned_to_id == current_user.id: flash(f'Ticket #{ticket.id} is already assigned to you.', 'info')
    else: flash(f'Ticket #{ticket.id} is already assigned to another agent ({ticket.assignee.username if ticket.assignee else "Unknown"}).', 'warning')
    return redirect(request.referrer or url_for('agent_ticket_list', view_name='unassigned'))

# --- Admin Routes ---
def _admin_list_options(model_class, template_name, title, order_by_attr='name'):
    items = model_class.query.order_by(getattr(model_class, order_by_attr)).all(); model_name_slug = to_snake_case(model_class.__name__)
    return render_template(template_name, title=title, items=items, model_name=model_name_slug)
def _admin_create_edit_option(model_class, form_class, list_url_func_name, item_id=None):
    item = model_class.query.get_or_404(item_id) if item_id else None; form = form_class(obj=item if request.method == 'GET' and item else None)
    type_name_raw = model_class.__name__.replace("Option",""); type_name_display = " ".join(re.findall('[A-Z][^A-Z]*', type_name_raw) or [type_name_raw]);
    if not type_name_display.strip(): type_name_display = model_class.__name__ 
    legend = f'New {type_name_display}' if not item else f'Edit {type_name_display}: {getattr(item, "name", "Item")}'
    if form.validate_on_submit():
        is_new = (item is None); option_instance = item or model_class(); existing_item_with_name_query = model_class.query.filter(model_class.name == form.name.data)
        if option_instance.id: existing_item_with_name_query = existing_item_with_name_query.filter(model_class.id != option_instance.id)
        existing_item_with_name = existing_item_with_name_query.first()
        if existing_item_with_name: form.name.errors.append(f'The name "{form.name.data}" already exists for {type_name_display}.')
        if not form.errors:
            form.populate_obj(option_instance);
            if is_new: db.session.add(option_instance)
            try: db.session.commit(); flash(f'{type_name_display} "{option_instance.name}" saved.', 'success'); return redirect(url_for(list_url_func_name))
            except Exception as e: db.session.rollback(); flash(f'DB error saving {type_name_display}: {e}', 'danger'); app.logger.error(f"Error saving option {type_name_display} {option_instance.name}: {e}", exc_info=True)
    return render_template('admin/create_edit_option.html', title=legend, form=form, legend=legend,item_type_name=type_name_display, list_url=url_for(list_url_func_name))
def _admin_delete_option(model_class, item_id, list_url_func_name, related_ticket_attr_id=None, related_ticket_attr_name=None):
    item = model_class.query.get_or_404(item_id); item_name = getattr(item, "name", "Item"); type_name_raw = model_class.__name__.replace("Option",""); type_name_display = " ".join(re.findall('[A-Z][^A-Z]*', type_name_raw) or [type_name_raw])
    if not type_name_display.strip(): type_name_display = model_class.__name__
    can_delete = True; query_filter = None
    if related_ticket_attr_id and hasattr(Ticket, related_ticket_attr_id): query_filter = (getattr(Ticket, related_ticket_attr_id) == item.id)
    elif related_ticket_attr_name and hasattr(Ticket, related_ticket_attr_name): query_filter = (getattr(Ticket, related_ticket_attr_name) == item.name)
    if query_filter is not None and Ticket.query.filter(query_filter).first(): can_delete = False; flash(f'Cannot delete "{item_name}", as it is associated with one or more tickets.', 'danger')    
    if can_delete:
        try: db.session.delete(item); db.session.commit(); flash(f'{type_name_display} "{item_name}" deleted.', 'success')
        except Exception as e: db.session.rollback(); flash(f'Error deleting {type_name_display} "{item_name}": {e}', 'danger'); app.logger.error(f"Error deleting option {type_name_display} {item_name}: {e}", exc_info=True)
    return redirect(url_for(list_url_func_name))

@app.route('/admin/users')
@admin_required
def admin_user_list(): users = User.query.order_by(User.username).all(); share_form = ShareCredentialsForm(); return render_template('admin/user_list.html', title='Manage Users', users=users, share_form=share_form)
@app.route('/admin/user/new', methods=['GET', 'POST'])
@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_user(user_id=None):
    user_to_edit = User.query.get_or_404(user_id) if user_id else None; form = AdminUserForm(obj=user_to_edit if request.method == 'GET' and user_to_edit else None)
    form.organization_id.choices = get_active_organization_choices() # Populate for admin form
    legend = 'Create New User' if not user_to_edit else f'Edit User: {user_to_edit.username}'
    original_password_validators = list(form.password.validators); original_password2_validators = list(form.password2.validators)
    if not user_to_edit: form.password.validators = [DataRequired(message="Password is required for new users.")] + [v for v in original_password_validators if not isinstance(v, Optional)]; form.password2.validators = [DataRequired(message="Please confirm the password.")] + [v for v in original_password2_validators if not isinstance(v, Optional)]
    else: form.password.validators = [Optional()] + [v for v in original_password_validators if not isinstance(v, (DataRequired, Optional))]; form.password2.validators = [EqualTo('password', message='Passwords must match if new password provided.')] + [Optional()] + [v for v in original_password2_validators if not isinstance(v, (DataRequired, Optional, EqualTo))]
    if form.validate_on_submit():
        is_new_user = (user_to_edit is None); user = user_to_edit or User(); user_id_to_exclude = user.id if user.id else -1
        if User.query.filter(User.username == form.username.data, User.id != user_id_to_exclude).first(): form.username.errors.append('This username is already taken.')
        if User.query.filter(User.email == form.email.data.lower(), User.id != user_id_to_exclude).first(): form.email.errors.append('This email address is already registered.')
        if not is_new_user and form.password.data and not form.password2.data: form.password2.errors.append("Please confirm the new password if you are changing it.")
        if not form.errors:
            user.username = form.username.data; user.email = form.email.data.lower(); user.role = form.role.data
            user.organization_id = form.organization_id.data if form.organization_id.data != 0 else None # Set org from admin
            if form.password.data: user.set_password(form.password.data)
            if is_new_user: db.session.add(user)
            try: db.session.commit(); flash(f'User "{user.username}" has been {"created" if is_new_user else "updated"} successfully.', 'success'); return redirect(url_for('admin_user_list'))
            except Exception as e: db.session.rollback(); flash(f'Database error: Could not save user. {str(e)}', 'danger'); app.logger.error(f"Admin user save error for '{form.username.data}': {e}", exc_info=True)
    elif request.method == 'GET' and user_to_edit: form.organization_id.data = user_to_edit.organization_id or 0 # Pre-fill for edit
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
            Ticket.query.filter_by(assigned_to_id=user_id).update({'assigned_to_id': None}); Attachment.query.filter_by(uploaded_by_id=user_id).delete(synchronize_session='fetch')
            Comment.query.filter_by(user_id=user_id).delete(synchronize_session='fetch'); Interaction.query.filter_by(user_id=user_id).update({'user_id': None}, synchronize_session='fetch')
            db.session.delete(user_to_delete); db.session.commit(); flash(f'User "{deleted_username}" and their associated comments/attachments deleted. Interactions anonymized.', 'success'); app.logger.info(f"Admin '{current_user.username}' deleted user '{deleted_username}'.")
        except Exception as e: db.session.rollback(); flash(f'Error deleting user "{deleted_username}": {e}', 'danger'); app.logger.error(f"Error deleting user {user_id}: {e}", exc_info=True)
    return redirect(url_for('admin_user_list'))

@app.route('/admin/user/<int:user_id>/share_credentials', methods=['POST'])
@admin_required
def admin_share_credentials(user_id):
    user_to_share = User.query.get_or_404(user_id); admin_user = current_user; form = ShareCredentialsForm(request.form)
    if form.validate():
        recipient_email = form.recipient_email.data; subject = f"Account Information for Ticket System: {user_to_share.username}"; body_text = render_template('email/share_credentials_email.txt', user_being_shared=user_to_share, admin_user=admin_user)
        msg = Message(subject, recipients=[recipient_email], body=body_text)
        try: mail.send(msg); flash(f'Account info for "{user_to_share.username}" sent to {recipient_email}.', 'success'); app.logger.info(f"Admin '{admin_user.username}' shared credentials info for '{user_to_share.username}' with '{recipient_email}'.")
        except Exception as e: flash(f'Failed to send email: {e}', 'danger'); app.logger.error(f"Failed to send share credentials email for {user_to_share.username}: {e}", exc_info=True)
    else:
        for field_name, errors in form.errors.items():
            label = getattr(getattr(form, field_name), 'label', None); label_text = label.text if label else field_name.replace("_", " ").title(); flash(f"Error in sharing form ({label_text}): {', '.join(errors)}", 'danger')
    return redirect(url_for('admin_user_list'))

@app.route('/admin/categories')
@admin_required
def admin_category_list(): return _admin_list_options(Category, 'admin/list_options.html', 'Manage Categories')
@app.route('/admin/category/new', methods=['GET', 'POST'])
@app.route('/admin/category/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_category(item_id=None): return _admin_create_edit_option(Category, CategoryForm, 'admin_category_list', item_id)
@app.route('/admin/category/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_category(item_id): return _admin_delete_option(Category, item_id, 'admin_category_list', related_ticket_attr_id='category_id')

@app.route('/admin/cloud_providers')
@admin_required
def admin_cloud_provider_list(): return _admin_list_options(CloudProviderOption, 'admin/list_options.html', 'Manage Cloud Providers')
@app.route('/admin/cloud_provider/new', methods=['GET', 'POST'])
@app.route('/admin/cloud_provider/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_cloud_provider(item_id=None): return _admin_create_edit_option(CloudProviderOption, CloudProviderOptionForm, 'admin_cloud_provider_list', item_id)
@app.route('/admin/cloud_provider/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_cloud_provider(item_id): return _admin_delete_option(CloudProviderOption, item_id, 'admin_cloud_provider_list', related_ticket_attr_name='cloud_provider')

@app.route('/admin/severities')
@admin_required
def admin_severity_list(): return _admin_list_options(SeverityOption, 'admin/list_options.html', 'Manage Severity Levels', 'order')
@app.route('/admin/severity/new', methods=['GET', 'POST'])
@app.route('/admin/severity/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_severity(item_id=None): return _admin_create_edit_option(SeverityOption, SeverityOptionForm, 'admin_severity_list', item_id)
@app.route('/admin/severity/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_severity(item_id): return _admin_delete_option(SeverityOption, item_id, 'admin_severity_list', related_ticket_attr_name='severity')

@app.route('/admin/environments')
@admin_required
def admin_environment_list(): return _admin_list_options(EnvironmentOption, 'admin/list_options.html', 'Manage Environments')
@app.route('/admin/environment/new', methods=['GET', 'POST'])
@app.route('/admin/environment/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_environment(item_id=None): return _admin_create_edit_option(EnvironmentOption, EnvironmentOptionForm, 'admin_environment_list', item_id)
@app.route('/admin/environment/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_environment(item_id): return _admin_delete_option(EnvironmentOption, item_id, 'admin_environment_list', related_ticket_attr_name='environment')

@app.route('/admin/organizations')
@admin_required
def admin_organization_list(): return _admin_list_options(OrganizationOption, 'admin/list_options.html', 'Manage Organizations')
@app.route('/admin/organization/new', methods=['GET', 'POST'])
@app.route('/admin/organization/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_organization(item_id=None): return _admin_create_edit_option(OrganizationOption, OrganizationOptionForm, 'admin_organization_list', item_id)
@app.route('/admin/organization/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_organization(item_id): return _admin_delete_option(OrganizationOption, item_id, 'admin_organization_list', related_ticket_attr_id='organization_id')

@app.route('/admin/form_types')
@admin_required
def admin_form_type_list(): return _admin_list_options(FormTypeOption, 'admin/list_options.html', 'Manage Form Types')
@app.route('/admin/form_type/new', methods=['GET', 'POST'])
@app.route('/admin/form_type/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_form_type(item_id=None): return _admin_create_edit_option(FormTypeOption, FormTypeOptionForm, 'admin_form_type_list', item_id)
@app.route('/admin/form_type/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_form_type(item_id): return _admin_delete_option(FormTypeOption, item_id, 'admin_form_type_list', related_ticket_attr_id='form_type_id')

@app.route('/admin/apn_opportunities')
@admin_required
def admin_apn_opportunity_list(): return _admin_list_options(APNOpportunityOption, 'admin/list_options.html', 'Manage APN Opportunities')
@app.route('/admin/apn_opportunity/new', methods=['GET', 'POST'])
@app.route('/admin/apn_opportunity/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_apn_opportunity(item_id=None): return _admin_create_edit_option(APNOpportunityOption, APNOpportunityOptionForm, 'admin_apn_opportunity_list', item_id)
@app.route('/admin/apn_opportunity/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_apn_opportunity(item_id): return _admin_delete_option(APNOpportunityOption, item_id, 'admin_apn_opportunity_list', related_ticket_attr_id='apn_opportunity_id')

@app.route('/admin/support_modals')
@admin_required
def admin_support_modal_list(): return _admin_list_options(SupportModalOption, 'admin/list_options.html', 'Manage Support Modals by Plan')
@app.route('/admin/support_modal/new', methods=['GET', 'POST'])
@app.route('/admin/support_modal/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_create_edit_support_modal(item_id=None): return _admin_create_edit_option(SupportModalOption, SupportModalOptionForm, 'admin_support_modal_list', item_id)
@app.route('/admin/support_modal/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_support_modal(item_id): return _admin_delete_option(SupportModalOption, item_id, 'admin_support_modal_list', related_ticket_attr_id='support_modal_id')

@app.route('/admin/tickets')
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

# --- CLI Commands ---
@app.cli.command('init-db')
def init_db_command():
    try:
        with app.app_context():
            engine = db.engine 
            if engine.name == 'mysql': app.logger.info("MySQL detected. Attempting to disable FOREIGN_KEY_CHECKS."); connection = engine.connect(); connection.execute(db.text('SET FOREIGN_KEY_CHECKS = 0;')); connection.commit(); connection.close()
            app.logger.info("Dropping all tables..."); db.drop_all(); app.logger.info("All tables dropped successfully.")
            app.logger.info("Creating all tables..."); db.create_all(); app.logger.info("All tables created successfully.")
            if engine.name == 'mysql': app.logger.info("Attempting to re-enable FOREIGN_KEY_CHECKS for MySQL."); connection = engine.connect(); connection.execute(db.text('SET FOREIGN_KEY_CHECKS = 1;')); connection.commit(); connection.close()
        print('Database tables dropped and recreated successfully.')
    except Exception as e:
        app.logger.error(f"Error during init-db CLI command: {e}", exc_info=True); print(f"Error during init-db: {e}")
        if 'engine' in locals() and engine.name == 'mysql':
            try:
                with app.app_context(): connection = db.engine.connect(); connection.execute(db.text('SET FOREIGN_KEY_CHECKS = 1;')); connection.commit(); connection.close()
            except Exception as fk_e: app.logger.error(f"Failed to re-enable FOREIGN_KEY_CHECKS after error: {fk_e}")

@app.cli.command('create-initial-data')
def create_initial_data_command():
    with app.app_context():
        users_data = [
            {'username': 'admin', 'email': os.environ.get('ADMIN_USER_EMAIL', 'monish.jodha@cloudkeeper.com'), 'role': 'admin', 'password': os.environ.get('ADMIN_USER_PASSWORD', 'adminpass')},
            {'username': 'agent', 'email': os.environ.get('AGENT_USER_EMAIL', 'monish.jodha+1@cloudkeeper.com'), 'role': 'agent', 'password': os.environ.get('AGENT_USER_PASSWORD', 'agentpass')},
            {'username': 'client', 'email': os.environ.get('CLIENT_USER_EMAIL', 'monish.jodha+2@cloudkeeper.com'), 'role': 'client', 'password': os.environ.get('CLIENT_USER_PASSWORD', 'clientpass')}
        ]
        print("Attempting to create initial users...")
        for u_data in users_data:
            existing_user = User.query.filter((User.username == u_data['username']) | (User.email == u_data['email'])).first()
            if not existing_user: user = User(username=u_data['username'], email=u_data['email'], role=u_data['role']); user.set_password(u_data['password']); db.session.add(user); print(f"  User '{u_data['username']}' created.")
            else: print(f"  Skipping user '{u_data['username']}', already exists.")
        
        print("\nEnsuring default options...")
        options_map = {
            OrganizationOption: ['CloudKeeper (CK)', 'Client Org A', 'Client Org B', 'Default Client Org'], # Added a default for clients if domain not mapped
            Category: ['Technical Support', 'Billing Inquiry', 'General Question', 'Feature Request'],
            CloudProviderOption: ['AWS', 'Azure', 'GCP', 'On-Premise', 'Other'],
            EnvironmentOption: ['Production', 'Staging', 'Development', 'Test', 'QA', 'UAT'],
            FormTypeOption: ['Technical', 'Billing', 'General Inquiry', 'Sales Query'],
            APNOpportunityOption: ['MAP', 'Well-Architected Review', 'New Service Adoption', 'Cost Optimization', 'Security Assessment', 'Test 1'],
            SupportModalOption: ['Basic Plan', 'Developer Plan', 'Business Plan', 'Enterprise Plan', 'Premium Plus']
        }
        for model_class, names in options_map.items():
            created_count = 0
            for name_val in names:
                if not model_class.query.filter_by(name=name_val).first():
                    instance_args = {'name': name_val}
                    if hasattr(model_class, 'is_active'): instance_args['is_active'] = True
                    if model_class == Category and hasattr(model_class, 'description'): instance_args['description'] = f"Default description for {name_val}"
                    db.session.add(model_class(**instance_args)); created_count +=1
            if created_count > 0: print(f"  Added {created_count} new default {model_class.__name__}(s).")
            else: print(f"  Default {model_class.__name__}s already exist or no new ones needed.")

        print("\nEnsuring default Severity Levels...")
        severities_data = [
            {'name': 'Severity 1 (Critical)', 'o': 1, 'd': 'Critical impact.'}, {'name': 'Severity 2 (High)', 'o': 2, 'd': 'Significant impact.'},
            {'name': 'Severity 3 (Medium)', 'o': 3, 'd': 'Moderate impact.'}, {'name': 'Severity 4 (Low)', 'o': 4, 'd': 'Minor impact.'}
        ]
        created_severity_count = 0
        for sev_data in severities_data:
            if not SeverityOption.query.filter_by(name=sev_data['name']).first(): db.session.add(SeverityOption(name=sev_data['name'], order=sev_data['o'], description=sev_data['d'], is_active=True)); created_severity_count +=1
        if created_severity_count > 0: print(f"  Added {created_severity_count} new default Severity Levels.")
        else: print(f"  Default Severity Levels already exist or no new ones needed.")
        
        try: db.session.commit(); print("\nUsers, options, and severities committed successfully.")
        except Exception as e: db.session.rollback(); print(f"\nError committing base data: {e}"); return 

        client_user = User.query.filter_by(role='client').first(); admin_user = User.query.filter_by(role='admin').first()
        if not client_user or not admin_user: print("\nSkipping dummy ticket: Default client or admin user not found."); return
        first_ticket = Ticket.query.order_by(Ticket.id.asc()).first()
        if not first_ticket: 
            print("\nNo existing tickets found. Creating a dummy ticket...")
            # Fetch necessary default options by name
            cat = Category.query.filter_by(name='Technical Support').first()
            sev = SeverityOption.query.filter_by(name='Severity 1 (Critical)').first()
            org = OrganizationOption.query.filter_by(name='CloudKeeper (CK)').first() or client_user.organization # Fallback to client's org
            form_type = FormTypeOption.query.filter_by(name='Technical').first()
            
            if not all([cat, sev, org, form_type]): print("  Could not find all necessary default options for dummy ticket. Skipping."); return

            first_ticket = Ticket(
                title="Urgent Server Down Issue", description="Production server is unresponsive after recent update.",
                created_by_id=client_user.id, status='Open', priority='Urgent', category_id=cat.id,
                severity=sev.name, organization_id=org.id, form_type_id=form_type.id,
                customer_name=client_user.get_organization_name() or client_user.username, # Use org name or username
                cloud_provider="AWS", aws_account_id="123456789012", environment="Production"
            )
            db.session.add(first_ticket)
            try:
                db.session.flush(); log_interaction(first_ticket.id, 'TICKET_CREATED', user_id=client_user.id, details={'title': first_ticket.title}, timestamp_override=first_ticket.created_at)
                db.session.commit(); print(f"  Created dummy ticket #{first_ticket.id}.")
            except Exception as e: db.session.rollback(); print(f"  Error creating dummy ticket: {e}"); app.logger.error(f"Dummy ticket creation error: {e}", exc_info=True); return
        
        if first_ticket and not Interaction.query.filter_by(ticket_id=first_ticket.id, interaction_type='TICKET_CREATED').first():
             log_interaction(first_ticket.id, 'TICKET_CREATED', user_id=first_ticket.created_by_id, details={'title': first_ticket.title}, timestamp_override=first_ticket.created_at, commit_now=True)
             print(f"  Logged TICKET_CREATED for existing ticket #{first_ticket.id}")
        print("\nInitial data creation process finished.")

if __name__ == '__main__':
    upload_folder_path_at_startup = app.config.get('UPLOAD_FOLDER')
    if not os.path.isabs(upload_folder_path_at_startup):
        upload_folder_path_at_startup = os.path.join(app.root_path, upload_folder_path_at_startup)
        app.config['UPLOAD_FOLDER'] = upload_folder_path_at_startup 
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        try: os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True); app.logger.info(f"Startup: Upload folder ensured/created at: {app.config['UPLOAD_FOLDER']}")
        except OSError as e: app.logger.critical(f"CRITICAL: Could not create upload folder {app.config['UPLOAD_FOLDER']}: {e}. Check path and permissions.", exc_info=True)
    app.run(debug=True, host='0.0.0.0', port=5000)