import os
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-ticket-system-secret-key-very-secure-now-final'

    # --- MySQL Configuration ---
    MYSQL_USER = os.environ.get('MYSQL_USER_TICKET_CMS') or 'ticket_user'
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD_TICKET_CMS') or 'Jodha@123' # YOUR PASSWORD
    MYSQL_HOST = os.environ.get('MYSQL_HOST_TICKET_CMS') or 'localhost'         # SHOULD BE 'localhost'
    MYSQL_DB = os.environ.get('MYSQL_DB_TICKET_CMS') or 'ticket_cms_db'
    MYSQL_CHARSET = 'utf8mb4'

    # Using PyMySQL
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@"
        f"{MYSQL_HOST}/{MYSQL_DB}?charset={MYSQL_CHARSET}"  # <-- This line constructs the URI
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    
    MAIL_SERVER = os.environ.get('MAIL_SERVER_TICKET_CMS') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT_TICKET_CMS') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS_TICKET_CMS', 'true').lower() in ['true', '1', 't'] # Gmail uses TLS
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL_TICKET_CMS', 'false').lower() in ['true', '1', 't'] # Not for Gmail with port 587
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME_TICKET_CMS') or 'monish.jodha@cloudkeeper.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD_TICKET_CMS') or 'klkm jzmv djvu kyjs'
    MAIL_DEFAULT_SENDER = ('TicketSys Admin', os.environ.get('MAIL_DEFAULT_SENDER_EMAIL_TICKET_CMS') or 'monish.jodha@cloudkeeper.com')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL_TICKET_CMS') or 'monish.jodha@cloudkeeper.com' 
    
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'}
    MAX_CONTENT_LENGTH = 16 * 1000 * 1000 # 16 MB upload limit
    