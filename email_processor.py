

import os
import sys
from datetime import datetime
import logging
import re
import uuid

# Add the project root to sys.path to allow importing app components
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from dotenv import load_dotenv, find_dotenv
dotenv_file_path = find_dotenv(raise_error_if_not_found=False)
if dotenv_file_path:
    loaded_env = load_dotenv(dotenv_file_path, verbose=True, override=True) # Override existing env vars
    print(f"INFO (email_processor): .env file found at: {dotenv_file_path}, Loaded by dotenv: {loaded_env}")
else:
    print(f"WARNING (email_processor): .env file not found. Relying on system environment variables or Config defaults.")


from imap_tools import MailBox, AND, NOT, MailMessageFlags, MailboxLoginError
import html2text
from werkzeug.utils import secure_filename
from urllib.parse import urlparse

# Import necessary components AFTER dotenv loading to ensure app.config is correct
from app import app, db, User, Ticket, Category, Attachment, CloudProviderOption, SeverityOption, EnvironmentOption, mail, allowed_file
from flask_mail import Message
from flask import render_template, url_for # current_app is not needed here for this fix


# Configure logging
logger = logging.getLogger('email_processor')
logger.setLevel(logging.INFO) 
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def process_email_body_for_ticket(email_body_html, email_body_text):
    """Extracts relevant content from email, attempting to strip signatures/replies."""
    if email_body_text:
        lines = email_body_text.splitlines()
        content_lines = []
        for line in lines:
            line_lower_stripped = line.lower().strip()
            if line_lower_stripped == '--' or \
               line_lower_stripped.startswith(('from:', 'sent from my', 'on ', '> wrote:', 'regards', 'best regards', 'thanks', 'sincerely')) or \
               re.match(r'^\s*on\s+.*\s+wrote:$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^sent from my (iphone|android|ipad|samsung|device|mail for windows)', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^-+original\s+message-+$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^\s*>*$', line_lower_stripped) or \
               "________________________________" in line or \
               re.match(r'^Sent from (Outlook|Mail) for.*', line, re.IGNORECASE):
                break 
            if line_lower_stripped.startswith('>'): 
                continue
            content_lines.append(line)
        description = "\n".join(content_lines).strip()
        if description: return description

    if email_body_html:
        h = html2text.HTML2Text()
        h.ignore_links = False
        h.ignore_images = True 
        h.body_width = 0 
        text_content = h.handle(email_body_html)
        
        lines = text_content.splitlines()
        content_lines = []
        for line in lines:
            if re.match(r'^\s*(From|Sent|To|Subject)\s*:\s*', line, re.IGNORECASE) and \
               any(kw in line.lower() for kw in ['@', 'wrote:', 'original message']):
                break 
            content_lines.append(line)
        description = "\n".join(content_lines).strip()
        return description if description else "(HTML email body processed to empty)"
        
    return "No readable content found in email."


def infer_details_from_email(subject, body):
    """Infers ticket details like category, severity from email subject/body."""
    details = {
        'category_name': app.config.get('EMAIL_TICKET_DEFAULT_CATEGORY_NAME', 'General Inquiry'),
        'severity_name': app.config.get('EMAIL_TICKET_DEFAULT_SEVERITY_NAME', 'Severity 3 (Medium)'),
        'priority': 'Medium', 'cloud_provider': None, 'environment': None
    }
    subject_lower = subject.lower(); body_lower = body.lower() if body else ""

    if 'urgent' in subject_lower or 'critical' in subject_lower or 'down' in body_lower or 'outage' in body_lower:
        details['priority'] = 'Urgent'
        sev_opt = SeverityOption.query.filter(
            (SeverityOption.name.ilike('%Critical%')) | (SeverityOption.name.ilike('%Severity 1%')),
            SeverityOption.is_active == True
        ).order_by(SeverityOption.order.asc()).first()
        if sev_opt: details['severity_name'] = sev_opt.name

    if 'billing' in subject_lower or 'invoice' in subject_lower or 'payment' in subject_lower:
        cat_opt = Category.query.filter(Category.name.ilike('%Billing%')).first()
        if cat_opt: details['category_name'] = cat_opt.name
    
    cloud_keywords = {'aws': 'AWS', 'amazon web services': 'AWS', 'azure': 'Azure', 'microsoft azure': 'Azure', 'gcp': 'GCP', 'google cloud': 'GCP'}
    for keyword, provider_name_in_db in cloud_keywords.items():
        if keyword in subject_lower or keyword in body_lower:
            cp_opt = CloudProviderOption.query.filter_by(name=provider_name_in_db, is_active=True).first()
            if cp_opt: details['cloud_provider'] = cp_opt.name; break
    
    env_keywords = {'production': 'Production', 'prod': 'Production', 'staging': 'Staging', 'stage': 'Staging', 'development': 'Development', 'dev': 'Development', 'test': 'Test', 'qa': 'QA'}
    for keyword, env_name_in_db in env_keywords.items():
        if keyword in subject_lower or keyword in body_lower:
            env_opt = EnvironmentOption.query.filter_by(name=env_name_in_db, is_active=True).first()
            if env_opt: details['environment'] = env_opt.name; break
            
    return details


def fetch_and_process_emails():
    with app.app_context(): 
        logger.info("Starting email fetch process...")
        try:
            imap_server = app.config.get('IMAP_SERVER')
            imap_username = app.config.get('IMAP_USERNAME')
            imap_password = app.config.get('IMAP_PASSWORD')
            imap_folder = app.config.get('IMAP_MAILBOX_FOLDER', 'INBOX')

            if not all([imap_server, imap_username, imap_password]):
                logger.error("CRITICAL: IMAP server, username, or password NOT SET in app.config. Aborting email fetch."); return

            with MailBox(imap_server).login(imap_username, imap_password, imap_folder) as mailbox:
                unseen_msgs_uids = mailbox.uids('UNSEEN') # Simpler query
                logger.info(f"Found {len(unseen_msgs_uids)} unseen email(s) in '{imap_folder}'.")

                for uid in unseen_msgs_uids:
                    msg_obj = None; 
                    log_msg_id = f"UID {uid}" 
                    try:
                        msg_generator = mailbox.fetch(uid, mark_seen=False)
                        msg_obj = next(msg_generator, None)

                        if not msg_obj:
                            logger.warning(f"Could not fetch message data for {log_msg_id}. Skipping.")
                            try: mailbox.flag([uid], MailMessageFlags.SEEN, True); logger.info(f"Marked unfetchable {log_msg_id} as SEEN.")
                            except Exception as e_flag: logger.error(f"Failed to mark unfetchable {log_msg_id} as SEEN: {e_flag}")
                            continue

                        log_msg_id = f"UID {uid} (From: {msg_obj.from_}, Subject: '{msg_obj.subject}')"
                        logger.info(f"Processing email: {log_msg_id}")

                        sender_email = msg_obj.from_.lower()
                        sender_name = msg_obj.from_values.name if msg_obj.from_values and msg_obj.from_values.name else sender_email.split('@')[0]
                        
                        ticket_title = msg_obj.subject or "No Subject (Email Import)"
                        ticket_description = process_email_body_for_ticket(msg_obj.html, msg_obj.text)
                        if not ticket_description.strip(): ticket_description = "(Email body processed to empty)"

                        user = User.query.filter_by(email=sender_email).first()
                        if not user:
                            base_username = re.sub(r'[^a-z0-9_]', '', sender_name.lower().replace(" ", "_")) or sender_email.split('@')[0].split('.')[0] or "emailuser"
                            username_candidate = base_username[:40]; count = 1
                            while User.query.filter_by(username=username_candidate).first():
                                username_candidate = f"{base_username[:40]}_{count}"; count += 1
                            user = User(username=username_candidate, email=sender_email, role='client')
                            db.session.add(user); db.session.flush()
                            logger.info(f"Created new user '{user.username}' (ID: {user.id}) from email {sender_email}")

                        inferred = infer_details_from_email(ticket_title, ticket_description)
                        category = Category.query.filter_by(name=inferred['category_name']).first()
                        severity = SeverityOption.query.filter_by(name=inferred['severity_name'], is_active=True).first()
                        cloud = CloudProviderOption.query.filter_by(name=inferred['cloud_provider'], is_active=True).first() if inferred['cloud_provider'] else None
                        env = EnvironmentOption.query.filter_by(name=inferred['environment'], is_active=True).first() if inferred['environment'] else None

                        new_ticket = Ticket(
                            title=ticket_title[:99], description=ticket_description, created_by_id=user.id,
                            status='Open', priority=inferred['priority'], 
                            category_id=category.id if category else None,
                            cloud_provider=cloud.name if cloud else None, 
                            severity=severity.name if severity else None,
                            environment=env.name if env else None
                        )
                        db.session.add(new_ticket); db.session.flush()

                        attachments_saved_count = 0
                        if msg_obj.attachments:
                            for att in msg_obj.attachments:
                                if att.filename and allowed_file(att.filename):
                                    try:
                                        safe_fn = secure_filename(att.filename)
                                        stored_fn = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}_{safe_fn}"
                                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_fn)
                                        with open(file_path, 'wb') as f: f.write(att.payload)
                                        
                                        db_attachment = Attachment(
                                            filename=safe_fn, stored_filename=stored_fn, 
                                            ticket_id=new_ticket.id, uploaded_by_id=user.id, 
                                            content_type=att.content_type
                                        )
                                        db.session.add(db_attachment)
                                        attachments_saved_count += 1
                                    except Exception as e_att: logger.error(f"Attachment save failed for '{att.filename}' on ticket #{new_ticket.id}: {e_att}")
                                else: logger.warning(f"Skipped attachment (disallowed type or no filename): '{att.filename or 'Unnamed'}' for ticket #{new_ticket.id}")
                        
                        db.session.commit()
                        logger.info(f"Ticket #{new_ticket.id} created for user '{user.username}'. {attachments_saved_count} attachments.")

                        # Send auto-reply confirmation
                        try:
                            login_url_val = url_for('login', _external=True)
                            ticket_url_val = url_for('view_ticket', ticket_id=new_ticket.id, _external=True)
                            
                            email_subject = f"Ticket Received: #{new_ticket.id} - {new_ticket.title}"
                            
                            # Pass the app's config directly to the template context
                            email_body = render_template('email/ticket_autoreply.txt', 
                                                         ticket=new_ticket, 
                                                         user=user,
                                                         login_url=login_url_val, 
                                                         ticket_url=ticket_url_val,
                                                         config=app.config) # Pass app.config as 'config'
                            
                            reply_msg = Message(email_subject, recipients=[sender_email], body=email_body, 
                                                sender=app.config.get('MAIL_DEFAULT_SENDER'))
                            mail.send(reply_msg)
                            logger.info(f"Auto-reply sent to {sender_email} for ticket #{new_ticket.id}")
                        except Exception as e_reply:
                            logger.error(f"Failed to send auto-reply for ticket #{new_ticket.id}: {e_reply}")
                            logger.exception("Auto-reply TRACEBACK:")
                        
                        mailbox.flag([uid], MailMessageFlags.SEEN, True)
                        logger.info(f"Successfully processed and marked {log_msg_id} as SEEN.")

                    except Exception as e_proc_msg:
                        db.session.rollback()
                        logger.error(f"Failed processing email {log_msg_id}: {e_proc_msg}")
                        logger.exception(f"TRACEBACK for email {log_msg_id} processing failure:")
                                
        except MailboxLoginError as e_login:
            logger.error(f"IMAP LOGIN FAILED: Server '{imap_server}', User '{imap_username}'. Error: {e_login}")
            if hasattr(e_login, 'command_result_text') and e_login.command_result_text:
                logger.error(f"Login error details from imap_tools: {e_login.command_result_text}")
            logger.exception("TRACEBACK for MailboxLoginError:")
        except Exception as e_general_mailbox:
            logger.error(f"General mailbox error (not login specific): {e_general_mailbox}")
            logger.exception("TRACEBACK for general mailbox error:")
        
        logger.info("Email fetch process finished.")


if __name__ == '__main__':
    with app.app_context():
        required_app_configs = [
            'SQLALCHEMY_DATABASE_URI', 'IMAP_SERVER', 'IMAP_USERNAME', 'IMAP_PASSWORD',
            'UPLOAD_FOLDER', 'MAIL_SERVER', 'MAIL_PORT', 'MAIL_DEFAULT_SENDER', 'BASE_URL'
        ]
        missing = [c for c in required_app_configs if not app.config.get(c)]
        if missing:
            logger.critical(f"FATAL (email_processor): Missing essential app.config values: {missing}. "
                            f"Ensure these are set in .env and loaded by app.py's Config. Exiting.")
            sys.exit(1)
        
        if not app.config.get('SERVER_NAME'):
            base_url = app.config['BASE_URL']
            parsed = urlparse(base_url)
            app.config['SERVER_NAME'] = parsed.netloc
            app.config['APPLICATION_ROOT'] = parsed.path.rstrip('/') or '/'
            app.config['PREFERRED_URL_SCHEME'] = parsed.scheme
            logger.info(f"Dynamically configured SERVER_NAME='{app.config['SERVER_NAME']}', "
                        f"ROOT='{app.config['APPLICATION_ROOT']}', SCHEME='{app.config['PREFERRED_URL_SCHEME']}' "
                        f"from BASE_URL='{base_url}' for email_processor script context.")

    fetch_and_process_emails()