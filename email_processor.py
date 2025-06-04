import os
import sys
from datetime import datetime
import logging
import re
import uuid
import time
from urllib.parse import urlparse

# Determine project root and add to sys.path if not already present
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from dotenv import load_dotenv, find_dotenv
dotenv_path = find_dotenv(raise_error_if_not_found=False)
if dotenv_path:
    load_dotenv(dotenv_path, verbose=True, override=True)
    print(f"INFO (email_processor): Loaded .env file from: {dotenv_path}")
else:
    print(f"WARNING (email_processor): .env file not found. Relying on system environment variables or Config defaults.")

from imap_tools import MailBox, AND, MailMessageFlags, MailboxLoginError, MailboxLogoutError, MailboxFolderSelectError, MailMessage
import html2text
from werkzeug.utils import secure_filename

# Import necessary components AFTER dotenv loading
from app import (
    app, db, User, Ticket, Category, Attachment,
    CloudProviderOption, SeverityOption, EnvironmentOption, OrganizationOption,
    mail, allowed_file, log_interaction, trigger_priority_call_alert,
    get_organization_by_email_domain, # Crucial import
    # Import Department if tickets from email should be auto-assigned to a default dept
    Department
)
from flask_mail import Message
from flask import render_template, url_for, current_app # Added current_app for accessing app.config within functions

# Logger setup
logger = logging.getLogger('email_processor')
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def process_email_body_for_ticket(email_body_html, email_body_text):
    """Extracts relevant content from email, attempting to strip signatures/replies."""
    description = ""
    if email_body_text:
        lines = email_body_text.splitlines()
        content_lines = []
        original_line_count = len(lines)
        for line in lines:
            line_lower_stripped = line.lower().strip()
            if line_lower_stripped == '--' or \
               line_lower_stripped.startswith(('from:', 'sent from my', 'on ', '> wrote:', 'regards,', 'best regards,', 'thanks,', 'sincerely,')) or \
               re.match(r'^\s*on\s+.*\s+wrote:$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^sent from my (iphone|android|ipad|samsung|device|mail for windows)', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^-+original\s+message-+$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^\s*>*$', line_lower_stripped) or \
               "________________________________" in line or \
               re.match(r'^Sent from (Outlook|Mail) for.*', line, re.IGNORECASE) or \
               re.match(r'^(\w+\s+){0,5}wrote:$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^(\w{3,}),\s*\w{3,}\s*\d{1,2},\s*\d{4}\s*at\s*\d{1,2}:\d{2}\s*(am|pm)', line_lower_stripped):
                logger.debug(f"Stripping signature/reply line (text): {line[:50]}...")
                break
            if line_lower_stripped.startswith('>'):
                continue
            content_lines.append(line)
        description = "\n".join(content_lines).strip()
        if len(description) > 20 or (description and original_line_count < 10):
            logger.debug(f"Processed text part for description. Length: {len(description)}")
            return description
        else:
            logger.debug(f"Text part processed to short/empty description (length: {len(description)}), will try HTML if available.")
            description = ""

    if email_body_html:
        logger.debug(f"Processing HTML part. Original description from text: '{description[:50]}...'")
        h = html2text.HTML2Text()
        h.ignore_links = False; h.ignore_images = True; h.body_width = 0
        h.unicode_snob = True; h.escape_snob = True
        try:
            text_content = h.handle(email_body_html)
        except Exception as e_html2text:
            logger.error(f"html2text failed to process HTML: {e_html2text}")
            text_content = "(Failed to parse HTML content)"
            return description if description else text_content

        lines = text_content.splitlines()
        content_lines = []
        for line in lines:
            line_lower_stripped = line.lower().strip()
            if line_lower_stripped == '--' or \
               line_lower_stripped.startswith(('from:', 'sent from my', 'on ', '> wrote:', 'regards,', 'best regards,', 'thanks,', 'sincerely,')) or \
               re.match(r'^\s*on\s+.*\s+wrote:$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^sent from my (iphone|android|ipad|samsung|device|mail for windows)', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^-+original\s+message-+$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^\s*>*$', line_lower_stripped) or \
               "________________________________" in line or \
               re.match(r'^Sent from (Outlook|Mail) for.*', line, re.IGNORECASE) or \
               re.match(r'^(\w+\s+){0,5}wrote:$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^(\w{3,}),\s*\w{3,}\s*\d{1,2},\s*\d{4}\s*at\s*\d{1,2}:\d{2}\s*(am|pm)', line_lower_stripped) or \
               re.match(r'^On \w{3}, \w{3} \d{1,2}, \d{4} at \d{1,2}:\d{2} (AM|PM),.*wrote:$', line, re.IGNORECASE):
                logger.debug(f"Stripping signature/reply line (html-text): {line[:50]}...")
                break
            if line_lower_stripped.startswith('>'): continue
            content_lines.append(line)
        html_description = "\n".join(content_lines).strip()
        if html_description:
            logger.debug(f"Processed HTML part for description. Length: {len(html_description)}")
            return html_description
        elif description:
             logger.debug("HTML part empty, falling back to (potentially short) text part description.")
             return description
        else:
            logger.warning("HTML part also processed to empty description.")
            return "(Email body processed to empty or only signature/reply)"

    if description:
        logger.debug(f"Only text part was available, returning it (length: {len(description)}).")
        return description

    logger.warning("No readable content found in email after processing text and HTML parts.")
    return "No readable content found in email."

def infer_details_from_email(subject, body):
    with app.app_context(): # Ensure app context for config and DB access
        default_category_name = current_app.config.get('EMAIL_TICKET_DEFAULT_CATEGORY_NAME', 'General Inquiry')
        default_severity_name = current_app.config.get('EMAIL_TICKET_DEFAULT_SEVERITY_NAME', 'Severity 3 (Medium)')
        details = {
            'category_name': default_category_name,
            'severity_name': default_severity_name,
            'priority': 'Medium', 'cloud_provider': None, 'environment': None
        }
        subject_lower = subject.lower() if subject else ""
        body_lower = body.lower() if body else ""
        full_text_lower = subject_lower + " " + body_lower

        if any(kw in full_text_lower for kw in ['urgent', 'critical', 'outage', 'system down', 'unusable', 'p0', 'p1']):
            details['priority'] = 'Urgent'
            sev_opt = SeverityOption.query.filter(
                (SeverityOption.name.ilike('%Critical%')) | (SeverityOption.name.ilike('%Severity 1%')),
                SeverityOption.is_active.is_(True)
            ).order_by(SeverityOption.order.asc()).first()
            if sev_opt: details['severity_name'] = sev_opt.name
        elif any(kw in full_text_lower for kw in ['high impact', 'major issue', 'significant problem', 'p2']):
            if details['priority'] != 'Urgent': details['priority'] = 'High'
            sev_opt = SeverityOption.query.filter(
                (SeverityOption.name.ilike('%High%')) | (SeverityOption.name.ilike('%Severity 2%')),
                SeverityOption.is_active.is_(True)
            ).order_by(SeverityOption.order.asc()).first()
            if sev_opt and (not details['severity_name'] or 
                            (details['severity_name'] != sev_opt.name and 
                             not ('Critical' in details['severity_name'] or 'Severity 1' in details['severity_name']))):
                details['severity_name'] = sev_opt.name

        category_keywords_map = {
            'Billing Inquiry': ['billing', 'invoice', 'payment', 'subscription', 'charge', 'refund'],
            'Technical Support': ['error', 'bug', 'issue', 'problem', 'fail', 'unable', 'cannot', 'login', 'vpn', 'server', 'api', 'gateway'],
            'Feature Request': ['feature request', 'suggestion', 'enhancement', 'new feature', 'idea for'],
            default_category_name: ['question', 'inquiry', 'how to', 'information'] # Use the default from config
        }
        for cat_name_key, keywords in category_keywords_map.items():
            cat_to_check = cat_name_key # The actual category name to query
            if cat_name_key == default_category_name and default_category_name not in Category.query.with_entities(Category.name).all():
                # If the default from config doesn't exist, use a fallback that likely exists
                # This is a safeguard, ideally default_category_name from config should be valid.
                cat_to_check = 'General Inquiry' # A common fallback

            if any(kw in full_text_lower for kw in keywords):
                cat_opt = Category.query.filter(Category.name == cat_to_check).first()
                if cat_opt:
                    details['category_name'] = cat_opt.name
                    logger.debug(f"Inferred category: {cat_opt.name} based on keywords matching: {[k for k in keywords if k in full_text_lower]}")
                    break
        
        cloud_keywords = {'aws': 'AWS', 'amazon web services': 'AWS', 'ec2': 'AWS', 's3': 'AWS', 'rds': 'AWS', 'vpc': 'AWS',
                          'azure': 'Azure', 'microsoft azure': 'Azure', 'gcp': 'GCP', 'google cloud': 'GCP'}
        for keyword, provider_name_in_db in cloud_keywords.items():
            if keyword in full_text_lower:
                cp_opt = CloudProviderOption.query.filter_by(name=provider_name_in_db, is_active=True).first()
                if cp_opt: details['cloud_provider'] = cp_opt.name; logger.debug(f"Inferred CP: {cp_opt.name} by: {keyword}"); break
        
        env_keywords = {'production': 'Production', 'prod': 'Production', 'live': 'Production', 
                        'staging': 'Staging', 'dev': 'Development', 'test': 'Test', 'qa': 'QA'}
        for keyword, env_name_in_db in env_keywords.items():
            if keyword in full_text_lower:
                env_opt = EnvironmentOption.query.filter_by(name=env_name_in_db, is_active=True).first()
                if env_opt: details['environment'] = env_opt.name; logger.debug(f"Inferred Env: {env_opt.name} by: {keyword}"); break
        
        logger.info(f"Inferred details from email: {details}")
        return details


def run_email_processing_logic(mailbox_instance):
    with app.app_context():
        max_emails_per_run = int(current_app.config.get('IMAP_MAX_EMAILS_PER_RUN', 10))
        logger.info(f"Checking for new/unseen emails (max {max_emails_per_run} per run)...")

        messages_to_process_generator = None
        initial_unseen_check_done = False
        try:
            messages_to_process_generator = mailbox_instance.fetch(AND(seen=False), limit=max_emails_per_run, mark_seen=False, bulk=True)
            initial_unseen_check_done = True
        except Exception as e_fetch_init:
            logger.error(f"Error initially fetching unseen messages: {e_fetch_init}")
            return

        processed_email_count = 0
        processed_uids_this_run = []

        first_message_peek = None
        if messages_to_process_generator:
            try:
                first_message_peek = next(messages_to_process_generator, None)
                if first_message_peek:
                    import itertools
                    messages_to_process_generator = itertools.chain([first_message_peek], messages_to_process_generator)
                    logger.info(f"Found at least one unseen email to process.")
                else:
                    logger.info("No new unseen emails found during this check (generator was empty).")
                    return
            except Exception as e_peek:
                logger.error(f"Error peeking at message generator (or it was empty): {e_peek}")
                return

        for msg_obj in messages_to_process_generator:
            if not msg_obj or not msg_obj.uid:
                logger.warning("Fetched an invalid message object or UID missing, skipping.")
                continue
            uid_str = msg_obj.uid
            processed_uids_this_run.append(uid_str)
            log_msg_id = f"UID {uid_str} (From: {msg_obj.from_}, Subject: '{msg_obj.subject if msg_obj.subject else 'N/A'}')"

            try:
                logger.info(f"Processing email: {log_msg_id}")
                sender_email = msg_obj.from_.lower() if msg_obj.from_ else f"unknown_sender_{uuid.uuid4().hex[:4]}@example.com"
                sender_name_parts = msg_obj.from_values.name if msg_obj.from_values and msg_obj.from_values.name else sender_email.split('@')[0]
                sender_name = re.sub(r'[^\w\s-]', '', sender_name_parts).strip() or sender_email.split('@')[0]

                ticket_title = msg_obj.subject or "No Subject (Email Import)"
                ticket_description = process_email_body_for_ticket(msg_obj.html, msg_obj.text)

                if not ticket_description.strip() or ticket_description == "No readable content found in email." or \
                   (ticket_title == "No Subject (Email Import)" and ticket_description == "No Subject (Email Import)"):
                    logger.warning(f"Skipping ticket creation for {log_msg_id} due to insufficient content.")
                    continue

                user = User.query.filter_by(email=sender_email).first()
                if not user:
                    base_username = re.sub(r'[^a-z0-9_]', '', sender_name.lower().replace(" ", "_"))[:20] or \
                                    sender_email.split('@')[0].split('.')[0][:20] or "emailuser"
                    username_candidate = base_username[:40]
                    count = 1
                    while User.query.filter_by(username=username_candidate).first():
                        username_candidate = f"{base_username[:38]}_{count}"
                        count += 1
                        if count > 100: username_candidate = f"emailuser_{uuid.uuid4().hex[:8]}"; break
                    user = User(username=username_candidate, email=sender_email, role='client')
                    org = get_organization_by_email_domain(sender_email, auto_create=True)
                    if org: user.organization_id = org.id
                    db.session.add(user); db.session.flush()
                    logger.info(f"Created new user '{user.username}' (ID: {user.id}, Org: {org.name if org else 'N/A'}) from email {sender_email}")

                inferred = infer_details_from_email(ticket_title, ticket_description)
                category = Category.query.filter_by(name=inferred['category_name']).first()
                if not category:
                    fallback_cat_name = current_app.config.get('EMAIL_TICKET_DEFAULT_CATEGORY_NAME', 'General Inquiry')
                    category = Category.query.filter_by(name=fallback_cat_name).first()
                    if not category: category = Category.query.order_by(Category.id).first()
                    if category: logger.warning(f"Inferred category '{inferred['category_name']}' not found, used fallback: '{category.name}'")
                    else: logger.error(f"No categories found for email ticket {log_msg_id}. Cannot create."); continue

                severity = SeverityOption.query.filter_by(name=inferred['severity_name'], is_active=True).first()
                if not severity:
                    severity = SeverityOption.query.filter_by(is_active=True).order_by(SeverityOption.order.desc()).first() # Highest order = lowest impact
                    if severity: logger.warning(f"Inferred severity '{inferred['severity_name']}' not found/inactive, used: '{severity.name}'")
                    else: logger.error(f"No active severities found for email ticket {log_msg_id}. Cannot create."); continue

                cloud = CloudProviderOption.query.filter_by(name=inferred['cloud_provider'], is_active=True).first() if inferred['cloud_provider'] else None
                env = EnvironmentOption.query.filter_by(name=inferred['environment'], is_active=True).first() if inferred['environment'] else None
                
                customer_name_for_ticket = user.organization.name if user.organization else user.username

                new_ticket = Ticket(
                    title=ticket_title[:99], description=ticket_description, created_by_id=user.id,
                    status='Open', priority=inferred['priority'], category_id=category.id,
                    organization_id=user.organization_id, # User's org
                    department_id=user.department_id, # User's department (if any, can be None)
                    customer_name=customer_name_for_ticket,
                    cloud_provider=cloud.name if cloud else None,
                    severity=severity.name,
                    environment=env.name if env else None,
                )
                db.session.add(new_ticket); db.session.flush()

                attachments_saved_count = 0
                if msg_obj.attachments:
                    for att_data in msg_obj.attachments:
                        if att_data.filename and allowed_file(att_data.filename):
                            try:
                                safe_fn = secure_filename(att_data.filename)
                                stored_fn = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}_{safe_fn}"
                                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], stored_fn)
                                with open(file_path, 'wb') as f: f.write(att_data.payload)
                                db.session.add(Attachment(
                                    filename=safe_fn, stored_filename=stored_fn, ticket_id=new_ticket.id,
                                    uploaded_by_id=user.id, content_type=att_data.content_type
                                ))
                                attachments_saved_count += 1
                            except Exception as e_att: logger.error(f"Attachment save failed for '{att_data.filename}' on ticket #{new_ticket.id}: {e_att}")
                        elif att_data.filename: logger.warning(f"Skipped attachment (disallowed type): '{att_data.filename}' for ticket #{new_ticket.id}")
                
                log_interaction(new_ticket.id, "EMAIL_TICKET_CREATED", user_id=user.id,
                                details={'subject': new_ticket.title, 'sender': sender_email},
                                timestamp_override=new_ticket.created_at, commit_now=False)
                db.session.commit()
                logger.info(f"Ticket #{new_ticket.id} created for user '{user.username}'. {attachments_saved_count} attachments.")
                processed_email_count += 1

                # Send auto-reply email
                try:
                    if not current_app.config.get('SERVER_NAME'):
                        logger.warning("SERVER_NAME not configured. External URLs in email auto-reply may be incorrect.")
                    
                    # Use app.test_request_context for url_for when outside a Flask request
                    with app.test_request_context(base_url=current_app.config.get('BASE_URL')): # Pass base_url
                        login_url_val = url_for('login', _external=True)
                        ticket_url_val = url_for('view_ticket', ticket_id=new_ticket.id, _external=True)

                    email_subject = f"Ticket Received: #{new_ticket.id} - {new_ticket.title}"
                    email_body = render_template('email/ticket_autoreply.txt',
                                                 ticket=new_ticket, user=user,
                                                 login_url=login_url_val, ticket_url=ticket_url_val)
                    reply_msg = Message(email_subject, recipients=[sender_email], body=email_body)
                    mail.send(reply_msg)
                    logger.info(f"Auto-reply sent to {sender_email} for ticket #{new_ticket.id}")
                except Exception as e_reply:
                    logger.error(f"Failed to send auto-reply for ticket #{new_ticket.id}: {e_reply}")
                    logger.exception("Traceback for auto-reply failure:")
                
                if new_ticket.severity in current_app.config.get('SEVERITIES_FOR_CALL_ALERT', []):
                    logger.info(f"Ticket #{new_ticket.id} has severity '{new_ticket.severity}'. Triggering call alert.")
                    trigger_priority_call_alert(new_ticket, old_severity=None)
                else:
                    logger.info(f"Ticket #{new_ticket.id} severity '{new_ticket.severity}' not in call alert list. Skipping call.")

            except Exception as e_proc_msg_outer:
                logger.error(f"Error processing email {log_msg_id}: {e_proc_msg_outer}")
                logger.exception(f"TRACEBACK for email {log_msg_id} processing failure:")
                db.session.rollback()
        
        if processed_uids_this_run:
            try:
                logger.info(f"Attempting to mark UIDs {processed_uids_this_run} as SEEN.")
                mailbox_instance.flag(processed_uids_this_run, MailMessageFlags.SEEN, True)
                logger.info(f"Successfully marked {len(processed_uids_this_run)} UIDs as SEEN.")
            except Exception as e_flag_batch:
                logger.error(f"Error marking batch of UIDs {processed_uids_this_run} as SEEN: {e_flag_batch}")
        
        if initial_unseen_check_done and not first_message_peek and processed_email_count == 0: pass
        elif initial_unseen_check_done and first_message_peek and processed_email_count == 0:
             logger.info("Unseen emails were found, but no tickets created (check logs for errors/empty bodies).")
        elif processed_email_count > 0:
            logger.info(f"Successfully processed {processed_email_count} email(s) into tickets.")


def imap_idle_listener():
    with app.app_context():
        imap_server = current_app.config.get('IMAP_SERVER')
        imap_username = current_app.config.get('IMAP_USERNAME')
        imap_password = current_app.config.get('IMAP_PASSWORD')
        imap_folder = current_app.config.get('IMAP_MAILBOX_FOLDER', 'INBOX')
        idle_timeout_seconds = int(current_app.config.get('IMAP_IDLE_TIMEOUT_SECONDS', 10 * 60))
        periodic_check_interval = int(current_app.config.get('IMAP_PERIODIC_CHECK_SECONDS', 2 * 60))
        if not all([imap_server, imap_username, imap_password]):
            logger.critical("CRITICAL: IMAP config NOT SET. IDLE listener cannot start.")
            return

    last_periodic_check = time.time()
    while True:
        try:
            logger.info(f"Attempting to connect to IMAP: {imap_server}, User: {imap_username}, Folder: {imap_folder}")
            with MailBox(imap_server).login(imap_username, imap_password, initial_folder=imap_folder) as mailbox:
                logger.info(f"Successfully connected to IMAP. Current folder: '{mailbox.folder.get()}'")
                run_email_processing_logic(mailbox) # Initial check
                last_periodic_check = time.time()
                logger.info(f"Entering IDLE mode (timeout: {idle_timeout_seconds}s)...")
                while True:
                    try:
                        effective_idle_timeout = min(idle_timeout_seconds, (periodic_check_interval // 2) if periodic_check_interval > 60 else 30)
                        logger.debug(f"IDLE wait with timeout: {effective_idle_timeout}s")
                        idle_responses = mailbox.idle.wait(timeout=effective_idle_timeout)
                        if idle_responses:
                            logger.info(f"IDLE responses: {idle_responses}. Triggering email processing.")
                            run_email_processing_logic(mailbox)
                            last_periodic_check = time.time()
                        else: 
                            logger.debug(f"IDLE timed out after {effective_idle_timeout}s.")
                        
                        if time.time() - last_periodic_check >= periodic_check_interval:
                            logger.info(f"Performing periodic email check (interval: {periodic_check_interval}s).")
                            run_email_processing_logic(mailbox)
                            last_periodic_check = time.time()
                    except (MailboxLogoutError, MailboxFolderSelectError) as e_mailbox_state:
                        logger.warning(f"Mailbox state error during IDLE: {e_mailbox_state}. Reconnecting.")
                        break 
                    except Exception as e_idle_inner:
                        logger.error(f"Unexpected error in IDLE loop: {e_idle_inner}")
                        logger.exception("Traceback for inner IDLE loop error:")
                        time.sleep(15) 
                        err_str_lower = str(e_idle_inner).lower()
                        if any(sub in err_str_lower for sub in ["socket error", "connection broken", "connection reset", "timeout", "aborted"]):
                            logger.error("Suspected connection loss/IMAP timeout, breaking to reconnect.")
                            break 
        except MailboxLoginError as e_login:
            logger.critical(f"IMAP LOGIN FAILED: {e_login}. Retrying in 60s.")
            time.sleep(60)
        except ConnectionRefusedError as e_conn_refused:
            logger.error(f"IMAP Connection Refused for {imap_server}. Retrying in 5m.")
            time.sleep(5 * 60)
        except Exception as e_outer: 
            logger.error(f"Outer loop error: {e_outer}")
            logger.exception("Traceback for outer loop error:")
            logger.info("Attempting to reconnect in 60s...")
            time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Email processor (IDLE listener) stopped by user.")
            break 
    logger.info("Email processor (IDLE listener) has shut down.")

if __name__ == '__main__':
    logger.info("Initializing email_processor.py script...")
    with app.app_context():
        required_configs = [
            'SQLALCHEMY_DATABASE_URI', 'IMAP_SERVER', 'IMAP_USERNAME', 'IMAP_PASSWORD',
            'UPLOAD_FOLDER', 'MAIL_SERVER', 'MAIL_PORT', 'MAIL_DEFAULT_SENDER'
        ]
        # SERVER_NAME and BASE_URL logic for url_for(_external=True)
        if not current_app.config.get('SERVER_NAME') and current_app.config.get('BASE_URL'):
            parsed_url = urlparse(current_app.config['BASE_URL'])
            current_app.config['SERVER_NAME'] = parsed_url.netloc or 'localhost:5000'
            logger.info(f"Dynamically configured SERVER_NAME='{current_app.config['SERVER_NAME']}' from BASE_URL.")
        elif not current_app.config.get('SERVER_NAME'):
            required_configs.append('BASE_URL') # Indicate one is needed for external URLs
            logger.warning("SERVER_NAME not set and BASE_URL also not set/unparsable. External URLs in emails might be incorrect.")

        missing = [c for c in required_configs if not current_app.config.get(c)]
        # Adjust missing check if SERVER_NAME is critical and not derivable
        if 'SERVER_NAME' in missing and 'BASE_URL' in missing and current_app.config.get('BASE_URL') is None:
             # If SERVER_NAME is expected but not found, and BASE_URL also not found to derive it
             pass # The general missing_configs check will catch this if SERVER_NAME was added to required_configs
        elif 'SERVER_NAME' in missing and not current_app.config.get('SERVER_NAME'):
             # If BASE_URL was there but SERVER_NAME still couldn't be set
             logger.critical("FATAL: SERVER_NAME missing and could not be derived from BASE_URL. External URLs will fail.")
             missing.append("SERVER_NAME (undetermined)") # Make it explicit for exit message

        if any(m for m in missing if m not in ['BASE_URL'] or (m == 'BASE_URL' and not current_app.config.get('SERVER_NAME'))):
             # Exit if essential configs are missing (excluding BASE_URL if SERVER_NAME is set)
            final_missing = [m for m in missing if not (m == 'BASE_URL' and current_app.config.get('SERVER_NAME'))]
            if final_missing:
                logger.critical(f"FATAL: Missing essential app.config values: {final_missing}. Exiting.")
                sys.exit(1)
        
        if not current_app.config.get('MAIL_USERNAME') or not current_app.config.get('MAIL_PASSWORD'):
            logger.warning("MAIL_USERNAME or MAIL_PASSWORD not configured. Auto-reply emails will fail.")

    imap_idle_listener()