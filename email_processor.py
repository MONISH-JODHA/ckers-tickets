import os
import sys
from datetime import datetime
import logging
import re
import uuid
import time 
from urllib.parse import urlparse

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from dotenv import load_dotenv, find_dotenv
dotenv_path = find_dotenv(raise_error_if_not_found=False)
if dotenv_path:
    load_dotenv(dotenv_path, verbose=True, override=True)
    print(f"INFO (email_processor): Loaded .env file from: {dotenv_path}")
else:
    print(f"WARNING (email_processor): .env file not found. Relying on system environment variables or Config defaults.")


from imap_tools import MailBox, AND, NOT, MailMessageFlags, MailboxLoginError, MailboxLogoutError, MailboxFolderSelectError, MailMessage
import html2text
from werkzeug.utils import secure_filename

# Import necessary components AFTER dotenv loading
from app import app, db, User, Ticket, Category, Attachment, CloudProviderOption, SeverityOption, EnvironmentOption, mail, allowed_file, log_interaction, trigger_priority_call_alert
from flask_mail import Message
from flask import render_template, url_for


logger = logging.getLogger('email_processor') 
logger.setLevel(logging.INFO) # Set to DEBUG for more verbosity if needed
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s') # Added module/lineno
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def process_email_body_for_ticket(email_body_html, email_body_text):
    """Extracts relevant content from email, attempting to strip signatures/replies."""
    description = ""
    
    # Prioritize text part if available and seems substantial
    if email_body_text:
        lines = email_body_text.splitlines()
        content_lines = []
        original_line_count = len(lines)
        for line in lines:
            line_lower_stripped = line.lower().strip()
            # Enhanced signature/reply stripping patterns
            if line_lower_stripped == '--' or \
               line_lower_stripped.startswith(('from:', 'sent from my', 'on ', '> wrote:', 'regards,', 'best regards,', 'thanks,', 'sincerely,')) or \
               re.match(r'^\s*on\s+.*\s+wrote:$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^sent from my (iphone|android|ipad|samsung|device|mail for windows)', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^-+original\s+message-+$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^\s*>*$', line_lower_stripped) or \
               "________________________________" in line or \
               re.match(r'^Sent from (Outlook|Mail) for.*', line, re.IGNORECASE) or \
               re.match(r'^(\w+\s+){0,5}wrote:$', line_lower_stripped, re.IGNORECASE) or \
               re.match(r'^(\w{3,}),\s*\w{3,}\s*\d{1,2},\s*\d{4}\s*at\s*\d{1,2}:\d{2}\s*(am|pm)', line_lower_stripped): # Common date line "On Mon, Jan 1, 2024 at 10:00 AM"
                logger.debug(f"Stripping signature/reply line (text): {line[:50]}...")
                break 
            if line_lower_stripped.startswith('>'): # Quoted reply
                continue
            content_lines.append(line)
        
        description = "\n".join(content_lines).strip()
        if len(description) > 20 or (description and original_line_count < 10): # Heuristic: if short email, probably not just signature
            logger.debug(f"Processed text part for description. Length: {len(description)}")
            return description
        else:
            logger.debug(f"Text part processed to short/empty description (length: {len(description)}), will try HTML if available.")
            description = "" # Reset if text part was likely just a signature

    if email_body_html:
        logger.debug(f"Processing HTML part. Original description from text: '{description[:50]}...'")
        h = html2text.HTML2Text()
        h.ignore_links = False 
        h.ignore_images = True 
        h.body_width = 0 
        h.unicode_snob = True 
        h.escape_snob = True  

        try:
            text_content = h.handle(email_body_html)
        except Exception as e_html2text:
            logger.error(f"html2text failed to process HTML: {e_html2text}")
            text_content = "(Failed to parse HTML content)"
            if description: return description # Return text part if HTML failed
            return text_content


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
               re.match(r'^(\w{3,}),\s*\w{3,}\s*\d{1,2},\s*\d{4}\s*at\s*\d{1,2}:\d{2}\s*(am|pm)', line_lower_stripped):
                logger.debug(f"Stripping signature/reply line (html-text): {line[:50]}...")
                break
            if line_lower_stripped.startswith('>'):
                continue
            if re.match(r'^On \w{3}, \w{3} \d{1,2}, \d{4} at \d{1,2}:\d{2} (AM|PM),.*wrote:$', line, re.IGNORECASE):
                break
            content_lines.append(line)

        html_description = "\n".join(content_lines).strip()
        if html_description:
            logger.debug(f"Processed HTML part for description. Length: {len(html_description)}")
            return html_description
        elif description: # If HTML part is empty but text part had something (even if short)
             logger.debug("HTML part empty, falling back to (potentially short) text part description.")
             return description
        else:
            logger.warning("HTML part also processed to empty description.")
            return "(Email body processed to empty or only signature/reply)"
        
    if description: # Only text part was available and it was short/empty initially
        logger.debug(f"Only text part was available, returning it (length: {len(description)}).")
        return description

    logger.warning("No readable content found in email after processing text and HTML parts.")
    return "No readable content found in email."


def infer_details_from_email(subject, body):
    with app.app_context(): 
        details = {
            'category_name': app.config.get('EMAIL_TICKET_DEFAULT_CATEGORY_NAME', 'General Inquiry'),
            'severity_name': app.config.get('EMAIL_TICKET_DEFAULT_SEVERITY_NAME', 'Severity 3 (Medium)'),
            'priority': 'Medium', 'cloud_provider': None, 'environment': None
        }
        subject_lower = subject.lower() if subject else ""; 
        body_lower = body.lower() if body else ""
        full_text_lower = subject_lower + " " + body_lower

        # Severity and Priority Inference
        if any(kw in full_text_lower for kw in ['urgent', 'critical', 'outage', 'system down', 'unusable', 'p0', 'p1']):
            details['priority'] = 'Urgent'
            sev_opt = SeverityOption.query.filter(
                (SeverityOption.name.ilike('%Critical%')) | (SeverityOption.name.ilike('%Severity 1%')),
                SeverityOption.is_active == True 
            ).order_by(SeverityOption.order.asc()).first()
            if sev_opt: details['severity_name'] = sev_opt.name
        elif any(kw in full_text_lower for kw in ['high impact', 'major issue', 'significant problem', 'p2']):
            if details['priority'] != 'Urgent': details['priority'] = 'High'
            sev_opt = SeverityOption.query.filter(
                (SeverityOption.name.ilike('%High%')) | (SeverityOption.name.ilike('%Severity 2%')),
                SeverityOption.is_active == True
            ).order_by(SeverityOption.order.asc()).first()
            if sev_opt and details['severity_name'] != 'Severity 1 (Critical)':
                details['severity_name'] = sev_opt.name
        
        # Category Inference
        category_keywords_map = {
            'Billing Inquiry': ['billing', 'invoice', 'payment', 'subscription', 'charge', 'refund'],
            'Technical Support': ['error', 'bug', 'issue', 'problem', 'fail', 'unable', 'cannot', 'login issue'],
            'Feature Request': ['feature request', 'suggestion', 'enhancement', 'new feature', 'idea for'],
            'General Question': ['question', 'inquiry', 'how to', 'information'] # More generic, lower precedence
        }
        # Iterate with some precedence (e.g., more specific categories first)
        for cat_name, keywords in category_keywords_map.items():
            if any(kw in full_text_lower for kw in keywords):
                cat_opt = Category.query.filter(Category.name == cat_name).first()
                if cat_opt: 
                    details['category_name'] = cat_opt.name
                    logger.debug(f"Inferred category: {cat_name} based on keywords: {keywords}")
                    break # Stop after first match based on precedence
        
        # Cloud Provider Inference
        cloud_keywords = {'aws': 'AWS', 'amazon web services': 'AWS', 'ec2': 'AWS', 's3': 'AWS', 
                          'azure': 'Azure', 'microsoft azure': 'Azure', 'gcp': 'GCP', 'google cloud': 'GCP'}
        for keyword, provider_name_in_db in cloud_keywords.items():
            if keyword in full_text_lower:
                cp_opt = CloudProviderOption.query.filter_by(name=provider_name_in_db, is_active=True).first()
                if cp_opt: 
                    details['cloud_provider'] = cp_opt.name
                    logger.debug(f"Inferred cloud provider: {provider_name_in_db} based on keyword: {keyword}")
                    break
        
        # Environment Inference
        env_keywords = {'production': 'Production', 'prod': 'Production', 'live': 'Production', 
                        'staging': 'Staging', 'stage': 'Staging', 'pre-prod': 'Staging',
                        'development': 'Development', 'dev': 'Development', 
                        'test': 'Test', 'qa': 'QA', 'uat': 'UAT'}
        for keyword, env_name_in_db in env_keywords.items():
            if keyword in full_text_lower:
                env_opt = EnvironmentOption.query.filter_by(name=env_name_in_db, is_active=True).first()
                if env_opt: 
                    details['environment'] = env_opt.name
                    logger.debug(f"Inferred environment: {env_name_in_db} based on keyword: {keyword}")
                    break
        logger.info(f"Inferred details from email: {details}")
        return details


# ... (imports and other functions as before, including the corrected process_email_body_for_ticket and infer_details_from_email) ...

def run_email_processing_logic(mailbox_instance):
    with app.app_context(): 
        max_emails_per_run = int(app.config.get('IMAP_MAX_EMAILS_PER_RUN', 10))
        logger.info(f"Checking for new/unseen emails (max {max_emails_per_run} per run)...")
        
        messages_to_process_generator = None
        initial_unseen_check_done = False # Flag to know if we even tried to fetch
        
        try:
            # Fetch unseen messages directly as MailMessage objects
            messages_to_process_generator = mailbox_instance.fetch(AND(seen=False), limit=max_emails_per_run, mark_seen=False, bulk=True)
            initial_unseen_check_done = True # We attempted the fetch
        except Exception as e_fetch_init:
            logger.error(f"Error initially fetching unseen messages: {e_fetch_init}")
            return # Exit if initial fetch fails

        processed_email_count = 0
        processed_uids_this_run = [] # Keep track of UIDs we attempt to process from the generator

        # Check if the generator is empty without consuming it, if possible, or just proceed
        # A simple way is to try to get the first item and then chain it back if needed,
        # or just rely on the loop not running if it's empty.

        first_message_peek = None
        if messages_to_process_generator:
            try:
                # Peek at the first message to see if there's anything
                first_message_peek = next(messages_to_process_generator, None)
                if first_message_peek:
                    # If we got one, put it back into a new generator chain
                    import itertools
                    messages_to_process_generator = itertools.chain([first_message_peek], messages_to_process_generator)
                    logger.info(f"Found at least one unseen email to process.")
                else:
                    logger.info("No new unseen emails found during this check (generator was empty).")
                    return # Exit if no messages
            except Exception as e_peek:
                logger.error(f"Error peeking at message generator: {e_peek}")
                return # Exit if peeking causes issues


        for msg_obj in messages_to_process_generator:
            if not msg_obj or not msg_obj.uid:
                logger.warning("Fetched an invalid message object or UID missing, skipping.")
                continue

            uid_str = msg_obj.uid 
            processed_uids_this_run.append(uid_str) # Add UID as soon as we get a valid msg_obj
            log_msg_id_prefix = f"UID {uid_str} in folder '{mailbox_instance.folder.get()}'"
            log_msg_id = f"UID {uid_str} (From: {msg_obj.from_}, Subject: '{msg_obj.subject if msg_obj.subject else 'N/A'}')" 
            
            try:
                logger.info(f"Processing email: {log_msg_id}")

                # ... (rest of the processing logic for a single email: sender, title, description, user creation, inference, ticket creation, attachments, logging, auto-reply, Twilio call) ...
                # This part is identical to the previous version of this function
                sender_email = msg_obj.from_.lower() if msg_obj.from_ else f"unknown_sender_{uuid.uuid4().hex[:4]}@example.com"
                sender_name_parts = msg_obj.from_values.name if msg_obj.from_values and msg_obj.from_values.name else sender_email.split('@')[0]
                sender_name = re.sub(r'[^\w\s-]', '', sender_name_parts).strip() or sender_email.split('@')[0]

                ticket_title = msg_obj.subject or "No Subject (Email Import)"
                ticket_description = process_email_body_for_ticket(msg_obj.html, msg_obj.text)
                
                if not ticket_description.strip() or ticket_description.startswith("(Email body processed to empty"):
                    logger.warning(f"Ticket description for {log_msg_id} is empty or default. Using subject as description if available and not default.")
                    ticket_description = ticket_title if ticket_title and ticket_title != "No Subject (Email Import)" else ticket_description

                user = User.query.filter_by(email=sender_email).first()
                if not user:
                    base_username = re.sub(r'[^a-z0-9_]', '', sender_name.lower().replace(" ", "_"))[:20] or \
                                    sender_email.split('@')[0].split('.')[0][:20] or "emailuser"
                    username_candidate = base_username[:40] 
                    count = 1
                    while User.query.filter_by(username=username_candidate).first():
                        username_candidate = f"{base_username[:38]}_{count}" 
                        count += 1
                        if count > 100: 
                            logger.error(f"Could not generate unique username for {sender_email} after 100 attempts.")
                            username_candidate = f"emailuser_{uuid.uuid4().hex[:8]}" 
                            break
                    user = User(username=username_candidate, email=sender_email, role='client')
                    org = get_organization_by_email_domain(sender_email, auto_create=True)
                    if org: user.organization_id = org.id
                    db.session.add(user)
                    db.session.flush() 
                    logger.info(f"Created new user '{user.username}' (ID: {user.id}, Org: {org.name if org else 'N/A'}) from email {sender_email}")

                inferred = infer_details_from_email(ticket_title, ticket_description) 
                category = Category.query.filter_by(name=inferred['category_name']).first()
                if not category:
                    category = Category.query.order_by(Category.id).first()
                    if category: logger.warning(f"Default category '{inferred['category_name']}' not found, used first available: '{category.name}'")
                    else: logger.error("No categories found in DB for email ticket.");
                
                severity = SeverityOption.query.filter_by(name=inferred['severity_name'], is_active=True).first()
                if not severity:
                    severity = SeverityOption.query.filter_by(is_active=True).order_by(SeverityOption.order.desc()).first() 
                    if severity: logger.warning(f"Default severity '{inferred['severity_name']}' not found/inactive, used: '{severity.name}'")
                    else: logger.error("No active severities found in DB for email ticket.");

                cloud = CloudProviderOption.query.filter_by(name=inferred['cloud_provider'], is_active=True).first() if inferred['cloud_provider'] else None
                env = EnvironmentOption.query.filter_by(name=inferred['environment'], is_active=True).first() if inferred['environment'] else None

                if not (category and severity):
                    logger.error(f"Cannot create ticket for {log_msg_id}. Missing critical category or severity after fallbacks.")
                    # No db.session.commit() here, so no ticket is created. Email will be marked seen later.
                    continue # Skip to next email


                new_ticket = Ticket(
                    title=ticket_title[:99], description=ticket_description, created_by_id=user.id,
                    status='Open', priority=inferred['priority'], 
                    category_id=category.id,
                    cloud_provider=cloud.name if cloud else None, 
                    severity=severity.name,
                    environment=env.name if env else None,
                    customer_name=user.organization.name if user.organization else user.username 
                )
                db.session.add(new_ticket)
                db.session.flush() 

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
                            except Exception as e_att:
                                logger.error(f"Attachment save failed for '{att.filename}' on ticket #{new_ticket.id}: {e_att}")
                        elif att.filename:
                            logger.warning(f"Skipped attachment (disallowed type): '{att.filename}' for ticket #{new_ticket.id}")
                
                log_interaction(new_ticket.id, "EMAIL_TICKET_CREATED", user_id=user.id, 
                                details={'subject': new_ticket.title, 'sender': sender_email},
                                timestamp_override=new_ticket.created_at, commit_now=False)

                db.session.commit() 
                logger.info(f"Ticket #{new_ticket.id} created and committed for user '{user.username}'. {attachments_saved_count} attachments.")
                processed_email_count += 1

                try:
                    if not app.config.get('SERVER_NAME'):
                        logger.warning("SERVER_NAME not configured. External URLs in email auto-reply may be incorrect.")
                    
                    with app.test_request_context():
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
                
                if new_ticket.severity in app.config.get('SEVERITIES_FOR_CALL_ALERT', []):
                    logger.info(f"Ticket #{new_ticket.id} has high priority severity '{new_ticket.severity}'. Triggering call alert.")
                    trigger_priority_call_alert(new_ticket, old_severity=None)
                else:
                    logger.info(f"Ticket #{new_ticket.id} severity '{new_ticket.severity}' not in call alert list. Skipping call.")

            except Exception as e_proc_msg_outer:
                logger.error(f"Error processing email {log_msg_id}: {e_proc_msg_outer}") # Use more specific log_msg_id
                logger.exception(f"TRACEBACK for email {log_msg_id} processing failure:")
                db.session.rollback()
        
        # After processing the batch (or attempting to), mark them as SEEN
        if processed_uids_this_run: # If we actually iterated over any UIDs
            try:
                logger.info(f"Attempting to mark UIDs {processed_uids_this_run} as SEEN.")
                mailbox_instance.flag(processed_uids_this_run, MailMessageFlags.SEEN, True)
                logger.info(f"Successfully marked {len(processed_uids_this_run)} emails (or attempted UIDs) as SEEN.")
            except Exception as e_flag_batch:
                logger.error(f"Error marking batch of UIDs {processed_uids_this_run} as SEEN: {e_flag_batch}")
        
        # Corrected logging for when no emails were converted to tickets
        if initial_unseen_check_done and not first_message_peek and processed_email_count == 0 : # No messages in generator initially
            pass # Already logged "No new unseen emails found..."
        elif initial_unseen_check_done and first_message_peek and processed_email_count == 0: # Messages were there, but none processed
             logger.info("Unseen emails were found, but no emails were successfully converted to tickets in this run.")
        elif processed_email_count > 0:
            logger.info(f"Successfully processed {processed_email_count} email(s) into tickets.")


def imap_idle_listener():
    with app.app_context():
        imap_server = app.config.get('IMAP_SERVER')
        imap_username = app.config.get('IMAP_USERNAME')
        imap_password = app.config.get('IMAP_PASSWORD')
        imap_folder = app.config.get('IMAP_MAILBOX_FOLDER', 'INBOX')
        idle_timeout_seconds = int(app.config.get('IMAP_IDLE_TIMEOUT_SECONDS', 10 * 60)) # Reduced default for testing
        periodic_check_interval = int(app.config.get('IMAP_PERIODIC_CHECK_SECONDS', 2 * 60)) # Reduced default

        if not all([imap_server, imap_username, imap_password]):
            logger.critical("CRITICAL: IMAP server, username, or password NOT SET. IDLE listener cannot start.")
            return

    last_periodic_check = time.time()

    while True: 
        try:
            logger.info(f"Attempting to connect to IMAP: {imap_server}, User: {imap_username}, Folder: {imap_folder}")
            with MailBox(imap_server).login(imap_username, imap_password, initial_folder=imap_folder) as mailbox:
                logger.info(f"Successfully connected to IMAP. Current folder: '{mailbox.folder.get()}'")
                
                logger.info("Performing initial email processing upon connection...")
                run_email_processing_logic(mailbox)
                last_periodic_check = time.time() 

                logger.info(f"Entering IDLE mode (timeout: {idle_timeout_seconds}s). Waiting for new mail...")
                while True: 
                    try:
                        effective_idle_timeout = min(idle_timeout_seconds, periodic_check_interval // 2 or 30) # Shortened for responsiveness
                        logger.debug(f"IDLE wait with timeout: {effective_idle_timeout}s")
                        idle_responses = mailbox.idle.wait(timeout=effective_idle_timeout)
                        
                        if idle_responses:
                            logger.info(f"IDLE responses received: {idle_responses}. Triggering email processing.")
                            run_email_processing_logic(mailbox)
                            last_periodic_check = time.time()
                        else: 
                            logger.debug(f"IDLE timed out after {effective_idle_timeout}s. No specific server messages.")
                        
                        current_time = time.time()
                        if current_time - last_periodic_check > periodic_check_interval:
                            logger.info(f"Performing periodic email check (interval: {periodic_check_interval}s).")
                            run_email_processing_logic(mailbox) # This will fetch based on SEEN=False
                            last_periodic_check = current_time 
                        
                    except MailboxLogoutError as e_logout_idle: 
                        logger.warning(f"MailboxLogoutError during IDLE: {e_logout_idle}. Will attempt to reconnect.")
                        break 
                    except MailboxFolderSelectError as e_folder_idle:
                        logger.error(f"MailboxFolderSelectError during IDLE (folder might have been deleted/renamed?): {e_folder_idle}. Reconnecting.")
                        break  
                    except Exception as e_idle_inner:
                        logger.error(f"Unexpected error within IDLE wait/process loop: {e_idle_inner}")
                        logger.exception("Traceback for inner IDLE loop error:")
                        time.sleep(15) 
                        if "socket error" in str(e_idle_inner).lower() or \
                           "connection broken" in str(e_idle_inner).lower() or \
                           "connection reset" in str(e_idle_inner).lower() or \
                           "timeout" in str(e_idle_inner).lower(): # Catch more connection issues
                            logger.error("Suspected connection loss or IMAP command timeout, breaking to reconnect.")
                            break 

        except MailboxLoginError as e_login:
            logger.critical(f"IMAP LOGIN FAILED: Server '{imap_server}', User '{imap_username}'. Error: {e_login}")
            logger.info("Will retry login after 60 seconds.")
            time.sleep(60)
        except ConnectionRefusedError as e_conn_refused:
            logger.error(f"IMAP Connection Refused for {imap_server}. Server down or incorrect port? Retrying in 5 minutes.")
            time.sleep(5 * 60)
        except Exception as e_outer: 
            logger.error(f"Outer loop connection/mailbox error: {e_outer}")
            logger.exception("Traceback for outer loop error:")
            logger.info("Attempting to reconnect in 60 seconds...")
            time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Email processor (IDLE listener) stopped by user (KeyboardInterrupt).")
            break 

    logger.info("Email processor (IDLE listener) has shut down.")


if __name__ == '__main__':
    logger.info("Initializing email_processor.py script...")
    with app.app_context():
        required_app_configs = [
            'SQLALCHEMY_DATABASE_URI', 'IMAP_SERVER', 'IMAP_USERNAME', 'IMAP_PASSWORD',
            'UPLOAD_FOLDER', 'MAIL_SERVER', 'MAIL_PORT', 'MAIL_DEFAULT_SENDER', 'BASE_URL'
        ]
        if not app.config.get('SERVER_NAME') and app.config.get('BASE_URL'):
            base_url = app.config['BASE_URL']
            parsed = urlparse(base_url)
            app.config['SERVER_NAME'] = parsed.netloc or 'localhost:5000' 
            logger.info(f"Dynamically configured SERVER_NAME='{app.config['SERVER_NAME']}' from BASE_URL='{base_url}' for script context.")
        elif not app.config.get('SERVER_NAME'):
            logger.warning("SERVER_NAME not set and BASE_URL also not set or unparsable. External URLs in emails may be incorrect.")


        missing = [c for c in required_app_configs if not app.config.get(c)]
        if missing:
            logger.critical(f"FATAL (email_processor): Missing essential app.config values: {missing}. "
                            f"Ensure these are set via .env and loaded by app.py's Config, or set directly. Exiting.")
            sys.exit(1)
        
        if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
            logger.warning("MAIL_USERNAME or MAIL_PASSWORD not configured. Auto-reply emails will fail.")

    imap_idle_listener()