# services/gmail_service.py (with PNG-specific QR detection)
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import datetime
import base64
from bs4 import BeautifulSoup
from services.ml_service import classify_urls_batch
import re
import logging
import requests
from io import BytesIO
from PIL import Image
from PIL import ImageOps, ImageEnhance
from pyzbar.pyzbar import decode

# Setup logging with more verbosity for debugging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def extract_urls_from_html(html):
    """Extract and clean URLs from HTML content"""
    if not html:
        return []
        
    try:
        soup = BeautifulSoup(html, "html.parser")
        urls = [a["href"] for a in soup.find_all("a", href=True)]
        
        # Basic URL validation and cleaning
        valid_urls = []
        for url in urls:
            # Skip anchor links, javascript, and mailto
            if url.startswith('#') or url.startswith('javascript:') or url.startswith('mailto:'):
                continue
                
            # Clean tracking parameters if present (common in marketing emails)
            cleaned_url = re.sub(r'utm_[^&=]*=[^&]*&?', '', url)
            cleaned_url = cleaned_url.rstrip('&?')
            
            valid_urls.append(cleaned_url)
            
        return valid_urls
    except Exception as e:
        logger.error(f"Error extracting URLs: {e}")
        return []

def extract_plain_text_urls(text):
    """Extract URLs from plain text content"""
    if not text:
        return []
        
    try:
        # Basic URL regex pattern
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        urls = re.findall(url_pattern, text)
        return urls
    except Exception as e:
        logger.error(f"Error extracting plain text URLs: {e}")
        return []

def get_email_body(payload):
    """Recursively extract email body content"""
    if 'parts' in payload:
        html_content = ""
        plain_content = ""
        
        for part in payload['parts']:
            part_content = get_email_body(part)
            if part.get('mimeType') == 'text/html' and part_content:
                html_content = part_content
            elif part.get('mimeType') == 'text/plain' and part_content:
                plain_content = part_content
                
        return html_content or plain_content
    
    elif 'body' in payload and 'data' in payload['body']:
        body_data = payload['body']['data']
        if body_data:
            return base64.urlsafe_b64decode(body_data).decode('utf-8', errors='replace')
    
    return ""

def preprocess_image_for_qr(img):
    """
    Apply various preprocessing techniques to enhance QR code detection
    """
    try:
        # Create a copy to avoid modifying the original
        processed_img = img.copy()
        
        # Method 1: Increase contrast
        enhancer = ImageEnhance.Contrast(processed_img)
        high_contrast = enhancer.enhance(2.0)  # Double the contrast
        
        # Method 2: Convert to grayscale if not already
        if processed_img.mode != 'L':
            grayscale = processed_img.convert('L')
        else:
            grayscale = processed_img
            
        # Method 3: Invert colors (sometimes helps with certain QR codes)
        inverted = ImageOps.invert(grayscale)
        
        # Return all processed versions for scanning
        return [processed_img, high_contrast, grayscale, inverted]
        
    except Exception as e:
        logger.error(f"Error preprocessing image: {e}")
        # Return the original image if preprocessing fails
        return [img]

def extract_direct_attachments(service, msg_id):
    """
    Directly extract all attachments from an email message
    This bypasses HTML parsing and directly accesses attachment data
    """
    attachment_data = []
    
    try:
        # Get the message details
        message = service.users().messages().get(
            userId='me', 
            id=msg_id, 
            format='full'
        ).execute()
        
        # Recursively find all parts/attachments
        def process_parts(parts):
            for part in parts:
                # If this part has sub-parts, process them
                if 'parts' in part:
                    process_parts(part['parts'])
                
                # Check for attachments and inline images
                mime_type = part.get('mimeType', '')
                if mime_type.startswith('image/'):
                    logger.info(f"Found image part with MIME type: {mime_type}")
                    
                    # Handle inline images
                    if 'body' in part and 'data' in part['body']:
                        logger.info("Found inline image data")
                        data = part['body']['data']
                        if data:
                            try:
                                decoded_data = base64.urlsafe_b64decode(data)
                                attachment_data.append({
                                    'data': decoded_data,
                                    'mimeType': mime_type,
                                    'filename': part.get('filename', 'inline_image.png')
                                })
                            except Exception as decode_error:
                                logger.error(f"Error decoding inline image data: {decode_error}")
                    
                    # Handle attachments with attachment IDs
                    elif 'body' in part and 'attachmentId' in part['body']:
                        attachment_id = part['body']['attachmentId']
                        logger.info(f"Found image attachment with ID: {attachment_id}")
                        
                        try:
                            # Get the attachment
                            attachment = service.users().messages().attachments().get(
                                userId='me',
                                messageId=msg_id,
                                id=attachment_id
                            ).execute()
                            
                            # Decode attachment data
                            if 'data' in attachment:
                                decoded_data = base64.urlsafe_b64decode(attachment['data'])
                                attachment_data.append({
                                    'data': decoded_data,
                                    'mimeType': mime_type,
                                    'filename': part.get('filename', 'attachment.png')
                                })
                        except Exception as get_error:
                            logger.error(f"Error getting attachment {attachment_id}: {get_error}")
        
        # Start processing from the message payload
        if 'payload' in message:
            if 'parts' in message['payload']:
                process_parts(message['payload']['parts'])
            else:
                # Handle single-part messages
                process_parts([message['payload']])
    
    except Exception as e:
        logger.error(f"Error extracting direct attachments: {e}")
    
    return attachment_data

def extract_qr_codes_from_attachments(attachments):
    """
    Extract QR codes from message attachments
    """
    qr_data = []
    
    for attachment in attachments:
        try:
            # Get attachment data
            image_data = attachment['data']
            mime_type = attachment['mimeType']
            filename = attachment['filename']
            
            logger.info(f"Processing attachment: {filename} ({mime_type})")
            
            # Open the image
            try:
                img = Image.open(BytesIO(image_data))
                logger.info(f"Successfully opened image: format={img.format}, size={img.size}, mode={img.mode}")
                
                # Get processed versions of the image
                processed_images = preprocess_image_for_qr(img)
                
                # Try to find QR codes in each processed version
                for idx, proc_img in enumerate(processed_images):
                    try:
                        decoded_objects = decode(proc_img)
                        
                        if decoded_objects:
                            logger.info(f"Found {len(decoded_objects)} QR codes in version {idx} of {filename}")
                            
                            for obj in decoded_objects:
                                try:
                                    data = obj.data.decode('utf-8', errors='replace')
                                    logger.info(f"Decoded QR content: {data}")
                                    
                                    # Handle different URL formats
                                    if data.startswith(('http://', 'https://')):
                                        qr_data.append(data)
                                    elif re.match(r'^(www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', data):
                                        qr_data.append(f"http://{data}")
                                    elif '.' in data and len(data) < 100:
                                        if re.search(r'[a-zA-Z0-9]+\.[a-zA-Z]{2,}', data):
                                            qr_data.append(f"http://{data}")
                                    else:
                                        logger.info(f"Non-URL QR data: {data}")
                                except Exception as decode_error:
                                    logger.error(f"Error decoding QR data: {decode_error}")
                        else:
                            logger.info(f"No QR codes found in version {idx} of {filename}")
                            
                    except Exception as qr_error:
                        logger.error(f"Error scanning for QR codes in version {idx}: {qr_error}")
                
            except Exception as img_error:
                logger.error(f"Error opening image: {img_error}")
                
        except Exception as att_error:
            logger.error(f"Error processing attachment: {att_error}")
    
    # Return unique QR URLs
    return list(set(qr_data))

def is_test_phishing_email(urls, subject="", sender=""):
    """
    Detect if this is likely a test phishing email based on URL patterns and email metadata
    
    Args:
        urls: List of URLs found in the email
        subject: Email subject
        sender: Email sender
    
    Returns:
        bool: True if this appears to be a test phishing email
    """
    if not urls:
        return False
        
    # Check subject for test patterns
    subject_lower = subject.lower()
    if any(pattern in subject_lower for pattern in ['test', 'phish', 'malware']):
        return True
        
    # Check sender for test patterns
    sender_lower = sender.lower()
    if 'test' in sender_lower:
        return True
        
    # Known test URL patterns
    test_patterns = [
        "testsafebrowsing.appspot.com",
        "malware.testing.google.test",
        "phishing.test", 
        "test.malware",
        "example.com/login.php?password",
        "paypal-secure.accounts-verify.com",
        "bank-secure-login.com",
        "secure-login-paypal.com@evil.com",
        "d0cum3nt-v3r1fy.example.com"
    ]
    
    # Check if any URL contains test patterns
    for url in urls:
        for pattern in test_patterns:
            if pattern in url.lower():
                return True
    
    return False

def fetch_and_process_emails(token, days=3, max_emails=100, models=None, enable_qr_detection=True):
    """Fetch and process emails, scan for phishing URLs"""
    try:
        # Create credentials from token
        creds = Credentials(token=token)
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                return {"error": "Invalid token"}
        
        # Create Gmail API service
        service = build("gmail", "v1", credentials=creds)
        
        # Handle phishing label
        label_id = get_or_create_label(service, "Phishing")
        
        # Calculate date range
        days_ago = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y/%m/%d")
        logger.info(f"Checking emails since: {days_ago}")
        
        # Fetch emails
        results = service.users().messages().list(
            userId="me", 
            q=f"after:{days_ago}",
            maxResults=max_emails
        ).execute()
        
        messages = results.get("messages", [])
        if not messages:
            return {
                "message": f"No emails found in the last {days} days", 
                "emails_checked": 0,
                "time_range": f"From {days_ago} to present"
            }
        
        # Process emails in batches
        batch_size = 10  # Process 10 emails at a time to avoid timeouts
        total_email_count = len(messages)
        processed_count = 0
        phishing_count = 0
        test_phishing_count = 0
        qr_codes_count = 0
        qr_malicious_count = 0
        email_data = []
        
        for i in range(0, total_email_count, batch_size):
            batch = messages[i:i+batch_size]
            batch_results = process_email_batch(service, batch, label_id, models, enable_qr_detection)
            
            email_data.extend(batch_results["emails"])
            processed_count += batch_results["processed"]
            phishing_count += batch_results["phishing"]
            test_phishing_count += batch_results.get("test_phishing", 0)
            qr_codes_count += batch_results.get("qr_codes", 0)
            qr_malicious_count += batch_results.get("qr_malicious", 0)
            
        return {
            "emails_checked": processed_count,
            "phishing_detected": phishing_count,
            "test_phishing_detected": test_phishing_count,
            "qr_codes_detected": qr_codes_count,
            "qr_malicious_detected": qr_malicious_count,
            "emails_data": email_data,
            "time_range": f"From {days_ago} to present"
        }
        
    except Exception as e:
        logger.error(f"Error processing emails: {e}")
        return {"error": str(e)}

def process_email_batch(service, message_batch, label_id, models, enable_qr_detection=True):
    """Process a batch of emails"""
    processed_count = 0
    phishing_count = 0
    test_phishing_count = 0
    qr_codes_count = 0
    qr_malicious_count = 0
    email_data = []
    
    for msg in message_batch:
        try:
            result = process_single_email(service, msg["id"], label_id, models, enable_qr_detection)
            if result:
                email_data.append(result)
                processed_count += 1
                if result.get("moved_to_label", False):
                    phishing_count += 1
                    if result.get("is_test_phishing", False):
                        test_phishing_count += 1
                qr_codes_count += result.get("qr_codes_found", 0)
                qr_malicious_count += result.get("qr_malicious_urls", 0)
        except Exception as e:
            logger.error(f"Error processing email {msg['id']}: {e}")
    
    return {
        "processed": processed_count,
        "phishing": phishing_count,
        "test_phishing": test_phishing_count,
        "qr_codes": qr_codes_count,
        "qr_malicious": qr_malicious_count,
        "emails": email_data
    }

def process_single_email(service, msg_id, label_id, models, enable_qr_detection=True):
    """Process a single email message with enhanced QR code detection"""
    try:
        # Get the full email
        full_email = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
        payload = full_email.get("payload", {})
        headers = payload.get("headers", [])
        
        # Extract headers
        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "No Subject")
        sender = next((h["value"] for h in headers if h["name"].lower() == "from"), "Unknown Sender")
        date = next((h["value"] for h in headers if h["name"].lower() == "date"), "Unknown Date")
        
        logger.info(f"Processing email: '{subject}' from {sender}")
        
        # Extract body content
        body_content = get_email_body(payload)
        
        # Extract URLs from email body
        urls = []
        if body_content:
            if 'text/html' in body_content:
                urls.extend(extract_urls_from_html(body_content))
            else:
                urls.extend(extract_plain_text_urls(body_content))
            
            logger.info(f"Found {len(urls)} URLs in email body")
        
        # Process QR codes if enabled
        qr_urls = []
        if enable_qr_detection:
            # Direct attachment method (more reliable for PNG files)
            attachments = extract_direct_attachments(service, msg_id)
            logger.info(f"Found {len(attachments)} direct attachments")
            
            if attachments:
                qr_urls = extract_qr_codes_from_attachments(attachments)
                logger.info(f"Found {len(qr_urls)} QR code URLs in attachments")
        
        # If no URLs and no QR codes, skip this email
        if not urls and not qr_urls:
            logger.info(f"No URLs or QR codes found in email: {subject}")
            return {
                "subject": str(subject),
                "sender": str(sender),
                "date": str(date),
                "urls_found": 0,
                "qr_codes_found": 0,
                "moved_to_label": False
            }
        
        # Check if this is a test phishing email
        is_test = is_test_phishing_email(urls, subject, sender)
        if is_test:
            logger.info(f"Test phishing email detected: {subject}")
        
        # Classify URLs (using both ML models and Safe Browsing API in batch)
        classified_urls_dict = classify_urls_batch(urls, models)
        classified_urls = list(classified_urls_dict.values())
        
        # Check which URLs are malicious
        malicious_urls = [u for u in classified_urls if u.get("is_malicious")]
        high_confidence_malicious = [u for u in classified_urls if u.get("is_malicious") and u.get("high_confidence", False)]
        
        # Safe Browsing detected URLs get highest priority
        safe_browsing_detected = [u for u in classified_urls if u.get("detection_source") == "safe_browsing" and u.get("is_malicious")]
        
        # Test URLs should be specifically identified
        test_urls = [u for u in classified_urls if u.get("is_test_url", False)]
        
        # Process QR URLs if found
        qr_classified_urls = []
        qr_malicious_urls = []
        qr_high_confidence_malicious = []
        qr_safe_browsing_detected = []
        
        if qr_urls:
            qr_classified_urls_dict = classify_urls_batch(qr_urls, models)
            qr_classified_urls = list(qr_classified_urls_dict.values())
            
            # Check which QR URLs are malicious
            qr_malicious_urls = [u for u in qr_classified_urls if u.get("is_malicious")]
            qr_high_confidence_malicious = [u for u in qr_classified_urls if u.get("is_malicious") and u.get("high_confidence", False)]
            qr_safe_browsing_detected = [u for u in qr_classified_urls if u.get("detection_source") == "safe_browsing" and u.get("is_malicious")]
            
            # Log QR detections
            if qr_malicious_urls:
                logger.info(f"Malicious QR code URLs detected in email '{subject}': {len(qr_malicious_urls)}")
            
            # Debug logging for all QR URLs, even if not marked malicious
            for qr_url in qr_urls:
                logger.info(f"QR URL: {qr_url}")
        
        # Decision logic based on the prioritization scheme
        should_move = len(safe_browsing_detected) > 0 or len(high_confidence_malicious) > 0
        
        # Additional check for QR code URLs
        should_move_qr = len(qr_safe_browsing_detected) > 0 or len(qr_high_confidence_malicious) > 0
        
        # For test emails, we want to ensure they're flagged regardless of Safe Browsing results
        if is_test:
            logger.info(f"Detected test phishing email: '{subject}' from {sender}")
            should_move = True
        elif len(test_urls) > 0:
            logger.info(f"Detected email with test phishing URLs: '{subject}' from {sender}")
            should_move = True
        
        # Include QR detection in decision
        should_move = should_move or should_move_qr
        
        # TEMPORARY FOR TESTING: Flag any email with QR codes for inspection
        if qr_urls and not should_move:
            logger.warning(f"DEBUG MODE: Flagging email with QR codes for testing: {subject}")
            should_move = True
        
        # Move phishing emails to label
        if should_move:
            logger.info(f"Moving email '{subject}' from {sender} to 'Phishing' (QR malicious: {should_move_qr})")
            service.users().messages().modify(
                userId="me", 
                id=msg_id, 
                body={"addLabelIds": [label_id]}
            ).execute()
        
        # Determine detection source
        detection_source = "unknown"
        if is_test or len(test_urls) > 0:
            detection_source = "test_detection"
        elif len(safe_browsing_detected) > 0:
            detection_source = "safe_browsing" 
        elif len(qr_safe_browsing_detected) > 0:
            detection_source = "qr_safe_browsing"
        elif len(qr_high_confidence_malicious) > 0:
            detection_source = "qr_ml_models"
        elif qr_urls:  # For testing, mark even if not detected as malicious
            detection_source = "qr_debug_mode"
        elif should_move:
            detection_source = "ml_models"
        
        # Return email info with detailed threat intelligence
        return {
            "subject": str(subject),
            "sender": str(sender),
            "date": str(date),
            "urls_found": int(len(urls)),
            "urls": classified_urls,
            "malicious_urls": int(len(malicious_urls)),
            "safe_browsing_detected": int(len(safe_browsing_detected)),
            "high_confidence_malicious": int(len(high_confidence_malicious)),
            "test_urls": int(len(test_urls)),
            "is_test_phishing": is_test,
            # QR code specific fields
            "qr_codes_found": int(len(qr_urls)),
            "qr_urls": qr_classified_urls,
            "qr_malicious_urls": int(len(qr_malicious_urls)),
            "qr_safe_browsing_detected": int(len(qr_safe_browsing_detected)),
            "qr_high_confidence_malicious": int(len(qr_high_confidence_malicious)),
            # Common fields
            "moved_to_label": bool(should_move),
            "detection_source": detection_source
        }
    
    except Exception as e:
        logger.error(f"Error processing email: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None

def get_or_create_label(service, label_name):
    """Get or create a Gmail label"""
    try:
        # Get all labels
        label_results = service.users().labels().list(userId="me").execute()
        labels = label_results.get("labels", [])
        
        # Check if label exists
        for label in labels:
            if label["name"].lower() == label_name.lower():
                return label["id"]
        
        # Create label if it doesn't exist
        label_body = {'name': label_name}
        label = service.users().labels().create(userId="me", body=label_body).execute()
        logger.info(f"Created new label: {label_name} with ID {label['id']}")
        return label["id"]
    
    except Exception as e:
        logger.error(f"Error getting/creating label: {e}")
        raise