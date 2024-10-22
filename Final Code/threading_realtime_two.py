# real_time.py

import datetime
import json
import os
import imaplib
import email
from email.header import decode_header
from email.policy import default
import hashlib
import re
from bs4 import BeautifulSoup
import pandas as pd
from urllib.parse import urlparse, parse_qs
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
import dns.resolver
import requests
import joblib
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
import base64
import OpenSSL
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.parser import BytesParser
import magic
from mimetypes import guess_extension
import lightgbm
import time
from tld import get_tld


import blacklist_pulldown
import mongodb_final as mongodb


global server_email, server_pass, tempvar,filename
data = None

#____________________________(AUTH FUNCTIONS)____________________________
def get_mx_record(domain):
    try:
        # Get the MX record for the domain
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = sorted(mx_records, key=lambda r: r.preference)[0]
        return mx_record.exchange.to_text().strip()  # Remove any extra spaces and periods
    except Exception as e:
        print(f"An error occurred while fetching MX record: {e}")
        return None

def server_fetch(email_address, password):
    # Dictionary of common email providers and their IMAP servers
    IMAP_SERVERS = {
        'gmail.com': 'imap.gmail.com',
        'yahoo.com': 'imap.mail.yahoo.com',
        'outlook.com': 'imap-mail.outlook.com',
        'hotmail.com': 'imap-mail.outlook.com',
        'live.com': 'imap-mail.outlook.com',
        'aol.com': 'imap.aol.com',
        'icloud.com': 'imap.mail.me.com',
        'google.com': 'imap.gmail.com',
        'aspmx.l.google.com': 'imap.gmail.com'  # Specific handling for MX server
    }
    # Split the email to get the domain
    domain = email_address.split('@')[1]
    if not domain:
        print("Invalid email address.")
        return None

    # Check if the domain is in the dictionary
    email_server = IMAP_SERVERS.get(domain)
    if not email_server:
        # If the domain is not in the dictionary, get the MX record
        mx_server = get_mx_record(domain)
        if not mx_server:
            print(f"Failed to retrieve MX record for domain: {domain}")
            return None

        # Remove trailing period if present
        mx_server = mx_server.rstrip('.')

        email_server = IMAP_SERVERS.get(mx_server)
        if email_server:
            return email_address, password, email_server
        else:
            # Extract the base domain using regex
            match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]+)$', mx_server)
            if match:
                base_domain = match.group(0)
                email_server = IMAP_SERVERS.get(base_domain, f'imap.{base_domain}')
            else:
                print(f"Failed to parse base domain from MX server: {mx_server}")
                return None

    return email_address, password, email_server


#___________________AI MODEL FUCNTIONS HERE______________
def get_tld_plus_one(domain):
    parts = domain.split('.')
    
    # If the domain has more than two parts, join the last two parts to get the TLD + 1
    if len(parts) > 2:
        tld_plus_one = ".".join(parts[-2:])
    else:
        tld_plus_one = domain  # If the domain is already in the TLD + 1 format

    return tld_plus_one

# Function to get domain age using python-whois
def get_domain_age(domain: str) -> int:
    try:
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        elif creation_date is None:
            print(f"Creation date not found for {domain}")
            return None
        age = (datetime.now() - creation_date).days
        return age
    except Exception as e:
        print(f"Error getting domain age for {domain}: {e}")
        return None

# Function to get domain rank using Open PageRank API
def get_domain_rank(domain):
    try:
        url = f"https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D={domain}"
        headers = {
            'API-OPR': 'ow08ogc0sgs84swk4g8g8o0kgogsgkcw8cs4g48k'  # Replace with your Open PageRank API key
        }
        response = requests.get(url, headers=headers)
        data = response.json()
        if data and 'response' in data and data['response']:
            rank = data['response'][0]['page_rank_integer']
            return int(rank)  # Ensure the rank is an integer
        return None
    except Exception as e:
        print(f"Error getting rank for {domain}: {e}")
        return None

# Function to check for popular keywords in domain
def check_popular_keywords(domain):
    popular_keywords = ["shop", "bank", "secure", "account", "login"]
    return any(keyword in domain for keyword in popular_keywords)

# Function to check if TLD is trustworthy
def check_tld(domain):
    trustworthy_tlds = [".com", ".org", ".net", ".edu", ".gov"]
    tld = '.' + domain.split('.')[-1]
    return tld in trustworthy_tlds

# Function to check domain reputation
def check_domain_reputation(domain):
    if domain is None:
        return 0.0, ["Domain is None."]

    score = 0
    reasons = []

    # Extract base domain (strip protocol and subdomains)
    domain_name = domain.split('//')[-1].split('/')[0]
    
    # Check domain age
    age = get_domain_age(domain_name)
    if age is not None:
        if age > 365:
            score += 0.2
        else:
            reasons.append("Domain age is less than 1 year.")
    else:
        reasons.append("Unable to determine domain age.")

    # Check domain rank
    rank = get_domain_rank(domain_name)
    if rank is not None:
        if rank >= 2:  # Adjust threshold as per Open PageRank scale
            score += 0.2
        else:
            reasons.append("Domain rank (Open PageRank) is less than 2.")
    else:
        reasons.append("Unable to determine domain rank.")

    # Check popular keywords
    if check_popular_keywords(domain_name):
        score += 0.2
    else:
        reasons.append("Domain does not contain popular keywords.")

    # Check TLD
    if check_tld(domain_name):
        score += 0.2
    else:
        reasons.append("TLD is not among the most trustworthy ones.")
    
    # Final adjustment
    if score >= 0.6:
        score = 1.0
    elif score >= 0.3:
        score = 0.5
    else:
        score = 0.0

    if score == 1.0:
        reasons.append("Domain has high reputation based on heuristics.")
    elif score == 0.5:
        reasons.append("Domain has medium reputation based on heuristics.")
    else:
        reasons.append("Domain has low reputation based on heuristics.")

    return score, reasons



# Function to extract features from URLs
def extract_features(url):
    parsed_url = urlparse(url)
    features = {
        'url_length': len(url),
        'hostname_length': len(parsed_url.hostname) if parsed_url.hostname else 0,
        'path_length': len(parsed_url.path),
        'query_length': len(parsed_url.query),
        'fragment_length': len(parsed_url.fragment),
        'num_special_chars': len(re.findall(r'[@\-_.]', url)),
        'num_subdomains': parsed_url.hostname.count('.') if parsed_url.hostname else 0,
        'uses_https': int(parsed_url.scheme == 'https'),
        'has_ip': int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', parsed_url.hostname))) if parsed_url.hostname else 0,
        'num_query_params': len(parse_qs(parsed_url.query)),
        'abnormal_url': int(bool(re.search(str(parsed_url.hostname), url))),
        'count_dot': url.count('.'),
        'count_www': url.count('www'),
        'count_atrate': url.count('@'),
        'count_dir': parsed_url.path.count('/'),
        'count_embed_domain': parsed_url.path.count('//'),
        'short_url': int(bool(re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                                         r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                                         r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                                         r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                                         r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                                         r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                                         r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                                         r'tr\.im|link\.zip\.net', url))),
        'count_https': url.count('https'),
        'count_http': url.count('http'),
        'count_per': url.count('%'),
        'count_ques': url.count('?'),
        'count_hyphen': url.count('-'),
        'count_equal': url.count('='),
        'sus_url': int(bool(re.search(r'PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url))),
        'count_digits': sum(c.isdigit() for c in url),
        'count_letters': sum(c.isalpha() for c in url),
        'fd_length': len(parsed_url.path.split('/')[1]) if len(parsed_url.path.split('/')) > 1 else 0,
        'tld_length': len(get_tld(url, fail_silently=True)) if get_tld(url, fail_silently=True) else -1
    }
    return features

# Function to check if URL domain matches sender domain
def check_same_domain(url, sender_domain):
    parsed_url = urlparse(url)
    return int(parsed_url.hostname == sender_domain)

def validate_and_clean_urls(url_list):
    pattern = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    cleaned_url_list = []
    for url in url_list:
        # Remove any invalid characters
        cleaned_url = re.sub(r'[<>]', '', url)
        # Check if the cleaned URL is valid
        if re.match(pattern, cleaned_url):
            # Add the cleaned URL to the list if it's not already there
            if cleaned_url not in cleaned_url_list:
                cleaned_url_list.append(cleaned_url)
    
    return cleaned_url_list

# Function to extract URLs from email content
def extract_urls_from_email(email_content):
    urls = []
    for part in email_content.walk():
        if part.get_content_type() == 'text/plain':
            text_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            urls.extend(re.findall(r'https?://\S+', text_content))
        elif part.get_content_type() == 'text/html':
            html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            soup = BeautifulSoup(html_content, 'html.parser')
            urls.extend([a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('http')])
    
    urls = validate_and_clean_urls(urls)
    return urls

# Function to extract sender's domain
def get_sender_domain(msg):
    sender = email.utils.parseaddr(msg.get('From'))[1]
    domain = sender.split('@')[-1]
    return domain

# Function to get sender IP from email headers
def get_sender_ip(headers):
    for header, value in headers:
        if header.lower() == 'received':
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', value)
            if ip_match:
                return ip_match.group(1)
    return None

# Function to check DMARC
def ml_check_dmarc(domain):
    try:
        answers = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                if 'v=DMARC1' in txt_string.decode():
                    return True
        return False
    except Exception as e:
        print(f"Error checking DMARC for domain {domain}: {e}")
        return False

# Function to get DNS information
def get_dns_info(domain):
    if domain is None:
        print("Domain is None. Cannot fetch DNS info.")
        return []

    try:
        dns_info = dns.resolver.resolve(domain, 'A')
        print("DNS A records:", [ip.address for ip in dns_info])
        return [ip.address for ip in dns_info]
    except Exception as e:
        print(f"Error getting DNS info for domain {domain}: {e}")
        return []


# Function to calculate phishing score and provide reasons
def calculate_phishing_score(reasons):
    score = 0
    if "URL and sender domain do not match." in reasons:
        score += 1
    if "Domain not whitelisted." in reasons:
        score += 1
    if "Domain blacklisted." in reasons:
        score += 1
    if "IP blacklisted." in reasons:
        score += 1
    if "Classified as phishing by model." in reasons:
        score += 1
    if "Poor domain reputation." in reasons:
        score += 1

    ratio = score / 6  # 6 is the total number of checks
    return ratio

# Function to classify URLs in emails and state the reason for phishing classification
def classify_urls_in_email(email_content, whitelisted_domains, clf):
    try:
        urls = extract_urls_from_email(email_content)
        print(urls)
        if not urls:
            print("No URLs found in the email.")
            return
        url_analysis = []
        sender_domain = get_sender_domain(email_content)
        headers = email_content.items()
        sender_ip = get_sender_ip(headers)
        for url in urls:
            domain = urlparse(url).hostname
            print(f"Domain Found: {domain}")
            if domain is None:
                print(f"URL {url} has no hostname.")
                continue

            reasons = []

            # Step 1: Check if sender domain matches the URL domain
            tld_plus_one = get_tld_plus_one(domain)
            if tld_plus_one != sender_domain:
                reasons.append("URL and sender domain do not match.")
            
            # Step 2: Check if domain is whitelisted
            if domain in whitelisted_domains:
                print(f"Whitelisted domain found: {domain}")
                # Reason for legitimate URL
                print(f"URL {url} is legitimate because it is from a whitelisted domain.")
                continue
            else:
                reasons.append("Domain not whitelisted.")

            # Step 3: Check if domain or IP is blacklisted
            ml_domain_check, bl_domain = check_domain_exists(domain)
            if ml_domain_check ==True:
                reasons.append("Domain blacklisted.")
            else:
                domain_ips = get_dns_info(domain)
                ml_ip_check,bl_ips = check_ips_exist(domain_ips)
                if ml_ip_check == True :
                    reasons.append("IP blacklisted.")

            if not ml_check_dmarc(sender_domain):
                reasons.append("DMARC validation failed.")

            # Step 6: Model prediction
            url_features = extract_features(url)
            url_data = pd.DataFrame([url_features])
            is_phishing = clf.predict(url_data)[0] == 'phishing'
            if is_phishing:
                reasons.append("Classified as phishing by model.")

            # Step 7: Domain reputation check
            reputation_score, reputation_reasons = check_domain_reputation(domain)
            if reputation_score < 0.5:
                reasons.append("Poor domain reputation.")

            # Calculate phishing score and classify
            phishing_score = calculate_phishing_score(reasons)
            print(f"Phishing score for URL {url}: {phishing_score}")
            print("Reasons for classification:")
            for reason in reasons:
                print(f"- {reason}")
            if phishing_score > 0.5:
                reason_string = f"{url}:{reasons}"
                url_analysis.append(reason_string)

        return url_analysis
        
    except Exception as e:
        print(f"Error processing machine learning model: {e}")
        traceback.print_exc()

#_________________CERTIFICATE VERIFICATION________________

def extract_certificate_from_eml(eml_content):
    """Extracts a certificate from email content.
    Args:
        eml_content (bytes): Raw email content.
    Returns:
        Tuple (bytes, str): Certificate data and format or None."""
    msg = email.message_from_bytes(eml_content)

    # Check for certificate in headers
    for header, value in msg.items():
        if 'CERTIFICATE' in value.upper():
            try:
                cert_data = base64.b64decode(value.strip())
                return cert_data, 'pem'
            except Exception as e:
                print(f"Error decoding certificate from header {header}: {str(e)}")

    # Check for certificate in body
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            filename = part.get_filename()
            content_disposition = str(part.get("Content-Disposition"))
            payload = part.get_payload(decode=True)

            if (content_type == 'application/x-x509-ca-cert' or
                content_type == 'application/pkcs7-mime' or
                (filename and filename.endswith(('.cer', '.der', '.pfx')))):
                return payload, 'attachment'
            elif 'attachment' not in content_disposition:
                # Check for inline certificate data
                try:
                    decoded_payload = base64.b64decode(payload.strip())
                    if b'-----BEGIN CERTIFICATE-----' in decoded_payload:
                        return decoded_payload, 'pem'
                    elif decoded_payload.startswith(b'0\x82'):
                        return decoded_payload, 'der'
                except Exception as e:
                    continue
    else:
        payload = msg.get_payload(decode=True)
        try:
            if b'-----BEGIN CERTIFICATE-----' in payload:
                return payload, 'pem'
            elif payload.startswith(b'0\x82'):
                return payload, 'der'
        except Exception as e:
            print(f"Error decoding certificate from body: {str(e)}")

    return None, None

def extract_sender_email(eml_content):
    """Extracts the sender's email address.
    Args:
        eml_content (bytes): Raw email content.
    Returns:
        str: Sender's email address."""
    msg = email.message_from_bytes(eml_content)
    sender = msg.get('From')
    return sender

def load_certificates(cert_data, cert_format):
    """Loads certificates from data.
    Args:
        cert_data (bytes): Certificate data.
        cert_format (str): Format of the certificate (pem, der, pfx).
    Returns:
        List[x509.Certificate]: List of certificates."""
    certificates = []
    if cert_format == 'pem':
        for cert in cert_data.split(b'-----END CERTIFICATE-----'):
            cert = cert.strip()
            if cert:
                cert = cert + b'-----END CERTIFICATE-----'
                certificates.append(x509.load_pem_x509_certificate(cert, default_backend()))
    elif cert_format == 'der':
        certificates.append(x509.load_der_x509_certificate(cert_data, default_backend()))
    elif cert_format == 'pfx':
        pfx = OpenSSL.crypto.load_pkcs12(cert_data)
        certificates.append(pfx.get_certificate())
    return certificates

def verify_certificate_chain(certificates):
    """Verifies the certificate chain.
    Args:
        certificates (List[x509.Certificate]): List of certificates.
    Returns:
        Tuple (bool, str): Chain validity and message."""
    for i in range(len(certificates) - 1):
        cert = certificates[i]
        issuer_cert = certificates[i + 1]
        try:
            cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_hash_algorithm
            )
        except Exception as e:
            return False, f"Verification failed for certificate {i}: {e}"
        if not cert.issuer == issuer_cert.subject:
            return False, f"Certificate {i} issuer does not match the subject of certificate {i+1}"
    return True, None

def check_expiration(cert):
    """Checks if the certificate is expired.
    Args:
        cert (x509.Certificate): The certificate to check.
    Returns:
        Tuple (bool, str): Expiration status and message."""
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if not_after < datetime.now(timezone.utc):
        return False, "Certificate is expired."
    return True, f"Certificate is valid until: {not_after}"

def verify_email(cert, email_address):
    """Verifies if the email matches the certificate.
    Args:
        cert (x509.Certificate): The certificate.
        email_address (str): The email address to verify.
    Returns:
        Tuple (bool, str): Email match status and message."""
    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if email_address == common_name:
            return True, "Email address matches the certificate (Common Name)."
        for ext in cert.extensions:
            if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                san = ext.value.get_values_for_type(x509.RFC822Name)
                if email_address in san:
                    return True, "Email address matches the certificate (Subject Alternative Name)."
        return False, "Email address does not match the certificate."
    except Exception as e:
        return False, f"Email verification failed: {e}"

def validate_email_certificate(eml_content):
    """Validates the certificate from an email.
    Args:
        eml_content (bytes): Raw email content."""
    cert_data, cert_location = extract_certificate_from_eml(eml_content)
    if not cert_data:
        return  False

    # Determine certificate format (PEM, DER, PFX)
    cert_format = 'pem'  # Default to PEM
    if b'-----BEGIN CERTIFICATE-----' in cert_data:
        cert_format = 'pem'
    elif cert_data.startswith(b'0\x82'):
        cert_format = 'der'
    elif b'-----BEGIN PKCS7-----' in cert_data or b'-----BEGIN CERTIFICATE-----' not in cert_data:
        cert_format = 'pfx'

    # Load the certificate chain from the extracted data
    certificates = load_certificates(cert_data, cert_format)

    # Verify the certificate chain
    is_valid_chain, chain_message = verify_certificate_chain(certificates)
    if not is_valid_chain:
        print(f"Certificate chain is not valid ({cert_location}): {chain_message}")
        return True

    sender_email = extract_sender_email(eml_content)
    clean_sender_email = email.utils.parseaddr(sender_email)[1]

    cert = certificates[0]

    # Verify the email address in the certificate
    is_valid_email, email_message = verify_email(cert, clean_sender_email)
    if not is_valid_email:
        print(f"Certificate validation failed for email {clean_sender_email}: {email_message} ({cert_location})")
        return True

    # Check certificate expiration
    is_not_expired, expiration_message = check_expiration(cert)
    if not is_not_expired:
        print(f"Certificate validation failed for email {clean_sender_email}: {expiration_message} ({cert_location})")
        return True

    # If all checks pass, we do not print anything as per the requirement   
    return False

#________________SPF verification_____________________
def spf_verification(message):
    from_header = message['From']
    email_address_match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
    if email_address_match:
        email_address = email_address_match.group(0)
        sender_domain = email_address.split('@')[-1]
    else:
        print(f"Could not extract sender domain from {from_header}")
        return False

    # Exclude trusted domains from SPF verification
    trusted_domains = [
        'gmail.com',
        'yahoo.com',
        'outlook.com',
        'office365.com',
        'amazonaws.com',  # for Amazon SES
        'sendgrid.net'
    ]

    if sender_domain in trusted_domains:
        return trusted_spf_verification(message)  # trusted domains 
    
    received_headers = message.get_all('Received')
    ip_addresses = []
    for header in received_headers:
        ip_address_match = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', header)
        if ip_address_match:
            ip_addresses.extend(ip_address_match)

    if not ip_addresses:
        print(f"No IP addresses found in Received headers")
        return False

    spf_result = None
    for ip_address in ip_addresses:
        try:
            spf_record = dns.resolver.resolve(sender_domain, 'TXT')
            for txt in spf_record:
                spf_policy = str(txt)
                if 'v=spf1' in spf_policy:
                    for mechanism in spf_policy.split():
                        if mechanism.startswith('ip4:'):
                            allowed_ip = mechanism.split(':')[1]
                            if ip_address == allowed_ip:
                                spf_result = True  # SPF pass
                                break
                        elif mechanism.startswith('ip6:'):
                            allowed_ip = mechanism.split(':')[1]
                            if ip_address == allowed_ip:
                                spf_result = True  # SPF pass
                                break
                        elif mechanism == '-all':
                            spf_result = False  # SPF fail
                            break
                    if spf_result is not None:
                        break
        except dns.resolver.NoAnswer:
            print(f"No SPF policy published for {sender_domain}")
            spf_result = False  # SPF fail
        except dns.resolver.NXDOMAIN:
            print(f"Domain {sender_domain} does not exist")
            spf_result = False  # SPF fail
        except dns.exception.DNSException as e:
            print(f"DNS error: {e}")
            spf_result = False  # SPF fail

    if spf_result is None:
        print(f"No SPF policy found for {sender_domain}")
        return False  # SPF fail
    else:
        return spf_result
    
def trusted_spf_verification(msg_data):
    for header, value in msg_data.items():
        if header == 'Received-SPF':
            spf_value = value
            break
    else:
        return False  # SPF header not found

    if 'pass' in spf_value:
        spf_result = 'Pass'
    elif 'fail' in spf_value:
        spf_result = 'Fail'
    elif 'neutral' in spf_value:
        spf_result = 'Neutral'
    else:
        return True  # Unknown SPF result

    if spf_result == 'Fail':
        return False
    else:
        return True
#_______________________JSON OBJECT HANDLING__________________________

def convert_bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode('utf-8', errors='ignore')
    if isinstance(data, dict):
        return {key: convert_bytes_to_str(value) for key, value in data.items()}
    if isinstance(data, list):
        return [convert_bytes_to_str(item) for item in data]
    return data

def update_json_value(key, value, check_object):
    if key in check_object:
        check_object[key] = value
    else:
        raise KeyError(f"Key {key} does not exist in the dictionary")

def evaluate_email_check(check_object):
    
    email_body = ""
    spam_check = None

    # Check if the email is flagged as phishing
    if (check_object["ip_blacklist_check"] or 
        check_object["domain_blacklist_check"] or 
        check_object["malware_check"] or 
        check_object["file_extension_check"] or 
        (check_object["dmarc_check"] and check_object["spf_verification_check"])):
        spam_check = True
        email_body += "Email flagged as phishing.\n"
    # Check if the email is flagged as suspicious
    elif (check_object["dmarc_check"] or 
          check_object["spf_verification_check"] or 
          check_object["certificate_check"] or 
          
          check_object["dkim_check"] or 
          check_object["url_analysis_result"]):
        spam_check = False
        email_body += "Email flagged as suspicious.\n" 

    # Add failed checks to the email body
    if check_object["ip_blacklist_check"]:
        email_body += "Failed IP blacklist check. Blacklisted IPs: {}\n".format(", ".join(check_object["blacklisted_ips"]))
    if check_object["domain_blacklist_check"]:
        email_body += "Failed domain blacklist check. Blacklisted domain: {}\n".format(check_object["blacklisted_domain"])
    if check_object["malware_check"]:
        email_body += "Failed malware check. Malware files: {}\n".format(", ".join(check_object["malware_files"]))
    if check_object["dmarc_check"]:
        email_body += "Failed DMARC check.\n"
    if check_object["spf_verification_check"]:
        email_body += "Failed SPF verification check.\n"
    if check_object["certificate_check"]:
        email_body += "Failed certificate check.\n"
    if check_object["file_extension_check"]:
        email_body += "Failed file extension check. Blacklisted file names: {}\n".format(", ".join(check_object["blacklisted_file_names"]))
    if check_object["dkim_check"]:
        email_body += "Failed DKIM check.\n"
    if check_object["url_analysis_result"]:
        email_body += "Failed URL analysis check.\n"
        for result in check_object["url_analysis_result"]:
            email_body += "{}\n".format(result)

    # If no checks failed, set email_body and spam_check to None
    if not email_body:
        email_body = None
        spam_check = None

    return email_body, spam_check

#_______________________(SPAM AND ALERT)_____________________________
def notify_user(user, server_mail, server_pass, body, spam_check):
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        if spam_check == True:
            subject = "Phishing Email Found"
        else:
            subject = "Suspicious Email Found"

        msg = MIMEMultipart()
        msg['From'] = server_mail
        msg['To'] = user
        msg['Subject'] = subject

        # Attach the email body
        msg.attach(MIMEText(body, 'plain'))

        # Connect to the SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection
        server.login(server_mail, server_pass)

        # Send the email
        server.send_message(msg)
        server.quit()

        print("Email sent successfully.")

    except smtplib.SMTPAuthenticationError as auth_error:
        print(f"SMTP Authentication Error: {auth_error}")
        print("Check if the email and password are correct. If you are using an app-specific password, ensure it is generated correctly.")

def move_to_spam(mail, num, mail_server):
    try:
        if mail_server == 'imap.gmail.com':
            mail.store(num, '+X-GM-LABELS', '\\Spam')
        elif mail_server == 'imap.yahoo.com':
            spam_folder = "Bulk"
            # Copy the email to the spam/junk folder
            copy_status = mail.copy(num, spam_folder)
            if copy_status[0] != "OK":
                print(f"Error copying email ID {num} to {spam_folder}: {copy_status[1]}")
            
            # Mark the email for deletion in the original folder
            delete_status = mail.store(num, '+FLAGS', '\\Deleted')
            if delete_status[0] != "OK":
                print(f"Error marking email ID {num} for deletion: {delete_status[1]}")
            mail.expunge()

        elif mail_server == 'imap-mail.outlook.com':
            # Copy the email to the Junk/Spam folder
            mail.copy(num, "Junk")
            
            # Mark the email for deletion in the original folder
            mail.store(num, '+FLAGS', '\\Deleted')
        else:
            mail.store(num, '+X-GM-LABELS', '\\Spam')
        
        print("Email moved to Spam folder.")
    except Exception as e:
        print(f"Error moving message to Spam folder: {e}")

#______________________(DMARC and DKIM)_______________________________________

    
def check_dmarc(message):
    from_header = message['From']
    email_address_match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
    if email_address_match:
        email_address = email_address_match.group(0)
        sender_domain = email_address.split('@')[-1]
    else:
        print(f"Could not extract sender domain from {from_header}")
        return False

    try:
        dmarc_record = dns.resolver.resolve('_dmarc.' + sender_domain, 'TXT')
        for txt in dmarc_record:
            dmarc_policy = str(txt)
            if 'v=DMARC1;' in dmarc_policy:
                for part in dmarc_policy.split(';'):
                    if part.startswith('p='):
                        policy = part.split('=')[1]
                        if policy in ['reject', 'quarantine']:
                            return True  # Phishing sign
            else:
                print(f"Invalid DMARC policy for {sender_domain}: {dmarc_policy}")
                return False
    except dns.resolver.NoAnswer:
        print(f"No DMARC policy published for {sender_domain}")
        return False
    except dns.resolver.NXDOMAIN:
        print(f"Domain {sender_domain} does not exist")
        return False
    except dns.exception.DNSException as e:
        print(f"DNS error: {e}")
        return False

# File Extension Check
def checkext_and_hash(filename, response_part):
    # Check if attachment is blacklisted
    blacklist = ['.pyx','.pyz','.exe', '.bat', '.cmd', '.js', '.adp', '.app', '.asp', '.bas', '.bat', '.cer', '.chm', '.cmd', '.cnt', '.com', '.cpl', '.crt', '.csh', '.der', '.exe', '.fxp', '.gadget', '.hlp', '.hpj', '.hta', '.inf', '.ins', '.isp', '.its', '.js', '.jse', '.ksh', '.lnk', '.mad', '.maf', '.mag', '.mar', '.mam', '.maq', '.mas', '.mat', '.mau', '.mav', '.mda', '.mdb', '.mde', '.mdt', '.mdw', '.mdz', '.msc', '.msh', '.msh1', '.msh2', '.mshxml', '.msh1xml', '.msh2xml', '.msi', '.msp', '.mst', '.ops', '.pcd', '.pif', '.plg', '.prf', '.prg', '.pst', '.reg', '.scf', '.scr', '.sct', '.shb', '.shs', '.ps1', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2', '.tmp', '.url', '.vb', '.vbe', '.vbp', '.vbs', '.vsmacros', '.vsw', '.ws', '.wsc', '.wsf', '.wsh', '.xnk', '.ade', '.cla', '.class', '.grp', '.jar', '.mcf', '.ocx', '.pl', '.xbap']
    if any(filename.lower().endswith(ext) for ext in blacklist):
        return True
    #Checking File hash Against Malware Database
    attachment_content=response_part.get_payload(decode=True)
    return False


def calculate_memory_hash(content):
    # Calculate SHA256 hash of the content
    sha256_hash = hashlib.sha256()
    sha256_hash.update(content)
    return sha256_hash.hexdigest()

#Blaclist_check

def check_ips_exist(ips_to_check):
    # Load the DataFrame from the pkl file
    filename = "processed_ip.pkl"
    check = None
    list = []
    df = pd.read_pickle(filename)

    # Check if any of the IPs in ips_to_check exist in the blacklist
    blacklist = df['ip'].values
    for ip in ips_to_check:
        if ip in blacklist:
            print(f"Alert: {ip} is Blacklisted !!!!")
            check = True
            list.append(ip)
    if check == True :
        return True , list
    return False , None


def check_domain_exists(domain_to_check):
    # Load the DataFrame from the pkl file
    filename = "processed_domains.pkl"
    df = pd.read_pickle(filename)

    exists = domain_to_check in df['domain'].values

    if exists:
        print(f"Alert : {domain_to_check} is Blacklisted !!!!")
        return True , domain_to_check
    return False , None

#Real_Time_analysis

def process_emails(email_id, msg_data,fetch_response, user,mail, server_email, server_pass, email_server, clf, whitelisted_domains):
    try:
        #___________________AI MODEL INITIATION CODE_______________________
        # Load the dataset and update whitelist
        #data = pd.read_csv(r"C:\Users\moksh\swiftsafe\malicious_phish_cleaned.csv")

        blacklist = ['.pyx','.pyz','.exe', '.bat', '.cmd', '.js', '.adp', '.app', '.asp', '.bas', '.bat', '.cer', '.chm', '.cmd', '.cnt', '.com', '.cpl', '.crt', '.csh', '.der', '.exe', '.fxp', '.gadget', '.hlp', '.hpj', '.hta', '.inf', '.ins', '.isp', '.its', '.js', '.jse', '.ksh', '.lnk', '.mad', '.maf', '.mag', '.mar', '.mam', '.maq', '.mas', '.mat', '.mau', '.mav', '.mda', '.mdb', '.mde', '.mdt', '.mdw', '.mdz', '.msc', '.msh', '.msh1', '.msh2', '.mshxml', '.msh1xml', '.msh2xml', '.msi', '.msp', '.mst', '.ops', '.pcd', '.pif', '.plg', '.prf', '.prg', '.pst', '.reg', '.scf', '.scr', '.sct', '.shb', '.shs', '.ps1', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2', '.tmp', '.url', '.vb', '.vbe', '.vbp', '.vbs', '.vsmacros', '.vsw', '.ws', '.wsc', '.wsf', '.wsh', '.xnk', '.ade', '.cla', '.class', '.grp', '.jar', '.mcf', '.ocx', '.pl', '.xbap']
        check_object = {
            "email": email_id,
            "email_id": False,
            "date-time": None,
            "dmarc_check": False,
            "dkim_check": False,
            "domain_blacklist_check": False,
            "blacklisted_domain": None,
            "ip_blacklist_check": False,
            "blacklisted_ips": [],
            "spf_verification_check": False,
            "certificate_check": False,
            "file_extension_check": False,
            "blacklisted_file_names": [],
            "malware_check" : False,
            "malware_files" : [],
            "url_analysis_result" : []
        }
        update_json_value("email_id", email_id, check_object)
        update_json_value("date-time", datetime.now().isoformat(), check_object)

        if not msg_data or len(msg_data) < 1:
            print(f"Email data is empty for {email_id}")
            return
        
        tempvar = None
        # ________________________(DATA PARSING)___________________________
        raw_email = fetch_response[0][1]
        email_message = email.message_from_bytes(msg_data[1], policy=default)
        from_header = email_message['From']
        print(f"From: {from_header}")
        email_address_match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
        if email_address_match:
            email_address = email_address_match.group(0)
            sender_domain = email_address.split('@')[-1]
            print(f"Sender Domain: {sender_domain}")
        else:
            print(f"Could not extract sender domain from {from_header}")
            return
        
        received_headers = email_message.get_all('Received')
        ip_addresses = []
        if received_headers:
            for header in received_headers:
                ip_address_match = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', header)
                if ip_address_match:
                    ip_addresses.extend(ip_address_match)
            print(f"IP Addresses: {ip_addresses}")
        #_______________________(SPF VERIFICATION)______________
        print("--Running SPF Verification")
        spf_check=trusted_spf_verification(email_message)
        if spf_check == False:
            print("---SPF verification Failed")
            update_json_value("spf_verification_check", True, check_object)
        
        #_______________________(BLACKLIST CHECK)________________________    
        print("--Running DNS Blacklist check")
        domainbl_check, bl_domain = check_domain_exists(sender_domain)
        if domainbl_check == True:
            print(f"---Domain Blacklist check Failed")
            update_json_value("domain_blacklist_check", True, check_object)
            update_json_value("blacklisted_domain", bl_domain, check_object)
        
        ipbl_check , bl_ips = check_ips_exist(ip_addresses)
        if ipbl_check == True:
            print(f"---IP Blacklist check Failed")
            update_json_value("ip_blacklist_check", True, check_object)
            update_json_value("blacklisted_ips", bl_ips, check_object)
        #________________________(CERT VERIFICATION)_______________________
        print("--Running Certiifcate Verification")
        cert_check = validate_email_certificate(raw_email)
        if cert_check == True:
            update_json_value("certificate_check",True,check_object)
        #________________________(DMARC AND DKIM CHECK)_____________________
        print("--Running DMARC Check")
        dmarc_check = check_dmarc(email_message)
        if dmarc_check == True:
            print("---DMARC Check Failed !")
            update_json_value("dmarc_check", True , check_object)
        #______________________________(FILE EXTENSION AND MALWARE CHECK)_____________________
        print("--Running File extension and Malware analysis checks")
        filenames = []
        check_flag = None
        for response_part in email_message.walk():
            filename = response_part.get_filename()
            if filename:
                fileext_check = checkext_and_hash(filename, response_part)
                if fileext_check == False :
                    file_data = response_part.get_payload(decode=True)
                    file_type = magic.from_buffer(file_data, mime=True)
                    file_extension = guess_extension(file_type)
                    if not file_extension:
                        file_extension = 'unknown'  # If no extension can be determined
                        print("---Unknown File extension found")
                    else:
                        print(f"---File extension Detected as :{file_extension}")
                        if file_extension in blacklist:
                            check_flag = True
                            print(f"---Blacklisted Content Found in {filename} of type {file_extension}")
                            filenames.append(filename)
                            continue
                #malware_check = malware check fucntion
                if fileext_check == True:
                    print(f"---{filename} Failed file extension check")
                    check_flag = True
                    filenames.append(filename)
                    continue
        if check_flag == True:
            update_json_value("file_extension_check",True, check_object)
            update_json_value("blacklisted_file_names",filenames, check_object)
        #________________________(MACHINE LEARNING CHECK)____________________
        print("--Running URL Analysis")
        url_analysis_check = classify_urls_in_email(email_message, whitelisted_domains, clf)
        if url_analysis_check:
            print("Suspicous URLS Found")
            update_json_value("url_analysis_result",url_analysis_check, check_object)
        #________________________(EVALUATE AND NOTIFY)___________________
        body,spam_check = evaluate_email_check(check_object)
        if spam_check == True:
            notify_user(user, server_email, server_pass, body, spam_check)
            move_to_spam(mail, email_id, email_server)
        elif spam_check == False:
            notify_user(user, server_email, server_pass, body, spam_check)
        #_____________________(SAVE AND DESTROY JSON OBJECT)______________
        converted_check_object = convert_bytes_to_str(check_object)
        if not os.path.exists("RTM_log.txt"):
            open("RTM_log.txt", 'w').close()
        with open("RTM_log.txt", 'a') as file:
            json_string = json.dumps(converted_check_object)
            file.write(json_string + '\n')
        check_object = {} #Destroy JSON Object

    except Exception as e:
        print(f"An error occurred during email processing: {str(e)}")

def email_fetchncheck(user, password, email_server, server_email , server_pass):
    try:
        #______________________(EMAIL AUTH AND FETCH)_____________________________
        mail = imaplib.IMAP4_SSL(email_server)
        mail.login(user, password)
        mail.select('inbox')
        whitelisted_domains = set(pd.read_csv(r"whitelisted_domains.csv")["domain"])

        # Load the machine learning model
        clf = joblib.load(r"lgb_model.pkl")
        # Fetch all unseen email IDs at once
        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()
        
        if not email_ids:
            print("No new emails to process.")
            return

        # Fetch all email data in a single call
        fetch_status, fetch_response = mail.fetch(",".join(email_id.decode() for email_id in email_ids), '(RFC822)')

        if fetch_status!= 'OK':
            print("Error fetching emails.")
            return
        

        # Process emails concurrently using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers = 5) as executor:
            futures = []
            for response_part in fetch_response:
                if isinstance(response_part, tuple):
                    num = response_part[0].split()[0]
                    futures.append(executor.submit(process_emails, num, response_part,fetch_response,  user, mail, server_email, server_pass, email_server, clf,whitelisted_domains))
            for future in as_completed(futures):
                future.result()  # To raise exceptions if any occurred during email processing

        print("Real Time Monitoring Module Executed")

    except Exception as e:
        print(f"An error occurred during email processing: {str(e)}")

def service():
    user = None
    password = None
    mail_server = None
    server_email = None
    server_pass = None
    blacklist_pulldown.domain_db_update()
    blacklist_pulldown.ip_db_update()
    whitelisted_domains = set(pd.read_csv(r"whitelisted_domains.csv")["domain"])
    clf = joblib.load(r"phishing_url_model.pkl")

    while True:
            if not all([user, password, mail_server, server_email, server_pass]):
                result = mongodb.verify_password()
                user = result['email']
                password = result['app_pass']
                server_email = result['alert_server_email']
                server_pass = result['alert_server_app_pass']
                user , password , mail_server = server_fetch(user,password)
                
            email_fetchncheck(user, password, mail_server, clf, whitelisted_domains, server_email, server_pass)
            time.sleep(5)
