import re
import email
import dns.resolver
import os
import logging
import requests
import hashlib
from email import policy
from email.parser import BytesParser

# Configure logging
logging.basicConfig(filename='phishing_email_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def extract_email_headers(raw_email):
    msg = email.message_from_string(raw_email)
    headers = {}
    for key, value in msg.items():
        headers[key] = value
    return headers

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'spf1' in rdata.to_text():
                return True
    except Exception:
        return False
    return False

def check_dkim(headers):
    return 'DKIM-Signature' in headers

def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        for rdata in answers:
            if 'v=DMARC1' in rdata.to_text():
                return True
    except Exception:
        return False
    return False

def check_suspicious_headers(headers):
    suspicious_fields = ['Reply-To', 'Return-Path']
    for field in suspicious_fields:
        if field in headers and headers[field] != headers.get('From', ''):
            return True
    return False

def analyze_email_headers(raw_email, filename="Unknown Email"):
    headers = extract_email_headers(raw_email)
    domain = headers.get('From', '').split('@')[-1]
    subject = headers.get('Subject', 'No Subject')
    
    spf_valid = check_spf(domain)
    dkim_valid = check_dkim(headers)
    dmarc_valid = check_dmarc(domain)
    suspicious_headers = check_suspicious_headers(headers)
    
    phishing_reasons = []
    if not spf_valid:
        phishing_reasons.append("SPF validation failed")
    if not dkim_valid:
        phishing_reasons.append("DKIM signature missing")
    if not dmarc_valid:
        phishing_reasons.append("DMARC policy not found")
    if suspicious_headers:
        phishing_reasons.append("Suspicious headers detected")
    
    if phishing_reasons:
        log_message = f"Phishing email detected: {filename} (Subject: {subject}) - Reasons: {', '.join(phishing_reasons)}"
        logging.warning(log_message)
        return log_message
    
    log_message = f"Email headers seem safe: {filename} (Subject: {subject})"
    logging.info(log_message)
    return log_message

def analyze_bulk_emails(directory):
    results = {}
    for filename in os.listdir(directory):
        if filename.endswith(".eml"):
            with open(os.path.join(directory, filename), "rb") as file:
                raw_email = file.read().decode(errors='ignore')
                results[filename] = analyze_email_headers(raw_email, filename)
    return results

# Example usage for a single email
raw_email = """From: fake@phishing.com\nReply-To: attacker@malicious.com\nReturn-Path: attacker@malicious.com\nSubject: Urgent: Verify Your Account Now!\n\nClick here to verify: http://malicious.com"""

result = analyze_email_headers(raw_email, "test_email.eml")
print(result)

# Example usage for bulk emails
# Provide the directory containing .eml files
# email_results = analyze_bulk_emails("/path/to/emails")
# for email, status in email_results.items():
#     print(f"{email}: {status}")
