#!/usr/bin/env python
"""
Test script for sending simulated phishing emails to the API
Run with: python test_email.py
"""
import requests
import json
import sys

# Configuration
API_URL = "http://127.0.0.1:5000/test_phishing_email"

# Test emails with various phishing patterns
TEST_EMAILS = [
    {
        "subject": "Your PayPal account has been limited",
        "sender": "service@paypal-secure.com",
        "body_html": """
        <html>
        <body>
            <p>Dear valued customer,</p>
            <p>Your PayPal account has been limited due to suspicious activity. Please verify your information by clicking on the link below:</p>
            <p><a href="http://paypal-secure.accounts-verify.com/login">Verify Account</a></p>
            <p>If you don't verify your account within 24 hours, your account will be suspended.</p>
            <p>Thank you,<br>PayPal Security Team</p>
        </body>
        </html>
        """
    },
    {
        "subject": "Netflix: Update your payment information",
        "sender": "info@netf1ix-billing.com",
        "body_html": """
        <html>
        <body>
            <p>Hello,</p>
            <p>We're having trouble with your current billing information. Please update your payment method by clicking the link below:</p>
            <p><a href="http://netflix-account-verify.secure-billing.com/update">Update Payment Information</a></p>
            <p>If you don't update your payment information, your subscription will be canceled.</p>
            <p>Netflix</p>
        </body>
        </html>
        """
    },
    {
        "subject": "Test Google Safe Browsing Detection",
        "sender": "test@example.com",
        "body_html": """
        <html>
        <body>
            <p>This is a test email with Google's test malware URL:</p>
            <p><a href="http://testsafebrowsing.appspot.com/s/malware.html">Test Malware Link</a></p>
            <p>And a test phishing URL:</p>
            <p><a href="http://testsafebrowsing.appspot.com/s/phishing.html">Test Phishing Link</a></p>
        </body>
        </html>
        """
    },
    {
        "subject": "Your bank account has been suspended",
        "sender": "security@bank-secure-login.com",
        "body_html": """
        <html>
        <body>
            <p>Dear customer,</p>
            <p>Your bank account has been temporarily suspended due to multiple failed login attempts.</p>
            <p>Please verify your identity by clicking on the link below:</p>
            <p><a href="http://bank-secure-login.com/webscr.php?cmd=_login-submit">Verify Identity</a></p>
            <p>Bank Security Team</p>
        </body>
        </html>
        """
    },
    {
        "subject": "Test Multiple Suspicious Patterns",
        "sender": "test@test.com",
        "urls": [
            "http://192.168.1.1/login.php",
            "http://secure-login-paypal.com@evil.com",
            "http://d0cum3nt-v3r1fy.example.com/login.php",
            "http://bit.ly/3xR5tY8",
            "http://example.com/login.php?password=reset&token=expired&account=verify"
        ]
    }
]

def test_email(email_data):
    """Test a simulated phishing email against the API"""
    try:
        response = requests.post(
            API_URL,
            json=email_data,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            return
        
        result = response.json()
        
        # Print email details
        print("\n===== EMAIL =====")
        print(f"Subject: {result['subject']}")
        print(f"Sender: {result['sender']}")
        print(f"URLs found: {result['urls_found']}")
        
        # Print detection results
        print("\n===== DETECTION RESULTS =====")
        print(f"Would be moved to Phishing folder: {'YES' if result['would_be_moved_to_phishing'] else 'NO'}")
        print(f"Malicious URLs: {result['malicious_urls']}/{result['urls_found']}")
        print(f"High confidence detections: {result['high_confidence_malicious']}")
        print(f"Safe Browsing detections: {result['safe_browsing_detected']}")
        print(f"Detection source: {result['detection_source']}")
        
        # Print URL details
        print("\n===== URL DETAILS =====")
        for url_data in result["urls"]:
            status = "🚨 MALICIOUS" if url_data.get("is_malicious") else "✅ SAFE"
            confidence = " (HIGH CONFIDENCE)" if url_data.get("high_confidence") else ""
            source = f" [{url_data.get('detection_source', 'unknown').upper()}]"
            
            print(f"{status}{confidence}{source}: {url_data.get('url')}")
            print(f"  - RF: {url_data.get('classification_rf')} ({url_data.get('rf_confidence', 0):.3f})")
            print(f"  - SVM: {url_data.get('classification_svm')} ({url_data.get('svm_confidence', 0):.3f})")
            
            if url_data.get("safe_browsing_checked"):
                sb_result = "No threats found" if not url_data.get("safe_browsing_threats") else ", ".join(url_data.get("safe_browsing_threats"))
                print(f"  - Safe Browsing: {sb_result}")
            
            print()
        
    except Exception as e:
        print(f"Error testing email: {e}")

def test_all_emails():
    """Test all predefined phishing email templates"""
    for i, email in enumerate(TEST_EMAILS):
        print(f"\n\n========== TEST EMAIL {i+1}/{len(TEST_EMAILS)} ==========")
        test_email(email)

if __name__ == "__main__":
    # Test all emails
    test_all_emails()