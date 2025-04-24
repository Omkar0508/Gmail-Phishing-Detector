#!/usr/bin/env python
"""
Test script for directly analyzing URLs through the API
Run with: python test_urls.py
"""
import requests
import json
import sys

# Configuration
API_URL = "http://127.0.0.1:5000/test_urls"

# Test URLs from various categories
TEST_URLS = [
    # Google's test URLs
    "http://testsafebrowsing.appspot.com/s/phishing.html",
    "http://testsafebrowsing.appspot.com/s/malware.html",
    "http://malware.testing.google.test/testing/malware/",
    
    # URLs with suspicious patterns
    "http://192.168.1.1/login.php",
    "http://paypal-secure.accounts-verify.com/login",
    "http://bank-secure-login.com/webscr.php?cmd=_login-submit",
    "http://www.amazonsecure.signin.userid.5549.validate-billing.com", 
    "http://d0cum3nt-v3r1fy.example.com/login.php",
    "http://secure-login-paypal.com@evil.com",
    "http://www.verify-account.com/session=expired/login/secure/",
    "http://download.free-antivirus2025.com/update.exe",
    
    # Suspicious query parameters
    "http://example.com/login.php?password=reset&token=expired&account=verify",
    "http://banking-secure.com/login?cmd=_login-submit&dispatch=5885d80a13c0db1f8e263663d3faee8d",
    
    # Multi-feature URLs
    "http://free.lucky.prize.verify-account.example.com",
    "http://signin.account.secure.update.example.com",
    "http://bit.ly/3xR5tY8",
    "http://example.com//////////admin/////login.php",
    
    # Safe URLs for comparison
    "https://google.com",
    "https://github.com",
    "https://microsoft.com"
]

def test_urls(urls):
    """Test a list of URLs against the API"""
    try:
        response = requests.post(
            API_URL,
            json={"urls": urls},
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            return
        
        results = response.json()
        
        # Print summary
        print("\n===== RESULTS SUMMARY =====")
        print(f"URLs analyzed: {results['analysis_details']['urls_analyzed']}")
        print(f"Malicious detected: {results['analysis_details']['malicious_detected']}")
        print(f"High confidence detections: {results['analysis_details']['high_confidence']}")
        
        # Print details for each URL
        print("\n===== DETAILED RESULTS =====")
        for url, result in results["results"].items():
            status = "🚨 MALICIOUS" if result.get("is_malicious") else "✅ SAFE"
            confidence = " (HIGH CONFIDENCE)" if result.get("high_confidence") else ""
            source = f" [{result.get('detection_source', 'unknown').upper()}]"
            
            print(f"{status}{confidence}{source}: {url}")
            print(f"  - RF: {result.get('classification_rf')} ({result.get('rf_confidence', 0):.3f})")
            print(f"  - SVM: {result.get('classification_svm')} ({result.get('svm_confidence', 0):.3f})")
            
            if result.get("safe_browsing_checked"):
                sb_result = "No threats found" if not result.get("safe_browsing_threats") else ", ".join(result.get("safe_browsing_threats"))
                print(f"  - Safe Browsing: {sb_result}")
            
            print()
        
    except Exception as e:
        print(f"Error testing URLs: {e}")

if __name__ == "__main__":
    # Use command line arguments if provided, otherwise use default test URLs
    urls_to_test = sys.argv[1:] if len(sys.argv) > 1 else TEST_URLS
    test_urls(urls_to_test)