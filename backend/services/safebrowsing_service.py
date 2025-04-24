# services/safebrowsing_service.py
import requests
import os
import json
import logging
from typing import List, Dict, Any
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class SafeBrowsingAPI:
    """Interface for Google Safe Browsing API"""
    
    def __init__(self, api_key=None):
        """Initialize the Safe Browsing API client"""
        self.api_key = api_key or os.getenv("GOOGLE_SAFEBROWSING_API_KEY")
        if not self.api_key:
            logger.warning("Google Safe Browsing API key not found. Safe Browsing checks will be disabled.")
        
        self.api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.threat_types = [
            "MALWARE", 
            "SOCIAL_ENGINEERING",  # Phishing
            "UNWANTED_SOFTWARE", 
            "POTENTIALLY_HARMFUL_APPLICATION"
        ]
        self.platform_types = ["ANY_PLATFORM"]
        self.threat_entry_types = ["URL"]
    
    def check_urls(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Check a list of URLs against Google Safe Browsing API
        
        Args:
            urls: List of URLs to check
            
        Returns:
            Dictionary mapping each URL to its safety status
            {
                "http://example.com": {
                    "is_safe": True/False,
                    "threats": [] or list of threat types,
                    "checked": True/False (if API was unavailable)
                }
            }
        """
        if not self.api_key:
            # Return all URLs as unchecked if no API key
            return {url: {"is_safe": True, "threats": [], "checked": False} for url in urls}
        
        # Remove duplicates and empty URLs
        unique_urls = list(set(url for url in urls if url))
        if not unique_urls:
            return {}
        
        # Prepare results with default values
        results = {url: {"is_safe": True, "threats": [], "checked": False} for url in unique_urls}
        
        try:
            # Batch URLs (Google recommends max 500 URLs per request)
            batch_size = 500
            for i in range(0, len(unique_urls), batch_size):
                batch_urls = unique_urls[i:i+batch_size]
                batch_results = self._check_url_batch(batch_urls)
                
                # Update results with batch findings
                for url, result in batch_results.items():
                    results[url] = result
            
            return results
        
        except Exception as e:
            logger.error(f"Error checking URLs with Safe Browsing API: {e}")
            # On error, mark all URLs as not checked but safe by default
            return {url: {"is_safe": True, "threats": [], "checked": False} for url in unique_urls}
    
    def _check_url_batch(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """Check a batch of URLs against the Safe Browsing API"""
        # Prepare the request payload
        payload = {
            "client": {
                "clientId": "gmail-phishing-detector",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": self.threat_types,
                "platformTypes": self.platform_types,
                "threatEntryTypes": self.threat_entry_types,
                "threatEntries": [{"url": url} for url in urls]
            }
        }
        
        # Initialize all URLs as safe
        results = {url: {"is_safe": True, "threats": [], "checked": True} for url in urls}
        
        try:
            # Make API request
            response = requests.post(
                f"{self.api_url}?key={self.api_key}",
                json=payload,
                timeout=10  # Timeout after 10 seconds
            )
            
            # Check response
            if response.status_code == 200:
                data = response.json()
                
                # Process matches if any
                if "matches" in data:
                    for match in data["matches"]:
                        url = match.get("threat", {}).get("url")
                        if url and url in results:
                            threat_type = match.get("threatType")
                            results[url]["is_safe"] = False
                            results[url]["threats"].append(threat_type)
            else:
                logger.error(f"Safe Browsing API error: {response.status_code} - {response.text}")
                # Mark all URLs as checked but with a warning
                for url in urls:
                    results[url]["api_error"] = f"Status code: {response.status_code}"
            
            return results
            
        except requests.RequestException as e:
            logger.error(f"Safe Browsing API request failed: {e}")
            # Mark all URLs as not checked on API error
            return {url: {"is_safe": True, "threats": [], "checked": False} for url in urls}

# Singleton instance
_safe_browsing_api = None

def get_safe_browsing_api():
    """Get or create the Safe Browsing API singleton instance"""
    global _safe_browsing_api
    if _safe_browsing_api is None:
        _safe_browsing_api = SafeBrowsingAPI()
    return _safe_browsing_api

# Example usage
if __name__ == "__main__":
    # Test the API with some example URLs
    api = get_safe_browsing_api()
    test_urls = [
        "https://google.com",
        "http://malware.testing.google.test/testing/malware/",  # Google's test URL that should trigger detection
        "https://github.com",
    ]
    results = api.check_urls(test_urls)
    print(json.dumps(results, indent=2))