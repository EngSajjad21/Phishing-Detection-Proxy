import requests
import logging
import os
from dotenv import load_dotenv

load_dotenv()

class ThreatDetector:
    def __init__(self):
        self.api_key = os.getenv("SAFE_BROWSING_API_KEY")
        self.enabled = bool(self.api_key)
        self.cache = {}
        
        if not self.enabled:
            print("[!] Warning: No SAFE_BROWSING_API_KEY found in .env. URL checking will be bypassed.")

    def is_malicious(self, url):
        """
        Checks if a URL is malicious using Google Safe Browsing API.
        Returns: (is_malicious: bool, reason: str, details: str)
        """
        if not self.enabled:
            return False, "API Disabled", "API key missing"

        if url in self.cache:
            return self.cache[url]

        # Google Safe Browsing API lookup
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {
                "clientId": "phishing-proxy",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["WINDOWS", "LINUX", "ANDROID", "OSX", "IOS"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            response = requests.post(endpoint, json=payload, timeout=5)
            data = response.json()

            if "matches" in data:
                match = data["matches"][0]
                reason = match.get("threatType", "MALICIOUS")
                result = (True, reason, f"Identified as {reason}")
            else:
                result = (False, "Safe", "No matches found")
            
            self.cache[url] = result
            return result

        except Exception as e:
            logging.error(f"Error checking threat for {url}: {e}")
            return False, "Error", str(e)
