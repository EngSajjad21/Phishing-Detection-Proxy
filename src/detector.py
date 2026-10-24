import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()


class ThreatDetector:
    def __init__(self):
        self.api_key = os.getenv("SAFE_BROWSING_API_KEY")
        self.enabled = bool(self.api_key)
        self.cache = {}
        if not self.enabled:
            print("[!] Warning: No SAFE_BROWSING_API_KEY found in .env. URL checking is disabled.")

    def is_malicious(self, url):
        """Return (blocked, reason, details), failing closed when the API is unavailable."""
        if not self.enabled:
            return False, "API_DISABLED", "No Safe Browsing API key configured"
        if url in self.cache:
            return self.cache[url]

        endpoint = (
            "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={self.api_key}"
        )
        payload = {
            "client": {"clientId": "phishing-proxy", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["WINDOWS", "LINUX", "ANDROID", "OSX", "IOS"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            response = requests.post(endpoint, json=payload, timeout=5)
            response.raise_for_status()
            data = response.json()
            if "matches" in data and data["matches"]:
                match = data["matches"][0]
                reason = match.get("threatType", "MALICIOUS")
                result = (True, reason, f"Identified as {reason}")
            else:
                result = (False, "SAFE", "No matches found")
            self.cache[url] = result
            return result
        except (requests.RequestException, ValueError) as exc:
            logging.error("Safe Browsing lookup failed for %s: %s", url, exc)
            return True, "CHECK_FAILED", "Threat intelligence service unavailable"
