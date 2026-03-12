import requests
import time
import sys

PROXY_URL = "http://127.0.0.1:8080"
TEST_URLS = {
    "Safe URL (Google)": "http://www.google.com",
    "Malicious URL (GS Test)": "http://testsafebrowsing.appspot.com/s/phishing.html",
    "Malicious URL (Malware)": "http://testsafebrowsing.appspot.com/s/malware.html"
}

def test_proxy():
    print("🧪 Starting Proxy Tests...")
    print("Make sure the proxy is running on localhost:8080\n")
    
    proxies = {
        "http": PROXY_URL,
        "https": PROXY_URL,
    }

    for name, url in TEST_URLS.items():
        print(f"Testing {name}: {url}")
        try:
            # We use allow_redirects=False to see the proxy's direct response
            response = requests.get(url, proxies=proxies, timeout=10, allow_redirects=False)
            
            if response.status_code == 403:
                print(f"🛑 [BLOCKED] Status: {response.status_code} - Correctly blocked.")
            elif response.status_code == 200:
                print(f"✅ [ALLOWED] Status: {response.status_code} - Correctly allowed.")
            else:
                print(f"ℹ️ [INFO] Status: {response.status_code}")
                
        except Exception as e:
            print(f"❌ [ERROR] Could not connect to proxy: {e}")
            break
        print("-" * 30)

if __name__ == "__main__":
    test_proxy()
