import requests

PROXY_URL = "http://127.0.0.1:8080"
TEST_URLS = {
    "Safe URL (Google)": ("http://www.google.com", 200),
    "Malicious URL (GS Test)": (
        "http://testsafebrowsing.appspot.com/s/phishing.html",
        403,
    ),
    "Malicious URL (Malware)": (
        "http://testsafebrowsing.appspot.com/s/malware.html",
        403,
    ),
}


def test_proxy():
    """Run end-to-end checks against a locally running proxy."""
    proxies = {"http": PROXY_URL, "https": PROXY_URL}
    for name, (url, expected_status) in TEST_URLS.items():
        try:
            response = requests.get(
                url, proxies=proxies, timeout=10, allow_redirects=False
            )
        except requests.RequestException as exc:
            raise AssertionError(
                "Start the proxy with `python start.py` before running this test"
            ) from exc
        assert response.status_code == expected_status, (
            f"{name}: expected {expected_status}, got {response.status_code}"
        )


if __name__ == "__main__":
    test_proxy()
    print("Proxy tests passed.")
