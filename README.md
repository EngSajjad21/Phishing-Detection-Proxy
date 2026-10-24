# Phishing Detection HTTP Proxy

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-GPL--3.0-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
  <img src="https://img.shields.io/badge/PRs-Welcome-orange.svg" alt="PRs Welcome">
</p>

A local HTTP proxy that checks HTTP URLs against Google Safe Browsing and blocks known malicious destinations. HTTPS is supported as a CONNECT tunnel, but its encrypted contents are not decrypted or inspected.

## Features

- HTTP GET, POST, and HEAD forwarding.
- Google Safe Browsing URL checks when `SAFE_BROWSING_API_KEY` is configured.
- Fail-closed behavior when the threat-intelligence service is unavailable.
- HTTPS CONNECT tunneling without TLS interception.
- Dashboard and request logging.

## Quick Start

### Prerequisites

- Python 3.8 or higher.
- A Google Safe Browsing API key for URL checks.

### Installation

```bash
git clone https://github.com/EngSajjad21/Phishing-Detection-Proxy.git
cd Phishing-Detection-Proxy
pip install -r requirements.txt
cp .env.example .env
```

Set the API key in `.env`:

```env
SAFE_BROWSING_API_KEY=your_key_here
```

Start the proxy and dashboard:

```bash
python start.py
```

- Proxy: `http://localhost:8080`
- Dashboard: `http://localhost:8081`

## Testing

Start the system first, then run:

```bash
python -m pytest tests/test_proxy.py
```

The tests require network access and a configured Safe Browsing API key. The proxy does not decrypt HTTPS traffic; it only creates a CONNECT tunnel.

## License

This project is licensed under the GPL-3.0 License. See [LICENSE](LICENSE).

Use this tool only on networks and systems you own or are explicitly authorized to monitor.
