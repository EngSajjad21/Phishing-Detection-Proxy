# <p align="center">🛡️ Phishing Detection HTTP Proxy</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-GPL--3.0-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen.svg" alt="Status">
  <img src="https://img.shields.io/badge/PRs-Welcome-orange.svg" alt="PRs Welcome">
</p>

<p align="center">
  <b>A professional cybersecurity tool to protect users from malicious web threats in real-time.</b>
</p>

---

## 📖 Overview

The **Phishing Detection HTTP Proxy** acts as a smart intermediary between your browser and the internet. It intercepts HTTP requests, analyzes requested URLs using the **Google Safe Browsing API**, and blocks dangerous links (phishing, malware, social engineering) before they reach your system.

### ✨ Key Features
- 🚀 **Real-time Interception**: Captures GET/POST requests instantly.
- 🔍 **Threat Intelligence**: Powered by Google Safe Browsing API.
- 🛑 **Secure Blocking**: Displays a premium warning page for malicious URLs.
- 📊 **Monitoring Dashboard**: Live web interface to track all network activity.
- 📝 **Detailed Logging**: Audits all requests with timestamps and threat types.
- 🎨 **Visual Feedback**: Color-coded terminal output for security auditing.

---

## 🚀 Quick Start

### 1️⃣ Prerequisites
- Python 3.8 or higher.
- A **Google Safe Browsing API Key**. [Get it here](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com).

### 2️⃣ Installation
```bash
# Clone the repository
git clone https://github.com/EngSajjad21/Phishing-Detection-Proxy.git
cd Phishing-Detection-Proxy

# Install dependencies
pip install -r requirements.txt
```

### 3️⃣ Configuration
1. Rename `.env.example` to `.env`.
2. Open `.env` and add your API key:
   ```env
   SAFE_BROWSING_API_KEY=your_key_here
   ```

### 4️⃣ Execution
Run both the proxy and dashboard with a single command:
```bash
python start.py
```

- **Proxy Address**: `http://localhost:8080`
- **Dashboard**: `http://localhost:8081`

---

## 🛠️ Testing the Tool
We have included a dedicated test suite to verify the proxy's effectiveness:
```bash
python tests/test_proxy.py
```

---

## 🖥️ Dashboard Preview
The dashboard provides a real-time view of your network security status, highlighting blocked threats in red and safe traffic in green.

---

## 📜 License & Rights
This project is licensed under the **GPL-3.0 License**.  
Developed with ❤️ by **Eng. Sajjad** and **Antigravity AI**.

> [!IMPORTANT]
> This tool is for educational and security enhancement purposes. Always ensure you have permission to monitor network traffic in your environment.

---

## 🤝 Contributing
Contributions are welcome! If you have ideas for improvements (like HTTPS support or custom threat databases), feel free to open a Pull Request.

<p align="center">
  <img src="https://img.shields.io/github/stars/EngSajjad21/Phishing-Detection-Proxy?style=social" alt="GitHub stars">
</p>
