import http.server
import socketserver
import requests
import logging
from datetime import datetime
from colorama import Fore, Style, init
from detector import ThreatDetector

# Initialize colorama
init(autoreset=True)

# Configuration
PORT = 8080
LOG_FILE = "phishing_proxy.log"

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    detector = ThreatDetector()

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def _handle_request(self):
        url = self.path
        if not url.startswith("http"):
            # Handle cases where path doesn't include scheme (common in proxy requests)
            host = self.headers.get('Host')
            if host:
                url = f"http://{host}{url}"
            else:
                self._send_error_page("Invalid URL", "Could not determine host")
                return

        print(f"{Fore.CYAN}[*] Processing request: {url}")
        
        is_malicious, reason, details = self.detector.is_malicious(url)

        if is_malicious:
            self._block_request(url, reason, details)
        else:
            self._forward_request()

    def _forward_request(self):
        log_msg = f"ALLOWED: {self.path}"
        logging.info(log_msg)
        print(f"{Fore.GREEN}[+] {log_msg}")
        
        # Simple forwarding
        try:
            headers = {key: value for key, value in self.headers.items()}
            # Remove proxy-specific headers
            headers.pop('Proxy-Connection', None)
            
            method = self.command
            data = None
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                data = self.rfile.read(content_length)

            resp = requests.request(
                method, 
                self.path, 
                headers=headers, 
                data=data, 
                stream=True, 
                allow_redirects=False,
                timeout=10
            )

            self.send_response(resp.status_code)
            for key, value in resp.headers.items():
                if key.lower() not in ['content-encoding', 'transfer-encoding', 'content-length', 'connection']:
                     self.send_header(key, value)
            
            self.end_headers()
            self.wfile.write(resp.content)

        except Exception as e:
            print(f"{Fore.RED}[!] Error forwarding request: {e}")
            self._send_error_page("Proxy Error", str(e))

    def _block_request(self, url, reason, details):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"BLOCKED: {url} ({reason})"
        logging.info(log_msg)
        print(f"{Fore.RED}[!] {log_msg}")

        self.send_response(403)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        block_page = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access Blocked - Security Warning</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #1a1a1a;
                    color: #fff;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }}
                .container {{
                    background-color: #2d2d2d;
                    padding: 40px;
                    border-radius: 12px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
                    text-align: center;
                    max-width: 600px;
                    border-top: 5px solid #ff4d4d;
                }}
                h1 {{ color: #ff4d4d; margin-top: 0; }}
                .url {{ font-weight: bold; color: #ffa333; word-break: break-all; }}
                .details {{ margin: 20px 0; font-size: 1.1em; color: #ddd; }}
                .footer {{ margin-top: 30px; font-size: 0.8em; color: #888; }}
                .icon {{ font-size: 50px; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">⚠️</div>
                <h1>Warning: Malicious URL Detected!</h1>
                <p class="details">The requested URL has been identified as a security threat.</p>
                <p><strong>URL:</strong> <span class="url">{url}</span></p>
                <p><strong>Reason:</strong> {reason}</p>
                <p><strong>Time:</strong> {timestamp}</p>
                <div class="footer">
                    This request was intercepted and blocked by the Phishing Detection Proxy to protect your system.
                </div>
            </div>
        </body>
        </html>
        """
        self.wfile.write(block_page.encode('utf-8'))

    def _send_error_page(self, title, message):
        self.send_response(500)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        error_html = f"<html><body><h1>{title}</h1><p>{message}</p></body></html>"
        self.wfile.write(error_html.encode('utf-8'))

if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("", PORT), ProxyHTTPRequestHandler) as httpd:
        print(f"{Fore.CYAN}===============================================")
        print(f"{Fore.CYAN}   Phishing Detection Proxy is Running")
        print(f"{Fore.CYAN}   Listening on port: {PORT}")
        print(f"{Fore.CYAN}===============================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Shutting down proxy server...")
            httpd.server_close()
