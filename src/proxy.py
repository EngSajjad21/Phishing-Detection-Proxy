import html
import http.server
import logging
import select
import socket
import socketserver
from datetime import datetime
from urllib.parse import urlsplit

import requests
from colorama import Fore, Style, init

from detector import ThreatDetector

init(autoreset=True)

PORT = 8080
LOG_FILE = "phishing_proxy.log"
BUFFER_SIZE = 64 * 1024

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    detector = ThreatDetector()

    def log_message(self, format_string, *args):
        logging.info("%s - %s", self.address_string(), format_string % args)

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_HEAD(self):
        self._handle_request()

    def do_CONNECT(self):
        """Create a raw tunnel for HTTPS; encrypted contents cannot be inspected."""
        try:
            host, port_text = self.path.rsplit(":", 1)
            port = int(port_text)
            if not host or not 1 <= port <= 65535:
                raise ValueError
            upstream = socket.create_connection((host, port), timeout=10)
        except (ValueError, OSError) as exc:
            logging.warning("CONNECT_FAILED: %s (%s)", self.path, exc)
            self.send_error(502, "Unable to establish HTTPS tunnel")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        logging.info("TUNNEL: %s", self.path)
        try:
            self._relay(self.connection, upstream)
        finally:
            upstream.close()

    @staticmethod
    def _relay(client, upstream):
        sockets = [client, upstream]
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 30)
            if exceptional or not readable:
                return
            for source in readable:
                data = source.recv(BUFFER_SIZE)
                if not data:
                    return
                destination = upstream if source is client else client
                destination.sendall(data)

    def _handle_request(self):
        url = self.path
        if not url.startswith(("http://", "https://")):
            host = self.headers.get("Host")
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
            self._forward_request(url)

    def _forward_request(self, url):
        log_msg = f"ALLOWED: {url}"
        logging.info(log_msg)
        print(f"{Fore.GREEN}[+] {log_msg}")
        try:
            headers = dict(self.headers.items())
            headers.pop("Proxy-Connection", None)
            data = None
            if self.command in {"POST", "PUT", "PATCH"}:
                content_length = int(self.headers.get("Content-Length", 0))
                data = self.rfile.read(content_length)

            response = requests.request(
                self.command,
                url,
                headers=headers,
                data=data,
                stream=True,
                allow_redirects=False,
                timeout=10,
            )
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                if key.lower() not in {
                    "content-encoding",
                    "transfer-encoding",
                    "content-length",
                    "connection",
                }:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(response.content)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response.content)
        except Exception as exc:
            print(f"{Fore.RED}[!] Error forwarding request: {exc}")
            self._send_error_page("Proxy Error", str(exc))

    def _block_request(self, url, reason, details):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"BLOCKED: {url} ({reason})"
        logging.info(log_msg)
        print(f"{Fore.RED}[!] {log_msg}")
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        safe_url = html.escape(url)
        safe_reason = html.escape(reason)
        safe_details = html.escape(details)
        block_page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Access Blocked - Security Warning</title></head><body>
<h1>Warning: Malicious URL Detected!</h1>
<p>The requested URL has been identified as a security threat.</p>
<p><strong>URL:</strong> {safe_url}</p><p><strong>Reason:</strong> {safe_reason}</p>
<p><strong>Details:</strong> {safe_details}</p><p><strong>Time:</strong> {timestamp}</p>
</body></html>"""
        self.wfile.write(block_page.encode("utf-8"))

    def _send_error_page(self, title, message):
        self.send_response(500)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            f"<html><body><h1>{html.escape(title)}</h1>"
            f"<p>{html.escape(message)}</p></body></html>".encode("utf-8")
        )


if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("", PORT), ProxyHTTPRequestHandler) as httpd:
        print(f"{Fore.CYAN}Phishing Detection Proxy listening on port {PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Shutting down proxy server...")
