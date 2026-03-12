import http.server
import socketserver
import json
import os

PORT = 8081
LOG_FILE = "phishing_proxy.log"

class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            
            with open('src/dashboard.html', 'r') as f:
                self.wfile.write(f.read().encode('utf-8'))
        
        elif self.path == '/api/logs':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            logs = []
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r') as f:
                    # Return last 50 logs
                    logs = f.readlines()[-50:]
            
            self.wfile.write(json.dumps(logs).encode('utf-8'))
        else:
            self.send_error(404)

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), DashboardHandler) as httpd:
        print(f"Dashboard available at http://localhost:{PORT}")
        httpd.serve_forever()
