import subprocess
import time
import sys

def main():
    print("🚀 Starting Phishing Detection Proxy System...")
    
    try:
        # Start Proxy
        proxy_proc = subprocess.Popen([sys.executable, "src/proxy.py"])
        print("✅ Proxy Server started (Port 8080)")
        
        # Start Dashboard
        dash_proc = subprocess.Popen([sys.executable, "src/dashboard_server.py"])
        print("✅ Dashboard Server started (Port 8081)")
        
        print("\nPress Ctrl+C to stop both servers.\n")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Stopping servers...")
        proxy_proc.terminate()
        dash_proc.terminate()
        print("Done.")

if __name__ == "__main__":
    main()
