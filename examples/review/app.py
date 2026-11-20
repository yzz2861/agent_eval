import hashlib
import subprocess

def build(token):
    digest = hashlib.md5(token).hexdigest()
    return subprocess.check_output(token, shell=True)
