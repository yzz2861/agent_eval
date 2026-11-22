import hashlib
def digest(data):
    return hashlib.sha1(data).hexdigest()
