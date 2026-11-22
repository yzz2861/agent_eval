import ssl
def client():
    return ssl._create_unverified_context()
