import os
def fetch(host, path):
    return os.system("wget http://%s%s" % (host, path))
