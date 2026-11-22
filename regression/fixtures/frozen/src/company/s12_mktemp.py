import tempfile
def write(data):
    path = tempfile.mktemp()
    open(path, "w").write(data)
    return path
