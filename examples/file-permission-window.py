import os
import shutil
import tempfile


def early_return_before_close():
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(b"secret")
        os.chmod(tmp.name, 0o644)
        return tmp.name


def early_return_after_close():
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(b"secret")
        os.chmod(tmp.name, 0o640)
    return tmp.name


def later_restore_does_not_help():
    fd, name = tempfile.mkstemp()
    os.write(fd, b"secret")
    os.chmod(name, 0o644)
    shutil.copyfile(name, "/srv/shared/report")
    os.chmod(name, 0o600)
    return name


def nested_handles_share_path():
    with tempfile.NamedTemporaryFile() as tmp:
        with open(tmp.name, "wb") as out:
            out.write(b"secret")
        os.chmod(tmp.name, 0o644)
    return tmp.name


def explicit_umask_context(path):
    old = os.umask(0o077)
    try:
        with open(path, "w") as out:
            out.write("secret")
        os.chmod(path, 0o644)
        return path
    finally:
        os.umask(old)


def narrowed_before_publication():
    fd, name = tempfile.mkstemp()
    os.write(fd, b"secret")
    os.chmod(name, 0o644)
    os.chmod(name, 0o600)
    return name


def unrelated_chmod_is_not_correlated():
    fd, name = tempfile.mkstemp()
    os.write(fd, b"secret")
    os.chmod("/srv/shared/other", 0o644)
    return name


def no_restricted_content_written():
    fd, name = tempfile.mkstemp()
    os.chmod(name, 0o644)
    return name


def create_permissive_from_start(path):
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o644)
    os.write(fd, b"secret")
    return path
