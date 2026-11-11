import subprocess
from subprocess import call as c

c("/bin/echo hi", shell=True)  # B602: resolves to subprocess.call


def param_shadow(c):
    c("/bin/echo hi")  # the parameter shadows the import


def local_import():
    import os

    os.system("/bin/echo hi")  # B605: local import resolves to os.system


def nested_function():
    def inner():
        c("/bin/echo hi", shell=True)  # B602: nested functions see imports

    inner()


def nested_shadow():
    c = print

    def inner():
        c("/bin/echo hi")  # the enclosing local shadows the import

    inner()


class ClassScope:
    import os as class_os

    class_os.system("/bin/echo hi")  # B605: class body sees class-level import

    def method(self):
        class_os.system("/bin/echo hi")  # class names are not method closures
        c("/bin/echo hi", shell=True)  # B602: methods still see module imports


def comprehension_shadow():
    [c("/bin/echo hi") for c in ["not", "an", "import"]]


def except_shadow():
    try:
        pass
    except Exception as c:
        c("/bin/echo hi")  # the exception handler binding shadows the import


def nonlocal_rebind():
    from subprocess import call as nc

    def inner():
        nonlocal nc
        nc = print

    inner()
    nc("/bin/echo hi", shell=True)  # rebound through nonlocal: origin unknown


def global_rebind():
    global c
    c = print


global_rebind()
c("/bin/echo hi", shell=True)  # rebound through global: origin unknown

from subprocess import call as cond_c

if cond_c is None:
    cond_c = print

cond_c("/bin/echo hi", shell=True)  # conditionally rebound: origin unknown

from subprocess import *

call("/bin/echo hi", shell=True)  # star import: origin unknown
