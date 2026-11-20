"""Syntax only newer host grammars accept.

Pattern matching needs Python 3.10 or newer, so an older target rejects the
whole file before any rule can run.  The explicit nosec only suppresses
B602; B404 on the import remains visible.
"""
import subprocess


def run_command(cmd):
    match cmd:
        case ["run", target]:
            subprocess.call(target, shell=True)  # nosec: B602
        case _:
            subprocess.call(cmd, shell=True)
