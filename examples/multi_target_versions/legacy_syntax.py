"""Syntax accepted by both the oldest and the host target.

The blanket nosec keeps B602 visible but marks it suppressed on every
target that can parse this file.
"""
import subprocess


def run_command(cmd):
    subprocess.call(cmd, shell=True)  # nosec
