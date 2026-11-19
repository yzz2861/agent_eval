#!/usr/bin/env python3
"""Offline runner for the pefuzz regression suite.

Usage:
    python run_offline_tests.py

The runner pins pytest to the local test tree so that rootdir discovery
never attempts to stat sandbox-restricted parent directories.  Everything
runs from synthetic in-memory PE images and completes in well under thirty
seconds with no network access.
"""

import subprocess
import sys


def main():
    command = [
        sys.executable,
        "-m",
        "pytest",
        "tests/pefuzz_regression_test.py",
        "-p",
        "no:cacheprovider",
        "--import-mode=importlib",
        "--rootdir=.",
        "--confcutdir=tests",
        "-q",
    ]
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
