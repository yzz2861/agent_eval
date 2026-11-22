#!/usr/bin/env python
#-------------------------------------------------------------------------------
# elftools: scripts/syslib_audit.py
#
# Command-line wrapper for the offline system-library audit.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
import os
import sys

# Allow running directly from a source checkout without installation.
sys.path[0:0] = [os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]

from elftools.elf.syslib_audit import main


if __name__ == "__main__":
    sys.exit(main())
