#!/usr/bin/env python
# vim: set et ai ts=4 sts=4 sw=4:
"""Command-line entry point for the certificate de-duplication preflight."""

from __future__ import print_function
import sys

from jks.cert_dedup import main


if __name__ == "__main__":
    sys.exit(main())
