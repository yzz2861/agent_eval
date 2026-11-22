"""Compatibility import for :mod:`jks.cert_dedup`."""

from __future__ import print_function
import sys

from .cert_dedup import *  # noqa: F401,F403
from .cert_dedup import main


if __name__ == "__main__":
    sys.exit(main())
