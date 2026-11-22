#!/usr/bin/env python

"""Compatibility import surface for cross-version scope audits."""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from .scope import *  # noqa: F401,F403
from .scope import __all__  # noqa: F401


if __name__ == "__main__":
    import sys

    sys.exit(main())
