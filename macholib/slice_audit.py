"""Compatibility entry point for :mod:`macholib.slice_pairing`."""

from __future__ import absolute_import

from .slice_pairing import *  # noqa: F401,F403
from . import slice_pairing as _slice_pairing


if __name__ == "__main__":
    import sys

    sys.exit(_slice_pairing.main())
