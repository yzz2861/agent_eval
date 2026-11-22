"""Compatibility alias for :mod:`pcapng.review`."""

from pcapng.review import *  # noqa: F401,F403
from pcapng.review import __all__  # noqa: F401
from pcapng.review import main  # noqa: F401


if __name__ == "__main__":
    raise SystemExit(main())
