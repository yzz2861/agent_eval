#
# SPDX-License-Identifier: Apache-2.0
"""Compatibility alias for :mod:`bandit.cli.attribution`."""

from bandit.cli.attribution import main

__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
