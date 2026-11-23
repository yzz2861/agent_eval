#
# SPDX-License-Identifier: Apache-2.0
"""Consume a Bandit JSON report and attribute findings to code owners."""

from bandit.core import attribution


def main(argv=None):
    """Run the attribution report consumer."""
    return attribution.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
