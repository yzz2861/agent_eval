#!/usr/bin/env python
r"""Read-only deletion evidence query for two SOFTWARE hive snapshots.

Example:

    python samples/deletion_evidence.py \
        --before before.SOFTWARE \
        --after after.SOFTWARE \
        --key 'SOFTWARE\Microsoft\Example\Agent' \
        --value Policy \
        --log after.SOFTWARE.LOG1 \
        --format markdown

The analyzer never writes to the hive or transaction-log inputs.  It compares
the target value's VK cell and data cell across snapshots and correlates any
supplied HvLE transaction batches by sequence number and dirty-page coverage.
"""

from __future__ import absolute_import

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from Registry.DeletionEvidence import main


if __name__ == "__main__":
    sys.exit(main())
