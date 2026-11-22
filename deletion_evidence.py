#!/usr/bin/env python
"""Compatibility entry point for samples/deletion_evidence.py."""

from __future__ import absolute_import

import os
import sys

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from Registry.DeletionEvidence import main


if __name__ == "__main__":
    sys.exit(main())
