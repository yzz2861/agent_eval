# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Pytest bootstrap to ensure the checkout is imported."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
