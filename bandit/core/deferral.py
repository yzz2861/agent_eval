# SPDX-License-Identifier: Apache-2.0
"""Compatibility import for :mod:`bandit.core.triage`.

The deferral queue and responsibility allocation live together in
``bandit.core.triage``; this module keeps the shorter integration name
available without duplicating the implementation.
"""

from bandit.core.triage import *  # noqa: F401,F403
from bandit.core.triage import __all__  # noqa: F401
