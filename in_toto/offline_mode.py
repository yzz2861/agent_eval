# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Alternate module name for offline verification support."""

from in_toto.offline import *  # noqa: F401,F403
from in_toto.offline import (  # noqa: F401
    OfflineVerificationReport,
    verify_offline,
)
