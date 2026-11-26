# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Offline approval verification module alias."""

from in_toto.offline import *  # noqa: F401,F403
from in_toto.offline import (  # noqa: F401
    OfflineApprovalVerifier,
    OfflineVerificationReport,
    verify_approvals,
    verify_offline,
)
