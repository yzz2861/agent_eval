# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Approval/rejection vocabulary alias for offline reporting."""

from in_toto.offline import *  # noqa: F401,F403
from in_toto.offline import (  # noqa: F401
    OfflineVerificationReport as ApprovalReport,
)
from in_toto.offline import verify_offline as verify_approvals  # noqa: F401
from in_toto.models.rejection import RejectionTicket  # noqa: F401
