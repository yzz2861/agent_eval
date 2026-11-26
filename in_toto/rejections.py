# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Plural module alias for offline rejection-ticket APIs."""

from in_toto.offline import *  # noqa: F401,F403
from in_toto.offline import (  # noqa: F401
    OfflineVerificationReport,
    RejectionTicket,
    verify_offline,
    verify_rejection_tickets,
)
