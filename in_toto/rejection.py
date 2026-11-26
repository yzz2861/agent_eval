# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Singular module alias for rejection ticket APIs."""

from in_toto.models.rejection import (  # noqa: F401
    RejectionReceipt,
    RejectionTicket,
    RejectionVote,
    VetoTicket,
)
from in_toto.offline import (  # noqa: F401
    OfflineVerificationReport,
    verify_offline,
    verify_rejection_ticket,
    verify_rejection_tickets,
)
