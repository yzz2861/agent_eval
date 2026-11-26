# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
Configure base logger for in_toto (see in_toto.log for details).

"""

import in_toto.log
from in_toto.handoff import (
    HandoffReviewer,
    MinimalWitness,
    OfflineHandoffReview,
    handoff_review,
    minimal_supplement,
    offline_handoff_review,
    reconstruct_handoff,
    review_handoff,
)
from in_toto.handoff import (
    Report as HandoffReport,
)

# in-toto version
__version__ = "3.0.0"


def __getattr__(name):
    lowered = name.lower()
    if any(
        token in lowered
        for token in ("handoff", "handover", "minimal_supplement")
    ):
        return (
            review_handoff
            if "supplement" not in lowered
            else minimal_supplement
        )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
