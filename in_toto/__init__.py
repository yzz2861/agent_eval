# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
Configure base logger for in_toto (see in_toto.log for details).

"""

import in_toto.log

# in-toto version
__version__ = "3.0.0"

_OFFLINE_EXPORTS = {
    "OfflineVerificationReport",
    "OfflineVerificationError",
    "RejectionTicket",
    "RejectionReceipt",
    "RejectionVote",
    "VetoTicket",
    "verify_offline",
}


def __getattr__(name):
    if name in _OFFLINE_EXPORTS:
        from in_toto import offline

        return getattr(offline, name)
    if name == "OfflineVerificationError":
        from in_toto.exceptions import OfflineVerificationError

        return OfflineVerificationError
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
