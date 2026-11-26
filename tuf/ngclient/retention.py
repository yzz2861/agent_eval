"""Client-cache retention planning.

The implementation lives in :mod:`tuf.retention`; this module keeps the
client-facing maintenance API next to :class:`tuf.ngclient.Updater`.
"""

from tuf.retention import *  # noqa: F403
from tuf.retention import (
    InstallState,
    Occupancy,
    RetentionPlan,
    RetentionPlanner,
    explain_occupancy,
    plan_offline_retention,
    plan_retention,
    rehearse_directory,
)

__all__ = [
    "InstallState",
    "Occupancy",
    "RetentionPlan",
    "RetentionPlanner",
    "explain_occupancy",
    "plan_offline_retention",
    "plan_retention",
    "rehearse_directory",
]
