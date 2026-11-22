# Copyright 2021-2025, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client public API."""

from tuf.api.metadata import TargetFile
from tuf.ngclient.config import UpdaterConfig
from tuf.ngclient.fetcher import FetcherInterface
from tuf.ngclient.remediation import (
    CompatibilityTable,
    Device,
    RemediationPlan,
    RemediationPlanner,
    VerifiedTargetView,
    plan_remediation,
)
from tuf.ngclient.updater import Updater
from tuf.ngclient.urllib3_fetcher import Urllib3Fetcher

__all__ = [  # noqa: PLE0604
    CompatibilityTable.__name__,
    Device.__name__,
    FetcherInterface.__name__,
    RemediationPlan.__name__,
    RemediationPlanner.__name__,
    Urllib3Fetcher.__name__,
    TargetFile.__name__,
    Updater.__name__,
    UpdaterConfig.__name__,
    VerifiedTargetView.__name__,
    plan_remediation.__name__,
]
