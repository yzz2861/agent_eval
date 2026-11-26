from dataclasses import replace
from datetime import datetime

import pytest
from packaging.version import Version

from pip_audit._offline.model import (
    AdvisoryRecord,
    AdvisoryStatus,
    DeploymentRecord,
    Snapshot,
)


@pytest.fixture()
def timestamps():
    return {
        "oct25": datetime(2026, 10, 25),
        "oct26": datetime(2026, 10, 26),
        "nov1": datetime(2026, 11, 1),
        "nov2": datetime(2026, 11, 2),
        "nov3": datetime(2026, 11, 3),
        "nov5": datetime(2026, 11, 5),
    }


@pytest.fixture()
def old_advisory(timestamps):
    return AdvisoryRecord(
        id="PYSEC-OLD",
        package="foo",
        affected_range=">=1.0,<1.1",
        description="known before the report",
        fix_versions=[Version("1.1.0")],
        aliases={"CVE-OLD"},
        effective_at=timestamps["oct25"],
        received_at=timestamps["oct26"],
    )


@pytest.fixture()
def late_advisory(timestamps):
    return AdvisoryRecord(
        id="PYSEC-LATE",
        package="foo",
        affected_range=">=1.0,<1.2",
        description="effective Nov 1, received Nov 3",
        fix_versions=[Version("1.2.0")],
        aliases=set(),
        effective_at=timestamps["nov1"],
        received_at=timestamps["nov3"],
    )


@pytest.fixture()
def deployments():
    return [
        DeploymentRecord(name="foo", version=Version("1.0.1"), deployed=True, scope="prod"),
        DeploymentRecord(
            name="ghost-pkg",
            version=Version("2.0.0"),
            deployed=False,
            scope="prod",
            note="never installed",
        ),
    ]


@pytest.fixture()
def first_snapshot(old_advisory, deployments, timestamps):
    return Snapshot(
        id="snap-1",
        created_at=timestamps["nov1"],
        rule_version="rules-1",
        advisories=[old_advisory],
        deployments=deployments,
        description="first",
    )


@pytest.fixture()
def second_snapshot(old_advisory, late_advisory, deployments, timestamps):
    return Snapshot(
        id="snap-2",
        created_at=timestamps["nov3"],
        rule_version="rules-1",
        advisories=[old_advisory, late_advisory],
        deployments=deployments,
        description="late bulletin",
    )


@pytest.fixture()
def corrected_late(late_advisory, timestamps):
    return replace(
        late_advisory,
        status=AdvisoryStatus.Corrected,
        corrected_at=timestamps["nov5"],
    )
