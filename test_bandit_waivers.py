import datetime as dt
import hashlib
import json

import pytest

from bandit_waivers import (
    NOT_COVERED,
    REVIEW_EXPIRED,
    REVIEW_MODIFIED,
    WAIVED_LEGACY,
    WAIVED_UPSTREAM,
    Waiver,
    WaiverBackend,
    filter_bandit_results,
)

UPSTREAM = b"import os\n# requests 2.31.0 vendored verbatim\n"
LOCAL_PATCH = UPSTREAM + b"# local hotfix: CVE-2026-1234 workaround\n"
DIGEST = hashlib.sha256(UPSTREAM).hexdigest()

EXPIRES = dt.date(2026, 12, 31)
BEFORE = dt.date(2026, 11, 28)
AFTER = dt.date(2027, 1, 1)


@pytest.fixture()
def backend():
    return WaiverBackend([
        Waiver(path="vendor/requests/*", source="upstream:requests@2.31.0",
               sha256=DIGEST, expires=EXPIRES, note="sec-team ticket SEC-88"),
        Waiver(path="legacy/*", note="old global config, still honored"),
    ])


def test_pristine_upstream_file_is_waived(backend):
    d = backend.decide("vendor/requests/sessions.py", UPSTREAM, today=BEFORE)
    assert d.status == WAIVED_UPSTREAM
    assert "pristine copy of approved upstream:requests@2.31.0" in d.reason


def test_local_patch_gets_a_different_reason(backend):
    d = backend.decide("vendor/requests/sessions.py", LOCAL_PATCH, today=BEFORE)
    assert d.status == REVIEW_MODIFIED
    assert "locally modified" in d.reason
    assert "upstream:requests@2.31.0" in d.reason


def test_legacy_global_waiver_still_applies(backend):
    d = backend.decide("legacy/old_tool.py", b"anything", today=BEFORE)
    assert d.status == WAIVED_LEGACY
    assert "old global config" in d.reason


def test_uncovered_location_is_flagged(backend):
    d = backend.decide("src/app.py", b"x = 1", today=BEFORE)
    assert d.status == NOT_COVERED


@pytest.mark.parametrize("day,expected", [
    (EXPIRES, WAIVED_UPSTREAM),      # valid through the expiry date itself
    (AFTER, REVIEW_EXPIRED),         # needs re-review the day after
])
def test_time_travel_across_expiry(backend, day, expected):
    d = backend.decide("vendor/requests/sessions.py", UPSTREAM, today=day)
    assert d.status == expected
    if expected == REVIEW_EXPIRED:
        assert "expired on 2026-12-31" in d.reason


def test_reaudit_due_lists_expired_waivers(backend):
    assert backend.reaudit_due(today=BEFORE) == []
    due = backend.reaudit_due(today=AFTER)
    assert [w.source for w in due] == ["upstream:requests@2.31.0"]


def test_audit_reports_whole_tree(backend):
    decisions = backend.audit({
        "vendor/requests/sessions.py": UPSTREAM,
        "vendor/requests/adapters.py": LOCAL_PATCH,
        "legacy/old_tool.py": b"anything",
    }, today=BEFORE)
    assert [d.status for d in decisions] == [
        WAIVED_UPSTREAM, REVIEW_MODIFIED, WAIVED_LEGACY]


def test_load_from_json_config(tmp_path):
    cfg = tmp_path / "waivers.json"
    cfg.write_text(json.dumps({"waivers": [
        {"path": "vendor/requests/*", "source": "upstream:requests@2.31.0",
         "sha256": DIGEST, "expires": "2026-12-31"},
        {"path": "legacy/*", "note": "old global config"},
    ]}))
    loaded = WaiverBackend.load(cfg)
    assert loaded.decide("vendor/requests/sessions.py", UPSTREAM,
                         today=BEFORE).status == WAIVED_UPSTREAM
    assert loaded.decide("legacy/a.py", b"", today=BEFORE).status == WAIVED_LEGACY


def test_filter_bandit_results(tmp_path, backend):
    (tmp_path / "vendor/requests").mkdir(parents=True)
    (tmp_path / "vendor/requests/sessions.py").write_bytes(UPSTREAM)
    (tmp_path / "vendor/requests/adapters.py").write_bytes(LOCAL_PATCH)
    results = [
        {"filename": "vendor/requests/sessions.py", "issue_severity": "LOW"},
        {"filename": "vendor/requests/adapters.py", "issue_severity": "MEDIUM"},
    ]
    kept = filter_bandit_results(results, backend, root=tmp_path, today=BEFORE)
    assert [i["filename"] for i in kept] == ["vendor/requests/adapters.py"]
    assert kept[0]["waiver_status"] == REVIEW_MODIFIED
