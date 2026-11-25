from sqlparse.governance import review_migration


VIEW_SQL = """
CREATE TEMP VIEW temp_chain AS
SELECT id, payload FROM raw_events
"""

FROZEN_SQL = """
CREATE VIEW forensic_snapshot AS
SELECT id, payload FROM temp_chain
"""


def test_rename_keeps_identity_and_path():
    report = review_migration(
        [VIEW_SQL],
        [{"name": "forensic_snapshot", "sql": FROZEN_SQL}],
        "ALTER VIEW temp_chain RENAME TO kept_chain",
    )
    assert report["approved"], report["findings"]
    assert report["renames"] == [{
        "object_id": "temp_chain",
        "from": "temp_chain",
        "to": "kept_chain",
    }]
    path = report["paths"][0]
    assert path["available"] is True
    assert path["status"] == "accessible"
    assert "kept_chain" in path["routes"][0]


def test_drop_breaks_unique_evidence_chain():
    report = review_migration(
        [VIEW_SQL],
        [FROZEN_SQL],
        "DROP VIEW temp_chain",
    )
    assert report["blocked"] is True
    codes = {item["code"] for item in report["findings"]}
    assert "UNIQUE_DEPENDENCY_CHAIN_REMOVED" in codes
    assert report["paths"][0]["available"] is False


def test_name_reuse_is_separate_from_incomplete_dependency():
    report = review_migration(
        [VIEW_SQL],
        [FROZEN_SQL],
        "DROP VIEW temp_chain; CREATE VIEW temp_chain AS SELECT id FROM unrelated_table",
    )
    assert report["name_reuse_detected"] is True
    assert report["name_reuses"][0]["previous_object_id"] == "temp_chain"
    assert report["incomplete_dependencies"] == []
    assert any(item["code"] == "NAME_REUSED" for item in report["findings"])


def test_missing_frozen_definition_is_incomplete():
    report = review_migration([], ["mystery_snapshot"], "")
    assert report["status"] == "incomplete"
    assert report["blocked"] is False
    assert report["incomplete_dependencies"]
