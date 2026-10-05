from __future__ import annotations

from limits.storage.sqlite import _sqlite_path


def test_sqlite_uri_paths():
    assert _sqlite_path("sqlite://") == ":memory:"
    assert _sqlite_path("sqlite:///") == ":memory:"
    assert _sqlite_path("sqlite:///:memory:") == ":memory:"
    assert _sqlite_path("sqlite:///tmp/limits.db") == "/tmp/limits.db"
    assert _sqlite_path("sqlite:////tmp/limits.db") == "/tmp/limits.db"
    assert _sqlite_path("sqlite://relative.db") == "relative.db"
