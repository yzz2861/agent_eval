"""Pytest configuration confined to the offline test tree.

The evaluation sandbox denies stat access to directories above the
workspace, so pytest upward rootdir discovery must not escape the tests
folder. The runner script ``run_offline_tests.py`` passes the matching
CLI flags; this conftest documents the constraint and keeps collection
local.
"""

collect_ignore_glob = ["test_data.tar.bz2.enc"]
