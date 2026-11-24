import json
import os

import pytest

from bandit.core.incremental import (
    IncrementalScanSession,
    ScanCounter,
    scan_full,
)


POLICY = {
    "version": "test-policy-v1",
    "rules": {
        "eval": {
            "id": "B307",
            "message": "eval sink",
            "severity": "HIGH",
            "confidence": "HIGH",
        },
        "raw_query": {
            "id": "T200",
            "message": "query sink needs sanitizer",
            "severity": "HIGH",
            "sanitizer_can_mitigate": True,
        },
        "new_sink": {
            "id": "T300",
            "message": "newly policy-enabled sink",
            "severity": "MEDIUM",
        },
    },
    "sanitizers": ["html.escape"],
}


def write_file(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def rewrite_file(root, name, content):
    path = write_file(root, name, content)
    stat = path.stat()
    os.utime(path, (stat.st_atime, stat.st_mtime + 10))
    return path


def make_session(tmp_path, **kwargs):
    counter = kwargs.pop("counter", ScanCounter())
    policy = kwargs.pop("policy", POLICY)
    return IncrementalScanSession(
        cache_path=tmp_path / "incremental-cache.json",
        root=tmp_path,
        policy=policy,
        counter=counter,
        **kwargs,
    )


def test_wrapper_change_invalidates_cross_file_callers(tmp_path):
    write_file(
        tmp_path,
        "wrapper.py",
        """
import html


def run(value):
    return html.escape(value)
""",
    )
    write_file(
        tmp_path,
        "caller.py",
        """
from wrapper import run


def handle(value):
    return run(value)
""",
    )
    write_file(
        tmp_path,
        "isolated.py",
        """
def untouched(value):
    return eval(value)
""",
    )

    counter = ScanCounter()
    session = make_session(tmp_path, counter=counter)
    first = session.scan(tmp_path)

    assert first.analyzed_files == ("caller.py", "isolated.py", "wrapper.py")
    assert any(finding.rule_id == "B307" for finding in first.findings)
    assert not any(finding.file == "caller.py" for finding in first.findings)

    rewrite_file(
        tmp_path,
        "wrapper.py",
        """
def run(value):
    return eval(value)
""",
    )
    second = session.scan(tmp_path)

    assert second.analyzed_files == ("caller.py", "wrapper.py")
    assert "isolated.py" not in second.analyzed_files
    assert counter.file_visits == 2
    assert counter.visited_files == ["wrapper.py", "caller.py"] or set(
        counter.visited_files
    ) == {"wrapper.py", "caller.py"}

    caller_findings = [f for f in second.findings if f.file == "caller.py"]
    assert caller_findings
    assert all(f.rule_id == "B307" for f in caller_findings)
    assert caller_findings[0].via == ("wrapper.run",)

    full = scan_full(tmp_path, root=tmp_path, policy=POLICY)
    assert second.finding_keys() == full.finding_keys()

    restored = IncrementalScanSession(
        cache_path=tmp_path / "incremental-cache.json",
        root=tmp_path,
        policy=POLICY,
    )
    cached = restored.scan(tmp_path)
    assert cached.analyzed_files == ()
    assert cached.finding_keys() == second.finding_keys()


def test_function_deletion_invalidates_dependents(tmp_path):
    write_file(
        tmp_path,
        "sanitizer.py",
        """
import html


def clean(value):
    return html.escape(value)
""",
    )
    write_file(
        tmp_path,
        "api.py",
        """
from sanitizer import clean


def lookup(value):
    return raw_query(clean(value))
""",
    )

    session = make_session(tmp_path)
    first = session.scan(tmp_path)
    assert not [f for f in first.findings if f.rule_id == "T200"]

    rewrite_file(tmp_path, "sanitizer.py", "# clean was deleted\n")
    second = session.scan(tmp_path)

    assert set(second.analyzed_files) == {"sanitizer.py", "api.py"}
    assert any(f.file == "api.py" and f.rule_id == "T200" for f in second.findings)
    full = scan_full(tmp_path, root=tmp_path, policy=POLICY)
    assert second.finding_keys() == full.finding_keys()


def test_import_rename_replaces_dependency_edge(tmp_path):
    write_file(
        tmp_path,
        "lib.py",
        """
def safe(value):
    return value


def dangerous(value):
    return eval(value)
""",
    )
    write_file(
        tmp_path,
        "consumer.py",
        """
from lib import safe as choose


def use(value):
    return choose(value)
""",
    )

    session = make_session(tmp_path)
    session.scan(tmp_path)

    rewrite_file(
        tmp_path,
        "consumer.py",
        """
from lib import dangerous as choose


def use(value):
    return choose(value)
""",
    )
    result = session.scan(tmp_path)

    assert any(f.file == "consumer.py" and f.rule_id == "B307" for f in result.findings)
    edge_targets = {
        target
        for source, target, kind in session.graph.edges
        if kind == "call" and source == "func:consumer.use"
    }
    assert "func:lib.dangerous" in edge_targets
    assert "func:lib.safe" not in edge_targets
    full = scan_full(tmp_path, root=tmp_path, policy=POLICY)
    assert result.finding_keys() == full.finding_keys()


def test_circular_dependency_converges_and_invalidates_cycle(tmp_path):
    write_file(
        tmp_path,
        "a.py",
        """
from b import beta


def alpha(value):
    return beta(value)
""",
    )
    write_file(
        tmp_path,
        "b.py",
        """
from a import alpha


def beta(value):
    return alpha(value)
""",
    )

    session = make_session(tmp_path)
    session.scan(tmp_path)

    rewrite_file(
        tmp_path,
        "b.py",
        """
from a import alpha


def beta(value):
    alpha(value)
    return eval(value)
""",
    )
    result = session.scan(tmp_path)

    assert set(result.analyzed_files) == {"a.py", "b.py"}
    assert any(f.file == "a.py" and f.rule_id == "B307" for f in result.findings)
    full = scan_full(tmp_path, root=tmp_path, policy=POLICY)
    assert result.finding_keys() == full.finding_keys()


def test_policy_version_change_invalidates_every_file(tmp_path):
    write_file(tmp_path, "app.py", "def run():\n    return new_sink('x')\n")
    policy_v1 = dict(POLICY, version="old-policy")
    policy_v1["rules"] = {
        "eval": POLICY["rules"]["eval"],
    }
    session = make_session(tmp_path, policy=policy_v1)
    first = session.scan(tmp_path)
    assert not any(f.rule_id == "T300" for f in first.findings)

    policy_v2 = dict(POLICY, version="new-policy")
    session_v2 = make_session(tmp_path, policy=policy_v2)
    result = session_v2.scan(tmp_path)

    assert result.policy_changed is True
    assert result.full_scan is True
    assert result.analyzed_files == ("app.py",)
    assert any(f.rule_id == "T300" for f in result.findings)


def test_configuration_change_invalidates_all_files(tmp_path):
    write_file(tmp_path, "app.py", "def run():\n    return eval('x')\n")
    config_path = tmp_path / "rules.json"
    config_path.write_text(json.dumps({"enabled": ["B307"]}), encoding="utf-8")
    session = make_session(tmp_path, config_path=config_path)
    session.scan(tmp_path)

    config_path.write_text(json.dumps({"enabled": ["B307", "T300"]}), encoding="utf-8")
    result = session.scan(tmp_path)

    assert result.policy_changed is True
    assert result.full_scan is True


def test_analysis_failure_keeps_previous_cache_and_graph(tmp_path, monkeypatch):
    wrapper = write_file(tmp_path, "wrapper.py", "def run(x):\n    return x\n")
    caller = write_file(
        tmp_path,
        "caller.py",
        "from wrapper import run\n\ndef use(x):\n    run(x)\n",
    )
    session = make_session(tmp_path)
    session.scan(tmp_path)
    cache_file = tmp_path / "incremental-cache.json"
    old_bytes = cache_file.read_bytes()

    rewrite_file(tmp_path, "wrapper.py", "def run(x):\n    return eval(x)\n")

    def fail_analysis(relative, path, source=None):
        raise RuntimeError("synthetic analysis failure")

    monkeypatch.setattr(session, "_analyze_file", fail_analysis)
    with pytest.raises(RuntimeError, match="synthetic"):
        session.scan(tmp_path)

    assert cache_file.read_bytes() == old_bytes
    assert "func:wrapper.run" in session.graph.nodes


def test_commit_failure_is_atomic(tmp_path, monkeypatch):
    write_file(tmp_path, "app.py", "def run(x):\n    return x\n")
    session = make_session(tmp_path)
    session.scan(tmp_path)
    cache_file = tmp_path / "incremental-cache.json"
    old_bytes = cache_file.read_bytes()

    rewrite_file(tmp_path, "app.py", "def run(x):\n    return eval(x)\n")

    def fail_replace(source, destination):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="synthetic replace"):
        session.scan(tmp_path)

    assert cache_file.read_bytes() == old_bytes
    temporary_files = list(tmp_path.glob(".incremental-cache.json.*.tmp"))
    assert temporary_files == []


def test_corrupt_cache_is_recovered(tmp_path):
    write_file(tmp_path, "app.py", "def run(x):\n    return eval(x)\n")
    cache_file = tmp_path / "incremental-cache.json"
    cache_file.write_text("{this is not json", encoding="utf-8")

    session = make_session(tmp_path)
    result = session.scan(tmp_path)

    assert result.recovered is True
    assert result.corrupt_cache is not None
    assert result.analyzed_files == ("app.py",)
    assert any(f.rule_id == "B307" for f in result.findings)
    recovered = json.loads(cache_file.read_text(encoding="utf-8"))
    assert recovered["schema_version"] == 1
    assert (tmp_path / "incremental-cache.json.corrupt").exists()


def test_existing_stateless_bandit_manager_still_works(tmp_path):
    from bandit.core import config as bandit_config
    from bandit.core import manager as bandit_manager

    source = tmp_path / "plain.py"
    source.write_text("assert True\n", encoding="utf-8")
    manager = bandit_manager.BanditManager(
        bandit_config.BanditConfig(), "file", quiet=True
    )
    manager.files_list = [str(source)]
    manager.run_tests()

    assert any(issue.test_id == "B101" for issue in manager.results)
