import hashlib
import json

import pytest

from pip_audit._disclosure import (
    DEFAULT_DISCLOSURE_FIELDS,
    DisclosureError,
    build_plan,
    main,
)


def _audit(dependencies, fixes=None):
    return {"dependencies": dependencies, "fixes": fixes or []}


def _dep(name, version, vuln_ids=(), **extra):
    dep = {
        "name": name,
        "version": version,
        "vulns": [
            {
                "id": vid,
                "fix_versions": ["9.9"],
                "aliases": ["CVE-0000-0000"],
                "description": "internal-only detail",
            }
            for vid in vuln_ids
        ],
        "internal_note": "do not disclose",
    }
    dep.update(extra)
    return dep


@pytest.fixture
def scoped_audits(tmp_path):
    # The "web" and "worker" lines share "sharedlib" but run different
    # versions of the same-name package "appx"; "ghost" belongs to a scope
    # that no recipient may claim.
    web = tmp_path / "web.json"
    web.write_text(
        json.dumps(
            _audit(
                [
                    _dep("sharedlib", "1.0", ["VULN-SHARED"]),
                    _dep("appx", "2.0", ["VULN-WEB"]),
                ],
                fixes=[{"name": "appx", "old_version": "2.0", "new_version": "2.1"}],
            )
        )
    )
    worker = tmp_path / "worker.json"
    worker.write_text(
        json.dumps(
            _audit(
                [
                    _dep("sharedlib", "1.0", ["VULN-SHARED"]),
                    _dep("appx", "1.0", ["VULN-WORKER"]),
                ]
            )
        )
    )
    lab = tmp_path / "lab.json"
    lab.write_text(json.dumps(_audit([_dep("ghost", "9.9", ["VULN-GHOST"])])))
    return [("web", web), ("worker", worker), ("lab", lab)]


@pytest.fixture
def config(tmp_path):
    path = tmp_path / "recipients.json"
    path.write_text(
        json.dumps(
            {
                "recipients": {
                    "contractor-a": {"scopes": ["web"]},
                    "contractor-b": {"scopes": ["worker"]},
                }
            }
        )
    )
    return path


def _digest(keys):
    return "sha256:" + hashlib.sha256("\n".join(sorted(keys)).encode()).hexdigest()


def test_same_name_packages_stay_on_their_own_build_lines(scoped_audits, config):
    plan = build_plan(scoped_audits, config)

    report_a = plan.recipient_report("contractor-a")
    report_b = plan.recipient_report("contractor-b")

    deps_a = {(d["name"], d["version"]) for d in report_a["dependencies"]}
    deps_b = {(d["name"], d["version"]) for d in report_b["dependencies"]}

    # Each recipient sees their own build line of "appx", never the other.
    assert deps_a == {("sharedlib", "1.0"), ("appx", "2.0")}
    assert deps_b == {("sharedlib", "1.0"), ("appx", "1.0")}

    # The shared dependency is counted for both recipients, but its scope
    # labels only ever mention the recipient's own lines.
    shared_a = next(d for d in report_a["dependencies"] if d["name"] == "sharedlib")
    shared_b = next(d for d in report_b["dependencies"] if d["name"] == "sharedlib")
    assert shared_a["scopes"] == ["web"]
    assert shared_b["scopes"] == ["worker"]

    # Fixes follow the disclosed records only.
    assert report_a["fixes"] == [{"name": "appx", "old_version": "2.0", "new_version": "2.1"}]
    assert report_b["fixes"] == []


def test_disclosure_fields_are_fixed_and_enforced(scoped_audits, config):
    plan = build_plan(scoped_audits, config)
    report = plan.recipient_report("contractor-a")

    assert report["disclosure_fields"] == list(DEFAULT_DISCLOSURE_FIELDS)
    for dep in report["dependencies"]:
        assert "internal_note" not in dep
        for vuln in dep["vulns"]:
            assert set(vuln) <= {"id", "fix_versions"}


def test_unclaimed_records_stay_internal(scoped_audits, config):
    plan = build_plan(scoped_audits, config)

    for name in ("contractor-a", "contractor-b"):
        report = plan.recipient_report(name)
        assert all(d["name"] != "ghost" for d in report["dependencies"])

    internal = plan.internal_report()
    assert internal["unclaimed"] == ["ghost==9.9"]
    assert any(d["name"] == "ghost" for d in internal["dependencies"])


def test_omissions_are_verifiable_from_the_internal_report(scoped_audits, config):
    plan = build_plan(scoped_audits, config)
    internal = plan.internal_report()

    for name in ("contractor-a", "contractor-b"):
        outgoing = plan.recipient_report(name)
        check = internal["recipients"][name]

        # The omission note in the outgoing report matches what the
        # internal reviewer recomputes from the merged data.
        assert outgoing["omissions"]["count"] == check["omitted"]["count"]
        assert outgoing["omissions"]["digest"] == check["omitted"]["digest"]
        assert outgoing["omissions"]["digest"] == _digest(check["omitted"]["keys"])

        # Included + omitted partitions the full merged record set.
        total = len(internal["dependencies"])
        assert check["included"]["count"] + check["omitted"]["count"] == total

    # contractor-a must not learn that "appx==1.0" or "ghost==9.9" exist,
    # only how many records were withheld.
    assert plan.recipient_report("contractor-a")["omissions"]["count"] == 2


def test_recipient_config_validation(scoped_audits, tmp_path):
    bad_fields = tmp_path / "bad-fields.json"
    bad_fields.write_text(
        json.dumps(
            {
                "recipients": {"x": {"scopes": ["web"]}},
                "disclosure_fields": ["name", "internal_note"],
            }
        )
    )
    with pytest.raises(DisclosureError, match="fixed whitelist"):
        build_plan(scoped_audits, bad_fields)

    bad_scopes = tmp_path / "bad-scopes.json"
    bad_scopes.write_text(json.dumps({"recipients": {"x": {"scopes": []}}}))
    with pytest.raises(DisclosureError, match="scopes"):
        build_plan(scoped_audits, bad_scopes)


def test_unknown_recipient(scoped_audits, config):
    plan = build_plan(scoped_audits, config)
    with pytest.raises(DisclosureError, match="unknown recipient"):
        plan.recipient_report("contractor-z")


def test_main_writes_reports(scoped_audits, config, tmp_path, capsys):
    out_dir = tmp_path / "dist"
    argv = []
    for scope, path in scoped_audits:
        argv += ["--scope", f"{scope}={path}"]
    argv += ["--recipients", str(config), "--out-dir", str(out_dir)]

    main(argv)

    report_a = json.loads((out_dir / "contractor-a.json").read_text())
    report_b = json.loads((out_dir / "contractor-b.json").read_text())
    internal = json.loads((out_dir / "internal.json").read_text())

    assert {d["version"] for d in report_a["dependencies"] if d["name"] == "appx"} == {"2.0"}
    assert {d["version"] for d in report_b["dependencies"] if d["name"] == "appx"} == {"1.0"}
    assert internal["unclaimed"] == ["ghost==9.9"]

    # The merged conclusion is recomputable: internal digests match the
    # outgoing omission notes.
    for name, report in (("contractor-a", report_a), ("contractor-b", report_b)):
        assert report["omissions"]["digest"] == internal["recipients"][name]["omitted"]["digest"]

    out = capsys.readouterr().out
    assert "withheld" in out
    assert "do not distribute" in out


def test_main_rejects_bad_input(tmp_path, capsys):
    missing = tmp_path / "missing.json"
    config = tmp_path / "recipients.json"
    config.write_text(json.dumps({"recipients": {"x": {"scopes": ["web"]}}}))

    with pytest.raises(SystemExit) as excinfo:
        main(["--scope", f"web={missing}", "--recipients", str(config), "--out-dir", str(tmp_path)])
    assert excinfo.value.code == 2
    assert "error:" in capsys.readouterr().err
