# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for the 'check_channel_overlap' offline release check."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from types import ModuleType

from securesystemslib.signer import CryptoSigner

from tuf.api._payload import TOP_LEVEL_ROLE_NAMES
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

SCRIPT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.pardir,
    "check_channel_overlap",
)


def load_checker_module() -> ModuleType:
    """Load the extensionless check_channel_overlap script as a module."""
    loader = SourceFileLoader("check_channel_overlap", SCRIPT_PATH)
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


checker = load_checker_module()


class RepoBuilder:
    """Builds a signed, consistent repository metadata directory."""

    def __init__(self) -> None:
        self.expires = datetime.now(UTC) + timedelta(days=30)
        self.signers: dict[str, CryptoSigner] = {}

    def signer(self, role: str) -> CryptoSigner:
        if role not in self.signers:
            self.signers[role] = CryptoSigner.generate_ed25519()
        return self.signers[role]

    def make_targets(
        self,
        files: dict[str, bytes],
        delegate_specs: list[tuple[str, list[str], bool]] | None = None,
    ) -> Targets:
        targets = Targets(expires=self.expires)
        for path, content in files.items():
            targets.targets[path] = TargetFile.from_data(
                path, content, ["sha256"]
            )
        if delegate_specs:
            keys = {}
            roles = {}
            for name, paths, terminating in delegate_specs:
                key = self.signer(name).public_key
                keys[key.keyid] = key
                roles[name] = DelegatedRole(
                    name, [key.keyid], 1, terminating, paths
                )
            targets.delegations = Delegations(keys, roles)
        return targets

    def publish(
        self,
        repo_dir: str,
        targets: Targets,
        delegates: dict[str, Targets],
    ) -> None:
        for role in TOP_LEVEL_ROLE_NAMES:
            self.signer(role)

        root = Root(expires=self.expires)
        for role in TOP_LEVEL_ROLE_NAMES:
            root.add_key(self.signer(role).public_key, role)
        md_root = Metadata(root)
        md_root.sign(self.signer(Root.type))

        mds = {}
        for name, signed in [(Targets.type, targets), *delegates.items()]:
            md = Metadata(signed)
            md.sign(self.signer(name))
            mds[name] = md

        snapshot = Snapshot(expires=self.expires)
        for name, md in mds.items():
            data = md.to_bytes(JSONSerializer())
            snapshot.meta[f"{name}.json"] = MetaFile.from_data(
                1, data, ["sha256"]
            )
        md_snapshot = Metadata(snapshot)
        md_snapshot.sign(self.signer(Snapshot.type))

        timestamp = Timestamp(expires=self.expires)
        timestamp.snapshot_meta = MetaFile.from_data(
            1, md_snapshot.to_bytes(JSONSerializer()), ["sha256"]
        )
        md_timestamp = Metadata(timestamp)
        md_timestamp.sign(self.signer(Timestamp.type))

        all_mds = {
            Root.type: md_root,
            Timestamp.type: md_timestamp,
            Snapshot.type: md_snapshot,
            **mds,
        }
        for name, md in all_mds.items():
            path = os.path.join(repo_dir, f"{name}.json")
            with open(path, "wb") as f:
                f.write(md.to_bytes(JSONSerializer()))


class TestCheckChannelOverlap(unittest.TestCase):
    """Tests for visibility computation and finding classification."""

    def setUp(self) -> None:
        self.repo_dir = os.path.realpath(tempfile.mkdtemp())
        self.builder = RepoBuilder()

    def tearDown(self) -> None:
        for name in os.listdir(self.repo_dir):
            os.remove(os.path.join(self.repo_dir, name))
        os.rmdir(self.repo_dir)

    def audit(
        self,
        approved_shares: list[dict[str, Any]] | None = None,
        channel_filter: list[str] | None = None,
    ) -> dict[str, Any]:
        roles = checker.load_trusted_roles(self.repo_dir)
        return checker.audit_channels(
            roles, approved_shares or [], 32, channel_filter
        )

    def test_delegation_order_decides_effective_claim(self) -> None:
        targets = self.builder.make_targets(
            {},
            [
                ("release", ["*"], False),
                ("experimental", ["*"], False),
            ],
        )
        delegates = {
            "release": self.builder.make_targets({"app.txt": b"release"}),
            "experimental": self.builder.make_targets(
                {"app.txt": b"experimental", "exp-only.txt": b"x"}
            ),
        }
        self.builder.publish(self.repo_dir, targets, delegates)

        report = self.audit()

        # release is delegated first: its claim on app.txt is effective
        self.assertEqual(
            report["visible_targets"]["release"]["app.txt"]["role"], "release"
        )
        self.assertNotIn("app.txt", report["visible_targets"]["experimental"])
        self.assertIn("exp-only.txt", report["visible_targets"]["experimental"])

        findings = report["findings"]
        self.assertEqual(findings["allowed_mirrors"], [])
        self.assertEqual(findings["unproven_identical"], [])
        self.assertEqual(len(findings["inconsistent_same_name"]), 1)
        entry = findings["inconsistent_same_name"][0]
        self.assertEqual(entry["path"], "app.txt")
        self.assertEqual(entry["effective_role"], "release")
        claims = {c["role"]: c["effective"] for c in entry["claims"]}
        self.assertEqual(claims, {"release": True, "experimental": False})

    def test_terminating_delegation_hides_later_roles(self) -> None:
        targets = self.builder.make_targets(
            {},
            [
                ("first", ["*"], True),
                ("second", ["*"], False),
            ],
        )
        delegates = {
            "first": self.builder.make_targets({}),
            "second": self.builder.make_targets({"a.txt": b"a"}),
        }
        self.builder.publish(self.repo_dir, targets, delegates)

        report = self.audit()

        # 'first' terminates the lookup: the client never reaches 'second'
        self.assertNotIn("a.txt", report["visible_targets"].get("second", {}))
        self.assertEqual(report["findings"]["inconsistent_same_name"], [])

    def test_top_level_targets_wins_over_delegations(self) -> None:
        targets = self.builder.make_targets(
            {"t.txt": b"top"}, [("role1", ["*"], False)]
        )
        delegates = {
            "role1": self.builder.make_targets({"t.txt": b"delegated"})
        }
        self.builder.publish(self.repo_dir, targets, delegates)

        report = self.audit()

        visible = report["visible_targets"]["targets"]["t.txt"]
        self.assertEqual(visible["role"], "targets")
        entry = report["findings"]["inconsistent_same_name"][0]
        self.assertEqual(entry["effective_role"], "targets")

    def test_mirror_classification_with_approved_shares(self) -> None:
        shared = b"same install file"
        leaked = b"experimental build of the same file name"
        targets = self.builder.make_targets(
            {"main/leaked.bin": leaked},
            [
                ("release", ["release/*", "vendor/*"], False),
                ("experimental", ["staging/*", "experimental/*"], False),
            ],
        )
        delegates = {
            "release": self.builder.make_targets(
                {"vendor/runtime.bin": shared, "release/app.bin": b"rel"}
            ),
            "experimental": self.builder.make_targets(
                {
                    "staging/runtime.bin": shared,
                    "experimental/leaked.bin": leaked,
                }
            ),
        }
        self.builder.publish(self.repo_dir, targets, delegates)

        approved = [
            {
                "channels": ["release", "experimental"],
                "paths": ["vendor/*", "staging/*"],
            }
        ]
        report = self.audit(approved_shares=approved)
        findings = report["findings"]

        # vendor/runtime.bin <-> staging/runtime.bin is an approved mirror
        self.assertEqual(len(findings["allowed_mirrors"]), 1)
        mirror = findings["allowed_mirrors"][0]
        copies = {(c["role"], c["path"]) for c in mirror["copies"]}
        self.assertEqual(
            copies,
            {
                ("release", "vendor/runtime.bin"),
                ("experimental", "staging/runtime.bin"),
            },
        )

        # experimental/leaked.bin <-> targets main/leaked.bin is not covered
        # by any approved scope: provenance cannot be proven
        self.assertEqual(len(findings["unproven_identical"]), 1)
        unproven = findings["unproven_identical"][0]
        copies = {(c["role"], c["path"]) for c in unproven["copies"]}
        self.assertEqual(
            copies,
            {
                ("targets", "main/leaked.bin"),
                ("experimental", "experimental/leaked.bin"),
            },
        )
        self.assertEqual(findings["inconsistent_same_name"], [])

    def test_identical_files_unproven_without_approval(self) -> None:
        shared = b"shared content"
        targets = self.builder.make_targets(
            {},
            [("release", ["*/*"], False), ("experimental", ["*/*"], False)],
        )
        delegates = {
            "release": self.builder.make_targets({"a/tool.bin": shared}),
            "experimental": self.builder.make_targets({"b/tool.bin": shared}),
        }
        self.builder.publish(self.repo_dir, targets, delegates)

        report = self.audit()
        findings = report["findings"]
        self.assertEqual(findings["allowed_mirrors"], [])
        self.assertEqual(len(findings["unproven_identical"]), 1)
        self.assertEqual(findings["inconsistent_same_name"], [])

    def test_channel_filter_restricts_report(self) -> None:
        shared = b"shared content"
        targets = self.builder.make_targets(
            {"main.bin": shared},
            [("experimental", ["*"], False)],
        )
        delegates = {
            "experimental": self.builder.make_targets({"copy.bin": shared})
        }
        self.builder.publish(self.repo_dir, targets, delegates)

        report = self.audit(channel_filter=["experimental"])
        self.assertEqual(report["channels"], ["experimental"])
        self.assertEqual(report["findings"]["unproven_identical"], [])

    def test_nested_delegation_inherits_channel(self) -> None:
        shared = b"nested shared"
        targets = self.builder.make_targets(
            {"root-copy.bin": shared}, [("release", ["*", "*/*"], False)]
        )
        release = self.builder.make_targets(
            {}, [("release-sub", ["sub/*"], False)]
        )
        delegates = {
            "release": release,
            "release-sub": self.builder.make_targets({"sub/copy.bin": shared}),
        }
        self.builder.publish(self.repo_dir, targets, delegates)

        report = self.audit()
        visible = report["visible_targets"]
        self.assertEqual(
            visible["release"]["sub/copy.bin"]["role"], "release-sub"
        )
        unproven = report["findings"]["unproven_identical"][0]
        copies = {(c["channel"], c["role"]) for c in unproven["copies"]}
        self.assertEqual(
            copies, {("targets", "targets"), ("release", "release-sub")}
        )


class TestCheckChannelOverlapCli(unittest.TestCase):
    """End-to-end tests running the script as a subprocess."""

    def setUp(self) -> None:
        self.repo_dir = os.path.realpath(tempfile.mkdtemp())
        self.builder = RepoBuilder()

    def tearDown(self) -> None:
        for name in os.listdir(self.repo_dir):
            os.remove(os.path.join(self.repo_dir, name))
        os.rmdir(self.repo_dir)

    def run_checker(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, SCRIPT_PATH, self.repo_dir, *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def publish_default_repo(self) -> None:
        shared = b"shared content"
        targets = self.builder.make_targets(
            {},
            [
                ("release", ["*", "*/*"], False),
                ("experimental", ["*", "*/*"], False),
            ],
        )
        delegates = {
            "release": self.builder.make_targets(
                {"vendor/tool.bin": shared, "conflict.txt": b"release"}
            ),
            "experimental": self.builder.make_targets(
                {"staging/tool.bin": shared, "conflict.txt": b"experimental"}
            ),
        }
        self.builder.publish(self.repo_dir, targets, delegates)

    def test_cli_exit_codes_and_report(self) -> None:
        self.publish_default_repo()
        report_path = os.path.join(self.repo_dir, "report.json")

        # Unapproved sharing and a name conflict: exit code 1
        result = self.run_checker("--report", report_path)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("UNPROVEN IDENTICAL", result.stdout)
        self.assertIn("INCONSISTENT NAME", result.stdout)

        with open(report_path) as f:
            report = json.load(f)
        self.assertEqual(report["summary"]["unproven_identical"], 1)
        self.assertEqual(report["summary"]["inconsistent_same_name"], 1)
        os.remove(report_path)

        # Approve the mirror scope: only the name conflict remains
        shares_path = os.path.join(self.repo_dir, "shares.json")
        with open(shares_path, "w") as f:
            json.dump(
                {
                    "allowed_shares": [
                        {
                            "channels": ["release", "experimental"],
                            "paths": ["vendor/*", "staging/*"],
                        }
                    ]
                },
                f,
            )
        result = self.run_checker(
            "--approved-shares", shares_path, "--report", report_path
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("ALLOWED MIRROR", result.stdout)
        with open(report_path) as f:
            report = json.load(f)
        self.assertEqual(report["summary"]["allowed_mirrors"], 1)
        self.assertEqual(report["summary"]["unproven_identical"], 0)

    def test_cli_clean_repo_exits_zero(self) -> None:
        targets = self.builder.make_targets(
            {"only.txt": b"content"}, [("release", ["release/*"], False)]
        )
        delegates = {
            "release": self.builder.make_targets({"release/app.bin": b"app"})
        }
        self.builder.publish(self.repo_dir, targets, delegates)

        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 allowed mirror(s)", result.stdout)

    def test_cli_invalid_metadata_exits_two(self) -> None:
        targets = self.builder.make_targets({"only.txt": b"content"})
        self.builder.publish(self.repo_dir, targets, {})

        # Tamper with targets.json: snapshot hashes no longer match
        path = os.path.join(self.repo_dir, "targets.json")
        with open(path, "ab") as f:
            f.write(b" ")

        result = self.run_checker()
        self.assertEqual(result.returncode, 2)
        self.assertIn("ERROR", result.stdout)


if __name__ == "__main__":
    unittest.main()
