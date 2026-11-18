# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for the offline delegation authorization surface comparison."""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from dataclasses import dataclass, field

from securesystemslib.signer import CryptoSigner

from tests.repository_simulator import RepositorySimulator
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    DelegatedRole,
    Delegations,
    Targets,
)
from tuf.ngclient import Updater
from tuf.ngclient.authorization import (
    AuthorizationLimits,
    ChangeType,
    LimitExceededError,
    TargetsBundle,
    UnknownScopeError,
    _AuthorizationResolver,
    compare_authorization,
)



@dataclass
class SpecRole:
    """Delegation specification for the miniature signed repository."""

    name: str
    paths: list[str] | None = field(default_factory=lambda: ["*"])
    prefixes: list[str] | None = None
    terminating: bool = False
    delegator: str = "targets"
    key_label: str = "default"


class AuthorizationTest(unittest.TestCase):
    """Build miniature signed repositories and compare authorization."""

    def _add_role(
        self,
        sim: RepositorySimulator,
        spec: SpecRole,
        signers: dict[str, CryptoSigner],
    ) -> None:
        if spec.key_label not in signers:
            signers[spec.key_label] = CryptoSigner.generate_ed25519()
        signer = signers[spec.key_label]
        delegator = sim._get_delegator(spec.delegator)
        if delegator.delegations is None:
            delegator.delegations = Delegations({}, roles={})
        if spec.name not in sim.md_delegates:
            sim.add_signer(spec.name, signer)
            sim.add_delegation(
                spec.delegator,
                DelegatedRole(
                    spec.name,
                    [signer.public_key.keyid],
                    1,
                    spec.terminating,
                    paths=spec.paths,
                    path_hash_prefixes=spec.prefixes,
                ),
                Targets(1, ".".join(SPECIFICATION_VERSION), sim.safe_expiry, {}, None),
            )
        elif spec.name not in delegator.delegations.roles:
            delegator.delegations.roles[spec.name] = DelegatedRole(
                spec.name,
                [signer.public_key.keyid],
                1,
                spec.terminating,
                paths=spec.paths,
                path_hash_prefixes=spec.prefixes,
            )
        role = delegator.delegations.roles[spec.name]
        role.terminating = spec.terminating
        role.keyids = [signer.public_key.keyid]
        delegator.delegations.keys[signer.public_key.keyid] = signer.public_key
        if spec.paths is not None:
            role.paths = list(spec.paths)
        if spec.prefixes is not None:
            role.path_hash_prefixes = list(spec.prefixes)

    def _bundle(
        self,
        roles: list[SpecRole],
        signers: dict[str, CryptoSigner] | None = None,
    ) -> TargetsBundle:
        sim = RepositorySimulator()
        owned: dict[str, CryptoSigner] = {}
        active = signers if signers is not None else owned
        for spec in roles:
            self._add_role(sim, spec, active)
        bundle = {"targets": sim.md_targets}
        bundle.update(sim.md_delegates)
        return TargetsBundle.from_mapping(bundle)

    def _paired(
        self,
        old_roles: list[SpecRole],
        new_roles: list[SpecRole],
    ) -> tuple[TargetsBundle, TargetsBundle]:
        signers: dict[str, CryptoSigner] = {}
        old = self._bundle(old_roles, signers)
        new = self._bundle(new_roles, signers)
        return old, new

    def test_role_order_exposes_new_authorization(self) -> None:
        """Moving a terminating role first hands the path to new keys."""
        old, new = self._paired(
            [
                SpecRole("A", paths=["pkg/*"], key_label="ka"),
                SpecRole("B", paths=["pkg/*"], key_label="kb"),
            ],
            [
                SpecRole("B", paths=["pkg/*"], terminating=True, key_label="kb"),
                SpecRole("A", paths=["pkg/*"], key_label="ka"),
            ],
        )
        change = compare_authorization(old, new, ["pkg/foo"]).changes[0]
        self.assertEqual(change.kind, ChangeType.OWNERSHIP_CHANGED)
        self.assertEqual(change.witness_paths, ("pkg/foo",))
        self.assertEqual(change.old_chain.first_delegated_role.role, "A")
        self.assertEqual(change.new_chain.first_delegated_role.role, "B")
        self.assertEqual(
            [link.role for link in change.old_chain.roles], ["targets", "A", "B"]
        )
        self.assertEqual(
            [link.role for link in change.new_chain.roles], ["targets", "B"]
        )

    def test_semantic_noop_reorder_reports_nothing(self) -> None:
        """Reordering disjoint delegations does not change ownership."""
        old, new = self._paired(
            [
                SpecRole("A", paths=["a/*"], key_label="ka"),
                SpecRole("B", paths=["b/*"], key_label="kb"),
            ],
            [
                SpecRole("B", paths=["b/*"], key_label="kb"),
                SpecRole("A", paths=["a/*"], key_label="ka"),
            ],
        )
        diff = compare_authorization(old, new, ["a/x", "b/y"])
        self.assertFalse(diff)
        self.assertEqual(diff.changed_paths, ())

    def test_non_terminating_swap_is_a_real_change(self) -> None:
        """Order matters even without terminating: first role is owner."""
        old, new = self._paired(
            [
                SpecRole("A", paths=["pkg/*"], key_label="ka"),
                SpecRole("B", paths=["pkg/*"], key_label="kb"),
            ],
            [
                SpecRole("B", paths=["pkg/*"], key_label="kb"),
                SpecRole("A", paths=["pkg/*"], key_label="ka"),
            ],
        )
        change = compare_authorization(old, new, ["pkg/foo"]).changes[0]
        self.assertEqual(change.kind, ChangeType.OWNERSHIP_CHANGED)
        self.assertEqual(change.old_chain.first_delegated_role.role, "A")
        self.assertEqual(change.new_chain.first_delegated_role.role, "B")

    def test_terminating_prunes_siblings_in_chain(self) -> None:
        """A terminating role stops backtracking to later siblings."""
        old, new = self._paired(
            [
                SpecRole("A", paths=["p/*"], terminating=True, key_label="ka"),
                SpecRole("B", paths=["p/*"], key_label="kb"),
            ],
            [
                SpecRole("A", paths=["p/*"], key_label="ka"),
                SpecRole("B", paths=["p/*"], terminating=True, key_label="kb"),
            ],
        )
        change = compare_authorization(old, new, ["p/x"]).changes[0]
        self.assertEqual(
            [link.role for link in change.old_chain.roles],
            ["targets", "A"],
        )
        self.assertEqual(
            [link.role for link in change.new_chain.roles],
            ["targets", "A", "B"],
        )

    def test_nested_delegation_chain_change(self) -> None:
        """A change in a nested role is reported with the full chain."""
        old, new = self._paired(
            [
                SpecRole("A", paths=["*/*"], key_label="ka"),
                SpecRole("C", paths=["*/*"], delegator="A", key_label="kc"),
            ],
            [
                SpecRole("A", paths=["*/*"], key_label="ka"),
                SpecRole("D", paths=["*/*"], delegator="A", key_label="kd"),
            ],
        )
        change = compare_authorization(old, new, ["x/y"]).changes[0]
        self.assertEqual(change.kind, ChangeType.CHAIN_CHANGED)
        self.assertEqual(
            [link.role for link in change.old_chain.roles],
            ["targets", "A", "C"],
        )
        self.assertEqual(
            [link.role for link in change.new_chain.roles],
            ["targets", "A", "D"],
        )

    def test_duplicate_arrival_uses_first_parent(self) -> None:
        """A role reached via two parents keeps its first-arrival chain."""
        shared = [
            SpecRole("A", paths=["*/*"], key_label="ka"),
            SpecRole("B", paths=["*/*"], key_label="kb"),
            SpecRole("C", paths=["*/*"], delegator="A", key_label="kc"),
            SpecRole("C", paths=["*/*"], delegator="B", key_label="kc"),
        ]
        signers: dict[str, CryptoSigner] = {}
        old = self._bundle(shared, signers)
        new = self._bundle(shared, signers)
        self.assertFalse(compare_authorization(old, new, ["x/y"]))
        swapped = [
            SpecRole("B", paths=["*/*"], key_label="kb"),
            SpecRole("A", paths=["*/*"], key_label="ka"),
            SpecRole("C", paths=["*/*"], delegator="A", key_label="kc"),
            SpecRole("C", paths=["*/*"], delegator="B", key_label="kc"),
        ]
        old2, swapped_bundle = self._paired(shared, swapped)
        change = compare_authorization(
            old2, swapped_bundle, ["x/y"]
        ).changes[0]
        # Full traversal includes backtracking siblings; the
        # first-arrival parent of C still differs between the graphs.
        self.assertEqual(
            [link.role for link in change.old_chain.roles],
            ["targets", "A", "C", "B"],
        )
        self.assertEqual(
            [link.role for link in change.new_chain.roles],
            ["targets", "B", "C", "A"],
        )

    def test_cycle_is_deterministic_and_terminates(self) -> None:
        """Cyclic delegations are traversed once per role and terminate."""
        roles = [
            SpecRole("A", paths=["*/*"], key_label="ka"),
            SpecRole("B", paths=["*/*"], delegator="A", key_label="kb"),
            SpecRole("C", paths=["*/*"], delegator="B", key_label="kc"),
            SpecRole("B", paths=["*/*"], delegator="C", key_label="kb"),
        ]
        bundle = self._bundle(roles)
        start = time.monotonic()
        diff = compare_authorization(bundle, bundle, ["x/y"])
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertFalse(diff)

    def test_glob_scope_generates_concrete_witness(self) -> None:
        """A glob subset produces concrete witnesses, not raw patterns."""
        old, new = self._paired(
            [SpecRole("A", paths=["pkg/*.tar.gz"], key_label="ka")],
            [
                SpecRole("B", paths=["pkg/*.zip"], key_label="kb"),
                SpecRole("A", paths=["pkg/*.tar.gz"], key_label="ka"),
            ],
        )
        change = compare_authorization(old, new, ["pkg/*"]).changes[0]
        self.assertEqual(change.kind, ChangeType.OWNERSHIP_CHANGED)
        self.assertEqual(len(change.witness_paths), 1)
        witness = change.witness_paths[0]
        self.assertNotIn("*", witness)
        self.assertTrue(witness.startswith("pkg/"))
        self.assertEqual(change.new_chain.first_delegated_role.role, "B")

    def test_glob_scope_with_nested_patterns(self) -> None:
        """Witness generation covers deeper, same-segment-count regions."""
        old, new = self._paired(
            [SpecRole("A", paths=["pkg/*/*"], key_label="ka")],
            [
                SpecRole("B", paths=["pkg/v1/*"], key_label="kb"),
                SpecRole("A", paths=["pkg/*/*"], key_label="ka"),
            ],
        )
        change = compare_authorization(old, new, ["pkg/*/*"]).changes[0]
        self.assertEqual(change.witness_paths[0].count("/"), 2)
        self.assertEqual(change.new_chain.first_delegated_role.role, "B")

    def test_hash_prefix_glob_scope_is_unknown(self) -> None:
        """A glob over hash-prefix delegations is incomparable."""
        hash_bundle = self._bundle([
            SpecRole("H", paths=None, prefixes=["a", "b"], key_label="kh")
        ])
        plain_bundle = self._bundle([
            SpecRole("A", paths=["pkg/*"], key_label="ka")
        ])
        with self.assertRaises(UnknownScopeError):
            compare_authorization(hash_bundle, plain_bundle, ["pkg/*"])

    def test_hash_prefix_literal_scope_is_comparable(self) -> None:
        """A concrete path is comparable even with hash-prefix roles."""
        hash_bundle = self._bundle([
            SpecRole("H", paths=None, prefixes=["0", "1"], key_label="kh")
        ])
        plain_bundle = self._bundle([
            SpecRole("A", paths=["pkg/*"], key_label="ka")
        ])
        diff = compare_authorization(hash_bundle, plain_bundle, ["pkg/foo"])
        self.assertIsInstance(diff.changes, tuple)

    def test_succinct_roles_glob_scope_is_unknown(self) -> None:
        """Succinct (hash bin) delegations also force unknown globs."""
        sim = RepositorySimulator()
        sim.add_succinct_roles("targets", 1, "bin")
        succinct_bundle = TargetsBundle.from_mapping(
            {"targets": sim.md_targets, **sim.md_delegates}
        )
        plain_bundle = self._bundle([
            SpecRole("A", paths=["pkg/*"], key_label="ka")
        ])
        with self.assertRaises(UnknownScopeError):
            compare_authorization(succinct_bundle, plain_bundle, ["pkg/*"])

    def test_witness_limit_is_enforced(self) -> None:
        """Hitting the witness cap raises instead of running unbounded."""
        old, new = self._paired(
            [SpecRole("A", paths=["p/*.a"], key_label="ka")],
            [
                SpecRole("B", paths=["p/*.b"], key_label="kb"),
                SpecRole("A", paths=["p/*.a"], key_label="ka"),
            ],
        )
        with self.assertRaises(LimitExceededError):
            compare_authorization(
                old, new, ["p/*"], AuthorizationLimits(max_witnesses=1)
            )

    def test_role_limit_is_enforced_on_cycles(self) -> None:
        """A tiny role cap terminates cyclic graphs with an error."""
        roles = [
            SpecRole("A", paths=["*/*"], key_label="ka"),
            SpecRole("B", paths=["*/*"], delegator="A", key_label="kb"),
            SpecRole("A", paths=["*/*"], delegator="B", key_label="ka"),
        ]
        bundle = self._bundle(roles)
        with self.assertRaises(LimitExceededError):
            compare_authorization(
                bundle, bundle, ["x/y"], AuthorizationLimits(max_roles=2)
            )

    def test_invalid_limits_rejected(self) -> None:
        with self.assertRaises(ValueError):
            AuthorizationLimits(max_roles=0)
        with self.assertRaises(ValueError):
            AuthorizationLimits(max_witnesses=0)

    def test_empty_scopes_rejected(self) -> None:
        bundle = self._bundle([SpecRole("A", key_label="ka")])
        with self.assertRaises(ValueError):
            compare_authorization(bundle, bundle, [])
        with self.assertRaises(ValueError):
            compare_authorization(bundle, bundle, [""])

    def test_key_rotation_is_ownership_change(self) -> None:
        """Same role name but a rotated key is an ownership change."""
        old = self._bundle([
            SpecRole("A", paths=["pkg/*"], key_label="ka")
        ])
        rotated = [
            SpecRole("A", paths=["pkg/*"], key_label="ka-rotated")
        ]
        old_bundle, new_bundle = self._paired(
            [SpecRole("A", paths=["pkg/*"], key_label="ka")], rotated
        )
        old_keyids = old_bundle.targets["targets"].signed.delegations.roles[
            "A"
        ].keyids
        new_keyids = new_bundle.targets["targets"].signed.delegations.roles[
            "A"
        ].keyids
        self.assertNotEqual(old_keyids, new_keyids)
        change = compare_authorization(
            old_bundle, new_bundle, ["pkg/foo"]
        ).changes[0]
        self.assertEqual(change.kind, ChangeType.OWNERSHIP_CHANGED)
        self.assertEqual(
            change.old_chain.first_delegated_role.keyids, tuple(old_keyids)
        )
        self.assertEqual(
            change.new_chain.first_delegated_role.keyids, tuple(new_keyids)
         )

    def test_output_is_deterministic(self) -> None:
        """Repeated comparisons yield identical ordered witnesses."""
        old, new = self._paired(
            [
                SpecRole("A", paths=["d/*.a"], key_label="ka"),
                SpecRole("B", paths=["d/*.b"], key_label="kb"),
            ],
            [
                SpecRole("B", paths=["d/*.b"], terminating=True, key_label="kb"),
                SpecRole("A", paths=["d/*.a"], key_label="ka"),
            ],
        )
        first = compare_authorization(old, new, ["d/*"])
        second = compare_authorization(old, new, ["d/*"])
        self.assertEqual(first, second)
        for change in first.changes:
            self.assertEqual(
                list(change.witness_paths), sorted(change.witness_paths)
            )

    def test_repeated_comparison_runs_quickly(self) -> None:
        """The offline comparison stays well below the time budget."""
        old, new = self._paired(
            [
                SpecRole("A", paths=["w/*"], key_label="ka"),
                SpecRole("B", paths=["w/*"], key_label="kb"),
                SpecRole("C", paths=["*/*"], delegator="A", key_label="kc"),
            ],
            [
                SpecRole("B", paths=["w/*"], terminating=True, key_label="kb"),
                SpecRole("A", paths=["w/*"], key_label="ka"),
                SpecRole("C", paths=["*/*"], delegator="A", key_label="kc"),
            ],
        )
        start = time.monotonic()
        for _ in range(20):
            compare_authorization(old, new, ["w/x", "w/y"])
        self.assertLess(time.monotonic() - start, 5.0)

    def test_bundle_requires_top_level_targets(self) -> None:
        with self.assertRaises(ValueError):
            TargetsBundle.from_mapping({})


    def test_matches_live_updater_traversal_order(self) -> None:
        """Offline chain order equals the Updater pre-order DFS order."""
        roles = [
            SpecRole("A", paths=["*/*"], key_label="ka"),
            SpecRole("B", paths=["*/*"], key_label="kb"),
            SpecRole("C", paths=["*/*"], delegator="A", terminating=True, key_label="kc"),
            SpecRole("D", paths=["*/*"], delegator="A", key_label="kd"),
        ]
        sim = RepositorySimulator()
        signers: dict[str, CryptoSigner] = {}
        for spec in roles:
            self._add_role(sim, spec, signers)
        sim.update_snapshot()
        bundle = TargetsBundle.from_mapping(
            {"targets": sim.md_targets, **sim.md_delegates}
        )
        with tempfile.TemporaryDirectory() as tmp:
            metadata_dir = os.path.join(tmp, "metadata")
            targets_dir = os.path.join(tmp, "targets")
            os.mkdir(metadata_dir)
            os.mkdir(targets_dir)
            updater = Updater(
                metadata_dir,
                "https://example.com/metadata/",
                targets_dir,
                "https://example.com/targets/",
                sim,
                bootstrap=sim.signed_roots[0],
            )
            updater.refresh()
            sim.fetch_tracker.metadata.clear()
            self.assertIsNone(updater.get_targetinfo("x/y"))
            visited = [name for name, _ in sim.fetch_tracker.metadata]
        chain = compare_authorization(bundle, bundle, ["x/y"])
        self.assertFalse(chain)
        resolved = [
            link.role
            for link in _AuthorizationResolver(
                bundle, AuthorizationLimits()
            ).resolve("x/y").roles
        ]
        resolved = [role for role in resolved if role != "targets"]
        self.assertEqual(resolved, visited)

    def test_missing_role_metadata_is_reported(self) -> None:
        """A chain whose role metadata is absent differs from a full one."""
        roles = [SpecRole("A", paths=["*/*"], key_label="ka")]
        full = self._bundle(roles)
        incomplete = TargetsBundle.from_mapping(
            {"targets": full.targets["targets"]}
        )
        change = compare_authorization(incomplete, full, ["x/y"]).changes[0]
        self.assertEqual(change.old_chain.missing_role, "A")
        self.assertIsNone(change.new_chain.missing_role)
        self.assertEqual(
            [link.role for link in change.old_chain.roles],
            ["targets", "A"],
        )

    def test_path_without_matching_role_is_stable(self) -> None:
        """A path no delegation claims keeps the top-level owner only."""
        bundle = self._bundle([SpecRole("A", paths=["zzz/*"], key_label="ka")])
        diff = compare_authorization(bundle, bundle, ["pkg/foo"])
        self.assertFalse(diff)

    def test_multiple_scopes_aggregate_witnesses(self) -> None:
        """Several literal scopes group under one chain pair."""
        old, new = self._paired(
            [SpecRole("A", paths=["p/*"], key_label="ka")],
            [SpecRole("B", paths=["p/*"], key_label="kb")],
        )
        change = compare_authorization(
            old, new, ["p/z", "p/a", "p/m"]
        ).changes[0]
        self.assertEqual(change.witness_paths, ("p/z", "p/a", "p/m"))

if __name__ == "__main__":
    unittest.main()
    unittest.main()

