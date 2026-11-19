# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for the offline key-compromise analyzer (tuf.analysis).

The fixtures use RepositorySimulator only to build in-memory metadata and
ephemeral test keys: the analyzer never sees a private key and never signs
or verifies anything itself. The exhaustive reference solver independently
cross-checks the branch-and-bound solver on every graph.
"""

from __future__ import annotations

import inspect
import random
import time
import unittest

from securesystemslib.signer import CryptoSigner

from tests.repository_simulator import RepositorySimulator
from tuf.analysis import (
    AnalysisLimits,
    CompromiseAnalysis,
    CompromiseLimitReachedError,
    analyze_target_compromise,
    compromise,
    exhaustive_minimum_keyids,
)
from tuf.analysis.compromise import (
    _branch_and_bound,
    _enumerate_routes,
    _top_level_gates,
)
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    DelegatedRole,
    Delegations,
    Key,
    Metadata,
    Targets,
)

SPEC_VER = ".".join(SPECIFICATION_VERSION)


class CompromiseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sim = RepositorySimulator()
        self.expiry = self.sim.safe_expiry
        self._key_lookup: dict[str, Key] = {}

    def _targets(self) -> Targets:
        return Targets(1, SPEC_VER, self.expiry, {}, None)

    def _new_key(self) -> CryptoSigner:
        signer = CryptoSigner.generate_ed25519()
        self._key_lookup[signer.public_key.keyid] = signer.public_key
        return signer

    def _delegate(
        self,
        delegator: str,
        name: str,
        keyids: list[str],
        threshold: int,
        paths: list[str],
        terminating: bool = False,
    ) -> None:
        """Create a delegation edge with an explicit key set."""

        role = DelegatedRole(name, list(keyids), threshold, terminating, paths)
        if name not in self.sim.md_delegates:
            self.sim.md_delegates[name] = Metadata(self._targets())
        delegator_md = self.sim._get_delegator(delegator)
        if delegator_md.delegations is None:
            delegator_md.delegations = Delegations({}, roles={})
        delegator_md.delegations.roles[name] = role
        for keyid in keyids:
            delegator_md.delegations.keys[keyid] = self._key_lookup[keyid]

    def _publish(self, role: str, path: str, data: bytes = b"x") -> None:
        self.sim.add_target(role, data, path)

    def _snapshot(self) -> None:
        self.sim.update_snapshot()

    def _metadata(self) -> dict[str, Targets]:
        md = {"targets": self.sim.md_targets.signed}
        md.update({n: m.signed for n, m in self.sim.md_delegates.items()})
        return md

    def _analyze(
        self, path: str, limits: AnalysisLimits | None = None
    ) -> CompromiseAnalysis:
        return analyze_target_compromise(
            self.sim.root,
            self._metadata(),
            path,
            limits if limits is not None else AnalysisLimits(),
        )

    def _top_keyids(self, *roles: str) -> set[str]:
        out: set[str] = set()
        for role in roles:
            out.update(self.sim.root.roles[role].keyids)
        return out

    def _edge_keyids(self, delegator: str, name: str) -> set[str]:
        return set(
            self.sim._get_delegator(delegator).delegations.roles[name].keyids
        )

    def test_simple_chain_minimum(self) -> None:
        ka = self._new_key()
        kb = self._new_key()
        self._delegate("targets", "a", [ka.public_key.keyid], 1, ["foo/*"])
        self._delegate("a", "b", [kb.public_key.keyid], 1, ["foo/bar"])
        self._publish("b", "foo/bar")
        self._snapshot()
        result = self._analyze("foo/bar")
        self.assertTrue(result.reachable)
        self.assertTrue(result.complete)
        expected = self._top_keyids("timestamp", "snapshot", "targets")
        expected |= self._edge_keyids("targets", "a")
        expected |= self._edge_keyids("a", "b")
        self.assertEqual(set(result.minimum_keyids), expected)
        self.assertEqual(len(result.minimum_keyids), 5)
        self.assertEqual(result.witness.proof, "exhaustive")
        self.assertIn("root-trusted", [a.code for a in result.assumptions])

    def test_threshold_requires_multiple_keys(self) -> None:
        k1 = self._new_key()
        k2 = self._new_key()
        ids = [k1.public_key.keyid, k2.public_key.keyid]
        self._delegate("targets", "dual", ids, 2, ["f"])
        self._publish("dual", "f")
        self._snapshot()
        result = self._analyze("f")
        self.assertTrue(result.complete)
        self.assertEqual(result.witness.gates["targets->dual"][0], 2)
        self.assertTrue(set(ids).issubset(result.minimum_keyids))
        self.assertEqual(len(result.minimum_keyids), 5)

    def test_shared_keyid_counted_once(self) -> None:
        shared = self._new_key()
        kb = self._new_key()
        sid = shared.public_key.keyid
        self._delegate("targets", "a", [sid], 1, ["p/*"])
        # Reuse the same key on the a->b edge plus one extra key.
        self._delegate("a", "b", [sid, kb.public_key.keyid], 1, ["p/f"])
        self._publish("b", "p/f")
        self._snapshot()
        result = self._analyze("p/f")
        self.assertTrue(result.complete)
        # 3 top-level keys + shared edge key + kb = 4 distinct keys.
        self.assertEqual(len(result.minimum_keyids), 4)
        self.assertIn(sid, result.minimum_keyids)
        naive = sum(g[0] for g in result.witness.gates.values())
        self.assertEqual(naive, 5)
        self.assertLess(len(result.minimum_keyids), naive)

    def test_shared_top_level_key(self) -> None:
        signer = self._new_key()
        kid = signer.public_key.keyid
        for role in ("timestamp", "snapshot", "targets"):
            self.sim.root.roles[role].keyids = [kid]
            self.sim.root.keys[kid] = signer.public_key
        self._publish("targets", "f")
        self._snapshot()
        result = self._analyze("f")
        self.assertTrue(result.complete)
        self.assertEqual(set(result.minimum_keyids), {kid})

    def test_alternative_paths_cheapest_wins(self) -> None:
        ka = self._new_key()
        kb = self._new_key()
        kc = self._new_key()
        kq = self._new_key()
        self._delegate("targets", "a", [ka.public_key.keyid], 1, ["p/*"])
        self._delegate("a", "b", [kb.public_key.keyid], 1, ["p/f"])
        self._delegate("b", "c", [kc.public_key.keyid], 1, ["p/f"])
        self._publish("c", "p/f", b"long")
        self._delegate("targets", "quick", [kq.public_key.keyid], 1, ["p/f"])
        self._publish("quick", "p/f", b"short")
        self._snapshot()
        result = self._analyze("p/f")
        self.assertTrue(result.complete)
        self.assertEqual(len(result.witness.routes), 2)
        self.assertEqual(len(result.minimum_keyids), 4)
        self.assertTrue(
            set(result.witness.gates["targets->quick"][1]).intersection(
                result.minimum_keyids
            )
        )
        self.assertFalse(
            set(result.witness.gates["b->c"][1]).intersection(
                result.minimum_keyids
            )
        )

    def test_diamond_shared_role_edges(self) -> None:
        shared = self._new_key()
        sid = shared.public_key.keyid
        self._delegate(
            "targets", "pa", [self._new_key().public_key.keyid], 1, ["x/*"]
        )
        self._delegate(
            "targets", "pb", [self._new_key().public_key.keyid], 1, ["x/*"]
        )
        self._delegate("pa", "release", [sid], 1, ["x/f"])
        # pb delegates to the same role but the edge is defined by pb.
        self._delegate("pb", "release", [sid], 1, ["x/f"])
        self._publish("release", "x/f", b"r")
        self._snapshot()
        result = self._analyze("x/f")
        self.assertTrue(result.complete)
        self.assertEqual(len(result.witness.routes), 2)
        self.assertIn("pa->release", result.witness.gates)
        self.assertIn("pb->release", result.witness.gates)
        self.assertIn(sid, result.minimum_keyids)

    def test_unreachable_target(self) -> None:
        k = self._new_key()
        self._delegate("targets", "a", [k.public_key.keyid], 1, ["covered/*"])
        self._publish("a", "covered/f")
        self._snapshot()
        result = self._analyze("elsewhere/f")
        self.assertFalse(result.reachable)
        self.assertTrue(result.complete)
        self.assertEqual(set(result.minimum_keyids), set())
        self.assertIsNone(result.witness)

    def test_missing_delegated_metadata_is_assumption(self) -> None:
        ka = self._new_key()
        kb = self._new_key()
        self._delegate("targets", "a", [ka.public_key.keyid], 1, ["p/*"])
        self._delegate("a", "b", [kb.public_key.keyid], 1, ["p/f"])
        self._publish("b", "p/f")
        self._snapshot()
        md = self._metadata()
        del md["a"]
        result = analyze_target_compromise(self.sim.root, md, "p/f")
        self.assertFalse(result.reachable)
        self.assertIn("missing-metadata", [a.code for a in result.assumptions])

    def test_delegation_cycle_not_followed(self) -> None:
        k = self._new_key()
        back = self._new_key()
        kid = k.public_key.keyid
        self._delegate("targets", "loop", [kid], 1, ["p/*"])
        loop_md = self.sim.md_delegates["loop"].signed
        loop_md.delegations = Delegations(
            {back.public_key.keyid: back.public_key},
            roles={
                "loop": DelegatedRole(
                    "loop", [back.public_key.keyid], 1, False, ["p/f"]
                )
            },
        )
        self._publish("loop", "p/f")
        self._snapshot()
        result = self._analyze("p/f")
        self.assertTrue(result.reachable)
        self.assertIn("delegation-cycle", [a.code for a in result.assumptions])
        self.assertEqual(
            result.witness.routes,
            (("timestamp", "snapshot", "targets", "loop"),),
        )

    def test_size_limit_returns_incomplete(self) -> None:
        k = self._new_key()
        self._delegate("targets", "a", [k.public_key.keyid], 1, ["f"])
        self._publish("a", "f")
        self._snapshot()
        tight = AnalysisLimits(
            max_keys=2, max_gates=256, max_routes=4096, max_subsets=10
        )
        result = self._analyze("f", tight)
        self.assertTrue(result.reachable)
        self.assertFalse(result.complete)
        self.assertIn("size-limit", [a.code for a in result.assumptions])
        self.assertEqual(set(result.minimum_keyids), set())

    def test_search_limit_returns_incomplete(self) -> None:
        k = self._new_key()
        self._delegate("targets", "a", [k.public_key.keyid], 1, ["f"])
        self._publish("a", "f")
        self._snapshot()
        tight = AnalysisLimits(
            max_keys=64, max_gates=256, max_routes=4096, max_subsets=0
        )
        result = self._analyze("f", tight)
        self.assertFalse(result.complete)
        self.assertIn("search-limit", [a.code for a in result.assumptions])

    def test_exhaustive_solver_raises_past_limit(self) -> None:
        k = self._new_key()
        self._delegate("targets", "a", [k.public_key.keyid], 1, ["f"])
        self._publish("a", "f")
        self._snapshot()
        routes, _ = _enumerate_routes(
            self._metadata(),
            _top_level_gates(self.sim.root),
            "f",
            AnalysisLimits(),
        )
        with self.assertRaises(CompromiseLimitReachedError):
            exhaustive_minimum_keyids(routes, AnalysisLimits(max_subsets=1))

    def test_unsatisfiable_gate_excluded(self) -> None:
        k = self._new_key()
        self._delegate("targets", "broken", [k.public_key.keyid], 2, ["f"])
        self._publish("broken", "f")
        self._snapshot()
        result = self._analyze("f")
        self.assertFalse(result.reachable)
        self.assertIn(
            "unsatisfiable-gate", [a.code for a in result.assumptions]
        )

    def test_succinct_roles_route(self) -> None:
        self.sim.add_succinct_roles("targets", 4, "bin")
        succinct = self.sim.targets.delegations.succinct_roles
        bin_name = succinct.get_role_for_target("f")
        self._publish(bin_name, "f")
        self._snapshot()
        result = self._analyze("f")
        self.assertTrue(result.reachable)
        self.assertTrue(result.complete)
        self.assertEqual(len(result.witness.routes), 1)
        self.assertEqual(result.witness.routes[0][-1], bin_name)

    def test_solvers_agree_on_random_graphs(self) -> None:
        rng = random.Random(7)
        names = [f"r{i}" for i in range(6)]
        for _ in range(25):
            sim = RepositorySimulator()
            lookup: dict[str, Key] = {}
            created: set[str] = set()
            for name in names:
                parent = "targets" if rng.random() < 0.5 else rng.choice(names)
                if parent == name or (
                    parent != "targets" and parent not in created
                ):
                    parent = "targets"
                threshold = rng.choice([1, 1, 1, 2])
                keyids = []
                for _ in range(max(threshold, rng.choice([1, 2, 3]))):
                    signer = CryptoSigner.generate_ed25519()
                    lookup[signer.public_key.keyid] = signer.public_key
                    keyids.append(signer.public_key.keyid)
                role = DelegatedRole(name, keyids, threshold, False, ["t"])
                if name not in sim.md_delegates:
                    sim.md_delegates[name] = Metadata(
                        Targets(1, SPEC_VER, sim.safe_expiry, {}, None)
                    )
                delegator_md = sim._get_delegator(parent)
                if delegator_md.delegations is None:
                    delegator_md.delegations = Delegations({}, roles={})
                delegator_md.delegations.roles[name] = role
                for kid in keyids:
                    delegator_md.delegations.keys[kid] = lookup[kid]
                created.add(name)
            terminal = rng.choice(names)
            sim.add_target(terminal, b"x", "t")
            sim.update_snapshot()
            md = {"targets": sim.md_targets.signed}
            md.update({n: m.signed for n, m in sim.md_delegates.items()})
            result = analyze_target_compromise(sim.root, md, "t")
            if not result.reachable:
                continue
            routes, _ = _enumerate_routes(
                md, _top_level_gates(sim.root), "t", AnalysisLimits()
            )
            ex_min, ex_n = exhaustive_minimum_keyids(routes)
            bb_min, _ = _branch_and_bound(routes, AnalysisLimits())
            self.assertEqual(set(ex_min), set(bb_min))
            self.assertEqual(len(result.minimum_keyids), len(ex_min[0]))
            self.assertEqual(ex_n, result.witness.subsets_inspected)

    def test_minimality_witness_lists_all_minima(self) -> None:
        ids = [self._new_key().public_key.keyid for _ in range(3)]
        self._delegate("targets", "tri", ids, 2, ["f"])
        self._publish("tri", "f")
        self._snapshot()
        result = self._analyze("f")
        self.assertTrue(result.complete)
        # 3 choose 2 = 3 alternative minima for the delegation gate.
        self.assertEqual(len(result.witness.alternative_minima), 3)
        for minimum in result.witness.alternative_minima:
            self.assertEqual(len(minimum), 5)

    def test_analyzer_does_not_mutate_inputs(self) -> None:
        ka = self._new_key()
        kb = self._new_key()
        self._delegate("targets", "a", [ka.public_key.keyid], 1, ["p/*"])
        self._delegate("a", "b", [kb.public_key.keyid], 1, ["p/f"])
        self._publish("b", "p/f")
        self._snapshot()
        root_before = self.sim.root.to_dict()
        md = self._metadata()
        md_before = {k: v.to_dict() for k, v in md.items()}
        self._analyze("p/f")
        self.assertEqual(self.sim.root.to_dict(), root_before)
        self.assertEqual({k: v.to_dict() for k, v in md.items()}, md_before)

    def test_analyzer_has_no_signing_dependency(self) -> None:
        source = inspect.getsource(compromise)
        self.assertNotIn("securesystemslib.signer", source)
        self.assertNotIn("CryptoSigner", source)
        self.assertNotIn(".sign(", source)

    def test_dozen_roles_under_ten_seconds(self) -> None:
        keys = [self._new_key() for _ in range(4)]
        kids = [s.public_key.keyid for s in keys]
        for i in range(12):
            parent = "targets" if i < 4 else f"r{(i - 4) % 4}"
            chosen = kids[: 1 + (i % 3)]
            self._delegate(parent, f"r{i}", chosen, 1, ["pkg/x"])
        self._publish("r11", "pkg/x")
        self._snapshot()
        start = time.perf_counter()
        result = self._analyze("pkg/x")
        elapsed = time.perf_counter() - start
        self.assertTrue(result.reachable)
        self.assertTrue(result.complete)
        self.assertLess(elapsed, 10.0)
        self.assertLessEqual(len(result.minimum_keyids), 7)

    def test_branch_and_bound_fallback_proves_minimum(self) -> None:
        # On a long chain the admissible bound lets branch-and-bound prove
        # the minimum far below the subset budget that exhausts the simple
        # reference solver, so the fallback still returns a complete result.
        self._delegate(
            "targets", "d0", [self._new_key().public_key.keyid], 1, ["f"]
        )
        for depth in range(1, 7):
            self._delegate(
                f"d{depth - 1}",
                f"d{depth}",
                [self._new_key().public_key.keyid],
                1,
                ["f"],
            )
        self._publish("d6", "f")
        self._snapshot()
        tight = AnalysisLimits(
            max_keys=64,
            max_gates=256,
            max_routes=4096,
            max_subsets=200,
        )
        result = self._analyze("f", tight)
        self.assertTrue(result.reachable)
        self.assertTrue(result.complete)
        self.assertEqual(result.witness.proof, "branch-and-bound")
        # Three top-level gates plus seven delegation gates.
        self.assertEqual(len(result.minimum_keyids), 10)


if __name__ == "__main__":
    unittest.main()
