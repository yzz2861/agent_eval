# SPDX-License-Identifier: Apache-2.0
import testtools

from bandit.core import rule_set


class RuleResolverTests(testtools.TestCase):
    def test_explicit_id_beats_wildcard_same_layer(self):
        resolver = rule_set.RuleResolver(
            repository={
                "B*": {"severity": "LOW"},
                "B105": {"severity": "HIGH"},
            }
        )
        self.assertEqual("HIGH", resolver.get_override("B105")["severity"])
        self.assertEqual("LOW", resolver.get_override("B106")["severity"])

    def test_profile_overrides_repository(self):
        resolver = rule_set.RuleResolver(
            repository={"B105": {"severity": "LOW"}},
            profile={"B105": {"severity": "MEDIUM"}},
        )
        self.assertEqual(
            "MEDIUM", resolver.get_override("B105")["severity"]
        )

    def test_command_line_overrides_profile_and_repository(self):
        resolver = rule_set.RuleResolver(
            repository={"B105": {"severity": "LOW"}},
            profile={"B105": {"severity": "MEDIUM"}},
            command_line={"B105": {"severity": "HIGH"}},
        )
        self.assertEqual(
            "HIGH", resolver.get_override("B105")["severity"]
        )

    def test_wildcard_deterministic_without_conflict(self):
        resolver = rule_set.RuleResolver(
            repository={
                "B3*": {"severity": "LOW"},
                "B30*": {"severity": "LOW"},
            },
            strict=True,
        )
        self.assertEqual("LOW", resolver.get_override("B307")["severity"])

    def test_conflicting_wildcards_fail_in_strict_mode(self):
        self.assertRaises(
            rule_set.RuleConfigError,
            rule_set.RuleResolver,
            repository={
                "B3*": {"severity": "LOW"},
                "B30*": {"severity": "HIGH"},
            },
            strict=True,
        )

    def test_overlapping_wildcards_in_different_layers_are_allowed(self):
        # Layer precedence deterministically resolves the overlap, so this
        # is not treated as a conflict even in strict mode.
        resolver = rule_set.RuleResolver(
            repository={"B3*": {"severity": "LOW"}},
            profile={"B30*": {"severity": "HIGH"}},
            strict=True,
        )
        self.assertEqual("HIGH", resolver.get_override("B307")["severity"])
        # The profile wildcard also matches B301 and wins by layer order.
        self.assertEqual("HIGH", resolver.get_override("B301")["severity"])
        # B324 is outside B30* and keeps the repository wildcard value.
        self.assertEqual("LOW", resolver.get_override("B324")["severity"])

    def test_conflicting_wildcards_tolerated_without_strict(self):
        resolver = rule_set.RuleResolver(
            repository={
                "B3*": {"severity": "LOW"},
                "B30*": {"severity": "HIGH"},
            },
        )
        # Deterministic: patterns are sorted, B3* wins the first match.
        self.assertEqual("LOW", resolver.get_override("B307")["severity"])

    def test_invalid_enum_fails_strict(self):
        self.assertRaises(
            rule_set.RuleConfigError,
            rule_set._normalise_overrides,
            {"B105": {"severity": "CRITICAL"}},
            "config file",
            True,
        )

    def test_invalid_enum_warns_when_lenient(self):
        normalised = rule_set._normalise_overrides(
            {"B105": {"severity": "CRITICAL"}}, "config file", False
        )
        self.assertEqual({}, normalised)

    def test_unknown_test_id_fails_strict(self):
        self.assertRaises(
            rule_set.RuleConfigError,
            rule_set._normalise_overrides,
            {"B999": {"severity": "HIGH"}},
            "config file",
            True,
        )

    def test_unknown_test_id_lenient_skips_entry(self):
        normalised = rule_set._normalise_overrides(
            {"B999": {"severity": "HIGH"}}, "config file", False
        )
        self.assertEqual({}, normalised)

    def test_wildcard_pattern_does_not_need_known_id(self):
        normalised = rule_set._normalise_overrides(
            {"B*": {"severity": "HIGH"}}, "config file", True
        )
        self.assertEqual(
            {"severity": "HIGH"}, normalised["B*"]
        )

    def test_confidence_override(self):
        resolver = rule_set.RuleResolver(
            repository={"B105": {"confidence": "HIGH"}},
        )
        self.assertEqual(
            "HIGH", resolver.get_override("B105")["confidence"]
        )

    def test_apply_mutates_issue_and_keeps_unmapped(self):
        from bandit.core import issue as issue_module

        resolver = rule_set.RuleResolver(
            repository={"B105": {"severity": "HIGH"}},
        )
        finding = issue_module.Issue(
            severity="LOW", confidence="MEDIUM", test_id="B105"
        )
        resolver.apply(finding)
        self.assertEqual("HIGH", finding.severity)
        self.assertEqual("MEDIUM", finding.confidence)

        untouched = issue_module.Issue(
            severity="LOW", confidence="LOW", test_id="B201"
        )
        resolver.apply(untouched)
        self.assertEqual("LOW", untouched.severity)

    def test_repeated_resolution_is_stable(self):
        resolver = rule_set.RuleResolver(
            repository={
                "B*": {"confidence": "LOW"},
            },
            profile={"B105": {"severity": "HIGH"}},
            command_line={"B105": {"severity": "MEDIUM"}},
            strict=True,
        )
        first = resolver.get_override("B105")
        for _ in range(5):
            self.assertEqual(first, resolver.get_override("B105"))
