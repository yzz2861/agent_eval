import unittest

from secure import (
    CustomHeader,
    HeaderOrigin,
    PolicyConflictError,
    PolicyDiagnostic,
    PolicyEntry,
    PolicyLayer,
    PolicyResolver,
    ResolvedPolicy,
)
from secure.headers import StrictTransportSecurity


def _layer(source: str, priority: int, *pairs: tuple[str, str]) -> PolicyLayer:
    return PolicyLayer.from_headers(source, priority, list(pairs))


class TestPolicyResolverPriority(unittest.TestCase):
    def test_higher_priority_wins_regardless_of_layer_order(self) -> None:
        short_hsts = StrictTransportSecurity().max_age(60)
        long_hsts = StrictTransportSecurity().max_age(31536000)

        resolver = PolicyResolver()
        layers = [
            PolicyLayer.from_headers("route-override", 30, [long_hsts]),
            PolicyLayer.from_headers("tenant", 20, [("Strict-Transport-Security", "max-age=3600")]),
            PolicyLayer.from_headers("default", 10, [short_hsts]),
        ]

        resolved = resolver.resolve(layers)

        self.assertEqual(
            resolved.header_items,
            (("Strict-Transport-Security", "max-age=31536000"),),
        )

        reversed_resolved = resolver.resolve(list(reversed(layers)))
        self.assertEqual(reversed_resolved.header_items, resolved.header_items)

    def test_same_value_across_layers_emits_one_line(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                _layer("default", 10, ("X-Content-Type-Options", "nosniff")),
                _layer("tenant", 20, ("X-Content-Type-Options", "nosniff")),
            ]
        )

        self.assertEqual(resolved.header_items, (("X-Content-Type-Options", "nosniff"),))

    def test_first_seen_header_order_is_stable(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                _layer("default", 10, ("X-One", "a"), ("X-Two", "b")),
                _layer("tenant", 20, ("X-Three", "c")),
            ]
        )

        self.assertEqual([name for name, _ in resolved.header_items], ["X-One", "X-Two", "X-Three"])

    def test_origins_record_source_and_priority(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                _layer("default", 10, ("Server", "old")),
                _layer("tenant", 20, ("Server", "new")),
            ]
        )

        origins = resolved.origins["server"]
        self.assertEqual(origins, (HeaderOrigin(source="tenant", priority=20, effect="allow", value="new"),))


class TestPolicyResolverDeny(unittest.TestCase):
    def test_deny_overrides_lower_priority_allow(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                _layer("default", 10, ("X-Frame-Options", "SAMEORIGIN")),
                PolicyLayer(
                    "tenant",
                    20,
                    (PolicyEntry.deny("X-Frame-Options", source="tenant"),),
                ),
            ]
        )

        self.assertEqual(resolved.header_items, ())
        self.assertEqual(resolved.origins["x-frame-options"][0].effect, "deny")

    def test_higher_priority_allow_beats_deny(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                PolicyLayer("tenant", 20, (PolicyEntry.deny("X-Frame-Options"),)),
                _layer("route", 30, ("X-Frame-Options", "DENY")),
            ]
        )

        self.assertEqual(resolved.header_items, (("X-Frame-Options", "DENY"),))

    def test_deny_at_same_priority_wins_over_allow(self) -> None:
        layer = PolicyLayer(
            "tenant",
            20,
            (
                PolicyEntry.allow("Server", "hidden"),
                PolicyEntry.deny("Server"),
            ),
        )

        resolved = PolicyResolver().resolve([layer])

        self.assertEqual(resolved.header_items, ())

    def test_deny_does_not_suppress_higher_priority_multi_lines(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                _layer("default", 10, ("Content-Security-Policy", "default-src 'self'")),
                PolicyLayer("tenant", 20, (PolicyEntry.deny("Content-Security-Policy"),)),
                _layer("route", 30, ("Content-Security-Policy", "frame-ancestors 'none'")),
            ]
        )

        self.assertEqual(
            resolved.header_items,
            (("Content-Security-Policy", "frame-ancestors 'none'"),),
        )


class TestPolicyResolverMultiValue(unittest.TestCase):
    def test_multi_ok_keeps_one_line_per_distinct_value(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                _layer("default", 10, ("Content-Security-Policy", "default-src 'self'")),
                _layer("tenant", 20, ("Content-Security-Policy", "img-src https:")),
                _layer("route", 20, ("Content-Security-Policy", "img-src https:")),
            ]
        )

        self.assertEqual(
            resolved.header_items,
            (
                ("Content-Security-Policy", "default-src 'self'"),
                ("Content-Security-Policy", "img-src https:"),
            ),
        )

    def test_comma_join_ok_merges_values_in_declaration_order(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                _layer("default", 10, ("Cache-Control", "max-age=0")),
                _layer("tenant", 20, ("Cache-Control", "no-cache")),
            ]
        )

        self.assertEqual(resolved.header_items, (("Cache-Control", "max-age=0, no-cache"),))

    def test_custom_merge_rules_are_supported(self) -> None:
        resolver = PolicyResolver(
            multi_ok=frozenset({"x-custom-multi"}),
            comma_join_ok=frozenset({"x-custom-join"}),
        )

        resolved = resolver.resolve(
            [
                _layer("default", 10, ("X-Custom-Multi", "a"), ("X-Custom-Join", "a")),
                _layer("tenant", 20, ("X-Custom-Multi", "b"), ("X-Custom-Join", "b")),
            ]
        )

        self.assertEqual(
            resolved.header_items,
            (
                ("X-Custom-Multi", "a"),
                ("X-Custom-Multi", "b"),
                ("X-Custom-Join", "a, b"),
            ),
        )

    def test_single_valued_header_ignores_shadowed_lower_priority_values(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                _layer("default", 10, ("Referrer-Policy", "unsafe-url")),
                _layer("tenant", 20, ("Referrer-Policy", "no-referrer")),
            ]
        )

        self.assertEqual(resolved.header_items, (("Referrer-Policy", "no-referrer"),))


class TestPolicyResolverConflicts(unittest.TestCase):
    def test_same_priority_conflicting_single_values_raise_readable_error(self) -> None:
        with self.assertRaises(PolicyConflictError) as context:
            PolicyResolver().resolve(
                [
                    _layer("tenant-a", 20, ("X-Frame-Options", "SAMEORIGIN")),
                    _layer("tenant-b", 20, ("X-Frame-Options", "DENY")),
                ]
            )

        message = str(context.exception)
        self.assertIn("X-Frame-Options", message)
        self.assertIn("SAMEORIGIN", message)
        self.assertIn("DENY", message)
        diagnostic = context.exception.diagnostics[0]
        self.assertIsInstance(diagnostic, PolicyDiagnostic)
        self.assertEqual([origin.source for origin in diagnostic.origins], ["tenant-a", "tenant-b"])

    def test_collect_mode_omits_conflicted_header_and_records_diagnostic(self) -> None:
        resolved = PolicyResolver(on_conflict="collect").resolve(
            [
                _layer("tenant-a", 20, ("X-Frame-Options", "SAMEORIGIN"), ("Server", "ok")),
                _layer("tenant-b", 20, ("X-Frame-Options", "DENY")),
            ]
        )

        self.assertEqual(resolved.header_items, (("Server", "ok"),))
        self.assertEqual(len(resolved.diagnostics), 1)
        self.assertEqual(resolved.diagnostics[0].header, "X-Frame-Options")

    def test_lower_priority_value_never_triggers_conflict(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                _layer("default", 10, ("X-Frame-Options", "SAMEORIGIN")),
                _layer("tenant", 20, ("X-Frame-Options", "DENY")),
            ]
        )

        self.assertEqual(resolved.header_items, (("X-Frame-Options", "DENY"),))
        self.assertEqual(resolved.diagnostics, ())


class TestPolicyResolverValidation(unittest.TestCase):
    def test_invalid_header_name_is_rejected_by_default(self) -> None:
        with self.assertRaises(ValueError):
            PolicyResolver().resolve([_layer("default", 10, ("Bad Header", "value"))])

    def test_crlf_in_value_is_rejected_in_strict_mode(self) -> None:
        with self.assertRaises(ValueError):
            PolicyResolver().resolve([_layer("default", 10, ("X-Inject", "bad\rvalue"))])

    def test_empty_value_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PolicyResolver().resolve([_layer("default", 10, ("X-Empty", "   "))])

    def test_deny_with_invalid_name_is_validated(self) -> None:
        with self.assertRaises(ValueError):
            PolicyResolver().resolve([PolicyLayer("default", 10, (PolicyEntry.deny("Bad Name"),))])

    def test_merge_cannot_bypass_validation_in_drop_mode(self) -> None:
        resolved = PolicyResolver(on_invalid="drop").resolve(
            [
                _layer("default", 10, ("Bad Name", "value"), ("X-Good", "value")),
            ]
        )

        self.assertEqual(resolved.header_items, (("X-Good", "value"),))

    def test_non_strict_resolver_sanitizes_crlf(self) -> None:
        resolved = PolicyResolver(strict=False).resolve([_layer("default", 10, ("X-Sanitized", "line1\nline2"))])

        self.assertEqual(resolved.header_items, (("X-Sanitized", "line1 line2"),))


class TestPolicyResolverEdgeCases(unittest.TestCase):
    def test_empty_layer_set_resolves_to_empty_snapshot(self) -> None:
        resolved = PolicyResolver().resolve(())

        self.assertEqual(resolved.header_items, ())
        self.assertEqual(dict(resolved.headers), {})
        self.assertEqual(resolved.diagnostics, ())

    def test_collect_mode_accumulates_multiple_conflicts(self) -> None:
        resolved = PolicyResolver(on_conflict="collect").resolve(
            [
                _layer("a", 10, ("X-One", "1"), ("X-Two", "a")),
                _layer("b", 10, ("X-One", "2"), ("X-Two", "b")),
            ]
        )

        self.assertEqual(resolved.header_items, ())
        self.assertEqual([diagnostic.header for diagnostic in resolved.diagnostics], ["X-One", "X-Two"])

    def test_invalid_deny_name_is_dropped_when_configured(self) -> None:
        resolved = PolicyResolver(on_invalid="drop").resolve(
            [
                PolicyLayer("default", 10, (PolicyEntry.deny("Bad Name"),)),
                _layer("default", 10, ("X-Good", "value")),
            ]
        )

        self.assertEqual(resolved.header_items, (("X-Good", "value"),))

    def test_entry_specific_source_overrides_layer_source(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                PolicyLayer(
                    "tenant",
                    20,
                    (PolicyEntry.allow("Server", "custom", source="route-override"),),
                )
            ]
        )

        self.assertEqual(resolved.origins["server"][0].source, "route-override")

    def test_non_layer_input_raises_type_error(self) -> None:
        with self.assertRaises(TypeError):
            PolicyResolver().resolve([("X-A", "1")])  # type: ignore[list-item]

    def test_invalid_entry_constructor_arguments_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            PolicyEntry(name="", value="v")
        with self.assertRaises(ValueError):
            PolicyEntry(name="X-A", value="v", effect="maybe")  # type: ignore[arg-type]


class TestResolvedPolicyImmutability(unittest.TestCase):
    def setUp(self) -> None:
        self.header = CustomHeader("X-Test", "original")
        self.resolved = PolicyResolver().resolve([PolicyLayer.from_headers("default", 10, [self.header])])

    def test_snapshot_is_an_immutable_resolved_policy(self) -> None:
        self.assertIsInstance(self.resolved, ResolvedPolicy)
        with self.assertRaises((AttributeError, TypeError)):
            self.resolved.items = ()  # type: ignore[misc]
        with self.assertRaises(TypeError):
            self.resolved.origins["new"] = ()  # type: ignore[index]
        with self.assertRaises(TypeError):
            self.resolved.items[0] = ("X-Other", "v")  # type: ignore[index]

    def test_source_mutation_does_not_change_snapshot(self) -> None:
        self.header.set("mutated")

        self.assertEqual(self.resolved.header_items, (("X-Test", "original"),))

    def test_layer_mutation_does_not_change_snapshot(self) -> None:
        layer = PolicyLayer.from_headers("default", 10, [("X-Other", "v")])
        resolved = PolicyResolver().resolve([layer])

        self.assertEqual(resolved.header_items, (("X-Other", "v"),))
        self.assertIsInstance(resolved.layers[0], PolicyLayer)
        with self.assertRaises((AttributeError, TypeError)):
            resolved.layers[0].source = "hacked"  # type: ignore[misc]

    def test_headers_mapping_is_immutable(self) -> None:
        with self.assertRaises(TypeError):
            self.resolved.headers["X-Test"] = "other"  # type: ignore[index]

    def test_headers_rejects_multi_line_snapshots(self) -> None:
        resolved = PolicyResolver().resolve(
            [
                _layer("default", 10, ("Content-Security-Policy", "a")),
                _layer("tenant", 20, ("Content-Security-Policy", "b")),
            ]
        )

        with self.assertRaises(ValueError):
            _ = resolved.headers


if __name__ == "__main__":
    unittest.main()
