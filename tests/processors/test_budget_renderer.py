# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

from __future__ import annotations

import json
import random

import pytest

from structlog.processors import BudgetedJSONRenderer


class TestBudgetedJSONRenderer:
    def test_renders_within_budget_when_everything_fits(self):
        event = {"event": "hello", "level": "info", "n": [1, 2, 3]}

        out = BudgetedJSONRenderer(200)(None, "", event)

        assert json.loads(out) == event
        assert len(out.encode("utf-8")) <= 200

    def test_output_is_compact(self):
        out = BudgetedJSONRenderer(200)(None, "", {"a": 1, "b": 2})

        assert out == '{"a":1,"b":2}'

    def test_budget_counts_utf8_bytes_not_characters(self):
        # 12 characters but more bytes; a character-based limit would fail.
        event = {"event": "中" * 100}
        budget = 60
        assert len(json.dumps(event, ensure_ascii=False)) > budget

        out = BudgetedJSONRenderer(budget)(None, "", event)

        assert len(out.encode("utf-8")) <= budget
        json.loads(out)

    def test_long_string_is_shortened(self):
        out = BudgetedJSONRenderer(40)(None, "", {"event": "x" * 100})

        decoded = json.loads(out)
        assert "_truncated" in decoded
        assert decoded["event"].endswith("\u2026")
        assert len(out.encode("utf-8")) <= 40

    def test_multibyte_string_cut_on_code_point_boundary(self):
        for budget in range(31, 80):
            out = BudgetedJSONRenderer(budget)(
                None, "", {"event": "😀🎉中" * 10}
            )

            assert len(out.encode("utf-8")) <= budget
            json.loads(out)

    def test_low_priority_fields_are_dropped_first(self):
        event = {"event": "important", "debug": "d" * 100}

        out = BudgetedJSONRenderer(50)(None, "", event)
        decoded = json.loads(out)

        assert decoded["event"] == "important"
        assert "debug" not in decoded
        assert decoded["_truncated"] == "truncated"

    def test_custom_priority_order(self):
        event = {"event": "e" * 50, "important": "keep"}

        out = BudgetedJSONRenderer(
            45, priority=("important", "event")
        )(None, "", event)
        decoded = json.loads(out)

        assert decoded["important"] == "keep"
        assert list(decoded)[:2] == ["_truncated", "important"]

    def test_nested_containers_are_reduced(self):
        event = {"event": "ok", "data": {"a": "x" * 100, "b": 2}}

        out = BudgetedJSONRenderer(60)(None, "", event)
        decoded = json.loads(out)

        assert decoded["event"] == "ok"
        assert isinstance(decoded.get("data"), dict)
        assert len(out.encode("utf-8")) <= 60

    def test_truncation_note_is_first_field(self):
        out = BudgetedJSONRenderer(60)(None, "", {"event": "x" * 100})

        assert out.startswith('{"_truncated":"truncated"')

    def test_user_truncated_key_does_not_duplicate(self):
        event = {"_truncated": "user-value", "event": "ok"}

        out = BudgetedJSONRenderer(200)(None, "", event)
        decoded = json.loads(out)

        assert decoded["_truncated"] == "user-value"
        assert out.count("_truncated") == 1

    def test_does_not_mutate_event_dict(self):
        event = {"event": "x" * 10_000_000, "n": [1, 2]}

        BudgetedJSONRenderer(100)(None, "", event)

        assert event["event"] == "x" * 10_000_000
        assert event["n"] == [1, 2]

    def test_does_not_materialize_huge_event(self):
        event = {"event": "x" * 50_000_000}

        out = BudgetedJSONRenderer(500)(None, "", event)

        assert len(out.encode("utf-8")) <= 500
        json.loads(out)

    def test_rejects_budget_below_minimum(self):
        minimum = BudgetedJSONRenderer(10_000).MIN_MAX_BYTES

        with pytest.raises(ValueError, match="max_bytes"):
            BudgetedJSONRenderer(minimum - 1)

    def test_minimum_budget_produces_failure_record(self):
        renderer = BudgetedJSONRenderer(
            BudgetedJSONRenderer(10_000).MIN_MAX_BYTES
        )

        out = renderer(None, "", {"event": "x" * 1000})

        assert json.loads(out) == {"_truncated": "truncated"}

    def test_encoding_error_produces_error_record(self):
        class Boom:
            def __structlog__(self):
                raise RuntimeError("boom")

        out = BudgetedJSONRenderer(60)(None, "", {"event": Boom()})
        decoded = json.loads(out)

        assert decoded["_truncated"] == "encoding error"
        assert len(out.encode()) <= 60

    def test_lone_surrogate_is_ascii_escaped(self):
        out = BudgetedJSONRenderer(80)(None, "", {"event": "a\ud800b"})

        raw = out.encode("utf-8")
        assert b"\\ud800" in raw
        json.loads(raw.decode("ascii"))

    def test_ensure_ascii_escapes_non_ascii(self):
        out = BudgetedJSONRenderer(200, ensure_ascii=True)(
            None, "", {"event": "中"}
        )

        assert out.encode("ascii").decode("ascii") == out
        assert json.loads(out)["event"] == "中"

    def test_custom_truncated_key(self):
        out = BudgetedJSONRenderer(
            30, truncated_key="_cut"
        )(None, "", {"event": "x" * 100})

        decoded = json.loads(out)
        assert "_cut" in decoded
        assert "_truncated" not in decoded

    def test_minimum_respects_custom_truncated_key(self):
        renderer = BudgetedJSONRenderer(1000, truncated_key="_x")
        minimum = renderer.MIN_MAX_BYTES

        tiny = BudgetedJSONRenderer(minimum, truncated_key="_x")
        out = tiny(None, "", {"event": "x" * 1000})

        assert json.loads(out) == {"_x": "truncated"}

    def test_cyclic_structure_does_not_recurse(self):
        event = {"event": "x"}
        event["self"] = event

        out = BudgetedJSONRenderer(120)(None, "", event)

        assert len(out.encode()) <= 120
        json.loads(out)

    def test_non_finite_float_becomes_null(self):
        out = BudgetedJSONRenderer(60)(None, "", {"event": float("nan")})

        assert json.loads(out)["event"] is None

    @pytest.mark.parametrize("budget", range(31, 120))
    def test_every_budget_is_valid_and_within_limit(self, budget):
        event = {
            "event": "hello 世界",
            "level": "info",
            "data": {"a": 1, "long": "z" * 40},
            "arr": [1, "中" * 5, 3],
        }

        out = BudgetedJSONRenderer(budget)(None, "", event)

        assert len(out.encode("utf-8")) <= budget
        json.loads(out)

    def test_randomized_outputs_are_valid_and_bounded(self):
        rng = random.Random(20260927)

        def value(depth):
            kind = rng.randrange(8)
            if depth <= 0 or kind == 0:
                return rng.choice(
                    [
                        "x" * rng.randrange(0, 40),
                        "中文测试😀",
                        42,
                        True,
                        False,
                        None,
                    ]
                )
            if kind == 1:
                return "q" * rng.randrange(0, 300)
            if kind in (2, 3):
                return [value(depth - 1) for _ in range(rng.randrange(5))]
            keys = rng.sample(
                ["event", "level", "a", "bb", "中", "z", "exception"],
                k=rng.randrange(1, 5),
            )
            return {key: value(depth - 1) for key in keys}

        for ensure_ascii in (False, True):
            for _ in range(2000):
                event = value(4)
                budget = rng.randrange(31, 400)
                out = BudgetedJSONRenderer(
                    budget, ensure_ascii=ensure_ascii
                )(None, "", event)

                assert len(out.encode("utf-8")) <= budget
                json.loads(out)
