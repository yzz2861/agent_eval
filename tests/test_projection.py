"""
Tests for offline HPACK replay into redacted training projections.

All encoded inputs in this file are produced in memory by ``Encoder``; no
fixture files or stored connection traces are used.
"""
from __future__ import annotations

import json

import pytest

from hpack import (
    REDACTED,
    Decoder,
    Encoder,
    Fragment,
    HeaderProjection,
    HeaderTuple,
    NeverIndexedHeaderTuple,
    OfflineFragment,
    PolicyAddition,
    ProjectedHeader,
    ProjectionReport,
    RedactionPolicy,
    TableCheckpoint,
    TrustedCheckpoint,
    build_projection,
    build_redacted_projection,
    create_checkpoint,
    project,
    project_headers,
    make_checkpoint,
    redact_headers,
    replay_fragments,
    replay_projection,
    training,
)


def _fresh_block(headers):
    return Encoder().encode(headers)


def _decoder_for(blocks):
    decoder = Decoder()
    for block in blocks:
        decoder.decode(block)
    return decoder


def _checkpoint(blocks, checkpoint_id, connection_id="conn", batch_id="batch"):
    return TableCheckpoint.from_decoder(
        _decoder_for(blocks),
        checkpoint_id,
        connection_id=connection_id,
        batch_id=batch_id,
    )


class TestRedaction:
    def test_only_allowlisted_values_are_exported(self):
        block = _fresh_block([
            (":method", "GET"),
            ("authorization", "Bearer top-secret-token"),
            ("x-trace", "trace-1"),
        ])

        report = build_projection([block], policy=["x-trace"])

        assert report.proven
        assert [header.name for header in report.headers] == [
            ":method",
            "authorization",
            "x-trace",
        ]
        assert [header.redacted for header in report.headers] == [True, True, False]
        assert report.headers[2].value == "trace-1"
        assert report.headers[1].value == REDACTED
        assert "top-secret-token" not in repr(report)
        assert "top-secret-token" not in json.dumps(report.to_dict())

    def test_deny_by_default_and_custom_marker(self):
        block = _fresh_block([("x-secret", "needle")])
        policy = RedactionPolicy(redaction_marker="***")
        report = build_projection([block], policy=policy)
        assert report.headers[0].value == "***"
        assert report.headers[0].redacted

    def test_redacted_fields_can_be_omitted(self):
        block = _fresh_block([("authorization", "needle"), ("x-keep", "ok")])
        policy = RedactionPolicy(allowed_fields={"x-keep"}, include_redacted=False)
        report = build_projection([block], policy=policy)
        assert [header.name for header in report.headers] == ["x-keep"]
        assert report.segments[0].omitted_field_count == 1
        assert "needle" not in json.dumps(report.to_dict())

    def test_never_indexed_value_is_always_redacted(self):
        block = Encoder().encode([NeverIndexedHeaderTuple("authorization", "never-indexed-secret")])
        report = build_projection([block], policy=["authorization"])
        assert report.headers[0].redacted
        assert report.headers[0].value == REDACTED

        permissive = RedactionPolicy(
            allowed_fields={"authorization"},
            redact_never_indexed=False,
        )
        report = build_projection([block], policy=permissive)
        assert report.headers[0].value == "never-indexed-secret"

    def test_json_export_and_save(self, tmp_path):
        block = _fresh_block([("authorization", "export-secret"), ("x-keep", "ok")])
        report = build_projection([block], policy=["x-keep"])
        text = report.to_json(indent=2)
        path = tmp_path / "projection.json"
        report.save(path)
        saved = path.read_text(encoding="utf-8")
        assert "export-secret" not in text
        assert saved == text
        assert json.loads(saved)["proven"] is True
        assert json.loads(saved)["segments"][0]["headers"][0]["redacted"] is True

    def test_redact_headers_helper(self):
        headers = [HeaderTuple(b"x-keep", b"visible"), HeaderTuple(b"authorization", b"secret")]
        projected = redact_headers(headers, ["x-keep"], fragment_index=4, policy_version=2)
        assert all(isinstance(header, ProjectedHeader) for header in projected)
        assert projected[0].value == "visible"
        assert projected[1].redacted
        assert projected[1].fragment_index == 4
        assert projected[1].policy_version == 2


class TestCheckpointReplay:
    def test_dependency_without_history_is_unprovable(self):
        encoder = Encoder()
        first = encoder.encode([("authorization", "Bearer secret")])
        second = encoder.encode([("authorization", "Bearer secret"), ("x-trace", "2")])

        missing = build_projection([Fragment(second)], policy=["x-trace"])
        assert not missing.proven
        assert missing.segments[0].reason == "missing_history"
        assert missing.segments[0].headers == ()

        with_history = build_projection(
            [Fragment(second, checkpoint_id="cp1")],
            policy=["x-trace"],
            checkpoints={"cp1": _checkpoint([first], "cp1")},
        )
        assert with_history.proven
        assert with_history.segments[0].checkpoint_id == "cp1"
        assert [header.name for header in with_history.headers] == ["authorization", "x-trace"]
        assert with_history.headers[0].redacted
        assert with_history.headers[1].value == "2"

    def test_self_contained_fragment_with_known_connection_is_tried_fresh(self):
        block = _fresh_block([("x-one", "1")])
        implicit = build_projection([Fragment(block, connection_id="conn", batch_id="batch")])
        assert implicit.proven

        declared = build_projection(
            [Fragment(block, connection_id="conn", batch_id="batch", fresh_context=True)],
        )
        assert declared.proven

        required = build_projection(
            [Fragment(block, connection_id="conn", batch_id="batch", requires_history=True)],
        )
        assert required.segments[0].reason == "missing_context"

    def test_continuation_is_explicit_and_provenance_is_chained(self):
        encoder = Encoder()
        first = encoder.encode([("x-a", "0")])
        second = encoder.encode([("x-a", "0"), ("x-b", "1")])
        report = build_projection([
            Fragment(first, fragment_id="f0", connection_id="conn", batch_id="batch", fresh_context=True),
            Fragment(second, fragment_id="f1", connection_id="conn", batch_id="batch", continues_from_previous=True),
        ])
        assert report.proven
        assert report.segments[0].proof_chain == ("fresh:f0",)
        assert report.segments[1].proof_chain[0] == "fresh:f0"
        assert report.segments[1].proof_chain[-1] == "f1"

    def test_broken_chain_is_reported(self):
        encoder = Encoder()
        first = encoder.encode([("x-a", "0")])
        second = encoder.encode([("x-a", "0"), ("x-b", "1")])
        report = build_projection([
            Fragment(second, connection_id="conn", batch_id="batch"),
            Fragment(second, connection_id="conn", batch_id="batch", continues_from_previous=True),
        ])
        assert report.segments[0].reason == "missing_context"
        assert report.segments[1].reason == "broken_chain"
        assert not report.proven
        # first is unused in this test, but encoding it keeps second a
        # realistic in-memory block that depends on prior dynamic-table state.
        assert first

    def test_continuation_across_connections_is_rejected(self):
        encoder = Encoder()
        first = encoder.encode([("x-a", "0")])
        second = encoder.encode([("x-a", "0"), ("x-b", "1")])
        report = build_projection([
            Fragment(first, connection_id="conn-a", batch_id="batch", fresh_context=True),
            Fragment(second, connection_id="conn-b", batch_id="batch", continues_from_previous=True),
        ])
        assert report.segments[0].proven
        assert report.segments[1].reason == "state_mismatch"
        assert report.segments[1].headers == ()


class TestProofRanges:
    def _fixture(self):
        encoder = Encoder()
        b0 = encoder.encode([("x-a", "0")])
        b1 = encoder.encode([("x-a", "0"), ("x-b", "1")])
        b2 = encoder.encode([("x-a", "0"), ("x-b", "1"), ("x-c", "2")])
        # Checkpoints are the state *before* the fragment that consumes them.
        checkpoints = {
            "cp0": TableCheckpoint.empty("cp0", connection_id="conn", batch_id="batch"),
            "cp1": _checkpoint([b0], "cp1"),
            "cp2": _checkpoint([b0, b1], "cp2"),
        }
        fragments = [
            Fragment(b0, connection_id="conn", batch_id="batch", checkpoint_id="cp0"),
            Fragment(b1, connection_id="conn", batch_id="batch", checkpoint_id="cp1"),
            Fragment(b2, connection_id="conn", batch_id="batch", checkpoint_id="cp2"),
        ]
        return fragments, checkpoints

    def test_all_fragments_proven_with_all_checkpoints(self):
        fragments, checkpoints = self._fixture()
        report = build_projection(fragments, policy=["x-a", "x-b", "x-c"], checkpoints=checkpoints)
        assert report.proven
        assert report.proven_ranges == ((0, 2),)
        assert report.unproven_ranges == ()
        assert [header.value for header in report.segments[0].headers] == ["0"]
        assert [header.value for header in report.segments[1].headers] == ["0", "1"]
        assert [header.value for header in report.segments[2].headers] == ["0", "1", "2"]

    def test_removing_one_checkpoint_reports_the_surviving_segments(self):
        fragments, checkpoints = self._fixture()
        del checkpoints["cp1"]

        report = build_projection(fragments, policy=["x-a", "x-b", "x-c"], checkpoints=checkpoints)

        assert report.proven_indices == (0, 2)
        assert report.unproven_indices == (1,)
        assert [segment.index for segment in report.proven_segments] == [0, 2]
        assert [segment.index for segment in report.unproven_segments] == [1]
        assert report.proven_ranges == ((0, 0), (2, 2))
        assert report.unproven_ranges == ((1, 1),)
        assert report.segments[1].reason == "missing_checkpoint"
        assert report.segments[1].checkpoint_id is None
        assert report.segments[1].headers == ()
        assert [header.value for header in report.segments[2].headers] == ["0", "1", "2"]
        assert "proven fragments: 0, 2" in report.summary()

    def test_missing_checkpoint_does_not_fall_back_to_another_state(self):
        fragments, checkpoints = self._fixture()
        other = TableCheckpoint.from_encoder(Encoder(), "other", connection_id="conn", batch_id="batch")
        checkpoints["other"] = other
        fragments[1] = Fragment(
            fragments[1].data,
            connection_id="conn",
            batch_id="batch",
            checkpoint_id="does-not-exist",
        )
        report = build_projection(fragments, checkpoints=checkpoints)
        assert report.segments[1].reason == "missing_checkpoint"
        assert report.segments[1].headers == ()

    def test_state_from_another_batch_is_rejected(self):
        fragments, checkpoints = self._fixture()
        foreign = Fragment(
            fragments[1].data,
            connection_id="conn",
            batch_id="other-batch",
            checkpoint_id="cp1",
        )
        report = build_projection([foreign], checkpoints=checkpoints)
        assert report.segments[0].reason == "state_mismatch"
        assert report.segments[0].rejected_checkpoint_id == "cp1"
        assert report.segments[0].headers == ()
        assert not report.proven

    def test_invalid_checkpoint_is_rejected(self):
        bad = TableCheckpoint(
            "bad",
            dynamic_entries=((b"x", b"y" * 100),),
            table_size=10,
        )
        assert not bad.valid
        report = build_projection([Fragment(b"\x82", checkpoint=bad)])
        assert report.segments[0].reason == "invalid_checkpoint"
        assert report.segments[0].rejected_checkpoint_id == "bad"


class TestDuplicates:
    def test_duplicate_fields_are_preserved_with_occurrence_metadata(self):
        block = _fresh_block([("x-tag", "a"), ("x-tag", "b")])
        report = build_projection([block], policy=["x-tag"])
        assert [(header.name, header.value) for header in report.headers] == [
            ("x-tag", "a"),
            ("x-tag", "b"),
        ]
        assert [header.occurrence for header in report.headers] == [0, 1]
        assert [header.duplicate for header in report.headers] == [False, True]

    def test_duplicate_sensitive_values_are_each_redacted(self):
        block = _fresh_block([("x-secret", "first"), ("x-secret", "second")])
        report = build_projection([block])
        assert len(report.headers) == 2
        assert [header.value for header in report.headers] == [REDACTED, REDACTED]
        assert [header.duplicate for header in report.headers] == [False, True]
        assert "first" not in repr(report)
        assert "second" not in repr(report)


class TestMidstreamPolicy:
    def test_added_field_applies_only_from_its_fragment(self):
        blocks = [
            _fresh_block([("x-policy", "v0")]),
            _fresh_block([("x-policy", "v1")]),
            _fresh_block([("x-policy", "v2")]),
        ]
        report = build_projection(blocks, policy=[], additions={1: ["x-policy"]})
        assert [header.value for header in report.headers] == [REDACTED, "v1", "v2"]
        assert [segment.policy_version for segment in report.segments] == [0, 1, 1]
        assert report.policy_events == ({
            "fragment_index": 1,
            "policy_version": 1,
            "added_fields": ["x-policy"],
            "retroactive": False,
        },)

    def test_policy_addition_objects_and_single_string_fields(self):
        blocks = [
            _fresh_block([("x-policy", "v0")]),
            _fresh_block([("x-policy", "v1")]),
        ]
        report = build_projection(
            blocks,
            additions=[PolicyAddition(at_fragment=1, fields="x-policy")],
        )
        assert [header.value for header in report.headers] == [REDACTED, "v1"]

    def test_repeated_addition_is_idempotent(self):
        blocks = [
            _fresh_block([("x-policy", "v0")]),
            _fresh_block([("x-policy", "v1")]),
        ]
        report = build_projection(
            blocks,
            additions=[PolicyAddition(0, ("x-policy",)), PolicyAddition(0, ("x-policy",))],
        )
        assert [header.value for header in report.headers] == ["v0", "v1"]
        assert report.policy_events[0]["added_fields"] == ["x-policy"]


class TestCheckpoints:
    def test_from_encoder_and_empty(self):
        encoder = Encoder()
        block = encoder.encode([("x-a", "1")])
        checkpoint = TableCheckpoint.from_encoder(encoder, "from-encoder", connection_id="c")
        assert checkpoint.dynamic_entries == ((b"x-a", b"1"),)
        assert checkpoint.checkpoint_id == "from-encoder"
        assert checkpoint.connection_id == "c"
        assert checkpoint.used_size > 0
        assert checkpoint.valid

        empty = TableCheckpoint.empty("empty")
        assert empty.dynamic_entries == ()
        assert empty.used_size == 0
        assert empty.valid

        report = build_projection([Fragment(block, checkpoint_id="empty")], checkpoints={"empty": empty})
        assert report.proven

    def test_decoder_and_encoder_snapshot_methods(self):
        encoder = Encoder()
        block = encoder.encode([("x-a", "1")])
        decoder = _decoder_for([block])

        from_encoder = encoder.snapshot("enc", connection_id="c", batch_id="b")
        from_decoder = decoder.checkpoint("dec", connection_id="c", batch_id="b")

        assert from_encoder.checkpoint_id == "enc"
        assert from_decoder.checkpoint_id == "dec"
        assert from_encoder.dynamic_entries == from_decoder.dynamic_entries

    def test_checkpoint_metadata_never_contains_entries(self):
        block = _fresh_block([("authorization", "checkpoint-secret")])
        decoder = _decoder_for([block])
        checkpoint = TableCheckpoint.from_decoder(decoder, "cp", connection_id="c", batch_id="b")
        payload = checkpoint.to_dict()
        assert payload["entry_count"] == 1
        assert "dynamic_entries" not in payload
        assert "checkpoint-secret" not in repr(checkpoint)
        assert "checkpoint-secret" not in json.dumps(payload)

    def test_fragment_repr_hides_encoded_payload(self):
        block = _fresh_block([("authorization", "fragment-secret")])
        fragment = Fragment(block, fragment_id="f")
        assert "fragment-secret" not in repr(fragment)
        assert f"encoded_size={len(block)}" in repr(fragment)
        assert "data" not in fragment.to_dict()
        assert "fragment-secret" not in json.dumps(fragment.to_dict())

    def test_checkpoint_validation(self):
        with pytest.raises(ValueError):
            TableCheckpoint("")
        with pytest.raises(ValueError):
            TableCheckpoint("cp", table_size=10, max_allowed_table_size=5)
        with pytest.raises(ValueError):
            TableCheckpoint("cp", table_size=-1)


class TestErrorsAndEdges:
    def test_decode_error_is_reported_without_leaking_raw_data(self):
        report = build_projection([Fragment(b"\x00\x05ab")])
        segment = report.segments[0]
        assert segment.reason == "decode_error"
        assert segment.error_type == "HPACKDecodingError"
        assert segment.headers == ()
        assert "ab" not in json.dumps(report.to_dict()) or "ab" not in repr(segment)

    def test_empty_projection(self):
        report = build_projection([])
        assert report.proven
        assert report.proven_ranges == ()
        assert report.unproven_ranges == ()
        assert report.summary() == "no fragments"

    def test_bare_bytes_and_buffers_are_independent_fragments(self):
        block = _fresh_block([("x-a", "1")])
        report = build_projection([block, bytearray(block), memoryview(block)])
        assert len(report.segments) == 3
        assert report.proven
        assert report.proven_ranges == ((0, 2),)

    def test_mapping_and_iterable_checkpoints(self):
        block = _fresh_block([("x-a", "1")])
        checkpoint = TableCheckpoint.from_encoder(Encoder(), "cp", connection_id="c")
        fragment = Fragment(block, connection_id="c", checkpoint_id="cp")

        as_mapping = build_projection([fragment], checkpoints={"cp": checkpoint})
        as_iterable = build_projection([fragment], checkpoints=[checkpoint])
        assert as_mapping.proven
        assert as_iterable.proven

        with pytest.raises(ValueError):
            build_projection([fragment], checkpoints={"other": checkpoint})
        with pytest.raises(ValueError):
            build_projection([fragment], checkpoints=[checkpoint, checkpoint])

    def test_fragment_validation(self):
        checkpoint = TableCheckpoint.empty("cp")
        with pytest.raises(ValueError):
            Fragment(b"", checkpoint=checkpoint, checkpoint_id="other")
        with pytest.raises(ValueError):
            Fragment(b"", checkpoint_id="cp", continues_from_previous=True)
        with pytest.raises(ValueError):
            Fragment(b"", continues_from_previous=True, fresh_context=True)
        with pytest.raises(ValueError):
            Fragment(b"", fresh_context=True, requires_history=True)

    def test_keyword_aliases_and_checkpoint_factory(self):
        block = _fresh_block([("x-alias", "1")])
        checkpoint = make_checkpoint(
            (),
            checkpoint_id="alias",
            connection_id="c",
            batch_id="b",
        )
        assert create_checkpoint is make_checkpoint
        report = build_projection(
            [Fragment(block, connection_id="c", batch_id="b", checkpoint_id="alias")],
            trusted_checkpoints={"alias": checkpoint},
            allowed_fields=["x-alias"],
        )
        assert report.proven
        assert report.headers[0].value == "1"

        with pytest.raises(ValueError):
            build_projection([block], policy=[], allowed_fields=[])
        with pytest.raises(ValueError):
            build_projection([block], checkpoints={}, trusted_checkpoints={})
        with pytest.raises(ValueError):
            build_projection([block], additions={}, policy_additions={})

    def test_policy_normalization(self):
        policy = RedactionPolicy(allowed_fields="x-a")
        assert policy.allows("X-A")
        assert not policy.allows(b"x-b")

    def test_aliases_and_reexports(self):
        assert HeaderProjection is ProjectionReport
        assert TrustedCheckpoint is TableCheckpoint
        assert OfflineFragment is Fragment
        assert project is build_projection
        assert project_headers is build_projection
        assert replay_projection is build_projection
        assert replay_fragments is build_projection
        assert build_redacted_projection is build_projection
        assert training.build_projection is build_projection
        assert training.Fragment is Fragment
