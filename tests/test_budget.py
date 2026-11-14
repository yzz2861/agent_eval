# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import gc
import os
import unittest

try:
    import tracemalloc
except ImportError:  # pragma: no cover: Python < 3.4 has no tracemalloc
    tracemalloc = None

from asn1crypto import core, parser, x509, cms, crl
from asn1crypto.parser import (
    ParseBudget,
    DepthLimitExceeded,
    NodeLimitExceeded,
    LengthLimitExceeded,
    ValueSizeLimitExceeded,
    TimeLimitExceeded,
)

from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class SequenceOfInts(core.SequenceOf):
    _child_spec = core.Integer


class SequenceOfAny(core.SequenceOf):
    _child_spec = core.Any


class WideChoice(core.Choice):
    _alternatives = [
        ('ints', SequenceOfInts),
    ]


def _wrap_indefinite(encoded, levels):
    """Wraps an encoded value in *levels* nested indefinite-length SEQUENCEs."""

    data = encoded
    for _ in range(levels):
        data = b'\x30\x80' + data + b'\x00\x00'
    return data


def _wrap_definite(encoded, levels):
    """Wraps an encoded value in *levels* nested definite-length SEQUENCEs."""

    data = encoded
    for _ in range(levels):
        length = len(data)
        if length < 128:
            header = b'\x30' + bytes([length])
        else:
            length_bytes = []
            remaining = length
            while remaining:
                length_bytes.insert(0, remaining & 0xff)
                remaining >>= 8
            header = b'\x30' + bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)
        data = header + data
    return data


class ParseBudgetTests(unittest.TestCase):

    def test_depth_limit_indefinite_eoc_scan(self):
        # Nested indefinite-length values force recursive EOC scanning inside
        # parser._parse(); a depth cap must stop the expansion early.
        data = _wrap_indefinite(b'\x02\x01\x01', 200)
        budget = ParseBudget(max_depth=20)

        with self.assertRaises(DepthLimitExceeded):
            parser.parse(data, budget=budget)

        with self.assertRaises(DepthLimitExceeded):
            core.Sequence.load(data, budget=budget)

    def test_depth_limit_definite_constructed_nesting(self):
        # Definite-length nesting is only descended into via core's DFS when
        # children are accessed, so the same budget depth must apply there.
        data = _wrap_definite(b'\x02\x01\x01', 200)
        budget = ParseBudget(max_depth=20)
        seq = core.Sequence.load(data, budget=budget)

        with self.assertRaises(DepthLimitExceeded):
            seq.native

    def test_node_limit_wide_sequence(self):
        # A wide SEQUENCE OF expands into one node per TLV; the node budget
        # must bound how many are visited even though the input is tiny.
        wide = SequenceOfInts(list(range(500))).dump()
        budget = ParseBudget(max_nodes=50)

        with self.assertRaises(NodeLimitExceeded):
            SequenceOfInts.load(wide, budget=budget).native

        # An indefinite-length encoding forces the parser itself to walk
        # every child while scanning for the EOC, so it is bounded too.
        indef_wide = b'\x30\x80' + b''.join(b'\x02\x01\x01' for _ in range(500)) + b'\x00\x00'
        budget = ParseBudget(max_nodes=50)
        with self.assertRaises(NodeLimitExceeded):
            parser.parse(indef_wide, budget=budget)

    def test_declared_length_over_substrate_fails_before_read(self):
        # The length octet claims far more bytes than exist. The per-value
        # length cap must trip before any contents are sliced or allocated.
        budget = ParseBudget(max_length=1024)
        oversized = b'\x04\x84\x00\x01\x00\x00' + b'\xaa' * 16

        with self.assertRaises(LengthLimitExceeded):
            parser.parse(oversized, budget=budget)

        # A declared length that fits the cap but exceeds the substrate is
        # still the ordinary insufficient-data failure, not a budget error.
        truncated = b'\x04\x82\x10\x00' + b'\x00' * 16
        with self.assertRaises(ValueError):
            parser.parse(truncated)

    def test_cumulative_value_byte_budget(self):
        # Value bytes are counted cumulatively for every visited node, so a
        # wide sequence of small values exhausts the value-byte budget even
        # though no single value is large.
        wide = SequenceOfInts([1] * 100).dump()
        budget = ParseBudget(max_value_bytes=50)

        with self.assertRaises(ValueSizeLimitExceeded):
            parser.parse(wide, budget=budget)

    def test_missing_eoc_is_bounded(self):
        # An indefinite-length container without an EOC must fail cleanly
        # without unbounded work.
        budget = ParseBudget(max_depth=100)
        with self.assertRaises(ValueError):
            parser.parse(b'\x30\x80\x02\x01\x01', budget=budget)

        nested = b'\x30\x80' * 500
        with self.assertRaises(DepthLimitExceeded):
            parser.parse(nested, budget=budget)

    def test_lazy_any_reuses_same_budget(self):
        # An Any value defers its real parsing until .parse()/.native is
        # accessed; that deferred work must continue under the original budget
        # instead of opening a fresh unlimited context.
        wide = SequenceOfInts(list(range(500))).dump()
        budget = ParseBudget(max_nodes=30)
        any_encoding = wide
        length = len(any_encoding)
        if length < 128:
            outer_encoding = b'\x30' + bytes([length]) + any_encoding
        elif length < 256:
            outer_encoding = b'\x30\x81' + bytes([length]) + any_encoding
        else:
            outer_encoding = b'\x30\x82' + bytes([(length >> 8) & 0xff, length & 0xff]) + any_encoding
        outer = SequenceOfAny.load(outer_encoding, budget=budget)
        lazy_any = outer[0]

        self.assertIs(lazy_any._budget, budget)

        with self.assertRaises(NodeLimitExceeded):
            lazy_any.parse(SequenceOfInts).native

    def test_lazy_parsable_octet_string_reuses_budget(self):
        wide = SequenceOfInts(list(range(500))).dump()
        octet_string = core.OctetString(wide).dump()
        budget = ParseBudget(max_nodes=30)

        parsable = core.ParsableOctetString.load(octet_string, budget=budget)
        self.assertIs(parsable._budget, budget)
        with self.assertRaises(NodeLimitExceeded):
            parsable.parse(SequenceOfInts).native

    def test_lazy_choice_reuses_budget(self):
        wide = SequenceOfInts(list(range(500))).dump()
        budget = ParseBudget(max_nodes=30)
        choice = WideChoice.load(wide, budget=budget)

        self.assertIs(choice._budget, budget)
        with self.assertRaises(NodeLimitExceeded):
            choice.chosen.native

    def test_indefinite_constructed_octet_string_merging_uses_budget(self):
        # Indefinite-length chunks are walked during the load-time EOC scan,
        # and _merge_chunks() later re-parses them lazily using the same
        # budget instead of opening a fresh context.
        chunks = b'\x04\x01a' * 100
        data = b'\x24\x80' + chunks + b'\x00\x00'
        with self.assertRaises(NodeLimitExceeded):
            core.OctetString.load(data, budget=ParseBudget(max_nodes=20))

        # With enough headroom to load, the lazy merge continues to draw from
        # the same stored budget.
        budget = ParseBudget(max_nodes=500)
        value = core.OctetString.load(data, budget=budget)
        self.assertIs(value._budget, budget)
        self.assertEqual(b'a' * 100, value.native)

    def test_time_limit(self):
        # A near-zero time budget must eventually stop a large wide parse.
        wide = SequenceOfInts(list(range(20000))).dump()
        budget = ParseBudget(max_time_seconds=1e-9)

        with self.assertRaises(TimeLimitExceeded):
            parser.parse(wide, budget=budget)

    def test_budget_validation(self):
        with self.assertRaises(TypeError):
            ParseBudget(max_depth=0)
        with self.assertRaises(TypeError):
            ParseBudget(max_nodes=-1)
        with self.assertRaises(TypeError):
            parser.parse(b'\x02\x01\x00', budget={'max_nodes': 10})

    def test_none_limits_disable_checks(self):
        budget = ParseBudget(
            max_depth=None,
            max_nodes=None,
            max_value_bytes=None,
            max_length=None,
            max_time_seconds=None,
        )
        data = _wrap_indefinite(b'\x02\x01\x01', 150)
        result = parser.parse(data, budget=budget)
        self.assertIsInstance(result, tuple)

    def test_strict_mode_still_rejects_trailing_data(self):
        # The budget work must not weaken DER strict-mode handling.
        budget = ParseBudget()
        with self.assertRaises(ValueError):
            parser.parse(b'\x02\x01\x00\x00', strict=True, budget=budget)

    def test_legitimate_fixtures_unchanged_and_bounded(self):
        # Real certificates, CMS and BER samples must parse to the same result
        # while keeping node counts and peak memory comfortably bounded.
        cert_path = os.path.join(fixtures_dir, 'admin.ch.crt')
        with open(cert_path, 'rb') as f:
            cert_bytes = f.read()

        cert = x509.Certificate.load(cert_bytes)
        subject_before = cert.subject.human_friendly
        cert.native

        budget = ParseBudget()
        cert = x509.Certificate.load(cert_bytes, budget=budget)
        cert.native
        self.assertEqual(subject_before, cert.subject.human_friendly)
        self.assertGreater(budget.node_count, 0)
        self.assertLess(budget.node_count, budget.max_nodes)
        self.assertLessEqual(budget.depth, budget.max_depth)
        self.assertLessEqual(budget.max_seen_length, budget.max_length)

        cms_path = os.path.join(fixtures_dir, 'cms-signed-indefinite-length.der')
        with open(cms_path, 'rb') as f:
            cms_bytes = f.read()
        cms_budget = ParseBudget()
        cms_content = cms.ContentInfo.load(cms_bytes, budget=cms_budget)
        cms_content.native
        self.assertLess(cms_budget.node_count, cms_budget.max_nodes)

    def test_large_crl_fixture_within_default_budget(self):
        # A 1.1 MB production CRL contains hundreds of thousands of nodes;
        # the default budget must still allow it to decode fully.
        crl_path = os.path.join(fixtures_dir, 'eid2011.crl')
        with open(crl_path, 'rb') as f:
            crl_bytes = f.read()

        budget = ParseBudget()
        cert_list = crl.CertificateList.load(crl_bytes, budget=budget)
        revoked = cert_list['tbs_cert_list']['revoked_certificates']
        self.assertEqual(15752, len(revoked.native))
        self.assertLess(budget.node_count, budget.max_nodes)
        self.assertEqual(0, budget.depth)

    def test_peak_memory_does_not_track_declared_length(self):
        # A hostile length declaration must be rejected while allocating only
        # O(input) memory: peak growth must stay far below the claimed size.
        if tracemalloc is None:
            self.skipTest('tracemalloc is not available on this Python version')

        declared = 16 * 1024 * 1024
        header = b'\x04\x84' + bytes([
            (declared >> 24) & 0xff,
            (declared >> 16) & 0xff,
            (declared >> 8) & 0xff,
            declared & 0xff,
        ])
        payload = b'\x30\x80' + header + b'\x00' * 32 + b'\x00\x00'
        budget = ParseBudget(max_length=1024 * 1024)

        gc.collect()
        tracemalloc.start()
        try:
            _, peak = tracemalloc.get_traced_memory()
            with self.assertRaises(LengthLimitExceeded):
                parser.parse(payload, budget=budget)
            _, peak_after = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertLess(peak_after - peak, declared // 16)
