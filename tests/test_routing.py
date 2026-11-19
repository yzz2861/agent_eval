# -*- coding: utf-8 -*-

from __future__ import absolute_import

import itertools
import unittest

import filetype
from filetype import routing
from filetype.routing import (
    ALLOW,
    QUARANTINE,
    NEED_MORE,
    MATCHED,
    PENDING,
    ELIMINATED,
    MagicMatcher,
    Consumer,
)


# Hand-written short signatures used as matchers.
GIF_MAGIC = b'GIF89a'
PNG_MAGIC = b'\x89PNG\r\n\x1a\n'
ZIP_MAGIC = b'PK\x03\x04'


def build_matchers():
    return [
        MagicMatcher('image/gif', 'gif', GIF_MAGIC),
        MagicMatcher('image/png', 'png', PNG_MAGIC),
        MagicMatcher('application/zip', 'zip', ZIP_MAGIC),
    ]


def build_consumers():
    # The preview consumer decodes images, the archive consumer decodes
    # archives: the same attachment may be seen by both.
    preview = Consumer('preview', mimes=['image/gif', 'image/png'])
    archive = Consumer('archive', mimes=['application/zip'])
    return [preview, archive]


class RoutingTest(unittest.TestCase):
    def setUp(self):
        self.matchers = build_matchers()
        self.consumers = build_consumers()

    def test_incomplete_shared_prefix_requests_more_evidence(self):
        # 'GIF89' is a strict prefix of the GIF magic but not a full match.
        decision = routing.route(b'GIF89', self.consumers, self.matchers)

        self.assertEqual(decision.verdict, NEED_MORE)
        self.assertEqual(decision.need_bytes, 1)
        self.assertEqual([c.extension for c in decision.matched], [])
        self.assertEqual([c.extension for c in decision.pending], ['gif'])
        self.assertEqual(
            sorted(c.extension for c in decision.eliminated),
            ['png', 'zip'])

    def test_full_signature_is_allowed_for_permitted_consumer(self):
        decision = routing.route(
            GIF_MAGIC + b' payload', self.consumers, self.matchers)

        self.assertEqual(decision.verdict, ALLOW)
        self.assertIsNotNone(decision.primary)
        self.assertEqual(decision.primary.extension, 'gif')
        self.assertEqual(
            [c.extension for c in decision.matched], ['gif'])
        self.assertEqual(
            decision.prefix_length, len(GIF_MAGIC + b' payload'))

    def test_policy_denial_quarantines_even_on_unique_match(self):
        # Only the image preview consumer is present; a zip is not allowed.
        preview = self.consumers[0]
        decision = routing.route(
            ZIP_MAGIC + b'xx', [preview], self.matchers)

        self.assertEqual(decision.verdict, QUARANTINE)
        self.assertEqual(decision.primary.extension, 'zip')
        self.assertTrue(
            any('not allowed' in reason for reason in decision.reasons))

    def test_contradicted_prefix_is_quarantined_without_more_sampling(self):
        decision = routing.route(b'ZZZZ', self.consumers, self.matchers)

        self.assertEqual(decision.verdict, QUARANTINE)
        self.assertIsNone(decision.need_bytes)
        self.assertEqual(decision.matched, ())
        self.assertEqual(decision.pending, ())
        self.assertEqual(len(decision.eliminated), 3)

    def test_final_stream_quarantines_undecidable_prefix(self):
        # Still only a prefix, but the upload stream has already ended.
        decision = routing.route(
            b'GIF89', self.consumers, self.matchers, final=True)
        self.assertEqual(decision.verdict, QUARANTINE)
        self.assertTrue(
            any('stream ended' in reason for reason in decision.reasons))

    def test_ambiguous_match_quarantines(self):
        # Two matchers sharing the same magic must both match the prefix.
        dup_a = MagicMatcher('image/gif', 'gif', GIF_MAGIC)
        dup_b = MagicMatcher('image/gif-alt', 'gif2', GIF_MAGIC)
        matchers = [dup_a, dup_b]

        decision = routing.route(GIF_MAGIC, self.consumers, matchers)
        self.assertEqual(decision.verdict, QUARANTINE)
        self.assertEqual(len(decision.matched), 2)
        self.assertTrue(
            any('ambiguous' in reason for reason in decision.reasons))

    def test_minimum_evidence_reflects_longest_pending_requirement(self):
        # A matcher that needs a deeper header reports a larger evidence gap.
        deep = MagicMatcher(
            'application/x-deep', 'deep', b'DEEP', minimum_bytes=10)
        matchers = [deep]
        decision = routing.route(b'DE', None, matchers)

        self.assertEqual(decision.verdict, NEED_MORE)
        self.assertEqual(decision.need_bytes, 8)

    def test_allowed_types_aggregate_consumers_and_matchers(self):
        reachable = routing.allowed_types(self.matchers)
        self.assertEqual(
            reachable['mimes'],
            ('application/zip', 'image/gif', 'image/png'))
        self.assertEqual(reachable['extensions'], ('gif', 'png', 'zip'))

        report = [consumer.to_dict() for consumer in self.consumers]
        names = sorted(item['name'] for item in report)
        self.assertEqual(names, ['archive', 'preview'])

    def test_collect_candidates_groups_all_outcomes(self):
        matched, pending, eliminated, candidates = routing.collect_candidates(
            b'GIF89', self.matchers)

        self.assertEqual([c.extension for c in matched], [])
        self.assertEqual([c.extension for c in pending], ['gif'])
        self.assertEqual(
            sorted(c.extension for c in eliminated), ['png', 'zip'])
        self.assertEqual(len(candidates), 3)
        # Deterministic, registration-order independent ordering.
        self.assertEqual(
            [c.mime for c in candidates],
            sorted(c.mime for c in candidates))


class OrderIndependenceTest(unittest.TestCase):
    def setUp(self):
        self.matchers = build_matchers()
        self.consumers = build_consumers()
        self.samples = [
            b'GIF89',                # need more
            GIF_MAGIC + b'x',        # allow (image)
            ZIP_MAGIC + b'x',        # allowed only by archive consumer
            b'ZZZZ',                 # contradiction -> quarantine
            b'',                     # nothing yet
        ]

    def _fingerprint(self, decision):
        return (
            decision.verdict,
            decision.reasons,
            decision.need_bytes,
            [(c.mime, c.extension, c.status, c.need_bytes)
             for c in decision.candidates],
        )

    def test_verdict_and_reasons_stable_under_registration_order(self):
        for sample in self.samples:
            baseline = routing.route(
                sample, self.consumers, self.matchers)
            expected = self._fingerprint(baseline)

            for permutation in itertools.permutations(self.matchers):
                decision = routing.route(
                    sample, self.consumers, list(permutation))
                self.assertEqual(
                    self._fingerprint(decision), expected,
                    'order changed routing for sample %r' % (sample,))

    def test_guess_behavior_remains_first_match(self):
        # The legacy API keeps its original first-match semantics.
        kind = filetype.guess(bytearray([0xFF, 0xD8, 0xFF, 0x00, 0x08]))
        self.assertIsNotNone(kind)
        self.assertEqual(kind.mime, 'image/jpeg')

        self.assertIsNone(filetype.guess(bytearray([0xFF, 0x00, 0x00])))


class PlainMatcherPendingTest(unittest.TestCase):
    def test_plain_type_without_magic_cannot_be_eliminated(self):
        # A legacy matcher that only exposes a boolean match() stays pending
        # and reports no finite evidence requirement.
        class Legacy(filetype.Type):
            def __init__(self):
                super(Legacy, self).__init__('application/x-legacy', 'leg')

            def match(self, buf):
                return len(buf) >= 4 and buf[:4] == b'LEGA'

        decision = routing.route(b'LE', None, [Legacy()])
        self.assertEqual(decision.verdict, NEED_MORE)
        self.assertIsNone(decision.need_bytes)
        self.assertEqual(
            [c.status for c in decision.pending], [PENDING])

        # Once enough bytes arrive it becomes a regular match.
        decision = routing.route(b'LEGA', None, [Legacy()])
        self.assertEqual(decision.verdict, ALLOW)
        self.assertEqual(
            [c.status for c in decision.matched], [MATCHED])


if __name__ == '__main__':
    unittest.main()
