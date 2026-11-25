"""Tests for synthetic CMS receipt timeline reconstruction."""

from __future__ import unicode_literals

import hashlib
import unittest

from evidence_timeline.analyzer import TimelineAnalyzer
from evidence_timeline.model import TrustInput, TrustInputs
from evidence_timeline.parser import parse_record
from evidence_timeline.samples import (
    build_repackaged_record,
    build_replacement_middle_record,
    build_three_stage_sample,
    build_tst_token,
)


def analyze(records, trust=None):
    verdicts = trust if trust is not None else {
        'tst-serial-1': TrustInput.TRUSTED,
        'tst-serial-2': TrustInput.TRUSTED,
        'tst-serial-3': TrustInput.TRUSTED,
    }
    analyzer = TimelineAnalyzer(TrustInputs(token_verdicts=verdicts))
    for record in records:
        analyzer.add_record(record.record_id, record.blob)
    return analyzer.build()


class CleanChainTests(unittest.TestCase):
    def setUp(self):
        self.records, _ = build_three_stage_sample()
        self.timeline = analyze(self.records)

    def test_three_receipts_in_chronological_order(self):
        entries = self.timeline.timeline
        self.assertEqual(
            ['tst-serial-1', 'tst-serial-2', 'tst-serial-3'],
            [entry.token_id for entry in entries],
        )
        self.assertLess(entries[0].generation_time, entries[1].generation_time)
        self.assertLess(entries[1].generation_time, entries[2].generation_time)

    def test_first_receipt_commits_to_signature_content_bytes(self):
        first = self.timeline.timeline[0]
        record_blob = self.records[0].blob
        self.assertEqual('matched', first.commitment.status)
        self.assertEqual('signature_value', first.commitment.kind)
        byte_range = first.commitment.byte_ranges[0]
        self.assertEqual(
            hashlib.sha256(
                record_blob[byte_range.start:byte_range.end]
            ).digest(),
            first.message_imprint,
        )
        self.assertIsNone(first.predecessor)

    def test_later_receipts_commit_to_whole_predecessor_records(self):
        second, third = self.timeline.timeline[1:]
        self.assertEqual('nested_record', second.commitment.kind)
        self.assertEqual('stage1-2018', second.predecessor)
        self.assertEqual('stage2-2021', third.predecessor)
        for entry, record in ((second, self.records[0]), (third, self.records[1])):
            byte_range = entry.commitment.byte_ranges[0]
            host_blob = next(
                item.blob for item in self.records
                if item.record_id == entry.record_id
            )
            self.assertEqual(
                host_blob[byte_range.start:byte_range.end],
                record.blob,
            )
            self.assertEqual(
                hashlib.sha256(record.blob).digest(),
                entry.message_imprint,
            )

    def test_no_gaps_and_full_provable_window(self):
        self.assertEqual([], self.timeline.gaps)
        self.assertEqual(
            ['tst-serial-1', 'tst-serial-2', 'tst-serial-3'],
            self.timeline.provable_window,
        )


class TrustBoundaryTests(unittest.TestCase):
    def test_trust_verdicts_are_supplied_not_inferred(self):
        records, _ = build_three_stage_sample()
        timeline = analyze(records, trust={
            'tst-serial-1': TrustInput.TRUSTED,
            'tst-serial-2': TrustInput.REJECTED,
            'tst-serial-3': TrustInput.UNDETERMINED,
        })
        verdicts = {
            entry.token_id: entry.trust for entry in timeline.timeline
        }
        self.assertEqual(TrustInput.TRUSTED, verdicts['tst-serial-1'])
        self.assertEqual(TrustInput.REJECTED, verdicts['tst-serial-2'])
        self.assertEqual(TrustInput.UNDETERMINED, verdicts['tst-serial-3'])
        self.assertNotIn('tst-serial-2', timeline.provable_window)

    def test_invalid_verdict_is_rejected_at_input_boundary(self):
        with self.assertRaises(ValueError):
            TrustInputs(token_verdicts={'tst-serial-1': 'verified-by-god'})


class RepackagingTests(unittest.TestCase):
    def test_original_commitment_still_verifiable_after_repackaging(self):
        records, trust = build_three_stage_sample()
        repackaged = build_repackaged_record(records[0])
        analyzer = TimelineAnalyzer(TrustInputs(token_verdicts=trust))
        analyzer.add_record(records[0].record_id, records[0].blob)
        analyzer.add_record(repackaged.record_id, repackaged.blob)
        for record in records[1:]:
            analyzer.add_record(record.record_id, record.blob)
        timeline = analyzer.build()

        wrapped_entries = [
            entry for entry in timeline.timeline
            if entry.record_id == repackaged.record_id
        ]
        self.assertEqual(1, len(wrapped_entries))
        entry = wrapped_entries[0]
        self.assertTrue(entry.repackaged)
        self.assertEqual('matched', entry.commitment.status)
        self.assertEqual('signature_value', entry.commitment.kind)
        self.assertEqual([], timeline.gaps)


class MissingMaterialTests(unittest.TestCase):
    def test_replacing_middle_record_names_exact_missing_segment(self):
        records, trust = build_three_stage_sample()
        replacement = build_replacement_middle_record()
        analyzer = TimelineAnalyzer(TrustInputs(token_verdicts=trust))
        analyzer.add_record(records[0].record_id, records[0].blob)
        analyzer.add_record('stage2-2021', replacement.blob)
        analyzer.add_record(records[2].record_id, records[2].blob)
        timeline = analyzer.build()

        self.assertEqual(2, len(timeline.timeline))
        self.assertEqual(1, len(timeline.gaps))
        gap = timeline.gaps[0]
        self.assertEqual('tst-serial-3', gap.after_token_id)
        self.assertEqual(
            hashlib.sha256(records[1].blob).hexdigest(),
            gap.missing_record_digest,
        )
        self.assertEqual(
            ['tst-serial-1', 'tst-serial-3'],
            timeline.provable_window,
        )
        surviving = next(
            entry for entry in timeline.timeline
            if entry.token_id == 'tst-serial-3'
        )
        self.assertEqual('matched', surviving.commitment.status)

    def test_missing_original_record_is_not_reverse_inferred(self):
        records, trust = build_three_stage_sample()
        analyzer = TimelineAnalyzer(TrustInputs(token_verdicts=trust))
        analyzer.add_record(records[1].record_id, records[1].blob)
        analyzer.add_record(records[2].record_id, records[2].blob)
        timeline = analyzer.build()
        record_ids = {record.record_id for record in timeline.records}
        self.assertNotIn('stage1-2018', record_ids)
        self.assertEqual(1, len(timeline.gaps))
        self.assertEqual(
            ['tst-serial-2', 'tst-serial-3'],
            timeline.provable_window,
        )


class ParserAndOffsetTests(unittest.TestCase):
    def test_parser_reports_only_direct_receipts_of_each_record(self):
        records, _ = build_three_stage_sample()
        parsed = parse_record(records[2].record_id, records[2].blob)
        self.assertEqual(['tst-serial-3'], [t.token_id for t in parsed.tokens])
        self.assertEqual(1, len(parsed.signers))

    def test_byte_ranges_point_to_real_blob_bytes(self):
        records, _ = build_three_stage_sample()
        timeline = analyze(records)
        for entry in timeline.timeline:
            for byte_range in entry.commitment.byte_ranges:
                host = next(
                    record for record in records
                    if record.record_id == byte_range.record_id
                )
                slice_bytes = host.blob[byte_range.start:byte_range.end]
                self.assertEqual(
                    hashlib.new(entry.hash_algorithm, slice_bytes).digest(),
                    entry.message_imprint,
                )

    def test_tampered_imprint_does_not_match(self):
        records, _ = build_three_stage_sample()
        tampered_token = build_tst_token(
            serial=1,
            gen_time='2018-06-01T08:00:00+00:00',
            tsa_key=b'TSA-2018-key',
            imprinted=b'bytes that were never in the record',
        )
        self.assertNotEqual(
            tampered_token.dump(),
            records[0].blob,
        )


if __name__ == '__main__':
    unittest.main()
