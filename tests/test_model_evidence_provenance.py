# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

import json
from decimal import Decimal
from os import path
from typing import Optional
from unittest import TestCase

from cyclonedx.exception.model import InvalidValueException
from cyclonedx.model.bom import Bom
from cyclonedx.model.component_evidence import (
    AttributionStatus,
    AttributionWarning,
    BatchInterval,
    ComponentEvidence,
    EvidenceProvenance,
    EvidenceSeal,
    Identity,
    IdentityField,
    LocalSample,
    LocalSampleRegistry,
    ProvenanceSource,
)
from cyclonedx.schema.schema import SchemaVersion1Dot6
from tests import OWN_DATA_DIRECTORY


def _identity(conclusion: str = 'tamper-check', provenance: Optional[EvidenceProvenance] = None) -> Identity:
    return Identity(
        field=IdentityField.HASH,
        confidence=Decimal('1'),
        concluded_value=conclusion,
        provenance=provenance,
    )


class TestBatchInterval(TestCase):

    def test_inclusive_intersection(self) -> None:
        self.assertTrue(BatchInterval(1, 3).intersects(BatchInterval(3, 5)))
        self.assertFalse(BatchInterval(1, 2).intersects(BatchInterval(3, 5)))

    def test_open_bounds(self) -> None:
        self.assertTrue(BatchInterval(4).intersects(BatchInterval(1, 5)))
        self.assertTrue(BatchInterval(end=2).intersects(BatchInterval(1, 5)))

    def test_alphanumeric_batch_codes(self) -> None:
        self.assertTrue(BatchInterval('B-01', 'B-03').intersects(BatchInterval('B-03', 'B-05')))
        self.assertFalse(BatchInterval('B-01', 'B-02').intersects(BatchInterval('B-03', 'B-05')))

    def test_unknown_is_not_a_wildcard(self) -> None:
        unknown = BatchInterval.unknown()
        self.assertTrue(unknown.is_unknown)
        self.assertFalse(unknown.intersects(BatchInterval(1, 100)))
        self.assertFalse(BatchInterval(1, 100).intersects(unknown))

    def test_invalid_interval(self) -> None:
        with self.assertRaises(InvalidValueException):
            BatchInterval(5, 1)
        with self.assertRaises(InvalidValueException):
            BatchInterval(1, 2, unknown=True)

    def test_round_trip_unknown(self) -> None:
        self.assertTrue(BatchInterval.from_dict(BatchInterval.unknown().to_dict()).is_unknown)
        self.assertEqual(BatchInterval(2, 9), BatchInterval.from_dict(BatchInterval(2, 9).to_dict()))
        unbounded = BatchInterval.from_dict(BatchInterval(None, None, unknown=False).to_dict())
        self.assertFalse(unbounded.is_unknown)


class TestEvidenceAttribution(TestCase):

    def setUp(self) -> None:
        self.sample_batch_one = LocalSample(
            sample_id='SAMPLE-B1',
            batch=BatchInterval(1, 3),
            photo_index='PHOTO-B1',
            seal=EvidenceSeal('SEAL-B1'),
            part_number='PART-42',
        )
        self.sample_batch_two = LocalSample(
            sample_id='SAMPLE-B2',
            batch=BatchInterval(4, 6),
            photo_index='PHOTO-B2',
            seal=EvidenceSeal('SEAL-B2'),
            part_number='PART-42',
        )
        self.samples = (self.sample_batch_one, self.sample_batch_two)

    def test_intersection_alone_is_only_a_candidate(self) -> None:
        evidence = ComponentEvidence(identity=[_identity(provenance=EvidenceProvenance(
            batch=BatchInterval(2, 5),
            photo_index='WRONG-PHOTO',
            seal=EvidenceSeal('WRONG-SEAL'),
        ))])
        report = evidence.review(self.samples)[0]
        self.assertEqual(AttributionStatus.CANDIDATE, report.status)
        self.assertEqual(('SAMPLE-B1', 'SAMPLE-B2'), report.candidate_sample_ids)
        self.assertEqual((), report.attributed_sample_ids)

    def test_photo_and_seal_are_both_required(self) -> None:
        photo_only = ComponentEvidence(identity=[_identity(provenance=EvidenceProvenance(
            batch=BatchInterval(1, 3),
            photo_index='PHOTO-B1',
            seal=EvidenceSeal('SEAL-B2'),
        ))]).review(self.samples)[0]
        self.assertEqual(AttributionStatus.CANDIDATE, photo_only.status)

        seal_only = ComponentEvidence(identity=[_identity(provenance=EvidenceProvenance(
            batch=BatchInterval(1, 3),
            photo_index='PHOTO-B2',
            seal=EvidenceSeal('SEAL-B1'),
        ))]).review(self.samples)[0]
        self.assertEqual(AttributionStatus.CANDIDATE, seal_only.status)

        both = ComponentEvidence(identity=[_identity(provenance=EvidenceProvenance(
            batch=BatchInterval(1, 3),
            photo_index='PHOTO-B1',
            seal=EvidenceSeal('SEAL-B1'),
        ))]).review(self.samples)[0]
        self.assertEqual(AttributionStatus.ATTRIBUTED, both.status)
        self.assertEqual(('SAMPLE-B1',), both.attributed_sample_ids)

    def test_unverified_seal_blocks_attribution(self) -> None:
        report = ComponentEvidence(identity=[_identity(provenance=EvidenceProvenance(
            batch=BatchInterval(1, 3),
            photo_index='PHOTO-B1',
            seal=EvidenceSeal('SEAL-B1', verified=False),
        ))]).review(self.samples)[0]
        self.assertEqual(AttributionStatus.CANDIDATE, report.status)

    def test_different_part_number_is_not_a_candidate(self) -> None:
        evidence = ComponentEvidence(identity=[_identity(provenance=EvidenceProvenance(
            part_number='PART-OTHER',
            batch=BatchInterval(1, 3),
            photo_index='PHOTO-B1',
            seal=EvidenceSeal('SEAL-B1'),
        ))])
        report = evidence.review(self.samples)[0]
        self.assertEqual(AttributionStatus.UNATTRIBUTED, report.status)
        self.assertEqual((), report.candidate_sample_ids)

    def test_second_report_cannot_claim_first_batch_evidence(self) -> None:
        stolen = EvidenceProvenance(
            sample_id='SAMPLE-B1',
            batch=BatchInterval(4, 6),
            photo_index='PHOTO-B1',
            seal=EvidenceSeal('SEAL-B1'),
        )
        report = ComponentEvidence(identity=[_identity(provenance=stolen)]).review(self.samples)[0]

        self.assertEqual(AttributionStatus.CANDIDATE, report.status)
        self.assertEqual(('SAMPLE-B2',), report.candidate_sample_ids)
        self.assertEqual((), report.attributed_sample_ids)
        self.assertEqual(('SAMPLE-B1',), report.source_sample_ids)
        codes = {warning.code for warning in report.warnings}
        self.assertIn(AttributionWarning.CROSS_BATCH_EVIDENCE, codes)
        self.assertIn(AttributionWarning.SOURCE_OUTSIDE_INTERVAL, codes)

    def test_two_batches_contending_for_same_evidence_warns(self) -> None:
        shared_seal = EvidenceSeal('SEAL-SHARED')
        first = LocalSample(
            sample_id='SAMPLE-B1', batch=BatchInterval(1, 3),
            photo_index='PHOTO-SHARED', seal=shared_seal)
        second = LocalSample(
            sample_id='SAMPLE-B2', batch=BatchInterval(4, 6),
            photo_index='PHOTO-SHARED', seal=shared_seal)
        evidence = ComponentEvidence(identity=[_identity(provenance=EvidenceProvenance(
            batch=BatchInterval(1, 6),
            photo_index='PHOTO-SHARED',
            seal=shared_seal,
        ))])

        review = evidence.review([first, second])
        report = review[0]
        self.assertEqual(AttributionStatus.CONTESTED, report.status)
        self.assertEqual(('SAMPLE-B1', 'SAMPLE-B2'), report.attributed_sample_ids)
        contention = [w for w in review.warnings if w.code == AttributionWarning.BATCH_CONTENTION]
        self.assertTrue(contention)
        self.assertIn('two batches contend', contention[0].message)
        self.assertEqual(('SAMPLE-B1', 'SAMPLE-B2'), contention[0].sample_ids)
        self.assertEqual(2, len(contention[0].batches))

    def test_shared_seal_across_batches_warns_even_with_different_photo(self) -> None:
        shared_seal = EvidenceSeal('SEAL-SHARED')
        first = LocalSample(
            sample_id='SAMPLE-B1', batch=BatchInterval(1, 3),
            photo_index='PHOTO-B1', seal=shared_seal)
        second = LocalSample(
            sample_id='SAMPLE-B2', batch=BatchInterval(4, 6),
            photo_index='PHOTO-B2', seal=shared_seal)
        evidence = ComponentEvidence(identity=[_identity(provenance=EvidenceProvenance(
            batch=BatchInterval(1, 3),
            photo_index='PHOTO-B1',
            seal=shared_seal,
        ))])

        review = evidence.review([first, second])
        self.assertEqual(AttributionStatus.CONTESTED, review[0].status)
        self.assertTrue(any(w.code == AttributionWarning.BATCH_CONTENTION for w in review.warnings))


class TestLegacyImportAndReview(TestCase):

    def test_legacy_manifest_preserves_unknown_batch_layer(self) -> None:
        with open(path.join(OWN_DATA_DIRECTORY, 'json', '1.6', 'component_evidence_identity.json')) as f:
            bom = Bom.from_json(json.load(f))
        self.assertIsNotNone(bom)
        assert bom is not None
        component = next(c for c in bom.components if c.name == 'alpine')
        self.assertIsNotNone(component.evidence)
        assert component.evidence is not None
        for identity in component.evidence.identity:
            self.assertIs(ProvenanceSource.LEGACY, identity.provenance.source)
            self.assertTrue(identity.provenance.batch.is_unknown)

        report = component.evidence.review([LocalSample(
            sample_id='SAMPLE-1',
            batch=BatchInterval(1, 3),
            photo_index='PHOTO-1',
            seal=EvidenceSeal('SEAL-1'),
        )])[0]
        self.assertEqual(AttributionStatus.UNKNOWN, report.status)

    def test_from_legacy_replaces_explicit_provenance(self) -> None:
        evidence = ComponentEvidence(identity=[_identity(provenance=EvidenceProvenance(
            sample_id='SAMPLE-1',
            batch=BatchInterval(1, 3),
            photo_index='PHOTO-1',
            seal=EvidenceSeal('SEAL-1'),
        ))])
        ComponentEvidence.from_legacy(evidence)
        self.assertTrue(evidence.identity.pop().provenance.is_legacy)

    def test_review_traces_each_conclusion_to_sample_ids(self) -> None:
        batch_one = LocalSample(
            sample_id='SAMPLE-B1', batch=BatchInterval(1, 3),
            photo_index='PHOTO-B1', seal=EvidenceSeal('SEAL-B1'))
        batch_two = LocalSample(
            sample_id='SAMPLE-B2', batch=BatchInterval(4, 6),
            photo_index='PHOTO-B2', seal=EvidenceSeal('SEAL-B2'))
        evidence = ComponentEvidence(
            identity=[
                _identity('hash-b1', EvidenceProvenance(
                    batch=BatchInterval(1, 3), photo_index='PHOTO-B1', seal=EvidenceSeal('SEAL-B1'))),
                _identity('hash-b2', EvidenceProvenance(
                    batch=BatchInterval(4, 6), photo_index='PHOTO-B2', seal=EvidenceSeal('SEAL-B2'))),
            ],
        )

        trace = evidence.review([batch_one, batch_two]).trace_sample_ids()
        self.assertEqual(('SAMPLE-B1',), trace['hash-b1'])
        self.assertEqual(('SAMPLE-B2',), trace['hash-b2'])
        self.assertEqual(trace, evidence.trace([batch_one, batch_two]))

    def test_component_evidence_accepts_provenance_by_conclusion(self) -> None:
        evidence = ComponentEvidence(
            identity=[_identity('hash-b1'), _identity('hash-b2')],
            provenance=[
                EvidenceProvenance(
                    conclusion='hash-b2', batch=BatchInterval(4, 6),
                    sample_id='SAMPLE-B2', photo_index='PHOTO-B2', seal=EvidenceSeal('SEAL-B2')),
                EvidenceProvenance(
                    conclusion='hash-b1', batch=BatchInterval(1, 3),
                    sample_id='SAMPLE-B1', photo_index='PHOTO-B1', seal=EvidenceSeal('SEAL-B1')),
            ],
        )
        by_conclusion = {i.concluded_value: i.provenance.sample_id for i in evidence.identity}
        self.assertEqual({'hash-b1': 'SAMPLE-B1', 'hash-b2': 'SAMPLE-B2'}, by_conclusion)

    def test_provenance_is_not_written_to_the_bom(self) -> None:
        evidence = ComponentEvidence(identity=[_identity(provenance=EvidenceProvenance(
            sample_id='SAMPLE-1', batch=BatchInterval(1, 3),
            photo_index='PHOTO-1', seal=EvidenceSeal('SEAL-1')))])
        serialized = evidence.as_json(SchemaVersion1Dot6)
        self.assertNotIn('provenance', serialized)
        self.assertNotIn('SAMPLE-1', serialized)

    def test_duplicate_local_sample_ids_are_rejected(self) -> None:
        sample = LocalSample(sample_id='SAMPLE-1', batch=BatchInterval(1, 3))
        with self.assertRaises(InvalidValueException):
            LocalSampleRegistry([sample, sample])
