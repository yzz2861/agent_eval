# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import date, datetime
import itertools
import os
import unittest

from asn1crypto import pem, x509
from asn1crypto.util import timezone

from certvalidator import CertificateValidator, ValidationContext
from certvalidator.freeze import (
    DEFERRED,
    MISSING_MATERIALS,
    REVIEW,
    AlternativeEvidence,
    Freeze,
    ReviewProject,
    project_from_validation_path,
    review_freeze_impact,
    review_validators,
)
from certvalidator.path import ValidationPath

from ._unittest_compat import patch


patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class FreezeReviewTests(unittest.TestCase):

    def _load_cert_object(self, *path_components):
        with open(os.path.join(fixtures_dir, *path_components), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            return x509.Certificate.load(cert_bytes)

    def _two_shared_projects(self):
        return [
            ReviewProject(
                'alpha',
                service_order=1,
                valid_until=date(2026, 12, 20),
                evidence=['issuer-shared']
            ),
            ReviewProject(
                'beta',
                service_order=2,
                valid_until=date(2026, 12, 20),
                evidence=['issuer-shared']
            ),
        ]

    def test_two_projects_shared_evidence_out_of_order(self):
        expected = None
        for projects in itertools.permutations(self._two_shared_projects()):
            plan = review_freeze_impact(
                list(projects),
                ['issuer-shared'],
                service_order=['alpha', 'beta']
            )
            result = [item.name for item in plan.review_queue]
            self.assertEqual(['alpha', 'beta'], result)
            if expected is None:
                expected = plan.to_dict()
            else:
                self.assertEqual(expected, plan.to_dict())

        self.assertEqual('alpha', plan.first_reviewer)
        self.assertEqual(('issuer-shared',), plan.items[0].shared_evidence)
        self.assertEqual(('beta',), plan.items[0].peers)

    def test_validity_end_beats_service_order(self):
        projects = [
            ReviewProject(
                'alpha',
                service_order=1,
                valid_until=date(2026, 12, 31),
                evidence=['issuer-shared']
            ),
            ReviewProject(
                'beta',
                service_order=2,
                valid_until=date(2026, 12, 15),
                evidence=['issuer-shared']
            ),
        ]
        plan = review_freeze_impact(
            projects,
            ['issuer-shared'],
            service_order=['alpha', 'beta']
        )
        self.assertEqual(['beta', 'alpha'], [item.name for item in plan.review_queue])

    def test_shared_evidence_beats_service_order(self):
        projects = [
            ReviewProject(
                'alpha',
                service_order=1,
                valid_until=date(2026, 12, 20),
                evidence=['issuer-shared']
            ),
            ReviewProject(
                'beta',
                service_order=2,
                valid_until=date(2026, 12, 20),
                evidence=['issuer-shared']
            ),
            ReviewProject(
                'gamma',
                service_order=0,
                valid_until=date(2026, 12, 20),
                evidence=['issuer-single']
            ),
        ]
        plan = review_freeze_impact(
            projects,
            ['issuer-shared', 'issuer-single'],
            service_order=['gamma', 'alpha', 'beta']
        )
        self.assertEqual(['alpha', 'beta', 'gamma'], [item.name for item in plan.review_queue])

    def test_report_separates_review_deferred_and_missing(self):
        projects = [
            ReviewProject(
                'alpha',
                service_order=1,
                valid_until=date(2026, 12, 31),
                evidence=['issuer-shared']
            ),
            ReviewProject(
                'beta',
                service_order=2,
                valid_until=date(2026, 12, 15),
                evidence=['issuer-shared'],
                alternatives=[
                    AlternativeEvidence(
                        'cross-sign-beta',
                        evidence=['issuer-alternate'],
                        valid_from=date(2026, 12, 1),
                        valid_until=date(2027, 6, 1),
                        reason='cross-signed path does not use the frozen issuer'
                    )
                ]
            ),
            ReviewProject(
                'gamma',
                service_order=3,
                valid_until=date(2026, 12, 20),
                evidence=['issuer-shared'],
                materials=['receipt'],
                required_materials=['receipt', 'invoice']
            ),
        ]

        plan = review_freeze_impact(
            projects,
            ['issuer-shared'],
            service_order=['alpha', 'beta', 'gamma'],
            moment=date(2026, 12, 10)
        )

        self.assertEqual(['alpha'], [item.name for item in plan.review_queue])
        self.assertEqual(['beta'], [item.name for item in plan.deferred])
        self.assertEqual(['gamma'], [item.name for item in plan.missing_materials])

        beta = plan.get('beta')
        self.assertEqual(DEFERRED, beta.status)
        self.assertTrue(beta.split_allowed)
        self.assertEqual('cross-sign-beta', beta.alternative.key)
        self.assertEqual(date(2026, 12, 1).isoformat(), beta.alternative_valid_from.date().isoformat())
        self.assertEqual(date(2027, 6, 1).isoformat(), beta.alternative_valid_until.date().isoformat())
        self.assertEqual(date(2027, 6, 1).isoformat(), beta.defer_until.date().isoformat())
        self.assertEqual(
            'cross-signed path does not use the frozen issuer',
            beta.split_reason
        )

        gamma = plan.get('gamma')
        self.assertEqual(MISSING_MATERIALS, gamma.status)
        self.assertEqual(('invoice',), gamma.missing_materials)

        report = plan.report()
        self.assertIn('First review: alpha', report)
        self.assertIn('May defer: beta', report)
        self.assertIn('Missing materials: gamma', report)
        review_section = report.split('Review queue')[1].split('Deferred to alternative evidence')[0]
        deferred_section = report.split('Deferred to alternative evidence')[1].split('Missing materials:\n')[0]
        missing_section = report.split('Missing materials:\n')[1]
        self.assertIn('1. alpha', review_section)
        self.assertNotIn('2. beta', review_section)
        self.assertIn('beta', deferred_section)
        self.assertIn('cross-sign-beta', deferred_section)
        self.assertIn('split reason', deferred_section)
        self.assertIn('gamma', missing_section)
        self.assertIn('invoice', missing_section)

        data = plan.to_dict()
        self.assertEqual(['alpha'], data['review_order'])
        self.assertEqual(['beta'], data['deferred'])
        self.assertEqual({'gamma': ['invoice']}, data['missing_materials'])

    def test_alternative_using_frozen_evidence_is_not_usable(self):
        project = ReviewProject(
            'alpha',
            valid_until=date(2026, 12, 20),
            evidence=['issuer-shared'],
            alternatives=[
                AlternativeEvidence('bad-alt', evidence=['issuer-shared'])
            ]
        )
        plan = review_freeze_impact([project], ['issuer-shared'])
        self.assertEqual(REVIEW, plan.get('alpha').status)

    def test_partial_alternative_must_cover_all_frozen_items(self):
        project = ReviewProject(
            'alpha',
            valid_until=date(2026, 12, 20),
            evidence=['issuer-a', 'issuer-b'],
            alternatives=[
                AlternativeEvidence(
                    'partial-alt',
                    covers=['issuer-a'],
                    complete=False
                )
            ]
        )
        plan = review_freeze_impact([project], ['issuer-a', 'issuer-b'])
        self.assertEqual(REVIEW, plan.get('alpha').status)

    def test_expired_alternative_is_not_usable(self):
        project = ReviewProject(
            'alpha',
            valid_until=date(2027, 1, 1),
            evidence=['issuer-shared'],
            alternatives=[
                AlternativeEvidence(
                    'old-alt',
                    evidence=['issuer-alternate'],
                    valid_until=date(2026, 6, 1)
                )
            ]
        )
        plan = review_freeze_impact(
            [project],
            ['issuer-shared'],
            moment=date(2026, 12, 10)
        )
        self.assertEqual(REVIEW, plan.get('alpha').status)

    def test_future_alternative_defers_until_it_belongs(self):
        project = ReviewProject(
            'alpha',
            valid_until=date(2027, 1, 1),
            evidence=['issuer-shared'],
            alternatives=[
                AlternativeEvidence(
                    'future-alt',
                    evidence=['issuer-alternate'],
                    valid_from=date(2027, 1, 1),
                    valid_until=date(2027, 12, 1)
                )
            ]
        )
        plan = review_freeze_impact(
            [project],
            ['issuer-shared'],
            moment=date(2026, 12, 10)
        )
        item = plan.get('alpha')
        self.assertEqual(DEFERRED, item.status)
        self.assertEqual(date(2027, 1, 1).isoformat(), item.defer_until.date().isoformat())

    def test_dict_projects_are_supported(self):
        projects = [
            {
                'id': 'alpha',
                'service': 2,
                'expires': '2026-12-20',
                'issuance_evidence': ['issuer-shared'],
            },
            {
                'id': 'beta',
                'service': 1,
                'expires': '2026-12-20',
                'issuance_evidence': ['issuer-shared'],
            },
        ]
        plan = review_freeze_impact(projects, ['issuer-shared'])
        self.assertEqual(['beta', 'alpha'], [item.name for item in plan.review_queue])

    def test_single_values_are_not_treated_as_character_sequences(self):
        project = ReviewProject(
            'alpha',
            valid_until=date(2026, 12, 20),
            evidence='issuer-shared'
        )
        plan = review_freeze_impact(project, 'issuer-shared', service_order='alpha')
        self.assertEqual(['alpha'], [item.name for item in plan.review_queue])
        self.assertEqual(('issuer-shared',), plan.get('alpha').affected_evidence)

        dict_plan = review_freeze_impact(
            {'name': 'beta', 'valid_until': '2026-12-20', 'evidence': 'issuer-shared'},
            'issuer-shared'
        )
        self.assertEqual(['beta'], [item.name for item in dict_plan.review_queue])

    def test_freeze_object_can_stand_in_for_evidence_list(self):
        freeze = Freeze(
            ['issuer-shared'],
            batch='external-2026-11',
            frozen_until='2026-12-31',
            reason='issuer incident under review'
        )
        project = ReviewProject(
            'alpha',
            valid_until=date(2026, 12, 20),
            evidence=['issuer-shared']
        )
        plan = review_freeze_impact(project, freeze)
        self.assertEqual(['alpha'], [item.name for item in plan.review_queue])
        self.assertEqual('external-2026-11', plan.to_dict()['batch'])
        self.assertEqual('2026-12-31T00:00:00+00:00', plan.to_dict()['frozen_until'])
        self.assertIn('Frozen batch: external-2026-11', plan.report())

    def test_validation_path_evidence_and_freeze_review(self):
        cert = self._load_cert_object('mozilla.org.crt')
        intermediate = self._load_cert_object('digicert-sha2-secure-server-ca.crt')
        root = self._load_cert_object('digicert-global-root-ca.crt')
        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        try:
            validator = CertificateValidator(
                cert,
                [intermediate],
                ValidationContext(trust_roots=[root], moment=moment)
            )
            plan = validator.freeze_impact_review(
                [intermediate.sha256_fingerprint],
                name='mozilla',
                service_order=['mozilla'],
                moment=moment
            )
        except OSError as e:
            self.skipTest('local crypto backend unavailable: %s' % e)

        self.assertEqual(1, len(plan))
        item = plan.get('mozilla')
        self.assertEqual(REVIEW, item.status)
        self.assertIn(intermediate.sha256_fingerprint, item.project.evidence)
        self.assertIn('mozilla', plan.report())

    def test_project_from_validation_path_uses_issuer_evidence(self):
        cert = self._load_cert_object('mozilla.org.crt')
        intermediate = self._load_cert_object('digicert-sha2-secure-server-ca.crt')
        root = self._load_cert_object('digicert-global-root-ca.crt')

        path = ValidationPath(cert)
        path.prepend(intermediate)
        path.prepend(root)

        project = project_from_validation_path(path, name='mozilla')
        self.assertEqual('mozilla', project.name)
        self.assertIn(intermediate.sha256_fingerprint, project.evidence)
        self.assertIn(root.sha256_fingerprint, project.evidence)
        self.assertNotIn(cert.sha256_fingerprint, project.evidence)
        self.assertEqual(cert.not_valid_after, project.valid_until)

    def test_review_validators_shares_issuer_evidence(self):
        cert = self._load_cert_object('mozilla.org.crt')
        intermediate = self._load_cert_object('digicert-sha2-secure-server-ca.crt')
        root = self._load_cert_object('digicert-global-root-ca.crt')
        moment = datetime(2019, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        try:
            validators = []
            for _ in range(2):
                validators.append(CertificateValidator(
                    cert,
                    [intermediate],
                    ValidationContext(trust_roots=[root], moment=moment)
                ))

            plan = review_validators(
                validators,
                [intermediate.sha256_fingerprint],
                names=['project-a', 'project-b'],
                service_order=['project-a', 'project-b']
            )
        except OSError as e:
            self.skipTest('local crypto backend unavailable: %s' % e)
        self.assertEqual(['project-a', 'project-b'], [item.name for item in plan.review_queue])
        self.assertEqual(('project-b',), plan.get('project-a').peers)


if __name__ == '__main__':
    unittest.main()
