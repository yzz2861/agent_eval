# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import os
import unittest

from asn1crypto import pem, x509
from asn1crypto.util import timezone

from certvalidator import (
    CertificateValidator,
    UsageRequirement,
    ValidationContext,
    validate_joint_usage,
)
from certvalidator.errors import (
    IndependentResponsibilityError,
    InvalidCertificateError,
)

from ._unittest_compat import patch


patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures', 'joint')


class JointValidationTests(unittest.TestCase):

    def _load_cert(self, filename):
        with open(os.path.join(fixtures_dir, filename), 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            return x509.Certificate.load(cert_bytes)

    def setUp(self):
        self.root_a = self._load_cert('root-a.crt')
        self.root_b = self._load_cert('root-b.crt')
        self.intermediate_a = self._load_cert('intermediate-a.crt')
        self.intermediate_b = self._load_cert('intermediate-b.crt')
        self.service_a = self._load_cert('service-a.crt')
        self.service_b = self._load_cert('service-b.crt')

        self.moment = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        self.context = ValidationContext(
            trust_roots=[self.root_a, self.root_b],
            other_certs=[self.intermediate_a, self.intermediate_b],
            moment=self.moment
        )

        self.client_usage = UsageRequirement(
            key_usage=set(['digital_signature']),
            extended_key_usage=set(['client_auth']),
            name='client-auth'
        )
        self.email_usage = UsageRequirement(
            key_usage=set(['digital_signature']),
            extended_key_usage=set(['email_protection']),
            name='email-protection'
        )

    def test_individual_usages_validate_for_both_service_certs(self):
        for cert in (self.service_a, self.service_b):
            for requirement in (self.client_usage, self.email_usage):
                validator = CertificateValidator(cert, validation_context=self.context)
                path = validator.validate_usage(
                    requirement.key_usage,
                    requirement.extended_key_usage
                )
                self.assertEqual(cert.sha256, path[-1].sha256)

    def test_joint_rejects_when_only_shared_intermediate_exists(self):
        validator = CertificateValidator(self.service_a, validation_context=self.context)

        # Normal certificate validation still succeeds for both purposes.
        validator.validate_usage(
            self.client_usage.key_usage,
            self.client_usage.extended_key_usage
        )
        validator.validate_usage(
            self.email_usage.key_usage,
            self.email_usage.extended_key_usage
        )

        with self.assertRaises(IndependentResponsibilityError) as context:
            validator.validate_joint_usage([self.client_usage, self.email_usage])

        message = str(context.exception)
        self.assertIn('independent', message)
        self.assertIn(self.intermediate_a.subject.human_friendly, message)
        self.assertEqual(2, len(context.exception.paths_by_usage))

    def test_joint_searches_past_the_first_chain(self):
        validator = CertificateValidator(self.service_a, validation_context=self.context)

        result = validator.validate_joint_usage(
            [self.client_usage, self.email_usage],
            end_entity_certs=[self.service_a, self.service_b]
        )

        self.assertEqual(2, len(result))
        self.assertEqual(self.client_usage, result.usages[0])
        self.assertEqual(self.email_usage, result.usages[1])
        self.assertEqual(self.service_a.subject.hashable, result[0][-1].subject.hashable)
        self.assertEqual(self.service_b.subject.hashable, result[1][-1].subject.hashable)

        first_intermediate = result[0][1]
        second_intermediate = result[1][1]
        self.assertNotEqual(first_intermediate.subject.hashable, second_intermediate.subject.hashable)
        self.assertEqual(
            set([self.intermediate_a.subject.hashable, self.intermediate_b.subject.hashable]),
            set([first_intermediate.subject.hashable, second_intermediate.subject.hashable])
        )

    def test_module_entry_accepts_named_usage_mapping(self):
        result = validate_joint_usage(
            self.context,
            self.service_a,
            {
                'client': {
                    'key_usage': set(['digital_signature']),
                    'extended_key_usage': set(['client_auth']),
                },
                'email': {
                    'key_usage': set(['digital_signature']),
                    'extended_key_usage': set(['email_protection']),
                },
            },
            end_entity_certs=[self.service_a, self.service_b]
        )

        self.assertEqual(['client', 'email'], [usage.name for usage in result.usages])
        self.assertEqual(2, len(result))

    def test_usage_failure_still_uses_normal_validator_error(self):
        validator = CertificateValidator(self.service_a, validation_context=self.context)

        with self.assertRaisesRegex(InvalidCertificateError, 'for the purpose'):
            validator.validate_joint_usage(
                [
                    {
                        'key_usage': set(['digital_signature']),
                        'extended_key_usage': set(['server_auth']),
                    },
                    self.email_usage,
                ],
                end_entity_certs=[self.service_a, self.service_b]
            )

    def test_joint_entry_is_offline_only(self):
        context = ValidationContext(
            trust_roots=[self.root_a, self.root_b],
            other_certs=[self.intermediate_a, self.intermediate_b],
            allow_fetching=True
        )
        validator = CertificateValidator(self.service_a, validation_context=context)

        with self.assertRaisesRegex(ValueError, 'offline'):
            validator.validate_joint_usage([self.client_usage, self.email_usage])
