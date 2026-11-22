# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest

from certvalidator import (
    BusinessConstraint,
    OfflineImpactAssessor,
    STATUS_DISTRUSTED,
    STATUS_INDETERMINATE,
    STATUS_ROOT_REMOVED,
    STATUS_TRUSTED,
    ValidationContext,
)
from certvalidator.errors import PathBuildingError

from ._oscrypto_backend import ensure_working_backend
from .impact_cert_tree import (
    CLIENT_CONSTRAINT,
    CODE_SIGNING_CONSTRAINT,
    SERVER_CONSTRAINT,
    VALIDATION_MOMENT,
    build_cert_tree,
)


class OfflineImpactAssessorTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.backend = ensure_working_backend()
        cls.material = build_cert_tree()
        cls.current_roots = [
            cls.material["r1"], cls.material["r2"], cls.material["r3"],
        ]
        cls.post_roots = [cls.material["r3"]]
        cls.intermediates = cls.material["all_intermediates"]

    def _assessor(self, **kwargs):
        params = {
            "intermediate_certs": self.intermediates,
            "moment": VALIDATION_MOMENT,
        }
        params.update(kwargs)
        return OfflineImpactAssessor(
            self.current_roots, self.post_roots, **params
        )

    def _status(self, leaf_name, constraint=SERVER_CONSTRAINT, **kwargs):
        assessor = self._assessor(**kwargs)
        return assessor.assess_usage(self.material[leaf_name], constraint)


    def test_removed_root_single_chain_is_root_removed(self):
        impact = self._status("ee_v")
        self.assertEqual(STATUS_ROOT_REMOVED, impact.status)
        self.assertIsNotNone(impact.current_path)
        self.assertIsNone(impact.replacement_path)
        self.assertEqual(
            self.material["r1"].sha256,
            impact.current_path.anchor.sha256,
        )
        self.assertIn("Historical Root R1", impact.reason)
        self.assertTrue(impact.is_affected)

    def test_cross_signed_chain_keeps_verifiable_replacement_path(self):
        impact = self._status("ee_x")
        self.assertEqual(STATUS_TRUSTED, impact.status)
        self.assertFalse(impact.is_affected)
        self.assertIsNotNone(impact.replacement_path)
        replacement = impact.replacement_path
        self.assertEqual(
            self.material["r3"].sha256, replacement.anchor.sha256
        )
        self.assertEqual(
            ["Common Name: Retained Root R3",
             "Common Name: Intermediate CA B",
             "Common Name: crosssigned.example"],
            replacement.subject_names,
        )
        self.assertEqual(
            self.material["r3"].sha256_fingerprint,
            replacement.anchor_sha256_fingerprint,
        )

    def test_doomed_chain_is_root_removed(self):
        impact = self._status("ee_c2")
        self.assertEqual(STATUS_ROOT_REMOVED, impact.status)
        self.assertEqual(
            self.material["r2"].sha256,
            impact.current_path.anchor.sha256,
        )

    def test_expired_certificate_is_distrusted_not_root_removed(self):
        impact = self._status("ee_e")
        self.assertEqual(STATUS_DISTRUSTED, impact.status)
        self.assertIsNone(impact.current_path)
        self.assertIn("expired", impact.reason)
        self.assertTrue(all(
            failure.configuration in ("current", "post_removal")
            for failure in impact.failures
        ))

    def test_missing_intermediate_is_indeterminate(self):
        incomplete = [
            cert for cert in self.intermediates
            if cert.sha256 != self.material["ca_a"].sha256
        ]
        impact = self._status("ee_m", intermediate_certs=incomplete)
        self.assertEqual(STATUS_INDETERMINATE, impact.status)
        self.assertIsNone(impact.current_path)
        failure_types = dict(
            (failure.configuration, failure.exception_type)
            for failure in impact.failures
        )
        self.assertEqual("PathBuildingError", failure_types["current"])
        self.assertEqual("PathBuildingError", failure_types["post_removal"])

    def test_require_revocation_without_material_is_indeterminate(self):
        impact = self._status("ee_o", revocation_mode="require")
        self.assertEqual(STATUS_INDETERMINATE, impact.status)
        self.assertIn("revocation", impact.reason)

    def test_unaffected_certificate_stays_trusted(self):
        impact = self._status("ee_o")
        self.assertEqual(STATUS_TRUSTED, impact.status)
        self.assertFalse(impact.is_affected)
        self.assertEqual(
            self.material["r3"].sha256,
            impact.replacement_path.anchor.sha256,
        )


    def test_joint_removal_is_worse_than_single_root_trials(self):
        leaves = ["ee_v", "ee_x", "ee_c2", "ee_d", "ee_e", "ee_o"]

        def statuses(post_roots):
            assessor = OfflineImpactAssessor(
                self.current_roots, post_roots,
                intermediate_certs=self.intermediates,
                moment=VALIDATION_MOMENT,
            )
            result = {}
            for leaf in leaves:
                result[leaf] = assessor.assess_usage(
                    self.material[leaf], SERVER_CONSTRAINT
                ).status
            return result

        remove_r1 = statuses([self.material["r2"], self.material["r3"]])
        remove_r2 = statuses([self.material["r1"], self.material["r3"]])
        remove_both = statuses([self.material["r3"]])

        # Each single-root trial keeps ee_d valid through the other anchor.
        self.assertEqual(STATUS_TRUSTED, remove_r1["ee_d"])
        self.assertEqual(STATUS_TRUSTED, remove_r2["ee_d"])
        # The joint removal eliminates both anchors at once.
        self.assertEqual(STATUS_ROOT_REMOVED, remove_both["ee_d"])

        trial_union = set([
            leaf for leaf in leaves
            if remove_r1[leaf] != STATUS_TRUSTED
            or remove_r2[leaf] != STATUS_TRUSTED
        ])
        joint_impacts = set([
            leaf for leaf in leaves
            if remove_both[leaf] != STATUS_TRUSTED
        ])
        self.assertEqual(set(["ee_d"]), joint_impacts - trial_union)

    def test_business_constraints_are_evaluated_separately(self):
        assessor = self._assessor()
        assessment = assessor.assess(self.material["ee_x"], [
            SERVER_CONSTRAINT, CLIENT_CONSTRAINT, CODE_SIGNING_CONSTRAINT,
        ])
        statuses = dict(
            (impact.label, impact.status) for impact in assessment.usage_impacts
        )
        self.assertEqual(STATUS_TRUSTED, statuses["tls_server_auth"])
        self.assertEqual(STATUS_TRUSTED, statuses["tls_client_auth"])
        self.assertEqual(STATUS_DISTRUSTED, statuses["code_signing"])
        self.assertEqual(
            set([STATUS_TRUSTED, STATUS_DISTRUSTED]), assessment.statuses
        )
        self.assertEqual(1, len(assessment.affected_usages))
        self.assertFalse(assessment.is_fully_trusted)

    def test_contexts_do_not_share_caches_across_configurations(self):
        assessor = self._assessor()
        current_context = assessor._new_context(assessor._current_roots)
        post_context = assessor._new_context(assessor._post_roots)
        self.assertIsNot(current_context, post_context)
        self.assertIsNot(
            current_context.certificate_registry,
            post_context.certificate_registry,
        )
        self.assertIsNot(current_context._validate_map, post_context._validate_map)
        self.assertFalse(current_context._allow_fetching)
        self.assertFalse(post_context._allow_fetching)

        current_anchors = set(
            cert.sha256 for cert in assessor._current_roots
        )
        post_anchors = set(cert.sha256 for cert in assessor._post_roots)
        self.assertTrue(post_anchors.issubset(current_anchors))

    def test_removed_roots_are_detected(self):
        assessor = self._assessor()
        removed = set(cert.sha256 for cert in assessor.removed_roots)
        self.assertEqual(
            set([self.material["r1"].sha256, self.material["r2"].sha256]),
            removed,
        )

    def test_assess_all_reports_every_certificate(self):
        assessor = self._assessor()
        assessments = assessor.assess_all(
            [self.material[name] for name in ("ee_v", "ee_o")],
            [SERVER_CONSTRAINT],
        )
        self.assertEqual(2, len(assessments))
        self.assertEqual(
            STATUS_ROOT_REMOVED, assessments[0].usage_impacts[0].status
        )
        self.assertEqual(
            STATUS_TRUSTED, assessments[1].usage_impacts[0].status
        )

    def test_path_building_failure_is_indeterminate_not_removed(self):
        # A leaf whose issuer is absent from both configurations must not be
        # mislabeled as a trust-root removal impact.
        assessor = self._assessor(intermediate_certs=[])
        impact = assessor.assess_usage(self.material["ee_v"], SERVER_CONSTRAINT)
        self.assertEqual(STATUS_INDETERMINATE, impact.status)
        self.assertIsNone(impact.current_path)

    def test_constructor_rejects_empty_current_roots(self):
        with self.assertRaises(ValueError):
            OfflineImpactAssessor(
                [], [self.material["r3"]],
                intermediate_certs=self.intermediates,
                moment=VALIDATION_MOMENT,
            )

    def test_constructor_rejects_naive_moment(self):
        from datetime import datetime
        with self.assertRaises(ValueError):
            OfflineImpactAssessor(
                self.current_roots, self.post_roots,
                intermediate_certs=self.intermediates,
                moment=datetime(2026, 6, 1),
            )


    def test_accepts_pem_encoded_inputs(self):
        from asn1crypto import pem
        current_pem = [pem.armor("CERTIFICATE", cert.dump()) for cert in self.current_roots]
        post_pem = [pem.armor("CERTIFICATE", cert.dump()) for cert in self.post_roots]
        intermediate_pem = [
            pem.armor("CERTIFICATE", cert.dump()) for cert in self.intermediates
        ]
        assessor = OfflineImpactAssessor(
            current_pem, post_pem,
            intermediate_certs=intermediate_pem,
            moment=VALIDATION_MOMENT,
        )
        leaf_pem = pem.armor("CERTIFICATE", self.material["ee_v"].dump())
        impact = assessor.assess_usage(leaf_pem, SERVER_CONSTRAINT)
        self.assertEqual(STATUS_ROOT_REMOVED, impact.status)

    def test_each_evaluation_uses_fresh_contexts(self):
        assessor = self._assessor()
        first = assessor._new_context(assessor._current_roots)
        second = assessor._new_context(assessor._current_roots)
        self.assertIsNot(first, second)
        self.assertIsNot(
            first.certificate_registry, second.certificate_registry
        )
        # Repeated assessments produce identical, deterministic statuses.
        first_impact = assessor.assess_usage(self.material["ee_v"], SERVER_CONSTRAINT)
        second_impact = assessor.assess_usage(self.material["ee_v"], SERVER_CONSTRAINT)
        self.assertEqual(first_impact.status, second_impact.status)
        self.assertEqual(first_impact.reason, second_impact.reason)


if __name__ == "__main__":
    unittest.main()
