#
# SPDX-License-Identifier: Apache-2.0
import os
import tempfile
import textwrap

import testtools

from bandit.core import config as b_config
from bandit.core import manager as b_manager
from bandit.core import test_set as b_test_set
from bandit.plugins.sensitive_log import engine


CONFIG = {
    "local_only": False,
    "sensitive_sources": [
        {"name": "fake_api.read_request",
         "fields": ["fake_card_no"]}
    ],
    "trusted_sanitizers": ["fake_sec.mask_card"],
    "log_sinks": [
        "logging.Logger.info",
        "logging.Logger.error",
        "logging.Logger.exception",
    ],
}


class TaintEngineTests(testtools.TestCase):

    def analyze(self, code):
        return engine.analyze_source(textwrap.dedent(code), CONFIG)

    def test_clean_sanitized_field_is_not_flagged(self):
        findings = self.analyze(
            """
            def case(logger):
                req = fake_api.read_request()
                safe = fake_sec.mask_card(req["fake_card_no"])
                logger.info("evt", extra={"fake_card_no": safe})
            """
        )
        self.assertEqual([], findings)

    def test_overwrite_back_to_original_is_flagged(self):
        findings = self.analyze(
            """
            def case(logger):
                req = fake_api.read_request()
                card = fake_sec.mask_card(req["fake_card_no"])
                card = req["fake_card_no"]
                logger.error("evt", extra={"fake_card_no": card})
            """
        )
        leaks = [f for f in findings if f.kind == engine.Finding.LEAK]
        self.assertEqual(1, len(leaks))
        self.assertEqual("fake_card_no", leaks[0].field)
        self.assertEqual("fake_api.read_request", leaks[0].source)


    def test_failure_fallback_branch_is_flagged(self):
        findings = self.analyze(
            """
            def case(logger):
                req = fake_api.read_request()
                try:
                    card = fake_sec.mask_card(req["fake_card_no"])
                except fake_exc.FakeError:
                    card = req["fake_card_no"]
                logger.exception("evt", extra={"fake_card_no": card})
            """
        )
        leaks = [f for f in findings if f.kind == engine.Finding.LEAK]
        self.assertEqual(1, len(leaks))
        self.assertEqual("fake_card_no", leaks[0].field)

    def test_local_alias_and_dict_unpack_reach_sink(self):
        findings = self.analyze(
            """
            def case(logger):
                req = fake_api.read_request()
                snapshot = req
                details = {"note": "x"}
                details.update(snapshot)
                logger.info("evt", extra={"outer": 1, **details})
            """
        )
        self.assertEqual(1, len(findings))
        self.assertEqual(engine.Finding.LEAK, findings[0].kind)

    def test_unverified_external_call_is_reported_separately(self):
        findings = self.analyze(
            """
            def case(logger):
                req = fake_api.read_request()
                transformed = fake_vendor.normalize(req)
                logger.error("evt", extra={"fake_card_no": transformed})
            """
        )
        unknown = [f for f in findings if f.kind == engine.Finding.UNKNOWN]
        self.assertEqual(1, len(unknown))
        self.assertEqual("fake_vendor.normalize", unknown[0].call_name)
        self.assertFalse(
            any(f.kind == engine.Finding.LEAK for f in findings)
        )

    def test_sanitizer_after_external_call_is_clean(self):
        findings = self.analyze(
            """
            def case(logger):
                req = fake_api.read_request()
                transformed = fake_sec.mask_card(fake_vendor.normalize(req))
                logger.error("evt", extra={"fake_card_no": transformed})
            """
        )
        self.assertEqual([], findings)


class BanditIntegrationTests(testtools.TestCase):

    def _config_file(self):
        handle = tempfile.NamedTemporaryFile(
            suffix=".yaml", mode="wt", delete=False
        )
        handle.write(textwrap.dedent("""
            sensitive_log:
              local_only: true
              local_paths:
                - examples
              sensitive_sources:
                - name: fake_api.read_request
                  fields: [fake_card_no]
              trusted_sanitizers:
                - fake_sec.mask_card
              log_sinks:
                - logging.Logger.info
                - logging.Logger.error
                - logging.Logger.exception
        """))
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_bandit_reports_b616_and_b617(self):
        conf = b_config.BanditConfig(self._config_file())
        manager = b_manager.BanditManager(conf, "file")
        path = os.path.join(os.getcwd(), "examples", "sensitive_log.py")
        manager.discover_files([path], True)
        manager.run_tests()
        ids = sorted(result.test_id for result in manager.results)
        self.assertIn("B616", ids)
        self.assertIn("B617", ids)
        b616 = [r for r in manager.results if r.test_id == "B616"]
        b617 = [r for r in manager.results if r.test_id == "B617"]
        # overwrite, fallback and alias/unpack sinks all leak.
        self.assertEqual(3, len(b616))
        # only the unmodeled vendor call ends up unverified.
        self.assertEqual(1, len(b617))
        self.assertTrue(all(r.lineno > 0 for r in manager.results))
