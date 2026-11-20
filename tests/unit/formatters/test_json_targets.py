#
# SPDX-License-Identifier: Apache-2.0
import json
import os
import tempfile

import testtools

from bandit.core import config
from bandit.core import constants
from bandit.core import manager
from bandit.core import metrics
from bandit.formatters import json as b_json


class MultiTargetJsonFormatterTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.manager = manager.BanditManager(config.BanditConfig(), "file")
        self.manager.metrics = metrics.Metrics()

    def _render(self):
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        name = handle.name
        try:
            b_json.report(
                self.manager,
                handle,
                constants.LOW,
                constants.LOW,
            )
            with open(name, encoding="utf-8") as stream:
                return json.loads(stream.read())
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def test_legacy_report_has_no_target_results(self):
        data = self._render()
        self.assertNotIn("target_results", data)
        self.assertIn("results", data)
        self.assertIn("errors", data)
        self.assertIn("metrics", data)

    def test_multi_target_block_is_additive(self):
        self.manager.multi_target_report = {
            "host_python_version": "3.12",
            "targets": ["3.8", "3.12"],
            "status_legend": {},
            "summary": {},
            "files": [],
        }
        data = self._render()
        self.assertEqual(data["results"], [])
        self.assertEqual(
            data["target_results"]["targets"], ["3.8", "3.12"]
        )
        self.assertEqual(
            data["target_results"]["host_python_version"], "3.12"
        )
