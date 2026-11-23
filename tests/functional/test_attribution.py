#
# SPDX-License-Identifier: Apache-2.0
import json
import os
import subprocess
import sys
import tempfile

import testtools


class AttributionFunctionalTests(testtools.TestCase):
    def test_cli_consumes_fake_release_manifests(self):
        descriptor, output_path = tempfile.mkstemp(suffix=".json")
        os.close(descriptor)
        self.addCleanup(os.unlink, output_path)

        command = [
            sys.executable,
            "-m",
            "bandit.cli.attribution",
            "tests/fixtures/attribution/bandit-report.json",
            "--manifest",
            "tests/fixtures/attribution/phase-1-legacy-manifest.json",
            "--output",
            output_path,
        ]
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(0, process.returncode, process.stderr.decode())
        with open(output_path, encoding="utf-8") as output_file:
            data = json.load(output_file)
        self.assertEqual(4, data["summary"]["finding_count"])
        self.assertEqual(2, len(data["risk_burden"]))
        self.assertEqual(1, len(data["review_candidates"]))
        self.assertTrue(
            any(
                row["reason"] == "shared_source_finding"
                for row in data["double_counting"]
            )
        )
