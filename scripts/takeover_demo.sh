#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Reproduce the directory-handoff adjudication example end to end.
#
# Runs the takeover decision layer over the fixtures in examples/takeover/ and
# writes three artefacts into reports/:
#   - approval-detail.txt : human approval document (new format)
#   - adjudication.json   : machine-readable decisions (new format)
#   - bandit-compat.json  : legacy Bandit JSON report, generated independently
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
mkdir -p reports

python -m bandit.takeover.cli \
  --policy examples/takeover/ownership-policy.yaml \
  --current examples/takeover/bandit-current.json \
  --legacy examples/takeover/bandit-legacy.json \
  --approval-out reports/approval-detail.txt \
  --json-out reports/adjudication.json \
  --legacy-json-out reports/bandit-compat.json
status=$?

echo
echo "Approval detail written to reports/approval-detail.txt"
echo "Legacy-compatible report written to reports/bandit-compat.json"
exit "${status}"
