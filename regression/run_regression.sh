#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m regression \
  --frozen-dir fixtures/frozen \
  --old-scan fixtures/scans/old_bandit.json \
  --new-scan fixtures/scans/new_bandit.json \
  --output-dir output \
  --sample-root fixtures/frozen
