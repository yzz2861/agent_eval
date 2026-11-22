"""Shared fixtures for the offline sampler tests."""

import json

import pytest


def _secret(secret_type, filename, hashed_secret, line_number):
    return {
        "type": secret_type,
        "filename": filename,
        "hashed_secret": hashed_secret,
        "is_verified": False,
        "line_number": line_number,
    }


@pytest.fixture
def baseline_file(tmp_path):
    """A baseline with a multi-plugin hit and a deliberately small queue."""
    results = {
        # Same location flagged by two plugins: must collapse into one finding.
        "src/payments/api.py": [
            _secret("AWS Access Key", "src/payments/api.py", "hash-aaa", 10),
            _secret("Secret Keyword", "src/payments/api.py", "hash-aaa", 10),
            _secret("AWS Access Key", "src/payments/api.py", "hash-bbb", 20),
            _secret("AWS Access Key", "src/payments/api.py", "hash-ccc", 30),
        ],
        "src/payments/worker.py": [
            _secret("Private Key", "src/payments/worker.py", "hash-ddd", 5),
            _secret("Private Key", "src/payments/worker.py", "hash-eee", 6),
        ],
        # Tiny legacy queue: only two findings, easy to starve of reviews.
        "legacy/old_module.py": [
            _secret("JSON Web Token", "legacy/old_module.py", "hash-fff", 1),
            _secret("JSON Web Token", "legacy/old_module.py", "hash-ggg", 2),
        ],
    }
    baseline = {
        "version": "1.5.0",
        "plugins_used": [],
        "filters_used": [],
        "results": results,
        "generated_at": "2026-11-23T00:00:00Z",
    }
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(baseline))
    return path


@pytest.fixture
def queue_map_file(tmp_path):
    mapping = {
        "src/payments/": "payments",
        "legacy/": "legacy",
    }
    path = tmp_path / "queues.json"
    path.write_text(json.dumps(mapping))
    return path


@pytest.fixture
def reviewed_file(tmp_path):
    # Review most of the payments findings but nothing from legacy.
    reviewed = [
        "src/payments/api.py:10:hash-aaa",
        "src/payments/api.py:20:hash-bbb",
        "src/payments/api.py:30:hash-ccc",
        "src/payments/worker.py:5:hash-ddd",
    ]
    path = tmp_path / "reviewed.json"
    path.write_text(json.dumps(reviewed))
    return path
