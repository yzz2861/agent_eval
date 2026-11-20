"""Shared fixtures for the delay_evidence test suite."""

from __future__ import annotations

import pytest

from delay_evidence.loader import load_bytes
from delay_evidence.make_samples import (
    SAMPLE_A_SPECS,
    SAMPLE_B_SPECS,
)
from delay_evidence.sample_builder import build_sample


@pytest.fixture(scope="session")
def sample_a_bytes():
    image, _ = build_sample(SAMPLE_A_SPECS)
    return image


@pytest.fixture(scope="session")
def sample_b_bytes():
    image, _ = build_sample(SAMPLE_B_SPECS)
    return image


@pytest.fixture()
def loaded_a(sample_a_bytes):
    return load_bytes(sample_a_bytes, source="sample_a")


@pytest.fixture()
def loaded_b(sample_b_bytes):
    return load_bytes(sample_b_bytes, source="sample_b")
