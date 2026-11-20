# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Shared fixtures for the offline release test suite."""

from __future__ import annotations

import pytest

from release.objectstore import ObjectStore
from release.signing import ReleaseBuilder, RepoKeyring


@pytest.fixture
def store() -> ObjectStore:
    return ObjectStore()


@pytest.fixture
def keyring() -> RepoKeyring:
    return RepoKeyring.generate()


@pytest.fixture
def builder(keyring: RepoKeyring) -> ReleaseBuilder:
    return ReleaseBuilder(keyring)
