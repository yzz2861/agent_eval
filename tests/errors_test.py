"""Tests for josepy.errors."""

import sys
import unittest

import pytest


class UnrecognizedTypeErrorTest(unittest.TestCase):
    def setUp(self) -> None:
        from josepy.errors import UnrecognizedTypeError

        self.error = UnrecognizedTypeError("foo", {"type": "foo"})

    def test_str(self) -> None:
        assert "foo was not recognized, full message: {'type': 'foo'}" == str(self.error)


class KeyAuthorizationErrorTest(unittest.TestCase):
    def test_hierarchy(self) -> None:
        from josepy.errors import (
            Error,
            KeyAuthorizationError,
            SerializationError,
        )

        error = KeyAuthorizationError("invalid token")
        assert isinstance(error, SerializationError)
        assert isinstance(error, ValueError)
        assert isinstance(error, Error)
        assert str(error) == "invalid token"


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
