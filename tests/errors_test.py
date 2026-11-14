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


class JWSHeaderErrorHierarchyTest(unittest.TestCase):
    def test_classified_errors_are_deserialization_errors(self) -> None:
        from josepy import errors

        for error_cls in (
            errors.JWSHeaderError,
            errors.HeaderConflictError,
            errors.HeaderSourceError,
            errors.AlgorithmError,
            errors.CriticalHeaderError,
            errors.KeySelectorError,
        ):
            assert issubclass(error_cls, errors.DeserializationError)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
