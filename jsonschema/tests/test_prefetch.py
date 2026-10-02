from unittest import TestCase
import asyncio
import json

import referencing.exceptions

from jsonschema import Draft202012Validator
from jsonschema.prefetch import (
    DisallowedTarget,
    PrefetchError,
    PrefetchTimeout,
    ResourceLimitExceeded,
    SizeLimitExceeded,
    prefetch,
)


class Loader:
    """
    A loader stub serving documents from a dict and recording its calls.
    """

    def __init__(self, documents, delay=0):
        self.documents = documents
        self.delay = delay
        self.calls = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def __call__(self, uri):
        self.calls.append(uri)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            return json.dumps(self.documents[uri]).encode()
        finally:
            self.in_flight -= 1


class TestPrefetch(TestCase):
    def prefetch(self, *args, **kwargs):
        return asyncio.run(prefetch(*args, **kwargs))

    def test_retrieves_referenced_document(self):
        loader = Loader({"https://example.com/int.json": {"type": "integer"}})
        schema = {"$ref": "https://example.com/int.json"}

        registry = self.prefetch(schema, loader=loader)

        self.assertEqual(loader.calls, ["https://example.com/int.json"])
        validator = Draft202012Validator(schema, registry=registry)
        self.assertEqual(list(validator.iter_errors(3)), [])
        self.assertEqual(
            [error.message for error in validator.iter_errors("three")],
            ["'three' is not of type 'integer'"],
        )

    def test_relative_references_resolve_against_resource_id(self):
        loader = Loader(
            {
                "https://example.com/dir/a.json": {
                    "$id": "https://example.com/dir/a.json",
                    "$ref": "b.json",
                },
                "https://example.com/dir/b.json": {"type": "integer"},
            },
        )
        schema = {"$ref": "https://example.com/dir/a.json"}

        registry = self.prefetch(schema, loader=loader)

        self.assertEqual(
            sorted(loader.calls),
            [
                "https://example.com/dir/a.json",
                "https://example.com/dir/b.json",
            ],
        )
        validator = Draft202012Validator(schema, registry=registry)
        self.assertEqual(list(validator.iter_errors(3)), [])

    def test_same_uri_is_retrieved_only_once(self):
        loader = Loader(
            {
                "https://example.com/a.json": {
                    "$id": "https://example.com/a.json",
                    "allOf": [
                        {"$ref": "common.json"},
                        {"$ref": "common.json"},
                    ],
                },
                "https://example.com/b.json": {
                    "$id": "https://example.com/b.json",
                    "$ref": "common.json",
                },
                "https://example.com/common.json": {"type": "integer"},
            },
            delay=0.01,
        )
        schema = {
            "properties": {
                "a": {"$ref": "https://example.com/a.json"},
                "b": {"$ref": "https://example.com/b.json"},
                "c": {"$ref": "https://example.com/common.json"},
            },
        }

        self.prefetch(schema, loader=loader)

        self.assertEqual(
            sorted(loader.calls),
            [
                "https://example.com/a.json",
                "https://example.com/b.json",
                "https://example.com/common.json",
            ],
        )

    def test_cycles_do_not_cause_duplicate_requests(self):
        loader = Loader(
            {
                "https://example.com/a.json": {
                    "$id": "https://example.com/a.json",
                    "properties": {"b": {"$ref": "b.json"}},
                },
                "https://example.com/b.json": {
                    "$id": "https://example.com/b.json",
                    "properties": {
                        "a": {"$ref": "a.json"},
                        "b": {"$ref": "b.json"},
                    },
                },
            },
        )
        schema = {"$ref": "https://example.com/a.json"}

        registry = self.prefetch(schema, loader=loader)

        self.assertEqual(
            sorted(loader.calls),
            ["https://example.com/a.json", "https://example.com/b.json"],
        )
        validator = Draft202012Validator(schema, registry=registry)
        self.assertEqual(list(validator.iter_errors({})), [])

    def test_concurrency_is_limited(self):
        documents = {
            f"https://example.com/{i}.json": {"type": "integer"}
            for i in range(6)
        }
        loader = Loader(documents, delay=0.02)
        schema = {
            "properties": {
                str(i): {"$ref": f"https://example.com/{i}.json"}
                for i in range(6)
            },
        }

        self.prefetch(schema, loader=loader, max_concurrency=2)

        self.assertEqual(len(loader.calls), 6)
        self.assertLessEqual(loader.max_in_flight, 2)
        self.assertGreaterEqual(loader.max_in_flight, 2)

    def test_too_many_resources(self):
        documents = {
            f"https://example.com/{i}.json": {"type": "integer"}
            for i in range(3)
        }
        loader = Loader(documents)
        schema = {
            "allOf": [
                {"$ref": f"https://example.com/{i}.json"} for i in range(3)
            ],
        }

        with self.assertRaises(ResourceLimitExceeded):
            self.prefetch(schema, loader=loader, max_resources=2)

    def test_too_many_bytes(self):
        loader = Loader(
            {
                "https://example.com/a.json": {
                    "$id": "https://example.com/a.json",
                    "$ref": "b.json",
                },
                "https://example.com/b.json": {"type": "integer"},
            },
        )
        schema = {"$ref": "https://example.com/a.json"}

        with self.assertRaises(SizeLimitExceeded):
            self.prefetch(schema, loader=loader, max_bytes=60)

    def test_disallowed_scheme(self):
        loader = Loader({"http://example.com/a.json": {"type": "integer"}})
        schema = {"$ref": "http://example.com/a.json"}

        with self.assertRaises(DisallowedTarget):
            self.prefetch(schema, loader=loader)
        self.assertEqual(loader.calls, [])

    def test_configured_scheme_is_allowed(self):
        loader = Loader({"http://example.com/a.json": {"type": "integer"}})
        schema = {"$ref": "http://example.com/a.json"}

        registry = self.prefetch(
            schema,
            loader=loader,
            allowed_schemes=("http",),
        )
        self.assertEqual(loader.calls, ["http://example.com/a.json"])
        Draft202012Validator(schema, registry=registry).validate(3)

    def test_disallowed_host(self):
        loader = Loader(
            {
                "https://good.example.com/a.json": {"type": "integer"},
                "https://evil.example.com/b.json": {"type": "string"},
            },
        )
        schema = {
            "properties": {
                "a": {"$ref": "https://good.example.com/a.json"},
                "b": {"$ref": "https://evil.example.com/b.json"},
            },
        }

        with self.assertRaises(DisallowedTarget):
            self.prefetch(
                schema,
                loader=loader,
                allowed_hosts={"good.example.com"},
            )

    def test_timeout(self):
        async def loader(uri):
            await asyncio.sleep(30)

        schema = {"$ref": "https://example.com/a.json"}

        with self.assertRaises(PrefetchTimeout):
            self.prefetch(schema, loader=loader, timeout=0.01)

    def test_cancellation_cancels_in_flight_loads(self):
        started = asyncio.Event()
        cancelled = asyncio.Event()

        async def loader(uri):
            started.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise

        async def main():
            task = asyncio.ensure_future(
                prefetch(
                    {"$ref": "https://example.com/a.json"},
                    loader=loader,
                ),
            )
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(main())
        self.assertTrue(cancelled.is_set())

    def test_loader_failure_produces_no_registry(self):
        async def loader(uri):
            if uri == "https://example.com/bad.json":
                raise OSError("boom")
            return json.dumps({"type": "integer"})

        schema = {
            "properties": {
                "a": {"$ref": "https://example.com/good.json"},
                "b": {"$ref": "https://example.com/bad.json"},
            },
        }

        with self.assertRaises(PrefetchError) as cm:
            self.prefetch(schema, loader=loader)
        self.assertIsInstance(cm.exception.__cause__, OSError)

    def test_invalid_json_produces_no_registry(self):
        async def loader(uri):
            return b"{"

        schema = {"$ref": "https://example.com/a.json"}

        with self.assertRaises(PrefetchError):
            self.prefetch(schema, loader=loader)

    def test_unexpected_loader_result_produces_no_registry(self):
        async def loader(uri):
            return {"type": "integer"}

        schema = {"$ref": "https://example.com/a.json"}

        with self.assertRaises(PrefetchError):
            self.prefetch(schema, loader=loader)

    def test_loader_may_return_str(self):
        async def loader(uri):
            return json.dumps({"type": "integer"})

        schema = {"$ref": "https://example.com/a.json"}

        registry = self.prefetch(schema, loader=loader)
        Draft202012Validator(schema, registry=registry).validate(3)

    def test_registry_is_offline(self):
        loader = Loader({"https://example.com/int.json": {"type": "integer"}})
        schema = {"$ref": "https://example.com/int.json"}
        registry = self.prefetch(schema, loader=loader)

        with self.assertRaises(
            referencing.exceptions.Unretrievable,
        ) as cm:
            registry.get_or_retrieve("https://example.com/missing.json")
        self.assertIsInstance(cm.exception.__cause__, PrefetchError)

        missing = {
            "properties": {
                "a": {"$ref": "https://example.com/int.json"},
                "b": {"$ref": "https://example.com/missing.json"},
            },
        }
        validator = Draft202012Validator(missing, registry=registry)
        with self.assertRaises(referencing.exceptions.Unresolvable) as cm:
            list(validator.iter_errors({"b": 1}))
        cause = cm.exception.__cause__
        while cause is not None and not isinstance(cause, PrefetchError):
            cause = cause.__cause__
        self.assertIsInstance(cause, PrefetchError)
        self.assertEqual(loader.calls, ["https://example.com/int.json"])

    def test_fragment_references(self):
        loader = Loader(
            {
                "https://example.com/a.json": {
                    "$defs": {"int": {"type": "integer"}},
                },
            },
        )
        schema = {"$ref": "https://example.com/a.json#/$defs/int"}

        registry = self.prefetch(schema, loader=loader)

        self.assertEqual(loader.calls, ["https://example.com/a.json"])
        validator = Draft202012Validator(schema, registry=registry)
        self.assertEqual(list(validator.iter_errors(3)), [])
        self.assertEqual(len(list(validator.iter_errors("three"))), 1)

    def test_subresources_are_not_retrieved_separately(self):
        loader = Loader(
            {
                "https://example.com/a.json": {
                    "$id": "https://example.com/a.json",
                    "properties": {
                        "inner": {
                            "$id": "inner.json",
                            "type": "integer",
                        },
                        "other": {"$ref": "inner.json"},
                    },
                },
            },
        )
        schema = {"$ref": "https://example.com/a.json"}

        registry = self.prefetch(schema, loader=loader, max_concurrency=1)

        self.assertEqual(loader.calls, ["https://example.com/a.json"])
        validator = Draft202012Validator(schema, registry=registry)
        self.assertEqual(
            [error.message for error in validator.iter_errors({"other": "x"})],
            ["'x' is not of type 'integer'"],
        )

    def test_subresources_known_by_the_time_they_dequeue(self):
        loader = Loader(
            {
                "https://example.com/a.json": {
                    "$id": "https://example.com/a.json",
                    "properties": {
                        "inner": {
                            "$id": "inner.json",
                            "type": "integer",
                        },
                    },
                },
            },
        )
        schema = {
            "$id": "https://example.com/root.json",
            "properties": {
                "b": {"$ref": "https://example.com/inner.json"},
                "a": {"$ref": "a.json"},
            },
        }

        registry = self.prefetch(schema, loader=loader, max_concurrency=1)

        self.assertEqual(loader.calls, ["https://example.com/a.json"])
        validator = Draft202012Validator(schema, registry=registry)
        self.assertEqual(
            [error.message for error in validator.iter_errors({"b": "x"})],
            ["'x' is not of type 'integer'"],
        )

    def test_meta_schemas_are_not_retrieved(self):
        async def loader(uri):  # pragma: no cover
            raise AssertionError("should not be called")

        schema = {
            "$ref": "https://json-schema.org/draft/2020-12/schema",
        }
        registry = self.prefetch(schema, loader=loader)
        Draft202012Validator(schema, registry=registry).validate(
            {"type": "integer"},
        )

    def test_boolean_schema(self):
        async def loader(uri):  # pragma: no cover
            raise AssertionError("should not be called")

        registry = self.prefetch(True, loader=loader)
        Draft202012Validator(True, registry=registry).validate(3)

    def test_invalid_limits(self):
        async def loader(uri):  # pragma: no cover
            raise AssertionError("should not be called")

        with self.assertRaises(ValueError):
            self.prefetch({}, loader=loader, max_concurrency=0)
        with self.assertRaises(ValueError):
            self.prefetch({}, loader=loader, max_resources=-1)
        with self.assertRaises(ValueError):
            self.prefetch({}, loader=loader, max_bytes=-1)
