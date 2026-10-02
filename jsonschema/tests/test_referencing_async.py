import asyncio
import json
from unittest import TestCase

from jsonschema import Draft202012Validator
from jsonschema.referencing import (
    ByteLimitExceeded,
    DisallowedURI,
    LoadedSchema,
    ResourceLimitExceeded,
    prepare_registry,
)


def run(coroutine):
    return asyncio.run(coroutine)


class RecordingLoader:
    def __init__(self, schemas):
        self.schemas = schemas
        self.calls = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def __call__(self, uri):
        self.calls.append(uri)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        await asyncio.sleep(0)
        self.in_flight -= 1
        return self.schemas[uri]


class AsyncRegistryPreparationTests(TestCase):
    def test_prepares_relative_references_for_offline_validation(self):
        loader = RecordingLoader({
            "https://example.test/schemas/child.json": {
                "$id": "child.json",
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "integer",
            },
        })
        root = {
            "$id": "https://example.test/schemas/root.json",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "child.json",
        }

        registry = run(prepare_registry(
            root,
            loader,
            allowed_targets=("https://example.test/schemas/",),
        ))

        self.assertEqual(
            loader.calls,
            ["https://example.test/schemas/child.json"],
        )
        validator = Draft202012Validator(root, registry=registry)
        validator.validate(1)
        self.assertFalse(validator.is_valid("no"))

    def test_same_uri_is_requested_once_including_cycles(self):
        root_id = "https://example.test/root"
        child_uri = "https://example.test/child"
        schemas = {
            child_uri: {
                "$id": child_uri,
                "allOf": [
                    {"$ref": child_uri},
                    {"$ref": "child"},
                    {"$ref": "#/allOf/0"},
                ],
            },
        }
        loader = RecordingLoader(schemas)

        run(prepare_registry(
            {"$id": root_id, "$ref": "child"},
            loader,
            allowed_targets=("https://example.test/",),
        ))

        self.assertEqual(loader.calls, [child_uri])

    def test_concurrency_is_limited(self):
        uris = [
            f"https://example.test/schema-{number}" for number in range(6)
        ]

        class ConcurrencyLoader:
            def __init__(self):
                self.in_flight = 0
                self.max_in_flight = 0

            async def __call__(self, uri):
                self.in_flight += 1
                self.max_in_flight = max(
                    self.max_in_flight,
                    self.in_flight,
                )
                await asyncio.sleep(0.02)
                self.in_flight -= 1
                return {"type": "integer"}

        loader = ConcurrencyLoader()
        root = {
            "$id": "https://example.test/root",
            "allOf": [{"$ref": uri} for uri in uris],
        }

        run(prepare_registry(
            root,
            loader,
            max_concurrency=2,
            allowed_targets=("https://example.test/",),
        ))

        self.assertEqual(loader.max_in_flight, 2)

    def test_concurrency_is_limited_after_dynamic_discovery(self):
        child_uris = [
            f"https://example.test/child-{number}"
            for number in range(4)
        ]

        class DynamicLoader:
            def __init__(self):
                self.in_flight = 0
                self.max_in_flight = 0

            async def __call__(self, uri):
                self.in_flight += 1
                self.max_in_flight = max(
                    self.max_in_flight,
                    self.in_flight,
                )
                await asyncio.sleep(0.02)
                self.in_flight -= 1
                if uri == "https://example.test/hub":
                    return {
                        "allOf": [{"$ref": child} for child in child_uris],
                    }
                return {"type": "integer"}

        loader = DynamicLoader()
        run(prepare_registry(
            {"$ref": "https://example.test/hub"},
            loader,
            max_concurrency=2,
            allowed_targets=("https://example.test/",),
        ))
        self.assertEqual(loader.max_in_flight, 2)

    def test_resource_and_byte_limits_are_enforced(self):
        root = {
            "$id": "https://example.test/root",
            "allOf": [
                {"$ref": "https://example.test/a"},
                {"$ref": "https://example.test/b"},
            ],
        }
        loader = RecordingLoader({
            "https://example.test/a": {"type": "integer"},
            "https://example.test/b": {"type": "integer"},
        })

        with self.assertRaises(ResourceLimitExceeded):
            run(prepare_registry(
                root,
                loader,
                max_resources=1,
                allowed_targets=("https://example.test/",),
            ))

        with self.assertRaises(ByteLimitExceeded):
            run(prepare_registry(
                root,
                loader,
                max_resources=None,
                max_bytes=10,
                allowed_targets=("https://example.test/",),
            ))

    def test_disallowed_scheme_and_target_are_rejected(self):
        loader = RecordingLoader({})

        with self.assertRaises(DisallowedURI):
            run(prepare_registry(
                {"$ref": "ftp://example.test/schema"},
                loader,
                allowed_targets=("ftp://example.test/",),
            ))

        with self.assertRaises(DisallowedURI):
            run(prepare_registry(
                {"$ref": "https://evil.test/schema"},
                loader,
                allowed_targets=("https://example.test/",),
            ))

        self.assertEqual(loader.calls, [])

    def test_failed_loader_stops_without_publishing_registry(self):
        called = []

        async def loader(uri):
            called.append(uri)
            if uri == "https://example.test/good":
                return schemas[uri]
            if uri.endswith("bad"):
                raise RuntimeError("boom")
            return {"type": "integer"}

        root = {
            "$id": "https://example.test/root",
            "$ref": "https://example.test/good",
        }
        schemas = {
            "https://example.test/good": {
                "allOf": [
                    {"$ref": "https://example.test/bad"},
                    {"$ref": "https://example.test/later"},
                ],
            },
        }

        with self.assertRaisesRegex(RuntimeError, "boom"):
            run(prepare_registry(
                root,
                loader,
                max_concurrency=1,
                allowed_targets=("https://example.test/",),
            ))

        self.assertEqual(
            called,
            ["https://example.test/good", "https://example.test/bad"],
        )

    def test_timeout_cancels_loader(self):
        async def loader(uri):
            await asyncio.Event().wait()

        with self.assertRaises(TimeoutError):
            run(prepare_registry(
                {"$ref": "https://example.test/hanging"},
                loader,
                timeout=0.01,
                allowed_targets=("https://example.test/",),
            ))

    def test_external_cancellation_cancels_loader(self):
        run(self.cancel_from_outside())

    async def cancel_from_outside(self):
        entered = asyncio.Event()

        async def loader(uri):
            entered.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(prepare_registry(
            {"$ref": "https://example.test/hanging"},
            loader,
            timeout=None,
            allowed_targets=("https://example.test/",),
        ))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    def test_loader_can_report_explicit_byte_count(self):
        async def loader(uri):
            return LoadedSchema({"type": "integer"}, num_bytes=99)

        with self.assertRaises(ByteLimitExceeded):
            run(prepare_registry(
                {"$ref": "https://example.test/large"},
                loader,
                max_bytes=10,
                allowed_targets=("https://example.test/",),
            ))

    def test_validation_never_calls_loader(self):
        async def loader(uri):
            raise AssertionError("validation must not call the loader")

        registry = run(prepare_registry(
            {"$id": "https://example.test/root"},
            loader,
            allowed_targets=("https://example.test/",),
        ))
        validator = Draft202012Validator(
            {"$ref": "https://example.test/missing"},
            registry=registry,
        )

        with self.assertRaises(Exception):
            validator.validate(1)

    def test_bytes_response_is_decoded(self):
        async def loader(uri):
            return json.dumps({"type": "integer"}).encode()

        registry = run(prepare_registry(
            {"$ref": "https://example.test/child"},
            loader,
            allowed_targets=("https://example.test/",),
        ))

        validator = Draft202012Validator(
            {"$ref": "https://example.test/child"},
            registry=registry,
        )
        validator.validate(3)

    def test_fetch_alias_and_internal_id_are_both_available(self):
        async def loader(uri):
            self.assertEqual(uri, "https://example.test/fetched")
            return {
                "$id": "https://cdn.example.test/canonical",
                "type": "integer",
            }

        registry = run(prepare_registry(
            {"$ref": "https://example.test/fetched"},
            loader,
            allowed_targets=(
                "https://example.test/",
                "https://cdn.example.test/",
            ),
        ))

        for uri in (
            "https://example.test/fetched",
            "https://cdn.example.test/canonical",
        ):
            validator = Draft202012Validator(
                {"$ref": uri},
                registry=registry,
            )
            validator.validate(4)

    def test_relative_reference_uses_nested_resource_id(self):
        async def loader(uri):
            calls.append(uri)
            return {"type": "integer"}

        calls = []
        root = {
            "$id": "https://example.test/v1/root.json",
            "$defs": {
                "nested": {
                    "$id": "../v2/nested.json",
                    "$ref": "leaf.json",
                },
            },
        }

        run(prepare_registry(
            root,
            loader,
            allowed_targets=(
                "https://example.test/v1/",
                "https://example.test/v2/",
            ),
        ))

        self.assertEqual(calls, ["https://example.test/v2/leaf.json"])
