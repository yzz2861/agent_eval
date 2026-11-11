import asyncio
import threading
import unittest

from secure import (
    CustomHeader,
    PolicyEntry,
    PolicyLayer,
    PolicyResolver,
    Secure,
)


class _Response:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}

    def set_header(self, key: str, value: str) -> None:
        self.headers[key] = value


class TestSecureLayeredAPI(unittest.TestCase):
    def test_from_layers_drives_headers_and_response(self) -> None:
        secure = Secure.from_layers(
            [
                PolicyLayer.from_headers("default", 10, [CustomHeader("X-A", "1")]),
                PolicyLayer.from_headers("route", 20, [CustomHeader("X-B", "2")]),
            ]
        )

        self.assertEqual(secure.header_items(), (("X-A", "1"), ("X-B", "2")))
        self.assertEqual(dict(secure.headers), {"X-A": "1", "X-B": "2"})
        self.assertIn("X-A: 1", str(secure))

        response = _Response()
        secure.set_headers(response)
        self.assertEqual(response.headers, {"X-A": "1", "X-B": "2"})

    def test_hsts_duplicate_uses_highest_priority_not_last_loaded(self) -> None:
        secure = Secure.from_layers(
            [
                PolicyLayer.from_headers(
                    "route",
                    30,
                    [CustomHeader("Strict-Transport-Security", "max-age=31536000")],
                ),
                PolicyLayer.from_headers(
                    "tenant",
                    20,
                    [CustomHeader("Strict-Transport-Security", "max-age=60")],
                ),
            ]
        )

        self.assertEqual(secure.headers["Strict-Transport-Security"], "max-age=31536000")

    def test_deny_layer_removes_header_from_response(self) -> None:
        secure = Secure.from_layers(
            [
                PolicyLayer.from_headers("default", 10, [CustomHeader("Server", "disclosed")]),
                PolicyLayer("tenant", 20, (PolicyEntry.deny("Server"),)),
            ]
        )

        response = _Response()
        secure.set_headers(response)
        self.assertNotIn("Server", response.headers)

    def test_async_response_uses_resolved_snapshot(self) -> None:
        secure = Secure.from_layers([PolicyLayer.from_headers("default", 10, [CustomHeader("X-Async", "ok")])])
        response = _Response()

        asyncio.run(secure.set_headers_async(response))

        self.assertEqual(response.headers, {"X-Async": "ok"})

    def test_snapshot_is_immune_to_source_builder_mutation(self) -> None:
        header = CustomHeader("X-Mutable", "before")
        secure = Secure.from_layers([PolicyLayer.from_headers("default", 10, [header])])

        header.set("after")

        self.assertEqual(secure.headers["X-Mutable"], "before")

    def test_reload_swaps_snapshot_atomically(self) -> None:
        secure = Secure.from_layers([PolicyLayer.from_headers("default", 10, [CustomHeader("X-Version", "v1")])])
        old_snapshot = secure.resolved_policy

        new_snapshot = secure.reload_layers(
            [PolicyLayer.from_headers("default", 10, [CustomHeader("X-Version", "v2")])]
        )

        self.assertIsNot(old_snapshot, new_snapshot)
        self.assertEqual(dict(old_snapshot.headers), {"X-Version": "v1"})
        self.assertEqual(secure.headers["X-Version"], "v2")

    def test_concurrent_reload_requests_see_complete_old_or_new_snapshot(self) -> None:
        secure = Secure.from_layers([PolicyLayer.from_headers("default", 10, [CustomHeader("X-Version", "v1")])])
        observed: set[str] = set()
        start = threading.Barrier(4)
        iterations = 500

        def reload_worker() -> None:
            start.wait()
            for index in range(iterations):
                version = f"v{2 + index % 3}"
                secure.reload_layers([PolicyLayer.from_headers("default", 10, [CustomHeader("X-Version", version)])])

        def read_worker() -> None:
            start.wait()
            for _ in range(iterations):
                snapshot = secure.resolved_policy
                values = [value for _name, value in snapshot.header_items]
                observed.update(values)
                self.assertEqual(len(values), 1)

        workers = [threading.Thread(target=reload_worker) for _ in range(2)]
        workers.extend(threading.Thread(target=read_worker) for _ in range(2))
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive())

        self.assertIn("v1", observed)
        self.assertTrue(observed & {"v2", "v3", "v4"})

    def test_headers_list_mutation_falls_back_to_classic_pipeline(self) -> None:
        secure = Secure.from_layers([PolicyLayer.from_headers("default", 10, [CustomHeader("X-Layered", "yes")])])

        secure.headers_list.append(CustomHeader("X-Classic", "yes"))

        self.assertIsNone(secure.resolved_policy)
        self.assertEqual(secure.headers["X-Classic"], "yes")
        response = _Response()
        secure.set_headers(response)
        self.assertEqual(response.headers["X-Classic"], "yes")

    def test_existing_chainable_api_still_works_alongside_layers(self) -> None:
        secure = Secure(custom=[CustomHeader("X-Not-Allowed", "value")])
        secure.allowlist_headers(
            allowed=frozenset({"x-allowed"}),
            on_unexpected="drop",
        )
        secure.headers_list.append(CustomHeader("X-Allowed", "value"))
        secure.validate_and_normalize_headers()

        response = _Response()
        secure.set_headers(response)
        self.assertEqual(response.headers, {"X-Allowed": "value"})

        secure.apply_layers(
            [PolicyLayer.from_headers("default", 10, [CustomHeader("X-Reloaded", "value")])],
            resolver=PolicyResolver(),
        )
        response = _Response()
        secure.set_headers(response)
        self.assertEqual(response.headers, {"X-Reloaded": "value"})

    def test_resolved_policy_property_reflects_installed_snapshot(self) -> None:
        secure = Secure()
        self.assertIsNone(secure.resolved_policy)

        snapshot = secure.apply_layers([PolicyLayer.from_headers("default", 10, [CustomHeader("X-A", "1")])])

        self.assertIs(secure.resolved_policy, snapshot)


if __name__ == "__main__":
    unittest.main()
