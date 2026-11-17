import threading
from unittest import TestCase
from unittest.mock import Mock

from lib.connection.response import NativeResponse
from lib.controller.controller import Controller
from lib.controller.run_resources import RunResources
from lib.core.discovery_config import DiscoveryConfig
from lib.core.option_defaults import default_options
from lib.core.run_config import RunConfig
from lib.core.scan_run_state import ScanRunState
from lib.core.target_progress import TargetProgress


def make_controller(**discovery_overrides):
    options = default_options()
    options.update(
        {
            "skip_on_status": set(),
            "full_url": False,
            "recursion_status_codes": {301},
            "recursive": True,
            "deep_recursive": False,
            "force_recursive": False,
            "replay_proxy": None,
            "crawl": False,
            "find_backup": False,
            "exclude_subdirs": [],
            "recursion_depth": 0,
        }
    )
    options.update(discovery_overrides)

    controller = object.__new__(Controller)
    controller._options = options
    controller.resources = RunResources(interface=Mock(), logger=Mock())
    controller.config = RunConfig(
        discovery=DiscoveryConfig.from_options(options)
    )
    controller.run_state = ScanRunState()
    controller.target_progress = TargetProgress()
    controller._operation_lock = threading.Lock()
    controller.target_progress.url = "https://example.test/"
    controller.target_progress.base_path = ""
    return controller


def redirect_response(url: str, location: str) -> NativeResponse:
    return NativeResponse(url, 301, [("Location", location)], b"")


class TestAddDirectoryCanonicalDedup(TestCase):
    def setUp(self):
        self.controller = make_controller()

    def test_trailing_slash_variants_dedup(self):
        self.controller.add_directory("admin/")
        self.controller.add_directory("admin")
        self.controller.add_directory("admin//")

        self.assertEqual(self.controller.target_progress.directories, ["admin/"])
        self.assertEqual(
            self.controller.run_state.passed_urls,
            {"https://example.test/admin"},
        )

    def test_case_variants_dedup(self):
        self.controller.add_directory("Admin/Users/")
        self.controller.add_directory("admin/users/")
        self.controller.add_directory("ADMIN/USERS/")

        self.assertEqual(
            self.controller.target_progress.directories, ["Admin/Users/"]
        )

    def test_percent_encoding_variants_dedup(self):
        self.controller.add_directory("%61dmin/")
        self.controller.add_directory("admin/")
        self.controller.add_directory("%61%64min/")

        self.assertEqual(
            self.controller.target_progress.directories, ["%61dmin/"]
        )

    def test_encoded_separator_stays_a_distinct_resource(self):
        self.controller.add_directory("a%2Fb/")
        self.controller.add_directory("a/b/")

        self.assertEqual(
            self.controller.target_progress.directories, ["a%2Fb/", "a/b/"]
        )

    def test_recursion_depth_still_limits_canonical_directories(self):
        controller = make_controller(recursion_depth=1)
        controller.target_progress.base_path = "base/"

        controller.add_directory("base/child/")
        controller.add_directory("base/child/deeper/")

        self.assertEqual(
            controller.target_progress.directories, ["base/child/"]
        )

    def test_excluded_subdirs_are_checked_before_dedup(self):
        controller = make_controller(exclude_subdirs=["private/"])

        controller.add_directory("private/")
        controller.add_directory("Private/")

        self.assertEqual(controller.target_progress.directories, [])


class TestRedirectLocationCanonicalDedup(TestCase):
    def setUp(self):
        self.controller = make_controller()

    def queued(self, url: str, location: str) -> list[str]:
        self.controller.target_progress.directories = []
        self.controller.run_state.passed_urls = set()
        self.controller.match_callback(redirect_response(url, location))
        return self.controller.target_progress.directories

    def test_slash_redirect_recurs_when_canonically_equivalent(self):
        # Non-canonical Location variants of the same directory still recur.
        # The queue keeps the Location spelling; only the dedup key is
        # canonical, so each distinct spelling enqueues at most one directory.
        cases = {
            "/admin/": "admin/",
            "/%61dmin/": "%61dmin/",
            "/ADMIN/": "ADMIN/",
            "admin/": "admin/",
            "https://example.test/admin/": "admin/",
            "https://EXAMPLE.TEST:443/admin/": "admin/",
        }
        for location, expected in cases.items():
            with self.subTest(location=location):
                self.assertEqual(
                    self.queued("https://example.test/admin", location),
                    [expected],
                )

    def test_redirect_to_a_different_resource_does_not_recur(self):
        for location in ("/other/", "https://other.test/admin/"):
            with self.subTest(location=location):
                self.assertEqual(
                    self.queued("https://example.test/admin", location), []
                )

    def test_redirect_variants_dedup_against_already_queued_directory(self):
        first = self.queued("https://example.test/admin", "/admin/")
        self.assertEqual(first, ["admin/"])

        # A second response whose Location only differs by case/encoding must
        # not enqueue the same recursive directory again.
        self.controller.match_callback(
            redirect_response(
                "https://example.test/admin", "/%61dmin/"
            )
        )
        self.assertEqual(
            self.controller.target_progress.directories, ["admin/"]
        )
        self.assertEqual(
            self.controller.run_state.passed_urls,
            {"https://example.test/admin"},
        )
