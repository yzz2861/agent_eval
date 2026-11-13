#
# Copyright (c) 2016 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
from unittest import mock

import testtools
from stevedore import extension

from bandit.blacklists import utils
from bandit.core import extension_loader
from bandit.core import issue
from bandit.core import rule_set
from bandit.core import test_properties as test
from bandit.core import test_set


@test.checks("Str")
@test.test_id("B000")
def test_plugin():
    sets = []
    sets.append(
        utils.build_conf_dict(
            "telnet",
            "B401",
            issue.Cwe.CLEARTEXT_TRANSMISSION,
            ["telnetlib"],
            "A telnet-related module is being imported.  Telnet is "
            "considered insecure. Use SSH or some other encrypted protocol.",
            "HIGH",
        )
    )

    sets.append(
        utils.build_conf_dict(
            "marshal",
            "B302",
            issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
            ["marshal.load", "marshal.loads"],
            "Deserialization with the marshal module is possibly dangerous.",
        )
    )

    return {"Import": sets, "ImportFrom": sets, "Call": sets}


class BanditTestSetTests(testtools.TestCase):
    def _make_test_manager(self, plugin):
        return extension.ExtensionManager.make_test_instance(
            [extension.Extension("test_plugin", None, test_plugin, None)]
        )

    def setUp(self):
        super().setUp()
        mngr = self._make_test_manager(mock.Mock)
        self.patchExtMan = mock.patch("stevedore.extension.ExtensionManager")
        self.mockExtMan = self.patchExtMan.start()
        self.mockExtMan.return_value = mngr
        self.old_ext_man = extension_loader.MANAGER
        extension_loader.MANAGER = extension_loader.Manager()
        self.config = mock.MagicMock()
        self.config.get_setting.return_value = None
        self.config.get_option.return_value = None

    def tearDown(self):
        self.patchExtMan.stop()
        super().tearDown()
        extension_loader.MANAGER = self.old_ext_man

    def test_has_defaults(self):
        ts = test_set.BanditTestSet(self.config)
        self.assertEqual(1, len(ts.get_tests("Str")))

    def test_profile_include_id(self):
        profile = {"include": ["B000"]}
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(1, len(ts.get_tests("Str")))

    def test_profile_exclude_id(self):
        profile = {"exclude": ["B000"]}
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(0, len(ts.get_tests("Str")))

    def test_profile_include_none(self):
        profile = {"include": []}  # same as no include
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(1, len(ts.get_tests("Str")))

    def test_profile_exclude_none(self):
        profile = {"exclude": []}  # same as no exclude
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(1, len(ts.get_tests("Str")))

    def test_profile_has_builtin_blacklist(self):
        ts = test_set.BanditTestSet(self.config)
        self.assertEqual(1, len(ts.get_tests("Import")))
        self.assertEqual(1, len(ts.get_tests("ImportFrom")))
        self.assertEqual(1, len(ts.get_tests("Call")))

    def test_profile_exclude_builtin_blacklist(self):
        profile = {"exclude": ["B001"]}
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(0, len(ts.get_tests("Import")))
        self.assertEqual(0, len(ts.get_tests("ImportFrom")))
        self.assertEqual(0, len(ts.get_tests("Call")))

    def test_profile_exclude_builtin_blacklist_specific(self):
        profile = {"exclude": ["B302", "B401"]}
        ts = test_set.BanditTestSet(self.config, profile)
        self.assertEqual(0, len(ts.get_tests("Import")))
        self.assertEqual(0, len(ts.get_tests("ImportFrom")))
        self.assertEqual(0, len(ts.get_tests("Call")))

    def test_profile_filter_blacklist_none(self):
        ts = test_set.BanditTestSet(self.config)
        blacklist = ts.get_tests("Import")[0]

        self.assertEqual(2, len(blacklist._config["Import"]))
        self.assertEqual(2, len(blacklist._config["ImportFrom"]))
        self.assertEqual(2, len(blacklist._config["Call"]))

    def test_profile_filter_blacklist_one(self):
        profile = {"exclude": ["B401"]}
        ts = test_set.BanditTestSet(self.config, profile)
        blacklist = ts.get_tests("Import")[0]

        self.assertEqual(1, len(blacklist._config["Import"]))
        self.assertEqual(1, len(blacklist._config["ImportFrom"]))
        self.assertEqual(1, len(blacklist._config["Call"]))

    def test_profile_filter_blacklist_include(self):
        profile = {"include": ["B001", "B401"]}
        ts = test_set.BanditTestSet(self.config, profile)
        blacklist = ts.get_tests("Import")[0]

        self.assertEqual(1, len(blacklist._config["Import"]))
        self.assertEqual(1, len(blacklist._config["ImportFrom"]))
        self.assertEqual(1, len(blacklist._config["Call"]))

    def test_profile_filter_blacklist_all(self):
        profile = {"exclude": ["B401", "B302"]}
        ts = test_set.BanditTestSet(self.config, profile)

        # if there is no blacklist data for a node type then we wont add a
        # blacklist test to it, as this would be pointless.
        self.assertEqual(0, len(ts.get_tests("Import")))
        self.assertEqual(0, len(ts.get_tests("ImportFrom")))
        self.assertEqual(0, len(ts.get_tests("Call")))

    def test_profile_blacklist_compat(self):
        data = [
            utils.build_conf_dict(
                "marshal",
                "B302",
                issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
                ["marshal.load", "marshal.loads"],
                (
                    "Deserialization with the marshal module is possibly "
                    "dangerous."
                ),
            )
        ]

        profile = {"include": ["B001"], "blacklist": {"Call": data}}

        ts = test_set.BanditTestSet(self.config, profile)
        blacklist = ts.get_tests("Call")[0]

        self.assertNotIn("Import", blacklist._config)
        self.assertNotIn("ImportFrom", blacklist._config)
        self.assertEqual(1, len(blacklist._config["Call"]))

    def test_rule_resolver_attached(self):
        ts = test_set.BanditTestSet(self.config)
        self.assertIsInstance(ts.rule_resolver, rule_set.RuleResolver)

    def test_rule_resolver_uses_profile_and_cli_layers(self):
        profile = {
            "include": [],
            "rule_overrides": {"B000": {"severity": "HIGH"}},
        }
        cli = {"B000": {"severity": "LOW"}}
        ts = test_set.BanditTestSet(self.config, profile, cli_overrides=cli)
        # CLI overrides the profile layer.
        self.assertEqual(
            "LOW", ts.rule_resolver.get_override("B000")["severity"]
        )

    def test_plugin_state_is_not_shared_between_test_sets(self):
        first = test_set.BanditTestSet(self.config)
        second = test_set.BanditTestSet(self.config)
        first_plugin = first.get_tests("Str")[0]
        second_plugin = second.get_tests("Str")[0]

        self.assertIsNot(first_plugin, second_plugin)
        first_plugin._isolation_marker = True
        self.assertFalse(hasattr(second_plugin, "_isolation_marker"))

    def test_blacklist_state_is_not_shared_between_test_sets(self):
        first = test_set.BanditTestSet(self.config)
        second = test_set.BanditTestSet(self.config)
        first_blacklist = first.get_tests("Call")[0]
        second_blacklist = second.get_tests("Call")[0]

        self.assertIsNot(first_blacklist, second_blacklist)
        first_blacklist._isolation_marker = True
        self.assertFalse(hasattr(second_blacklist, "_isolation_marker"))

    def test_strict_wildcard_conflict_raises_when_building_test_set(self):
        strict_config = mock.MagicMock()
        strict_config.get_setting.return_value = None
        strict_config.get_option.side_effect = lambda key: (
            True if key == "strict" else None
        )
        profile = {
            "include": [],
            "rule_overrides": {
                "B*": {"severity": "LOW"},
                "B0*": {"severity": "HIGH"},
            },
        }
        self.assertRaises(
            rule_set.RuleConfigError,
            test_set.BanditTestSet,
            strict_config,
            profile,
        )
