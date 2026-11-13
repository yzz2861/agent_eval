#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import importlib
import logging
import types

from bandit.core import blacklisting
from bandit.core import extension_loader
from bandit.core import rule_set

LOG = logging.getLogger(__name__)


class _PluginWrapper:
    """Minimal stand-in for a stevedore extension with a copied plugin."""

    def __init__(self, name, plugin):
        self.name = name
        self.plugin = plugin


def _copy_plugin_function(original):
    """Return an isolated copy of a plugin function and its attributes."""
    plugin = types.FunctionType(
        original.__code__,
        original.__globals__,
        original.__name__,
        original.__defaults__,
        original.__closure__,
    )
    plugin.__dict__.update(original.__dict__)
    return plugin


class BanditTestSet:
    def __init__(self, config, profile=None, cli_overrides=None):
        if not profile:
            profile = {}
        extman = extension_loader.MANAGER
        self.rule_resolver = self._build_rule_resolver(
            config, profile, cli_overrides
        )
        filtering = self._get_filter(config, profile)
        self.plugins = [
            self._wrap_plugin(p)
            for p in extman.plugins
            if p.plugin._test_id in filtering
        ]
        self.plugins.extend(self._load_builtins(filtering, profile))
        self._load_tests(config, self.plugins)

    @staticmethod
    def _build_rule_resolver(config, profile, cli_overrides):
        """Build the resolver from the three documented config layers."""
        strict = bool(config.get_option("strict"))
        repository = config.get_option("rule_overrides")
        profile_overrides = profile.get("rule_overrides")
        return rule_set.RuleResolver(
            repository=repository,
            profile=profile_overrides,
            command_line=cli_overrides,
            strict=strict,
        )

    @staticmethod
    def _wrap_plugin(extension):
        """Return a per-test-set view of a plugin.

        Plugin functions carry mutable attributes (``_config`` in particular)
        which used to be written onto the shared, globally loaded function.
        Copying the function keeps every :class:`BanditTestSet` (and therefore
        every :class:`~bandit.core.manager.BanditManager`) isolated.
        """
        original = extension.plugin
        return _PluginWrapper(extension.name, _copy_plugin_function(original))

    @staticmethod
    def _get_filter(config, profile):
        extman = extension_loader.MANAGER

        inc = set(profile.get("include", []))
        exc = set(profile.get("exclude", []))

        all_blacklist_tests = set()
        for _, tests in extman.blacklist.items():
            all_blacklist_tests.update(t["id"] for t in tests)

        # this block is purely for backwards compatibility, the rules are as
        # follows:
        # B001,B401 means B401
        # B401 means B401
        # B001 means all blacklist tests
        if "B001" in inc:
            if not inc.intersection(all_blacklist_tests):
                inc.update(all_blacklist_tests)
            inc.discard("B001")
        if "B001" in exc:
            if not exc.intersection(all_blacklist_tests):
                exc.update(all_blacklist_tests)
            exc.discard("B001")

        if inc:
            filtered = inc
        else:
            filtered = set(extman.plugins_by_id.keys())
            filtered.update(extman.builtin)
            filtered.update(all_blacklist_tests)
        return filtered - exc

    def _load_builtins(self, filtering, profile):
        """loads up builtin functions, so they can be filtered."""
        extman = extension_loader.MANAGER
        blacklist = profile.get("blacklist")
        if not blacklist:  # not overridden by legacy data
            blacklist = {}
            for node, tests in extman.blacklist.items():
                values = [t for t in tests if t["id"] in filtering]
                if values:
                    blacklist[node] = values

        if not blacklist:
            return []

        # Dress a *copy* of the blacklist function up as a plugin.  Copying
        # avoids mutating the shared module-level function and keeps separate
        # BanditManager instances from observing each other's blacklist data.
        plugin = _copy_plugin_function(blacklisting.blacklist)
        plugin._test_id = "B001"
        plugin._checks = list(blacklist.keys())
        plugin._config = blacklist
        return [_PluginWrapper("blacklist", plugin)]

    def _load_tests(self, config, plugins):
        """Builds a dict mapping tests to node types."""
        self.tests = {}
        for plugin in plugins:
            if hasattr(plugin.plugin, "_takes_config"):
                # TODO(??): config could come from profile ...
                cfg = config.get_option(plugin.plugin._takes_config)
                if cfg is None:
                    genner = importlib.import_module(plugin.plugin.__module__)
                    cfg = genner.gen_config(plugin.plugin._takes_config)
                plugin.plugin._config = cfg
            for check in plugin.plugin._checks:
                self.tests.setdefault(check, []).append(plugin.plugin)
                LOG.debug(
                    "added function %s (%s) targeting %s",
                    plugin.name,
                    plugin.plugin._test_id,
                    check,
                )

    def get_tests(self, checktype):
        """Returns all tests that are of type checktype

        :param checktype: The type of test to filter on
        :return: A list of tests which are of the specified type
        """
        return self.tests.get(checktype) or []
