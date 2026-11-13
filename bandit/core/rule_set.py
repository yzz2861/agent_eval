# SPDX-License-Identifier: Apache-2.0
r"""Deterministic rule resolution for severity and confidence overrides.

This module is the single source of truth for deciding which severity and
confidence a finding receives.  Three layers can contribute overrides and
they are merged in a fixed, documented order:

1. explicit test id overrides always win over wildcard (``B*`` style)
   overrides;
2. a named profile overrides repository default (top level) overrides;
3. command line overrides override everything coming from a config file.

The plugin defaults (the values shipped with each plugin / blacklist entry)
sit below every configurable layer.
"""
import fnmatch
import logging

from bandit.core import constants
from bandit.core import extension_loader

LOG = logging.getLogger(__name__)

#: keys accepted inside a single override mapping
OVERRIDE_KEYS = frozenset(("severity", "confidence"))

#: Warnings already emitted in this process, kept quiet on repeat.
_WARNED = set()


def _warn_once(message):
    if message not in _WARNED:
        _WARNED.add(message)
        LOG.warning(message)


class RuleConfigError(ValueError):
    """Raised when rule configuration is invalid in strict mode."""


def is_valid_level(value):
    """Return True if *value* is a usable severity/confidence enum value."""
    return isinstance(value, str) and value in constants.RANKING


def _normalise_overrides(raw, source, strict):
    """Validate *raw* override data and return a clean mapping.

    A mapping of test_id -> {"severity": ..., "confidence": ...} or the
    equivalent wildcard form is expected.  Invalid enum values and unknown
    test ids raise :class:`RuleConfigError` in strict mode and are skipped
    with a warning otherwise.
    """
    normalised = {}
    if raw is None:
        return normalised
    if not isinstance(raw, dict):
        message = (
            f"rule overrides from {source} must be a mapping, got "
            f"{type(raw).__name__}"
        )
        if strict:
            raise RuleConfigError(message)
        _warn_once(message)
        return normalised

    extman = extension_loader.MANAGER
    for test_id, override in raw.items():
        if not isinstance(test_id, str):
            message = f"rule override key from {source} must be a string"
            if strict:
                raise RuleConfigError(message)
            _warn_once(message)
            continue

        if not isinstance(override, dict):
            message = (
                f"rule override for '{test_id}' from {source} must be a "
                f"mapping, got {type(override).__name__}"
            )
            if strict:
                raise RuleConfigError(message)
            _warn_once(message)
            continue

        unknown_keys = set(override) - OVERRIDE_KEYS
        if unknown_keys:
            message = (
                f"rule override for '{test_id}' from {source} contains "
                f"unknown keys {sorted(unknown_keys)}"
            )
            if strict:
                raise RuleConfigError(message)
            _warn_once(message)

        clean = {}
        for key in OVERRIDE_KEYS:
            if key not in override or override[key] is None:
                continue
            value = override[key]
            if not is_valid_level(value):
                message = (
                    f"invalid {key} '{value}' for test '{test_id}' from "
                    f"{source}; expected one of {constants.RANKING[1:]}"
                )
                if strict:
                    raise RuleConfigError(message)
                _warn_once(message)
                continue
            clean[key] = value

        if not clean:
            continue

        is_wildcard = any(ch in test_id for ch in "*?[]")
        if not is_wildcard and not extman.check_id(test_id):
            message = (
                f"unknown test id '{test_id}' in rule overrides from "
                f"{source}"
            )
            if strict:
                raise RuleConfigError(message)
            _warn_once(message)
            continue

        normalised[test_id] = clean
    return normalised


class RuleResolver:
    """Resolve the effective severity/confidence for every finding.

    Override layers are merged deterministically.  Within a layer an exact
    test id takes precedence over a wildcard pattern; across layers command
    line overrides take precedence over profile overrides, which themselves
    take precedence over repository (top level config) overrides.
    """

    def __init__(
        self,
        repository=None,
        profile=None,
        command_line=None,
        strict=False,
    ):
        self.strict = strict
        self._layers = [
            _normalise_overrides(repository, "config file", strict),
            _normalise_overrides(profile, "profile", strict),
            _normalise_overrides(command_line, "command line", strict),
        ]
        self._wildcards = []
        self._layer_names = (
            "repository default",
            "profile",
            "command line",
        )
        for layer in self._layers:
            for test_id, override in layer.items():
                if any(ch in test_id for ch in "*?[]"):
                    self._wildcards.append((test_id, override))
        # Deterministic ordering independent of plugin/dict insertion order.
        self._wildcards.sort(key=lambda item: item[0])
        self._build_resolution_table()
        if strict:
            self._check_wildcard_conflicts()

    def _build_resolution_table(self):
        """Pre-compute the winning override for every known test id.

        Precedence, highest first:

        1. command line explicit test id, then profile, then repository;
        2. command line wildcard, then profile wildcard, then repository
           wildcard.
        """
        extman = extension_loader.MANAGER
        known_ids = set(extman.plugins_by_id)
        known_ids.update(extman.blacklist_by_id)
        known_ids.update(extman.builtin)

        self._resolution = {}
        for test_id in known_ids:
            winner = self._resolve(test_id)
            if winner is not None:
                self._resolution[test_id] = winner

    def _resolve(self, test_id):
        # Explicit ids always outrank wildcard patterns.
        for layer_index in (2, 1, 0):
            override = self._layers[layer_index].get(test_id)
            if override is not None:
                return dict(override), "exact", layer_index
        for layer_index in (2, 1, 0):
            for pattern, override in self._wildcards:
                # Only wildcards belonging to this layer count here.
                if pattern not in self._layers[layer_index]:
                    continue
                if fnmatch.fnmatchcase(test_id, pattern):
                    return dict(override), pattern, layer_index
        return None

    def _check_wildcard_conflicts(self):
        """Fail on ambiguous wildcard rules inside a single layer.

        Overlaps between layers are resolved deterministically by the
        documented layer precedence (command line > profile > repository),
        so only wildcard patterns living in the same layer can be
        ambiguous: within a layer no precedence between two patterns is
        defined.  An explicit test id override always wins, so ids covered
        by an exact override are not considered ambiguous.
        """
        extman = extension_loader.MANAGER
        known_ids = set(extman.plugins_by_id)
        known_ids.update(extman.blacklist_by_id)
        known_ids.update(extman.builtin)

        for layer in self._layers:
            patterns = sorted(
                test_id
                for test_id in layer
                if any(ch in test_id for ch in "*?[]")
            )
            for index, left in enumerate(patterns):
                left_values = layer[left]
                for right in patterns[index + 1:]:
                    right_values = layer[right]
                    if left_values == right_values:
                        continue
                    ambiguous = sorted(
                        test_id
                        for test_id in known_ids
                        if fnmatch.fnmatchcase(test_id, left)
                        and fnmatch.fnmatchcase(test_id, right)
                        and self._resolve(test_id)[1] != "exact"
                    )
                    if ambiguous:
                        raise RuleConfigError(
                            f"conflicting wildcard rule overrides "
                            f"'{left}' and '{right}' both match test(s) "
                            f"{ambiguous} with different "
                            "severity/confidence values"
                        )

    def get_override(self, test_id):
        """Return the merged override applicable to *test_id*."""
        resolved = self._resolution.get(test_id) or self._resolve(test_id)
        if resolved is None:
            return {}
        return resolved[0]

    def apply(self, issue_obj):
        """Apply the resolved override to a finding in place.

        Every change is logged at debug level together with the reason so
        that findings dropped by a threshold remain explainable when
        debugging a scan.
        """
        resolved = self._resolution.get(issue_obj.test_id)
        if resolved is None:
            return issue_obj
        override, match, layer_index = resolved
        for key, attribute in (
            ("severity", "severity"),
            ("confidence", "confidence"),
        ):
            if key not in override:
                continue
            new_value = override[key]
            old_value = getattr(issue_obj, attribute)
            if old_value == new_value:
                continue
            source = self._layer_names[layer_index]
            if match == "exact":
                reason = (
                    f"explicit test id override for "
                    f"{issue_obj.test_id} from {source}"
                )
            else:
                reason = (
                    f"wildcard override '{match}' from {source} for "
                    f"{issue_obj.test_id}"
                )
            LOG.debug(
                "rule override: %s %s changed from %s to %s (%s)",
                issue_obj.test_id,
                attribute,
                old_value,
                new_value,
                reason,
            )
            setattr(issue_obj, attribute, new_value)
        return issue_obj
