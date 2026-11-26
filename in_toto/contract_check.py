# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Offline cross-platform path contract checks for in-toto artifact rules.

This module does not read or write build artifacts. It simulates the path
strings that a step reports on different platforms, feeds those strings through
in-toto's real artifact rule verification functions, and compares the resulting
security decisions.

The check makes the following questions explicit for acceptance testing:

* Are rules evaluated against the original recorded path or a normalized path?
* Do case, Unicode, and path-root differences change the decision?
* Which candidates exist if a platform path is ambiguous?
* Which rule's set of applicable artifacts grew between two policies?

The expected input is a JSON-compatible dictionary. See
``examples/contract-check/windows-linux-contract.json`` for a complete example.

The simulator temporarily applies the selected platform's ``os.path`` and
``fnmatch.filter`` semantics, so checks should be run from one thread at a time.
"""

import fnmatch
import hashlib
import json
import ntpath
import os
import posixpath
import shlex
import unicodedata
from collections import defaultdict
from contextlib import contextmanager
from difflib import SequenceMatcher

import in_toto.verifylib
from in_toto.exceptions import RuleVerificationError
from in_toto.models.link import Link
from in_toto.rulelib import pack_rule_data, unpack_rule
from in_toto.verifylib import (
    _filter_match_rule_artifacts,
    verify_allow_rule,
    verify_create_rule,
    verify_delete_rule,
    verify_disallow_rule,
    verify_item_rules,
    verify_match_rule,
    verify_modify_rule,
    verify_require_rule,
)

SCHEMA_VERSION = 1

_PATH_STYLES = {"posix", "windows"}
_EXPORT_STYLES = {"relative", "rooted", "dot-relative"}
_MATCH_NAMES = {"original", "normalized"}
_UNICODE_FORMS = {"none", "NFC", "NFD", "NFKC", "NFKD"}
_CASE_MODES = {"preserve", "lower", "casefold", "upper"}
_SEPARATOR_MODES = {"native", "slash"}


class ContractError(ValueError):
    """Raised for a malformed contract or an inconsistent simulation."""


def _require_mapping(value, what):
    """Return value if it is a mapping, otherwise raise ContractError."""
    if not isinstance(value, dict):
        raise ContractError(f"{what} must be an object")
    return value


def _require_str(value, what):
    """Return value if it is a non-empty string, otherwise raise."""
    if not isinstance(value, str) or not value:
        raise ContractError(f"{what} must be a non-empty string")
    return value


def _require_str_list(value, what):
    """Return a list of strings, otherwise raise."""
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ContractError(f"{what} must be a list of strings")
    return value


def _path_module(path_style):
    """Return the path module used for the platform's recorded path."""
    return ntpath if path_style == "windows" else posixpath


def _native_separator(path_style):
    """Return the platform's native path separator."""
    return "\\" if path_style == "windows" else "/"


def _record_path(path, path_style):
    """Normalize a native path the way in-toto records artifact names.

    ``FileResolver`` runs ``normpath`` on the platform and then replaces
    backslashes with forward slashes in ``_mangle``. Mirroring that here makes
    the simulated link metadata use the same path spelling as real in-toto
    metadata.
    """
    normalized = _path_module(path_style).normpath(path)
    return normalized.replace("\\", "/")


def _apply_text_normalization(value, normalization):
    """Apply Unicode, case, and separator normalization to a path string."""
    unicode_form = normalization["unicode"]
    if unicode_form != "none":
        value = unicodedata.normalize(unicode_form, value)

    case_mode = normalization["case"]
    if case_mode == "lower":
        value = value.lower()
    elif case_mode == "casefold":
        value = value.casefold()
    elif case_mode == "upper":
        value = value.upper()

    separator_mode = normalization["separator"]
    if separator_mode == "slash":
        value = value.replace("\\", "/")

    return value


def _normalize_path(path, normalization):
    """Normalize a recorded path or rule pattern under a policy."""
    normalized = _apply_text_normalization(path, normalization)

    for prefix in normalization["strip_prefixes"]:
        normalized_prefix = _apply_text_normalization(prefix, normalization)
        if normalized.startswith(normalized_prefix):
            normalized = normalized[len(normalized_prefix) :]
            break

    return normalized


def _auto_export(artifact_name, platform):
    """Build a platform path for an artifact without an explicit mapping."""
    separator = _native_separator(platform["path_style"])
    native_name = artifact_name.replace("/", separator)
    style = platform["export_style"]

    if style == "rooted":
        root = platform["root"].rstrip("/\\")
        return f"{root}{separator}{native_name}"
    if style == "dot-relative":
        return f".{separator}{native_name}"
    return native_name


def _parse_artifact(item, what):
    """Validate and normalize one material or product entry."""
    _require_mapping(item, what)
    name = _require_str(item.get("name"), f"{what}.name")

    if "hashes" in item:
        hashes = _require_mapping(item["hashes"], f"{what}.hashes")
        if not hashes or not all(
            isinstance(algorithm, str) and isinstance(digest, str)
            for algorithm, digest in hashes.items()
        ):
            raise ContractError(
                f"{what}.hashes must map algorithm names to digest strings"
            )
        hashes = dict(hashes)
    elif "sha256" in item:
        hashes = {"sha256": _require_str(item["sha256"], f"{what}.sha256")}
    elif "content" in item:
        content = item["content"]
        if not isinstance(content, str):
            raise ContractError(f"{what}.content must be a string")
        hashes = {"sha256": hashlib.sha256(content.encode()).hexdigest()}
    else:
        hashes = {"sha256": hashlib.sha256(name.encode()).hexdigest()}

    return {"name": name, "hashes": hashes}


def _parse_rule(rule, what):
    """Validate a rule and return it in list-of-strings form."""
    if isinstance(rule, str):
        rule = shlex.split(rule)
    rule = _require_str_list(rule, what)
    unpack_rule(rule)
    return list(rule)


def _parse_normalization(value, what):
    """Validate and fill defaults for a normalization policy."""
    value = _require_mapping({} if value is None else value, what)
    normalization = {
        "unicode": value.get("unicode", "none"),
        "case": value.get("case", "preserve"),
        "separator": value.get("separator", "native"),
        "strip_prefixes": _require_str_list(
            value.get("strip_prefixes", []), f"{what}.strip_prefixes"
        ),
    }

    if normalization["unicode"] not in _UNICODE_FORMS:
        raise ContractError(
            f"{what}.unicode must be one of {sorted(_UNICODE_FORMS)}"
        )
    if normalization["case"] not in _CASE_MODES:
        raise ContractError(f"{what}.case must be one of {sorted(_CASE_MODES)}")
    if normalization["separator"] not in _SEPARATOR_MODES:
        raise ContractError(
            f"{what}.separator must be one of {sorted(_SEPARATOR_MODES)}"
        )

    return normalization


def _parse_policy(value, what):
    """Validate and normalize a before/after policy."""
    value = _require_mapping(value, what)
    match_names = value.get("match_names", "original")
    if match_names not in _MATCH_NAMES:
        raise ContractError(
            f"{what}.match_names must be one of {sorted(_MATCH_NAMES)}"
        )

    rules = value.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ContractError(f"{what}.rules must be a non-empty list")

    return {
        "match_names": match_names,
        "normalization": _parse_normalization(
            value.get("normalization", {}), f"{what}.normalization"
        ),
        "rules": [
            _parse_rule(rule, f"{what}.rules[{index}]")
            for index, rule in enumerate(rules)
        ],
    }


def _parse_platform(value, index):
    """Validate and normalize a platform description."""
    what = f"platforms[{index}]"
    value = _require_mapping(value, what)
    name = _require_str(value.get("name"), f"{what}.name")
    path_style = value.get("path_style")
    if path_style not in _PATH_STYLES:
        raise ContractError(
            f"{what}.path_style must be one of {sorted(_PATH_STYLES)}"
        )

    export = value.get("export", "relative")
    root = value.get("root")
    if isinstance(export, dict):
        export = _require_mapping(export, f"{what}.export")
        root = export.get("root", root)
        export_style = export.get("style", "relative")
    else:
        export_style = export

    if export_style not in _EXPORT_STYLES:
        raise ContractError(
            f"{what}.export style must be one of {sorted(_EXPORT_STYLES)}"
        )
    if export_style == "rooted":
        root = _require_str(root, f"{what}.root")

    case_sensitive = value.get("case_sensitive", path_style != "windows")
    if not isinstance(case_sensitive, bool):
        raise ContractError(f"{what}.case_sensitive must be a boolean")

    unicode_form = value.get("unicode_normalization", "none")
    if unicode_form not in _UNICODE_FORMS:
        raise ContractError(
            f"{what}.unicode_normalization must be one of "
            f"{sorted(_UNICODE_FORMS)}"
        )

    mapping = value.get("mapping", {})
    mapping = _require_mapping(mapping, f"{what}.mapping")
    normalized_mapping = {}
    for artifact_name, paths in mapping.items():
        _require_str(artifact_name, f"{what}.mapping key")
        normalized_paths = [paths] if isinstance(paths, str) else paths
        if not normalized_paths:
            raise ContractError(
                f"{what}.mapping[{artifact_name!r}] must not be empty"
            )
        normalized_mapping[artifact_name] = _require_str_list(
            normalized_paths, f"{what}.mapping[{artifact_name!r}]"
        )

    return {
        "name": name,
        "path_style": path_style,
        "case_sensitive": case_sensitive,
        "unicode_normalization": unicode_form,
        "export_style": export_style,
        "root": root,
        "mapping": normalized_mapping,
    }


def _parse_step(value, index):
    """Validate and normalize one step/link description."""
    what = f"steps[{index}]"
    value = _require_mapping(value, what)
    name = _require_str(value.get("name"), f"{what}.name")

    step = {"name": name, "materials": [], "products": []}
    for artifact_type in ("materials", "products"):
        items = value.get(artifact_type, [])
        if not isinstance(items, list):
            raise ContractError(f"{what}.{artifact_type} must be a list")
        seen = set()
        for item_index, item in enumerate(items):
            artifact = _parse_artifact(
                item, f"{what}.{artifact_type}[{item_index}]"
            )
            if artifact["name"] in seen:
                raise ContractError(
                    f"{what}.{artifact_type} contains duplicate artifact "
                    f"{artifact['name']!r}"
                )
            seen.add(artifact["name"])
            step[artifact_type].append(artifact)

    return step


def _parse_case(value, index):
    """Validate and normalize one contract case."""
    what = f"cases[{index}]"
    value = _require_mapping(value, what)
    name = _require_str(value.get("name"), f"{what}.name")

    steps = value.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ContractError(f"{what}.steps must be a non-empty list")
    steps = [_parse_step(item, i) for i, item in enumerate(steps)]
    step_names = [step["name"] for step in steps]
    if len(step_names) != len(set(step_names)):
        raise ContractError(f"{what}.steps contains duplicate step names")

    target = _require_mapping(value.get("target"), f"{what}.target")
    target_step = _require_str(target.get("step"), f"{what}.target.step")
    target_type = target.get("type")
    if target_type not in {"materials", "products"}:
        raise ContractError(
            f"{what}.target.type must be 'materials' or 'products'"
        )
    if target_step not in step_names:
        raise ContractError(
            f"{what}.target.step {target_step!r} is not defined in steps"
        )

    policies = _require_mapping(value.get("policies"), f"{what}.policies")
    unknown_policies = set(policies) - {"before", "after"}
    if unknown_policies:
        raise ContractError(
            f"{what}.policies has unsupported entries "
            f"{sorted(unknown_policies)}; use 'before' and/or 'after'"
        )
    if not policies:
        raise ContractError(f"{what}.policies must not be empty")

    return {
        "name": name,
        "description": value.get("description", ""),
        "steps": steps,
        "target": {"step": target_step, "type": target_type},
        "policies": {
            policy_name: _parse_policy(policy, f"{what}.policies.{policy_name}")
            for policy_name, policy in policies.items()
        },
    }


def parse_contract(data):
    """Validate a contract dictionary and return it with defaults filled in.

    <Arguments>
      data:
              A JSON-compatible contract dictionary.

    <Exceptions>
      ContractError: if the contract is malformed.

    <Returns>
      A normalized contract dictionary.
    """
    data = _require_mapping(data, "contract")
    schema_version = data.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise ContractError(f"contract.schema_version must be {SCHEMA_VERSION}")

    platforms = data.get("platforms")
    if not isinstance(platforms, list) or not platforms:
        raise ContractError("contract.platforms must be a non-empty list")
    platforms = [
        _parse_platform(platform, index)
        for index, platform in enumerate(platforms)
    ]
    platform_names = [platform["name"] for platform in platforms]
    if len(platform_names) != len(set(platform_names)):
        raise ContractError("contract.platforms contains duplicate names")

    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ContractError("contract.cases must be a non-empty list")
    cases = [_parse_case(case, index) for index, case in enumerate(cases)]
    case_names = [case["name"] for case in cases]
    if len(case_names) != len(set(case_names)):
        raise ContractError("contract.cases contains duplicate names")

    return {
        "schema_version": SCHEMA_VERSION,
        "name": data.get("name", "unnamed-contract"),
        "description": data.get("description", ""),
        "platforms": platforms,
        "cases": cases,
    }


def load_contract(path):
    """Load and validate a JSON contract from a file."""
    with open(path, encoding="utf-8") as fileobj:
        return parse_contract(json.load(fileobj))


def _hash_identity(hashes):
    """Return a stable identity string for a hash dictionary."""
    return json.dumps(hashes, sort_keys=True)


def _match_fold(value, path_style):
    """Fold a path the way ``ntpath.normcase`` folds it."""
    value = value.lower()
    if path_style == "windows":
        value = value.replace("/", "\\")
    return value


def _candidate(export):
    """Return the report representation of one mapped path candidate."""
    return {
        "artifact": export["artifact"],
        "exported": export["exported"],
        "recorded": export["recorded"],
        "hashes": export["hashes"],
    }


def _ambiguity(  # noqa: PLR0913
    platform,
    policy_name,
    case_name,
    step,
    artifact_type,
    kind,
    key,
    group,
    reason,
):
    """Build an ambiguity record for a group of path exports."""
    candidates = sorted(
        (_candidate(export) for export in group),
        key=lambda item: (item["artifact"], item["exported"]),
    )
    distinct_artifacts = {candidate["artifact"] for candidate in candidates}
    distinct_hashes = {
        _hash_identity(candidate["hashes"]) for candidate in candidates
    }
    return {
        "platform": platform["name"],
        "policy": policy_name,
        "case": case_name,
        "step": step,
        "artifact_type": artifact_type,
        "kind": kind,
        "key": key,
        "blocking": len(distinct_artifacts) > 1 or len(distinct_hashes) > 1,
        "candidates": candidates,
        "reason": reason,
    }


def _collect_ambiguities(  # noqa: C901
    case, platform, policy_name, exports_by_link
):
    """Find ambiguous mappings and matcher collisions in a simulated link."""
    ambiguities = []
    seen = set()

    def add(  # noqa: PLR0913
        step, artifact_type, kind, key, group, reason
    ):
        record = _ambiguity(
            platform,
            policy_name,
            case["name"],
            step,
            artifact_type,
            kind,
            key,
            group,
            reason,
        )
        signature = (
            record["step"],
            record["artifact_type"],
            record["kind"],
            record["key"],
            tuple(
                (candidate["artifact"], candidate["exported"])
                for candidate in record["candidates"]
            ),
        )
        if signature not in seen:
            seen.add(signature)
            ambiguities.append(record)

    for (step_name, artifact_type), exports in exports_by_link.items():
        by_recorded = defaultdict(list)
        by_match_name = defaultdict(list)
        by_folded_name = defaultdict(list)
        by_artifact = defaultdict(list)

        for export in exports:
            by_recorded[export["recorded"]].append(export)
            by_match_name[export["match_name"]].append(export)
            by_folded_name[
                _match_fold(export["match_name"], platform["path_style"])
            ].append(export)
            by_artifact[export["artifact"]].append(export)

        for key, group in sorted(by_recorded.items()):
            if len({export["artifact"] for export in group}) > 1:
                add(
                    step_name,
                    artifact_type,
                    "recorded-path-collision",
                    key,
                    group,
                    "multiple canonical artifacts record the same path",
                )

        for key, group in sorted(by_match_name.items()):
            identities = {
                (export["artifact"], _hash_identity(export["hashes"]))
                for export in group
            }
            if len(identities) > 1:
                add(
                    step_name,
                    artifact_type,
                    "match-name-collision",
                    key,
                    group,
                    "normalization maps distinct artifacts to one match key",
                )

        if not platform["case_sensitive"]:
            for key, group in sorted(by_folded_name.items()):
                if len({export["artifact"] for export in group}) > 1:
                    add(
                        step_name,
                        artifact_type,
                        "case-fold-collision",
                        key,
                        group,
                        "platform case folding maps distinct artifacts to "
                        "one match key",
                    )

        for artifact_name, group in sorted(by_artifact.items()):
            if len({export["recorded"] for export in group}) > 1:
                add(
                    step_name,
                    artifact_type,
                    "multiple-exports",
                    artifact_name,
                    group,
                    "one artifact has multiple exported path spellings",
                )

    return ambiguities


def _build_links(case, platform, policy_name):  # noqa: C901
    """Build simulated links and collect path-mapping ambiguities."""
    policy = case["policies"][policy_name]
    normalization = policy["normalization"]
    exports_by_link = {}
    ambiguities = []

    for step in case["steps"]:
        for artifact_type in ("materials", "products"):
            exports = []
            for artifact in step[artifact_type]:
                mapped_paths = platform["mapping"].get(artifact["name"])
                if mapped_paths is None:
                    mapped_paths = [_auto_export(artifact["name"], platform)]

                for path in mapped_paths:
                    normalized_path = path
                    if platform["unicode_normalization"] != "none":
                        normalized_path = unicodedata.normalize(
                            platform["unicode_normalization"], path
                        )
                    recorded = _record_path(
                        normalized_path, platform["path_style"]
                    )
                    match_name = recorded
                    if policy["match_names"] == "normalized":
                        match_name = _normalize_path(recorded, normalization)
                    exports.append(
                        {
                            "artifact": artifact["name"],
                            "hashes": artifact["hashes"],
                            "step": step["name"],
                            "artifact_type": artifact_type,
                            "exported": normalized_path,
                            "recorded": recorded,
                            "match_name": match_name,
                        }
                    )

            exports_by_link[(step["name"], artifact_type)] = exports

    ambiguities = _collect_ambiguities(
        case, platform, policy_name, exports_by_link
    )

    links = {}
    for step in case["steps"]:
        artifact_dicts = {}
        for artifact_type in ("materials", "products"):
            exports = exports_by_link[(step["name"], artifact_type)]
            by_match_name = defaultdict(list)
            for export in exports:
                by_match_name[export["match_name"]].append(export)

            artifacts = {}
            for match_name, group in sorted(by_match_name.items()):
                chosen = sorted(
                    group, key=lambda item: (item["artifact"], item["exported"])
                )[0]
                artifacts[match_name] = chosen["hashes"]
            artifact_dicts[artifact_type] = artifacts

        links[step["name"]] = Link(
            name=step["name"],
            materials=artifact_dicts["materials"],
            products=artifact_dicts["products"],
        )

    return links, exports_by_link, ambiguities


@contextmanager
def _matching_semantics(path_style, case_sensitive):
    """Temporarily apply a platform's path and glob matching semantics."""
    old_path = os.path
    old_filter = fnmatch.filter

    def platform_filter(names, pattern):
        def normalize(value):
            if not case_sensitive:
                value = value.lower()
            if path_style == "windows":
                value = value.replace("/", "\\")
            return value

        normalized_pattern = normalize(pattern)
        return [
            name
            for name in names
            if fnmatch.fnmatchcase(normalize(name), normalized_pattern)
        ]

    os.path = _path_module(path_style)
    fnmatch.filter = platform_filter
    try:
        yield
    finally:
        os.path = old_path
        fnmatch.filter = old_filter


def _effective_rule(rule, policy):
    """Return the rule as the policy's matcher sees it."""
    rule_data = dict(unpack_rule(rule))
    if policy["match_names"] == "normalized":
        normalization = policy["normalization"]
        rule_data["pattern"] = _normalize_path(
            rule_data["pattern"], normalization
        )
        if rule_data.get("source_prefix"):
            rule_data["source_prefix"] = _normalize_path(
                rule_data["source_prefix"], normalization
            )
        if rule_data.get("dest_prefix"):
            rule_data["dest_prefix"] = _normalize_path(
                rule_data["dest_prefix"], normalization
            )

    return pack_rule_data(rule_data)


def _apply_rule(rule_data, artifacts_queue, context):
    """Apply one rule with in-toto's verifier and report matched artifacts."""
    rule_type = rule_data["rule_type"]
    pattern = rule_data["pattern"]
    matched = set()
    consumed = set()
    error = None

    try:
        if rule_type == "match":
            matched = {
                full_path
                for _, full_path in _filter_match_rule_artifacts(
                    rule_data, artifacts_queue
                )
            }
            consumed = verify_match_rule(
                rule_data,
                artifacts_queue,
                context["source_artifacts"],
                context["links"],
            )
        elif rule_type == "create":
            matched = set(fnmatch.filter(artifacts_queue, pattern))
            consumed = verify_create_rule(
                pattern,
                artifacts_queue,
                context["materials"],
                context["products"],
            )
        elif rule_type == "delete":
            matched = set(fnmatch.filter(artifacts_queue, pattern))
            consumed = verify_delete_rule(
                pattern,
                artifacts_queue,
                context["materials"],
                context["products"],
            )
        elif rule_type == "modify":
            matched = set(fnmatch.filter(artifacts_queue, pattern))
            consumed = verify_modify_rule(
                pattern,
                artifacts_queue,
                context["materials_dict"],
                context["products_dict"],
            )
        elif rule_type == "allow":
            matched = set(fnmatch.filter(artifacts_queue, pattern))
            consumed = verify_allow_rule(pattern, artifacts_queue)
        elif rule_type == "disallow":
            matched = set(fnmatch.filter(artifacts_queue, pattern))
            verify_disallow_rule(pattern, artifacts_queue)
        else:
            matched = {pattern} & artifacts_queue
            verify_require_rule(pattern, artifacts_queue)
    except RuleVerificationError as exception:
        error = str(exception)

    return matched, consumed, error


def _simulate_rules(case, links, effective_rules, original_rules):
    """Run artifact rules and return per-rule applicability information."""
    source_name = case["target"]["step"]
    source_type = case["target"]["type"]
    source_artifacts = getattr(links[source_name], source_type)
    context = {
        "links": links,
        "source_artifacts": source_artifacts,
        "materials": set(links[source_name].materials),
        "products": set(links[source_name].products),
        "materials_dict": links[source_name].materials,
        "products_dict": links[source_name].products,
    }
    artifacts_queue = set(source_artifacts)
    initial_queue = set(artifacts_queue)
    records = []
    passed = True
    error = None

    # Direct calls to the individual rule verifiers use this global structure
    # to build rich error messages, just like verify_item_rules does.
    in_toto.verifylib.RULE_TRACE.clear()
    in_toto.verifylib.RULE_TRACE.update(
        {
            "source_name": source_name,
            "source_type": source_type,
            "materials": list(context["materials_dict"]),
            "products": list(context["products_dict"]),
            "trace": [],
        }
    )

    for index, (rule, effective_rule) in enumerate(
        zip(original_rules, effective_rules)
    ):
        queue_before = set(artifacts_queue)
        matched, consumed, rule_error = _apply_rule(
            unpack_rule(effective_rule), artifacts_queue, context
        )
        if rule_error is not None:
            passed = False
            error = rule_error

        artifacts_queue -= consumed
        in_toto.verifylib.RULE_TRACE["trace"].append(
            {"rule": effective_rule, "queue": list(artifacts_queue)}
        )
        records.append(
            {
                "index": index,
                "rule": list(rule),
                "effective_rule": list(effective_rule),
                "matched": sorted(matched),
                "consumed": sorted(consumed),
                "queue_before": sorted(queue_before),
                "queue_after": sorted(artifacts_queue),
                "error": rule_error,
                "evaluated": True,
            }
        )

        if not passed:
            break

    try:
        verify_item_rules(source_name, source_type, effective_rules, links)
        reference_passed = True
    except RuleVerificationError:
        reference_passed = False

    if reference_passed != passed:  # pragma: no cover (defensive)
        raise ContractError(
            "internal error: per-rule simulation and verify_item_rules disagree"
        )

    return {
        "passed": passed,
        "error": error,
        "rules": records,
        "consumed": sorted(initial_queue - artifacts_queue),
        "unconsumed": sorted(artifacts_queue),
    }


def _canonical_names(names, match_name_map):
    """Map matched path names back to canonical artifact names."""
    result = set()
    for name in names:
        result.update(match_name_map.get(name, {name}))
    return sorted(result)


def _run_platform(case, platform, policy_name):
    """Simulate one case/policy on one platform."""
    policy = case["policies"][policy_name]
    links, exports_by_link, ambiguities = _build_links(
        case, platform, policy_name
    )
    effective_rules = [
        _effective_rule(rule, policy) for rule in policy["rules"]
    ]

    with _matching_semantics(
        platform["path_style"], platform["case_sensitive"]
    ):
        simulation = _simulate_rules(
            case,
            links,
            effective_rules,
            policy["rules"],
        )

    source_key = (case["target"]["step"], case["target"]["type"])
    match_name_map = defaultdict(set)
    for export in exports_by_link[source_key]:
        match_name_map[export["match_name"]].add(export["artifact"])

    for record in simulation["rules"]:
        record["matched_canonical"] = _canonical_names(
            record["matched"], match_name_map
        )
        record["consumed_canonical"] = _canonical_names(
            record["consumed"], match_name_map
        )

    simulation["consumed_canonical"] = _canonical_names(
        simulation["consumed"], match_name_map
    )
    simulation["unconsumed_canonical"] = _canonical_names(
        simulation["unconsumed"], match_name_map
    )

    blocking = any(ambiguity["blocking"] for ambiguity in ambiguities)
    return {
        "platform": platform["name"],
        "path_style": platform["path_style"],
        "case_sensitive": platform["case_sensitive"],
        "match_basis": policy["match_names"],
        "normalization": policy["normalization"],
        "rules": simulation["rules"],
        "passed": simulation["passed"],
        "error": simulation["error"],
        "consumed_canonical": simulation["consumed_canonical"],
        "unconsumed_canonical": simulation["unconsumed_canonical"],
        "ambiguous": blocking,
        "ambiguities": ambiguities,
    }


def _compare_platforms(decisions):
    """Compare one policy's decisions across all platforms."""
    platform_names = sorted(decisions)
    blocking_ambiguities = [
        ambiguity
        for decision in decisions.values()
        for ambiguity in decision["ambiguities"]
        if ambiguity["blocking"]
    ]

    passed_values = {decision["passed"] for decision in decisions.values()}
    consumed_values = {
        frozenset(decision["consumed_canonical"])
        for decision in decisions.values()
    }

    rule_sets = defaultdict(dict)
    for platform_name, decision in decisions.items():
        for record in decision["rules"]:
            rule_sets[record["index"]][platform_name] = frozenset(
                record["matched_canonical"]
            )

    differences = []
    if len(passed_values) > 1:
        differences.append(
            {
                "kind": "decision",
                "platforms": {
                    name: decision["passed"]
                    for name, decision in decisions.items()
                },
            }
        )

    all_consumed = set()
    for consumed in consumed_values:
        all_consumed.update(consumed)
    common_consumed = set(all_consumed)
    for consumed in consumed_values:
        common_consumed.intersection_update(consumed)
    differences.extend(
        {
            "kind": "consumed",
            "artifact": artifact,
            "platforms": [
                name
                for name in platform_names
                if artifact in decisions[name]["consumed_canonical"]
            ],
        }
        for artifact in sorted(all_consumed - common_consumed)
    )

    for rule_index in sorted(rule_sets):
        sets = {
            name: rule_sets[rule_index].get(name) for name in platform_names
        }
        if len(set(sets.values())) > 1:
            rule = next(
                (
                    record["rule"]
                    for decision in decisions.values()
                    for record in decision["rules"]
                    if record["index"] == rule_index
                ),
                [],
            )
            differences.append(
                {
                    "kind": "applicability",
                    "index": rule_index,
                    "rule": rule,
                    "platforms": {
                        name: sorted(values) if values is not None else []
                        for name, values in sorted(sets.items())
                    },
                    "evaluated": {
                        name: values is not None
                        for name, values in sorted(sets.items())
                    },
                }
            )

    if blocking_ambiguities:
        status = "AMBIGUOUS"
        equivalent = None
    elif differences:
        status = "DIVERGENT"
        equivalent = False
    else:
        equivalent = True
        status = (
            "EQUIVALENT_PASS" if passed_values == {True} else "EQUIVALENT_FAIL"
        )

    return {
        "platforms": decisions,
        "status": status,
        "equivalent": equivalent,
        "same_decision": equivalent,
        "differences": differences,
        "blocking_ambiguities": blocking_ambiguities,
    }


def _align_rules(before_rules, after_rules):
    """Align before/after rules, preserving unchanged rules by identity.

    A replacement block is paired positionally, so a modified rule can still be
    reported as the same logical rule. Rules with no counterpart are reported as
    added or removed.
    """
    matcher = SequenceMatcher(
        a=[tuple(rule) for rule in before_rules],
        b=[tuple(rule) for rule in after_rules],
        autojunk=False,
    )
    aligned = []
    for (
        tag,
        before_start,
        before_end,
        after_start,
        after_end,
    ) in matcher.get_opcodes():
        if tag == "equal":
            aligned.extend(
                zip(
                    range(before_start, before_end),
                    range(after_start, after_end),
                )
            )
            continue

        before_count = before_end - before_start
        after_count = after_end - after_start
        paired = min(before_count, after_count)
        aligned.extend(
            (before_start + offset, after_start + offset)
            for offset in range(paired)
        )
        aligned.extend(
            (index, None) for index in range(before_start + paired, before_end)
        )
        aligned.extend(
            (None, index) for index in range(after_start + paired, after_end)
        )

    return aligned


def _compare_policies(case, before_decisions, after_decisions):
    """Compare per-rule applicable sets before and after a policy change."""
    if not before_decisions or not after_decisions:
        return {"available": False, "rules": [], "expanded_rules": []}

    rules = []
    platform_names = sorted(set(before_decisions) & set(after_decisions))
    before_rules = case["policies"]["before"]["rules"]
    after_rules = case["policies"]["after"]["rules"]
    aligned_rules = _align_rules(before_rules, after_rules)

    for before_index, after_index in aligned_rules:
        per_platform = {}
        all_added = set()
        all_removed = set()
        indeterminate = False

        for platform_name in platform_names:
            before_decision = before_decisions[platform_name]
            after_decision = after_decisions[platform_name]
            before_record = next(
                (
                    record
                    for record in before_decision["rules"]
                    if record["index"] == before_index
                ),
                None,
            )
            after_record = next(
                (
                    record
                    for record in after_decision["rules"]
                    if record["index"] == after_index
                ),
                None,
            )

            before_set = set(
                before_record["matched_canonical"] if before_record else []
            )
            after_set = set(
                after_record["matched_canonical"] if after_record else []
            )
            added = sorted(after_set - before_set)
            removed = sorted(before_set - after_set)
            evaluated = (
                before_index is None
                or (before_record is not None and before_record["evaluated"])
            ) and (
                after_index is None
                or (after_record is not None and after_record["evaluated"])
            )
            if not evaluated:
                indeterminate = True
            all_added.update(added)
            all_removed.update(removed)
            per_platform[platform_name] = {
                "before": sorted(before_set),
                "after": sorted(after_set),
                "added": added,
                "removed": removed,
                "expanded": bool(added),
                "evaluated": evaluated,
            }

        changed = bool(all_added or all_removed)
        rules.append(
            {
                "rule_index": (
                    after_index if after_index is not None else before_index
                ),
                "before_index": before_index,
                "after_index": after_index,
                "rule_before": (
                    list(before_rules[before_index])
                    if before_index is not None
                    else None
                ),
                "rule_after": (
                    list(after_rules[after_index])
                    if after_index is not None
                    else None
                ),
                "platforms": per_platform,
                "added": sorted(all_added),
                "removed": sorted(all_removed),
                "expanded": bool(all_added) and not indeterminate,
                "changed": changed,
                "indeterminate": indeterminate,
            }
        )

    return {
        "available": True,
        "rules": rules,
        "expanded_rules": [rule for rule in rules if rule["expanded"]],
    }


def check_contract(contract, policy_name="after"):
    """Run all offline path contract checks for a parsed contract.

    <Arguments>
      contract:
              A contract returned by ``parse_contract`` or ``load_contract``.

      policy_name:
              Policy used for the primary cross-platform verdict.

    <Returns>
      A JSON-compatible result dictionary.
    """
    if policy_name not in {"before", "after"}:
        raise ContractError("policy_name must be 'before' or 'after'")

    case_results = []
    summary = {
        "cases": 0,
        "equivalent": 0,
        "divergent": 0,
        "ambiguous": 0,
        "expanded_rules": 0,
    }

    for case in contract["cases"]:
        if policy_name not in case["policies"]:
            raise ContractError(
                f"case {case['name']!r} has no {policy_name!r} policy"
            )

        decisions = {}
        for available_policy in ("before", "after"):
            if available_policy not in case["policies"]:
                continue
            decisions[available_policy] = {
                platform["name"]: _run_platform(
                    case, platform, available_policy
                )
                for platform in contract["platforms"]
            }

        cross_platform = {
            name: _compare_platforms(result)
            for name, result in decisions.items()
        }
        policy_change = _compare_policies(
            case, decisions.get("before"), decisions.get("after")
        )

        selected = cross_platform[policy_name]
        summary["cases"] += 1
        if selected["status"] == "AMBIGUOUS":
            summary["ambiguous"] += 1
        elif selected["status"] == "DIVERGENT":
            summary["divergent"] += 1
        elif selected["status"].startswith("EQUIVALENT"):
            summary["equivalent"] += 1
        summary["expanded_rules"] += len(policy_change["expanded_rules"])

        case_results.append(
            {
                "name": case["name"],
                "description": case["description"],
                "target": case["target"],
                "policies": {
                    name: {
                        "match_names": policy["match_names"],
                        "normalization": policy["normalization"],
                        "rules": policy["rules"],
                    }
                    for name, policy in case["policies"].items()
                },
                "cross_platform": cross_platform,
                "policy_change": policy_change,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "contract": contract["name"],
        "description": contract["description"],
        "policy": policy_name,
        "platforms": [
            {
                "name": platform["name"],
                "path_style": platform["path_style"],
                "case_sensitive": platform["case_sensitive"],
            }
            for platform in contract["platforms"]
        ],
        "summary": summary,
        "cases": case_results,
    }


def _code(value):
    """Format a value as a Markdown code span."""
    text = "" if value is None else str(value)
    return "`" + text.replace("`", "\\`") + "`"


def _path_label(value):
    """Format a path and make non-ASCII code points explicit."""
    text = str(value)
    label_text = text
    if any(ord(character) > 127 for character in text):
        label_text = text.encode("unicode_escape").decode("ascii")
    label = _code(label_text)
    code_points = " ".join(
        f"U+{ord(character):04X}" for character in text if ord(character) > 127
    )
    return f"{label} ({code_points})" if code_points else label


def _join(values, formatter=_code):
    """Format a list of values for a table cell."""
    if not values:
        return ""
    return ", ".join(formatter(value) for value in values)


def _join_paths(values):
    """Format a list of paths for a table cell."""
    return _join(values, _path_label)


def _table(headers, rows):
    """Render a simple Markdown table."""
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def render_markdown(result):  # noqa: C901, PLR0912, PLR0915
    """Render an acceptance report for a contract check result."""
    lines = [
        "# Offline path contract acceptance report",
        "",
        f"**Contract:** {_code(result['contract'])}",
        "",
    ]
    if result.get("description"):
        lines.extend([result["description"], ""])

    platform_text = ", ".join(
        f"{_code(platform['name'])} ({platform['path_style']}, "
        f"{'case-sensitive' if platform['case_sensitive'] else 'case-insensitive'})"
        for platform in result["platforms"]
    )
    lines.extend(
        [
            "## Contract setup",
            "",
            f"- Platforms: {platform_text}",
            f"- Primary policy: {_code(result['policy'])}",
            "- Recorded paths are normalized like in-toto link metadata: "
            "platform `normpath`, then backslashes become forward slashes.",
            "- Evaluation uses in-toto's artifact rule functions. No build "
            "artifacts are read or written.",
            "",
            "## Verdict",
            "",
        ]
    )

    rows = []
    for case in result["cases"]:
        selected = case["cross_platform"][result["policy"]]
        platform_results = [
            "pass"
            if selected["platforms"][platform["name"]]["passed"]
            else "fail"
            for platform in result["platforms"]
        ]
        same = selected["same_decision"]
        same_text = (
            "indeterminate" if same is None else ("yes" if same else "no")
        )
        rows.append(
            [
                _code(case["name"]),
                _code(
                    case["cross_platform"]
                    .get("before", {})
                    .get("status", "not specified")
                ),
                _code(
                    case["cross_platform"]
                    .get("after", {})
                    .get("status", "not specified")
                ),
                same_text,
                *platform_results,
            ]
        )

    lines.extend(
        [
            _table(
                [
                    "Case",
                    "Before policy",
                    "After policy",
                    "Same decision",
                    *[platform["name"] for platform in result["platforms"]],
                ],
                rows,
            ),
            "",
            "Status values: `EQUIVALENT_PASS` and `EQUIVALENT_FAIL` mean all "
            "platforms reached the same decision; `DIVERGENT` means they did "
            "not; `AMBIGUOUS` means a mapping collision prevents a decision.",
            "",
            f"Primary-policy summary: {result['summary']['equivalent']} "
            f"equivalent, {result['summary']['divergent']} divergent, "
            f"{result['summary']['ambiguous']} ambiguous; "
            f"{result['summary']['expanded_rules']} expanded rule(s).",
            "",
        ]
    )

    lines.extend(
        [
            "## Rule applicability",
            "",
            "Rows are shown for every policy so the original/normalized basis "
            "can be compared directly.",
            "",
        ]
    )
    for case in result["cases"]:
        lines.extend([f"### {_code(case['name'])}", ""])
        rows = []
        for policy_name in ("before", "after"):
            if policy_name not in case["cross_platform"]:
                continue
            cross = case["cross_platform"][policy_name]
            for platform in result["platforms"]:
                decision = cross["platforms"][platform["name"]]
                basis = decision["match_basis"]
                for record in decision["rules"]:
                    rows.append(
                        [
                            _code(policy_name),
                            _code(platform["name"]),
                            _code(basis),
                            str(record["index"]),
                            _code(" ".join(record["effective_rule"])),
                            _join_paths(record["matched"]),
                            _join_paths(record["matched_canonical"]),
                        ]
                    )
        lines.extend(
            [
                _table(
                    [
                        "Policy",
                        "Platform",
                        "Match basis",
                        "#",
                        "Effective rule",
                        "Matched recorded paths",
                        "Matched canonical artifacts",
                    ],
                    rows,
                ),
                "",
            ]
        )

    lines.extend(["## Cross-platform differences", ""])
    found_difference = False
    for case in result["cases"]:
        for policy_name in ("before", "after"):
            if policy_name not in case["cross_platform"]:
                continue
            cross = case["cross_platform"][policy_name]
            if not cross["differences"]:
                continue
            found_difference = True
            lines.append(
                f"- {_code(case['name'])} ({_code(policy_name)}): "
                f"{_code(cross['status'])}"
            )
            for difference in cross["differences"]:
                if difference["kind"] == "decision":
                    lines.append(
                        "  - pass/fail differs: "
                        + ", ".join(
                            f"{_code(name)}={'pass' if passed else 'fail'}"
                            for name, passed in difference["platforms"].items()
                        )
                    )
                elif difference["kind"] == "consumed":
                    lines.append(
                        f"  - {_path_label(difference['artifact'])} consumed on "
                        + ", ".join(
                            _code(name) for name in difference["platforms"]
                        )
                    )
                elif difference["kind"] == "applicability":
                    details = ", ".join(
                        f"{_code(name)}={_join_paths(values) or '(none)'}"
                        for name, values in difference["platforms"].items()
                    )
                    lines.append(
                        f"  - rule {difference['index']} "
                        f"{_code(' '.join(difference['rule']))} matched: "
                        f"{details}"
                    )
    if not found_difference:
        lines.append("No cross-platform decision differences were found.")
    lines.append("")

    lines.extend(["## Mapping ambiguities", ""])
    rows = []
    for case in result["cases"]:
        for policy_name in ("before", "after"):
            if policy_name not in case["cross_platform"]:
                continue
            cross = case["cross_platform"][policy_name]
            for platform in result["platforms"]:
                decision = cross["platforms"][platform["name"]]
                for ambiguity in decision["ambiguities"]:
                    candidates = ", ".join(
                        f"{_path_label(candidate['artifact'])} "
                        f"({_path_label(candidate['exported'])})"
                        for candidate in ambiguity["candidates"]
                    )
                    rows.append(
                        [
                            _code(case["name"]),
                            _code(policy_name),
                            _code(platform["name"]),
                            _code(ambiguity["step"]),
                            ambiguity["artifact_type"],
                            _code(ambiguity["kind"]),
                            _path_label(ambiguity["key"]),
                            "yes" if ambiguity["blocking"] else "no",
                            candidates,
                        ]
                    )
    if rows:
        lines.append(
            _table(
                [
                    "Case",
                    "Policy",
                    "Platform",
                    "Step",
                    "Type",
                    "Kind",
                    "Key",
                    "Blocking",
                    "Candidates",
                ],
                rows,
            )
        )
    else:
        lines.append("No mapping ambiguities were found.")
    lines.append("")

    lines.extend(["## Policy change: expanded applicability", ""])
    expanded_rows = []
    for case in result["cases"]:
        change = case["policy_change"]
        if not change["available"]:
            continue
        for rule in change["expanded_rules"]:
            per_platform = []
            for platform_name, values in rule["platforms"].items():
                if values["added"]:
                    per_platform.append(
                        f"{_code(platform_name)}: +{_join_paths(values['added'])}"
                    )
            expanded_rows.append(
                [
                    _code(case["name"]),
                    str(rule["rule_index"]),
                    _code(
                        " ".join(
                            rule["rule_after"] or rule["rule_before"] or []
                        )
                    ),
                    _join_paths(rule["added"]),
                    _join_paths(rule["removed"]),
                    "; ".join(per_platform),
                ]
            )

    if expanded_rows:
        lines.append(
            _table(
                [
                    "Case",
                    "Rule #",
                    "Rule",
                    "Added",
                    "Removed",
                    "Expanded on",
                ],
                expanded_rows,
            )
        )
        lines.extend(["", "Expanded rules:"])
        for case in result["cases"]:
            for rule in case["policy_change"]["expanded_rules"]:
                rule_text = " ".join(
                    rule["rule_after"] or rule["rule_before"] or []
                )
                platforms = ", ".join(
                    f"{name} (+{_join_paths(values['added'])})"
                    for name, values in rule["platforms"].items()
                    if values["added"]
                )
                lines.append(
                    f"- {_code(case['name'])}, rule {rule['rule_index']} "
                    f"{_code(rule_text)}: {platforms}"
                )
    else:
        lines.append(
            "No rule's applicable set expanded between the before and after "
            "policies."
        )
    lines.append("")

    lines.extend(
        [
            "## Interpretation notes",
            "",
            "- `original` means rules see the recorded path spelling. Platform "
            "glob semantics still apply: a Windows profile folds case, a POSIX "
            "profile does not.",
            "- `normalized` means the explicit normalization (Unicode form, "
            "case mode, separator, stripped prefixes) is applied to both "
            "recorded names and rule patterns before matching.",
            "- Unicode-equivalent spellings are not implicitly equal in "
            "`fnmatch`; an NFC/NFD mismatch remains a mismatch unless a policy "
            "normalizes it.",
            "- Ambiguous mappings are never silently resolved. Candidates are "
            "listed and a blocking collision makes the verdict `AMBIGUOUS`.",
            "",
        ]
    )

    return "\n".join(lines)
