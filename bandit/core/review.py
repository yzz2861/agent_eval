#
# SPDX-License-Identifier: Apache-2.0
"""Optional review mode: reproducible evidence identifiers for results.

Security sign-off usually happens against a SARIF/JSON report long after
the scan ran.  By that time the build tool may have replaced the source
tree, so the reviewer cannot tell which exact file contents and which
exact rule material produced a finding.

The optional review mode attaches two material identifiers to every
result:

* ``file_material`` identifies the exact bytes that were parsed and handed
  to the rules, not whatever happens to sit on disk later.
* ``rule_material`` identifies the rule plugin declaration (its source)
  together with the resolved configuration that was passed to the rule.

The identifiers are content based and the recorded location is a
workspace-relative logical path, so moving the whole working directory to
a new location does not invalidate a finding.  Replacing the scanned
input invalidates results at the file layer; changing a plugin
declaration or the controllable plugin configuration invalidates them at
the rule layer.  A missing plugin declaration or configuration material
is classified as not reproducible rather than guessed at.

Only the Python standard library is required, so a report can be
re-verified without any running service.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path

from bandit.core import blacklisting
from bandit.core import extension_loader

DIGEST_ALGORITHM = "sha256"

# Verification outcomes.
REPRODUCIBLE = "reproducible"
NOT_REPRODUCIBLE = "not_reproducible"

# Layers responsible for a non-reproducible result.
LAYER_FILE = "file"
LAYER_RULE = "rule"

# Reasons recorded for findings withheld because a file changed or was
# deleted while the scan was in progress.
REASON_FILE_CHANGED = "file changed during scan"
REASON_FILE_DELETED = "file deleted during scan"


def content_digest(data):
    """Return the content digest of the bytes (or text) actually scanned."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.new(DIGEST_ALGORITHM, data).hexdigest()


def file_digest(path):
    """Digest of a file on disk, or ``None`` when it cannot be read."""
    try:
        with open(path, "rb") as handle:
            return content_digest(handle.read())
    except OSError:
        return None


def _canonical(value):
    """Coerce arbitrary plugin configuration into stable, JSON-safe data.

    Bandit blacklist configuration uses sets and tuples, and plugin
    configurations may contain arbitrary nested structures.  Sorting the
    normalized output means equivalent configuration always hashes the
    same regardless of ordering.
    """
    if isinstance(value, dict):
        return {
            str(key): _canonical(value[key])
            for key in sorted(value, key=lambda item: str(item))
        }
    if isinstance(value, (set, frozenset)):
        return [_canonical(item) for item in sorted(value, key=repr)]
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def config_digest(config):
    """Return a stable digest of the resolved config passed to a rule."""
    payload = json.dumps(
        _canonical(config), sort_keys=True, separators=(",", ":")
    )
    return content_digest(payload)


def compute_scan_root(files):
    """Choose a stable root from the discovered file list.

    The common parent directory of the scanned files is used so that the
    logical paths recorded in the materials survive a move of the whole
    workspace.
    """
    absolute = [
        os.path.abspath(name) for name in files if name != "<stdin>"
    ]
    if not absolute:
        return os.getcwd()
    common = os.path.commonpath(absolute)
    if os.path.isdir(common):
        return common
    return os.path.dirname(common) or os.getcwd()


def logical_path(fname, scan_root):
    """Return a workspace-relative, move-independent location identifier."""
    if fname == "<stdin>":
        return "<stdin>"
    path = Path(os.path.normpath(fname))
    if scan_root:
        try:
            return path.relative_to(Path(scan_root)).as_posix()
        except ValueError:
            pass
    if path.is_absolute():
        return path.name
    return path.as_posix()


def resolve_logical_path(logical, roots):
    """Locate a logical path under candidate scan roots after a move."""
    for root in roots:
        candidate = Path(root) / logical
        if candidate.is_file():
            return str(candidate)
    if Path(logical).is_file():
        return logical
    return None


def plugin_callable(test_id):
    """Resolve the callable backing a test id, or ``None`` if undeclared."""
    extman = extension_loader.MANAGER
    extension = extman.plugins_by_id.get(test_id)
    if extension is not None:
        return extension.plugin
    if test_id in extman.blacklist_by_id:
        return blacklisting.blacklist
    return None


def build_rule_material(test_id, test_name, config):
    """Build the rule material for a plugin run and its resolved config.

    Returns ``None`` when the plugin declaration cannot be found or its
    source cannot be read: a result without rule material cannot be
    re-computed and must be treated as missing material at review time.
    """
    plugin = plugin_callable(test_id)
    if plugin is None:
        return None
    source_file = inspect.getsourcefile(plugin)
    plugin_hash = file_digest(source_file) if source_file else None
    if plugin_hash is None:
        return None
    return {
        "test_id": test_id,
        "test_name": test_name,
        "algorithm": DIGEST_ALGORITHM,
        "plugin_source": source_file,
        "plugin_source_digest": plugin_hash,
        "config": _canonical(config),
        "config_digest": config_digest(config),
    }


def resolve_testset_func(testset, test_id):
    """Return the configured callable backing a finding from a test set.

    The test set is the same object the scanner used: its plugin instances
    carry the resolved ``_config`` (including generated defaults), so both
    the declaration and the configuration material can be reproduced here.
    Falls back to the global extension manager when no test set is given.
    """
    if testset is not None:
        for wrapper in getattr(testset, "plugins", []):
            func = wrapper.plugin
            if getattr(func, "_test_id", None) == test_id:
                return func
            # The built-in blacklist wrapper is declared as B001 while
            # its individual findings carry B3xx/B4xx identifiers.
            if func is blacklisting.blacklist and (
                test_id in extension_loader.MANAGER.blacklist_by_id
            ):
                return func
        return None
    return plugin_callable(test_id)


def current_rule_config(plugin):
    """Resolve the configuration a plugin would receive in this process."""
    return getattr(plugin, "_config", None)


def current_rule_material(testset, test_id, test_name):
    """Rebuild a rule material from the current, scan-equivalent rules."""
    plugin = resolve_testset_func(testset, test_id)
    if plugin is None:
        return None
    source_file = inspect.getsourcefile(plugin)
    plugin_hash = file_digest(source_file) if source_file else None
    if plugin_hash is None:
        return None
    return {
        "test_id": test_id,
        "test_name": test_name,
        "algorithm": DIGEST_ALGORITHM,
        "plugin_source": source_file,
        "plugin_source_digest": plugin_hash,
        "config": _canonical(getattr(plugin, "_config", None)),
        "config_digest": config_digest(getattr(plugin, "_config", None)),
    }


class ReviewRecorder:
    """Collects material identifiers and enforces scan-time integrity.

    A per-file snapshot is taken immediately before parsing.  After the
    file has been processed the on-disk content is checked again.  Results
    from a file whose contents changed, or that disappeared, while it was
    being scanned are withheld because the published report cannot claim
    they describe the bytes currently on disk.
    """

    def __init__(self, files):
        self.scan_root = compute_scan_root(files)
        self.snapshots = {}
        self.rule_materials = {}

    def snapshot(self, fname):
        """Record the on-disk content identity of a file before scanning."""
        if fname == "<stdin>":
            self.snapshots[fname] = None
            return
        self.snapshots[fname] = file_digest(fname)

    def is_stale(self, fname):
        """Return ``(stale, reason)`` for a file that was just processed."""
        if fname == "<stdin>" or fname not in self.snapshots:
            return False, None
        if not os.path.isfile(fname):
            return True, REASON_FILE_DELETED
        current = file_digest(fname)
        if current is None:
            return True, REASON_FILE_DELETED
        if current != self.snapshots[fname]:
            return True, REASON_FILE_CHANGED
        return False, None

    def rule_material_for(self, test_id, test_name, config):
        """Cache and return the rule material for a given test id."""
        if test_id not in self.rule_materials:
            self.rule_materials[test_id] = build_rule_material(
                test_id, test_name, config
            )
        return self.rule_materials[test_id]

    def file_material_for(self, fname, data):
        """Build the file material from the bytes actually handed to rules."""
        return {
            "logical_path": logical_path(fname, self.scan_root),
            "algorithm": DIGEST_ALGORITHM,
            "content_digest": content_digest(data),
            "byte_length": len(data),
        }

    def summary(self):
        return {
            "mode": "review",
            "algorithm": DIGEST_ALGORITHM,
            "scan_root": self.scan_root,
        }


def attach_attestation(issue_obj, recorder, data):
    """Attach file and rule material identifiers to a scanned issue."""
    file_material = recorder.file_material_for(issue_obj.fname, data)
    rule_material = recorder.rule_material_for(
        issue_obj.test_id,
        issue_obj.test,
        getattr(issue_obj, "_rule_config", None),
    )
    issue_obj.review = {
        "file_material": file_material,
        "rule_material": rule_material,
    }
    return issue_obj.review


def verify_result(entry, roots, testset=None):
    """Re-check one report result against the current workspace.

    The checks are layered.  The file material is confirmed first; only
    then is the rule material compared, and a missing plugin declaration
    or configuration is reported at the rule layer instead of being
    guessed at.

    :return: a dict with ``status``, ``layer`` and ``reason`` keys.
    """
    review = entry.get("review") or {}
    file_material = review.get("file_material") or {}
    rule_material = review.get("rule_material")
    logical = file_material.get("logical_path") or entry.get("filename")
    line_number = entry.get("line_number")
    test_id = entry.get("test_id")
    if rule_material and rule_material.get("test_id"):
        test_id = rule_material.get("test_id")
    context = {
        "logical_path": logical,
        "test_id": test_id,
        "line_number": line_number,
    }

    if not logical or not file_material.get("content_digest"):
        return _failure(None, "report is missing file material", **context)

    located = resolve_logical_path(logical, roots)
    if located is None:
        return _failure(
            LAYER_FILE, "file material cannot be located", **context
        )

    current_file_hash = file_digest(located)
    if current_file_hash is None:
        return _failure(
            LAYER_FILE, "file material cannot be read", **context
        )
    if current_file_hash != file_material["content_digest"]:
        return _failure(
            LAYER_FILE,
            "file content digest differs from recorded file material",
            **context,
        )

    if line_number is not None and not _line_exists(located, line_number):
        return _failure(
            LAYER_FILE,
            "finding location is absent from the file material",
            **context,
        )

    if not rule_material:
        return _failure(
            LAYER_RULE,
            "plugin declaration or configuration material is missing",
            **context,
        )

    current_material = current_rule_material(
        testset, test_id, rule_material.get("test_name", "")
    )
    if current_material is None:
        if plugin_callable(test_id) is None:
            return _failure(
                LAYER_RULE,
                "plugin declaration is missing from the active rules",
                **context,
            )
        return _failure(
            LAYER_RULE,
            "plugin declaration material cannot be located",
            **context,
        )
    if (
        current_material["plugin_source_digest"]
        != rule_material.get("plugin_source_digest")
    ):
        return _failure(
            LAYER_RULE,
            "plugin declaration digest differs from recorded rule material",
            **context,
        )
    if (
        current_material["config_digest"]
        != rule_material.get("config_digest")
    ):
        return _failure(
            LAYER_RULE,
            "plugin configuration digest differs from recorded rule "
            "material",
            **context,
        )

    return {
        "status": REPRODUCIBLE,
        "layer": None,
        "reason": "file and rule material match",
        "logical_path": logical,
        "located_at": located,
        "test_id": test_id,
        "line_number": line_number,
    }


def verify_report(report, roots, testset=None):
    """Verify every result in a JSON report produced with review mode."""
    results = report.get("results", []) if isinstance(report, dict) else []
    entries = []
    counts = {
        REPRODUCIBLE: 0,
        NOT_REPRODUCIBLE: 0,
        LAYER_FILE: 0,
        LAYER_RULE: 0,
    }
    for entry in results:
        outcome = verify_result(entry, roots, testset=testset)
        counts[outcome["status"]] += 1
        if outcome["layer"]:
            counts[outcome["layer"]] += 1
        entries.append(outcome)
    return {
        "scan_roots": list(roots),
        "total": len(results),
        "counts": counts,
        "results": entries,
    }


def _line_exists(path, lineno):
    try:
        with open(path, "rb") as handle:
            return lineno <= len(handle.read().splitlines())
    except OSError:
        return False


def _failure(layer, reason, logical_path=None, test_id=None,
             line_number=None):
    return {
        "status": NOT_REPRODUCIBLE,
        "layer": layer,
        "reason": reason,
        "logical_path": logical_path,
        "located_at": None,
        "test_id": test_id,
        "line_number": line_number,
    }
