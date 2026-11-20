"""Offline policy previews for :mod:`html_sanitizer`.

The preview compares two sanitizer policies without requiring a running
application. Every element in the input gets a stable structural path (for
example ``/p[2]/span[1]``) before either policy runs. The same path is used in
both results, so duplicate-looking nodes remain distinguishable.

Only structural decisions and lengths are recorded. Text nodes and attribute
values are never stored in preview results or decision logs. The two sanitized
HTML strings are the only content-bearing values in the public result.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .sanitizer import Sanitizer


__all__ = (
    "DiffEntry",
    "NodeOutcome",
    "PolicyDecision",
    "PolicyPreview",
    "compare_policies",
    "preview",
    "preview_policy",
    "policy_preview",
    "sanitize_preview",
    "preview_html",
)


_MARKER_ATTRIBUTE = "data-hs-preview-node"

# Tags which lxml.html.clean removes together with their contents in one of
# the two cleaner passes used by Sanitizer.
_CLEANER_KILL_TAGS = {
    "applet",
    "base",
    "frame",
    "frameset",
    "link",
    "meta",
    "noframes",
    "script",
}

# Tags which lxml.html.clean unwraps, keeping their contents.
_CLEANER_REMOVE_TAGS = {
    "blink",
    "embed",
    "head",
    "html",
    "iframe",
    "layer",
    "marquee",
    "object",
    "param",
    "title",
}


def _tag_name(element):
    return element.tag if isinstance(element.tag, str) else None


def _build_paths(root):
    """Return ``{element: path}`` with indices for same-tag siblings."""
    paths = {}

    def walk(parent, prefix):
        counts = Counter()
        for child in parent:
            tag = _tag_name(child)
            if tag is None:
                walk(child, prefix)
                continue
            counts[tag] += 1
            path = f"{prefix}/{tag}[{counts[tag]}]"
            paths[child] = path
            walk(child, path)

    walk(root, "")
    return paths


def _is_attached(element, root):
    node = element
    while node is not None:
        if node is root:
            return True
        node = node.getparent()
    return False


def _decision_dict(decision):
    return {
        key: value
        for key, value in decision.__dict__.items()
        if value is not None and value != ()
    }


@dataclass(frozen=True)
class PolicyDecision:
    """A redacted description of one sanitizer decision."""

    action: str
    reason: str
    node_id: str
    path: str
    tag: str
    source_tag: str | None = None
    target_tag: str | None = None
    target_node_id: str | None = None
    attribute: str | None = None
    removed_nodes: int | None = None
    text_length: int | None = None
    content_length: int | None = None
    old_length: int | None = None
    new_length: int | None = None

    def to_dict(self):
        return _decision_dict(self)


@dataclass(frozen=True)
class NodeOutcome:
    """The fate of one original node under one policy."""

    node_id: str
    path: str
    original_tag: str
    status: str
    reason: str | None = None
    tag: str | None = None
    output_path: str | None = None
    source_text_length: int = 0
    source_content_length: int = 0
    output_text_length: int | None = None
    output_content_length: int | None = None
    retained_content_length: int = 0
    subtree_nodes: int = 1
    attribute_names: tuple[str, ...] = ()
    kept_attribute_names: tuple[str, ...] = ()
    removed_attribute_names: tuple[str, ...] = ()
    merge_target: str | None = None
    covered_by: str | None = None
    decisions: tuple[PolicyDecision, ...] = ()

    @property
    def xpath(self):
        return self.path

    def to_dict(self):
        return {
            "node_id": self.node_id,
            "path": self.path,
            "xpath": self.path,
            "original_tag": self.original_tag,
            "status": self.status,
            "reason": self.reason,
            "tag": self.tag,
            "output_path": self.output_path,
            "source_text_length": self.source_text_length,
            "source_content_length": self.source_content_length,
            "output_text_length": self.output_text_length,
            "output_content_length": self.output_content_length,
            "retained_content_length": self.retained_content_length,
            "subtree_nodes": self.subtree_nodes,
            "attribute_names": list(self.attribute_names),
            "kept_attribute_names": list(self.kept_attribute_names),
            "removed_attribute_names": list(self.removed_attribute_names),
            "merge_target": self.merge_target,
            "covered_by": self.covered_by,
            "decisions": [decision.to_dict() for decision in self.decisions],
        }


@dataclass(frozen=True)
class DiffEntry:
    """One row of the review table."""

    node_id: str
    path: str
    tag: str
    change: str
    old: NodeOutcome
    new: NodeOutcome
    covered_by: str | None = None
    summary: str = ""

    @property
    def primary(self):
        return self.covered_by is None

    @property
    def xpath(self):
        return self.path

    @property
    def category(self):
        return self.change

    @property
    def old_status(self):
        return self.old.status

    @property
    def new_status(self):
        return self.new.status

    @property
    def old_tag(self):
        return self.old.tag

    @property
    def new_tag(self):
        return self.new.tag

    def to_dict(self):
        return {
            "node_id": self.node_id,
            "path": self.path,
            "xpath": self.path,
            "tag": self.tag,
            "change": self.change,
            "old_status": self.old.status,
            "new_status": self.new.status,
            "old_tag": self.old.tag,
            "new_tag": self.new.tag,
            "covered_by": self.covered_by,
            "primary": self.primary,
            "summary": self.summary,
            "old": self.old.to_dict(),
            "new": self.new.to_dict(),
        }


@dataclass(frozen=True)
class PolicyPreview:
    """Result of :func:`preview_policy`.

    The object is mapping-like (``preview["old_html"]``) in addition to
    exposing typed attributes.
    """

    old_html: str
    new_html: str
    old_summary: dict[str, Any]
    new_summary: dict[str, Any]
    policy_changes: dict[str, Any]
    differences: tuple[DiffEntry, ...]

    @property
    def primary_differences(self):
        return tuple(entry for entry in self.differences if entry.primary)

    @property
    def old(self):
        return {"html": self.old_html, "summary": self.old_summary}

    @property
    def new(self):
        return {"html": self.new_html, "summary": self.new_summary}

    @property
    def old_result(self):
        return self.old_html

    @property
    def new_result(self):
        return self.new_html

    @property
    def old_output(self):
        return self.old_html

    @property
    def new_output(self):
        return self.new_html

    @property
    def diff(self):
        return self.differences

    @property
    def rows(self):
        return self.differences

    @property
    def summary(self):
        return {
            "old": self.old_summary,
            "new": self.new_summary,
            "policy_changes": self.policy_changes,
        }

    def to_dict(self, *, include_outputs=True):
        result = {
            "old_summary": self.old_summary,
            "new_summary": self.new_summary,
            "policy_changes": self.policy_changes,
            "differences": [entry.to_dict() for entry in self.differences],
        }
        if include_outputs:
            result["old"] = self.old
            result["new"] = self.new
            result["old_html"] = self.old_html
            result["new_html"] = self.new_html
            result["old_result"] = self.old_html
            result["new_result"] = self.new_html
        else:
            result["old"] = {"summary": self.old_summary}
            result["new"] = {"summary": self.new_summary}
        return result

    def to_debug_dict(self):
        """Return a report without either sanitized HTML payload.

        Decision records in this report contain tags, paths and lengths only.
        They never contain text or attribute values.
        """

        return self.to_dict(include_outputs=False)

    def to_json(self, *, include_outputs=True, indent=2):
        return json.dumps(
            self.to_dict(include_outputs=include_outputs),
            ensure_ascii=False,
            indent=indent,
            sort_keys=False,
        )

    def format_table(self, *, include_covered=False):
        entries = self.differences if include_covered else self.primary_differences
        return _format_table(entries)

    def __repr__(self):
        return f"PolicyPreview(old_length={len(self.old_html)}, new_length={len(self.new_html)}, differences={len(self.differences)})"

    def __getitem__(self, key):
        return self.to_dict()[key]

    def keys(self):
        return self.to_dict().keys()

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def __iter__(self):
        return iter(self.to_dict())

    def __len__(self):
        return len(self.to_dict())


@dataclass
class _Origin:
    node_id: str
    path: str
    depth: int
    tag: str
    parent_id: str | None
    element: Any = field(repr=False, compare=False)
    text_length: int = 0
    tail_length: int = 0
    content_length: int = 0
    child_count: int = 0
    subtree_nodes: int = 1
    attribute_names: tuple[str, ...] = ()
    decisions: list[PolicyDecision] = field(default_factory=list)
    terminal_action: str | None = None
    terminal_reason: str | None = None
    merge_target: str | None = None
    detached_stage: str | None = None
    status: str | None = None
    status_reason: str | None = None
    output_tag: str | None = None
    output_path: str | None = None
    output_text_length: int | None = None
    output_content_length: int | None = None
    retained_content_length: int = 0
    kept_attribute_names: tuple[str, ...] = ()
    covered_by: str | None = None


class _Trace:
    """Internal sanitizer observer used by the preview implementation."""

    def __init__(self, marker_attribute=_MARKER_ATTRIBUTE):
        self.marker_attribute = marker_attribute
        self.origins: list[_Origin] = []
        self.by_id: dict[str, _Origin] = {}
        self.by_element: dict[int, _Origin] = {}
        self.by_marker: dict[str, _Origin] = {}
        self.output_node_count = 0

    def start(self, doc):
        attributes = {key for element in doc.iter() for key in element.attrib}
        while self.marker_attribute in attributes:
            self.marker_attribute += "_"

        paths = _build_paths(doc)
        parent_by_element = {}
        for element in doc.iter():
            for child in element:
                parent_by_element[child] = element

        index = 0
        for element in doc.iterdescendants():
            tag = _tag_name(element)
            if tag is None:
                continue
            index += 1
            node_id = f"n{index}"
            parent = parent_by_element.get(element)
            parent_origin = self._origin_for(parent) if parent is not None else None
            text_length = len(element.text or "")
            tail_length = len(element.tail or "")
            path = paths.get(element, f"/{tag}[1]")
            origin = _Origin(
                node_id=node_id,
                path=path,
                depth=max(0, self._path_depth(path) - 1),
                tag=tag,
                parent_id=parent_origin.node_id if parent_origin is not None else None,
                element=element,
                text_length=text_length,
                tail_length=tail_length,
                content_length=len(element.text_content() or ""),
                child_count=len(element),
                attribute_names=tuple(sorted(element.attrib)),
            )
            element.set(self.marker_attribute, node_id)
            self.origins.append(origin)
            self.by_id[node_id] = origin
            self.by_element[id(element)] = origin
            self.by_marker[node_id] = origin

        sizes = {origin.node_id: 1 for origin in self.origins}
        for origin in reversed(self.origins):
            if origin.parent_id is not None:
                sizes[origin.parent_id] += sizes[origin.node_id]
        for origin in self.origins:
            origin.subtree_nodes = sizes[origin.node_id]

    @staticmethod
    def _path_depth(path):
        return path.count("/")

    def _origin_for(self, element):
        if element is None:
            return None
        origin = self.by_element.get(id(element))
        if origin is not None:
            return origin
        marker = element.get(self.marker_attribute)
        if marker is not None:
            return self.by_marker.get(marker)
        return None

    def ensure_marker(self, element):
        origin = self._origin_for(element)
        if origin is not None and element.get(self.marker_attribute) != origin.node_id:
            element.set(self.marker_attribute, origin.node_id)

    def _decision(self, origin, action, reason, **extra):
        decision = PolicyDecision(
            action=action,
            reason=reason,
            node_id=origin.node_id,
            path=origin.path,
            tag=origin.tag,
            text_length=origin.text_length,
            content_length=origin.content_length,
            **extra,
        )
        if not any(
            existing.action == decision.action
            and existing.reason == decision.reason
            and existing.attribute == decision.attribute
            and existing.target_node_id == decision.target_node_id
            for existing in origin.decisions
        ):
            origin.decisions.append(decision)

    def tag_changed(self, element, source_tag, target_tag, *, reason):
        origin = self._origin_for(element)
        if origin is None:
            return
        self._decision(
            origin,
            "convert",
            reason,
            source_tag=source_tag,
            target_tag=target_tag,
        )

    def dropped_subtree(self, element, *, reason):
        origin = self._origin_for(element)
        if origin is None:
            return
        self._decision(
            origin,
            "drop_tree",
            reason,
            removed_nodes=origin.subtree_nodes,
        )
        origin.terminal_action = "drop_tree"
        origin.terminal_reason = reason

    def dropped_tag(self, element, *, reason):
        origin = self._origin_for(element)
        if origin is None:
            return
        self._decision(origin, "drop_tag", reason)
        origin.terminal_action = "drop_tag"
        origin.terminal_reason = reason
        origin.retained_content_length = (
            0 if reason == "empty" else origin.content_length
        )

    def merged(self, target, source):
        target_origin = self._origin_for(target)
        source_origin = self._origin_for(source)
        if target_origin is None or source_origin is None:
            return
        self._decision(
            source_origin,
            "merge",
            "adjacent_same_tag",
            target_node_id=target_origin.node_id,
        )
        self._decision(
            target_origin,
            "merge_in",
            "adjacent_same_tag",
            target_node_id=source_origin.node_id,
        )
        source_origin.terminal_action = "merge"
        source_origin.terminal_reason = "adjacent_same_tag"
        source_origin.merge_target = target_origin.node_id

    def attribute_removed(self, element, attribute):
        origin = self._origin_for(element)
        if origin is None:
            return
        self._decision(
            origin,
            "drop_attribute",
            "attribute_not_allowed",
            attribute=attribute,
        )

    def attribute_maybe_changed(self, element, attribute, old_length, *, reason):
        origin = self._origin_for(element)
        if origin is None:
            return
        new_length = len(element.get(attribute) or "")
        if new_length == old_length:
            return
        self._decision(
            origin,
            "normalize_attribute",
            reason,
            attribute=attribute,
            old_length=old_length,
            new_length=new_length,
        )

    def attribute_changed(self, element, attribute, old_length, new_length):
        origin = self._origin_for(element)
        if origin is None:
            return
        self._decision(
            origin,
            "sanitize_attribute",
            "attribute_value_rejected",
            attribute=attribute,
            old_length=old_length,
            new_length=new_length,
        )

    def text_lengths(self, element):
        return (len(element.text or ""), len(element.tail or ""))

    def text_maybe_changed(self, element, before, *, reason):
        origin = self._origin_for(element)
        if origin is None:
            return
        after = self.text_lengths(element)
        if tuple(after) == tuple(before):
            return
        self._decision(
            origin,
            "normalize_text",
            reason,
            old_length=before[0] + before[1],
            new_length=after[0] + after[1],
        )

    def after_initial_cleaner(self, doc):
        for origin in self.origins:
            if not _is_attached(origin.element, doc):
                origin.detached_stage = "initial_cleaner"

    def finish(self, doc, sanitizer):
        paths = _build_paths(doc)
        surviving = {}
        for element in doc.iter():
            marker = element.get(self.marker_attribute)
            if marker:
                surviving[marker] = element
        self.output_node_count = sum(
            1 for element in doc.iterdescendants() if _tag_name(element)
        )

        for origin in self.origins:
            element = surviving.get(origin.node_id)
            if element is not None:
                origin.output_tag = _tag_name(element)
                origin.status = (
                    "kept" if origin.output_tag == origin.tag else "converted"
                )
                origin.status_reason = (
                    "tag_unchanged" if origin.status == "kept" else "tag_converted"
                )
                origin.output_path = paths.get(element)
                origin.output_text_length = len(element.text or "")
                origin.output_content_length = len(element.text_content() or "")
                origin.retained_content_length = origin.output_content_length
                origin.kept_attribute_names = tuple(
                    sorted(
                        key for key in element.attrib if key != self.marker_attribute
                    )
                )
                continue

            if origin.terminal_action == "drop_tree":
                origin.status = "removed"
                origin.status_reason = origin.terminal_reason
                origin.retained_content_length = 0
            elif origin.terminal_action == "drop_tag":
                origin.status = "unwrapped"
                origin.status_reason = origin.terminal_reason

        self._resolve_merges()
        self._classify_detached(sanitizer)
        self._propagate_ancestors()
        self._finalize_unresolved(sanitizer)
        self._resolve_merges()
        self._compute_retained_lengths()

    def _resolve_merges(self):
        for _ in range(len(self.origins) + 1):
            changed = False
            for origin in self.origins:
                if origin.merge_target is None:
                    continue
                if origin.terminal_action != "merge":
                    continue
                if origin.status in {"kept", "converted", "merged"}:
                    continue
                if (
                    origin.status == "removed"
                    and origin.covered_by == origin.merge_target
                ):
                    continue
                target = self.by_id.get(origin.merge_target)
                if target is None:
                    continue
                if target.status == "removed":
                    origin.status = "removed"
                    origin.status_reason = "merge_target_removed"
                    origin.covered_by = target.node_id
                    origin.retained_content_length = 0
                    changed = True
                elif target.status is not None:
                    origin.status = "merged"
                    origin.status_reason = "merged_into_adjacent_tag"
                    origin.retained_content_length = origin.content_length
                    changed = True
            if not changed:
                break

    def _compute_retained_lengths(self):
        for origin in self.origins:
            if origin.status not in {"unwrapped", "merged"}:
                continue
            if origin.status_reason == "empty":
                origin.retained_content_length = 0
                continue
            removed = 0
            for other in self.origins:
                if other.status != "removed":
                    continue
                parent_id = other.parent_id
                topmost = True
                while parent_id is not None and parent_id != origin.node_id:
                    if self.by_id[parent_id].status == "removed":
                        topmost = False
                        break
                    parent_id = self.by_id[parent_id].parent_id
                if topmost and parent_id == origin.node_id:
                    removed += other.content_length
            origin.retained_content_length = max(0, origin.content_length - removed)

    def _detached_status(self, origin, sanitizer):
        tag = origin.tag
        if tag in _CLEANER_KILL_TAGS:
            return "removed", "cleaner_kill"
        if tag == "style" and tag not in sanitizer.tags:
            return "removed", "cleaner_kill"
        if tag in _CLEANER_REMOVE_TAGS:
            return "unwrapped", "cleaner_remove_tag"
        if tag not in sanitizer.tags:
            return "unwrapped", "tag_not_allowed"
        return None, None

    def _classify_detached(self, sanitizer):
        for origin in self.origins:
            if origin.status is not None:
                continue
            if origin.detached_stage is None:
                continue
            status, reason = self._detached_status(origin, sanitizer)
            if status is None:
                continue
            origin.status = status
            origin.status_reason = reason
            origin.retained_content_length = (
                origin.content_length if status == "unwrapped" else 0
            )
            self._decision(
                origin,
                "drop_tree" if status == "removed" else "drop_tag",
                reason,
            )

    def _propagate_ancestors(self):
        parents = {origin.node_id: origin.parent_id for origin in self.origins}
        for origin in sorted(self.origins, key=lambda item: item.depth):
            parent_id = parents.get(origin.node_id)
            while parent_id is not None:
                parent = self.by_id[parent_id]
                if parent.status == "removed":
                    if origin.status != "removed":
                        origin.status = "removed"
                        origin.status_reason = "ancestor_removed"
                    origin.retained_content_length = 0
                    origin.covered_by = parent.node_id
                    break
                parent_id = parents.get(parent_id)

    def _finalize_unresolved(self, sanitizer):
        for origin in self.origins:
            if origin.status is not None:
                continue
            if origin.tag not in sanitizer.tags:
                origin.status = "unwrapped"
                origin.status_reason = "tag_not_allowed"
                origin.retained_content_length = origin.content_length
                self._decision(origin, "drop_tag", "tag_not_allowed")
            else:
                origin.status = "removed"
                origin.status_reason = "not_present_in_output"
                origin.retained_content_length = 0
                self._decision(origin, "drop_tree", "not_present_in_output")

    def strip_markers(self, doc):
        for element in doc.iter():
            if self.marker_attribute in element.attrib:
                del element.attrib[self.marker_attribute]

    def outcomes(self):
        return {origin.path: _outcome(origin) for origin in self.origins}

    def origin_parents(self):
        return {
            origin.path: (
                self.by_id[origin.parent_id].path if origin.parent_id else None
            )
            for origin in self.origins
        }

    def summary(
        self,
        sanitizer,
        *,
        input_length,
        input_bytes,
        output_length,
        output_bytes,
    ):
        statuses = Counter(origin.status for origin in self.origins)
        removed_roots = [
            origin
            for origin in self.origins
            if origin.status == "removed" and origin.covered_by is None
        ]
        decision_counts = Counter(
            decision.action for origin in self.origins for decision in origin.decisions
        )
        return {
            "input_length": input_length,
            "input_bytes": input_bytes,
            "output_length": output_length,
            "output_bytes": output_bytes,
            "input_nodes": len(self.origins),
            "output_nodes": self.output_node_count,
            "status_counts": dict(sorted(statuses.items())),
            "kept_nodes": statuses["kept"],
            "converted_nodes": statuses["converted"],
            "unwrapped_nodes": statuses["unwrapped"],
            "merged_nodes": statuses["merged"],
            "removed_nodes": statuses["removed"],
            "removed_branches": len(removed_roots),
            "removed_content_length": sum(
                origin.content_length for origin in removed_roots
            ),
            "decision_counts": dict(sorted(decision_counts.items())),
            "policy": _settings_snapshot(sanitizer),
        }


def _outcome(origin):
    return NodeOutcome(
        node_id=origin.node_id,
        path=origin.path,
        original_tag=origin.tag,
        status=origin.status or "removed",
        reason=origin.status_reason,
        tag=origin.output_tag,
        output_path=origin.output_path,
        source_text_length=origin.text_length,
        source_content_length=origin.content_length,
        output_text_length=origin.output_text_length,
        output_content_length=origin.output_content_length,
        retained_content_length=origin.retained_content_length,
        subtree_nodes=origin.subtree_nodes,
        attribute_names=origin.attribute_names,
        kept_attribute_names=origin.kept_attribute_names,
        removed_attribute_names=tuple(
            sorted(set(origin.attribute_names) - set(origin.kept_attribute_names))
        )
        if origin.status in {"kept", "converted"}
        else (),
        merge_target=origin.merge_target,
        covered_by=origin.covered_by,
        decisions=tuple(origin.decisions),
    )


def _settings_snapshot(sanitizer):
    return {
        "tags": sorted(sanitizer.tags),
        "attributes": {
            tag: sorted(attributes)
            for tag, attributes in sorted(sanitizer.attributes.items())
        },
        "empty": sorted(sanitizer.empty),
        "separate": sorted(sanitizer.separate),
        "whitespace": sorted(sanitizer.whitespace),
        "preserve_whitespace": sorted(sanitizer.preserve_whitespace),
        "keep_typographic_whitespace": bool(sanitizer.keep_typographic_whitespace),
        "drop_disallowed_contents": bool(sanitizer.drop_disallowed_contents),
        "add_nofollow": bool(sanitizer.add_nofollow),
        "autolink": bool(sanitizer.autolink),
        "embedded_hosts": sorted(sanitizer.embedded_hosts),
        "element_preprocessors": [
            getattr(processor, "__name__", type(processor).__name__)
            for processor in sanitizer.element_preprocessors
        ],
        "element_postprocessors": [
            getattr(processor, "__name__", type(processor).__name__)
            for processor in sanitizer.element_postprocessors
        ],
        "is_mergeable": getattr(
            sanitizer.is_mergeable, "__name__", type(sanitizer.is_mergeable).__name__
        ),
        "sanitize_href": getattr(
            sanitizer.sanitize_href, "__name__", type(sanitizer.sanitize_href).__name__
        ),
    }


def _settings_changes(old, new):
    old_snapshot = _settings_snapshot(old)
    new_snapshot = _settings_snapshot(new)
    changes = {
        "tags_added": sorted(set(new_snapshot["tags"]) - set(old_snapshot["tags"])),
        "tags_removed": sorted(set(old_snapshot["tags"]) - set(new_snapshot["tags"])),
        "attributes_added": {},
        "attributes_removed": {},
        "changed": {},
    }
    for tag in sorted(
        set(old_snapshot["attributes"]) | set(new_snapshot["attributes"])
    ):
        old_attributes = set(old_snapshot["attributes"].get(tag, ()))
        new_attributes = set(new_snapshot["attributes"].get(tag, ()))
        added = sorted(new_attributes - old_attributes)
        removed = sorted(old_attributes - new_attributes)
        if added:
            changes["attributes_added"][tag] = added
        if removed:
            changes["attributes_removed"][tag] = removed

    for key in (
        "empty",
        "separate",
        "whitespace",
        "preserve_whitespace",
        "embedded_hosts",
    ):
        added = sorted(set(new_snapshot[key]) - set(old_snapshot[key]))
        removed = sorted(set(old_snapshot[key]) - set(new_snapshot[key]))
        if added:
            changes[f"{key}_added"] = added
        if removed:
            changes[f"{key}_removed"] = removed

    for key in (
        "keep_typographic_whitespace",
        "drop_disallowed_contents",
        "add_nofollow",
        "autolink",
        "element_preprocessors",
        "element_postprocessors",
        "is_mergeable",
        "sanitize_href",
    ):
        if old_snapshot[key] != new_snapshot[key]:
            changes["changed"][key] = {
                "old": old_snapshot[key],
                "new": new_snapshot[key],
            }
    return changes


def _change_kind(old, new):
    if old.status == "removed" and new.status == "removed":
        return "unchanged"
    if old.status == "removed":
        return "restored"
    if new.status == "removed":
        return "removed_subtree"
    if new.status == "unwrapped" and old.status != "unwrapped":
        return "unwrapped"
    if old.status == "unwrapped" and new.status != "unwrapped":
        return "rewrapped"
    if (old.status == "merged") != (new.status == "merged"):
        return "merge_changed"
    if old.tag != new.tag:
        return "format_changed"
    if old.kept_attribute_names != new.kept_attribute_names:
        return "attributes_changed"
    if (
        old.output_content_length is not None
        and new.output_content_length is not None
        and old.output_content_length != new.output_content_length
    ):
        return "text_changed"
    if old.retained_content_length != new.retained_content_length:
        return "text_changed"
    if old.source_text_length != new.source_text_length:
        return "text_changed"
    return "unchanged"


def _difference_summary(change, old, new):
    if change == "removed_subtree":
        return f"removed {new.subtree_nodes} node(s), {new.source_content_length} chars"
    if change == "restored":
        return f"old policy removed it; new outcome is {new.status}"
    if change == "unwrapped":
        if new.retained_content_length:
            return (
                f"outer <{old.original_tag}> removed, contents kept; "
                f"{new.retained_content_length} chars retained"
            )
        return f"outer <{old.original_tag}> removed; no content remained"
    if change == "rewrapped":
        return f"old policy unwrapped it; new outcome is {new.status}"
    if change == "format_changed":
        return (
            f"<{old.original_tag}> written as "
            f"{old.tag or 'removed'} -> {new.tag or 'removed'}"
        )
    if change == "attributes_changed":
        return (
            "attributes "
            f"{list(old.kept_attribute_names)} -> {list(new.kept_attribute_names)}"
        )
    if change == "merge_changed":
        return f"merge behaviour changed ({old.status} -> {new.status})"
    if change == "text_changed":
        return f"text length {old.output_content_length} -> {new.output_content_length}"
    return "unchanged"


def _diff_entries(old_outcomes, new_outcomes, parents, *, include_unchanged):
    entries = []
    for path, old in old_outcomes.items():
        new = new_outcomes.get(path)
        if new is None:
            new = old
        change = _change_kind(old, new)
        if change == "unchanged" and not include_unchanged:
            continue
        entries.append(
            DiffEntry(
                node_id=old.node_id,
                path=path,
                tag=old.original_tag,
                change=change,
                old=old,
                new=new,
                summary=_difference_summary(change, old, new),
            )
        )

    by_path = {entry.path: entry for entry in entries}
    result = []
    for item in entries:
        entry = item
        if entry.change in {"removed_subtree", "unwrapped"}:
            parent = parents.get(entry.path)
            while parent is not None:
                candidate = by_path.get(parent)
                if candidate is not None and candidate.change == entry.change:
                    entry = replace(entry, covered_by=candidate.node_id)
                    break
                parent = parents.get(parent)
        result.append(entry)
    return result


def _format_status(outcome):
    reason = f"({outcome.reason})" if outcome.reason else ""
    if outcome.status in {"kept", "converted"} and outcome.tag:
        if outcome.status == "converted":
            return f"converted->{outcome.tag}{reason}"
        return f"kept({outcome.tag})"
    if outcome.status == "merged":
        return f"merged->{outcome.merge_target or '?'}"
    return f"{outcome.status}{reason}"


def _format_chars(outcome):
    if outcome.status == "removed":
        return str(outcome.source_content_length)
    if outcome.status == "unwrapped":
        return str(outcome.retained_content_length)
    if outcome.output_content_length is not None:
        return str(outcome.output_content_length)
    return str(outcome.retained_content_length)


def _format_table(entries):
    if not entries:
        return "No policy differences."
    rows = [
        (
            "CHANGE",
            "PATH",
            "TAG",
            "OLD",
            "NEW",
            "CHARS",
            "DETAIL",
        )
    ]
    for entry in entries:
        covered = f" (within {entry.covered_by})" if entry.covered_by else ""
        rows.append(
            (
                entry.change,
                entry.path,
                entry.tag,
                _format_status(entry.old),
                _format_status(entry.new),
                _format_chars(entry.new),
                entry.summary + covered,
            )
        )
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    lines = []
    for row in rows:
        lines.append(
            "  ".join(
                value.ljust(widths[index]) for index, value in enumerate(row)
            ).rstrip()
        )
    return "\n".join(lines)


def _coerce_sanitizer(value, *, default=None):
    if value is None:
        return default
    if isinstance(value, Sanitizer):
        return value
    if isinstance(value, str):
        value = json.loads(value)
    if isinstance(value, Mapping):
        return Sanitizer(dict(value))
    return value


def preview_policy(
    html,
    old_settings=None,
    new_settings=None,
    *,
    old=None,
    new=None,
    old_rules=None,
    new_rules=None,
    include_unchanged=False,
):
    """Compare sanitized output under an old and a new policy.

    ``old_settings``/``new_settings`` may be setting dictionaries or
    :class:`~html_sanitizer.sanitizer.Sanitizer` instances. ``old`` and ``new``
    are aliases. Omitted policies fall back to the default settings.
    """

    if not isinstance(html, (str, bytes)) and isinstance(new_settings, (str, bytes)):
        html, old_settings, new_settings = new_settings, html, old_settings

    if isinstance(html, bytes):
        html = html.decode("utf-8")

    if not isinstance(html, str):
        raise TypeError("html must be a string")

    if old_rules is not None:
        old = old_rules
    if new_rules is not None:
        new = new_rules

    old_value = old if old is not None else old_settings
    new_value = new if new is not None else new_settings
    old_sanitizer = _coerce_sanitizer(old_value, default=Sanitizer())
    new_sanitizer = _coerce_sanitizer(new_value, default=Sanitizer())

    old_trace = _Trace()
    new_trace = _Trace()
    old_html = old_sanitizer.sanitize(html, trace=old_trace)
    new_html = new_sanitizer.sanitize(html, trace=new_trace)

    input_length = len(html)
    input_bytes = len(html.encode("utf-8"))
    old_summary = old_trace.summary(
        old_sanitizer,
        input_length=input_length,
        input_bytes=input_bytes,
        output_length=len(old_html),
        output_bytes=len(old_html.encode("utf-8")),
    )
    new_summary = new_trace.summary(
        new_sanitizer,
        input_length=input_length,
        input_bytes=input_bytes,
        output_length=len(new_html),
        output_bytes=len(new_html.encode("utf-8")),
    )

    differences = _diff_entries(
        old_trace.outcomes(),
        new_trace.outcomes(),
        old_trace.origin_parents(),
        include_unchanged=include_unchanged,
    )
    return PolicyPreview(
        old_html=old_html,
        new_html=new_html,
        old_summary=old_summary,
        new_summary=new_summary,
        policy_changes=_settings_changes(old_sanitizer, new_sanitizer),
        differences=tuple(differences),
    )


preview = preview_policy
compare_policies = preview_policy
policy_preview = preview_policy
sanitize_preview = preview_policy
preview_html = preview_policy


def _load_settings(path):
    if path is None:
        return None
    if path == "-":
        return json.load(sys.stdin)
    config_path = Path(path)
    text = config_path.read_text(encoding="utf-8")
    if config_path.suffix == ".py":
        namespace = {}
        exec(compile(text, str(config_path), "exec"), namespace)
        return namespace.get("SETTINGS", namespace.get("settings"))
    return json.loads(text)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="html-sanitizer-preview",
        description=(
            "Compare two HTML sanitizer policies offline. Debug output contains "
            "paths, tag names and lengths only; text and attribute values are "
            "never logged."
        ),
    )
    parser.add_argument("html", nargs="?", help="HTML file, or - for stdin")
    parser.add_argument("--old", "--old-config", dest="old_config")
    parser.add_argument("--new", "--new-config", dest="new_config")
    parser.add_argument("--format", choices=("table", "json"), default="table")
    parser.add_argument("--include-unchanged", action="store_true")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="omit sanitized HTML payloads from the JSON report",
    )
    args = parser.parse_args(argv)

    if args.html in (None, "-"):
        html = sys.stdin.read()
    else:
        html = Path(args.html).read_text(encoding="utf-8")

    result = preview_policy(
        html,
        _load_settings(args.old_config),
        _load_settings(args.new_config),
        include_unchanged=args.include_unchanged,
    )
    if args.format == "json":
        print(result.to_json(include_outputs=not args.debug))
    else:
        print(result.format_table())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
