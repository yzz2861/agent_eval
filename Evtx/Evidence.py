"""Derive field-level evidence bundles from EVTX files.

The module deliberately keeps the evidence package independent from the
original EVTX bytes.  A bundle contains only allow-listed fields, a manifest
that describes how values were selected, and source references that can later
be checked against the original file.  Missing values are represented with an
explicit status instead of being silently omitted.

Typical use::

    from Evtx.Evidence import actor_only_policy, create_evidence_bundle

    create_evidence_bundle("Security.evtx", "narrow", actor_only_policy())
    create_evidence_bundle("Security.evtx", "broad", actor_and_org_unit_policy())

The bundle layout is:

    manifest.json       package metadata, scope, source digest, package digest
    records.jsonl       one JSON object per selected record
    relationships.json  shared object identities allowed by the policy

All JSON is written with sorted keys and compact separators.  Digests are
SHA-256 over the UTF-8 encoded canonical JSON described by
``canonicalization`` in the manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import Evtx.Evtx as evtx
import Evtx.Nodes as e_nodes


BUNDLE_FORMAT = "evtx-evidence-bundle"
BUNDLE_VERSION = 1

STATUS_PRESENT = "present"
STATUS_NOT_COLLECTED = "not_collected"
STATUS_REDACTED = "redacted"
STATUS_PARSE_FAILURE = "parse_failure"
MISSING_STATUSES = (STATUS_NOT_COLLECTED, STATUS_REDACTED, STATUS_PARSE_FAILURE)

ACCESS_INCLUDE = "include"
ACCESS_REDACT = "redact"
ACCESS_OMIT = "omit"

REASON_SOURCE_ABSENT = "source_field_absent"
REASON_APPROVAL = "approval_withheld"
REASON_POLICY_EXCLUDED = "policy_excluded"
REASON_PARSER = "parser_error"


class EvidenceError(Exception):
    """Base error for evidence bundle creation and verification."""


class BundleVerificationError(EvidenceError):
    """Raised when a bundle is structurally invalid."""


@dataclass(frozen=True)
class FieldRule:
    """Describe one logical field and the BXML paths that may supply it.

    Paths are relative to the Event element.  ``Data[@Name='X']`` predicates are
    supported, as is a final ``/@Attribute`` segment.  The first path that
    yields a non-empty value wins; this keeps the rule tolerant of event
    schemas that use one of several common Windows field names.
    """

    name: str
    paths: Tuple[str, ...]
    identity: bool = False
    access: str = ACCESS_INCLUDE
    description: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.paths, str):
            object.__setattr__(self, "paths", (self.paths,))
        if self.access not in (ACCESS_INCLUDE, ACCESS_REDACT, ACCESS_OMIT):
            raise ValueError("invalid field access: {!r}".format(self.access))
        if not self.paths and self.access == ACCESS_INCLUDE:
            raise ValueError("field {!r} has no selector".format(self.name))

    def public_dict(self) -> Dict[str, Any]:
        """Return a manifest-safe description.

        Selectors for withheld fields are not published: the reviewer can see
        that a field was withheld, but cannot learn the source column name from
        the narrow package.
        """

        result = {
            "name": self.name,
            "access": self.access,
            "identity": self.identity,
        }
        if self.access == ACCESS_INCLUDE:
            result["paths"] = list(self.paths)
        if self.description:
            result["description"] = self.description
        return result


@dataclass(frozen=True)
class EvidencePolicy:
    """A field allow-list plus explicit redaction decisions."""

    name: str
    fields: Tuple[FieldRule, ...]
    metadata: Tuple[FieldRule, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", tuple(self.fields))
        object.__setattr__(self, "metadata", tuple(self.metadata))
        seen = set()
        for field in self.fields + self.metadata:
            if field.name in seen:
                raise ValueError("duplicate field name: {!r}".format(field.name))
            seen.add(field.name)

    @property
    def visible_identity_fields(self) -> Tuple[str, ...]:
        return tuple(
            field.name for field in self.fields if field.identity and field.access == ACCESS_INCLUDE
        )

    def field_by_name(self, name: str) -> FieldRule:
        for field in self.fields:
            if field.name == name:
                return field
        raise KeyError(name)

    def public_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "fields": [field.public_dict() for field in self.fields],
            "metadata": [field.public_dict() for field in self.metadata],
        }


ACTOR_PATHS = (
    "EventData/Data[@Name='SubjectUserName']",
    "EventData/Data[@Name='TargetUserName']",
    "System/Security/@UserID",
)

ORG_UNIT_PATHS = (
    "EventData/Data[@Name='SubjectDomainName']",
    "EventData/Data[@Name='TargetDomainName']",
    "System/Computer",
)

DEFAULT_METADATA = (
    FieldRule("event_id", ("System/EventID",), description="Windows event identifier"),
    FieldRule("event_time", ("System/TimeCreated/@SystemTime",), description="Event creation time"),
    FieldRule("provider", ("System/Provider/@Name",), description="Event provider"),
    FieldRule("channel", ("System/Channel",), description="Event channel"),
)


def _actor_rule(access: str) -> FieldRule:
    return FieldRule("actor", ACTOR_PATHS, identity=True, access=access, description="User that performed the change")


def _org_unit_rule(access: str) -> FieldRule:
    return FieldRule("org_unit", ORG_UNIT_PATHS, identity=True, access=access, description="Organizational unit")


def actor_only_policy() -> EvidencePolicy:
    """Policy that releases the actor and withholds organizational unit values."""

    return EvidencePolicy(
        name="actor-only",
        description="Actor is visible; organizational unit is approval-redacted.",
        fields=(_actor_rule(ACCESS_INCLUDE), _org_unit_rule(ACCESS_REDACT)),
        metadata=DEFAULT_METADATA,
    )


def actor_and_org_unit_policy() -> EvidencePolicy:
    """Policy that releases both actor and organizational unit values."""

    return EvidencePolicy(
        name="actor-and-org-unit",
        description="Actor and organizational unit are visible.",
        fields=(_actor_rule(ACCESS_INCLUDE), _org_unit_rule(ACCESS_INCLUDE)),
        metadata=DEFAULT_METADATA,
    )


POLICIES = {
    "actor-only": actor_only_policy,
    "actor-and-org-unit": actor_and_org_unit_policy,
    "narrow": actor_only_policy,
    "broad": actor_and_org_unit_policy,
}


def policy_for_scope(scope: str) -> EvidencePolicy:
    """Return a built-in policy by name (``actor-only`` or ``actor-and-org-unit``)."""

    try:
        factory = POLICIES[scope]
    except KeyError:
        raise ValueError("unknown evidence policy: {!r}".format(scope))
    return factory()


@dataclass
class _SourceValue:
    value: str
    offset: Optional[int]
    length: Optional[int]
    encoding: str
    raw_sha256: Optional[str]
    node_type: str

    def source_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "length": self.length,
            "encoding": self.encoding,
            "raw_sha256": self.raw_sha256,
            "node_type": self.node_type,
        }


@dataclass
class _SourceElement:
    tag: str
    path: str
    attrs: Dict[str, _SourceValue]
    text_parts: List[_SourceValue]
    children: List["_SourceElement"]

    def text_value(self) -> str:
        return "".join(part.value for part in self.text_parts)


class _SourceTree:
    """A rendered XML view whose values retain byte ranges in the EVTX file."""

    def __init__(self, root: _SourceElement):
        self.root = root


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256_file(path: str) -> Tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size


def _encoding_for_node(node: Any) -> str:
    if isinstance(node, e_nodes.WstringTypeNode):
        return "utf-16le"
    if isinstance(node, e_nodes.StringTypeNode):
        return "ascii"
    return "binary"


def _node_bytes(node: Any, offset: int, length: int) -> Optional[bytes]:
    if length <= 0:
        return b""
    try:
        return bytes(node._buf[offset : offset + length])
    except Exception:
        return None


def _source_value_from_variant(node: Any) -> _SourceValue:
    offset = getattr(node, "offset", lambda: None)()
    length = getattr(node, "length", lambda: None)()
    encoding = _encoding_for_node(node)
    raw = _node_bytes(node, offset, length) if offset is not None and length is not None else None
    return _SourceValue(
        value=node.string(),
        offset=offset,
        length=length,
        encoding=encoding,
        raw_sha256=_sha256_bytes(raw) if raw is not None else None,
        node_type=type(node).__name__,
    )


def _source_value_from_value_node(node: e_nodes.ValueNode) -> _SourceValue:
    return _source_value_from_variant(node.value())


def _source_value_from_cdata(node: e_nodes.CDataSectionNode) -> _SourceValue:
    value = node.cdata()
    length = node.length()
    raw = _node_bytes(node, node.offset(), length)
    return _SourceValue(
        value=value,
        offset=node.offset(),
        length=length,
        encoding="binary",
        raw_sha256=_sha256_bytes(raw) if raw is not None else None,
        node_type=type(node).__name__,
    )


def _element_path(parent_path: str, tag: str, attrs: Dict[str, _SourceValue]) -> str:
    name = attrs.get("Name")
    predicate = ""
    if name is not None and name.value:
        escaped = name.value.replace("\\", "\\\\").replace("'", "\\'")
        predicate = "[@Name='{}']".format(escaped)
    return "{}/{}{}".format(parent_path.rstrip("/"), tag, predicate) if parent_path else "/" + tag


def _rebase_element(element: _SourceElement, parent_path: str) -> None:
    """Attach a nested BXML element below its rendered parent."""

    if element.tag == "#fragment":
        for child in element.children:
            _rebase_element(child, parent_path)
        return
    element.path = _element_path(parent_path, element.tag, element.attrs)
    for child in element.children:
        _rebase_element(child, element.path)


def _build_element(
    node: e_nodes.OpenStartElementNode,
    substitutions: Sequence[Any],
    parent_path: str,
) -> _SourceElement:
    attrs: Dict[str, _SourceValue] = {}
    texts: List[_SourceValue] = []
    children: List[_SourceElement] = []

    for child in node.children():
        if isinstance(child, e_nodes.AttributeNode):
            attr_value = child.attribute_value()
            if isinstance(attr_value, e_nodes.ValueNode):
                attrs[child.attribute_name().string()] = _source_value_from_value_node(attr_value)
            elif isinstance(attr_value, (e_nodes.NormalSubstitutionNode, e_nodes.ConditionalSubstitutionNode)):
                resolved = _resolve_substitution(attr_value, substitutions)
                if isinstance(resolved, _SourceValue):
                    attrs[child.attribute_name().string()] = resolved
                elif isinstance(resolved, _SourceElement):
                    children.append(resolved)
        elif isinstance(child, e_nodes.OpenStartElementNode):
            children.append(_build_element(child, substitutions, _element_path(parent_path, node.tag_name(), attrs)))
        elif isinstance(child, e_nodes.ValueNode):
            texts.append(_source_value_from_value_node(child))
        elif isinstance(child, (e_nodes.NormalSubstitutionNode, e_nodes.ConditionalSubstitutionNode)):
            resolved = _resolve_substitution(child, substitutions)
            if isinstance(resolved, _SourceValue):
                texts.append(resolved)
            elif isinstance(resolved, _SourceElement):
                children.append(resolved)
        elif isinstance(child, e_nodes.CDataSectionNode):
            texts.append(_source_value_from_cdata(child))
        elif isinstance(child, e_nodes.EntityReferenceNode):
            value = child.entity_reference()
            texts.append(_SourceValue(value, child.offset(), child.length(), "utf-8", None, type(child).__name__))
        elif isinstance(child, e_nodes.CharacterReferenceNode):
            value = child.entity_reference()
            texts.append(_SourceValue(value, child.offset(), child.length(), "utf-8", None, type(child).__name__))

    path = _element_path(parent_path, node.tag_name(), attrs)
    for child in children:
        _rebase_element(child, path)
    return _SourceElement(node.tag_name(), path, attrs, texts, children)


def _resolve_substitution(node: Any, substitutions: Sequence[Any]) -> Optional[Any]:
    if isinstance(node, e_nodes.ConditionalSubstitutionNode):
        index = node.index()
        if index >= len(substitutions) or isinstance(substitutions[index], e_nodes.NullTypeNode):
            return None
    else:
        index = node.index()
        if index >= len(substitutions):
            raise ValueError("substitution index {} out of range".format(index))

    value = substitutions[index]
    if isinstance(value, e_nodes.BXmlTypeNode):
        nested_root = value.root()
        nested_subs = nested_root.substitutions()
        nested_elements: List[_SourceElement] = []
        for child in nested_root.template().children():
            if isinstance(child, e_nodes.OpenStartElementNode):
                nested_elements.append(_build_element(child, nested_subs, ""))
        if len(nested_elements) == 1:
            return nested_elements[0]
        if nested_elements:
            # BXML normally renders one document element.  Preserve all of
            # them under a synthetic element rather than dropping data.
            return _SourceElement("#fragment", "#fragment", {}, [], nested_elements)
        return None
    if isinstance(value, e_nodes.NullTypeNode):
        return _SourceValue("", value.offset(), value.length(), "binary", None, type(value).__name__)
    return _source_value_from_variant(value)


def _build_source_tree(record: evtx.Record) -> _SourceTree:
    root_node = record.root()
    substitutions = root_node.substitutions()
    template_children = root_node.template().children()
    elements: List[_SourceElement] = []
    for child in template_children:
        if isinstance(child, e_nodes.OpenStartElementNode):
            elements.append(_build_element(child, substitutions, ""))
    if len(elements) != 1:
        raise ValueError("record template produced {} document elements".format(len(elements)))
    return _SourceTree(elements[0])


def _parse_part(part: str) -> Tuple[str, Optional[str], Optional[str]]:
    match = re.match(r"^([^\[\]]+?)(?:\[@([^=\]]+)=['\"](.*)['\"]\])?$", part)
    if not match:
        raise ValueError("invalid field selector: {!r}".format(part))
    return match.group(1), match.group(2), match.group(3)


def _matching_children(elements: Iterable[_SourceElement], part: str) -> List[_SourceElement]:
    tag, attr_name, attr_value = _parse_part(part)
    result = []
    for element in elements:
        if element.tag != tag:
            continue
        if attr_name is not None:
            value = element.attrs.get(attr_name)
            if value is None or value.value != attr_value:
                continue
        result.append(element)
    return result


def _select_hits(tree: _SourceTree, selector: str) -> List[Tuple[str, str, _SourceValue]]:
    """Return ``(path, kind, value)`` matches for a selector.

    ``kind`` is either ``text`` or ``attr:<name>``.
    """

    path = selector.strip()
    descendant = path.startswith(".//")
    if descendant:
        path = path[3:]
    else:
        path = path.lstrip("/")
        if path.startswith("./"):
            path = path[2:]
    parts = [part for part in path.split("/") if part]
    if not parts:
        return []
    if parts[0] == tree.root.tag:
        parts = parts[1:]

    current = [tree.root]
    for index, part in enumerate(parts):
        if part.startswith("@"):
            attr_name = part[1:]
            hits = []
            for element in current:
                value = element.attrs.get(attr_name)
                if value is not None:
                    hits.append((element.path + "/@" + attr_name, "attr:" + attr_name, value))
            return hits
        if index == 0 and descendant:
            candidates: List[_SourceElement] = []
            stack = list(tree.root.children)
            while stack:
                candidate = stack.pop(0)
                candidates.append(candidate)
                stack.extend(candidate.children)
            current = _matching_children(candidates, part)
        else:
            candidates = []
            for element in current:
                candidates.extend(element.children)
            current = _matching_children(candidates, part)
        if not current:
            return []

    return [(element.path, "text", _text_source_value(element)) for element in current]


def _text_source_value(element: _SourceElement) -> _SourceValue:
    if len(element.text_parts) == 1:
        return element.text_parts[0]
    return _SourceValue(
        value=element.text_value(),
        offset=None,
        length=None,
        encoding="utf-8",
        raw_sha256=None,
        node_type="Composite",
    )


def _is_collectable(value: str) -> bool:
    return value.strip() not in ("", "-")


def _source_segments(element: _SourceElement, kind: str) -> List[Dict[str, Any]]:
    if kind.startswith("attr:"):
        value = element.attrs[kind.split(":", 1)[1]]
        return [value.source_dict()]
    return [part.source_dict() for part in element.text_parts]


def _extract_rule(tree: _SourceTree, rule: FieldRule) -> Dict[str, Any]:
    if rule.access == ACCESS_OMIT:
        return {
            "name": rule.name,
            "status": STATUS_NOT_COLLECTED,
            "reason": REASON_POLICY_EXCLUDED,
            "value": None,
        }
    if rule.access == ACCESS_REDACT and not rule.paths:
        return {
            "name": rule.name,
            "status": STATUS_REDACTED,
            "reason": REASON_APPROVAL,
            "value": None,
        }

    present_hit: Optional[Tuple[str, str, _SourceValue, _SourceElement]] = None
    for selector in rule.paths:
        for path, kind, value in _select_hits(tree, selector):
            if _is_collectable(value.value):
                element = _find_element_by_path(tree.root, path.split("/@", 1)[0])
                if element is not None:
                    present_hit = (selector, kind, value, element)
                    break
        if present_hit is not None:
            break

    if present_hit is None:
        return {
            "name": rule.name,
            "status": STATUS_NOT_COLLECTED,
            "reason": REASON_SOURCE_ABSENT,
            "value": None,
        }

    selector, kind, value, element = present_hit
    if rule.access == ACCESS_REDACT:
        return {
            "name": rule.name,
            "status": STATUS_REDACTED,
            "reason": REASON_APPROVAL,
            "value": None,
        }

    return {
        "name": rule.name,
        "status": STATUS_PRESENT,
        "value": value.value,
        "value_sha256": _sha256_text(value.value),
        "selector": selector,
        "path": element.path + ("/@" + kind.split(":", 1)[1] if kind.startswith("attr:") else ""),
        "source": {"segments": _source_segments(element, kind)},
    }


def _find_element_by_path(root: _SourceElement, path: str) -> Optional[_SourceElement]:
    stack = [root]
    while stack:
        element = stack.pop()
        if element.path == path:
            return element
        stack.extend(element.children)
    return None


def _missing_fields(policy: EvidencePolicy, status: str, reason: str) -> List[Dict[str, Any]]:
    return _missing_rules(policy.fields, status, reason)


def _missing_rules(rules: Sequence[FieldRule], status: str, reason: str) -> List[Dict[str, Any]]:
    result = []
    for field in rules:
        item = {"name": field.name, "status": status, "reason": reason, "value": None}
        result.append(item)
    return result


def _format_exception(exc: BaseException) -> str:
    message = str(exc).strip()
    if message:
        return "{}: {}".format(type(exc).__name__, message)
    return type(exc).__name__


def _record_header(record: evtx.Record, chunk_index: int, record_index: int) -> Dict[str, Any]:
    chunk = record._chunk
    raw = record.data()
    try:
        timestamp = record.timestamp().isoformat()
    except Exception:
        timestamp = None
    return {
        "number": record.record_num(),
        "offset": record.offset(),
        "length": record.length(),
        "chunk_offset": chunk.offset(),
        "chunk_index": chunk_index,
        "record_index": record_index,
        "raw_sha256": _sha256_bytes(raw),
        "timestamp": timestamp,
        "header_valid": bool(record.verify()),
    }


def _metadata(tree: _SourceTree, policy: EvidencePolicy) -> List[Dict[str, Any]]:
    result = []
    for rule in policy.metadata:
        result.append(_extract_rule(tree, rule))
    return result


def _record_digest(record: Dict[str, Any]) -> str:
    material = {key: value for key, value in record.items() if key not in ("digest", "forensic_digest")}
    return _sha256_text(_canonical_json(material))


def _record_content_digest(record: Dict[str, Any]) -> str:
    material = {"metadata": record.get("metadata", []), "fields": record.get("fields", [])}
    return _sha256_text(_canonical_json(material))


def record_digest(record: Dict[str, Any]) -> str:
    """Recompute a record digest from retained record content only."""

    return _record_digest(record)


def record_content_digest(record: Dict[str, Any]) -> str:
    """Recompute the digest over only the retained metadata and field excerpts."""

    return _record_content_digest(record)


def _relationship_digest(group: Dict[str, Any]) -> str:
    material = {key: value for key, value in group.items() if key != "digest"}
    return _sha256_text(_canonical_json(material))


def relationship_digest(relationships: Dict[str, Any]) -> str:
    """Recompute the relationship digest from its retained objects and links."""

    return _relationship_digest(relationships)


def _object_token(kind: str, value: str) -> str:
    return "{}:sha256:{}".format(kind, _sha256_text(kind + "\x00" + value))


def _relationships(records: Sequence[Dict[str, Any]], policy: EvidencePolicy) -> Dict[str, Any]:
    visible = {
        field.name: field
        for field in policy.fields
        if field.identity and field.access == ACCESS_INCLUDE
    }
    buckets: Dict[Tuple[str, str], List[int]] = {}
    for record in records:
        record_number = record["record"]["number"]
        for field_entry in record["fields"]:
            if field_entry["status"] != STATUS_PRESENT:
                continue
            if field_entry["name"] not in visible:
                continue
            value = field_entry["value"]
            buckets.setdefault((field_entry["name"], value), []).append(record_number)

    objects = []
    links = []
    for (kind, value), numbers in sorted(buckets.items(), key=lambda item: (item[0][0], item[0][1])):
        token = _object_token(kind, value)
        members = sorted(set(numbers))
        objects.append(
            {
                "kind": kind,
                "value": value,
                "token": token,
                "records": members,
            }
        )
        if len(members) > 1:
            links.append(
                {
                    "kind": "same_" + kind,
                    "object_token": token,
                    "records": members,
                }
            )

    group = {
        "scope": list(policy.visible_identity_fields),
        "objects": objects,
        "relationships": links,
    }
    group["digest"] = _relationship_digest(group)
    return group


def _package_digest(
    manifest: Dict[str, Any],
    records: Sequence[Dict[str, Any]],
    relationships: Dict[str, Any],
) -> str:
    source = manifest["source"]
    material = {
        "format": manifest["format"],
        "version": manifest["version"],
        "policy": manifest["policy"],
        "source": {
            "artifact": source["artifact"],
            "sha256": source["sha256"],
            "size": source["size"],
        },
        "selection": manifest["selection"],
        "summary": manifest.get("summary"),
        "canonicalization": manifest.get("canonicalization"),
        "records_file": manifest.get("records_file"),
        "relationships_file": manifest.get("relationships_file"),
        "reference_protocol": manifest.get("reference_protocol"),
        "missing_reasons": manifest.get("missing_reasons"),
        "records": [
            {
                "number": record["record"]["number"],
                "offset": record["record"]["offset"],
                "length": record["record"]["length"],
                "raw_sha256": record["record"]["raw_sha256"],
                "digest": record["digest"],
            }
            for record in records
        ],
        "relationships_digest": relationships["digest"],
    }
    return _sha256_text(_canonical_json(material))


def package_digest(
    manifest: Dict[str, Any],
    records: Sequence[Dict[str, Any]],
    relationships: Dict[str, Any],
) -> str:
    """Recompute the package forensic digest from retained content."""

    return _package_digest(manifest, records, relationships)


def recompute_digests(
    manifest: Dict[str, Any],
    records: List[Dict[str, Any]],
    relationships: Dict[str, Any],
) -> str:
    """Refresh record, relationship, and package digests in place.

    This is the supported way for a reviewer to demonstrate that the forensic
    digest follows from the retained fields.  It does not authenticate against
    the original file; use :func:`verify_bundle` with ``source=`` for that.
    """

    for record in records:
        record["content_digest"] = _record_content_digest(record)
        record["digest"] = _record_digest(record)
    relationships["digest"] = _relationship_digest(relationships)
    if "selection" in manifest:
        manifest["selection"]["record_count"] = len(records)
    manifest["summary"] = _summarize(records)
    manifest["forensic_digest"] = _package_digest(manifest, records, relationships)
    return manifest["forensic_digest"]


def _parse_record_numbers(value: Any) -> Optional[List[int]]:
    if value is None:
        return None
    if isinstance(value, str):
        result: List[int] = []
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_text, end_text = part.split("-", 1)
                start, end = int(start_text), int(end_text)
                if end < start:
                    raise ValueError("invalid record range: {!r}".format(part))
                result.extend(range(start, end + 1))
            else:
                result.append(int(part))
        return result
    return [int(number) for number in value]


def _iter_records(source: str) -> Iterable[Tuple[evtx.Record, int, int]]:
    with evtx.Evtx(source) as log:
        for chunk_index, chunk in enumerate(log.chunks()):
            record_index = 0
            try:
                iterator = chunk.records()
                while True:
                    try:
                        record = next(iterator)
                    except StopIteration:
                        break
                    yield record, chunk_index, record_index
                    record_index += 1
            except Exception:
                # A damaged chunk can terminate its record stream.  Continue
                # with later chunks; the damaged record itself is represented
                # when the failure occurs after a record header was obtained.
                continue


def _build_record_entry(
    record: evtx.Record,
    chunk_index: int,
    record_index: int,
    policy: EvidencePolicy,
) -> Dict[str, Any]:
    header = _record_header(record, chunk_index, record_index)
    try:
        tree = _build_source_tree(record)
        metadata = _metadata(tree, policy)
        fields = [_extract_rule(tree, rule) for rule in policy.fields]
        status = "ok" if header["header_valid"] else "header_invalid"
        error = None
    except Exception as exc:
        metadata = _missing_rules(policy.metadata, STATUS_PARSE_FAILURE, REASON_PARSER)
        fields = _missing_fields(policy, STATUS_PARSE_FAILURE, REASON_PARSER)
        status = STATUS_PARSE_FAILURE
        error = _format_exception(exc)

    entry = {
        "record": header,
        "status": status,
        "metadata": metadata,
        "fields": fields,
    }
    if error:
        entry["error"] = error
    entry["content_digest"] = _record_content_digest(entry)
    entry["digest"] = _record_digest(entry)
    return entry


def _iter_selected_entries(
    source: str,
    policy: EvidencePolicy,
    record_numbers: Optional[Sequence[int]],
    start: Optional[int],
    end: Optional[int],
    limit: Optional[int],
) -> Iterable[Dict[str, Any]]:
    wanted = set(record_numbers) if record_numbers is not None else None
    selected = 0
    for record, chunk_index, record_index in _iter_records(source):
        try:
            number = record.record_num()
        except Exception:
            continue
        if wanted is not None and number not in wanted:
            continue
        if start is not None and number < start:
            continue
        if end is not None and number > end:
            continue
        yield _build_record_entry(record, chunk_index, record_index, policy)
        selected += 1
        if limit is not None and selected >= limit:
            break


def _write_json(path: str, value: Any) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _write_jsonl(path: str, records: Sequence[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(_canonical_json(record))
            stream.write("\n")


@dataclass
class EvidenceBundle:
    """Loaded evidence bundle."""

    path: str
    manifest: Dict[str, Any]
    records: List[Dict[str, Any]]
    relationships: Dict[str, Any]

    def record(self, number: int) -> Dict[str, Any]:
        for entry in self.records:
            if entry["record"]["number"] == number:
                return entry
        raise KeyError(number)

    def field(self, number: int, name: str) -> Dict[str, Any]:
        for entry in self.record(number)["fields"]:
            if entry["name"] == name:
                return entry
        raise KeyError(name)

    def objects(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return allowed identity objects, optionally filtered by field kind."""

        return [obj for obj in self.relationships.get("objects", []) if kind is None or obj["kind"] == kind]

    def related_records(self, kind: str, value: str) -> List[int]:
        """Return record numbers sharing one allowed identity value."""

        for obj in self.objects(kind):
            if obj["value"] == value:
                return list(obj["records"])
        return []

    def __fspath__(self) -> str:
        return self.path

    def __str__(self) -> str:
        return self.path


def create_evidence_bundle(
    source: str,
    destination: str,
    policy: Any,
    record_numbers: Optional[Any] = None,
    start: Optional[int] = None,
    end: Optional[int] = None,
    limit: Optional[int] = None,
    overwrite: bool = False,
) -> EvidenceBundle:
    """Create an evidence bundle and return its in-memory representation.

    ``record_numbers`` accepts a sequence or a string such as ``"1-3,9"``.
    Selection is applied to the record number stored in the EVTX record
    header.  ``limit`` is applied after ``start``/``end``/``record_numbers``.
    """

    source = os.fspath(source)
    destination = os.fspath(destination)
    if not os.path.isfile(source):
        raise FileNotFoundError(source)
    if isinstance(policy, str):
        policy = policy_for_scope(policy)
    if not isinstance(policy, EvidencePolicy):
        raise TypeError("policy must be an EvidencePolicy or built-in policy name")
    if os.path.exists(destination) and not overwrite:
        raise FileExistsError(destination)

    wanted = _parse_record_numbers(record_numbers)
    if wanted is not None:
        wanted = sorted(set(wanted))
    source_sha256, source_size = _sha256_file(source)
    records = list(_iter_selected_entries(source, policy, wanted, start, end, limit))
    if wanted is not None:
        missing = sorted(set(wanted) - {entry["record"]["number"] for entry in records})
        if missing:
            raise ValueError("records not found: {}".format(", ".join(str(number) for number in missing)))

    relationships = _relationships(records, policy)
    manifest: Dict[str, Any] = {
        "format": BUNDLE_FORMAT,
        "version": BUNDLE_VERSION,
        "policy": policy.public_dict(),
        "source": {
            "artifact": os.path.basename(source),
            "path": os.path.abspath(source),
            "sha256": source_sha256,
            "size": source_size,
        },
        "selection": {
            "record_numbers": wanted,
            "start": start,
            "end": end,
            "limit": limit,
            "record_count": len(records),
        },
        "canonicalization": {
            "algorithm": "sha256",
            "encoding": "utf-8",
            "json": "sorted-keys, compact-separators, no-ascii-escape",
        },
        "reference_protocol": {
            "record": {
                "locator": ["offset", "length", "number", "raw_sha256"],
                "check": "read length bytes at offset; verify magic, size, number, and raw_sha256",
            },
            "field": {
                "locator": ["selector", "path", "source.segments.offset", "source.segments.length"],
                "check": "reparse the record, compare value_sha256, and hash each source segment",
            },
            "digest": "sha256 over canonical JSON as described in canonicalization",
        },
        "missing_reasons": {
            STATUS_NOT_COLLECTED: "field was absent from the source or explicitly out of policy scope",
            STATUS_REDACTED: "field was present but withheld by the approval policy",
            STATUS_PARSE_FAILURE: "the EVTX/BXML parser could not read the record or field",
        },
        "records_file": "records.jsonl",
        "relationships_file": "relationships.json",
        "summary": _summarize(records),
    }
    manifest["forensic_digest"] = _package_digest(manifest, records, relationships)

    os.makedirs(destination, exist_ok=True)
    _write_jsonl(os.path.join(destination, "records.jsonl"), records)
    _write_json(os.path.join(destination, "relationships.json"), relationships)
    _write_json(os.path.join(destination, "manifest.json"), manifest)
    return EvidenceBundle(destination, manifest, records, relationships)


def _summarize(records: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    summary = {
        "records": len(records),
        "present": 0,
        STATUS_NOT_COLLECTED: 0,
        STATUS_REDACTED: 0,
        STATUS_PARSE_FAILURE: 0,
    }
    for record in records:
        for field in list(record["fields"]) + list(record["metadata"]):
            summary[field["status"]] = summary.get(field["status"], 0) + 1
    return summary


def load_bundle(path: str) -> EvidenceBundle:
    """Load a bundle from disk and minimally validate its structure."""

    path = os.fspath(path)
    manifest_path = os.path.join(path, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as stream:
        manifest = json.load(stream)
    if manifest.get("format") != BUNDLE_FORMAT:
        raise BundleVerificationError("unsupported bundle format")
    records_path = os.path.join(path, manifest.get("records_file", "records.jsonl"))
    records = []
    with open(records_path, "r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise BundleVerificationError("invalid records.jsonl line {}: {}".format(line_number, exc))
    relationships_path = os.path.join(path, manifest.get("relationships_file", "relationships.json"))
    with open(relationships_path, "r", encoding="utf-8") as stream:
        relationships = json.load(stream)
    return EvidenceBundle(path, manifest, records, relationships)


def _policy_from_manifest(manifest: Dict[str, Any]) -> EvidencePolicy:
    policy_dict = manifest.get("policy") or {}
    fields = []
    for item in policy_dict.get("fields", []):
        fields.append(
            FieldRule(
                name=item["name"],
                paths=tuple(item.get("paths", ())),
                identity=bool(item.get("identity", False)),
                access=item.get("access", ACCESS_INCLUDE),
                description=item.get("description", ""),
            )
        )
    metadata = []
    for item in policy_dict.get("metadata", []):
        metadata.append(
            FieldRule(
                name=item["name"],
                paths=tuple(item.get("paths", ())),
                identity=bool(item.get("identity", False)),
                access=item.get("access", ACCESS_INCLUDE),
                description=item.get("description", ""),
            )
        )
    return EvidencePolicy(
        name=policy_dict.get("name", "unknown"),
        description=policy_dict.get("description", ""),
        fields=tuple(fields),
        metadata=tuple(metadata),
    )


def _verify_record_against_original(
    record_entry: Dict[str, Any],
    source_path: str,
    policy: EvidencePolicy,
    errors: List[str],
) -> int:
    ref = record_entry["record"]
    offset = ref["offset"]
    length = ref["length"]
    with open(source_path, "rb") as stream:
        stream.seek(offset)
        raw = stream.read(length)
    if len(raw) != length:
        errors.append("record {}: short read at offset {}".format(ref["number"], offset))
        return 0
    actual_sha = _sha256_bytes(raw)
    if actual_sha != ref["raw_sha256"]:
        errors.append("record {}: source bytes changed".format(ref["number"]))
        return 0
    if len(raw) < 8 or int.from_bytes(raw[0:4], "little") != 0x2A2A:
        errors.append("record {}: record magic mismatch".format(ref["number"]))
        return 0
    if int.from_bytes(raw[4:8], "little") < 8:
        errors.append("record {}: invalid record size".format(ref["number"]))
        return 0
    if int.from_bytes(raw[8:16], "little") != ref["number"]:
        errors.append("record {}: record number at offset does not match".format(ref["number"]))
        return 0

    try:
        tree = _build_source_tree_for_offset(source_path, offset)
    except Exception as exc:
        if record_entry["status"] == STATUS_PARSE_FAILURE:
            return 0
        errors.append("record {}: original no longer parses: {}".format(ref["number"], _format_exception(exc)))
        return 0

    checked = 0
    for field_entry in list(record_entry["fields"]) + list(record_entry.get("metadata", [])):
        rule = _find_manifest_rule(policy, field_entry["name"])
        if rule is None:
            errors.append("record {}: field {!r} is not in policy".format(ref["number"], field_entry["name"]))
            continue
        if field_entry["status"] == STATUS_PARSE_FAILURE:
            continue
        if rule.access == ACCESS_REDACT:
            if field_entry["status"] not in (STATUS_REDACTED, STATUS_NOT_COLLECTED):
                errors.append("record {}: redacted field {!r} has status {}".format(
                    ref["number"], rule.name, field_entry["status"]
                ))
            continue
        current = _extract_rule(tree, rule)
        if current["status"] != field_entry["status"]:
            errors.append("record {}: field {!r} status differs".format(ref["number"], rule.name))
            continue
        if current["status"] == STATUS_PRESENT:
            if current["value_sha256"] != field_entry.get("value_sha256"):
                errors.append("record {}: field {!r} value differs".format(ref["number"], rule.name))
                continue
            for segment in field_entry.get("source", {}).get("segments", []):
                if not _verify_segment(source_path, segment):
                    errors.append("record {}: field {!r} source range mismatch".format(ref["number"], rule.name))
                    continue
            checked += 1
    return checked


def _find_manifest_rule(policy: EvidencePolicy, name: str) -> Optional[FieldRule]:
    for field in policy.fields + policy.metadata:
        if field.name == name:
            return field
    return None


def _verify_segment(source_path: str, segment: Dict[str, Any]) -> bool:
    offset = segment.get("offset")
    length = segment.get("length")
    if offset is None or length is None:
        return True
    with open(source_path, "rb") as stream:
        stream.seek(offset)
        raw = stream.read(length)
    if len(raw) != length:
        return False
    return _sha256_bytes(raw) == segment.get("raw_sha256")


def _build_source_tree_for_offset(source_path: str, offset: int) -> _SourceTree:
    with evtx.Evtx(source_path) as log:
        for chunk in log.chunks():
            chunk_start = chunk.offset()
            if chunk_start <= offset < chunk_start + 0x10000:
                for record in chunk.records():
                    if record.offset() == offset:
                        return _build_source_tree(record)
    raise ValueError("record offset {} not found".format(offset))


def verify_bundle(bundle: Any, source: Optional[str] = None) -> Dict[str, Any]:
    """Verify a bundle, optionally against the original EVTX file.

    Self-verification always recomputes every record digest, the relationship
    digest, and the package digest.  When ``source`` is supplied, every record
    reference is located by byte offset, its raw bytes are re-hashed, fields are
    re-extracted, and every field source segment is checked.

    Returns a JSON-serializable report.  ``ok`` is false if any check fails.
    """

    if not isinstance(bundle, EvidenceBundle):
        bundle = load_bundle(bundle)
    if source is not None:
        source = os.fspath(source)
    errors: List[str] = []
    warnings: List[str] = []
    refs_checked = 0

    try:
        policy = _policy_from_manifest(bundle.manifest)
    except Exception as exc:
        return {
            "ok": False,
            "errors": ["invalid policy: {}".format(_format_exception(exc))],
            "warnings": warnings,
            "digest_ok": False,
            "relationships_ok": False,
            "source_ok": None,
            "records_checked": 0,
            "field_refs_checked": 0,
        }

    for record in bundle.records:
        if record.get("content_digest") != _record_content_digest(record):
            errors.append("record {}: content digest mismatch".format(record.get("record", {}).get("number")))
        expected = _record_digest(record)
        if expected != record.get("digest"):
            errors.append("record {}: digest mismatch".format(record.get("record", {}).get("number")))

    numbers = [record.get("record", {}).get("number") for record in bundle.records]
    if len(numbers) != len(set(numbers)):
        errors.append("records: duplicate record numbers")
    if bundle.manifest.get("selection", {}).get("record_count") != len(bundle.records):
        errors.append("manifest: selection record count mismatch")
    if bundle.manifest.get("summary") != _summarize(bundle.records):
        errors.append("manifest: summary does not match retained records")

    if bundle.relationships.get("digest") != _relationship_digest(bundle.relationships):
        errors.append("relationships: digest mismatch")

    expected_relationships = _relationships(bundle.records, policy)
    if _canonical_json(expected_relationships) != _canonical_json(bundle.relationships):
        errors.append("relationships: content does not match retained records and policy")

    expected_package_digest = _package_digest(bundle.manifest, bundle.records, bundle.relationships)
    if expected_package_digest != bundle.manifest.get("forensic_digest"):
        errors.append("manifest: forensic digest mismatch")

    source_ok: Optional[bool] = None
    if source is not None:
        source_ok = True
        if not os.path.isfile(source):
            errors.append("source: file not found: {}".format(source))
            source_ok = False
        else:
            source_sha256, source_size = _sha256_file(source)
            if source_sha256 != bundle.manifest["source"]["sha256"]:
                errors.append("source: sha256 mismatch")
                source_ok = False
            if source_size != bundle.manifest["source"]["size"]:
                errors.append("source: size mismatch")
                source_ok = False
            if source_ok:
                with open(source, "rb") as stream:
                    for record in bundle.records:
                        refs_checked += _verify_record_against_original(record, source, policy, errors)

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "digest_ok": not any("digest" in error for error in errors),
        "relationships_ok": not any(error.startswith("relationships:") for error in errors),
        "source_ok": source_ok,
        "records_checked": len(bundle.records),
        "field_refs_checked": refs_checked,
        "policy": policy.name,
    }


def locate_record(source: str, offset: Any) -> Dict[str, Any]:
    """Locate one record in an original EVTX file by byte offset."""

    if isinstance(offset, dict):
        offset = offset["offset"]
    offset = int(offset)
    source = os.fspath(source)
    with evtx.Evtx(source) as log:
        for chunk_index, chunk in enumerate(log.chunks()):
            if not (chunk.offset() <= offset < chunk.offset() + 0x10000):
                continue
            for record_index, record in enumerate(chunk.records()):
                if record.offset() == offset:
                    header = _record_header(record, chunk_index, record_index)
                    return {
                        "record": header,
                        "source": source,
                    }
    raise KeyError("no record at offset {}".format(offset))


def locate_field(source: str, record_offset: Any, selector: str) -> Dict[str, Any]:
    """Re-resolve one field selector against the original EVTX record."""

    if isinstance(record_offset, dict):
        record_offset = record_offset["offset"]
    source = os.fspath(source)
    tree = _build_source_tree_for_offset(source, int(record_offset))
    rule = FieldRule("field", (selector,))
    result = _extract_rule(tree, rule)
    result["selector"] = selector
    result["record_offset"] = int(record_offset)
    return result


create_bundle = create_evidence_bundle
derive_bundle = create_evidence_bundle
verify = verify_bundle


__all__ = [
    "BUNDLE_FORMAT",
    "BUNDLE_VERSION",
    "STATUS_PRESENT",
    "STATUS_NOT_COLLECTED",
    "STATUS_REDACTED",
    "STATUS_PARSE_FAILURE",
    "MISSING_STATUSES",
    "ACCESS_INCLUDE",
    "ACCESS_REDACT",
    "ACCESS_OMIT",
    "FieldRule",
    "EvidencePolicy",
    "EvidenceBundle",
    "actor_only_policy",
    "actor_and_org_unit_policy",
    "policy_for_scope",
    "create_evidence_bundle",
    "create_bundle",
    "derive_bundle",
    "load_bundle",
    "verify_bundle",
    "verify",
    "locate_record",
    "locate_field",
    "record_digest",
    "record_content_digest",
    "relationship_digest",
    "package_digest",
    "recompute_digests",
    "_canonical_json",
    "_record_digest",
    "_relationships",
    "_package_digest",
]
