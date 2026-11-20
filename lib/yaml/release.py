"""Offline release checks for secret references in YAML configuration.

The checker deliberately stops at YAML values.  It never resolves a secret
identifier through a secret store or executes a custom YAML constructor.
Parsing is performed with :class:`yaml.SafeLoader`, and every alias occurrence
is retained so that the same anchor can be authorized differently at different
consumer locations.
"""

__all__ = [
    "ReleaseCheckError",
    "ReleaseFinding",
    "ReleaseReport",
    "check_release",
    "release_check",
    "release_scan",
    "safe_release_check",
]

from collections.abc import Iterable, Mapping
from fnmatch import fnmatchcase
import inspect
import re

from .composer import ComposerError
from .error import MarkedYAMLError, YAMLError
from .events import (
    AliasEvent,
    DocumentEndEvent,
    DocumentStartEvent,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
    StreamEndEvent,
    StreamStartEvent,
)
from .loader import SafeLoader


class ReleaseCheckError(YAMLError):
    """Raised when a release check cannot be completed."""


class _AttributeDict(dict):
    """Small dictionary wrapper that also supports attribute access."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


class _PathString(str):
    """JSON Pointer string that can also compare equal to its path parts."""

    __slots__ = ("parts",)

    def __new__(cls, value, parts):
        instance = str.__new__(cls, value)
        instance.parts = tuple(parts)
        return instance

    def __eq__(self, other):
        if isinstance(other, (tuple, list)):
            return self.parts == tuple(other)
        return str.__eq__(self, other)

    __hash__ = str.__hash__


class ReleaseFinding(_AttributeDict):
    """One expanded scalar reference and its authorization decision."""

    def __getitem__(self, key):
        return super().__getitem__(key)


class ReleaseReport(_AttributeDict):
    """Result returned by :func:`release_check`.

    Reports contain locations and caller-supplied identifiers only.  Source
    scalar values are never copied into a report.
    """

    def __bool__(self):
        return bool(self["ok"])

    @property
    def ok(self):
        return self["ok"]

    @property
    def findings(self):
        return self["findings"]

    @property
    def violations(self):
        return self["violations"]

    def as_dict(self):
        return dict(self)


class _Node:
    __slots__ = (
        "kind",
        "value",
        "start_mark",
        "end_mark",
        "tag",
        "style",
        "anchor",
    )

    def __init__(
        self, kind, value, start_mark, end_mark=None, tag=None, style=None
    ):
        self.kind = kind
        self.value = value
        self.start_mark = start_mark
        self.end_mark = end_mark
        self.tag = tag
        self.style = style
        self.anchor = None


class _AliasOccurrence:
    __slots__ = ("target", "anchor", "start_mark", "end_mark")

    def __init__(self, target, anchor, start_mark, end_mark=None):
        self.target = target
        self.anchor = anchor
        self.start_mark = start_mark
        self.end_mark = end_mark


class _Anchor:
    __slots__ = ("name", "mark", "document", "node", "path", "aliases")

    def __init__(self, name, mark, document, node):
        self.name = name
        self.mark = mark
        self.document = document
        self.node = node
        self.path = None
        self.aliases = []


class _TreeParser:
    """Parse safe YAML events into a tree that preserves alias occurrences."""

    def __init__(self, stream):
        self.loader = SafeLoader(stream)
        self.anchors = []
        self._document_anchors = {}
        self._document_index = 0

    def parse(self):
        loader = self.loader
        try:
            if loader.check_event(StreamStartEvent):
                loader.get_event()

            documents = []
            while not loader.check_event(StreamEndEvent):
                if loader.check_event(DocumentStartEvent):
                    loader.get_event()

                self._document_anchors = {}
                start_index = len(self.anchors)
                root = None
                if not loader.check_event(DocumentEndEvent):
                    root = self._parse_node()
                if loader.check_event(DocumentEndEvent):
                    loader.get_event()

                documents.append(
                    (self._document_index, root, self.anchors[start_index:])
                )
                self._document_index += 1

            if loader.check_event(StreamEndEvent):
                loader.get_event()
            return documents
        finally:
            loader.dispose()

    def _parse_node(self):
        loader = self.loader
        if loader.check_event(AliasEvent):
            event = loader.get_event()
            if event.anchor not in self._document_anchors:
                raise ComposerError(
                    None,
                    None,
                    "found undefined alias %r" % event.anchor,
                    event.start_mark,
                )
            return _AliasOccurrence(
                self._document_anchors[event.anchor].node,
                self._document_anchors[event.anchor],
                event.start_mark,
                event.end_mark,
            )

        event = loader.peek_event()
        if isinstance(event, ScalarEvent):
            event = loader.get_event()
            node = _Node(
                "scalar",
                event.value,
                event.start_mark,
                event.end_mark,
                event.tag,
                event.style,
            )
            self._register_anchor(event.anchor, event.start_mark, node)
            return node

        if isinstance(event, SequenceStartEvent):
            start_event = loader.get_event()
            node = _Node(
                "sequence",
                [],
                start_event.start_mark,
                None,
                start_event.tag,
            )
            self._register_anchor(start_event.anchor, start_event.start_mark, node)
            while not loader.check_event(SequenceEndEvent):
                node.value.append(self._parse_node())
            end_event = loader.get_event()
            node.end_mark = end_event.end_mark
            return node

        if isinstance(event, MappingStartEvent):
            start_event = loader.get_event()
            node = _Node(
                "mapping",
                [],
                start_event.start_mark,
                None,
                start_event.tag,
            )
            self._register_anchor(start_event.anchor, start_event.start_mark, node)
            while not loader.check_event(MappingEndEvent):
                key = self._parse_node()
                value = self._parse_node()
                node.value.append((key, value))
            end_event = loader.get_event()
            node.end_mark = end_event.end_mark
            return node

        raise ReleaseCheckError("unexpected YAML event %r" % (event,))

    def _register_anchor(self, name, mark, node):
        if name is None:
            return
        if name in self._document_anchors:
            first = self._document_anchors[name]
            raise ComposerError(
                "found duplicate anchor %r; first occurrence" % name,
                first.node.start_mark,
                "second occurrence",
                mark,
            )
        anchor = _Anchor(name, mark, self._document_index, node)
        node.anchor = anchor
        self._document_anchors[name] = anchor
        self.anchors.append(anchor)


class _RuleSet:
    def __init__(self):
        self.exact = {}
        self.detectors = []
        self.identifier_locations = {}
        self.path_rules = []
        self.default_locations = None
        self.consumption_callable = None
        self.has_rules = False

    def add_exact_identifier(self, identifier):
        key = _identifier_key(identifier)
        self.exact[key] = identifier

    def add_detector(self, detector):
        self.detectors.append(detector)

    def detect(self, value):
        key = _identifier_key(value)
        if key in self.exact:
            return self.exact[key]

        for detector in self.detectors:
            if isinstance(detector, re.Pattern):
                match = detector.search(value)
                if match is not None:
                    return match.group(0)
            else:
                result = detector(value)
                if result is None or result is False:
                    continue
                if isinstance(result, str):
                    return result
                return value
        return None

    def authorize(self, identifier, path, location):
        if self.consumption_callable is not None:
            return _call_consumption_rule(
                self.consumption_callable, identifier, path, location
            )

        id_key = _identifier_key(identifier)
        if id_key in self.identifier_locations:
            return _locations_allow(
                self.identifier_locations[id_key],
                identifier,
                path,
                location,
            )
        if "*" in self.identifier_locations:
            return _locations_allow(
                self.identifier_locations["*"],
                identifier,
                path,
                location,
            )

        if self.path_rules:
            applicable = [
                allowed
                for matcher, allowed in self.path_rules
                if _location_matches(matcher, path, location)
            ]
            if applicable:
                return any(
                    _identifier_rule_allows(allowed, identifier)
                    for allowed in applicable
                )

        if self.default_locations is not None:
            return _locations_allow(
                self.default_locations,
                identifier,
                path,
                location,
            )

        # With no matching authorization rule, fail closed.
        return False


def release_check(
    stream,
    identifiers=None,
    consumption_rules=None,
    *,
    rules=None,
    identifier_rule=None,
    consumption_rule=None,
    secret_identifiers=None,
    consumer_rules=None,
    location_rules=None,
    allowed_locations=None,
    allowed_consumers=None,
    identifier_pattern=None,
    Loader=None,
    **kwargs
):
    """Inspect secret references after YAML alias expansion.

    Parameters are intentionally permissive so checks can be expressed either
    as ``identifier -> locations`` or ``location -> identifiers`` rules.

    ``identifiers`` may be an iterable of identifiers, a mapping of identifiers
    to allowed locations, a regular expression, or a predicate taking a scalar
    string.  ``consumption_rules`` maps identifiers to allowed consumer paths.
    ``consumer_rules`` is the inverse form, mapping consumer paths to allowed
    identifiers.

    Paths are JSON Pointer strings such as ``/release/token``.  Exact paths,
    JSON Pointer globs (``/release/**``), dotted globs (``release.*``), and
    compiled regular expressions are accepted as location matchers.

    The YAML is parsed, not constructed, and source values are never included
    in the returned report.  The checker does not read a secret store.
    """

    kwargs = _apply_keyword_aliases(kwargs)
    if "identifier_rule" in kwargs:
        if identifier_rule is not None:
            raise TypeError("identifier_rule was specified more than once")
        identifier_rule = kwargs.pop("identifier_rule")
    if "secret_identifiers" in kwargs:
        if secret_identifiers is not None:
            raise TypeError("secret_identifiers was specified more than once")
        secret_identifiers = kwargs.pop("secret_identifiers")
    if "consumer_rules" in kwargs:
        if consumer_rules is not None:
            raise TypeError("consumer_rules was specified more than once")
        consumer_rules = kwargs.pop("consumer_rules")
    _reject_unknown_kwargs(kwargs)
    if Loader not in (None, SafeLoader):
        if not (isinstance(Loader, type) and issubclass(Loader, SafeLoader)):
            raise ValueError("release checks require yaml.SafeLoader")

    if identifier_pattern is not None:
        if identifier_rule is not None:
            raise TypeError("specify only one of identifier_rule and identifier_pattern")
        identifier_rule = identifier_pattern

    rule_set = _RuleSet()

    if identifiers is not None:
        _add_identifiers(rule_set, identifiers)
    if secret_identifiers is not None:
        _add_identifiers(rule_set, secret_identifiers)
    if identifier_rule is not None:
        rule_set.add_detector(_make_detector(identifier_rule))
    if rules is not None:
        _add_rules(rule_set, rules, path_keyed=False)
    if consumption_rules is not None:
        if callable(consumption_rules):
            _set_consumption_callable(rule_set, consumption_rules)
        elif isinstance(consumption_rules, Mapping):
            _add_rules(rule_set, consumption_rules, path_keyed=False)
        else:
            rule_set.default_locations = consumption_rules
            rule_set.has_rules = True
    if consumer_rules is not None:
        _add_rules(rule_set, consumer_rules, path_keyed=True)
    if location_rules is not None:
        _add_rules(rule_set, location_rules, path_keyed=True)
    if allowed_consumers is not None:
        _add_rules(rule_set, allowed_consumers, path_keyed=True)
    if allowed_locations is not None:
        if isinstance(allowed_locations, Mapping):
            _add_rules(rule_set, allowed_locations, path_keyed=False)
        else:
            rule_set.default_locations = allowed_locations
            rule_set.has_rules = True
    if consumption_rule is not None:
        if callable(consumption_rule):
            _set_consumption_callable(rule_set, consumption_rule)
        else:
            rule_set.default_locations = consumption_rule
            rule_set.has_rules = True

    parser = _TreeParser(stream)
    try:
        documents = parser.parse()
    except MarkedYAMLError:
        raise
    except YAMLError:
        raise

    alias_targets = set()
    for document_index, root, anchors in documents:
        if root is not None:
            _collect_alias_targets(root, alias_targets, set())

    findings = []
    for document_index, root, anchors in documents:
        if root is None:
            continue
        _walk(
            root,
            (),
            None,
            None,
            False,
            document_index,
            alias_targets,
            rule_set,
            findings,
            set(),
        )

    for finding in findings:
        finding["document"] = finding.pop("_document")

    violations = [finding for finding in findings if not finding["allowed"]]
    anchor_reports = [_anchor_report(anchor) for anchor in parser.anchors]
    anchor_definitions = {}
    for anchor in parser.anchors:
        key = anchor.name
        if key in anchor_definitions:
            key = "%s#%s" % (anchor.name, anchor.document)
        anchor_definitions[key] = _anchor_report(anchor)

    report = ReleaseReport(
        {
            "ok": not violations,
            "findings": findings,
            "violations": violations,
            "denied": violations,
            "anchors": anchor_reports,
            "anchor_definitions": anchor_definitions,
        }
    )
    return report


def safe_release_check(stream, *args, **kwargs):
    """Alias for :func:`release_check` using the safe loader."""

    return release_check(stream, *args, **kwargs)


def check_release(stream, *args, **kwargs):
    """Alias for :func:`release_check`."""

    return release_check(stream, *args, **kwargs)


def release_scan(stream, *args, **kwargs):
    """Alias for :func:`release_check`."""

    return release_check(stream, *args, **kwargs)


_KEYWORD_ALIASES = {
    "identifier_rules": "identifier_rule",
    "identifiers_rule": "identifier_rule",
    "consumers": "consumer_rules",
    "consumer_locations": "consumer_rules",
    "secret_ids": "secret_identifiers",
}


def _apply_keyword_aliases(kwargs):
    aliases = {}
    for key, value in kwargs.items():
        canonical = _KEYWORD_ALIASES.get(key)
        if canonical is not None:
            aliases[canonical] = value
        else:
            aliases[key] = value
    return aliases


def _reject_unknown_kwargs(kwargs):
    if kwargs:
        unknown = sorted(kwargs)
        raise TypeError(
            "release_check() got unexpected keyword argument(s): %s"
            % ", ".join(unknown)
        )


def _identifier_key(identifier):
    if isinstance(identifier, str):
        return identifier
    return str(identifier)


def _add_identifiers(rule_set, identifiers):
    if isinstance(identifiers, Mapping):
        _add_rules(rule_set, identifiers, path_keyed=False)
        return
    if isinstance(identifiers, re.Pattern) or callable(identifiers):
        rule_set.add_detector(_make_detector(identifiers))
        return
    if isinstance(identifiers, (str, bytes)):
        rule_set.add_exact_identifier(identifiers)
        return
    for identifier in identifiers:
        if isinstance(identifier, re.Pattern) or callable(identifier):
            rule_set.add_detector(_make_detector(identifier))
        else:
            rule_set.add_exact_identifier(identifier)


def _make_detector(rule):
    if isinstance(rule, re.Pattern):
        return rule
    if isinstance(rule, str):
        return re.compile(rule)
    if callable(rule):
        return rule
    raise TypeError("identifier rules must be a regex, string, or callable")


def _add_rules(rule_set, rules, path_keyed):
    if not isinstance(rules, Mapping):
        raise TypeError("release rules must be a mapping")
    if not rules:
        rule_set.has_rules = True
        return

    if not path_keyed and _looks_path_keyed(rules, rule_set):
        path_keyed = True

    if path_keyed:
        for matcher, allowed in rules.items():
            rule_set.path_rules.append((matcher, allowed))
            _add_identifiers_from_rule(rule_set, allowed)
        rule_set.has_rules = True
        return

    for identifier, locations in rules.items():
        key = _identifier_key(identifier)
        rule_set.identifier_locations[key] = locations
        if key != "*" and not callable(identifier) and not isinstance(
            identifier, re.Pattern
        ):
            rule_set.add_exact_identifier(identifier)
        rule_set.has_rules = True


def _add_identifiers_from_rule(rule_set, allowed):
    if allowed is True or allowed is None or allowed is False:
        return
    if isinstance(allowed, re.Pattern) or callable(allowed):
        rule_set.add_detector(_make_detector(allowed))
        return
    if isinstance(allowed, str):
        rule_set.add_exact_identifier(allowed)
        return
    if isinstance(allowed, Mapping):
        for value in allowed.values():
            _add_identifiers_from_rule(rule_set, value)
        return
    if isinstance(allowed, Iterable):
        for value in allowed:
            _add_identifiers_from_rule(rule_set, value)


def _looks_path_keyed(rules, rule_set):
    if not rules:
        return False
    keys = list(rules)
    if not all(isinstance(key, str) for key in keys):
        return False
    known_identifiers = set(rule_set.exact)
    if known_identifiers and all(key in known_identifiers for key in keys):
        return False
    if any(key.startswith("/") or key.startswith("./") for key in keys):
        return True
    if all("." in key for key in keys):
        values = list(rules.values())
        return any(
            isinstance(value, (str, list, tuple, set, frozenset))
            for value in values
        )
    return False


def _set_consumption_callable(rule_set, rule):
    rule_set.consumption_callable = rule
    rule_set.has_rules = True


def _call_consumption_rule(rule, identifier, path, location):
    try:
        signature = inspect.signature(rule)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
    except (TypeError, ValueError):
        positional = []

    count = len(positional)
    if count >= 3:
        result = rule(identifier, tuple(path), location)
    elif count == 2:
        result = rule(identifier, location)
    elif count == 1:
        result = rule(identifier)
    else:
        try:
            result = rule(identifier, location)
        except TypeError:
            result = rule(identifier)
    return bool(result)


def _locations_allow(rule, identifier, path, location):
    if rule is True:
        return True
    if rule is None or rule is False:
        return False
    if isinstance(rule, Mapping):
        return any(
            _location_matches(matcher, path, location) and _identifier_rule_allows(
                allowed, identifier
            )
            for matcher, allowed in rule.items()
        )
    if isinstance(rule, (str, bytes, re.Pattern)) or callable(rule):
        return _location_matches(rule, path, location)
    if isinstance(rule, Iterable):
        return any(_location_matches(item, path, location) for item in rule)
    raise TypeError("invalid allowed-location rule %r" % (rule,))


def _identifier_rule_allows(rule, identifier):
    if rule is True:
        return True
    if rule is None or rule is False:
        return False
    if isinstance(rule, re.Pattern):
        return rule.search(identifier) is not None
    if isinstance(rule, str):
        return identifier == rule or fnmatchcase(identifier, rule)
    if callable(rule):
        return bool(rule(identifier))
    if isinstance(rule, Iterable):
        return any(_identifier_rule_allows(item, identifier) for item in rule)
    return identifier == rule


def _location_matches(matcher, path, location):
    if matcher is True:
        return True
    if matcher is None or matcher is False:
        return False
    if callable(matcher) and not isinstance(matcher, re.Pattern):
        return _call_location_matcher(matcher, path, location)
    if isinstance(matcher, re.Pattern):
        return (
            matcher.fullmatch(location) is not None
            or matcher.fullmatch(_dotted_path(path)) is not None
        )
    if isinstance(matcher, (tuple, list)):
        return _match_path_parts(tuple(str(part) for part in matcher), path)
    if not isinstance(matcher, str):
        raise TypeError("invalid location matcher %r" % (matcher,))

    matcher = matcher.strip()
    if matcher in ("*", "**"):
        return True
    if matcher.startswith("/"):
        matcher_parts = _pointer_parts(matcher)
    else:
        matcher_parts = _dotted_parts(matcher)

    if any(_has_wildcard(part) for part in matcher_parts):
        return _match_path_parts(matcher_parts, path)
    return (
        tuple(str(part) for part in path) == tuple(matcher_parts)
        or location == matcher
        or _dotted_path(path) == matcher
    )


def _call_location_matcher(matcher, path, location):
    try:
        signature = inspect.signature(matcher)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
    except (TypeError, ValueError):
        positional = []

    if len(positional) >= 2:
        return bool(matcher(location, tuple(path)))
    return bool(matcher(location))


def _has_wildcard(part):
    return any(character in part for character in "*?[")


def _match_path_parts(pattern_parts, path):
    path_parts = tuple(str(part) for part in path)

    def match(pattern_index, path_index):
        if pattern_index == len(pattern_parts):
            return path_index == len(path_parts)
        part = pattern_parts[pattern_index]
        if part == "**":
            return match(pattern_index + 1, path_index) or (
                path_index < len(path_parts)
                and match(pattern_index, path_index + 1)
            )
        return (
            path_index < len(path_parts)
            and fnmatchcase(path_parts[path_index], part)
            and match(pattern_index + 1, path_index + 1)
        )

    return match(0, 0)


def _pointer_parts(pointer):
    if pointer == "/":
        return [""]
    return [
        part.replace("~1", "/").replace("~0", "~")
        for part in pointer.lstrip("/").split("/")
    ]


def _dotted_parts(value):
    parts = []
    for part in value.split("."):
        if not part:
            continue
        while "[" in part and part.endswith("]"):
            head, tail = part.rsplit("[", 1)
            index = tail[:-1]
            if head:
                parts.append(head)
            parts.append(index)
            part = ""
        if part:
            parts.append(part)
    return parts


def _pointer_path(path):
    if not path:
        return "/"
    return "/" + "/".join(
        str(part).replace("~", "~0").replace("/", "~1") for part in path
    )


def _dotted_path(path):
    return ".".join(str(part) for part in path)


def _position(mark):
    if mark is None:
        return None
    return {
        "line": mark.line + 1,
        "column": mark.column + 1,
        "index": mark.index,
    }


def _anchor_report(anchor):
    result = {
        "name": anchor.name,
        "document": anchor.document,
        "path": _pointer_path(anchor.path or ()),
        "defined_at": _position(anchor.mark),
        "aliases": [
            {
                "path": _pointer_path(path),
                "used_at": _position(mark),
            }
            for path, mark in anchor.aliases
        ],
    }
    return result


def _collect_alias_targets(value, targets, seen):
    if isinstance(value, _AliasOccurrence):
        targets.add(id(value.target))
        if id(value.target) in seen:
            return
        seen.add(id(value.target))
        _collect_alias_targets(value.target, targets, seen)
        return
    if not isinstance(value, _Node):
        return
    if id(value) in seen:
        return
    seen.add(id(value))
    if value.kind == "sequence":
        for child in value.value:
            _collect_alias_targets(child, targets, seen)
    elif value.kind == "mapping":
        for key, child in value.value:
            _collect_alias_targets(key, targets, seen)
            _collect_alias_targets(child, targets, seen)


def _walk(
    value,
    path,
    used_mark,
    alias_anchor,
    through_alias,
    document_index,
    alias_targets,
    rule_set,
    findings,
    stack,
):
    if isinstance(value, _AliasOccurrence):
        anchor = value.anchor
        anchor.aliases.append((path, value.start_mark))
        if id(value.target) in stack:
            return
        _walk(
            value.target,
            path,
            value.start_mark,
            anchor,
            True,
            document_index,
            alias_targets,
            rule_set,
            findings,
            stack | {id(value.target)},
        )
        return

    if not isinstance(value, _Node):
        return

    if value.anchor is not None and value.anchor.path is None:
        value.anchor.path = path

    if (
        value.anchor is not None
        and id(value) in alias_targets
        and not through_alias
    ):
        # The anchored occurrence is the definition, not a consumer.  The
        # aliases themselves are reported at their respective destinations.
        return

    if value.kind == "scalar":
        identifier = rule_set.detect(value.value)
        if identifier is None:
            return
        mark = used_mark or value.start_mark
        location = _pointer_path(path)
        allowed = rule_set.authorize(identifier, path, location)
        anchor = alias_anchor or value.anchor
        finding = ReleaseFinding(
            {
                "identifier": identifier,
                "allowed": allowed,
                "authorized": allowed,
                "reason": (
                    "allowed by consumption rule"
                    if allowed
                    else "consumption location is not authorized"
                ),
                "path": location,
                "path_parts": list(path),
                "location": location,
                "used_at": _position(mark),
                "source": "alias" if through_alias else "literal",
                "anchor": anchor.name if anchor is not None else None,
                "anchor_name": anchor.name if anchor is not None else None,
                "anchor_path": (
                    _pointer_path(anchor.path or ())
                    if anchor is not None
                    else None
                ),
                "anchor_definition": (
                    _position(anchor.mark) if anchor is not None else None
                ),
                "defined_at": _position(value.start_mark),
                "_document": document_index,
            }
        )
        finding["line"] = mark.line + 1
        finding["column"] = mark.column + 1
        findings.append(finding)
        return

    if value.kind == "sequence":
        for index, child in enumerate(value.value):
            _walk(
                child,
                path + (index,),
                used_mark,
                alias_anchor,
                through_alias,
                document_index,
                alias_targets,
                rule_set,
                findings,
                stack,
            )
        return

    for key, child in value.value:
        key_value = _mapping_key(key)
        if _is_merge_key(key):
            _walk_merge(
                child,
                path,
                used_mark,
                alias_anchor,
                through_alias,
                document_index,
                alias_targets,
                rule_set,
                findings,
                stack,
            )
            continue
        child_path = path + (key_value,)
        _walk(
            child,
            child_path,
            used_mark,
            alias_anchor,
            through_alias,
            document_index,
            alias_targets,
            rule_set,
            findings,
            stack,
        )


def _walk_merge(
    value,
    path,
    used_mark,
    alias_anchor,
    through_alias,
    document_index,
    alias_targets,
    rule_set,
    findings,
    stack,
):
    if isinstance(value, _AliasOccurrence):
        anchor = value.anchor
        anchor.aliases.append((path, value.start_mark))
        if id(value.target) in stack:
            return
        _walk_merge(
            value.target,
            path,
            value.start_mark,
            anchor,
            True,
            document_index,
            alias_targets,
            rule_set,
            findings,
            stack | {id(value.target)},
        )
        return
    if not isinstance(value, _Node):
        return
    if value.kind == "sequence":
        for child in value.value:
            _walk_merge(
                child,
                path,
                used_mark,
                alias_anchor,
                through_alias,
                document_index,
                alias_targets,
                rule_set,
                findings,
                stack,
            )
        return
    _walk(
        value,
        path,
        used_mark,
        alias_anchor,
        True,
        document_index,
        alias_targets,
        rule_set,
        findings,
        stack,
    )


def _mapping_key(value):
    if isinstance(value, _AliasOccurrence):
        value = value.target
    if isinstance(value, _Node) and value.kind == "scalar":
        return value.value
    return "<key>"


def _is_merge_key(value):
    if isinstance(value, _AliasOccurrence):
        value = value.target
    if not isinstance(value, _Node) or value.kind != "scalar":
        return False
    if value.value != "<<":
        return False
    if value.tag is not None:
        return value.tag == "tag:yaml.org,2002:merge"
    return value.style is None
