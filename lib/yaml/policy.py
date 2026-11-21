"""
Tri-state security policy round-trip support.

A policy rule has three meanings:

* ``allow`` -- explicitly allowed;
* ``deny`` -- explicitly denied;
* ``inherit`` -- decided by the parent / supervisor rule.

The important property is that these are three distinct values.  A plain
``None`` or an absent key must not be used to mean "deny", and a boolean
``False`` must not silently become an absent value when a policy is passed
through another tool and written back out.

This module deliberately works on the YAML representation graph.  Anchors,
aliases and merge keys are therefore still visible while a document is
verified, and a serialized document keeps the same sharing relationships.
The module also provides a small constraint language so a caller can limit
verification to the paths it actually cares about.
"""

__all__ = [
    'ALLOW',
    'DENY',
    'INHERIT',
    'DEFAULT',
    'ALLOWED',
    'DENIED',
    'PolicyError',
    'PolicyState',
    'PolicyConstraint',
    'PolicyContract',
    'PolicyChange',
    'PolicyDecision',
    'PolicyDocument',
    'PolicyIssue',
    'PolicyReport',
    'PolicyRoundTripResult',
    'PolicyMigrationResult',
    'ManualReview',
    'SharedItem',
    'normalize_state',
    'normalize_path',
    'path_string',
    'supported_loaders',
    'other_supported_loader',
    'load_policy',
    'load_policy_all',
    'dump_policy',
    'roundtrip_policy',
    'verify_policy_roundtrip',
    'migrate_legacy_policy',
    'policy_roundtrip',
    'verify_roundtrip',
    'security_roundtrip',
    'config_roundtrip',
    'safe_roundtrip',
    'verify_policy',
    'migrate_policy',
]

import copy
import fnmatch

from .error import YAMLError
from .loader import FullLoader, SafeLoader
from .nodes import MappingNode, ScalarNode, SequenceNode

try:  # pragma: no cover - depends on whether libyaml was built
    from .cyaml import CFullLoader, CSafeLoader
except ImportError:  # pragma: no cover
    CFullLoader = None
    CSafeLoader = None


ALLOW = 'allow'
DENY = 'deny'
INHERIT = 'inherit'
DEFAULT = INHERIT
ALLOWED = ALLOW
DENIED = DENY

_STATES = (ALLOW, DENY, INHERIT)
_NULL_TAG = 'tag:yaml.org,2002:null'
_BOOL_TAG = 'tag:yaml.org,2002:bool'
_STR_TAG = 'tag:yaml.org,2002:str'
_INT_TAG = 'tag:yaml.org,2002:int'
_MERGE_TAG = 'tag:yaml.org,2002:merge'
_VALUE_TAG = 'tag:yaml.org,2002:value'
_MAP_TAG = 'tag:yaml.org,2002:map'

_POLICY_KEYWORDS = (
    'rule', 'rules', 'allow', 'deny', 'ban', 'block', 'access',
    'permission', 'policy', 'effect', 'decision', 'inherit', 'default',
    'read', 'write', 'delete', 'execute', 'admin', 'guest', 'role',
    'scope', 'restrict',
)


class PolicyState:
    """Namespace containing the three policy states.

    The constants are plain strings so they can be compared with values read
    from YAML without unwrapping an enum.
    """

    ALLOW = ALLOW
    DENY = DENY
    INHERIT = INHERIT
    DEFAULT = INHERIT


_STATE_ALIASES = {
    'allow': ALLOW,
    'allowed': ALLOW,
    'permit': ALLOW,
    'permitted': ALLOW,
    'true': ALLOW,
    'yes': ALLOW,
    'on': ALLOW,
    '1': ALLOW,
    'enable': ALLOW,
    'enabled': ALLOW,
    'whitelist': ALLOW,
    'deny': DENY,
    'denied': DENY,
    'block': DENY,
    'blocked': DENY,
    'ban': DENY,
    'banned': DENY,
    'false': DENY,
    'no': DENY,
    'off': DENY,
    '0': DENY,
    'disable': DENY,
    'disabled': DENY,
    'blacklist': DENY,
    'reject': DENY,
    'rejected': DENY,
    'inherit': INHERIT,
    'inherited': INHERIT,
    'default': INHERIT,
    'defaults': INHERIT,
    'parent': INHERIT,
    'supervisor': INHERIT,
    'unspecified': INHERIT,
    'unset': INHERIT,
    'none': INHERIT,
    'null': INHERIT,
    '': INHERIT,
}


class PolicyError(YAMLError, ValueError):
    """Raised when a policy document or verification contract is invalid."""


def normalize_state(value, *, allow_unknown=False):
    """Return the canonical ``allow``/``deny``/``inherit`` state.

    ``True`` maps to ``allow`` and ``False`` maps to ``deny``.  In
    particular, ``False`` is *not* allowed to become ``inherit``: that is the
    exact lossy conversion this module exists to prevent.
    """

    if isinstance(value, bytes):
        value = value.decode('utf-8')
    if value is True:
        return ALLOW
    if value is False:
        return DENY
    if value is None:
        return INHERIT
    if isinstance(value, str):
        key = value.strip().lower()
        if key in _STATE_ALIASES:
            return _STATE_ALIASES[key]
    if isinstance(value, int) and not isinstance(value, bool):
        if value == 1:
            return ALLOW
        if value == 0:
            return DENY
    if allow_unknown:
        return None
    raise PolicyError("invalid policy state: %r" % (value,))


def normalize_path(path):
    """Normalize a path to a tuple of string / integer segments.

    Dotted strings (``"team.api.read"``) and JSON-pointer strings
    (``"/team/api/read"``) are accepted.  A tuple or list is used as-is.
    """

    if path is None:
        return ()
    if isinstance(path, (tuple, list)):
        return tuple(path)
    if isinstance(path, int):
        return (path,)
    if not isinstance(path, str):
        raise PolicyError("policy paths must be strings or tuples: %r" % (path,))
    if path.startswith('$.'):
        path = path[2:]
    if path.startswith('/'):
        if path == '/':
            return ()
        parts = []
        for part in path[1:].split('/'):
            part = part.replace('~1', '/').replace('~0', '~')
            parts.append(part)
        return tuple(parts)
    if path == '':
        return ()
    return tuple(path.split('.'))


def path_string(path):
    """Return a stable human-readable dotted path (without a ``$`` prefix)."""

    return '.'.join(str(part) for part in normalize_path(path))


def _path_sort_key(path):
    path = normalize_path(path)
    return tuple(
        (0, part) if isinstance(part, int) and not isinstance(part, bool)
        else (1, str(part))
        for part in path
    )



def _looks_like_policy_path(path):
    text = '.'.join(str(part).lower() for part in normalize_path(path))
    return any(word in text for word in _POLICY_KEYWORDS)


def _is_canonical_state_node(node):
    if not isinstance(node, ScalarNode) or node.tag != _STR_TAG:
        return False
    return str(node.value).strip().lower() in _STATES


def _leaf_is_decision(path, node, contract_paths=()):
    path = normalize_path(path)
    if path in set(normalize_path(item) for item in contract_paths):
        return True
    if _is_canonical_state_node(node):
        return True
    return _looks_like_policy_path(path)


class _PathMap(dict):
    """A dict whose keys accept tuple, dotted-string and JSON-pointer paths."""

    def _key(self, key):
        return normalize_path(key)

    def __getitem__(self, key):
        return super().__getitem__(self._key(key))

    def __setitem__(self, key, value):
        super().__setitem__(self._key(key), value)

    def __contains__(self, key):
        return super().__contains__(self._key(key))

    def get(self, key, default=None):
        return super().get(self._key(key), default)

    def pop(self, key, *args):
        return super().pop(self._key(key), *args)

    def to_dict(self):
        return {path_string(key): value for key, value in self.items()}


class PolicyConstraint:
    """A constraint for one (possibly wildcard) policy path."""

    def __init__(self, path, allowed=None, required=True, default=None,
                 shared=None, manual_review=False, legacy=None,
                 sharing_sensitive=False):
        self.path = normalize_path(path)
        if allowed is None:
            self.allowed = None
        else:
            if isinstance(allowed, (str, bool, type(None))):
                allowed = [allowed]
            self.allowed = frozenset(normalize_state(item) for item in allowed)
        self.required = required
        self.default = None if default is None else normalize_state(default)
        self.shared = shared
        self.manual_review = manual_review
        self.legacy = legacy
        self.sharing_sensitive = sharing_sensitive

    @property
    def wildcard(self):
        return self.path == ('**',) or any(
            isinstance(part, str) and any(char in part for char in '*?[')
            for part in self.path)

    def matches(self, path):
        path = normalize_path(path)
        if self.wildcard:
            return _path_matches(self.path, path)
        return self.path == path

    def __repr__(self):
        return 'PolicyConstraint(%r, allowed=%r, required=%r)' % (
            self.path, self.allowed, self.required)


def _path_matches(pattern, path):
    """Match a normalized path pattern, with ``**`` consuming any depth."""

    if not pattern:
        return not path
    head = pattern[0]
    if head == '**':
        if len(pattern) == 1:
            return True
        for index in range(len(path) + 1):
            if _path_matches(pattern[1:], path[index:]):
                return True
        return False
    if not path:
        return False
    if not fnmatch.fnmatchcase(str(path[0]), str(head)):
        return False
    return _path_matches(pattern[1:], path[1:])


def _constraint_from_spec(path, spec):
    if isinstance(spec, PolicyConstraint):
        return spec
    if spec is None:
        return PolicyConstraint(path)
    if isinstance(spec, dict):
        allowed = spec.get('allowed', spec.get('states', spec.get('allow')))
        default = spec.get('default', spec.get('inherits'))
        required = spec.get('required')
        if required is None:
            required = not spec.get('optional', False)
        return PolicyConstraint(
            path,
            allowed=allowed,
            required=required,
            default=default,
            shared=spec.get('shared'),
            manual_review=bool(spec.get('manual_review', False)),
            legacy=spec.get('legacy'),
            sharing_sensitive=bool(spec.get('sharing_sensitive', False)),
        )
    if isinstance(spec, (set, list, tuple)):
        return PolicyConstraint(path, allowed=spec)
    return PolicyConstraint(path, allowed=[spec])


class PolicyContract:
    """A caller-defined set of paths and states that must survive a round trip."""

    def __init__(self, entries=None, *, strict=False, constraints=None):
        self.entries = _PathMap()
        self.strict = strict
        if entries is None:
            entries = constraints
        if entries:
            if isinstance(entries, (list, tuple)):
                for constraint in entries:
                    if not isinstance(constraint, PolicyConstraint):
                        raise PolicyError(
                            "contract lists must contain PolicyConstraint objects")
                    self.entries[constraint.path] = constraint
            else:
                for path, spec in entries.items():
                    constraint = _constraint_from_spec(path, spec)
                    self.entries[constraint.path] = constraint

    def constraints_for(self, path):
        path = normalize_path(path)
        result = []
        for pattern, constraint in self.entries.items():
            if constraint.matches(path):
                result.append(constraint)
        return result

    def declared_paths(self, document=None):
        exact = [path for path in self.entries if not self.entries[path].wildcard]
        wildcard = [constraint for constraint in self.entries.values()
                    if constraint.wildcard]
        if document is None or not wildcard:
            return sorted(exact)
        matched = set(exact)
        node_paths = document._index()
        for node in _iter_nodes(document.root):
            if not isinstance(node, ScalarNode):
                continue
            if _state_from_node(node) is None:
                continue
            for path in node_paths.get(id(node), ()):
                if path and any(constraint.matches(path)
                                for constraint in wildcard):
                    matched.add(path)
        return sorted(matched, key=_path_sort_key)

    def __repr__(self):
        return 'PolicyContract(%r)' % (self.entries.to_dict(),)


class PolicyChange:
    """A requested state change for one path."""

    def __init__(self, path, state, isolate=True):
        self.path = normalize_path(path)
        self.state = normalize_state(state)
        self.isolate = isolate

    def __repr__(self):
        return 'PolicyChange(%r, %r)' % (self.path, self.state)


class ManualReview:
    """A field that a legacy migration cannot decide without a person."""

    def __init__(self, path, reason, detail='', suggested=None):
        self.path = normalize_path(path)
        self.reason = reason
        self.detail = detail
        self.suggested = suggested

    @property
    def path_str(self):
        return path_string(self.path)

    def to_dict(self):
        return {
            "path": self.path_str,
            "reason": self.reason,
            "detail": self.detail,
            "suggested": self.suggested,
        }

    def __str__(self):
        return self.path_str

    def __eq__(self, other):
        if isinstance(other, ManualReview):
            return (self.path, self.reason, self.detail, self.suggested) == (other.path, other.reason, other.detail, other.suggested)
        if isinstance(other, (tuple, list)):
            return self.path == tuple(other)
        return self.path_str == str(other)

    def __hash__(self):
        return hash((self.path, self.reason))

    def __repr__(self):
        return 'ManualReview(%r, %r)' % (self.path, self.reason)


class PolicyDecision:
    """The effective decision reached at one path."""

    def __init__(self, path, state, present, explicit, via_merge, via_alias,
                 shared_with=()):
        self.path = normalize_path(path)
        self.state = state
        self.present = present
        self.explicit = explicit
        self.via_merge = via_merge
        self.via_alias = via_alias
        self.shared_with = tuple(shared_with)

    @property
    def path_str(self):
        return path_string(self.path)

    def __repr__(self):
        return "PolicyDecision(%r, state=%r, present=%r, explicit=%r)" % (
            self.path, self.state, self.present, self.explicit)

    def to_dict(self):
        return {
            "path": self.path_str,
            "state": self.state,
            "present": self.present,
            "explicit": self.explicit,
            "via_merge": self.via_merge,
            "via_alias": self.via_alias,
            "shared_with": [path_string(item) for item in self.shared_with],
        }

    def __str__(self):
        return self.state or ""

    def __eq__(self, other):
        if isinstance(other, PolicyDecision):
            return (
                self.path == other.path
                and self.state == other.state
                and self.present == other.present
                and self.explicit == other.explicit
            )
        return self.state == other

    def __hash__(self):
        return hash((self.path, self.state, self.present))


class SharedItem:
    """A YAML node that is consumed at more than one path."""

    def __init__(self, definition_path, paths, anchors=(), kind='value'):
        self.definition_path = normalize_path(definition_path)
        self.paths = tuple(normalize_path(path) for path in paths)
        self.anchors = tuple(anchors)
        self.kind = kind

    def to_dict(self):
        return {
            'definition_path': path_string(self.definition_path),
            'paths': [path_string(path) for path in self.paths],
            'anchors': list(self.anchors),
            'kind': self.kind,
        }

    def __repr__(self):
        return 'SharedItem(%r, paths=%r)' % (
            self.definition_path, self.paths)


class PolicyIssue:
    """One diagnostic produced by verification or migration."""

    def __init__(self, kind, path, message, severity='error', detail=None,
                 before=None, after=None):
        self.kind = kind
        self.path = normalize_path(path)
        self.message = message
        self.severity = severity
        self.detail = detail or {}
        self.before = before
        self.after = after

    @property
    def path_str(self):
        return path_string(self.path)

    def to_dict(self):
        return {
            'kind': self.kind,
            'path': self.path_str,
            'message': self.message,
            'severity': self.severity,
            'detail': self.detail,
            'before': self.before,
            'after': self.after,
        }

    def __repr__(self):
        return 'PolicyIssue(%r, path=%r, severity=%r)' % (
            self.kind, self.path, self.severity)


class PolicyReport:
    """Verification result for a policy round trip."""

    def __init__(self, issues=(), decisions=None, before_decisions=None,
                 shared=None, manual_review=(), before=None, after=None,
                 expected_changes=None, loaders=None):
        self.issues = list(issues)
        self.decisions = _PathMap()
        if decisions:
            for path, decision in decisions.items():
                self.decisions[path] = decision
        self.before_decisions = _PathMap()
        if before_decisions:
            for path, decision in before_decisions.items():
                self.before_decisions[path] = decision
        self.shared = _PathMap()
        if shared:
            for path, item in shared.items():
                self.shared[path] = item
        self.manual_review = []
        for item in manual_review or ():
            if isinstance(item, ManualReview):
                self.manual_review.append(item)
            elif isinstance(item, (tuple, list)) and len(item) >= 2:
                self.manual_review.append(ManualReview(item[0], item[1]))
            else:
                self.manual_review.append(ManualReview(item, "caller"))
        self.before = before
        self.after = after
        self.expected_changes = expected_changes or {}
        self.loaders = loaders

    @property
    def ok(self):
        return not any(issue.severity == 'error' for issue in self.issues)

    @property
    def errors(self):
        return [issue for issue in self.issues if issue.severity == 'error']

    @property
    def warnings(self):
        return [issue for issue in self.issues if issue.severity != 'error']

    def findings(self, kind=None):
        if kind is None:
            return list(self.issues)
        return [issue for issue in self.issues if issue.kind == kind]

    @property
    def consumption(self):
        """Shared definition path -> every actual consumer path."""
        return {
            path_string(path): [path_string(item) for item in shared.paths]
            for path, shared in self.shared.items()
        }

    @property
    def shared_paths(self):
        return self.consumption

    @property
    def states(self):
        return {
            path_string(path): decision.state
            for path, decision in self.decisions.items()
        }

    def to_dict(self):
        result = {
            'ok': self.ok,
            'decisions': {
                path_string(path): decision.state
                for path, decision in self.decisions.items()
            },
            'before_decisions': {
                path_string(path): decision.state
                for path, decision in self.before_decisions.items()
            },
            'shared': {
                path_string(path): item.to_dict()
                for path, item in self.shared.items()
            },
            'issues': [issue.to_dict() for issue in self.issues],
            'manual_review': [
                {
                    'path': item.path_str,
                    'reason': item.reason,
                    'detail': item.detail,
                    'suggested': item.suggested,
                }
                for item in self.manual_review
            ],
        }
        if self.loaders:
            result['loaders'] = [loader.__name__ for loader in self.loaders]
        return result

    @property
    def violations(self):
        return self.errors

    def to_yaml(self, **kwargs):
        from . import safe_dump
        kwargs.setdefault("sort_keys", False)
        return safe_dump(self.to_dict(), **kwargs)

    def __repr__(self):
        return 'PolicyReport(ok=%r, issues=%d)' % (self.ok, len(self.issues))


class PolicyRoundTripResult:
    """The saved document and the evidence collected while checking it."""

    def __init__(self, text, before, after, report, changes=()):
        self.text = text
        self.before = before
        self.after = after
        self.report = report
        self.changes = tuple(changes)

    @property
    def document(self):
        return self.after

    @property
    def saved_text(self):
        return self.text

    @property
    def loaders(self):
        return self.report.loaders

    @property
    def shared(self):
        return self.report.shared

    @property
    def before_decisions(self):
        return self.report.before_decisions

    @property
    def states(self):
        return self.report.states

    @property
    def ok(self):
        return self.report.ok

    @property
    def decisions(self):
        return self.report.decisions

    @property
    def issues(self):
        return self.report.issues

    @property
    def manual_review(self):
        return self.report.manual_review

    def to_dict(self):
        data = self.report.to_dict()
        data['text'] = self.text
        return data

    def to_yaml(self, **kwargs):
        from . import safe_dump
        kwargs.setdefault("sort_keys", False)
        return safe_dump(self.to_dict(), **kwargs)

    def __repr__(self):
        return 'PolicyRoundTripResult(ok=%r, issues=%d)' % (
            self.ok, len(self.issues))


class PolicyMigrationResult:
    """A canonicalized legacy document plus fields needing manual review."""

    def __init__(self, document, text, report, manual_review):
        self.document = document
        self.text = text
        self.report = report
        self.manual_review = list(manual_review)

    @property
    def ok(self):
        return not [item for item in self.manual_review]

    @property
    def decisions(self):
        return self.report.decisions

    @property
    def fields(self):
        return [item.path_str for item in self.manual_review]

    @property
    def field_paths(self):
        return [item.path for item in self.manual_review]

    def to_dict(self):
        data = self.report.to_dict()
        data['text'] = self.text
        data['manual_review'] = [
            {
                'path': item.path_str,
                'reason': item.reason,
                'detail': item.detail,
                'suggested': item.suggested,
            }
            for item in self.manual_review
        ]
        return data

    def to_yaml(self, **kwargs):
        from . import safe_dump
        kwargs.setdefault("sort_keys", False)
        return safe_dump(self.to_dict(), **kwargs)

    def __repr__(self):
        return 'PolicyMigrationResult(manual_review=%r)' % (
            [item.path_str for item in self.manual_review],)


class _Pair:
    __slots__ = ('key_node', 'value_node', 'via_merge', 'merge_source',
                 'merge_consumer', 'pair_index')

    def __init__(self, key_node, value_node, via_merge=False,
                 merge_source=None, merge_consumer=None, pair_index=None):
        self.key_node = key_node
        self.value_node = value_node
        self.via_merge = via_merge
        self.merge_source = merge_source
        self.merge_consumer = merge_consumer
        self.pair_index = pair_index


class _Hop:
    __slots__ = ('container', 'segment', 'pair', 'value_node', 'index')

    def __init__(self, container, segment, pair, value_node, index=None):
        self.container = container
        self.segment = segment
        self.pair = pair
        self.value_node = value_node
        self.index = index


class _Resolution:
    __slots__ = ('path', 'hops', 'node', 'present')

    def __init__(self, path, hops, node, present):
        self.path = path
        self.hops = hops
        self.node = node
        self.present = present

    @property
    def via_merge(self):
        return any(hop.pair is not None and hop.pair.via_merge
                   for hop in self.hops)

    @property
    def explicit(self):
        return bool(self.hops) and self.hops[-1].pair is not None \
            and not self.hops[-1].pair.via_merge


def _key_identity(key_node):
    if isinstance(key_node, ScalarNode):
        return ('scalar', key_node.tag, str(key_node.value))
    return ('node', id(key_node))


def _key_matches(segment, key_node):
    if isinstance(key_node, ScalarNode):
        value = key_node.value
        if isinstance(segment, int) and not isinstance(segment, bool):
            try:
                return int(value) == segment
            except (TypeError, ValueError):
                return False
        return str(value) == str(segment)
    return False


def _effective_pairs(mapping, memo=None, stack=None):
    """Return effective mapping pairs, resolving merge keys.

    YAML merge semantics are preserved: the first merge source that provides
    a key wins, and an explicit key wins over any merged key.
    """

    if memo is None:
        memo = {}
    if stack is None:
        stack = set()
    key = id(mapping)
    if key in memo:
        return memo[key]
    if key in stack:
        raise PolicyError("cyclic merge key")
    stack.add(key)
    try:
        ordered = {}
        for key_node, value_node in mapping.value:
            if key_node.tag != _MERGE_TAG:
                continue
            for source in _merge_sources(value_node):
                for pair in _effective_pairs(source, memo, stack):
                    identity = _key_identity(pair.key_node)
                    if identity not in ordered:
                        ordered[identity] = _Pair(
                            pair.key_node,
                            pair.value_node,
                            via_merge=True,
                            merge_source=source,
                            merge_consumer=mapping,
                            pair_index=pair.pair_index,
                        )
        for index, (key_node, value_node) in enumerate(mapping.value):
            if key_node.tag in (_MERGE_TAG, _VALUE_TAG):
                continue
            identity = _key_identity(key_node)
            ordered[identity] = _Pair(
                key_node, value_node, pair_index=index)
        result = list(ordered.values())
        memo[key] = result
        return result
    finally:
        stack.discard(key)


def _merge_sources(node):
    if isinstance(node, MappingNode):
        return [node]
    if isinstance(node, SequenceNode):
        sources = []
        for item in node.value:
            if not isinstance(item, MappingNode):
                raise PolicyError(
                    "merge sequence entries must be mappings, got %s" %
                    item.__class__.__name__)
            sources.append(item)
        return sources
    raise PolicyError("merge value must be a mapping or a list of mappings")


def _find_pair(mapping, segment):
    for pair in _effective_pairs(mapping):
        if _key_matches(segment, pair.key_node):
            return pair
    return None


def _resolve(root, path):
    path = normalize_path(path)
    hops = []
    current = root
    for index, segment in enumerate(path):
        if isinstance(current, MappingNode):
            pair = _find_pair(current, segment)
            if pair is None:
                return _Resolution(path, hops, None, False)
            hops.append(_Hop(current, segment, pair, pair.value_node))
            current = pair.value_node
        elif isinstance(current, SequenceNode):
            if isinstance(segment, str):
                try:
                    position = int(segment)
                except ValueError:
                    return _Resolution(path, hops, None, False)
            else:
                position = segment
            if position < 0 or position >= len(current.value):
                return _Resolution(path, hops, None, False)
            value_node = current.value[position]
            hops.append(_Hop(current, position, None, value_node, position))
            current = value_node
        else:
            return _Resolution(path, hops, None, False)
    return _Resolution(path, hops, current, len(path) == 0 or bool(hops))


def _state_from_node(node):
    if not isinstance(node, ScalarNode):
        return None
    if node.tag == _NULL_TAG:
        return INHERIT
    if node.tag == _BOOL_TAG:
        return ALLOW if str(node.value).lower() in (
            'true', 'yes', 'on') else DENY
    if node.tag == _INT_TAG:
        text = str(node.value).strip()
        if text in ("0", "1"):
            return normalize_state(text)
        return None
    if node.tag == _STR_TAG:
        return normalize_state(node.value, allow_unknown=True)
    return normalize_state(node.value, allow_unknown=True)


def _replace_scalar(node, state):
    node.tag = _STR_TAG
    node.value = state
    node.style = None


def _local_override(shared_node, remaining, state):
    """Build a local mapping/value that merges a shared node and overrides
    one path, so the other consumers of the shared node keep their value."""
    remaining = tuple(remaining)
    if not remaining:
        if isinstance(shared_node, ScalarNode):
            return ScalarNode(_STR_TAG, state)
        raise PolicyError(
            "cannot replace a shared collection with a single policy state")
    if isinstance(shared_node, MappingNode):
        pair = _find_pair(shared_node, remaining[0])
        if pair is None:
            raise PolicyError("cannot isolate missing path %r" % (remaining,))
        key_node = copy.deepcopy(pair.key_node)
        if len(remaining) == 1:
            value_node = ScalarNode(_STR_TAG, state)
        else:
            value_node = copy.deepcopy(pair.value_node)
            sub = _resolve(value_node, remaining[1:])
            if not sub.present or not isinstance(sub.node, ScalarNode):
                raise PolicyError(
                    "cannot isolate path %r" % (remaining,))
            _replace_scalar(sub.node, state)
        merge_key = ScalarNode(_MERGE_TAG, "<<")
        return MappingNode(
            _MAP_TAG,
            [(merge_key, shared_node), (key_node, value_node)],
            flow_style=getattr(shared_node, "flow_style", None))
    if isinstance(shared_node, SequenceNode):
        local = copy.deepcopy(shared_node)
        sub = _resolve(local, remaining)
        if not sub.present or not isinstance(sub.node, ScalarNode):
            raise PolicyError("cannot isolate path %r" % (remaining,))
        _replace_scalar(sub.node, state)
        return local
    raise PolicyError("cannot isolate a shared scalar below a path")


def _walk_paths(node, path, node_paths, visiting, include_nulls,
                contract_paths):
    node_paths.setdefault(id(node), []).append(path)
    if id(node) in visiting:
        return
    visiting.add(id(node))
    try:
        if isinstance(node, MappingNode):
            for pair in _effective_pairs(node):
                child = path + (
                    pair.key_node.value
                    if isinstance(pair.key_node, ScalarNode)
                    else '<key>',
                )
                _walk_paths(pair.value_node, child, node_paths, visiting,
                            include_nulls, contract_paths)
        elif isinstance(node, SequenceNode):
            for index, item in enumerate(node.value):
                _walk_paths(item, path + (index,), node_paths, visiting,
                            include_nulls, contract_paths)
        elif isinstance(node, ScalarNode):
            state = _state_from_node(node)
            if state is None:
                return
            if not _leaf_is_decision(path, node, contract_paths):
                return
            if node.tag == _NULL_TAG and not include_nulls \
                    and normalize_path(path) not in contract_paths:
                return
    finally:
        visiting.discard(id(node))


class PolicyDocument:
    """A parsed policy document with path-level tri-state decisions."""

    def __init__(self, root, anchors=None, source=None, loader=SafeLoader):
        self.root = root
        self.anchors = dict(anchors or {})
        self.source = source
        self.loader = loader
        self._node_paths = None

    @classmethod
    def from_stream(cls, stream, *, Loader=None):
        text = _read_stream(stream)
        root, anchors = _compose_with_anchors(text)
        if root is None:
            raise PolicyError("policy document is empty")
        Loader = Loader or SafeLoader
        from . import load as _load
        data = _load(text, Loader=Loader)
        document = cls(root, anchors, source=text, loader=Loader)
        document.data = data
        return document

    @classmethod
    def from_data(cls, data, *, Dumper=None):
        if Dumper is None:
            from . import safe_dump
            text = safe_dump(data, sort_keys=False)
        else:
            from . import dump
            text = dump(data, Dumper=Dumper, sort_keys=False)
        document = cls.from_stream(text)
        document.data = data
        return document

    def copy(self):
        memo = {}
        root = copy.deepcopy(self.root, memo)
        anchors = {}
        for name, node in self.anchors.items():
            anchors[name] = memo.get(id(node), node)
        duplicate = PolicyDocument(root, anchors, self.source, self.loader)
        duplicate.data = copy.deepcopy(getattr(self, 'data', None))
        return duplicate

    def _index(self, contract_paths=(), include_nulls=True):
        if self._node_paths is None:
            self._node_paths = {}
            _walk_paths(self.root, (), self._node_paths, set(),
                        True, set())
        return self._node_paths

    def _reset_cache(self):
        self._node_paths = None

    def resolve(self, path):
        return _resolve(self.root, path)

    def decision(self, path):
        resolution = self.resolve(path)
        if not resolution.present:
            return PolicyDecision(path, None, False, False, False, False)
        state = _state_from_node(resolution.node)
        node_paths = self._index()
        paths = node_paths.get(id(resolution.node), [])
        shared_with = tuple(item for item in paths if item != resolution.path)
        return PolicyDecision(
            path,
            state,
            True,
            resolution.explicit,
            resolution.via_merge,
            bool(shared_with),
            shared_with=shared_with,
        )

    def state(self, path):
        return self.decision(path).state

    def get_state(self, path):
        return self.state(path)

    def set_state(self, path, state, **kwargs):
        return self.set(path, state, **kwargs)

    def decision_paths(self):
        node_paths = self._index()
        paths = set()
        for node in _iter_nodes(self.root):
            if isinstance(node, ScalarNode) and _state_from_node(node) is not None:
                for path in node_paths.get(id(node), ()):
                    if _leaf_is_decision(path, node):
                        paths.add(path)
        return sorted(paths, key=_path_sort_key)

    def decisions(self, include_nulls=True):
        result = _PathMap()
        paths = set()
        node_paths = self._index(include_nulls=include_nulls)
        for node in _iter_nodes(self.root):
            if not isinstance(node, ScalarNode):
                continue
            state = _state_from_node(node)
            if state is None:
                continue
            if node.tag == _NULL_TAG and not include_nulls:
                continue
            for path in node_paths.get(id(node), ()):
                if path and _leaf_is_decision(path, node):
                    paths.add(path)
        for path in sorted(paths, key=_path_sort_key):
            result[path] = self.decision(path)
        return result

    @property
    def shared(self):
        return self.shared_items()

    def shared_items(self, contract_paths=()):
        node_paths = self._index(contract_paths)
        contract_paths = tuple(normalize_path(path) for path in contract_paths)
        result = _PathMap()
        for node_id, paths in node_paths.items():
            unique = sorted(set(paths), key=_path_sort_key)
            if len(unique) < 2:
                continue
            if contract_paths and not any(
                    _is_related_path(path, contract_paths)
                    for path in unique):
                continue
            anchors = sorted(
                name for name, node in self.anchors.items()
                if id(node) == node_id)
            definition = self._definition_path(anchors, unique)
            node = _first_node(self.root, node_id)
            if isinstance(node, MappingNode):
                kind = 'mapping'
            elif isinstance(node, SequenceNode):
                kind = 'sequence'
            else:
                kind = 'value'
            item = SharedItem(definition, unique, anchors, kind)
            result[definition] = item
        return result

    def _definition_path(self, anchors, paths):
        for name in anchors:
            node = self.anchors[name]
            for path in paths:
                if _resolve(self.root, path).node is node:
                    return path
        return min(paths, key=lambda item: (len(item), _path_sort_key(item)))

    def _node_definition_path(self, node, node_paths=None):
        if node_paths is None:
            node_paths = self._index()
        paths = sorted(set(node_paths.get(id(node), ())), key=_path_sort_key)
        if not paths:
            return ()
        anchors = sorted(
            name for name, value in self.anchors.items()
            if id(value) == id(node))
        return self._definition_path(anchors, paths)

    def _is_definition_path(self, path, node, node_paths=None):
        definition = self._node_definition_path(node, node_paths)
        return bool(definition) and path[:len(definition)] == definition

    def apply(self, changes, *, isolate=True):
        items = changes.items() if isinstance(changes, dict) else changes
        for change in items:
            if isinstance(change, PolicyChange):
                self.set(change.path, change.state, isolate=change.isolate)
            else:
                path, state = change
                self.set(path, state, isolate=isolate)
        return self

    def update(self, changes, *, isolate=True):
        return self.apply(changes, isolate=isolate)

    def set(self, path, state, *, isolate=True):
        """Set the tri-state decision at ``path``.

        When ``isolate`` is true and the value is only present through a merge
        key, a local explicit key is added to the consumer mapping.  This keeps
        the shared source (and its other consumers) unchanged.
        """

        state = normalize_state(state)
        path = normalize_path(path)
        resolution = self.resolve(path)
        if not resolution.present:
            return self._insert(path, state)
        node_paths = self._index()
        if isolate:
            for index, hop in enumerate(resolution.hops):
                if hop.pair is None or hop.pair.via_merge:
                    continue
                shared_paths = set(node_paths.get(id(hop.value_node), ()))
                if len(shared_paths) > 1 and not self._is_definition_path(
                        path, hop.value_node, node_paths):
                    remaining = path[index + 1:]
                    replacement = _local_override(
                        hop.value_node, remaining, state)
                    hop.container.value[hop.pair.pair_index] = (
                        hop.pair.key_node, replacement)
                    self._reset_cache()
                    return self.decision(path)
        merge_index = next(
            (index for index, hop in enumerate(resolution.hops)
             if hop.pair is not None and hop.pair.via_merge),
            None,
        )
        if isolate and merge_index is not None:
            hop = resolution.hops[merge_index]
            local_value = copy.deepcopy(hop.value_node)
            key_node = copy.deepcopy(hop.pair.key_node)
            hop.container.value.append((key_node, local_value))
            remaining = path[merge_index + 1:]
            if remaining:
                sub = _resolve(local_value, remaining)
                if not sub.present:
                    raise PolicyError(
                        "cannot isolate missing path %r" % (path,))
                _replace_scalar(sub.node, state)
            else:
                _replace_scalar(local_value, state)
            self._reset_cache()
            return self.decision(path)
        if isolate and resolution.explicit:
            node_paths = self._index()
            if len(set(node_paths.get(id(resolution.node), ()))) > 1 \
                    and not self._is_definition_path(
                        path, resolution.node, node_paths):
                hop = resolution.hops[-1]
                replacement = copy.deepcopy(resolution.node)
                _replace_scalar(replacement, state)
                if hop.pair is None:
                    hop.container.value[hop.index] = replacement
                else:
                    hop.container.value[hop.pair.pair_index] = (
                        hop.pair.key_node, replacement)
                self._reset_cache()
                return self.decision(path)
        if not isinstance(resolution.node, ScalarNode):
            raise PolicyError("policy path %r does not point to a scalar"
                              % (path,))
        _replace_scalar(resolution.node, state)
        self._reset_cache()
        return self.decision(path)

    def _insert(self, path, state):
        if not path:
            raise PolicyError("cannot replace the document root with a state")
        parent_path = path[:-1]
        resolution = self.resolve(parent_path)
        if not resolution.present:
            raise PolicyError("cannot insert %r: parent path is missing"
                              % (path,))
        if not isinstance(resolution.node, MappingNode):
            raise PolicyError("cannot insert %r: parent is not a mapping"
                              % (path,))
        key = path[-1]
        node = ScalarNode(_STR_TAG, str(key))
        value = ScalarNode(_STR_TAG, state)
        resolution.node.value.append((node, value))
        self._reset_cache()
        return self.decision(path)

    def dump(self, *, canonical=True, Dumper=None, contract=None, **kwargs):
        node = copy.deepcopy(self.root)
        if canonical:
            paths = ()
            if isinstance(contract, PolicyContract):
                paths = tuple(contract.declared_paths(self))
            elif contract:
                paths = tuple(normalize_path(path) for path in contract)
            _canonicalize(node, (), set(), paths)
        from . import serialize as _serialize
        if Dumper is None:
            from .dumper import SafeDumper
            Dumper = SafeDumper
        kwargs.setdefault('allow_unicode', True)
        return _serialize(node, Dumper=Dumper, **kwargs)

    @property
    def states(self):
        return {
            path_string(path): decision.state
            for path, decision in self.decisions().items()
        }

    def to_dict(self):
        return {
            "decisions": self.states,
            "shared": {
                path_string(path): item.to_dict()
                for path, item in self.shared_items().items()
            },
        }

    def __getitem__(self, key):
        return getattr(self, "data", None)[key]

    def __contains__(self, key):
        data = getattr(self, "data", None)
        return data is not None and key in data

    def get(self, key, default=None):
        data = getattr(self, "data", None)
        if data is None:
            return default
        return data.get(key, default)

    def keys(self):
        return getattr(self, "data", {}).keys()

    def items(self):
        return getattr(self, "data", {}).items()

    def values(self):
        return getattr(self, "data", {}).values()

    def __eq__(self, other):
        if isinstance(other, PolicyDocument):
            return getattr(self, "data", None) == getattr(other, "data", None)
        return getattr(self, "data", None) == other

    def __repr__(self):
        return 'PolicyDocument(anchor_count=%d)' % len(self.anchors)


def _first_node(root, node_id):
    for node in _iter_nodes(root):
        if id(node) == node_id:
            return node
    return None


def _is_related_path(path, contract_paths):
    for wanted in contract_paths:
        if path[:len(wanted)] == wanted or wanted[:len(path)] == path:
            return True
    return False


def _iter_nodes(root):
    seen = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        yield node
        if isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                stack.append(key_node)
                stack.append(value_node)
        elif isinstance(node, SequenceNode):
            stack.extend(node.value)


def _canonicalize(node, path, seen, contract_paths=()):
    if id(node) in seen:
        return
    seen.add(id(node))
    if isinstance(node, MappingNode):
        for key_node, value_node in node.value:
            child = path + (
                key_node.value if isinstance(key_node, ScalarNode) else '<key>',
            )
            _canonicalize(value_node, child, seen, contract_paths)
    elif isinstance(node, SequenceNode):
        for index, item in enumerate(node.value):
            _canonicalize(item, path + (index,), seen, contract_paths)
    elif isinstance(node, ScalarNode):
        state = _state_from_node(node)
        if state is not None and _leaf_is_decision(path, node, contract_paths):
            _replace_scalar(node, state)


def _read_stream(stream):
    if hasattr(stream, 'read'):
        return stream.read()
    return stream


def _compose_with_anchors(stream):
    class StructuralLoader(SafeLoader):
        captured_anchors = {}

        def compose_document(self):
            self.get_event()
            node = self.compose_node(None, None)
            self.get_event()
            self.captured_anchors = dict(self.anchors)
            self.anchors = {}
            return node

    loader = StructuralLoader(stream)
    try:
        root = loader.get_single_node()
        return root, dict(loader.captured_anchors)
    finally:
        loader.dispose()


def supported_loaders():
    """Return the safe-ish loaders available in this installation."""

    loaders = []
    for loader in (CSafeLoader, SafeLoader, CFullLoader, FullLoader):
        if loader is not None and loader not in loaders:
            loaders.append(loader)
    return loaders


def other_supported_loader(loader=None):
    """Pick a different supported load entry point than ``loader``."""

    loader = loader or SafeLoader
    if loader is SafeLoader and CSafeLoader is not None:
        return CSafeLoader
    if loader is CSafeLoader and SafeLoader is not None:
        return SafeLoader
    if loader is FullLoader and CFullLoader is not None:
        return CFullLoader
    if loader is CFullLoader and FullLoader is not None:
        return FullLoader
    for candidate in supported_loaders():
        if candidate is not loader:
            return candidate
    return loader


def load_policy(stream, *, Loader=None, loader=None):
    """Load one policy document with explicit tri-state paths."""

    return PolicyDocument.from_stream(stream, Loader=Loader or loader)


def load_policy_all(stream, *, Loader=None, loader=None):
    """Load every document in a stream, retaining sharing information."""

    Loader = Loader or loader
    text = _read_stream(stream)
    # Split only for the common case; PyYAML's parser is the source of truth.
    from . import compose_all
    documents = []
    for node in compose_all(text, Loader=Loader or SafeLoader):
        if node is None:
            continue
        documents.append(PolicyDocument(node))
    return documents


def dump_policy(document_or_stream, *, canonical=True, Loader=None,
                loader=None, **kwargs):
    """Serialize a policy document without dropping its sharing structure."""

    Loader = Loader or loader
    if isinstance(document_or_stream, PolicyDocument):
        document = document_or_stream
    elif isinstance(document_or_stream, (dict, list, tuple)):
        document = PolicyDocument.from_data(document_or_stream)
    else:
        document = PolicyDocument.from_stream(document_or_stream, Loader=Loader)
    return document.dump(canonical=canonical, **kwargs)


def verify_policy_roundtrip(before, after, contract=None, *,
                            constraints=None, schema=None,
                            expected_changes=None, strict_tristate=True,
                            loaders=None, manual_review=()):
    """Verify that a policy round trip preserved decisions and sharing.

    ``before`` and ``after`` may be policy documents, YAML streams, or plain
    Python data.  ``contract`` restricts which paths are checked and which
    states are acceptable.
    """

    if contract is None:
        contract = constraints if constraints is not None else schema
    before_doc = _as_document(before)
    after_doc = _as_document(after)
    if contract is None:
        contract = PolicyContract()
    elif not isinstance(contract, PolicyContract):
        contract = PolicyContract(contract)

    changes = _normalize_changes(expected_changes)
    issues = []
    targets = contract.declared_paths(after_doc)
    if not contract.entries:
        targets = sorted(set(before_doc.decision_paths())
                         | set(after_doc.decision_paths()))

    after_decisions = _PathMap()
    before_decisions = _PathMap()
    for path in targets:
        previous = before_doc.decision(path)
        current = after_doc.decision(path)
        before_decisions[path] = previous
        after_decisions[path] = current
        for constraint in contract.constraints_for(path) or [PolicyConstraint(path)]:
            _check_decision(path, previous, current, constraint, changes,
                            issues, after_doc)

    if strict_tristate:
        _check_lost_decisions(before_doc, after_doc, changes, issues, targets)

    shared = after_doc.shared_items(targets)
    _check_sharing(before_doc, after_doc, targets, changes, issues, shared)
    for path in _lossy_sharing_paths(before_doc, after_doc, targets):
        if path not in changes and not any(
                issue.kind == 'sharing_changed' and issue.path == path
                for issue in issues):
            issues.append(PolicyIssue(
                'sharing_changed', path,
                'shared consumer set changed across the round trip'))

    reviews = list(manual_review or ())
    for path in targets:
        for constraint in contract.constraints_for(path):
            if constraint.manual_review:
                reviews.append(ManualReview(
                    path, "contract_manual_review",
                    detail=constraint.legacy or
                    "contract requires manual confirmation"))
    return PolicyReport(
        issues=issues,
        decisions=after_decisions,
        before_decisions=before_decisions,
        shared=shared,
        manual_review=reviews,
        before=before_doc,
        after=after_doc,
        expected_changes=changes,
        loaders=loaders,
    )


def _normalize_changes(changes):
    result = {}
    if not changes:
        return result
    if isinstance(changes, dict):
        items = changes.items()
    else:
        items = changes
    for change in items:
        if isinstance(change, PolicyChange):
            result[change.path] = change.state
            continue
        path, state = change
        result[normalize_path(path)] = normalize_state(state)
    return result


def _check_decision(path, previous, current, constraint, changes, issues,
                    after_doc):
    state = current.state
    requested = changes.get(normalize_path(path))
    if not current.present:
        lost_deny = previous.present and previous.state == DENY
        if lost_deny:
            issues.append(PolicyIssue(
                "decision_lost", path,
                "explicit deny was lost instead of being written back",
                before=previous.state, after=None))
        elif constraint.default is not None:
            state = constraint.default
            issues.append(PolicyIssue(
                "default_used", path,
                "path is absent; contract default %r applies" % state,
                severity="info", after=state))
        elif constraint.required:
            issues.append(PolicyIssue(
                "missing", path,
                "required policy path is absent",
                before=previous.state if previous.present else None))
        if requested is not None and not lost_deny:
            issues.append(PolicyIssue(
                "change_not_applied", path,
                "requested %r decision was not written explicitly" % requested,
                before=previous.state, after=None))
        return
    if state is None:
        issues.append(PolicyIssue(
            "not_a_decision", path,
            "declared policy path is not a tri-state scalar",
            after=state))
        return
    if constraint.allowed is not None and state not in constraint.allowed:
        issues.append(PolicyIssue(
            "state_not_allowed", path,
            "state %r is not allowed by the verification contract" % state,
            detail={"allowed": sorted(constraint.allowed)},
            before=previous.state,
            after=state))
    if constraint.shared is True and len(current.shared_with) == 0:
        issues.append(PolicyIssue(
            "sharing_required", path,
            "contract requires this path to be a shared consumer"))
    if constraint.shared is False and current.shared_with:
        issues.append(PolicyIssue(
            "unexpected_sharing", path,
            "contract forbids sharing for this path",
            detail={"shared_with": [path_string(item)
                                    for item in current.shared_with]}))
    if constraint.manual_review:
        issues.append(PolicyIssue(
            "manual_review", path,
            "contract marks this path for manual review",
            severity="warning"))

    if requested is not None:
        if state != requested:
            issues.append(PolicyIssue(
                "change_not_applied", path,
                "requested %r but reloaded as %r" % (requested, state),
                before=previous.state, after=state))
        return

    if not previous.present and current.present:
        issues.append(PolicyIssue(
            "unexpected_change", path,
            "a decision appeared where none existed before",
            before=None, after=state))
    elif previous.present and not current.present:
        kind = "decision_lost" if previous.state == DENY else "unexpected_change"
        issues.append(PolicyIssue(
            kind, path,
            "decision %r disappeared" % previous.state,
            before=previous.state, after=None))
    elif previous.state != state:
        if previous.state == DENY and state == INHERIT:
            issues.append(PolicyIssue(
                "decision_lost", path,
                "explicit deny was downgraded to the default/inherit state",
                before=previous.state, after=state))
        else:
            issues.append(PolicyIssue(
                "unexpected_change", path,
                "decision changed without being requested",
                before=previous.state, after=state))


def _check_lost_decisions(before_doc, after_doc, changes, issues, targets):
    checked = set(normalize_path(path) for path in targets)
    for path, previous in before_doc.decisions(include_nulls=True).items():
        if path in checked or path in changes:
            continue
        if previous.state != DENY:
            continue
        current = after_doc.decision(path)
        if not current.present or current.state == INHERIT:
            issues.append(PolicyIssue(
                'decision_lost', path,
                'explicit deny disappeared during the round trip',
                before=previous.state,
                after=current.state if current.present else None))


def _check_sharing(before_doc, after_doc, targets, changes, issues, shared):
    changed = set(changes)
    for path in targets:
        if path in changed:
            continue
        before = set(before_doc.decision(path).shared_with)
        after = set(after_doc.decision(path).shared_with)
        before = before - changed
        after = after - changed
        unexpected = before ^ after
        if unexpected:
            issues.append(PolicyIssue(
                "sharing_changed", path,
                "shared consumer set changed across the round trip",
                detail={
                    "before": sorted(path_string(item) for item in before),
                    "after": sorted(path_string(item) for item in after),
                }))
        elif set(before_doc.decision(path).shared_with) != set(
                after_doc.decision(path).shared_with):
            issues.append(PolicyIssue(
                "sharing_changed", path,
                "shared consumer set changed as requested by an explicit "
                "path override",
                severity="info",
                detail={
                    "before": sorted(path_string(item)
                                     for item in before_doc.decision(path).shared_with),
                    "after": sorted(path_string(item)
                                    for item in after_doc.decision(path).shared_with),
                }))


def _lossy_sharing_paths(before_doc, after_doc, targets):
    paths = []
    for path in targets:
        before = before_doc.decision(path)
        after = after_doc.decision(path)
        if before.present and after.present and before.via_alias \
                and not after.via_alias:
            paths.append(path)
    return paths


def roundtrip_policy(source, contract=None, *, constraints=None,
                     schema=None, changes=None, loader=None, Loader=None,
                     reload_loader=None,
                     isolate=True, canonical=True, Dumper=None,
                     manual_review=(), through=None):
    """Read, edit, save and reload a security policy.

    The saved document is reloaded through a *different* supported load
    entry point (for example pure-Python ``SafeLoader`` versus
    ``CSafeLoader`` when libyaml is available).  The returned report contains
    the decisions and shared consumers seen by that second loader.

    ``through`` can be a callable that models an intermediate tool.  It
    receives the plain Python data and returns replacement data; this is the
    lossy path the verification is designed to catch.
    """

    if contract is None:
        contract = constraints if constraints is not None else schema
    loader = loader or Loader or SafeLoader
    reload_loader = reload_loader or other_supported_loader(loader)
    before = _as_document(source, Loader=loader)
    working = before.copy()
    applied = []
    if callable(changes) and not isinstance(
            changes, (dict, list, tuple, PolicyChange)):
        result = changes(working)
        if isinstance(result, PolicyDocument):
            working = result
        elif result is not None and not isinstance(result, (dict, list)):
            raise PolicyError(
                "policy change callback must return a PolicyDocument or None")
    elif changes:
        if isinstance(changes, PolicyChange):
            changes = [changes]
        items = changes.items() if isinstance(changes, dict) else changes
        for change in items:
            if isinstance(change, PolicyChange):
                applied.append(change)
            else:
                path, state = change
                applied.append(PolicyChange(path, state, isolate=isolate))
    for change in applied:
        working.set(change.path, change.state,
                    isolate=change.isolate if change.isolate is not None
                    else isolate)

    if through is not None:
        from . import safe_dump, safe_load
        materialized = safe_load(working.dump(canonical=True,
                                             contract=contract))
        transformed = through(copy.deepcopy(materialized))
        if isinstance(transformed, (str, bytes)):
            text = transformed
        else:
            text = safe_dump(transformed, sort_keys=False)
        after = _as_document(text, Loader=reload_loader)
    else:
        text = working.dump(canonical=canonical, Dumper=Dumper,
                            contract=contract)
        after = _as_document(text, Loader=reload_loader)

    # Also read the saved text with the original entry point so the report can
    # show a loader mismatch instead of hiding it.
    cross = _as_document(text, Loader=loader)
    report = verify_policy_roundtrip(
        before, after, contract,
        expected_changes={change.path: change.state for change in applied},
        loaders=(loader, reload_loader),
        manual_review=manual_review,
    )
    for path in sorted(set(after.decision_paths()) | set(cross.decision_paths()), key=_path_sort_key):
        left = after.decision(path)
        right = cross.decision(path)
        if (left.present, left.state) != (right.present, right.state):
            report.issues.append(PolicyIssue(
                'loader_mismatch', path,
                'the two supported load entry points disagree',
                detail={
                    'first': right.state if right.present else None,
                    'second': left.state if left.present else None,
                }))
    return PolicyRoundTripResult(text, before, after, report, applied)


def migrate_legacy_policy(source, contract=None, *, constraints=None,
                          schema=None, loader=None, Loader=None,
                          legacy_values=None, manual_review=None):
    """Canonicalize an old policy and point out fields needing human review.

    Recoverable legacy values (booleans, common aliases and explicit
    ``null``) become canonical tri-state strings.  Values whose meaning
    cannot be established are left untouched and reported in
    ``manual_review``.  In particular, an old ``false`` becomes ``deny``, never
    the default/inherit state.
    """

    if contract is None:
        contract = constraints if constraints is not None else schema
    loader = loader or Loader or SafeLoader
    document = _as_document(source, Loader=loader)
    if contract is None:
        contract = PolicyContract()
    elif not isinstance(contract, PolicyContract):
        contract = PolicyContract(contract)

    reviews = []
    if manual_review:
        for path, reason in (manual_review.items()
                             if isinstance(manual_review, dict)
                             else manual_review):
            reviews.append(ManualReview(path, 'caller',
                                        detail=str(reason)))

    legacy_values = {
        normalize_path(path): value
        for path, value in (legacy_values or {}).items()
    }
    handled = set()
    for node, path in _leaf_nodes(
            document, contract.declared_paths(document)):
        if not path:
            continue
        constraint = _constraint_for(contract, path)
        state, note = _legacy_state(node)
        if state is None:
            handled.add(path)
            reviews.append(ManualReview(
                path, 'unknown_legacy_value',
                detail='legacy value %r has no unambiguous tri-state meaning'
                       % _safe_value(node)))
            continue
        if node.tag == _NULL_TAG:
            reviews.append(ManualReview(
                path, 'legacy_empty_value',
                detail='empty value is provisionally inherit; confirm whether '
                       'it was meant as an explicit deny',
                suggested=INHERIT))
        if node.tag == _BOOL_TAG:
            note = note or 'legacy boolean mapped to %r' % state
        if constraint is not None and constraint.manual_review:
            reviews.append(ManualReview(
                path, 'contract_manual_review',
                detail=constraint.legacy or
                       'contract requires manual confirmation',
                suggested=state))
        if path in legacy_values:
            requested = normalize_state(legacy_values[path])
            if requested != state:
                reviews.append(ManualReview(
                    path, 'legacy_value_override',
                    detail='caller says %r; document says %r'
                           % (requested, state),
                    suggested=requested))
                state = requested
        _replace_scalar(node, state)
        handled.add(path)

    for path in contract.declared_paths(document):
        if path not in handled:
            constraint = _constraint_for(contract, path)
            if constraint is not None and constraint.required:
                reviews.append(ManualReview(
                    path, 'missing_legacy_field',
                    detail='field is absent in the legacy document; '
                           'the intended tri-state must be supplied manually',
                    suggested=constraint.default))

    if isinstance(getattr(document, 'data', None), dict):
        for path in contract.declared_paths(document):
            constraint = _constraint_for(contract, path)
            if constraint is not None and (constraint.shared or
                                           constraint.sharing_sensitive):
                reviews.append(ManualReview(
                    path, 'sharing_unrecoverable',
                    detail='legacy data was already materialized; its original '
                           'anchor/alias sharing cannot be proven'))

    document._reset_cache()
    text = document.dump(canonical=True, contract=contract)
    after = _as_document(text)
    report = verify_policy_roundtrip(
        document, after, contract, manual_review=reviews)
    # Missing/migration-only issues are already represented as manual reviews.
    report.issues = [issue for issue in report.issues
                     if issue.kind not in ('missing', 'not_a_decision')]
    return PolicyMigrationResult(document, text, report, reviews)


def _legacy_state(node):
    if not isinstance(node, ScalarNode):
        return None, None
    if node.tag == _NULL_TAG:
        return INHERIT, 'legacy empty value treated as inherit'
    if node.tag == _BOOL_TAG:
        return (ALLOW if str(node.value).lower() in ('true', 'yes', 'on')
                else DENY), 'legacy boolean'
    if node.tag == _INT_TAG:
        return normalize_state(node.value, allow_unknown=True), 'legacy integer'
    if node.tag == _STR_TAG:
        return normalize_state(node.value, allow_unknown=True), 'legacy alias'
    return normalize_state(node.value, allow_unknown=True), None


def _safe_value(node):
    value = str(getattr(node, 'value', ''))
    if len(value) > 40:
        value = value[:37] + '...'
    return value


def _leaf_nodes(document, contract_paths=()):
    contract_paths = set(normalize_path(path) for path in contract_paths)
    seen_paths = set()
    for path in document.decision_paths():
        if path in seen_paths:
            continue
        seen_paths.add(path)
        resolution = document.resolve(path)
        if resolution.present and isinstance(resolution.node, ScalarNode):
            yield resolution.node, path
    # Also include null leaves, which decision_paths skips when it cannot tell
    # whether they are policy fields.
    node_paths = document._index(include_nulls=True)
    for node in _iter_nodes(document.root):
        if not isinstance(node, ScalarNode):
            continue
        for path in node_paths.get(id(node), ()):
            if path and path not in seen_paths and _leaf_is_decision(
                    path, node, contract_paths):
                seen_paths.add(path)
                yield node, path


def _constraint_for(contract, path):
    matches = contract.constraints_for(path)
    return matches[0] if matches else None


def _as_document(value, *, Loader=None):
    if isinstance(value, PolicyDocument):
        return value
    if hasattr(value, 'read') or isinstance(value, (str, bytes)):
        return PolicyDocument.from_stream(value, Loader=Loader)
    if isinstance(value, (dict, list, tuple)):
        return PolicyDocument.from_data(value)
    raise PolicyError("cannot use %r as a policy document" % (value,))


# Friendly aliases used by callers that describe the operation rather than
# the data model.
policy_roundtrip = roundtrip_policy
verify_roundtrip = verify_policy_roundtrip
security_roundtrip = roundtrip_policy
config_roundtrip = roundtrip_policy
safe_roundtrip = roundtrip_policy
verify_policy = verify_policy_roundtrip
migrate_policy = migrate_legacy_policy
security_config_roundtrip = roundtrip_policy
verify_security_roundtrip = verify_policy_roundtrip
migrate_policy_config = migrate_legacy_policy

# Short names for callers that use the module as a namespace.
roundtrip = roundtrip_policy
verify = verify_policy_roundtrip
migrate = migrate_legacy_policy
PolicyConfig = PolicyDocument
TriState = PolicyState
PolicyRoundTripReport = PolicyReport
PolicyVerificationReport = PolicyReport

round_trip = roundtrip_policy
verify_round_trip = verify_policy_roundtrip
migrate_legacy = migrate_legacy_policy
