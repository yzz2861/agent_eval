"""
Pre-load review mode for shared YAML configuration blocks.

Security policy documents often define a shared block once (an anchored
mapping) and let several resources consume it through aliases and merge
keys.  A change approval usually covers only one of those resources, so
editing the shared block silently affects the others.

This module reviews such an update *before* the document is handed to a
safe loader for construction:

* the document is composed with a SafeLoader subclass, so no custom
  objects are built during review;
* the caller defines resource roles that bind consumption paths to
  approval scopes;
* the reviewer records the actual consumption paths of every anchored
  (shared) node, including merge-key consumers;
* a partial update to a shared mapping is checked against the granted
  approvals: paths covered by an approval are released, every other
  consumer is reported as an impact that still requires approval.

Merge keys (``<<``), aliased mappings and caller-restricted custom tags
(``allowed_tags``) coexist: only the tags the caller explicitly allows
are constructible, anything else fails the review as usual.
"""

__all__ = [
    'ReviewError',
    'ResourceRole',
    'MappingUpdate',
    'ReviewImpact',
    'ReviewReport',
    'review_update',
]

import fnmatch

from .error import YAMLError
from .loader import SafeLoader
from .nodes import MappingNode, ScalarNode, SequenceNode

MERGE_TAG = 'tag:yaml.org,2002:merge'
STANDARD_TAG_PREFIX = 'tag:yaml.org,2002:'


def _tag_checker(allowed_tags):
    exact_tags = set()
    tag_prefixes = []
    for entry in allowed_tags:
        if entry.endswith('*'):
            tag_prefixes.append(entry[:-1])
        else:
            exact_tags.add(entry)

    def check_tag(tag):
        if tag.startswith(STANDARD_TAG_PREFIX):
            return
        if tag in exact_tags:
            return
        if any(tag.startswith(prefix) for prefix in tag_prefixes):
            return
        raise ReviewError(
            "tag %r is not in the caller-restricted allowed tags" % tag)

    return check_tag


class ReviewError(YAMLError):
    pass


class ResourceRole:
    """Caller-defined binding of consumption paths to an approval scope."""

    def __init__(self, name, patterns, scope=None):
        if isinstance(patterns, str):
            patterns = [patterns]
        self.name = name
        self.patterns = tuple(patterns)
        self.scope = scope if scope is not None else name

    def matches(self, path):
        return any(fnmatch.fnmatchcase(path, pattern)
                   for pattern in self.patterns)


class MappingUpdate:
    """A legitimate partial update: only the given keys of the anchored
    mapping are set, the rest of the shared block is left untouched."""

    def __init__(self, anchor, values):
        if not isinstance(values, dict) or not values:
            raise ReviewError("a partial update requires a non-empty mapping")
        for key, value in values.items():
            if not isinstance(key, str):
                raise ReviewError("update keys must be strings: %r" % (key,))
            _ensure_plain_data(value)
        self.anchor = anchor
        self.values = dict(values)


class ReviewImpact:
    """One consumption path affected by a reviewed change."""

    def __init__(self, path, role, scope, approved, via_merge):
        self.path = path
        self.role = role
        self.scope = scope
        self.approved = approved
        self.via_merge = via_merge

    def __repr__(self):
        status = 'approved' if self.approved else 'requires-approval'
        return 'ReviewImpact(%r, role=%r, scope=%r, %s)' % (
            self.path, self.role, self.scope, status)


class ReviewReport:
    """Outcome of reviewing a partial update against resource roles."""

    def __init__(self, change, consumption, impacts, updated):
        self.change = change
        # anchor name -> sorted list of actual consumption paths.
        self.consumption = consumption
        self.impacts = impacts
        # Preview of the shared block after the partial update.
        self.updated = updated

    @property
    def allowed(self):
        """Impacts released by the granted approvals."""
        return [impact for impact in self.impacts if impact.approved]

    @property
    def requires_approval(self):
        """Impacts whose resource role still needs a separate approval."""
        return [impact for impact in self.impacts if not impact.approved]

    @property
    def permitted(self):
        """The partial update may proceed for the approved scopes."""
        return bool(self.allowed)


def _ensure_plain_data(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _ensure_plain_data(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReviewError("update keys must be strings: %r" % (key,))
            _ensure_plain_data(item)
        return
    raise ReviewError("update values must be plain data: %r" % (value,))


def _make_review_loader(check_tag):
    class ReviewLoader(SafeLoader):
        """SafeLoader that remembers anchors and only constructs
        caller-restricted custom tags."""

        def compose_document(self):
            self.get_event()
            node = self.compose_node(None, None)
            self.get_event()
            self.review_anchors = dict(self.anchors)
            self.anchors = {}
            return node

    def construct_restricted_tag(loader, tag_suffix, node):
        check_tag('!' + tag_suffix)
        if isinstance(node, ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_mapping(node, deep=True)

    ReviewLoader.add_multi_constructor('!', construct_restricted_tag)
    return ReviewLoader


def _walk(node, path, paths, visiting, check_tag):
    check_tag(node.tag)
    paths.setdefault(id(node), []).append(path)
    if id(node) in visiting:
        return
    visiting.add(id(node))
    if isinstance(node, MappingNode):
        for key_node, value_node in node.value:
            if key_node.tag == MERGE_TAG:
                child = path + '.<<'
            elif isinstance(key_node, ScalarNode):
                child = path + '.' + str(key_node.value) if path \
                        else str(key_node.value)
            else:
                child = path + '.?'
            _walk(value_node, child, paths, visiting, check_tag)
    elif isinstance(node, SequenceNode):
        for index, item in enumerate(node.value):
            _walk(item, '%s[%d]' % (path, index), paths, visiting,
                  check_tag)
    visiting.discard(id(node))


def _find_role(roles, path):
    for role in roles:
        if role.matches(path):
            return role
    return None


def review_update(stream, change, roles, approvals=(), allowed_tags=()):
    """Review a partial update to a shared block before safe-loading.

    ``stream`` is the YAML source, ``change`` a MappingUpdate targeting an
    anchored mapping, ``roles`` the caller-defined ResourceRole list,
    ``approvals`` the granted approval scopes, and ``allowed_tags`` the
    caller-restricted custom tags that may be constructed (exact tags, or
    prefixes ending in ``*``).
    """
    if not isinstance(change, MappingUpdate):
        raise ReviewError("only MappingUpdate changes can be reviewed")
    check_tag = _tag_checker(allowed_tags)
    loader_class = _make_review_loader(check_tag)
    loader = loader_class(stream)
    try:
        root = loader.get_single_node()
        anchors = getattr(loader, 'review_anchors', {})
        if root is None:
            raise ReviewError("cannot review an empty document")
        paths = {}
        _walk(root, '', paths, set(), check_tag)
        consumption = {}
        consumers = {}
        for anchor, node in anchors.items():
            recorded = paths.get(id(node), [])
            consumption[anchor] = sorted(recorded)
            # The first recorded path is the definition site of the anchor;
            # every later path is an actual consumer (alias or merge key).
            consumers[anchor] = recorded[1:]
        if change.anchor not in anchors:
            raise ReviewError("unknown anchor %r" % (change.anchor,))
        target = anchors[change.anchor]
        if not isinstance(target, MappingNode):
            raise ReviewError(
                "anchor %r does not refer to a mapping" % (change.anchor,))
        impacts = []
        for consumed_path in consumers[change.anchor]:
            via_merge = consumed_path.endswith('.<<')
            resource_path = consumed_path[:-3] if via_merge else consumed_path
            role = _find_role(roles, resource_path)
            if role is None:
                impacts.append(ReviewImpact(
                    resource_path, None, None, False, via_merge))
            else:
                approved = role.scope in approvals or role.name in approvals
                impacts.append(ReviewImpact(
                    resource_path, role.name, role.scope, approved, via_merge))
        loader.flatten_mapping(target)
        updated = loader.construct_mapping(target, deep=True)
        updated.update(change.values)
        return ReviewReport(change, consumption, impacts, updated)
    finally:
        loader.dispose()
