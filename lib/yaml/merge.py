__all__ = [
    'MergeError',
    'MergeBudgetExceededError',
    'MergeCycleError',
    'MergeDuplicateSourceError',
    'MergeProtectedKeyError',
    'MergeBudget',
    'MergePolicy',
    'MergeOrigin',
    'MergeAudit',
    'MergePlanner',
    'DEFAULT_MERGE_BUDGET',
]

from .error import MarkedYAMLError
from .nodes import MappingNode, ScalarNode, SequenceNode

import collections.abc as collections_abc

MERGE_TAG = 'tag:yaml.org,2002:merge'
VALUE_TAG = 'tag:yaml.org,2002:value'
STR_TAG = 'tag:yaml.org,2002:str'
MAP_TAG = 'tag:yaml.org,2002:map'


def _location(mark, anchor=None):
    """Render a node location without ever including configuration values."""
    location = "line %d, column %d" % (mark.line + 1, mark.column + 1)
    if mark.name:
        location = "%s, %s" % (mark.name, location)
    if anchor:
        location = "%s (anchor %r)" % (location, anchor)
    return location


class MergeError(MarkedYAMLError):
    """Base class for merge planning failures.

    Messages reference node paths and source locations only; configuration
    values are never embedded and no source snippets are attached.
    """


class MergeBudgetExceededError(MergeError):
    pass


class MergeCycleError(MergeError):
    pass


class MergeDuplicateSourceError(MergeError):
    pass


class MergeProtectedKeyError(MergeError):
    pass


class MergeBudget(object):
    """Resource budget applied while expanding ``<<`` merge keys.

    Any limit set to ``None`` is not enforced.
    """

    def __init__(self, max_depth=64, max_branches=1024,
            max_total_keys=10000, max_scalar_length=None):
        self.max_depth = max_depth
        self.max_branches = max_branches
        self.max_total_keys = max_total_keys
        self.max_scalar_length = max_scalar_length

    def __repr__(self):
        return ('%s(max_depth=%r, max_branches=%r, max_total_keys=%r, '
                'max_scalar_length=%r)' % (self.__class__.__name__,
                self.max_depth, self.max_branches, self.max_total_keys,
                self.max_scalar_length))


DEFAULT_MERGE_BUDGET = MergeBudget()


class MergePolicy(object):
    """Policy controlling tenant overrides of protected keys.

    A protected key that reaches a mapping through a merge source cannot be
    overridden by later merge sources or by the mapping's own explicit keys.
    The first (highest priority) source providing the key wins.
    """

    def __init__(self, protected_keys=()):
        self.protected_keys = frozenset(protected_keys)

    def is_protected(self, key):
        if not isinstance(key, collections_abc.Hashable):
            return False
        return key in self.protected_keys


class MergeOrigin(object):
    """Provenance record for a single key in an expanded mapping."""

    __slots__ = ('key', 'key_line', 'key_column', 'source_line',
            'source_column', 'source_anchor', 'merged')

    def __init__(self, key, key_line, key_column, source_line, source_column,
            source_anchor=None, merged=False):
        self.key = key
        self.key_line = key_line
        self.key_column = key_column
        self.source_line = source_line
        self.source_column = source_column
        self.source_anchor = source_anchor
        self.merged = merged

    def as_dict(self):
        return {
            'key': self.key,
            'key_line': self.key_line,
            'key_column': self.key_column,
            'source_line': self.source_line,
            'source_column': self.source_column,
            'source_anchor': self.source_anchor,
            'merged': self.merged,
        }

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.as_dict())


class MergeAudit(object):
    """Path-indexed provenance records for merge-expanded documents."""

    def __init__(self):
        self.origins = {}

    def record(self, path, origin):
        self.origins[tuple(path)] = origin

    def get(self, path):
        if not isinstance(path, (list, tuple)):
            path = (path,)
        return self.origins.get(tuple(path))

    def paths(self):
        return list(self.origins)

    def as_dict(self):
        return {
            path: origin.as_dict()
            for path, origin in self.origins.items()
        }


class MergePlanner(object):
    """Expands ``<<`` merge keys into an explicit, budgeted merge plan.

    Historical PyYAML merge semantics are preserved (first source wins,
    explicit mapping keys win over merged keys). On top of that the planner
    enforces depth/branch/key/scalar budgets, rejects cycles, optionally
    rejects repeated merge sources, enforces protected keys and attaches
    per-key provenance to expanded mapping nodes.
    """

    ORIGIN_ATTR = '_yaml_merge_origins'

    def __init__(self, constructor, budget=None, policy=None, strict=False,
            anchors=None):
        self.constructor = constructor
        self.budget = budget
        self.policy = policy or MergePolicy()
        self.strict = strict
        self.anchors = anchors if anchors is not None else {}
        self.branch_count = 0
        self.total_keys = 0
        self.audit = MergeAudit()
        self._anchor_index = None
        self._planned = set()

    def reset_document_state(self):
        """Reset per-document counters and memoization."""
        self.branch_count = 0
        self.total_keys = 0
        self._planned = set()
        self.audit = MergeAudit()

    def anchor_of(self, node):
        anchor = getattr(node, 'anchor', None)
        if anchor is not None:
            return anchor
        if self._anchor_index is None:
            self._anchor_index = {
                id(referent): anchor
                for anchor, referent in self.anchors.items()
            }
        return self._anchor_index.get(id(node))

    def _error(self, exc_type, problem, mark=None, anchor=None):
        if mark is not None:
            problem = '%s; at %s' % (problem, _location(mark, anchor))
        return exc_type(None, None, problem, None)

    def _check_scalar_budget(self, node):
        if self.budget is None:
            return
        limit = self.budget.max_scalar_length
        if limit is not None and isinstance(node, ScalarNode) \
                and len(node.value) > limit:
            raise self._error(MergeBudgetExceededError,
                    'merge scalar value length %d exceeds budget %d'
                    % (len(node.value), limit), node.start_mark,
                    self.anchor_of(node))

    def flatten_mapping(self, node):
        if id(node) not in self._planned:
            self._plan_roots([(node, 0)])
            self._planned.add(id(node))

    def plan_document(self, root):
        """Plan every mapping in an intact node graph before construction.

        Running the merge plan once over the whole representation tree keeps
        the real merge-chain depth visible (construction would otherwise
        flatten source mappings first) and makes later flatten calls O(1).
        """
        roots = []
        seen = set()
        has_merge = [False]

        def collect(current):
            node_id = id(current)
            if node_id in seen:
                return
            seen.add(node_id)
            if isinstance(current, MappingNode):
                if current.tag == MAP_TAG:
                    for key_node, value_node in current.value:
                        if key_node.tag == MERGE_TAG:
                            has_merge[0] = True
                    roots.append((current, 0))
                for key_node, value_node in current.value:
                    collect(key_node)
                    collect(value_node)
            elif isinstance(current, SequenceNode):
                for child in current.value:
                    collect(child)

        collect(root)
        if not has_merge[0]:
            return
        self._plan_roots(roots)
        for node, _depth in roots:
            self._planned.add(id(node))

    def _merge_sources(self, node):
        from .constructor import ConstructorError
        sources = []
        for key_node, value_node in node.value:
            if key_node.tag != MERGE_TAG:
                continue
            if isinstance(value_node, MappingNode):
                sources.append(value_node)
            elif isinstance(value_node, SequenceNode):
                for subnode in value_node.value:
                    if not isinstance(subnode, MappingNode):
                        raise ConstructorError(
                                'while constructing a mapping',
                                node.start_mark,
                                'expected a mapping for merging, but found %s'
                                % subnode.id, subnode.start_mark)
                    sources.append(subnode)
            else:
                raise ConstructorError('while constructing a mapping',
                        node.start_mark,
                        'expected a mapping or list of mappings for merging, '
                        'but found %s' % value_node.id, value_node.start_mark)
        return sources

    def _plan_roots(self, roots):
        # Explicit iterative DFS over merge edges. Each frame tracks the
        # mapping, the depth it is reached at, its merge sources and the
        # ancestor chain, so completion memoization never hides chain depth.
        expanded = set()
        max_depth_seen = {}
        stack = []

        def push(node, depth, ancestors):
            node_id = id(node)
            if node_id in ancestors:
                raise self._error(MergeCycleError,
                        'cyclic merge reference detected',
                        node.start_mark, self.anchor_of(node))
            previous = max_depth_seen.get(node_id)
            if previous is not None and depth <= previous:
                return
            max_depth_seen[node_id] = depth
            sources = self._merge_sources(node)
            stack.append([node, depth, sources, 0, ancestors | {node_id}])

        for root_node, root_depth in roots:
            push(root_node, root_depth, set())

        while stack:
            frame = stack[-1]
            node, depth, sources, index, ancestors = frame
            if index < len(sources):
                source_node = sources[index]
                frame[3] = index + 1
                source_id = id(source_node)
                if source_id in ancestors:
                    raise self._error(MergeCycleError,
                            'cyclic merge reference detected',
                            source_node.start_mark,
                            self.anchor_of(source_node))
                if self.strict:
                    local_ids = {id(item) for item in sources[:index]}
                    if source_id in local_ids:
                        raise self._error(MergeDuplicateSourceError,
                                'duplicate merge source rejected',
                                source_node.start_mark,
                                self.anchor_of(source_node))
                source_depth = depth + 1
                if self.budget is not None \
                        and self.budget.max_depth is not None \
                        and source_depth > self.budget.max_depth:
                    raise self._error(MergeBudgetExceededError,
                            'merge depth %d exceeds budget %d'
                            % (source_depth, self.budget.max_depth),
                            source_node.start_mark,
                            self.anchor_of(source_node))
                if self.budget is not None \
                        and self.budget.max_branches is not None:
                    self.branch_count += 1
                    if self.branch_count > self.budget.max_branches:
                        raise self._error(MergeBudgetExceededError,
                                'merge branch count exceeds budget %d'
                                % self.budget.max_branches,
                                source_node.start_mark,
                                self.anchor_of(source_node))
                push(source_node, source_depth, ancestors)
                continue
            if id(node) not in expanded:
                self._expand(node, sources)
                expanded.add(id(node))
            stack.pop()

    def _expand(self, node, sources):
        budget = self.budget
        merge_pairs = []
        merge_origins = {}
        origin_by_dedup = {}
        dedup_ids = set()
        remaining = []

        for key_node, value_node in node.value:
            if key_node.tag != MERGE_TAG:
                remaining.append((key_node, value_node))

        for source_node in sources:
            source_anchor = self.anchor_of(source_node)
            for pair in source_node.value:
                pair_key_node, pair_value_node = pair
                self._check_scalar_budget(pair_key_node)
                self._check_scalar_budget(pair_value_node)
                if budget is not None and budget.max_total_keys is not None:
                    self.total_keys += 1
                    if self.total_keys > budget.max_total_keys:
                        raise self._error(MergeBudgetExceededError,
                                'total merge key count exceeds budget %d'
                                % budget.max_total_keys,
                                pair_key_node.start_mark,
                                source_anchor)
                dedup_key = self._dedup_key(pair_key_node)
                pair_key = self._scalar_key(pair_key_node)
                if self.policy.is_protected(pair_key) \
                        and dedup_key in dedup_ids:
                    first = origin_by_dedup[dedup_key]
                    raise self._error(MergeProtectedKeyError,
                            'protected key %r cannot be overridden by a '
                            'lower priority merge source; higher priority '
                            'source at line %d, column %d'
                            % (pair_key, first.source_line,
                                    first.source_column),
                            pair_key_node.start_mark, source_anchor)
                if dedup_key in dedup_ids:
                    continue
                dedup_ids.add(dedup_key)
                merge_pairs.append(pair)
                origin = MergeOrigin(
                        key=pair_key,
                        key_line=pair_key_node.start_mark.line + 1,
                        key_column=pair_key_node.start_mark.column + 1,
                        source_line=source_node.start_mark.line + 1,
                        source_column=source_node.start_mark.column + 1,
                        source_anchor=source_anchor,
                        merged=True)
                merge_origins[id(pair_key_node)] = origin
                origin_by_dedup[dedup_key] = origin

        origins = {}
        protected = {}
        final_pairs = []

        for pair in merge_pairs:
            key_node, value_node = pair
            self._check_scalar_budget(key_node)
            self._check_scalar_budget(value_node)
            origin = merge_origins[id(key_node)]
            key = origin.key
            if self.policy.is_protected(key):
                protected.setdefault(self._dedup_key(key_node), origin)
            origins[id(key_node)] = origin
            final_pairs.append(pair)

        for key_node, value_node in remaining:
            if key_node.tag == VALUE_TAG:
                key_node.tag = STR_TAG
            self._check_scalar_budget(key_node)
            self._check_scalar_budget(value_node)
            key = self._scalar_key(key_node)
            dedup_key = self._dedup_key(key_node)
            if self.policy.is_protected(key) and dedup_key in protected:
                first = protected[dedup_key]
                raise self._error(MergeProtectedKeyError,
                        'protected key %r cannot be overridden; higher '
                        'priority source at line %d, column %d'
                        % (key, first.source_line, first.source_column),
                        key_node.start_mark, self.anchor_of(node))
            origin = MergeOrigin(
                    key=key,
                    key_line=key_node.start_mark.line + 1,
                    key_column=key_node.start_mark.column + 1,
                    source_line=node.start_mark.line + 1,
                    source_column=node.start_mark.column + 1,
                    source_anchor=self.anchor_of(node),
                    merged=False)
            origins[id(key_node)] = origin
            final_pairs.append((key_node, value_node))

        node.value = final_pairs
        setattr(node, self.ORIGIN_ATTR, origins)

    @staticmethod
    def _dedup_key(key_node):
        if isinstance(key_node, ScalarNode):
            return (True, key_node.tag, key_node.value)
        return (False, id(key_node))

    def _scalar_key(self, key_node):
        if isinstance(key_node, ScalarNode):
            return key_node.value
        try:
            return self.constructor.construct_object(key_node, deep=True)
        except Exception:
            return None
