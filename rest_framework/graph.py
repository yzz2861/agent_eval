"""
Opt-in support for serializing object graphs that contain shared nodes
or reference cycles.

When graph serialization is enabled on a root serializer, every object
is emitted in full the first time it is encountered, together with a
reference identifier. Any further occurrence of the same object within
the same serialization run is emitted as a reference only:

    {
        "$id": "ref-1",
        "name": "parent",
        "child": {"$id": "ref-2", "name": "child", "parent": {"$ref": "ref-1"}}
    }

The mode is enabled explicitly by passing `graph` to the root
serializer, and leaves regular serializers untouched:

    serializer = MySerializer(instance, graph=True)
    serializer = MySerializer(instance, graph={'max_depth': 10, 'max_nodes': 1000})

Reference identifiers are only stable within a single serialization run.
They are deliberately *not* derived from primary keys alone, as primary
keys collide across models, across databases, and for unsaved instances.
"""

from collections.abc import Mapping

from django.db import DEFAULT_DB_ALIAS, models

# Keys used in the emitted representations. They are not valid Python
# identifiers, so they can never clash with declared serializer fields.
GRAPH_ID_KEY = '$id'
GRAPH_REF_KEY = '$ref'
GRAPH_TRUNCATED_KEY = '$truncated'

# Truncation reasons used as the value of `GRAPH_TRUNCATED_KEY`.
TRUNCATED_MAX_DEPTH = 'max_depth'
TRUNCATED_MAX_NODES = 'max_nodes'


class GraphSerializationState:
    """
    Holds the shared reference space for a single serialization run.

    A single state instance is shared by the root serializer and all of
    its nested serializers, including every root object of a
    `many=True` serialization, so repeated objects collapse onto the
    same reference identifier no matter where they appear in the graph.
    """

    def __init__(self, max_nodes=None, max_depth=None):
        assert max_nodes is None or max_nodes >= 0, (
            '`max_nodes` must be a non-negative integer or `None`.'
        )
        assert max_depth is None or max_depth >= 0, (
            '`max_depth` must be a non-negative integer or `None`.'
        )
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self._refs = {}
        # Keep strong references to every registered instance, so that an
        # `id()` based identity cannot be recycled by the garbage
        # collector partway through a serialization run.
        self._instances = []
        self._counter = 0
        self._depth = 0

    @property
    def node_count(self):
        return self._counter

    def identity_key(self, instance):
        """
        Return a hashable key identifying `instance` within this run.

        Saved model instances are identified by model, database and
        primary key, so the same row fetched twice collapses onto one
        node, while identical primary keys on different models or
        different databases do not. Unsaved instances and non-model
        objects fall back to object identity.
        """
        if isinstance(instance, models.Model):
            pk = instance.pk
            if pk is not None:
                database = instance._state.db or DEFAULT_DB_ALIAS
                return ('model', instance._meta.label_lower, database, pk)
        return ('object', id(instance))

    def serialize_node(self, instance, produce):
        """
        Serialize `instance` exactly once, emitting a reference afterwards.

        `produce` is a zero-argument callable returning the regular
        (non-graph) representation of the instance. It is only invoked
        for the first occurrence of the instance, and only if neither
        `max_depth` nor `max_nodes` has been exceeded.
        """
        key = self.identity_key(instance)
        existing_ref = self._refs.get(key)
        if existing_ref is not None:
            return {GRAPH_REF_KEY: existing_ref}

        if self.max_depth is not None and self._depth > self.max_depth:
            return {GRAPH_TRUNCATED_KEY: TRUNCATED_MAX_DEPTH}
        if self.max_nodes is not None and self._counter >= self.max_nodes:
            return {GRAPH_TRUNCATED_KEY: TRUNCATED_MAX_NODES}

        # Register the instance *before* producing its content, so that
        # self-references encountered while serializing its fields are
        # emitted as references instead of recursing forever.
        self._counter += 1
        ref = 'ref-%d' % self._counter
        self._refs[key] = ref
        self._instances.append(instance)

        self._depth += 1
        try:
            content = produce()
        finally:
            self._depth -= 1

        return {GRAPH_ID_KEY: ref, **content}


def coerce_graph_state(options):
    """
    Build a `GraphSerializationState` from the `graph=` serializer argument.

    Accepts `True` for defaults, a mapping of `GraphSerializationState`
    keyword arguments, or a pre-built `GraphSerializationState` instance.
    """
    if isinstance(options, GraphSerializationState):
        return options
    if options is True:
        return GraphSerializationState()
    if isinstance(options, Mapping):
        return GraphSerializationState(**options)
    raise TypeError(
        "`graph` must be `True`, a dict of `GraphSerializationState` "
        "options, or a `GraphSerializationState` instance. "
        "Got %s." % type(options).__name__
    )
