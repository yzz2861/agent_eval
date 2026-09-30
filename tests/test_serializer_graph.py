"""
Tests for the opt-in graph serialization mode.

Graph serialization is enabled with `graph=True` (or
`Meta.graph_serialization = True`). The first occurrence of an object
emits its content together with a `$id`; later occurrences of the same
object only emit a `$ref`.
"""
from django.test import TestCase

from rest_framework import serializers
from rest_framework.serializers import GraphSerializationState

from .models import BasicModel, ManyToManyTarget


class Node:
    """Simple stand-in for model instances in a relationship graph."""

    def __init__(self, name, pk=None, friend=None):
        self.name = name
        self.pk = pk
        self.friend = friend


def node_serializer_class(**meta_attrs):
    """Build a fresh self-referential serializer class for one test."""
    class NodeSerializer(serializers.Serializer):
        name = serializers.CharField()

    NodeSerializer._declared_fields['friend'] = NodeSerializer(required=False)
    if meta_attrs:
        NodeSerializer.Meta = type('Meta', (), meta_attrs)
    return NodeSerializer


class TestSharedObjects:
    def test_first_occurrence_expands_later_occurrences_reference(self):
        serializer_class = node_serializer_class()
        shared = Node('shared', pk=1)
        root = Node('root', pk=2)
        root.friend = shared

        class RootSerializer(serializers.Serializer):
            name = serializers.CharField()
            friend = serializer_class()
            again = serializer_class(source='friend')

        data = RootSerializer(root, graph=True).data
        assert data['$id'] == '1'
        assert data['friend'] == {'$id': '2', 'name': 'shared', 'friend': None}
        assert data['again'] == {'$ref': '2'}

    def test_references_are_stable_within_one_serialization(self):
        serializer_class = node_serializer_class()
        shared = Node('shared', pk=1)
        root = Node('root', pk=2)
        root.friend = shared

        class RootSerializer(serializers.Serializer):
            first = serializer_class(source='friend')
            second = serializer_class(source='friend')
            third = serializer_class(source='friend')

        data = RootSerializer(root, graph=True).data
        assert data['first']['$id'] == data['second']['$ref']
        assert data['second'] == data['third'] == {'$ref': data['first']['$id']}

    def test_plain_serializer_still_duplicates_shared_objects(self):
        serializer_class = node_serializer_class()
        shared = Node('shared', pk=1)
        root = Node('root', pk=2)
        root.friend = shared

        class RootSerializer(serializers.Serializer):
            friend = serializer_class()
            again = serializer_class(source='friend')

        data = RootSerializer(root).data
        expected = {'name': 'shared', 'friend': None}
        assert data['friend'] == expected
        assert data['again'] == expected


class TestCycles:
    def test_self_cycle_expands_only_once(self):
        serializer_class = node_serializer_class()
        node = Node('loop', pk=1)
        node.friend = node

        data = serializer_class(node, graph=True).data
        assert data == {'$id': '1', 'name': 'loop', 'friend': {'$ref': '1'}}

    def test_mutual_cycle_terminates(self):
        serializer_class = node_serializer_class()
        one = Node('one', pk=1)
        two = Node('two', pk=2)
        one.friend = two
        two.friend = one

        data = serializer_class(one, graph=True).data
        assert data == {
            '$id': '1',
            'name': 'one',
            'friend': {
                '$id': '2',
                'name': 'two',
                'friend': {'$ref': '1'},
            },
        }


class TestManyRoots:
    def test_many_true_roots_share_a_reference_space(self):
        serializer_class = node_serializer_class()
        one = Node('one', pk=1)
        two = Node('two', pk=2)
        two.friend = one

        data = serializer_class([one, two], many=True, graph=True).data
        assert data[0] == {'$id': '1', 'name': 'one', 'friend': None}
        assert data[1]['friend'] == {'$ref': '1'}

    def test_many_true_inherits_graph_option_from_child_meta(self):
        serializer_class = node_serializer_class(graph_serialization=True)
        one = Node('one', pk=1)
        two = Node('two', pk=2)
        two.friend = one

        data = serializer_class([one, two], many=True).data
        assert '$id' in data[0]
        assert data[1]['friend'] == {'$ref': data[0]['$id']}

    def test_nested_many_true_field_participates(self):
        serializer_class = node_serializer_class()
        shared = Node('shared', pk=1)
        other = Node('other', pk=2, friend=shared)
        root = Node('root', pk=3, friend=shared)
        root.friends = [shared, other]

        class RootSerializer(serializers.Serializer):
            name = serializers.CharField()
            friend = serializer_class()
            friends = serializer_class(many=True)

        data = RootSerializer(root, graph=True).data
        assert data['friend'] == {'$id': '2', 'name': 'shared', 'friend': None}
        assert data['friends'][0] == {'$ref': '2'}
        assert data['friends'][1]['friend'] == {'$ref': '2'}


class TestIdentity:
    def test_same_pk_on_different_types_gets_different_references(self):
        class TypeA:
            class _meta:
                label_lower = 'tests.typea'

            def __init__(self, pk):
                self.pk = pk
                self.name = 'a'

        class TypeB:
            class _meta:
                label_lower = 'tests.typeb'

            def __init__(self, pk):
                self.pk = pk
                self.name = 'b'

        class PairSerializer(serializers.Serializer):
            name = serializers.CharField()

        class Holder:
            pk = 1
            name = 'holder'

            def __init__(self):
                self.a = TypeA(1)
                self.b = TypeB(1)

        class HolderSerializer(serializers.Serializer):
            name = serializers.CharField()
            a = PairSerializer()
            b = PairSerializer()

        data = HolderSerializer(Holder(), graph=True).data
        assert data['a']['$id'] != data['b']['$id']
        assert data['a'] == {'$id': '2', 'name': 'a'}
        assert data['b'] == {'$id': '3', 'name': 'b'}

    def test_unsaved_instances_are_distinguished_by_identity(self):
        serializer_class = node_serializer_class()
        first = Node('first')
        second = Node('second')
        root = Node('root', pk=9)
        root.friend = first

        class RootSerializer(serializers.Serializer):
            friend = serializer_class()
            other = serializer_class()
            friend_again = serializer_class(source='friend')

        root.other = second
        data = RootSerializer(root, graph=True).data
        assert data['friend']['$id'] != data['other']['$id']
        assert data['friend_again'] == {'$ref': data['friend']['$id']}

    def test_identity_key_includes_database(self):
        class FakeState:
            def __init__(self, db):
                self.db = db

        class FakeMeta:
            label_lower = 'tests.thing'

        class Thing:
            _meta = FakeMeta()

            def __init__(self, db):
                self.pk = 1
                self._state = FakeState(db)

        default = Thing('default')
        replica = Thing('replica')
        key_default = GraphSerializationState.identity_key(default)
        key_replica = GraphSerializationState.identity_key(replica)
        assert key_default != key_replica
        assert GraphSerializationState.identity_key(default) == key_default


class TestTruncation:
    def test_max_depth_truncates_with_explicit_marker(self):
        serializer_class = node_serializer_class()
        chain = [Node('node-%d' % index, pk=index) for index in range(4)]
        for current, following in zip(chain, chain[1:]):
            current.friend = following

        data = serializer_class(chain[0], graph=True, graph_max_depth=2).data
        assert data['friend']['friend'] == {'$truncated': 'max_depth'}

    def test_max_nodes_truncates_with_explicit_marker(self):
        serializer_class = node_serializer_class()
        chain = [Node('node-%d' % index, pk=index) for index in range(4)]
        for current, following in zip(chain, chain[1:]):
            current.friend = following

        data = serializer_class(chain[0], graph=True, graph_max_nodes=2).data
        assert data['friend']['friend'] == {'$truncated': 'max_nodes'}

    def test_meta_limits(self):
        serializer_class = node_serializer_class(
            graph_serialization=True, graph_max_depth=1,
        )
        one = Node('one', pk=1)
        one.friend = Node('two', pk=2)

        data = serializer_class(one).data
        assert data['friend'] == {'$truncated': 'max_depth'}

    def test_truncated_objects_may_expand_when_reached_again(self):
        serializer_class = node_serializer_class()
        leaf = Node('leaf', pk=3)
        middle = Node('middle', pk=2, friend=leaf)
        root = Node('root', pk=1, friend=middle)
        root.leaf = leaf

        class RootSerializer(serializers.Serializer):
            name = serializers.CharField()
            friend = serializer_class()
            leaf = serializer_class()

        data = RootSerializer(root, graph=True, graph_max_depth=2).data
        assert data['friend']['friend'] == {'$truncated': 'max_depth'}
        assert data['leaf'] == {'$id': '3', 'name': 'leaf', 'friend': None}


class TestFieldSelection:
    def test_write_only_fields_are_not_leaked(self):
        class ChildSerializer(serializers.Serializer):
            name = serializers.CharField()
            secret = serializers.CharField(write_only=True)

        class Child:
            pk = 1
            name = 'child'
            secret = 'hidden'

        class Root:
            pk = 2
            name = 'root'

            def __init__(self, child):
                self.child = child
                self.child_again = child

        class RootSerializer(serializers.Serializer):
            child = ChildSerializer()
            child_again = ChildSerializer(source='child')

        data = RootSerializer(Root(Child()), graph=True).data
        assert data['child'] == {'$id': '2', 'name': 'child'}
        assert data['child_again'] == {'$ref': '2'}


class TestStateCleanup:
    def test_state_is_cleared_after_serialization(self):
        serializer_class = node_serializer_class()
        node = Node('one', pk=1)
        node.friend = Node('two', pk=2)
        serializer = serializer_class(node, graph=True)
        serializer.data

        assert serializer._graph_state is None
        assert serializer.fields['friend']._graph_state is None

    def test_state_is_cleared_on_error(self):
        class FailingSerializer(serializers.Serializer):
            name = serializers.CharField()

            def to_representation(self, instance):
                raise RuntimeError('boom')

        class RootSerializer(serializers.Serializer):
            name = serializers.CharField()
            child = FailingSerializer()

        class Root:
            pk = 1
            name = 'root'
            child = object()

        serializer = RootSerializer(Root(), graph=True)
        try:
            serializer.data
        except RuntimeError:
            pass
        else:
            raise AssertionError('expected RuntimeError')
        assert serializer._graph_state is None


class TestModelIdentity(TestCase):
    def test_model_serializer_meta_opt_in(self):
        basic = BasicModel.objects.create(text='basic')

        class BasicSerializer(serializers.ModelSerializer):
            class Meta:
                model = BasicModel
                fields = ['text']
                graph_serialization = True

        class Holder:
            pk = 1

            def __init__(self, item):
                self.first = item
                self.second = item

        class HolderSerializer(serializers.Serializer):
            first = BasicSerializer()
            second = BasicSerializer()

        data = HolderSerializer(Holder(basic), graph=True).data
        assert data['first'] == {'$id': '2', 'text': 'basic'}
        assert data['second'] == {'$ref': '2'}

    def test_same_pk_on_different_models_gets_different_references(self):
        basic = BasicModel.objects.create(text='basic')
        target = ManyToManyTarget.objects.create(name='target')
        # Force colliding primary keys across the two models.
        ManyToManyTarget.objects.filter(pk=target.pk).update(id=basic.pk)
        target.pk = basic.pk

        class EntrySerializer(serializers.Serializer):
            label = serializers.SerializerMethodField()

            def get_label(self, instance):
                return getattr(instance, 'text', None) or instance.name

        class Holder:
            pk = 1

            def __init__(self, first, second):
                self.first = first
                self.second = second

        class HolderSerializer(serializers.Serializer):
            first = EntrySerializer()
            second = EntrySerializer()

        data = HolderSerializer(Holder(basic, target), graph=True).data
        assert data['first'] == {'$id': '2', 'label': 'basic'}
        assert data['second'] == {'$id': '3', 'label': 'target'}
