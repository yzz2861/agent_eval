"""
Tests for the opt-in graph serialization mode (`graph=`).

Graph serialization emits each object in full the first time it is
encountered, together with a reference identifier, and emits only a
reference for any subsequent occurrence within the same run.
"""
from types import SimpleNamespace

import pytest
from django.db import models
from django.test import TestCase

from rest_framework import serializers
from rest_framework.graph import (
    GRAPH_ID_KEY, GRAPH_REF_KEY, GRAPH_TRUNCATED_KEY,
    GraphSerializationState
)


class GraphPerson(models.Model):
    name = models.CharField(max_length=100)
    best_friend = models.ForeignKey('self', null=True, blank=True, related_name='+', on_delete=models.CASCADE)
    colleague = models.ForeignKey('self', null=True, blank=True, related_name='+', on_delete=models.CASCADE)


class GraphTeam(models.Model):
    name = models.CharField(max_length=100)


class PersonSerializer(serializers.ModelSerializer):
    class Meta:
        model = GraphPerson
        fields = ['id', 'name', 'best_friend', 'colleague']


PersonSerializer._declared_fields['best_friend'] = PersonSerializer(required=False, allow_null=True)
PersonSerializer._declared_fields['colleague'] = PersonSerializer(required=False, allow_null=True)


class TeamSerializer(serializers.ModelSerializer):
    class Meta:
        model = GraphTeam
        fields = ['id', 'name']


class PersonAndTeamSerializer(serializers.Serializer):
    person = PersonSerializer()
    team = TeamSerializer()


def link(source, **relations):
    for name, target in relations.items():
        setattr(source, name, target)
    source.save()
    return source


class GraphSerializationTests(TestCase):
    def setUp(self):
        self.alice = GraphPerson.objects.create(name='alice')
        self.bob = GraphPerson.objects.create(name='bob')
        self.carol = GraphPerson.objects.create(name='carol')

    def test_shared_node_is_emitted_once_then_referenced(self):
        link(self.alice, best_friend=self.bob, colleague=self.bob)

        data = PersonSerializer(self.alice, graph=True).data

        assert data['best_friend']['name'] == 'bob'
        assert GRAPH_ID_KEY in data['best_friend']
        assert data['colleague'] == {GRAPH_REF_KEY: data['best_friend'][GRAPH_ID_KEY]}

    def test_reference_identifiers_are_stable_within_a_run(self):
        link(self.alice, best_friend=self.bob)
        link(self.bob, best_friend=self.carol, colleague=self.carol)

        data = PersonSerializer(self.alice, graph=True).data

        friend = data['best_friend']
        assert friend['colleague'] == {GRAPH_REF_KEY: friend['best_friend'][GRAPH_ID_KEY]}

    def test_cycle_terminates_with_a_reference(self):
        link(self.alice, best_friend=self.bob)
        link(self.bob, best_friend=self.alice)

        data = PersonSerializer(self.alice, graph=True).data

        assert data['best_friend']['best_friend'] == {GRAPH_REF_KEY: data[GRAPH_ID_KEY]}

    def test_self_loop_is_expanded_exactly_once(self):
        link(self.alice, best_friend=self.alice)

        data = PersonSerializer(self.alice, graph=True).data

        assert data['name'] == 'alice'
        assert data['best_friend'] == {GRAPH_REF_KEY: data[GRAPH_ID_KEY]}

    def test_many_roots_share_a_single_reference_space(self):
        link(self.bob, best_friend=self.alice)

        data = PersonSerializer([self.alice, self.bob], many=True, graph=True).data

        assert data[0]['name'] == 'alice'
        assert data[1]['best_friend'] == {GRAPH_REF_KEY: data[0][GRAPH_ID_KEY]}

    def test_repeated_root_object_is_a_reference(self):
        data = PersonSerializer([self.alice, self.alice], many=True, graph=True).data

        assert data[0]['name'] == 'alice'
        assert data[1] == {GRAPH_REF_KEY: data[0][GRAPH_ID_KEY]}

    def test_same_primary_key_on_different_models_gets_distinct_refs(self):
        # Force both rows to share the same primary key value.
        team = GraphTeam.objects.create(id=self.alice.id, name='team')
        instance = SimpleNamespace(person=self.alice, team=team)

        data = PersonAndTeamSerializer(instance, graph=True).data

        assert data['person']['id'] == data['team']['id']
        assert data['person'][GRAPH_ID_KEY] != data['team'][GRAPH_ID_KEY]
        assert data['person']['name'] == 'alice'
        assert data['team']['name'] == 'team'

    def test_unsaved_instances_use_object_identity(self):
        first = GraphPerson(name='first')
        second = GraphPerson(name='second')

        data = PersonSerializer([first, second, first], many=True, graph=True).data

        assert data[0][GRAPH_ID_KEY] != data[1][GRAPH_ID_KEY]
        assert data[2] == {GRAPH_REF_KEY: data[0][GRAPH_ID_KEY]}

    def test_max_depth_truncates_with_an_explicit_marker(self):
        link(self.alice, best_friend=self.bob)
        link(self.bob, best_friend=self.carol)

        data = PersonSerializer(self.alice, graph={'max_depth': 1}).data

        assert data['best_friend']['name'] == 'bob'
        assert data['best_friend']['best_friend'] == {GRAPH_TRUNCATED_KEY: 'max_depth'}

    def test_max_depth_zero_only_expands_roots(self):
        link(self.alice, best_friend=self.bob)

        data = PersonSerializer([self.alice], many=True, graph={'max_depth': 0}).data

        assert data[0]['name'] == 'alice'
        assert data[0]['best_friend'] == {GRAPH_TRUNCATED_KEY: 'max_depth'}

    def test_max_nodes_truncates_with_an_explicit_marker(self):
        link(self.alice, best_friend=self.bob)
        link(self.bob, best_friend=self.carol)

        data = PersonSerializer(self.alice, graph={'max_nodes': 2}).data

        assert data['best_friend']['name'] == 'bob'
        assert data['best_friend']['best_friend'] == {GRAPH_TRUNCATED_KEY: 'max_nodes'}

    def test_references_do_not_leak_fields(self):
        link(self.alice, best_friend=self.bob, colleague=self.bob)

        data = PersonSerializer(self.alice, graph=True).data

        # The reference-only representation must not backfill any field
        # of the already-seen object.
        assert set(data['colleague'].keys()) == {GRAPH_REF_KEY}

    def test_write_only_fields_are_not_exposed(self):
        class SecretSerializer(serializers.Serializer):
            name = serializers.CharField()
            secret = serializers.CharField(write_only=True)

        class DuoSerializer(serializers.Serializer):
            first = SecretSerializer()
            second = SecretSerializer()

        holder = SimpleNamespace(name='holder', secret='hidden')
        instance = SimpleNamespace(first=holder, second=holder)

        data = DuoSerializer(instance, graph=True).data

        assert 'secret' not in data['first']
        assert data['first']['name'] == 'holder'
        assert data['second'] == {GRAPH_REF_KEY: data['first'][GRAPH_ID_KEY]}

    def test_graph_state_can_be_passed_explicitly(self):
        link(self.alice, best_friend=self.bob)
        state = GraphSerializationState()

        data = PersonSerializer(self.alice, graph=state).data

        assert state.node_count == 2
        assert data['best_friend'][GRAPH_ID_KEY] == 'ref-2'

    def test_invalid_graph_option_raises_type_error(self):
        with pytest.raises(TypeError):
            PersonSerializer(self.alice, graph='yes').data


class RegularSerializerUnaffectedTests(TestCase):
    def setUp(self):
        self.alice = GraphPerson.objects.create(name='alice')
        self.bob = GraphPerson.objects.create(name='bob')

    def test_shared_node_is_duplicated_without_graph_mode(self):
        link(self.alice, best_friend=self.bob, colleague=self.bob)

        data = PersonSerializer(self.alice).data

        assert GRAPH_ID_KEY not in data
        assert GRAPH_ID_KEY not in data['best_friend']
        assert data['best_friend'] == data['colleague']
        assert data['best_friend']['name'] == 'bob'

    def test_graph_false_matches_regular_output(self):
        link(self.alice, best_friend=self.bob)

        assert PersonSerializer(self.alice, graph=False).data == PersonSerializer(self.alice).data

    def test_deserialization_is_unaffected_by_graph_option(self):
        serializer = PersonSerializer(data={'name': 'new'}, graph=True, partial=True)
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data == {'name': 'new'}

