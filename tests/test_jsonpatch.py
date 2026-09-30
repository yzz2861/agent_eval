import io
import types

import pytest

from rest_framework import serializers
from rest_framework.exceptions import ParseError
from rest_framework.jsonpatch import JSONPatchError, apply_json_patch
from rest_framework.parsers import JSONPatchParser


class ProfileSerializer(serializers.Serializer):
    bio = serializers.CharField(max_length=100)
    tags = serializers.ListField(
        child=serializers.CharField(max_length=5), required=False,
    )


class ItemSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=20)
    score = serializers.IntegerField(required=False)


class RecordSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    title = serializers.CharField(max_length=10, source='internal_title')
    count = serializers.IntegerField()
    profile = ProfileSerializer(required=False)
    items = ItemSerializer(many=True, required=False)

    saved = 0

    def update(self, instance, validated_data):
        type(self).saved += 1
        for key, value in validated_data.items():
            if isinstance(value, dict):
                value = types.SimpleNamespace(**value)
            elif isinstance(value, list):
                value = [
                    types.SimpleNamespace(**item)
                    if isinstance(item, dict) else item
                    for item in value
                ]
            setattr(instance, key, value)
        return instance

    def create(self, validated_data):
        raise NotImplementedError


def make_instance():
    return types.SimpleNamespace(
        id=1,
        internal_title='old',
        count=3,
        profile=types.SimpleNamespace(bio='hello', tags=['a', 'b', 'c']),
        items=[
            types.SimpleNamespace(name='x', score=1),
            types.SimpleNamespace(name='y', score=2),
            types.SimpleNamespace(name='z', score=3),
        ],
    )


@pytest.fixture(autouse=True)
def reset_saved_counter():
    RecordSerializer.saved = 0


def make_serializer(instance=None):
    return RecordSerializer(instance or make_instance())


class TestBasicOperations:
    def test_replace(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'replace', 'path': '/count', 'value': 42},
        ])
        assert instance.count == 42

    def test_add_new_member(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'add', 'path': '/profile/bio', 'value': 'new bio'},
        ])
        assert instance.profile.bio == 'new bio'

    def test_add_list_element_by_index_and_dash(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'add', 'path': '/profile/tags/1', 'value': 'new'},
            {'op': 'add', 'path': '/profile/tags/-', 'value': 'last'},
        ])
        assert instance.profile.tags == ['a', 'new', 'b', 'c', 'last']

    def test_remove_list_element(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'remove', 'path': '/profile/tags/0'},
        ])
        assert instance.profile.tags == ['b', 'c']

    def test_operations_apply_sequentially(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'remove', 'path': '/profile/tags/0'},
            {'op': 'remove', 'path': '/profile/tags/0'},
        ])
        assert instance.profile.tags == ['c']

    def test_save_called_once_after_all_operations(self):
        apply_json_patch(make_serializer(), [
            {'op': 'replace', 'path': '/count', 'value': 1},
            {'op': 'replace', 'path': '/count', 'value': 2},
        ])
        assert RecordSerializer.saved == 1


class TestMoveAndCopy:
    def test_move_list_element(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'move', 'from': '/items/0', 'path': '/items/2'},
        ])
        assert [item.name for item in instance.items] == ['y', 'z', 'x']

    def test_copy_list_element(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'copy', 'from': '/items/0', 'path': '/items/1'},
        ])
        assert [item.name for item in instance.items] == ['x', 'x', 'y', 'z']

    def test_move_uses_value_before_removal(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {
                'op': 'move',
                'from': '/profile/tags/0', 'path': '/profile/tags/2',
            },
        ])
        assert instance.profile.tags == ['b', 'c', 'a']

    def test_move_into_own_child_is_rejected(self):
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(), [
                {'op': 'move', 'from': '/profile', 'path': '/profile/bio'},
            ])
        assert exc_info.value.detail.code == 'invalid_operation'


class TestTestOperation:
    def test_test_passes_on_equal_value(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'test', 'path': '/count', 'value': 3},
            {'op': 'replace', 'path': '/count', 'value': 4},
        ])
        assert instance.count == 4

    def test_test_compares_raw_document_values(self):
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(), [
                {'op': 'test', 'path': '/profile/tags/1', 'value': 'B'},
            ])
        assert exc_info.value.detail.code == 'test_failed'
        assert exc_info.value.index == 0
        assert exc_info.value.path == '/profile/tags/1'

    def test_test_compares_against_patched_document(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'replace', 'path': '/count', 'value': 10},
            {'op': 'test', 'path': '/count', 'value': 10},
        ])
        assert instance.count == 10


class TestFieldNameSemantics:
    def test_source_mapping_uses_external_name(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'replace', 'path': '/title', 'value': 'new'},
        ])
        assert instance.internal_title == 'new'

    def test_internal_attribute_name_is_rejected(self):
        instance = make_instance()
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(instance), [
                {'op': 'replace', 'path': '/internal_title', 'value': 'new'},
            ])
        assert exc_info.value.detail.code == 'does_not_exist'
        assert instance.internal_title == 'old'

    def test_read_only_field_cannot_be_written(self):
        instance = make_instance()
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(instance), [
                {'op': 'replace', 'path': '/id', 'value': 99},
            ])
        assert exc_info.value.detail.code == 'read_only'
        assert instance.id == 1

    def test_read_only_nested_field_cannot_be_written(self):
        class Outer(serializers.Serializer):
            profile = ProfileSerializer(read_only=True)
            count = serializers.IntegerField()

            def update(self, instance, validated_data):
                raise NotImplementedError

        instance = types.SimpleNamespace(
            profile=types.SimpleNamespace(bio='b', tags=[]), count=1,
        )
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(Outer(instance), [
                {'op': 'replace', 'path': '/profile/bio', 'value': 'x'},
            ])
        assert exc_info.value.detail.code == 'read_only'

    def test_nested_serializer_list_of_objects(self):
        instance = make_instance()
        apply_json_patch(make_serializer(instance), [
            {'op': 'replace', 'path': '/items/1/score', 'value': 20},
        ])
        assert [item.score for item in instance.items] == [1, 20, 3]


class TestAtomicity:
    def test_failed_operation_leaves_instance_untouched(self):
        instance = make_instance()
        original_tags = instance.profile.tags
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(instance), [
                {'op': 'add', 'path': '/profile/tags/-', 'value': 'one'},
                {'op': 'add', 'path': '/profile/tags/-', 'value': 'two'},
                {'op': 'test', 'path': '/count', 'value': 999},
            ])
        assert exc_info.value.index == 2
        assert instance.count == 3
        # The nested list on the original object must not be mutated.
        assert instance.profile.tags is original_tags
        assert instance.profile.tags == ['a', 'b', 'c']
        assert RecordSerializer.saved == 0

    def test_failed_validation_leaves_nested_lists_untouched(self):
        instance = make_instance()
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(instance), [
                {'op': 'remove', 'path': '/profile/tags/0'},
                {'op': 'add', 'path': '/profile/tags/-', 'value': 'ok'},
                {'op': 'replace', 'path': '/count', 'value': 'not-an-int'},
            ])
        assert exc_info.value.index == 2
        assert exc_info.value.path == '/count'
        assert exc_info.value.detail.code == 'invalid'
        assert instance.profile.tags == ['a', 'b', 'c']
        assert instance.count == 3
        assert RecordSerializer.saved == 0

    def test_error_reports_index_path_and_code(self):
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(), [
                {'op': 'replace', 'path': '/count', 'value': 5},
                {'op': 'replace', 'path': '/title', 'value': 'way too long'},
            ])
        error = exc_info.value
        assert error.index == 1
        assert error.path == '/title'
        assert error.detail.code == 'max_length'
        assert 'title' in error.errors


class TestInvalidOperations:
    def test_unknown_operation(self):
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(), [
                {'op': 'frobnicate', 'path': '/count'},
            ])
        assert exc_info.value.detail.code == 'invalid_operation'
        assert exc_info.value.index == 0

    def test_remove_missing_member(self):
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(), [
                {'op': 'remove', 'path': '/profile/missing'},
            ])
        assert exc_info.value.detail.code == 'does_not_exist'

    def test_replace_missing_member(self):
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(), [
                {'op': 'replace', 'path': '/profile/tags/9', 'value': 'x'},
            ])
        assert exc_info.value.detail.code == 'does_not_exist'

    def test_move_missing_from(self):
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(), [
                {'op': 'move', 'from': '/missing', 'path': '/count'},
            ])
        assert exc_info.value.detail.code == 'does_not_exist'

    def test_patch_document_must_be_a_list(self):
        with pytest.raises(JSONPatchError) as exc_info:
            apply_json_patch(make_serializer(), {'op': 'remove', 'path': '/x'})
        assert exc_info.value.detail.code == 'invalid_operation'


class TestJSONPatchParser:
    def test_media_type(self):
        assert JSONPatchParser.media_type == 'application/json-patch+json'

    def test_parse_operation_list(self):
        parser = JSONPatchParser()
        stream = io.BytesIO(b'[{"op": "replace", "path": "/a", "value": 1}]')
        assert parser.parse(stream) == [
            {'op': 'replace', 'path': '/a', 'value': 1},
        ]

    def test_parse_rejects_non_list_documents(self):
        parser = JSONPatchParser()
        stream = io.BytesIO(b'{"op": "replace"}')
        with pytest.raises(ParseError):
            parser.parse(stream)
