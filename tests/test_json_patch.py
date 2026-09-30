import io

from django.test import TestCase

from rest_framework import generics, mixins, serializers, status
from rest_framework.exceptions import ParseError
from rest_framework.json_patch import JsonPatchError, apply_json_patch
from rest_framework.parsers import JSONParser, JSONPatchParser
from rest_framework.test import APIRequestFactory


factory = APIRequestFactory()


class ChildSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=10)
    score = serializers.IntegerField(min_value=0, required=False)


class PatchableSerializer(serializers.Serializer):
    external_name = serializers.CharField(source='internal_name', max_length=20)
    identifier = serializers.ReadOnlyField()
    items = ChildSerializer(many=True)
    details = ChildSerializer(required=False)
    readonly_nested = ChildSerializer(read_only=True)
    metadata = serializers.JSONField(required=False)

    def update(self, instance, validated_data):
        if 'internal_name' in validated_data:
            instance.internal_name = validated_data['internal_name']
        if 'items' in validated_data:
            instance.items = validated_data['items']
        if 'details' in validated_data:
            instance.details = validated_data['details']
        return instance


class ExampleObject:
    def __init__(self):
        self.internal_name = 'original'
        self.identifier = 'read-only'
        self.items = [
            {'name': 'one', 'score': 1},
            {'name': 'two', 'score': 2},
        ]
        self.details = {'name': 'detail', 'score': 3}
        self.metadata = {}
        self.readonly_nested = {'name': 'read', 'score': 4}


class ExampleView(mixins.JSONPatchUpdateModelMixin, generics.RetrieveUpdateAPIView):
    queryset = None
    serializer_class = PatchableSerializer
    parser_classes = (JSONPatchParser, JSONParser)

    def get_object(self):
        return self.request.instance


class JsonPatchTests(TestCase):
    def setUp(self):
        self.instance = ExampleObject()
        self.serializer = PatchableSerializer(self.instance)

    def apply(self, patch, save=True):
        return apply_json_patch(self.serializer, patch, save=save)

    def test_supports_all_operations_and_saves_once(self):
        save_calls = 0

        original_save = PatchableSerializer.save

        def counting_save(self, **kwargs):
            nonlocal save_calls
            save_calls += 1
            return original_save(self, **kwargs)

        PatchableSerializer.save = counting_save
        try:
            result = self.apply([
                {'op': 'test', 'path': '/external_name', 'value': 'original'},
                {'op': 'add', 'path': '/items/-', 'value': {'name': 'three', 'score': 3}},
                {'op': 'replace', 'path': '/items/0/name', 'value': 'first'},
                {'op': 'move', 'from': '/items/2', 'path': '/items/1'},
                {'op': 'copy', 'from': '/items/0/name', 'path': '/details/name'},
                {'op': 'remove', 'path': '/items/0/score'},
            ])
        finally:
            PatchableSerializer.save = original_save

        assert result.validated_data['items'] == [
            {'name': 'first'}, {'name': 'three', 'score': 3},
        ]
        assert result.data['details']['name'] == 'first'
        assert self.instance.internal_name == 'original'
        assert self.instance.items[0] == {'name': 'first'}
        assert self.instance.items[1] == {'name': 'three', 'score': 3}
        assert save_calls == 1

    def test_uses_external_names_and_blocks_read_only_paths(self):
        assert self.apply([
            {'op': 'replace', 'path': '/external_name', 'value': 'updated'},
        ]).data['external_name'] == 'updated'
        assert self.instance.internal_name == 'updated'

        with self.assertRaises(JsonPatchError) as context:
            self.apply([{'op': 'replace', 'path': '/identifier', 'value': 'changed'}])

        assert context.exception.index == 0
        assert context.exception.path == '/identifier'
        assert context.exception.code == 'read_only'
        assert self.instance.identifier == 'read-only'

        protected = ExampleObject()
        protected_serializer = PatchableSerializer(protected)
        with self.assertRaises(JsonPatchError) as context:
            apply_json_patch(protected_serializer, [
                {'op': 'replace', 'path': '/internal_name', 'value': 'changed'},
            ])

        assert context.exception.code == 'unknown_field'
        assert protected.internal_name == 'original'

        with self.assertRaises(JsonPatchError) as context:
            apply_json_patch(protected_serializer, [
                {'op': 'replace', 'path': '/readonly_nested/name', 'value': 'changed'},
            ])

        assert context.exception.code == 'read_only'
        assert protected.internal_name == 'original'
        assert protected.readonly_nested == {'name': 'read', 'score': 4}

    def test_test_compares_representation_and_failure_does_not_mutate(self):
        with self.assertRaises(JsonPatchError) as context:
            self.apply([
                {'op': 'test', 'path': '/items/0/score', 'value': True},
            ])

        assert context.exception.code == 'test_failed'
        assert self.instance.items[0]['score'] == 1

    def test_move_uses_array_positions_after_previous_operations(self):
        result = self.apply([
            {'op': 'add', 'path': '/items/-', 'value': {'name': 'three'}},
            {'op': 'remove', 'path': '/items/0'},
            {'op': 'move', 'from': '/items/0', 'path': '/items/1'},
        ])

        assert result.data['items'] == [
            {'name': 'three'},
            {'name': 'two', 'score': 2},
        ]

    def test_validation_failure_keeps_earlier_nested_changes_off_instance(self):
        with self.assertRaises(JsonPatchError) as context:
            self.apply([
                {'op': 'add', 'path': '/items/-', 'value': {'name': 'three'}},
                {'op': 'move', 'from': '/items/0', 'path': '/items/2'},
                {'op': 'replace', 'path': '/items/2/score', 'value': -1},
            ])

        assert context.exception.index == 2
        assert context.exception.path == '/items/2/score'
        assert context.exception.code == 'min_value'
        assert self.instance.items == [
            {'name': 'one', 'score': 1},
            {'name': 'two', 'score': 2},
        ]

    def test_validation_failure_reports_field_code(self):
        with self.assertRaises(JsonPatchError) as context:
            self.apply([
                {'op': 'replace', 'path': '/external_name', 'value': 'x' * 21},
            ])

        assert context.exception.code == 'max_length'

    def test_json_pointer_decoding(self):
        result = apply_json_patch(self.serializer, [
            {'op': 'add', 'path': '/metadata/a~1b', 'value': 4},
        ])

        assert result.data['metadata']['a/b'] == 4

    def test_many_serializer_uses_public_list_schema(self):
        instances = [ExampleObject(), ExampleObject()]
        list_serializer = PatchableSerializer(instances, many=True)

        result = apply_json_patch(list_serializer, [
            {'op': 'replace', 'path': '/1/external_name', 'value': 'second'},
        ], save=False)

        assert result.data[0]['external_name'] == 'original'
        assert result.data[1]['external_name'] == 'second'
        assert instances[1].internal_name == 'original'

    def test_malformed_pointer_keeps_operation_index(self):
        with self.assertRaises(JsonPatchError) as context:
            self.apply([
                {'op': 'test', 'path': 'external_name', 'value': 'original'},
            ])

        assert context.exception.index == 0
        assert context.exception.path == 'external_name'
        assert context.exception.code == 'invalid_pointer'

    def test_final_validation_failure_points_to_last_mutation(self):
        with self.assertRaises(JsonPatchError) as context:
            self.apply([
                {'op': 'test', 'path': '/external_name', 'value': 'original'},
                {'op': 'remove', 'path': '/external_name'},
            ])

        assert context.exception.index == 1
        assert context.exception.path == '/external_name'
        assert context.exception.code == 'required'


class JSONPatchParserTests(TestCase):
    def test_parses_patch_document(self):
        parser = JSONPatchParser()
        stream = io.BytesIO(b'[{"op":"test","path":"/","value":{}}]')

        assert parser.parse(stream) == [{'op': 'test', 'path': '/', 'value': {}}]

    def test_rejects_non_array_document(self):
        parser = JSONPatchParser()

        with self.assertRaises(ParseError):
            parser.parse(io.BytesIO(b'{"op":"test","path":"/"}'))


class JSONPatchViewTests(TestCase):
    def test_generic_patch_accepts_json_patch_media_type(self):
        instance = ExampleObject()
        view = ExampleView.as_view()
        request = factory.patch(
            '/',
            [{'op': 'replace', 'path': '/external_name', 'value': 'updated'}],
            content_type='application/json-patch+json',
        )
        request.instance = instance
        response = view(request).render()

        assert response.status_code == status.HTTP_200_OK
        assert response.data['external_name'] == 'updated'
        assert instance.internal_name == 'updated'

    def test_regular_merged_patch_still_uses_json_media_type(self):
        instance = ExampleObject()
        view = ExampleView.as_view()
        request = factory.patch(
            '/',
            {'external_name': 'updated'},
            format='json',
        )
        request.instance = instance
        response = view(request).render()

        assert response.status_code == status.HTTP_200_OK
        assert instance.internal_name == 'updated'
