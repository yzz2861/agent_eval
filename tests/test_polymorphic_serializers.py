import pytest

from django.urls import path

from rest_framework import generics, pagination, serializers
from rest_framework.schemas.openapi import AutoSchema, SchemaGenerator


class TextPayloadSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=['text'])
    text = serializers.CharField()
    secret = serializers.CharField(write_only=True)

    def create(self, validated_data):
        return validated_data


class NumberPayloadSerializer(serializers.Serializer):
    value = serializers.IntegerField()
    computed = serializers.IntegerField(read_only=True)

    def create(self, validated_data):
        return validated_data


class TextResultSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=['text'])
    rendered = serializers.CharField(read_only=True)


class NumberResultSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=['number'])
    rendered = serializers.IntegerField(read_only=True)


class PayloadSerializer(serializers.PolymorphicSerializer):
    def get_branches(self):
        return (
            serializers.SerializerBranch('text', TextPayloadSerializer),
            serializers.SerializerBranch('number', NumberPayloadSerializer),
        )


class ResultSerializer(serializers.PolymorphicSerializer):
    def get_branches(self):
        return (
            serializers.SerializerBranch('text', TextResultSerializer),
            serializers.SerializerBranch('number', NumberResultSerializer),
        )


class Pagination(pagination.BasePagination):
    def get_paginated_response_schema(self, schema):
        return {
            'type': 'object',
            'count': {'type': 'integer'},
            'results': schema,
        }


class StaticSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return path.strip('/')

    def get_path_parameters(self, path, method):
        return []


class PolymorphicSchema(AutoSchema):
    def get_request_serializer(self, path, method):
        return PayloadSerializer()

    def get_response_serializer(self, path, method):
        return ResultSerializer()


class PolymorphicView(generics.GenericAPIView):
    pagination_class = Pagination
    serializer_class = PayloadSerializer
    schema = PolymorphicSchema()


class TestPolymorphicSerializerRuntime:
    def test_selects_serializer_from_discriminator(self):
        serializer = PayloadSerializer(data={'type': 'number', 'value': 3})

        assert serializer.is_valid()
        assert serializer.validated_data == {'type': 'number', 'value': 3}

    def test_unknown_label_is_rejected(self):
        serializer = PayloadSerializer(data={'type': 'unknown'})

        assert not serializer.is_valid()
        assert serializer.errors['type'][0].code == 'invalid_choice'

    def test_missing_label_is_rejected(self):
        serializer = PayloadSerializer(data={'value': 3})

        assert not serializer.is_valid()
        assert serializer.errors['type'][0].code == 'required'

    def test_non_object_input_is_invalid(self):
        serializer = PayloadSerializer(data=['not', 'an', 'object'])

        assert not serializer.is_valid()
        assert serializer.errors['non_field_errors'][0].code == 'invalid'

    def test_many_selects_each_serializer(self):
        serializer = PayloadSerializer(data=[
            {'type': 'text', 'text': 'hello', 'secret': 'x'},
            {'type': 'number', 'value': 3},
        ], many=True)

        assert serializer.is_valid()
        assert serializer.validated_data == [
            {'type': 'text', 'text': 'hello', 'secret': 'x'},
            {'type': 'number', 'value': 3},
        ]

    def test_many_unknown_label_is_rejected(self):
        serializer = PayloadSerializer(data=[{'type': 'unknown'}], many=True)

        assert not serializer.is_valid()
        assert 0 in serializer.errors

    def test_many_requires_list_input(self):
        serializer = PayloadSerializer(data={'type': 'text'}, many=True)

        assert not serializer.is_valid()
        assert serializer.errors['non_field_errors'][0].code == 'not_a_list'

    def test_response_render_uses_selected_branch(self):
        serializer = ResultSerializer(instance={'type': 'number', 'value': 3, 'rendered': 6})

        assert serializer.data == {'type': 'number', 'rendered': 6}

    def test_save_selects_branch(self):
        serializer = PayloadSerializer(data={'type': 'text', 'text': 'hello', 'secret': 'x'})
        assert serializer.is_valid()

        saved = serializer.save()
        assert saved == {'type': 'text', 'text': 'hello', 'secret': 'x'}

    def test_many_save_selects_each_branch(self):
        serializer = PayloadSerializer(data=[
            {'type': 'text', 'text': 'hello', 'secret': 'x'},
            {'type': 'number', 'value': 3},
        ], many=True)
        assert serializer.is_valid()

        saved = serializer.save()
        assert saved == [
            {'type': 'text', 'text': 'hello', 'secret': 'x'},
            {'type': 'number', 'value': 3},
        ]

    def test_duplicate_labels_are_invalid(self):
        with pytest.raises(ValueError, match='Duplicate serializer branch label'):
            serializers.PolymorphicSerializer(branches=[
                ('same', TextPayloadSerializer),
                ('same', NumberPayloadSerializer),
            ])


class TestPolymorphicSchema:
    def test_one_of_discriminator_components_and_pagination(self):
        generator = SchemaGenerator()
        view = generator.create_view(PolymorphicView.as_view(), 'GET')
        inspector = view.schema

        components = inspector.get_components('/items/', 'GET')
        inspector.response_media_types = ['application/json']
        operation = {'responses': inspector.get_responses('/items/', 'GET')}

        response_schema = operation['responses']['200']['content']['application/json']['schema']
        assert response_schema['type'] == 'object'
        assert response_schema['results']['type'] == 'array'
        result_ref = response_schema['results']['items']
        result_name = result_ref['$ref'].split('/')[-1]
        result_schema = components[result_name]
        assert len(result_schema['oneOf']) == 2
        assert result_schema['discriminator']['propertyName'] == 'type'
        assert set(result_schema['discriminator']['mapping']) == {'text', 'number'}

        text_component = components[result_schema['discriminator']['mapping']['text'].split('/')[-1]]
        number_component = components[result_schema['discriminator']['mapping']['number'].split('/')[-1]]
        assert text_component['properties']['type']['enum'] == ['text']
        assert 'rendered' in text_component['properties']
        assert number_component['properties']['rendered']['type'] == 'integer'

    def test_request_and_response_use_different_branch_sets(self):
        generator = SchemaGenerator()
        view = generator.create_view(PolymorphicView.as_view(), 'POST')
        inspector = view.schema

        components = inspector.get_components('/items/', 'POST')
        inspector.request_media_types = ['application/json']
        inspector.response_media_types = ['application/json']
        operation = {
            'requestBody': inspector.get_request_body('/items/', 'POST'),
            'responses': inspector.get_responses('/items/', 'POST'),
        }

        request_name = operation['requestBody']['content']['application/json']['schema']['$ref'].split('/')[-1]
        response_name = operation['responses']['201']['content']['application/json']['schema']['$ref'].split('/')[-1]
        assert set(components[request_name]['discriminator']['mapping']) == {'text', 'number'}
        assert set(components[response_name]['discriminator']['mapping']) == {'text', 'number'}

        payload_text_name = components[request_name]['discriminator']['mapping']['text'].split('/')[-1]
        result_text_name = components[response_name]['discriminator']['mapping']['text'].split('/')[-1]
        assert payload_text_name != result_text_name
        assert components[payload_text_name]['properties']['secret']['writeOnly'] is True
        assert components[result_text_name]['properties']['rendered']['readOnly'] is True

    def test_same_named_serializers_do_not_overwrite(self):
        class SharedNameSerializer(serializers.Serializer):
            first = serializers.CharField()

        other = SharedNameSerializer

        class SharedNameSerializer(serializers.Serializer):  # noqa: F811
            second = serializers.IntegerField()

        inspector = AutoSchema()
        registry = inspector._get_component_registry()
        first_ref = registry.map(other())
        second_ref = registry.map(SharedNameSerializer())

        assert first_ref != second_ref
        components = registry.components
        assert 'first' in components[first_ref['$ref'].split('/')[-1]]['properties']
        assert 'second' in components[second_ref['$ref'].split('/')[-1]]['properties']

    def test_same_named_serializers_do_not_overwrite_in_generated_schema(self):
        class FirstSerializer(serializers.Serializer):
            first = serializers.CharField()

        class SecondSerializer(serializers.Serializer):
            second = serializers.IntegerField()

        first_serializer = FirstSerializer
        second_serializer = SecondSerializer
        first_serializer.__name__ = 'SharedNameSerializer'
        second_serializer.__name__ = 'SharedNameSerializer'

        class FirstView(generics.GenericAPIView):
            serializer_class = first_serializer
            schema = StaticSchema()

            def get(self, request):
                pass

        class SecondView(generics.GenericAPIView):
            serializer_class = second_serializer
            schema = StaticSchema()

            def get(self, request):
                pass

        generator = SchemaGenerator(patterns=[
            path('first/', FirstView.as_view()),
            path('second/', SecondView.as_view()),
        ])
        generated_schema = generator.get_schema(public=True)
        assert generated_schema['paths']
        components = generated_schema['components']['schemas']

        assert components['SharedName']['properties'] == {
            'first': {'type': 'string'}
        }
        assert components['SharedName2']['properties'] == {
            'second': {'type': 'integer'}
        }

    def test_recursive_reference_terminates(self):
        class Recursive(serializers.Serializer):
            name = serializers.CharField()

        Recursive._declared_fields['children'] = Recursive(many=True)

        inspector = AutoSchema()
        registry = inspector._get_component_registry()
        ref = registry.map(Recursive())
        component = registry.components['Recursive']

        assert ref == {'$ref': '#/components/schemas/Recursive'}
        assert component['properties']['children'] == {
            'type': 'array',
            'items': {'$ref': '#/components/schemas/Recursive'},
        }

    def test_non_recursive_nested_serializer_stays_inline(self):
        class NestedSerializer(serializers.Serializer):
            number = serializers.IntegerField()

        class ItemSerializer(serializers.Serializer):
            text = serializers.CharField()
            nested = NestedSerializer()

        inspector = AutoSchema()
        registry = inspector._get_component_registry()
        ref = registry.map(ItemSerializer())
        component = registry.components[ref['$ref'].split('/')[-1]]

        assert component['properties']['nested'] == {
            'type': 'object',
            'properties': {'number': {'type': 'integer'}},
            'required': ['number'],
        }
        assert 'Nested' not in registry.components

    def test_polymorphic_recursive_branch_terminates(self):
        class BranchSerializer(serializers.Serializer):
            name = serializers.CharField()

        class RecursivePolymorphicSerializer(serializers.PolymorphicSerializer):
            discriminator_field_name = 'type'

            def get_branches(self):
                return (
                    serializers.SerializerBranch('node', BranchSerializer),
                )

        BranchSerializer._declared_fields['child'] = RecursivePolymorphicSerializer()

        inspector = AutoSchema()
        registry = inspector._get_component_registry()
        ref = registry.map(RecursivePolymorphicSerializer())
        wrapper_name = ref['$ref'].split('/')[-1]
        branch_ref = registry.components[wrapper_name]['oneOf'][0]
        branch_name = branch_ref['$ref'].split('/')[-1]

        assert registry.components[branch_name]['properties']['child'] == {
            '$ref': '#/components/schemas/RecursivePolymorphic'
        }
