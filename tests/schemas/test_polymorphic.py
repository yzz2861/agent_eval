from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase
from django.urls import path

from rest_framework import generics, pagination, serializers
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.schemas.openapi import AutoSchema, ComponentRegistry, SchemaGenerator
from rest_framework.test import APIRequestFactory


factory = APIRequestFactory()


def make_duplicate_named_serializer(field_name):
    class CatSerializer(serializers.Serializer):
        pass

    field = serializers.IntegerField()
    CatSerializer._declared_fields = {
        'type': serializers.CharField(),
        field_name: field,
    }
    return CatSerializer


class TestPolymorphicSerializer(TestCase):
    def test_runtime_selects_matching_serializer(self):
        class CatSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()
            lives = serializers.IntegerField()

        class DogSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()
            breed = serializers.CharField()

        class PetSerializer(serializers.PolymorphicSerializer):
            serializer_types = {
                'cat': CatSerializer,
                'dog': DogSerializer,
            }

        cat = PetSerializer(data={'type': 'cat', 'name': 'Milo', 'lives': 9})
        dog = PetSerializer(data={'type': 'dog', 'name': 'Rex', 'breed': 'Labrador'})

        assert cat.is_valid()
        assert dog.is_valid()
        assert cat.validated_data == {'type': 'cat', 'name': 'Milo', 'lives': 9}
        assert dog.validated_data == {
            'type': 'dog', 'name': 'Rex', 'breed': 'Labrador'
        }

    def test_unknown_label_does_not_fall_back_to_first_branch(self):
        class CatSerializer(serializers.Serializer):
            type = serializers.CharField()

        class DogSerializer(serializers.Serializer):
            type = serializers.CharField()

        class PetSerializer(serializers.PolymorphicSerializer):
            serializer_types = {
                'cat': CatSerializer,
                'dog': DogSerializer,
            }

        serializer = PetSerializer(data={'type': 'bird'})

        assert not serializer.is_valid()
        assert 'type' in serializer.errors
        assert 'bird' in str(serializer.errors['type'][0])

    def test_duplicate_labels_are_rejected(self):
        class CatSerializer(serializers.Serializer):
            type = serializers.CharField()

        class DogSerializer(serializers.Serializer):
            type = serializers.CharField()

        class PetSerializer(serializers.PolymorphicSerializer):
            serializer_types = (
                ('cat', CatSerializer),
                ('cat', DogSerializer),
            )

        with self.assertRaisesRegex(ValueError, 'labels must be unique'):
            PetSerializer.get_serializer_types()

    def test_many_runtime_selects_a_serializer_for_each_item(self):
        class CatSerializer(serializers.Serializer):
            type = serializers.CharField()
            lives = serializers.IntegerField()

        class DogSerializer(serializers.Serializer):
            type = serializers.CharField()
            breed = serializers.CharField()

        class PetSerializer(serializers.PolymorphicSerializer):
            serializer_types = {
                'cat': CatSerializer,
                'dog': DogSerializer,
            }

        serializer = PetSerializer(data=[
            {'type': 'cat', 'lives': 9},
            {'type': 'dog', 'breed': 'Collie'},
        ], many=True)

        assert serializer.is_valid()
        assert serializer.validated_data == [
            {'type': 'cat', 'lives': 9},
            {'type': 'dog', 'breed': 'Collie'},
        ]

    def test_many_unknown_label_keeps_its_index(self):
        class CatSerializer(serializers.Serializer):
            type = serializers.CharField()

        class DogSerializer(serializers.Serializer):
            type = serializers.CharField()

        class PetSerializer(serializers.PolymorphicSerializer):
            serializer_types = {
                'cat': CatSerializer,
                'dog': DogSerializer,
            }

        serializer = PetSerializer(data=[
            {'type': 'cat'},
            {'type': 'bird'},
        ], many=True)

        assert not serializer.is_valid()
        assert 1 in serializer.errors
        assert 'type' in serializer.errors[1]

    def test_save_uses_selected_branch(self):
        class CatSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()

            def create(self, validated_data):
                return {'created': validated_data}

        class DogSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()

        class PetSerializer(serializers.PolymorphicSerializer):
            serializer_types = {
                'cat': CatSerializer,
                'dog': DogSerializer,
            }

        serializer = PetSerializer(data={'type': 'cat', 'name': 'Milo'})
        assert serializer.is_valid()
        assert serializer.save() == {
            'created': {'type': 'cat', 'name': 'Milo'}
        }

    def test_documentation_and_runtime_branch_validation_match(self):
        class WriteCatSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()
            secret = serializers.CharField(write_only=True)

        class WriteDogSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()
            owner = serializers.CharField(write_only=True)

        class ReadCatSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()
            identifier = serializers.IntegerField(read_only=True)

        class ReadDogSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()
            family = serializers.CharField(read_only=True)

        class WritePetSerializer(serializers.PolymorphicSerializer):
            serializer_types = {
                'cat': WriteCatSerializer,
                'dog': WriteDogSerializer,
            }

        class ReadPetSerializer(serializers.PolymorphicSerializer):
            serializer_types = {
                'cat': ReadCatSerializer,
                'dog': ReadDogSerializer,
            }

        class PetSchema(AutoSchema):
            def get_request_serializer(self, path, method):
                return WritePetSerializer()

            def get_response_serializer(self, path, method):
                return ReadPetSerializer()

        class PetView(generics.GenericAPIView):
            serializer_class = WritePetSerializer
            schema = PetSchema()

            def post(self, request):
                write_serializer = WritePetSerializer(data=request.data)
                write_serializer.is_valid(raise_exception=True)
                response_data = dict(write_serializer.validated_data)
                if response_data['type'] == 'cat':
                    response_data['identifier'] = 7
                else:
                    response_data['family'] = 'Canidae'
                read_serializer = ReadPetSerializer(response_data)
                return Response(read_serializer.data, status=201)

        route = '/pets/'
        schema_request = Request(factory.get(route))
        generator = SchemaGenerator()
        view = generator.create_view(PetView.as_view(), 'POST', schema_request)
        inspector = view.schema
        components = inspector.get_components(route, 'POST')
        request_body = inspector.get_request_body(route, 'POST')
        responses = inspector.get_responses(route, 'POST')

        request_schema = request_body['content']['application/json']['schema']
        response_schema = responses['201']['content']['application/json']['schema']

        assert request_schema['discriminator']['propertyName'] == 'type'
        assert set(request_schema['discriminator']['mapping']) == {'cat', 'dog'}
        assert response_schema['discriminator']['mapping']['cat'] == '#/components/schemas/ReadCat'
        assert components['WriteCat']['properties']['secret']['writeOnly'] is True
        assert 'readOnly' not in components['WriteCat']['properties']['secret']
        assert components['ReadCat']['properties']['identifier']['readOnly'] is True
        assert 'writeOnly' not in components['ReadCat']['properties']['identifier']

        cat_response = PetView.as_view()(factory.post(
            route, {'type': 'cat', 'name': 'Milo', 'secret': 'x'}, format='json'
        ))
        dog_response = PetView.as_view()(factory.post(
            route, {'type': 'dog', 'name': 'Rex', 'owner': 'Amy'}, format='json'
        ))
        unknown_response = PetView.as_view()(factory.post(
            route, {'type': 'bird'}, format='json'
        ))

        assert cat_response.status_code == 201
        assert cat_response.data == {
            'type': 'cat', 'name': 'Milo', 'identifier': 7
        }
        assert dog_response.status_code == 201
        assert dog_response.data == {
            'type': 'dog', 'name': 'Rex', 'family': 'Canidae'
        }
        assert unknown_response.status_code == 400
        assert 'type' in unknown_response.data

    def test_many_paginated_response_wraps_oneOf(self):
        class CatSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()

        class DogSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()

        class PetSerializer(serializers.PolymorphicSerializer):
            serializer_types = {
                'cat': CatSerializer,
                'dog': DogSerializer,
            }

        class Pagination(pagination.BasePagination):
            def get_paginated_response_schema(self, schema):
                return {'type': 'object', 'results': schema}

        class View(generics.GenericAPIView):
            serializer_class = PetSerializer
            pagination_class = Pagination

        route = '/'
        schema_request = Request(factory.get(route))
        generator = SchemaGenerator()
        view = generator.create_view(View.as_view(), 'GET', schema_request)
        inspector = view.schema
        responses = inspector.get_responses(route, 'GET')
        components = inspector.get_components(route, 'GET')
        response_schema = responses['200']['content']['application/json']['schema']

        assert response_schema['type'] == 'object'
        assert response_schema['results']['type'] == 'array'
        assert 'oneOf' in response_schema['results']['items']
        assert response_schema['results']['items']['discriminator']['propertyName'] == 'type'
        assert set(components) == {'Cat', 'Dog'}

    def test_same_component_names_are_disambiguated(self):
        first_serializer_class = make_duplicate_named_serializer('indoor')
        second_serializer_class = make_duplicate_named_serializer('barks')
        assert first_serializer_class is not second_serializer_class
        assert list(first_serializer_class().fields) == ['type', 'indoor']
        assert list(second_serializer_class().fields) == ['type', 'barks']

        class FirstPetSerializer(serializers.PolymorphicSerializer):
            serializer_types = {'cat': first_serializer_class}

        class SecondPetSerializer(serializers.PolymorphicSerializer):
            serializer_types = {'dog': second_serializer_class}

        class FirstView(generics.GenericAPIView):
            serializer_class = FirstPetSerializer

            def post(self, request):
                pass

        class SecondView(generics.GenericAPIView):
            serializer_class = SecondPetSerializer

            def post(self, request):
                pass

        patterns = [
            path('first/', FirstView.as_view()),
            path('second/', SecondView.as_view()),
        ]
        fake_uritemplate = SimpleNamespace(variables=lambda path: ())
        with patch('rest_framework.schemas.openapi.uritemplate', fake_uritemplate):
            schema = SchemaGenerator(patterns=patterns).get_schema(public=True)
        components = schema['components']['schemas']

        assert 'Cat' in components
        assert 'Cat2' in components
        assert components['Cat'] != components['Cat2']
        first_schema = schema['paths']['/first/']['post']['requestBody']['content']['application/json']['schema']
        second_schema = schema['paths']['/second/']['post']['requestBody']['content']['application/json']['schema']
        assert first_schema['oneOf'] == [{'$ref': '#/components/schemas/Cat'}]
        assert second_schema['oneOf'] == [{'$ref': '#/components/schemas/Cat2'}]
        assert second_schema['discriminator']['mapping']['dog'] == '#/components/schemas/Cat2'

    def test_recursive_branch_reference_terminates(self):
        class NodeTreeSerializer(serializers.PolymorphicSerializer):
            serializer_types = {}

        class NodeSerializer(serializers.Serializer):
            type = serializers.CharField()
            name = serializers.CharField()
            children = NodeTreeSerializer(many=True, read_only=True)

        NodeTreeSerializer.serializer_types = {'node': NodeSerializer}

        inspector = AutoSchema()
        registry = ComponentRegistry()
        schema = inspector.map_polymorphic_serializer(
            NodeTreeSerializer(), registry=registry, direction='response'
        )
        components = registry.components

        assert schema == {
            'oneOf': [{'$ref': '#/components/schemas/Node'}],
            'discriminator': {
                'propertyName': 'type',
                'mapping': {'node': '#/components/schemas/Node'},
            },
        }
        nested = components['Node']['properties']['children']
        assert nested['readOnly'] is True
        assert nested['type'] == 'array'
        assert nested['items'] == schema
