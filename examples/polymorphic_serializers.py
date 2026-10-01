#!/usr/bin/env python3
"""Runnable polymorphic serializer and OpenAPI example.

Run from the repository root with:

    PYTHONPATH=. python examples/polymorphic_serializers.py
"""

import json

import django
from django.conf import settings


settings.configure(
    DEBUG=True,
    SECRET_KEY='polymorphic-example',
    ROOT_URLCONF=__name__,
    INSTALLED_APPS=(
        'django.contrib.contenttypes',
        'django.contrib.auth',
        'rest_framework',
    ),
    DATABASES={'default': {}},
)
django.setup()

from django.urls import path
from rest_framework import generics, pagination, serializers
from rest_framework.response import Response
from rest_framework.schemas.openapi import AutoSchema, SchemaGenerator


class CreateTextSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=['text'])
    text = serializers.CharField()
    internal_note = serializers.CharField(write_only=True, required=False)


class CreateNumberSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=['number'])
    value = serializers.IntegerField()


class TextResultSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=['text'])
    rendered = serializers.CharField(read_only=True)


class NumberResultSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=['number'])
    rendered = serializers.IntegerField(read_only=True)


class EventRequestSerializer(serializers.PolymorphicSerializer):
    def get_branches(self):
        return (
            serializers.SerializerBranch('text', CreateTextSerializer),
            serializers.SerializerBranch('number', CreateNumberSerializer),
        )


class EventResponseSerializer(serializers.PolymorphicSerializer):
    def get_branches(self):
        return (
            serializers.SerializerBranch('text', TextResultSerializer),
            serializers.SerializerBranch('number', NumberResultSerializer),
        )


class EventSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return {'GET': 'listEvents', 'POST': 'createEvents'}[method]

    def get_path_parameters(self, path, method):
        return []

    def get_request_serializer(self, path, method):
        return EventRequestSerializer()

    def get_response_serializer(self, path, method):
        return EventResponseSerializer()


class ExamplePagination(pagination.BasePagination):
    def get_paginated_response_schema(self, schema):
        return {
            'type': 'object',
            'count': {'type': 'integer'},
            'results': schema,
        }


class EventView(generics.GenericAPIView):
    serializer_class = EventRequestSerializer
    schema = EventSchema()
    pagination_class = ExamplePagination

    def get(self, request):
        events = [
            {'type': 'text', 'rendered': 'hello'},
            {'type': 'number', 'rendered': 42},
        ]
        return Response({'count': len(events), 'results': EventResponseSerializer(events, many=True).data})

    def post(self, request):
        serializer = EventRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.validated_data['type'] == 'text':
            result = {'type': 'text', 'rendered': serializer.validated_data['text']}
        else:
            result = {'type': 'number', 'rendered': serializer.validated_data['value'] * 2}
        return Response(EventResponseSerializer(result).data, status=201)


urlpatterns = [
    path('events/', EventView.as_view()),
]


def main():
    schema = SchemaGenerator(patterns=urlpatterns).get_schema(public=True)
    get_operation = schema['paths']['/events/']['get']
    post_operation = schema['paths']['/events/']['post']
    assert get_operation['responses']['200']['content']['application/json']['schema']['results'] == {
        'type': 'array',
        'items': {'$ref': '#/components/schemas/EventResponse'},
    }
    assert post_operation['requestBody']['content']['application/json']['schema'] == {
        '$ref': '#/components/schemas/EventRequest'
    }
    print(json.dumps(schema['components']['schemas']['EventResponse'], indent=2, sort_keys=True))

    valid = EventRequestSerializer(data={'type': 'number', 'value': 21})
    assert valid.is_valid(), valid.errors

    unknown = EventRequestSerializer(data={'type': 'image'})
    assert not unknown.is_valid()
    assert unknown.errors['type'][0].code == 'invalid_choice'

    rendered = EventResponseSerializer([
        {'type': 'text', 'rendered': 'hello'},
        {'type': 'number', 'rendered': 42},
    ], many=True).data
    assert rendered == [
        {'type': 'text', 'rendered': 'hello'},
        {'type': 'number', 'rendered': 42},
    ]
    print('Runtime validation selected the declared branches successfully.')


if __name__ == '__main__':
    main()
