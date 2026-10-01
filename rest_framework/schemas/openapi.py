import re
import warnings
from decimal import Decimal
from operator import attrgetter
from urllib.parse import urljoin

from django.core.validators import (
    DecimalValidator, EmailValidator, MaxLengthValidator, MaxValueValidator,
    MinLengthValidator, MinValueValidator, RegexValidator, URLValidator
)
from django.db import models
from django.utils.encoding import force_str

from rest_framework import exceptions, renderers, serializers
from rest_framework.compat import inflection, uritemplate
from rest_framework.fields import _UnvalidatedField, empty
from rest_framework.settings import api_settings

from .generators import BaseSchemaGenerator
from .inspectors import ViewInspector
from .utils import get_pk_description, is_list_view


class ComponentRegistry:
    def __init__(self):
        self.components = {}
        self.serializer_info = {}
        self.polymorphic_serializers = set()
        self.current_direction = None

    def register(self, serializer, content=None, name=None, explicit=False, direction=None):
        serializer_class = serializer.__class__
        component_key = (serializer_class, direction)
        for existing_name, info in self.serializer_info.items():
            if info[0] == component_key:
                return existing_name

        if name is None:
            name = self.get_default_name(serializer)

        if name in self.components:
            has_other_direction = any(
                existing_class is serializer_class and
                existing_direction not in (None, direction)
                for existing_class, existing_direction in self.serializer_info.values()
            )
            if direction is not None and has_other_direction:
                name = f'{name}{direction.title()}'
            suffix = 2
            while name in self.components:
                name = f'{name}{suffix}'
                suffix += 1

        self.serializer_info[name] = (component_key, explicit)
        if content is None:
            self.components[name] = {}
        else:
            self.components[name] = content
        return name

    def get_default_name(self, serializer):
        component_name = serializer.__class__.__name__
        return re.sub('serializer', '', component_name, flags=re.IGNORECASE)

    def resolve_name(self, serializer, direction):
        default_name = self.get_default_name(serializer)
        default_key = (serializer.__class__, direction)
        if default_name in self.serializer_info and (
            self.serializer_info[default_name][0] == default_key or
            self.serializer_info[default_name][0][0] is serializer.__class__
        ):
            return default_name
        for name, (key, _) in self.serializer_info.items():
            serializer_class, component_direction = key
            if serializer_class is serializer.__class__ and (
                component_direction == direction or
                component_direction is None
            ):
                return name
        return self.register(serializer, direction=direction)

    def update(self, name, serializer, content, explicit=False, direction=None):
        self.components[name] = content
        self.serializer_info[name] = ((serializer.__class__, direction), explicit)


class SchemaGenerator(BaseSchemaGenerator):

    def get_info(self):
        # Title and version are required by openapi specification 3.x
        info = {
            'title': self.title or '',
            'version': self.version or ''
        }

        if self.description is not None:
            info['description'] = self.description

        return info

    def check_duplicate_operation_id(self, paths):
        ids = {}
        for route in paths:
            for method in paths[route]:
                if 'operationId' not in paths[route][method]:
                    continue
                operation_id = paths[route][method]['operationId']
                if operation_id in ids:
                    warnings.warn(
                        'You have a duplicated operationId in your OpenAPI schema: {operation_id}\n'
                        '\tRoute: {route1}, Method: {method1}\n'
                        '\tRoute: {route2}, Method: {method2}\n'
                        '\tAn operationId has to be unique across your schema. Your schema may not work in other tools.'
                        .format(
                            route1=ids[operation_id]['route'],
                            method1=ids[operation_id]['method'],
                            route2=route,
                            method2=method,
                            operation_id=operation_id
                        )
                    )
                ids[operation_id] = {
                    'route': route,
                    'method': method
                }

    def get_schema(self, request=None, public=False):
        """
        Generate a OpenAPI schema.
        """
        self._initialise_endpoints()
        components_schemas = {}

        # Iterate endpoints generating per method path operations.
        paths = {}
        component_classes = {}
        _, view_endpoints = self._get_paths_and_endpoints(None if public else request)
        for path, method, view in view_endpoints:
            if not self.has_view_permissions(path, method, view):
                continue

            operation, components, component_info = view.schema.get_operation_with_components(
                path, method
            )
            for component_name, content in components.items():
                component_key, explicit = component_info.get(
                    component_name, ((None, None), False)
                )
                serializer_class, _ = component_key
                if component_name in components_schemas:
                    existing_key = component_classes.get(component_name)
                    if component_key[0] is not None and existing_key == component_key:
                        continue
                    if explicit:
                        if components_schemas[component_name] != content:
                            warnings.warn(
                                f'Schema component "{component_name}" has been '
                                'overridden with a different value.'
                            )
                        continue

                    canonical_name = component_name
                    suffix = 2
                    while canonical_name in components_schemas:
                        candidate = f'{component_name}{suffix}'
                        if candidate not in components_schemas:
                            canonical_name = candidate
                            break
                        suffix += 1
                    operation = self._rename_component_reference(
                        operation, component_name, canonical_name
                    )
                    component_info[canonical_name] = (
                        component_key, explicit
                    )
                    component_name = canonical_name

                components_schemas[component_name] = content
                if serializer_class is not None:
                    component_classes[component_name] = component_key

            # Normalize path for any provided mount url.
            if path.startswith('/'):
                path = path[1:]
            path = urljoin(self.url or '/', path)

            paths.setdefault(path, {})
            paths[path][method.lower()] = operation

        self.check_duplicate_operation_id(paths)

        # Compile final schema.
        schema = {
            'openapi': '3.0.2',
            'info': self.get_info(),
            'paths': paths,
        }

        if len(components_schemas) > 0:
            schema['components'] = {
                'schemas': components_schemas
            }

        return schema

    def _rename_component_reference(self, value, old_name, new_name):
        if isinstance(value, list):
            return [
                self._rename_component_reference(item, old_name, new_name)
                for item in value
            ]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                old_reference = f'#/components/schemas/{old_name}'
                new_reference = f'#/components/schemas/{new_name}'
                if key == '$ref' and item == old_reference:
                    result[key] = new_reference
                elif isinstance(item, str) and item == old_reference:
                    result[key] = new_reference
                else:
                    result[key] = self._rename_component_reference(
                        item, old_name, new_name
                    )
            return result
        return value

# View Inspectors


class AutoSchema(ViewInspector):

    def __init__(self, tags=None, operation_id_base=None, component_name=None):
        """
        :param operation_id_base: user-defined name in operationId. If empty, it will be deducted from the Model/Serializer/View name.
        :param component_name: user-defined component's name. If empty, it will be deducted from the Serializer's class name.
        """
        if tags and not all(isinstance(tag, str) for tag in tags):
            raise ValueError('tags must be a list or tuple of string.')
        self._tags = tags
        self.operation_id_base = operation_id_base
        self.component_name = component_name
        super().__init__()

    request_media_types = []
    response_media_types = []

    method_mapping = {
        'get': 'retrieve',
        'post': 'create',
        'put': 'update',
        'patch': 'partialUpdate',
        'delete': 'destroy',
    }

    def get_operation_with_components(self, path, method):
        components, component_info = self.get_components_with_info(path, method)
        registry = getattr(self, '_last_component_registry', ComponentRegistry())
        operation = self.get_operation(path, method, registry)
        return operation, components, component_info

    def get_operation(self, path, method, registry=None):
        if registry is None:
            registry = ComponentRegistry()
        operation = {}

        operation['operationId'] = self.get_operation_id(path, method)
        operation['description'] = self.get_description(path, method)

        parameters = []
        parameters += self.get_path_parameters(path, method)
        parameters += self.get_pagination_parameters(path, method)
        parameters += self.get_filter_parameters(path, method)
        operation['parameters'] = parameters

        request_body = self.get_request_body(path, method, registry)
        if request_body:
            operation['requestBody'] = request_body
        operation['responses'] = self.get_responses(path, method, registry)
        operation['tags'] = self.get_tags(path, method)

        return operation

    def get_component_name(self, serializer):
        """
        Compute the component's name from the serializer.
        Raise an exception if the serializer's class name is "Serializer" (case-insensitive).
        """
        if self.component_name is not None:
            return self.component_name

        # use the serializer's class name as the component name.
        component_name = serializer.__class__.__name__
        # We remove the "serializer" string from the class name.
        pattern = re.compile("serializer", re.IGNORECASE)
        component_name = pattern.sub("", component_name)

        if component_name == "":
            raise Exception(
                '"{}" is an invalid class name for schema generation. '
                'Serializer\'s class name should be unique and explicit. e.g. "ItemSerializer"'
                .format(serializer.__class__.__name__)
            )

        return component_name

    def get_components(self, path, method):
        """
        Return components with their properties from the serializer.
        """
        if method.lower() == 'delete':
            return {}

        request_serializer = self.get_request_serializer(path, method)
        response_serializer = self.get_response_serializer(path, method)
        registry = ComponentRegistry()
        self._last_component_registry = registry

        endpoint_serializers = []
        if method.lower() in ('post', 'put', 'patch'):
            endpoint_serializers.append((request_serializer, 'request', 0))
        endpoint_serializers.append((response_serializer, 'response', 0))

        for endpoint_serializer, direction, depth in endpoint_serializers:
            serializer = self._unwrap_serializer(endpoint_serializer)
            if not isinstance(serializer, serializers.Serializer):
                continue
            registry.current_direction = direction
            if isinstance(serializer, serializers.PolymorphicSerializer):
                self._register_polymorphic_components(serializer, direction, registry)
            else:
                component_name = self.get_component_name(serializer)
                explicit = self.component_name is not None
                component_name = registry.register(
                    serializer,
                    explicit=explicit,
                    name=component_name,
                    direction=None,
                )
                content = self.map_serializer(serializer, registry=registry, depth=depth)
                registry.update(
                    component_name,
                    serializer,
                    content,
                    explicit=explicit,
                    direction=None,
                )

        return registry.components

    def get_components_with_info(self, path, method):
        components = self.get_components(path, method)
        if not components:
            return components, {}
        registry = self._last_component_registry
        return components, registry.serializer_info

    def _unwrap_serializer(self, serializer):
        if isinstance(serializer, serializers.ListSerializer):
            return serializer.child
        return serializer

    def _register_polymorphic_components(self, serializer, direction, registry):
        poly_key = (serializer.__class__, direction)
        if poly_key in registry.polymorphic_serializers:
            return
        registry.polymorphic_serializers.add(poly_key)
        registry.current_direction = direction
        for label in serializer.get_serializer_types():
            branch = serializer.get_serializer_for_type(
                label, context=getattr(serializer, '_context', {})
            )
            component_name = self._register_polymorphic_branch(
                branch, registry, {}, direction
            )
            content = self.map_serializer(branch, registry=registry, depth=1)
            properties = content.setdefault('properties', {})
            type_property = properties.setdefault(
                serializer.serializer_type_field_name,
                {'type': 'string'}
            )
            type_property['enum'] = [label]
            required = content.setdefault('required', [])
            if serializer.serializer_type_field_name not in required:
                required.append(serializer.serializer_type_field_name)
            component_name = registry.resolve_name(branch, direction)
            registry.update(
                component_name, branch, content, direction=direction
            )
        registry.current_direction = None

    def _register_polymorphic_branch(self, branch, registry, content, direction):
        for name, (key, _) in registry.serializer_info.items():
            existing_class, existing_direction = key
            if existing_class is not branch.__class__:
                continue
            if existing_direction == direction or registry.components.get(name) == content:
                return name

        component_name = registry.get_default_name(branch)
        if component_name in registry.components:
            directional_name = f'{component_name}{direction.title()}'
            if directional_name not in registry.components:
                component_name = directional_name
            else:
                suffix = 2
                while f'{component_name}{suffix}' in registry.components:
                    suffix += 1
                component_name = f'{component_name}{suffix}'

        registry.components[component_name] = content
        registry.serializer_info[component_name] = (
            (branch.__class__, direction), False
        )
        return component_name

    def _to_camel_case(self, snake_str):
        components = snake_str.split('_')
        # We capitalize the first letter of each component except the first one
        # with the 'title' method and join them together.
        return components[0] + ''.join(x.title() for x in components[1:])

    def get_operation_id_base(self, path, method, action):
        """
        Compute the base part for operation ID from the model, serializer or view name.
        """
        model = getattr(getattr(self.view, 'queryset', None), 'model', None)

        if self.operation_id_base is not None:
            name = self.operation_id_base

        # Try to deduce the ID from the view's model
        elif model is not None:
            name = model.__name__

        # Try with the serializer class name
        elif self.get_serializer(path, method) is not None:
            name = self.get_serializer(path, method).__class__.__name__
            if name.endswith('Serializer'):
                name = name[:-10]

        # Fallback to the view name
        else:
            name = self.view.__class__.__name__
            if name.endswith('APIView'):
                name = name[:-7]
            elif name.endswith('View'):
                name = name[:-4]

            # Due to camel-casing of classes and `action` being lowercase, apply title in order to find if action truly
            # comes at the end of the name
            if name.endswith(action.title()):  # ListView, UpdateAPIView, ThingDelete ...
                name = name[:-len(action)]

        if action == 'list':
            assert inflection, '`inflection` must be installed for OpenAPI schema support.'
            name = inflection.pluralize(name)

        return name

    def get_operation_id(self, path, method):
        """
        Compute an operation ID from the view type and get_operation_id_base method.
        """
        method_name = getattr(self.view, 'action', method.lower())
        if is_list_view(path, method, self.view):
            action = 'list'
        elif method_name not in self.method_mapping:
            action = self._to_camel_case(method_name)
        else:
            action = self.method_mapping[method.lower()]

        name = self.get_operation_id_base(path, method, action)

        return action + name

    def get_path_parameters(self, path, method):
        """
        Return a list of parameters from templated path variables.
        """
        assert uritemplate, '`uritemplate` must be installed for OpenAPI schema support.'

        model = getattr(getattr(self.view, 'queryset', None), 'model', None)
        parameters = []

        for variable in uritemplate.variables(path):
            description = ''
            if model is not None:  # TODO: test this.
                # Attempt to infer a field description if possible.
                try:
                    model_field = model._meta.get_field(variable)
                except Exception:
                    model_field = None

                if model_field is not None and model_field.help_text:
                    description = force_str(model_field.help_text)
                elif model_field is not None and model_field.primary_key:
                    description = get_pk_description(model, model_field)

            parameter = {
                "name": variable,
                "in": "path",
                "required": True,
                "description": description,
                'schema': {
                    'type': 'string',  # TODO: integer, pattern, ...
                },
            }
            parameters.append(parameter)

        return parameters

    def get_filter_parameters(self, path, method):
        if not self.allows_filters(path, method):
            return []
        parameters = []
        for filter_backend in self.view.filter_backends:
            parameters += filter_backend().get_schema_operation_parameters(self.view)
        return parameters

    def allows_filters(self, path, method):
        """
        Determine whether to include filter Fields in schema.

        Default implementation looks for ModelViewSet or GenericAPIView
        actions/methods that cause filtering on the default implementation.
        """
        if getattr(self.view, 'filter_backends', None) is None:
            return False
        if hasattr(self.view, 'action'):
            return self.view.action in ["list", "retrieve", "update", "partial_update", "destroy"]
        return method.lower() in ["get", "put", "patch", "delete"]

    def get_pagination_parameters(self, path, method):
        view = self.view

        if not is_list_view(path, method, view):
            return []

        paginator = self.get_paginator()
        if not paginator:
            return []

        return paginator.get_schema_operation_parameters(view)

    def map_choicefield(self, field):
        choices = list(dict.fromkeys(field.choices))  # preserve order and remove duplicates
        if all(isinstance(choice, bool) for choice in choices):
            type = 'boolean'
        elif all(isinstance(choice, int) for choice in choices):
            type = 'integer'
        elif all(isinstance(choice, (int, float, Decimal)) for choice in choices):  # `number` includes `integer`
            # Ref: https://tools.ietf.org/html/draft-wright-json-schema-validation-00#section-5.21
            type = 'number'
        elif all(isinstance(choice, str) for choice in choices):
            type = 'string'
        else:
            type = None

        mapping = {
            # The value of `enum` keyword MUST be an array and SHOULD be unique.
            # Ref: https://tools.ietf.org/html/draft-wright-json-schema-validation-00#section-5.20
            'enum': choices
        }

        # If We figured out `type` then and only then we should set it. It must be a string.
        # Ref: https://swagger.io/docs/specification/data-models/data-types/#mixed-type
        # It is optional but it can not be null.
        # Ref: https://tools.ietf.org/html/draft-wright-json-schema-validation-00#section-5.21
        if type:
            mapping['type'] = type
        return mapping

    def map_field(self, field, registry=None, depth=0):

        # Nested Serializers, `many` or not.
        if isinstance(field, serializers.ListSerializer):
            child = self._unwrap_serializer(field.child)
            if registry is not None and depth > 0:
                return {
                    'type': 'array',
                    'items': self._map_nested_serializer(child, registry, depth)
                }
            return {
                'type': 'array',
                'items': self.map_serializer(field.child, registry=registry, depth=depth)
            }
        if isinstance(field, serializers.Serializer):
            if (
                isinstance(field, serializers.PolymorphicSerializer) or
                (registry is not None and depth > 0)
            ):
                return self._map_nested_serializer(field, registry, depth)
            data = self.map_serializer(field, registry=registry, depth=depth)
            data['type'] = 'object'
            return data

        # Related fields.
        if isinstance(field, serializers.ManyRelatedField):
            return {
                'type': 'array',
                'items': self.map_field(field.child_relation, registry, depth)
            }
        if isinstance(field, serializers.PrimaryKeyRelatedField):
            if getattr(field, "pk_field", False):
                return self.map_field(field=field.pk_field, registry=registry, depth=depth)
            model = getattr(field.queryset, 'model', None)
            if model is not None:
                model_field = model._meta.pk
                if isinstance(model_field, models.AutoField):
                    return {'type': 'integer'}

        # ChoiceFields (single and multiple).
        # Q:
        # - Is 'type' required?
        # - can we determine the TYPE of a choicefield?
        if isinstance(field, serializers.MultipleChoiceField):
            return {
                'type': 'array',
                'items': self.map_choicefield(field)
            }

        if isinstance(field, serializers.ChoiceField):
            return self.map_choicefield(field)

        # ListField.
        if isinstance(field, serializers.ListField):
            mapping = {
                'type': 'array',
                'items': {},
            }
            if not isinstance(field.child, _UnvalidatedField):
                mapping['items'] = self.map_field(field.child, registry, depth)
            return mapping

        # DateField and DateTimeField type is string
        if isinstance(field, serializers.DateField):
            return {
                'type': 'string',
                'format': 'date',
            }

        if isinstance(field, serializers.DateTimeField):
            return {
                'type': 'string',
                'format': 'date-time',
            }

        # "Formats such as "email", "uuid", and so on, MAY be used even though undefined by this specification."
        # see: https://github.com/OAI/OpenAPI-Specification/blob/main/versions/3.0.2.md#data-types
        # see also: https://swagger.io/docs/specification/data-models/data-types/#string
        if isinstance(field, serializers.EmailField):
            return {
                'type': 'string',
                'format': 'email'
            }

        if isinstance(field, serializers.URLField):
            return {
                'type': 'string',
                'format': 'uri'
            }

        if isinstance(field, serializers.UUIDField):
            return {
                'type': 'string',
                'format': 'uuid'
            }

        if isinstance(field, serializers.IPAddressField):
            content = {
                'type': 'string',
            }
            if field.protocol != 'both':
                content['format'] = field.protocol
            return content

        if isinstance(field, serializers.DecimalField):
            if getattr(field, 'coerce_to_string', api_settings.COERCE_DECIMAL_TO_STRING):
                content = {
                    'type': 'string',
                    'format': 'decimal',
                }
            else:
                content = {
                    'type': 'number'
                }

            if field.decimal_places:
                content['multipleOf'] = float('.' + (field.decimal_places - 1) * '0' + '1')
            if field.max_whole_digits:
                content['maximum'] = int(field.max_whole_digits * '9') + 1
                content['minimum'] = -content['maximum']
            self._map_min_max(field, content)
            return content

        if isinstance(field, serializers.FloatField):
            content = {
                'type': 'number',
            }
            self._map_min_max(field, content)
            return content

        if isinstance(field, serializers.IntegerField):
            content = {
                'type': 'integer'
            }
            self._map_min_max(field, content)
            # Use int64 format when the value range exceeds signed int32 bounds.
            maximum = content.get('maximum')
            minimum = content.get('minimum')
            if (
                (maximum is not None and (
                    int(maximum) > 2147483647 or int(maximum) < -2147483648
                )) or
                (minimum is not None and (
                    int(minimum) > 2147483647 or int(minimum) < -2147483648
                ))
            ):
                content['format'] = 'int64'
            return content

        if isinstance(field, serializers.FileField):
            return {
                'type': 'string',
                'format': 'binary'
            }

        # Simplest cases, default to 'string' type:
        FIELD_CLASS_SCHEMA_TYPE = {
            serializers.BooleanField: 'boolean',
            serializers.JSONField: 'object',
            serializers.DictField: 'object',
            serializers.HStoreField: 'object',
        }
        return {'type': FIELD_CLASS_SCHEMA_TYPE.get(field.__class__, 'string')}

    def _map_nested_serializer(self, serializer, registry, depth):
        serializer = self._unwrap_serializer(serializer)
        if isinstance(serializer, serializers.PolymorphicSerializer):
            return self.map_polymorphic_serializer(
                serializer, registry, registry.current_direction
            )

        component_name = registry.resolve_name(
            serializer, registry.current_direction
        )
        if component_name not in registry.serializer_info:
            registry.register(serializer, direction=registry.current_direction)
        content = self.map_serializer(serializer, registry, depth + 1)
        registry.update(
            component_name, serializer, content,
            direction=registry.current_direction
        )
        return {'$ref': f'#/components/schemas/{component_name}'}

    def map_polymorphic_serializer(self, serializer, registry=None, direction=None):
        if registry is None:
            registry = ComponentRegistry()
        previous_direction = registry.current_direction
        if direction is not None:
            registry.current_direction = direction

        poly_key = (serializer.__class__, direction)
        if poly_key not in registry.polymorphic_serializers:
            self._register_polymorphic_components(serializer, direction, registry)

        registry.current_direction = previous_direction

        def reference_for_label(label):
            branch = serializer.get_serializer_for_type(label)
            component_name = registry.resolve_name(branch, direction)
            return f'#/components/schemas/{component_name}'

        return {
            'oneOf': [
                {'$ref': reference_for_label(label)}
                for label in serializer.get_serializer_types()
            ],
            'discriminator': {
                'propertyName': serializer.serializer_type_field_name,
                'mapping': {
                    label: reference_for_label(label)
                    for label in serializer.get_serializer_types()
                }
            }
        }

    def _map_min_max(self, field, content):
        if field.max_value is not None:
            content['maximum'] = field.max_value
        if field.min_value is not None:
            content['minimum'] = field.min_value

    def map_serializer(self, serializer, registry=None, depth=0):
        # Assuming we have a valid serializer instance.
        required = []
        properties = {}

        for field in serializer.fields.values():
            if isinstance(field, serializers.HiddenField):
                continue

            if field.required and not serializer.partial:
                required.append(self.get_field_name(field))

            schema = self.map_field(field, registry, depth)
            if field.read_only:
                schema['readOnly'] = True
            if field.write_only:
                schema['writeOnly'] = True
            if field.allow_null:
                schema['nullable'] = True
            if field.default is not None and field.default != empty and not callable(field.default):
                schema['default'] = field.default
            if field.help_text:
                schema['description'] = str(field.help_text)
            self.map_field_validators(field, schema)

            properties[self.get_field_name(field)] = schema

        result = {
            'type': 'object',
            'properties': properties
        }
        if required:
            result['required'] = required

        return result

    def map_field_validators(self, field, schema):
        """
        map field validators
        """
        for v in field.validators:
            # "Formats such as "email", "uuid", and so on, MAY be used even though undefined by this specification."
            # https://github.com/OAI/OpenAPI-Specification/blob/main/versions/3.0.2.md#data-types
            if isinstance(v, EmailValidator):
                schema['format'] = 'email'
            if isinstance(v, URLValidator):
                schema['format'] = 'uri'
            if isinstance(v, RegexValidator):
                # In Python, the token \Z does what \z does in other engines.
                # https://stackoverflow.com/questions/53283160
                schema['pattern'] = v.regex.pattern.replace('\\Z', '\\z')
            elif isinstance(v, MaxLengthValidator):
                attr_name = 'maxLength'
                if isinstance(field, serializers.ListField):
                    attr_name = 'maxItems'
                schema[attr_name] = v.limit_value
            elif isinstance(v, MinLengthValidator):
                attr_name = 'minLength'
                if isinstance(field, serializers.ListField):
                    attr_name = 'minItems'
                schema[attr_name] = v.limit_value
            elif isinstance(v, MaxValueValidator):
                schema['maximum'] = v.limit_value
            elif isinstance(v, MinValueValidator):
                schema['minimum'] = v.limit_value
            elif isinstance(v, DecimalValidator) and \
                    not getattr(field, 'coerce_to_string', api_settings.COERCE_DECIMAL_TO_STRING):
                if v.decimal_places:
                    schema['multipleOf'] = float('.' + (v.decimal_places - 1) * '0' + '1')
                if v.max_digits:
                    digits = v.max_digits
                    if v.decimal_places is not None and v.decimal_places > 0:
                        digits -= v.decimal_places
                    schema['maximum'] = int(digits * '9') + 1
                    schema['minimum'] = -schema['maximum']

    def get_field_name(self, field):
        """
        Override this method if you want to change schema field name.
        For example, convert snake_case field name to camelCase.
        """
        return field.field_name

    def get_paginator(self):
        pagination_class = getattr(self.view, 'pagination_class', None)
        if pagination_class:
            return pagination_class()
        return None

    def map_parsers(self, path, method):
        return list(map(attrgetter('media_type'), self.view.parser_classes))

    def map_renderers(self, path, method):
        media_types = []
        for renderer in self.view.renderer_classes:
            # BrowsableAPIRenderer not relevant to OpenAPI spec
            if issubclass(renderer, renderers.BrowsableAPIRenderer):
                continue
            media_types.append(renderer.media_type)
        return media_types

    def get_serializer(self, path, method):
        view = self.view

        if not hasattr(view, 'get_serializer'):
            return None

        try:
            return view.get_serializer()
        except exceptions.APIException:
            warnings.warn('{}.get_serializer() raised an exception during '
                          'schema generation. Serializer fields will not be '
                          'generated for {} {}.'
                          .format(view.__class__.__name__, method, path))
            return None

    def get_request_serializer(self, path, method):
        """
        Override this method if your view uses a different serializer for
        handling request body.
        """
        return self.get_serializer(path, method)

    def get_response_serializer(self, path, method):
        """
        Override this method if your view uses a different serializer for
        populating response data.
        """
        return self.get_serializer(path, method)

    def get_reference(self, serializer):
        return {'$ref': f'#/components/schemas/{self.get_component_name(serializer)}'}

    def get_serializer_schema(self, serializer, registry):
        if isinstance(serializer, serializers.ListSerializer):
            child = self._unwrap_serializer(serializer.child)
            if isinstance(child, serializers.PolymorphicSerializer):
                direction = registry.current_direction
                return {
                    'type': 'array',
                    'items': self.map_polymorphic_serializer(child, registry, direction)
                }
        serializer = self._unwrap_serializer(serializer)
        if isinstance(serializer, serializers.PolymorphicSerializer):
            direction = registry.current_direction
            return self.map_polymorphic_serializer(serializer, registry, direction)
        return self.get_reference(serializer)

    def get_request_body(self, path, method, registry=None):
        if method not in ('PUT', 'PATCH', 'POST'):
            return {}
        if registry is None:
            registry = ComponentRegistry()

        self.request_media_types = self.map_parsers(path, method)
        if registry is not None:
            registry.current_direction = 'request'

        serializer = self.get_request_serializer(path, method)

        if not isinstance(serializer, serializers.Serializer):
            item_schema = {}
        else:
            item_schema = self.get_serializer_schema(serializer, registry)

        return {
            'content': {
                ct: {'schema': item_schema}
                for ct in self.request_media_types
            }
        }

    def get_responses(self, path, method, registry=None):
        if method == 'DELETE':
            return {
                '204': {
                    'description': ''
                }
            }
        if registry is None:
            registry = ComponentRegistry()

        self.response_media_types = self.map_renderers(path, method)
        if registry is not None:
            registry.current_direction = 'response'

        serializer = self.get_response_serializer(path, method)

        if not isinstance(serializer, serializers.Serializer):
            item_schema = {}
        else:
            item_schema = self.get_serializer_schema(serializer, registry)

        if is_list_view(path, method, self.view):
            response_schema = {
                'type': 'array',
                'items': item_schema,
            }
            paginator = self.get_paginator()
            if paginator:
                response_schema = paginator.get_paginated_response_schema(response_schema)
        else:
            response_schema = item_schema
        status_code = '201' if method == 'POST' else '200'
        return {
            status_code: {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                # description is a mandatory property,
                # https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.2.md#responseObject
                # TODO: put something meaningful into it
                'description': ""
            }
        }

    def get_tags(self, path, method):
        # If user have specified tags, use them.
        if self._tags:
            return self._tags

        # First element of a specific path could be valid tag. This is a fallback solution.
        # PUT, PATCH, GET(Retrieve), DELETE:        /user_profile/{id}/       tags = [user-profile]
        # POST, GET(List):                          /user_profile/            tags = [user-profile]
        if path.startswith('/'):
            path = path[1:]

        return [path.split('/')[0].replace('_', '-')]
