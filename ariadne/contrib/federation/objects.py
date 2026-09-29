from typing import cast

from graphql import GraphQLNamedType
from graphql.type import GraphQLSchema

from ...objects import ObjectType
from ...types import Resolver
from ...utils import type_set_extension


class FederatedObjectType(ObjectType):
    """Add `__referenceResolver` to objects as per apollo-federation."""

    _reference_resolver: Resolver | None = None
    _batch_reference_resolver: Resolver | None = None
    _batch_reference_resolver_deduplicate: bool = False

    def reference_resolver(self, arg: Resolver | None = None) -> Resolver:
        def register_reference_resolver(f: Resolver) -> Resolver:
            self._reference_resolver = f
            return f

        if callable(arg):
            return register_reference_resolver(arg)
        return register_reference_resolver

    def batch_reference_resolver(
        self,
        arg: Resolver | None = None,
        *,
        deduplicate: bool = False,
    ) -> Resolver:
        def register_batch_reference_resolver(f: Resolver) -> Resolver:
            self._batch_reference_resolver = f
            self._batch_reference_resolver_deduplicate = deduplicate
            return f

        if callable(arg):
            return register_batch_reference_resolver(arg)
        return register_batch_reference_resolver

    def bind_to_schema(self, schema: GraphQLSchema) -> None:
        super().bind_to_schema(schema)

        graphql_type = schema.type_map.get(self.name)
        graphql_type = cast(GraphQLNamedType, graphql_type)

        if callable(self._reference_resolver):
            type_set_extension(
                graphql_type,
                "__resolve_reference__",
                self._reference_resolver,
            )

        if callable(self._batch_reference_resolver):
            type_set_extension(
                graphql_type,
                "__resolve_references__",
                self._batch_reference_resolver,
            )
            type_set_extension(
                graphql_type,
                "__resolve_references_deduplicate__",
                self._batch_reference_resolver_deduplicate,
            )
