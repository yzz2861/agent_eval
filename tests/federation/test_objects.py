import pytest
from graphql import graphql, graphql_sync

from ariadne.contrib.federation import (
    FederatedObjectType,
    make_federated_schema,
)


@pytest.fixture
def schema():
    return make_federated_schema(
        """
        type Query {
            hello: String
        }

        scalar Date

        type Product @key(fields: "upc") {
            upc: Int
            name: String
        }
    """
    )


def test_bind_federated_object_type_to_undefined_type_raises_error(schema):
    obj = FederatedObjectType("Test")
    with pytest.raises(ValueError):
        obj.bind_to_schema(schema)


def test_bind_federated_object_type_to_invalid_type_raises_error(schema):
    obj = FederatedObjectType("Date")
    with pytest.raises(ValueError):
        obj.bind_to_schema(schema)


def test_reference_resolver_can_be_set_using_decorator(schema):
    obj = FederatedObjectType("Product")
    obj.reference_resolver()(lambda *_: {"name": "Malbec"})
    obj.bind_to_schema(schema)

    result = graphql_sync(
        schema,
        """
            query GetEntities($representations: [_Any!]!) {
                _entities(representations: $representations) {
                    ... on Product {
                        name
                    }
                }
            }
        """,
        variable_values={"representations": [{"__typename": "Product", "upc": 1}]},
    )

    assert result.errors is None
    assert result.data["_entities"] == [{"name": "Malbec"}]


@pytest.fixture
def batch_schema():
    return """
        type Query {
            hello: String
        }

        type Organization {
            id: Int
        }

        type Product @key(fields: "upc") {
            upc: Int
            name: String
        }

        type User @key(fields: "id organization { id }") {
            id: Int
            organization: Organization
            firstName: String
        }
    """


def entities_query(*, product: bool = True, user: bool = False):
    selections = ""
    if product:
        selections += "... on Product { upc name } "
    if user:
        selections += "... on User { id firstName } "
    return f"""
        query GetEntities($representations: [_Any!]!) {{
            _entities(representations: $representations) {{
                {selections}
            }}
        }}
        """


def test_batch_reference_resolver_can_be_set_using_decorator(batch_schema):
    product = FederatedObjectType("Product")

    @product.batch_reference_resolver
    def resolve_products(_, _info, references):
        return [
            {"upc": ref["upc"], "name": f"Product {ref['upc']}"} for ref in references
        ]

    schema = make_federated_schema(batch_schema, product)

    result = graphql_sync(
        schema,
        entities_query(),
        variable_values={
            "representations": [
                {"__typename": "Product", "upc": 2},
                {"__typename": "Product", "upc": 1},
            ]
        },
    )

    assert result.errors is None
    assert result.data["_entities"] == [
        {"upc": 2, "name": "Product 2"},
        {"upc": 1, "name": "Product 1"},
    ]


def test_batch_reference_resolver_can_be_set_using_setter(batch_schema):
    product = FederatedObjectType("Product")
    product.batch_reference_resolver(
        lambda _, _info, references: [{"name": "Malbec"} for _ in references]
    )
    schema = make_federated_schema(batch_schema, product)

    result = graphql_sync(
        schema,
        entities_query(),
        variable_values={"representations": [{"__typename": "Product", "upc": 1}]},
    )

    assert result.errors is None
    assert result.data["_entities"] == [{"upc": None, "name": "Malbec"}]


def test_batch_reference_resolver_groups_representations_by_type(batch_schema):
    product = FederatedObjectType("Product")
    user = FederatedObjectType("User")
    received_references = []

    @product.batch_reference_resolver
    def resolve_products(_, _info, references):
        received_references.extend(references)
        return [
            {"upc": ref["upc"], "name": f"Product {ref['upc']}"} for ref in references
        ]

    @user.reference_resolver
    def resolve_user(_, _info, reference):
        return {"id": reference["id"], "firstName": "James"}

    schema = make_federated_schema(batch_schema, product, user)

    result = graphql_sync(
        schema,
        entities_query(user=True),
        variable_values={
            "representations": [
                {"__typename": "Product", "upc": 1},
                {"__typename": "User", "id": 1, "organization": {"id": 1}},
                {"__typename": "Product", "upc": 2},
            ]
        },
    )

    assert result.errors is None
    assert received_references == [
        {"__typename": "Product", "upc": 1},
        {"__typename": "Product", "upc": 2},
    ]
    assert result.data["_entities"] == [
        {"upc": 1, "name": "Product 1"},
        {"id": 1, "firstName": "James"},
        {"upc": 2, "name": "Product 2"},
    ]


def test_batch_reference_resolver_passes_duplicate_references_by_default(batch_schema):
    product = FederatedObjectType("Product")
    received_references = []

    @product.batch_reference_resolver
    def resolve_products(_, _info, references):
        received_references.extend(references)
        return [{"upc": ref["upc"]} for ref in references]

    schema = make_federated_schema(batch_schema, product)

    result = graphql_sync(
        schema,
        entities_query(),
        variable_values={
            "representations": [
                {"__typename": "Product", "upc": 1},
                {"__typename": "Product", "upc": 1},
            ]
        },
    )

    assert result.errors is None
    assert received_references == [
        {"__typename": "Product", "upc": 1},
        {"__typename": "Product", "upc": 1},
    ]
    assert result.data["_entities"] == [
        {"upc": 1, "name": None},
        {"upc": 1, "name": None},
    ]


def test_batch_reference_resolver_deduplicates_references_with_option(batch_schema):
    product = FederatedObjectType("Product")
    received_references = []

    @product.batch_reference_resolver(deduplicate=True)
    def resolve_products(_, _info, references):
        received_references.extend(references)
        return [
            {"upc": ref["upc"], "name": f"Product {ref['upc']}"} for ref in references
        ]

    schema = make_federated_schema(batch_schema, product)

    result = graphql_sync(
        schema,
        entities_query(),
        variable_values={
            "representations": [
                {"__typename": "Product", "upc": 1},
                {"__typename": "Product", "upc": 2},
                {"__typename": "Product", "upc": 1},
            ]
        },
    )

    assert result.errors is None
    assert received_references == [
        {"__typename": "Product", "upc": 1},
        {"__typename": "Product", "upc": 2},
    ]
    assert result.data["_entities"] == [
        {"upc": 1, "name": "Product 1"},
        {"upc": 2, "name": "Product 2"},
        {"upc": 1, "name": "Product 1"},
    ]


@pytest.mark.asyncio
async def test_batch_reference_resolver_supports_async_functions(batch_schema):
    product = FederatedObjectType("Product")

    @product.batch_reference_resolver
    async def resolve_products(_, _info, references):
        return [{"upc": ref["upc"], "name": "Malbec"} for ref in references]

    schema = make_federated_schema(batch_schema, product)

    result = await graphql(
        schema,
        entities_query(),
        variable_values={
            "representations": [
                {"__typename": "Product", "upc": 1},
                {"__typename": "Product", "upc": 2},
            ]
        },
    )

    assert result.errors is None
    assert result.data["_entities"] == [
        {"upc": 1, "name": "Malbec"},
        {"upc": 2, "name": "Malbec"},
    ]


def test_batch_reference_resolver_item_error_affects_only_its_position(batch_schema):
    product = FederatedObjectType("Product")

    @product.batch_reference_resolver
    def resolve_products(_, _info, references):
        return [
            {"upc": references[0]["upc"], "name": "Malbec"},
            ValueError("Product not found"),
        ]

    schema = make_federated_schema(batch_schema, product)

    result = graphql_sync(
        schema,
        entities_query(),
        variable_values={
            "representations": [
                {"__typename": "Product", "upc": 1},
                {"__typename": "Product", "upc": 2},
            ]
        },
    )

    assert result.data["_entities"] == [{"upc": 1, "name": "Malbec"}, None]
    assert len(result.errors) == 1
    assert result.errors[0].message == "Product not found"
    assert result.errors[0].path == ["_entities", 1]


def test_batch_reference_resolver_missing_item_returns_null_at_position(batch_schema):
    product = FederatedObjectType("Product")

    @product.batch_reference_resolver
    def resolve_products(_, _info, references):
        return [
            None,
            {"upc": references[1]["upc"], "name": "Malbec"},
        ]

    schema = make_federated_schema(batch_schema, product)

    result = graphql_sync(
        schema,
        entities_query(),
        variable_values={
            "representations": [
                {"__typename": "Product", "upc": 1},
                {"__typename": "Product", "upc": 2},
            ]
        },
    )

    assert result.errors is None
    assert result.data["_entities"] == [None, {"upc": 2, "name": "Malbec"}]


def test_batch_reference_resolver_with_wrong_results_count_raises_error(batch_schema):
    product = FederatedObjectType("Product")

    @product.batch_reference_resolver
    def resolve_products(_, _info, references):
        return [{"upc": references[0]["upc"], "name": "Malbec"}]

    schema = make_federated_schema(batch_schema, product)

    result = graphql_sync(
        schema,
        entities_query(),
        variable_values={
            "representations": [
                {"__typename": "Product", "upc": 1},
                {"__typename": "Product", "upc": 2},
            ]
        },
    )

    assert result.data is None
    assert len(result.errors) == 1
    assert result.errors[0].message == (
        'Batch reference resolver for type "Product" returned'
        " 1 results for 2 representations."
    )


def test_batch_reference_resolver_with_non_list_result_raises_error(batch_schema):
    product = FederatedObjectType("Product")

    @product.batch_reference_resolver
    def resolve_products(_, _info, references):
        return {"upc": references[0]["upc"]}

    schema = make_federated_schema(batch_schema, product)

    result = graphql_sync(
        schema,
        entities_query(),
        variable_values={"representations": [{"__typename": "Product", "upc": 1}]},
    )

    assert result.data is None
    assert len(result.errors) == 1
    assert result.errors[0].message == (
        'Batch reference resolver for type "Product" should return'
        " a list of 1 results, got dict instead."
    )


def test_batch_reference_resolver_receives_composite_key_representation(batch_schema):
    user = FederatedObjectType("User")
    received_references = []

    @user.batch_reference_resolver
    def resolve_users(_, _info, references):
        received_references.extend(references)
        return [
            {"id": ref["id"], "firstName": f"User {ref['organization']['id']}"}
            for ref in references
        ]

    schema = make_federated_schema(batch_schema, user)

    result = graphql_sync(
        schema,
        entities_query(product=False, user=True),
        variable_values={
            "representations": [
                {"__typename": "User", "id": 1, "organization": {"id": 7}},
            ]
        },
    )

    assert result.errors is None
    assert received_references == [
        {"__typename": "User", "id": 1, "organization": {"id": 7}}
    ]
    assert result.data["_entities"] == [{"id": 1, "firstName": "User 7"}]


def test_reference_resolver_can_be_set_using_setter(schema):
    obj = FederatedObjectType("Product")
    obj.reference_resolver(lambda *_: {"name": "Malbec"})
    obj.bind_to_schema(schema)

    result = graphql_sync(
        schema,
        """
            query GetEntities($representations: [_Any!]!) {
                _entities(representations: $representations) {
                    ... on Product {
                        name
                    }
                }
            }
        """,
        variable_values={"representations": [{"__typename": "Product", "upc": 1}]},
    )

    assert result.errors is None
    assert result.data["_entities"] == [{"name": "Malbec"}]
