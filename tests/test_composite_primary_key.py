from __future__ import annotations

import uuid

import pytest
import pytest_asyncio

from tortoise import fields
from tortoise.context import tortoise_test_context
from tortoise.exceptions import ConfigurationError, ParamsError
from tortoise.migrations.operations import CreateModel
from tortoise.migrations.schema_generator.state import State
from tortoise.migrations.schema_generator.state_apps import StateApps
from tortoise.migrations.schema_editor.sqlite import SqliteSchemaEditor
from tortoise.migrations.writer import MigrationWriter
from tests.utils.fake_client import FakeClient
from tortoise.models import Model


class CompositeParent(Model):
    number = fields.IntField()
    code = fields.CharField(max_length=20)
    external_id = fields.UUIDField()
    name = fields.CharField(max_length=50)

    class Meta:
        table = "composite_parent"
        primary_key = ("number", "code")


class CompositeChild(Model):
    id = fields.IntField(primary_key=True)
    title = fields.CharField(max_length=50)
    parent = fields.ForeignKeyField(
        "models.CompositeParent",
        related_name="children",
    )


@pytest_asyncio.fixture
async def composite_db():
    async with tortoise_test_context(modules=[__name__]) as ctx:
        yield ctx


@pytest.mark.asyncio
async def test_composite_pk_crud_and_conversion(composite_db):
    identifier = uuid.uuid4()
    parent = await CompositeParent.create(
        number="7",
        code="alpha",
        external_id=identifier,
        name="Parent",
    )

    assert parent.pk == (7, "alpha")
    fetched = await CompositeParent.get(pk=("7", "alpha"))
    assert fetched.pk == (7, "alpha")
    assert fetched.external_id == identifier

    fetched.name = "Changed"
    await fetched.save()
    refreshed = await CompositeParent.get(pk=(7, "alpha"))
    assert refreshed.name == "Changed"

    await refreshed.delete()
    assert await CompositeParent.filter(pk=(7, "alpha")).exists() is False


@pytest.mark.asyncio
async def test_composite_pk_invalid_tuple(composite_db):
    await CompositeParent.create(number=1, code="one", external_id=uuid.uuid4(), name="A")

    with pytest.raises(ParamsError, match="must have 2"):
        await CompositeParent.get(pk=(1,))
    with pytest.raises(ParamsError, match="cannot be null"):
        await CompositeParent.get(pk=(1, None))
    with pytest.raises(ParamsError, match="cannot be empty"):
        await CompositeParent.get(pk=(1, ""))
    with pytest.raises(ParamsError, match="must be a tuple"):
        await CompositeParent.get(pk=[1, "x"])


@pytest.mark.asyncio
async def test_composite_pk_ordering_and_bulk_delete(composite_db):
    for number, code in ((2, "b"), (1, "b"), (1, "a")):
        await CompositeParent.create(
            number=number,
            code=code,
            external_id=uuid.uuid4(),
            name=code,
        )

    assert [(item.number, item.code) for item in await CompositeParent.all().order_by("pk")] == [
        (1, "a"),
        (1, "b"),
        (2, "b"),
    ]

    deleted = await CompositeParent.filter(pk__in=[(1, "a"), (2, "b")]).delete()
    assert deleted == 2
    assert await CompositeParent.all().count() == 1


@pytest.mark.asyncio
async def test_composite_pk_bulk_update(composite_db):
    first = await CompositeParent.create(
        number=1,
        code="a",
        external_id=uuid.uuid4(),
        name="First",
    )
    second = await CompositeParent.create(
        number=1,
        code="b",
        external_id=uuid.uuid4(),
        name="Second",
    )
    first.name = "Updated first"
    second.name = "Updated second"

    await CompositeParent.bulk_update([first, second], ["name"])

    assert (await CompositeParent.get(pk=(1, "a"))).name == "Updated first"
    assert (await CompositeParent.get(pk=(1, "b"))).name == "Updated second"


@pytest.mark.asyncio
async def test_composite_pk_forward_relation_and_select_related(composite_db):
    parent = await CompositeParent.create(
        number=1,
        code="x",
        external_id=uuid.uuid4(),
        name="Parent",
    )
    child = await CompositeChild.create(title="Child", parent=parent)

    assert child.parent_number == 1
    assert child.parent_code == "x"
    assert (await CompositeChild.filter(parent=parent).first()).id == child.id

    fetched_child = await CompositeChild.all().select_related("parent").get(pk=child.id)
    assert fetched_child.parent.pk == (1, "x")
    assert fetched_child.parent.name == "Parent"

    await parent.fetch_related("children")
    assert [item.id for item in parent.children] == [child.id]


def test_composite_pk_metadata():
    description = CompositeParent.describe()
    assert description["pk_field"]["field_type"] == "CompositePrimaryKey"
    assert description["pk_field"]["fields"] == ("number", "code")
    assert [field["name"] for field in description["pk_fields"]] == ["number", "code"]
    assert {field["name"] for field in description["data_fields"]} == {"external_id", "name"}


def test_composite_pk_configuration_errors():
    with pytest.raises(ConfigurationError, match="ordered tuple"):
        class BadList(Model):
            a = fields.IntField()
            b = fields.CharField(max_length=10)

            class Meta:
                primary_key = ["a", "b"]

    with pytest.raises(ConfigurationError, match="at least two fields"):
        class BadShort(Model):
            a = fields.IntField()

            class Meta:
                primary_key = ("a",)


def test_composite_pk_migration_state_round_trip():
    state = State(models={}, apps=StateApps())
    operation = CreateModel(
        name="CompositeParent",
        fields=[
            ("number", fields.IntField()),
            ("code", fields.CharField(max_length=20)),
        ],
        options={"table": "composite_parent", "primary_key": ("number", "code")},
    )

    operation.state_forward("models", state)
    rendered = state.apps.get_model("models.CompositeParent")
    assert rendered._meta.pk_attrs == ("number", "code")
    assert rendered._meta.db_pk_columns == ("number", "code")

    output = MigrationWriter("test_composite", "models", [operation]).as_string()
    assert "'primary_key': ('number', 'code')" in output


@pytest.mark.asyncio
async def test_composite_pk_migration_sqlite_ddl():
    state = State(models={}, apps=StateApps(default_connections={"models": "default"}))
    parent = CreateModel(
        name="CompositeParent",
        fields=[
            ("number", fields.IntField()),
            ("code", fields.CharField(max_length=20)),
        ],
        options={
            "table": "composite_parent",
            "app": "models",
            "primary_key": ("number", "code"),
        },
    )
    child = CreateModel(
        name="CompositeChild",
        fields=[
            ("id", fields.IntField(primary_key=True)),
            ("title", fields.CharField(max_length=50)),
            (
                "parent",
                fields.ForeignKeyField("models.CompositeParent", related_name="children"),
            ),
        ],
        options={"table": "composite_child", "app": "models"},
    )
    parent.state_forward("models", state)
    child.state_forward("models", state)

    client = FakeClient("sqlite")
    editor = SqliteSchemaEditor(client)
    await editor.create_model(state.apps.get_model("models.CompositeParent"))
    await editor.create_model(state.apps.get_model("models.CompositeChild"))
    parent_sql, child_sql = client.executed

    assert 'PRIMARY KEY ("number", "code")' in parent_sql
    assert (
        'FOREIGN KEY ("parent_number", "parent_code") '
        'REFERENCES "composite_parent" ("number", "code")'
    ) in child_sql
