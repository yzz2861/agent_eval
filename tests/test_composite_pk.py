from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

from tortoise import fields
from tortoise.context import tortoise_test_context
from tortoise.exceptions import ConfigurationError, FieldError, IntegrityError
from tortoise.models import Model
from tortoise.utils import get_schema_sql


class CompositeEvent(Model):
    tournament_id = fields.IntField()
    name = fields.CharField(max_length=100)
    description = fields.CharField(max_length=200, null=True)

    class Meta:
        pk_attrs = ("tournament_id", "name")


class CompositeDevice(Model):
    uid = fields.UUIDField()
    slot = fields.IntField()
    label = fields.CharField(max_length=20, null=True)

    class Meta:
        pk_attrs = ("uid", "slot")
        ordering = ("pk",)


class CompositeRegistration(Model):
    id = fields.IntField(primary_key=True)
    event = fields.ForeignKeyField("models.CompositeEvent", related_name="registrations")
    player = fields.CharField(max_length=50)


class SinglePk(Model):
    id = fields.IntField(primary_key=True)
    name = fields.CharField(max_length=20)


@pytest_asyncio.fixture(scope="function")
async def db():
    db_url = os.getenv("TORTOISE_TEST_DB", "sqlite://:memory:")
    async with tortoise_test_context(
        modules=["tests.test_composite_pk"],
        db_url=db_url,
        app_label="models",
        connection_label="models",
    ) as ctx:
        yield ctx


class TestDeclaration:
    def test_meta_attributes(self):
        meta = CompositeEvent._meta
        assert meta.is_composite_pk is True
        assert meta.pk_attrs == ("tournament_id", "name")
        assert meta.pk_fields == (
            meta.fields_map["tournament_id"],
            meta.fields_map["name"],
        )
        assert meta.db_pk_columns == ("tournament_id", "name")
        assert meta.pk is None
        assert meta.pk_attr == ""
        assert meta.db_pk_column == ""
        # no surrogate id column is added
        assert "id" not in meta.fields_map

    def test_single_pk_meta_attributes(self):
        meta = SinglePk._meta
        assert meta.is_composite_pk is False
        assert meta.pk_attrs == ("id",)
        assert meta.pk_fields == (meta.fields_map["id"],)
        assert meta.db_pk_columns == ("id",)
        assert meta.pk is meta.fields_map["id"]

    def test_unknown_field(self):
        with pytest.raises(ConfigurationError, match="unknown field"):

            class Bad(Model):
                a = fields.IntField()

                class Meta:
                    pk_attrs = ("a", "missing")

    def test_single_attribute(self):
        with pytest.raises(ConfigurationError, match="at least two fields"):

            class Bad(Model):
                a = fields.IntField()

                class Meta:
                    pk_attrs = ("a",)

    def test_duplicated_attributes(self):
        with pytest.raises(ConfigurationError, match="duplicated"):

            class Bad(Model):
                a = fields.IntField()

                class Meta:
                    pk_attrs = ("a", "a")

    def test_mixed_with_primary_key_field(self):
        with pytest.raises(ConfigurationError, match="primary_key=True"):

            class Bad(Model):
                a = fields.IntField(primary_key=True)
                b = fields.IntField()

                class Meta:
                    pk_attrs = ("a", "b")

    def test_generated_component(self):
        with pytest.raises(ConfigurationError, match="DB-generated"):

            class Bad(Model):
                a = fields.IntField(generated=True)
                b = fields.IntField()

                class Meta:
                    pk_attrs = ("a", "b")

    def test_null_component(self):
        with pytest.raises(ConfigurationError, match="nullable"):

            class Bad(Model):
                a = fields.IntField(null=True)
                b = fields.IntField()

                class Meta:
                    pk_attrs = ("a", "b")

    def test_pk_attr_and_pk_attrs_conflict(self):
        with pytest.raises(ConfigurationError, match="both Meta.pk_attrs and Meta.pk_attr"):

            class Bad(Model):
                a = fields.IntField()
                b = fields.IntField()

                class Meta:
                    pk_attr = "a"
                    pk_attrs = ("a", "b")

    def test_non_concrete_component(self):
        with pytest.raises(ConfigurationError, match="not a concrete database field"):

            class Bad(Model):
                a = fields.IntField()
                b = fields.IntField()
                rel = fields.ManyToManyField("models.CompositeEvent")

                class Meta:
                    pk_attrs = ("a", "rel")

    def test_inherit_pk_attrs_from_abstract_base(self):
        class Base(Model):
            a = fields.IntField()
            b = fields.IntField()

            class Meta:
                abstract = True
                pk_attrs = ("a", "b")

        class Child(Base):
            c = fields.IntField(null=True)

        assert Child._meta.is_composite_pk is True
        assert Child._meta.pk_attrs == ("a", "b")


class TestPkProperty:
    def test_pk_tuple(self):
        obj = CompositeEvent(tournament_id=1, name="A")
        assert obj.pk == (1, "A")

    def test_pk_none_when_incomplete(self):
        obj = CompositeEvent()
        assert obj.pk is None
        obj.tournament_id = 1
        assert obj.pk is None

    def test_pk_setter(self):
        obj = CompositeEvent()
        obj.pk = (2, "B")
        assert obj.tournament_id == 2
        assert obj.name == "B"
        assert obj.pk == (2, "B")
        obj.pk = [3, "C"]
        assert obj.pk == (3, "C")

    def test_pk_setter_none_clears(self):
        obj = CompositeEvent(tournament_id=1, name="A")
        obj.pk = None
        assert obj.tournament_id is None
        assert obj.name is None
        assert obj.pk is None

    def test_pk_setter_wrong_length(self):
        obj = CompositeEvent()
        with pytest.raises(ValueError, match="expects 2 values"):
            obj.pk = (1,)
        with pytest.raises(ValueError, match="expects 2 values"):
            obj.pk = (1, "a", "x")

    def test_pk_setter_empty_component(self):
        obj = CompositeEvent()
        with pytest.raises(ValueError, match="empty"):
            obj.pk = (1, None)

    def test_pk_setter_not_a_tuple(self):
        obj = CompositeEvent()
        with pytest.raises(ValueError, match="must be a tuple"):
            obj.pk = 1


class TestSchema:
    @pytest.mark.asyncio
    async def test_create_table_sql(self, db):
        conn = CompositeEvent._meta.db
        sql = get_schema_sql(conn, safe=True)
        assert 'PRIMARY KEY ("tournament_id", "name")' in sql
        # components are plain columns, no column-level PRIMARY KEY
        event_sql = [line for line in sql.splitlines() if "tournament_id" in line]
        assert event_sql[0].strip() == '"tournament_id" INT NOT NULL,'

    @pytest.mark.asyncio
    async def test_composite_fk_constraint_sql(self, db):
        conn = CompositeRegistration._meta.db
        sql = get_schema_sql(conn, safe=True)
        assert (
            'FOREIGN KEY ("event_tournament_id", "event_name")'
            ' REFERENCES "compositeevent" ("tournament_id", "name")' in sql
        )

    @pytest.mark.asyncio
    async def test_single_pk_schema_unchanged(self, db):
        conn = SinglePk._meta.db
        sql = get_schema_sql(conn, safe=True)
        assert '"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL' in sql


class TestCRUD:
    @pytest.mark.asyncio
    async def test_create_and_get(self, db):
        obj = await CompositeEvent.create(tournament_id=1, name="A", description="d")
        assert obj.pk == (1, "A")
        fetched = await CompositeEvent.get(pk=(1, "A"))
        assert fetched.pk == (1, "A")
        assert fetched.description == "d"

    @pytest.mark.asyncio
    async def test_get_by_components(self, db):
        await CompositeEvent.create(tournament_id=1, name="A")
        fetched = await CompositeEvent.get(tournament_id=1, name="A")
        assert fetched.pk == (1, "A")

    @pytest.mark.asyncio
    async def test_get_by_pk_lookup_on_model(self, db):
        await CompositeEvent.create(tournament_id=1, name="A")
        fetched = await CompositeEvent[(1, "A")]
        assert fetched.pk == (1, "A")

    @pytest.mark.asyncio
    async def test_filter_pk(self, db):
        await CompositeEvent.create(tournament_id=1, name="A")
        await CompositeEvent.create(tournament_id=1, name="B")
        await CompositeEvent.create(tournament_id=2, name="A")
        assert await CompositeEvent.filter(pk=(1, "A")).count() == 1
        result = await CompositeEvent.filter(pk__in=[(1, "A"), (2, "A")]).order_by("name")
        assert [obj.pk for obj in result] == [(1, "A"), (2, "A")]

    @pytest.mark.asyncio
    async def test_filter_pk_invalid(self, db):
        with pytest.raises(ValueError, match="expects 2 values"):
            await CompositeEvent.filter(pk=(1,))
        with pytest.raises(ValueError, match="empty"):
            await CompositeEvent.filter(pk=(1, None))
        with pytest.raises(FieldError, match="Unsupported lookup"):
            await CompositeEvent.filter(pk__gt=(1, "A"))
        with pytest.raises(FieldError, match="non-empty"):
            await CompositeEvent.filter(pk__in=[])

    @pytest.mark.asyncio
    async def test_save_insert_and_update(self, db):
        obj = CompositeEvent(tournament_id=1, name="A", description="d")
        await obj.save()
        obj.description = "d2"
        await obj.save()
        assert (await CompositeEvent.get(pk=(1, "A"))).description == "d2"
        assert await CompositeEvent.all().count() == 1

    @pytest.mark.asyncio
    async def test_save_update_fields(self, db):
        obj = await CompositeEvent.create(tournament_id=1, name="A", description="d")
        obj.description = "changed"
        await obj.save(update_fields=["description"])
        assert (await CompositeEvent.get(pk=(1, "A"))).description == "changed"

    @pytest.mark.asyncio
    async def test_save_force_update(self, db):
        obj = await CompositeEvent.create(tournament_id=1, name="A", description="d")
        obj.description = "d3"
        await obj.save(force_update=True)
        assert (await CompositeEvent.get(pk=(1, "A"))).description == "d3"

    @pytest.mark.asyncio
    async def test_delete_instance(self, db):
        obj = await CompositeEvent.create(tournament_id=1, name="A")
        await obj.delete()
        assert await CompositeEvent.filter(pk=(1, "A")).count() == 0

    @pytest.mark.asyncio
    async def test_bulk_delete(self, db):
        await CompositeEvent.create(tournament_id=1, name="A")
        await CompositeEvent.create(tournament_id=1, name="B")
        await CompositeEvent.create(tournament_id=2, name="A")
        deleted = await CompositeEvent.filter(pk__in=[(1, "A"), (2, "A")]).delete()
        assert deleted == 2
        assert await CompositeEvent.all().count() == 1
        deleted = await CompositeEvent.all().delete()
        assert deleted == 1

    @pytest.mark.asyncio
    async def test_queryset_update_rejects_pk_component(self, db):
        await CompositeEvent.create(tournament_id=1, name="A")
        with pytest.raises(IntegrityError, match="PK"):
            await CompositeEvent.filter(pk=(1, "A")).update(tournament_id=2)

    @pytest.mark.asyncio
    async def test_queryset_update(self, db):
        await CompositeEvent.create(tournament_id=1, name="A", description="d")
        await CompositeEvent.filter(pk=(1, "A")).update(description="new")
        assert (await CompositeEvent.get(pk=(1, "A"))).description == "new"

    @pytest.mark.asyncio
    async def test_bulk_create(self, db):
        await CompositeEvent.bulk_create(
            [CompositeEvent(tournament_id=1, name=str(i)) for i in range(5)]
        )
        assert await CompositeEvent.all().count() == 5

    @pytest.mark.asyncio
    async def test_bulk_update(self, db):
        await CompositeEvent.bulk_create(
            [CompositeEvent(tournament_id=1, name=str(i), description="d") for i in range(3)]
        )
        objs = await CompositeEvent.all()
        for obj in objs:
            obj.description = "x"
        await CompositeEvent.bulk_update(objs, fields=["description"])
        descriptions = {obj.description for obj in await CompositeEvent.all()}
        assert descriptions == {"x"}

    @pytest.mark.asyncio
    async def test_in_bulk(self, db):
        await CompositeEvent.create(tournament_id=1, name="A")
        await CompositeEvent.create(tournament_id=2, name="B")
        result = await CompositeEvent.in_bulk([(1, "A"), (2, "B")])
        assert set(result.keys()) == {(1, "A"), (2, "B")}
        assert result[(1, "A")].pk == (1, "A")

    @pytest.mark.asyncio
    async def test_refresh_from_db(self, db):
        obj = await CompositeEvent.create(tournament_id=1, name="A", description="d")
        await CompositeEvent.filter(pk=(1, "A")).update(description="new")
        await obj.refresh_from_db()
        assert obj.description == "new"

    @pytest.mark.asyncio
    async def test_contains(self, db):
        obj = await CompositeEvent.create(tournament_id=1, name="A")
        assert await CompositeEvent.all().contains(obj)

    @pytest.mark.asyncio
    async def test_get_or_create(self, db):
        obj, created = await CompositeEvent.get_or_create(
            tournament_id=1, name="A", defaults={"description": "d"}
        )
        assert created is True
        assert obj.pk == (1, "A")
        obj2, created2 = await CompositeEvent.get_or_create(tournament_id=1, name="A")
        assert created2 is False
        assert obj2.description == "d"

    @pytest.mark.asyncio
    async def test_update_or_create(self, db):
        obj, created = await CompositeEvent.update_or_create(
            tournament_id=1, name="A", defaults={"description": "d"}
        )
        assert created is True
        obj, created = await CompositeEvent.update_or_create(
            tournament_id=1, name="A", defaults={"description": "d2"}
        )
        assert created is False
        assert obj.description == "d2"

    @pytest.mark.asyncio
    async def test_clone(self, db):
        obj = await CompositeEvent.create(tournament_id=1, name="A", description="d")
        cloned = obj.clone(pk=(2, "B"))
        await cloned.save()
        assert cloned.pk == (2, "B")
        assert (await CompositeEvent.get(pk=(2, "B"))).description == "d"

    @pytest.mark.asyncio
    async def test_clone_requires_pk(self, db):
        obj = await CompositeEvent.create(tournament_id=1, name="A")
        with pytest.raises(Exception, match="requires explicit primary key"):
            obj.clone()


class TestOrdering:
    @pytest.mark.asyncio
    async def test_order_by_pk(self, db):
        await CompositeEvent.create(tournament_id=2, name="A")
        await CompositeEvent.create(tournament_id=1, name="B")
        await CompositeEvent.create(tournament_id=1, name="A")
        assert [obj.pk for obj in await CompositeEvent.all().order_by("pk")] == [
            (1, "A"),
            (1, "B"),
            (2, "A"),
        ]
        assert [obj.pk for obj in await CompositeEvent.all().order_by("-pk")] == [
            (2, "A"),
            (1, "B"),
            (1, "A"),
        ]

    @pytest.mark.asyncio
    async def test_default_ordering_pk(self, db):
        uid1 = uuid.UUID("00000000-0000-0000-0000-000000000001")
        uid2 = uuid.UUID("00000000-0000-0000-0000-000000000002")
        await CompositeDevice.create(uid=uid2, slot=1)
        await CompositeDevice.create(uid=uid1, slot=2)
        await CompositeDevice.create(uid=uid1, slot=1)
        # Meta.ordering = ('pk',) orders by every component in order
        assert [obj.pk for obj in await CompositeDevice.all()] == [
            (uid1, 1),
            (uid1, 2),
            (uid2, 1),
        ]

    @pytest.mark.asyncio
    async def test_last(self, db):
        await CompositeEvent.create(tournament_id=1, name="A")
        await CompositeEvent.create(tournament_id=1, name="B")
        await CompositeEvent.create(tournament_id=2, name="A")
        last = await CompositeEvent.all().order_by("tournament_id", "name").last()
        assert last.pk == (2, "A")

    @pytest.mark.asyncio
    async def test_single_pk_order_by_pk(self, db):
        await SinglePk.create(name="a")
        await SinglePk.create(name="b")
        assert [obj.name for obj in await SinglePk.all().order_by("pk")] == ["a", "b"]
        assert [obj.name for obj in await SinglePk.all().order_by("-pk")] == ["b", "a"]


class TestDescribe:
    def test_composite_describe(self):
        description = CompositeEvent.describe()
        assert description["pk_field"] is None
        assert [field["name"] for field in description["pk_fields"]] == [
            "tournament_id",
            "name",
        ]
        data_field_names = [field["name"] for field in description["data_fields"]]
        assert "tournament_id" not in data_field_names
        assert "name" not in data_field_names
        assert "description" in data_field_names

    def test_single_pk_describe_unchanged(self):
        description = SinglePk.describe()
        assert description["pk_field"]["name"] == "id"
        assert "pk_fields" not in description


class TestUUIDComponent:
    @pytest.mark.asyncio
    async def test_uuid_conversion(self, db):
        uid = uuid.uuid4()
        obj = await CompositeDevice.create(uid=uid, slot=1, label="x")
        assert obj.pk == (uid, 1)
        assert isinstance(obj.pk[0], uuid.UUID)
        fetched = await CompositeDevice.get(pk=(uid, 1))
        assert fetched.uid == uid
        assert fetched.label == "x"

    @pytest.mark.asyncio
    async def test_uuid_filter(self, db):
        uid = uuid.uuid4()
        await CompositeDevice.create(uid=uid, slot=1)
        await CompositeDevice.create(uid=uid, slot=2)
        assert await CompositeDevice.filter(uid=uid, slot=1).count() == 1
        assert await CompositeDevice.filter(pk__in=[(uid, 1), (uid, 2)]).count() == 2


class TestCompositeFK:
    @pytest.mark.asyncio
    async def test_backing_fields(self, db):
        event = await CompositeEvent.create(tournament_id=1, name="A")
        registration = await CompositeRegistration.create(event=event, player="p1")
        assert registration.event_tournament_id == 1
        assert registration.event_name == "A"

    @pytest.mark.asyncio
    async def test_fk_getter(self, db):
        event = await CompositeEvent.create(tournament_id=1, name="A")
        registration = await CompositeRegistration.create(event=event, player="p1")
        fetched = await CompositeRegistration.get(id=registration.id)
        related = await fetched.event
        assert related.pk == (1, "A")

    @pytest.mark.asyncio
    async def test_fk_setter(self, db):
        event = await CompositeEvent.create(tournament_id=1, name="A")
        event2 = await CompositeEvent.create(tournament_id=2, name="B")
        registration = await CompositeRegistration.create(event=event, player="p1")
        registration.event = event2
        assert registration.event_tournament_id == 2
        assert registration.event_name == "B"
        await registration.save()
        fetched = await CompositeRegistration.get(id=registration.id)
        assert fetched.event_tournament_id == 2
        assert fetched.event_name == "B"

    @pytest.mark.asyncio
    async def test_filter_by_backward_relation(self, db):
        event = await CompositeEvent.create(tournament_id=1, name="A")
        event2 = await CompositeEvent.create(tournament_id=2, name="B")
        await CompositeRegistration.create(event=event, player="p1")
        await CompositeRegistration.create(event=event2, player="p2")
        result = await CompositeEvent.filter(registrations__player="p1")
        assert [obj.pk for obj in result] == [(1, "A")]

    @pytest.mark.asyncio
    async def test_delete_with_join_filter(self, db):
        event = await CompositeEvent.create(tournament_id=1, name="A")
        event2 = await CompositeEvent.create(tournament_id=2, name="B")
        await CompositeRegistration.create(event=event, player="p1")
        await CompositeRegistration.create(event=event2, player="p2")
        deleted = await CompositeEvent.filter(registrations__player="p1").delete()
        # sqlite reports cascaded deletes of the registrations as well
        assert deleted >= 1
        assert [obj.pk for obj in await CompositeEvent.all()] == [(2, "B")]

    @pytest.mark.asyncio
    async def test_filter_by_relation(self, db):
        event = await CompositeEvent.create(tournament_id=1, name="A")
        event2 = await CompositeEvent.create(tournament_id=2, name="B")
        await CompositeRegistration.create(event=event, player="p1")
        await CompositeRegistration.create(event=event2, player="p2")
        assert await CompositeRegistration.filter(event=event).count() == 1
        assert await CompositeRegistration.filter(event__pk=(2, "B")).count() == 1
        assert await CompositeRegistration.filter(event__pk__in=[(1, "A"), (2, "B")]).count() == 2

    @pytest.mark.asyncio
    async def test_select_related(self, db):
        event = await CompositeEvent.create(tournament_id=1, name="A", description="d")
        await CompositeRegistration.create(event=event, player="p1")
        registration = await CompositeRegistration.all().select_related("event").first()
        assert registration.event.pk == (1, "A")
        assert registration.event.description == "d"

    @pytest.mark.asyncio
    async def test_backward_relation(self, db):
        event = await CompositeEvent.create(tournament_id=1, name="A")
        event2 = await CompositeEvent.create(tournament_id=2, name="B")
        await CompositeRegistration.create(event=event, player="p1")
        await CompositeRegistration.create(event=event, player="p2")
        await CompositeRegistration.create(event=event2, player="p3")
        await event.fetch_related("registrations")
        assert len(event.registrations) == 2
        await event2.fetch_related("registrations")
        assert len(event2.registrations) == 1

    @pytest.mark.asyncio
    async def test_queryset_update_relation(self, db):
        event = await CompositeEvent.create(tournament_id=1, name="A")
        event2 = await CompositeEvent.create(tournament_id=2, name="B")
        registration = await CompositeRegistration.create(event=event, player="p1")
        await CompositeRegistration.filter(id=registration.id).update(event=event2)
        fetched = await CompositeRegistration.get(id=registration.id)
        assert fetched.event_tournament_id == 2
        assert fetched.event_name == "B"

    def test_o2o_to_composite_pk_rejected(self):
        import types

        from tortoise.apps import Apps

        class Bad(Model):
            id = fields.IntField(primary_key=True)
            event = fields.OneToOneField("models.CompositeEvent")

            class Meta:
                app = "models"

        module = types.ModuleType("fake_models")
        module.CompositeEvent = CompositeEvent
        module.Bad = Bad
        with pytest.raises(ConfigurationError, match="composite primary key"):
            Apps(None, None).init_app("models", [module])

    @pytest.mark.asyncio
    async def test_fk_describe(self, db):
        description = CompositeRegistration.describe()
        fk_description = description["fk_fields"][0]
        assert fk_description["raw_fields"] == ["event_tournament_id", "event_name"]


class TestMigrationState:
    def test_state_saves_pk_attrs(self):
        from tortoise.migrations.schema_generator.state import ModelState

        state = ModelState.make_from_model("models", CompositeEvent)
        assert state.options["pk_attrs"] == ["tournament_id", "name"]

    def test_state_round_trip(self):
        from tortoise.context import TortoiseContext
        from tortoise.migrations.operations import CreateModel
        from tortoise.migrations.schema_generator.state import State
        from tortoise.migrations.schema_generator.state_apps import StateApps

        with TortoiseContext() as ctx:
            ctx.connections._init_config(
                {
                    "default": {
                        "engine": "tortoise.backends.sqlite",
                        "credentials": {"file_path": ":memory:"},
                    }
                }
            )
            state = State(models={}, apps=StateApps(default_connections={"blog": "default"}))
            CreateModel(
                name="Event",
                fields=[
                    ("tournament_id", fields.IntField()),
                    ("name", fields.CharField(max_length=100)),
                ],
                options={"pk_attrs": ["tournament_id", "name"]},
            ).state_forward("blog", state)
            CreateModel(
                name="Registration",
                fields=[
                    ("id", fields.IntField(primary_key=True)),
                    ("event", fields.ForeignKeyField("blog.Event", related_name="registrations")),
                ],
            ).state_forward("blog", state)

            model_state = state.models[("blog", "Event")]
            assert model_state.options["pk_attrs"] == ["tournament_id", "name"]

            model = state.apps.get_model("blog.Event")
            assert model._meta.is_composite_pk is True
            assert model._meta.pk_attrs == ("tournament_id", "name")
            assert model._meta.db_pk_columns == ("tournament_id", "name")

            registration = state.apps.get_model("blog.Registration")
            event_fk = registration._meta.fields_map["event"]
            assert event_fk.source_fields == ("event_tournament_id", "event_name")

    def test_state_round_trip_from_live_model(self):
        from tortoise.context import TortoiseContext
        from tortoise.migrations.schema_generator.state import ModelState, State
        from tortoise.migrations.schema_generator.state_apps import StateApps

        # states built from live (fully initialised) models must be re-renderable
        event_state = ModelState.make_from_model("models", CompositeEvent)
        registration_state = ModelState.make_from_model("models", CompositeRegistration)
        assert "source_field" not in registration_state.fields["event"].deconstruct()[2]
        with TortoiseContext() as ctx:
            ctx.connections._init_config(
                {
                    "default": {
                        "engine": "tortoise.backends.sqlite",
                        "credentials": {"file_path": ":memory:"},
                    }
                }
            )
            state = State(
                models={
                    ("models", "CompositeEvent"): event_state,
                    ("models", "CompositeRegistration"): registration_state,
                },
                apps=StateApps(default_connections={"models": "default"}),
            )
            state.reload_models([("models", "CompositeEvent"), ("models", "CompositeRegistration")])
            model = state.apps.get_model("models.CompositeRegistration")
            event_fk = model._meta.fields_map["event"]
            assert event_fk.source_fields == ("event_tournament_id", "event_name")
            related = state.apps.get_model("models.CompositeEvent")
            assert related._meta.pk_attrs == ("tournament_id", "name")
