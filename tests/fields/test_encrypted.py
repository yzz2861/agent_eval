from __future__ import annotations

import pytest

from tests.fields.encrypted_support import (
    PROVIDER_ID,
    EncryptedDefaultModel,
    EncryptedModel,
    RotatingXORProvider,
)
from tortoise.exceptions import ConfigurationError, FieldError
from tortoise.fields import (
    get_encryption_provider,
    pack_envelope,
    parse_envelope,
    register_encryption_provider,
    unregister_encryption_provider,
)


async def raw_column(model, column="secret"):
    db = model._meta.db
    _count, rows = await db.execute_query(
        f'SELECT "{column}" FROM "{model._meta.db_table}" ORDER BY "{model._meta.db_pk_column}"'
    )
    return [row[column] for row in rows]


@pytest.fixture
def provider():
    provider = RotatingXORProvider()
    provider.add_key("k1", "first-secret", current=True)
    register_encryption_provider(provider)
    try:
        yield provider
    finally:
        unregister_encryption_provider(PROVIDER_ID)


@pytest.mark.asyncio
async def test_save_encrypts_and_read_decrypts(db_encrypted_fields, provider):
    obj = await EncryptedModel.create(secret="hello world")

    raw = await raw_column(EncryptedModel)
    # The column stores an envelope, never the plaintext.
    assert raw and raw[0] != "hello world"
    envelope = parse_envelope(raw[0])
    assert envelope is not None
    assert envelope.version == 1
    assert envelope.key_id == "k1"

    fetched = await EncryptedModel.get(id=obj.id)
    assert fetched.secret == "hello world"


@pytest.mark.asyncio
async def test_randomized_ciphertext_differs_per_write(db_encrypted_fields, provider):
    first = await EncryptedModel.create(secret="same")
    second = await EncryptedModel.create(secret="same")
    raws = await raw_column(EncryptedModel)
    assert raws[0] != raws[1]
    assert await EncryptedModel.get(id=first.id) is not None
    assert (await EncryptedModel.get(id=second.id)).secret == "same"


@pytest.mark.asyncio
async def test_instance_save_and_filtered_update(db_encrypted_fields, provider):
    obj = EncryptedModel(secret="before")
    await obj.save()
    provider.rotate("k2", "second-secret")
    await EncryptedModel.filter(id=obj.id).update(secret="after")

    raw_now = (await raw_column(EncryptedModel))[0]
    assert parse_envelope(raw_now).key_id == "k2"
    assert (await EncryptedModel.get(id=obj.id)).secret == "after"
    assert (await EncryptedModel.get(id=obj.id)).secret == "after"


@pytest.mark.asyncio
async def test_bulk_create_encrypts_each_row(db_encrypted_fields, provider):
    await EncryptedModel.bulk_create(
        [EncryptedModel(secret="one"), EncryptedModel(secret="two"), EncryptedModel()]
    )
    rows = await EncryptedModel.all().order_by("id").values_list("id", "secret")
    assert [secret for _id, secret in rows] == ["one", "two", None]
    raws = await raw_column(EncryptedModel)
    assert all(
        parse_envelope(value) is None or parse_envelope(value).key_id == "k1" for value in raws
    )


@pytest.mark.asyncio
async def test_bulk_update_uses_current_key(db_encrypted_fields, provider):
    a = await EncryptedModel.create(secret="a")
    b = await EncryptedModel.create(secret="b")
    provider.rotate("k2", "second-secret")
    a.secret = "a2"
    b.secret = "b2"
    await EncryptedModel.bulk_update([a, b], fields=["secret"])

    for row in await raw_column(EncryptedModel):
        assert parse_envelope(row).key_id == "k2"
    assert [row.secret for row in await EncryptedModel.all().order_by("id")] == ["a2", "b2"]


@pytest.mark.asyncio
async def test_key_rotation_old_rows_decrypt_new_rows_use_current_key(
    db_encrypted_fields, provider
):
    old = await EncryptedModel.create(secret="old secret")
    provider.rotate("k2", "second-secret")
    new = await EncryptedModel.create(secret="new secret")

    all_raw = await raw_column(EncryptedModel)
    old_raw, new_raw = all_raw[0], all_raw[1]
    assert parse_envelope(old_raw).key_id == "k1"
    assert parse_envelope(new_raw).key_id == "k2"

    # Both rows decrypt through the single field protocol using their embedded key ids.
    decrypted = {row.id: row.secret for row in await EncryptedModel.all().order_by("id")}
    assert decrypted[old.id] == "old secret"
    assert decrypted[new.id] == "new secret"
    assert any(key_id == "k1" for _cipher, key_id in provider.decrypt_calls)
    assert any(key_id == "k2" for _cipher, key_id in provider.decrypt_calls)


@pytest.mark.asyncio
async def test_raw_database_value_is_not_double_encrypted(db_encrypted_fields, provider):
    obj = await EncryptedModel.create(secret="secret")
    envelope_text = (await raw_column(EncryptedModel))[0]

    # Assign the raw DB value back onto an instance (e.g. raw SQL read -> save).
    obj.secret = envelope_text
    await obj.save(update_fields=["secret"])
    stored = (await raw_column(EncryptedModel))[0]
    assert stored == envelope_text
    assert (await EncryptedModel.get(id=obj.id)).secret == "secret"


@pytest.mark.asyncio
async def test_legacy_plaintext_rows_still_read(db_encrypted_fields, provider):
    obj = await EncryptedModel.create(secret="readable")
    db = db_encrypted_fields.db()
    await db.execute_query(
        f'UPDATE "{EncryptedModel._meta.db_table}" SET "secret" = ? WHERE "id" = ?',
        ["legacy plaintext", obj.id],
    )
    assert (await EncryptedModel.get(id=obj.id)).secret == "legacy plaintext"


@pytest.mark.asyncio
async def test_content_lookups_rejected_but_null_checks_allowed(db_encrypted_fields, provider):
    await EncryptedModel.create(secret="match")
    with pytest.raises(FieldError, match="not supported"):
        await EncryptedModel.filter(secret="match")
    with pytest.raises(FieldError, match="not supported"):
        await EncryptedModel.filter(secret__in=["match", "nope"])
    with pytest.raises(FieldError, match="not supported"):
        await EncryptedModel.filter(secret__not="nope")
    assert await EncryptedModel.filter(secret__isnull=True).count() == 0
    assert await EncryptedModel.filter(secret__isnull=False).count() == 1


@pytest.mark.parametrize(
    "lookup",
    [
        "secret__contains",
        "secret__startswith",
        "secret__endswith",
        "secret__icontains",
        "secret__istartswith",
        "secret__iendswith",
        "secret__iexact",
        "secret__in",
        "secret__not_in",
        "secret__not",
        "secret__gt",
        "secret__gte",
        "secret__lt",
        "secret__lte",
        "secret__range",
        "secret__search",
    ],
)
@pytest.mark.asyncio
async def test_unsupported_lookups_rejected(db_encrypted_fields, provider, lookup):
    value = ["a", "z"] if lookup == "secret__range" else "a"
    with pytest.raises(FieldError, match="not supported"):
        await EncryptedModel.filter(**{lookup: value})


@pytest.mark.asyncio
async def test_order_by_rejected(db_encrypted_fields, provider):
    with pytest.raises(FieldError, match="Ordering"):
        await EncryptedModel.all().order_by("secret")
    with pytest.raises(FieldError, match="Ordering"):
        await EncryptedModel.all().order_by("-secret")


@pytest.mark.asyncio
async def test_values_paths_decrypt(db_encrypted_fields, provider):
    obj = await EncryptedModel.create(secret="via values")
    values = await EncryptedModel.filter(id=obj.id).values("secret")
    assert values == [{"secret": "via values"}]
    flat = await EncryptedModel.all().values_list("secret", flat=True)
    assert flat == ["via values"]


@pytest.mark.asyncio
async def test_only_partial_model_path_decrypts(db_encrypted_fields, provider):
    obj = await EncryptedModel.create(secret="partial")
    fetched = await EncryptedModel.filter(id=obj.id).only("id", "secret").first()
    assert fetched.secret == "partial"


def test_deconstruct_records_only_provider_id(provider):
    field = EncryptedModel._meta.fields_map["secret"]
    path, args, kwargs = field.deconstruct()
    assert path.endswith("EncryptedTextField")
    assert args == []
    assert kwargs["provider"] == PROVIDER_ID
    serialized = repr(kwargs)
    assert "first-secret" not in serialized
    assert "RotatingXORProvider" not in serialized


def test_unregistered_provider_rejected_at_write(db_encrypted_fields):
    unregister_encryption_provider(PROVIDER_ID)
    try:
        field = EncryptedDefaultModel._meta.fields_map["secret"]
        with pytest.raises(ConfigurationError, match="not registered"):
            field.to_db_value("x", None)
    finally:
        provider = RotatingXORProvider()
        provider.add_key("k1", "first-secret")
        register_encryption_provider(provider)


def test_pack_parse_roundtrip_and_version():
    packed = pack_envelope("CIPHER", "key-9")
    assert packed.startswith("enc::v1::")
    envelope = parse_envelope(packed)
    assert envelope.key_id == "key-9"
    assert envelope.ciphertext == "CIPHER"
    assert parse_envelope("plain value") is None
    assert parse_envelope(None) is None


def test_get_unknown_provider_raises():
    with pytest.raises(ConfigurationError):
        get_encryption_provider("does-not-exist")


def test_register_invalid_provider_raises():
    class Broken:
        provider_id = "broken"

    with pytest.raises(ConfigurationError):
        register_encryption_provider(Broken())

    class Broken2:
        provider_id = ""
        current_key_id = "k"

        def encrypt(self, plaintext, *, key_id=None):
            return ""

        def decrypt(self, ciphertext, *, key_id):
            return ""

    with pytest.raises(ConfigurationError):
        register_encryption_provider(Broken2())
