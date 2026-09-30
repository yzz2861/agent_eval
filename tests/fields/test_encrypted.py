import os

import pytest
import pytest_asyncio

from tests.fields.encrypted_models import OrderedSecret, SecretNote, toy_provider
from tortoise.context import tortoise_test_context
from tortoise.exceptions import ConfigurationError, FieldError
from tortoise.fields.encrypted import (
    EncryptedField,
    build_envelope,
    is_envelope,
    parse_envelope,
)


@pytest.fixture(autouse=True)
def reset_provider():
    toy_provider.keys = {"k1": b"test-key-one"}
    toy_provider.current = "k1"
    yield
    toy_provider.keys = {"k1": b"test-key-one"}
    toy_provider.current = "k1"


@pytest_asyncio.fixture(scope="function")
async def db_encrypted():
    db_url = os.getenv("TORTOISE_TEST_DB", "sqlite://:memory:")
    async with tortoise_test_context(
        modules=["tests.fields.encrypted_models"],
        db_url=db_url,
        app_label="models",
        connection_label="models",
    ) as ctx:
        yield ctx


async def raw_value(field: str, note_id: int) -> str:
    conn = SecretNote._meta.db
    rows = await conn.execute_query_dict(
        f"SELECT {field} FROM secretnote WHERE id = {int(note_id)}"  # nosec
    )
    return rows[0][field]


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------


def test_envelope_roundtrip():
    envelope = build_envelope("k1", b"ciphertext-bytes")
    assert envelope.startswith("enc:v1:k1:")
    version, key_id, ciphertext = parse_envelope(envelope)
    assert (version, key_id, ciphertext) == (1, "k1", b"ciphertext-bytes")
    assert is_envelope(envelope)


def test_envelope_carries_version_and_key_id():
    envelope = build_envelope("key-2026-09", b"xx")
    assert envelope.split(":")[:3] == ["enc", "v1", "key-2026-09"]


@pytest.mark.parametrize("value", ["", "plain text", "enc:", "enc:v1::AA", "enc:vx:k:AA", None, 42])
def test_is_envelope_rejects_non_envelopes(value):
    assert not is_envelope(value)


def test_parse_envelope_rejects_garbage():
    with pytest.raises(ValueError):
        parse_envelope("enc:v1:k1:not valid base64!!!")


def test_build_envelope_rejects_bad_key_id():
    with pytest.raises(ConfigurationError):
        build_envelope("bad:key", b"xx")
    with pytest.raises(ConfigurationError):
        build_envelope("", b"xx")


# ---------------------------------------------------------------------------
# Field construction / provider handling
# ---------------------------------------------------------------------------


def test_provider_object_without_id_rejected():
    class NoIdProvider:
        current_key_id = "k1"

        def encrypt(self, plaintext, key_id):
            return plaintext

        def decrypt(self, ciphertext, key_id):
            return ciphertext

    with pytest.raises(ConfigurationError, match="provider_id"):
        EncryptedField(provider=NoIdProvider())


def test_provider_string_resolved_lazily():
    field = EncryptedField(provider="tests.fields.encrypted_models:toy_provider")
    assert field.provider_id == "tests.fields.encrypted_models:toy_provider"
    assert field.provider is toy_provider


def test_provider_string_bad_reference():
    field = EncryptedField(provider="tests.fields.encrypted_models.does_not_exist")
    with pytest.raises(ConfigurationError, match="Cannot import encryption provider"):
        field.provider


def test_deconstruct_records_only_provider_identifier():
    field = SecretNote._meta.fields_map["secret"]
    path, args, kwargs = field.deconstruct()
    assert path == "tortoise.fields.encrypted.EncryptedField"
    assert kwargs["provider"] == "tests.fields.encrypted_models.toy_provider"
    # No key material may leak into the migration deconstruct output.
    assert b"test-key-one" not in repr(kwargs).encode()
    assert "test-key-one" not in repr(kwargs)


def test_deconstruct_with_provider_instance():
    field = SecretNote._meta.fields_map["secret_null"]
    _, _, kwargs = field.deconstruct()
    assert kwargs["provider"] == "tests.fields.encrypted_models.toy_provider"


# ---------------------------------------------------------------------------
# Write/read paths all go through the same protocol
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_and_read(db_encrypted):
    note = await SecretNote.create(title="t", secret="plain-text")
    assert note.secret == "plain-text"

    raw = await raw_value("secret", note.id)
    assert raw != "plain-text"
    assert is_envelope(raw)
    _, key_id, _ = parse_envelope(raw)
    assert key_id == "k1"

    fetched = await SecretNote.get(id=note.id)
    assert fetched.secret == "plain-text"


@pytest.mark.asyncio
async def test_instance_save_reencrypts_once(db_encrypted):
    note = await SecretNote.create(title="t", secret="value")
    note.secret = "updated"
    await note.save()
    raw = await raw_value("secret", note.id)
    assert is_envelope(raw)
    fetched = await SecretNote.get(id=note.id)
    assert fetched.secret == "updated"


@pytest.mark.asyncio
async def test_queryset_update(db_encrypted):
    note = await SecretNote.create(title="t", secret="before")
    await SecretNote.filter(id=note.id).update(secret="after")
    raw = await raw_value("secret", note.id)
    assert is_envelope(raw)
    fetched = await SecretNote.get(id=note.id)
    assert fetched.secret == "after"


@pytest.mark.asyncio
async def test_bulk_create(db_encrypted):
    notes = [SecretNote(title=f"t{i}", secret=f"secret-{i}") for i in range(3)]
    await SecretNote.bulk_create(notes)
    conn = SecretNote._meta.db
    rows = await conn.execute_query_dict("SELECT secret FROM secretnote")
    assert len(rows) == 3
    for row in rows:
        assert is_envelope(row["secret"])
    fetched = await SecretNote.all()
    assert sorted(n.secret for n in fetched) == ["secret-0", "secret-1", "secret-2"]


@pytest.mark.asyncio
async def test_values_and_values_list(db_encrypted):
    note = await SecretNote.create(title="t", secret="via-values")
    row = await SecretNote.get(id=note.id).values("secret")
    assert row["secret"] == "via-values"
    value = await SecretNote.get(id=note.id).values_list("secret", flat=True)
    assert value == "via-values"


@pytest.mark.asyncio
async def test_bulk_update(db_encrypted):
    notes = [await SecretNote.create(title=f"t{i}", secret=f"secret-{i}") for i in range(2)]
    for i, note in enumerate(notes):
        note.secret = f"updated-{i}"
    await SecretNote.bulk_update(notes, fields=["secret"])
    for i, note in enumerate(notes):
        raw = await raw_value("secret", note.id)
        assert is_envelope(raw)
        fetched = await SecretNote.get(id=note.id)
        assert fetched.secret == f"updated-{i}"


@pytest.mark.asyncio
async def test_refresh_from_db(db_encrypted):
    note = await SecretNote.create(title="t", secret="original")
    await SecretNote.filter(id=note.id).update(secret="changed")
    await note.refresh_from_db()
    assert note.secret == "changed"


@pytest.mark.asyncio
async def test_null_roundtrip(db_encrypted):
    note = await SecretNote.create(title="t", secret="s")
    assert note.secret_null is None
    raw = await raw_value("secret_null", note.id)
    assert raw is None
    note.secret_null = "now-set"
    await note.save()
    fetched = await SecretNote.get(id=note.id)
    assert fetched.secret_null == "now-set"
    assert await SecretNote.filter(secret_null__isnull=True).count() == 0
    assert await SecretNote.filter(secret_null__not_isnull=True).count() == 1


@pytest.mark.asyncio
async def test_raw_db_value_is_not_encrypted_twice(db_encrypted):
    note = await SecretNote.create(title="t", secret="sensitive")
    raw_before = await raw_value("secret", note.id)
    # Simulate a raw database value flowing back into a model instance.
    note.secret = raw_before
    await note.save()
    raw_after = await raw_value("secret", note.id)
    assert raw_after == raw_before
    fetched = await SecretNote.get(id=note.id)
    assert fetched.secret == "sensitive"


@pytest.mark.asyncio
async def test_to_db_value_idempotent_for_envelopes():
    field = SecretNote._meta.fields_map["secret"]
    envelope = field.to_db_value("hello", None)
    assert is_envelope(envelope)
    assert field.to_db_value(envelope, None) == envelope


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_key_rotation(db_encrypted):
    old_note = await SecretNote.create(title="old", secret="written-with-k1")
    toy_provider.rotate_to("k2", b"test-key-two")
    new_note = await SecretNote.create(title="new", secret="written-with-k2")

    _, old_key_id, _ = parse_envelope(await raw_value("secret", old_note.id))
    _, new_key_id, _ = parse_envelope(await raw_value("secret", new_note.id))
    assert old_key_id == "k1"
    assert new_key_id == "k2"

    # Old rows still decrypt through the key id stored in their envelope.
    assert (await SecretNote.get(id=old_note.id)).secret == "written-with-k1"
    assert (await SecretNote.get(id=new_note.id)).secret == "written-with-k2"

    # New writes always use the current key id, also on update paths.
    await SecretNote.filter(id=old_note.id).update(secret="rewritten")
    _, rewritten_key_id, _ = parse_envelope(await raw_value("secret", old_note.id))
    assert rewritten_key_id == "k2"
    assert (await SecretNote.get(id=old_note.id)).secret == "rewritten"


# ---------------------------------------------------------------------------
# Unsupported query operations are rejected at query construction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "lookup",
    [
        "gte",
        "lte",
        "gt",
        "lt",
        "range",
        "contains",
        "icontains",
        "startswith",
        "istartswith",
        "endswith",
        "iendswith",
        "iexact",
        "search",
        "posix_regex",
    ],
)
async def test_unsupported_filters_rejected(db_encrypted, lookup):
    value = ("a", "z") if lookup == "range" else "x"
    with pytest.raises(FieldError):
        await SecretNote.filter(**{f"secret__{lookup}": value})


@pytest.mark.asyncio
async def test_supported_filters_construct(db_encrypted):
    await SecretNote.create(title="t", secret="s")
    # Exact / in / isnull filters exist; they just cannot match randomized
    # ciphertext, but constructing them must not blow up.
    assert await SecretNote.filter(secret="s").count() in (0, 1)
    assert await SecretNote.filter(secret__in=["s"]).count() in (0, 1)
    assert await SecretNote.filter(secret_null__isnull=True).count() == 1


@pytest.mark.asyncio
async def test_order_by_rejected_at_construction(db_encrypted):
    with pytest.raises(FieldError, match="not orderable"):
        SecretNote.all().order_by("secret")
    with pytest.raises(FieldError, match="not orderable"):
        SecretNote.all().order_by("-secret")


@pytest.mark.asyncio
async def test_default_ordering_on_encrypted_field_rejected(db_encrypted):
    await OrderedSecret.create(secret="x")
    with pytest.raises(FieldError, match="not orderable"):
        await OrderedSecret.all()


# ---------------------------------------------------------------------------
# Corrupt / foreign data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_corrupt_envelope_raises(db_encrypted):
    note = await SecretNote.create(title="t", secret="s")
    conn = SecretNote._meta.db
    await conn.execute_query_dict(
        f"UPDATE secretnote SET secret = 'enc:v1:k1:!!!' WHERE id = {int(note.id)}"  # nosec
    )
    with pytest.raises(ValueError):
        await SecretNote.get(id=note.id)


@pytest.mark.asyncio
async def test_unknown_envelope_version_raises(db_encrypted):
    note = await SecretNote.create(title="t", secret="s")
    conn = SecretNote._meta.db
    await conn.execute_query_dict(
        f"UPDATE secretnote SET secret = 'enc:v99:k1:AAAA' WHERE id = {int(note.id)}"  # nosec
    )
    with pytest.raises(ValueError, match="Unsupported encryption envelope version"):
        await SecretNote.get(id=note.id)
