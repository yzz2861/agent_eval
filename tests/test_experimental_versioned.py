import pytest

from pydantic import BaseModel, ValidationError
from pydantic.experimental.versioned import (
    AmbiguousMigrationError,
    DuplicateMigrationError,
    DuplicateVersionError,
    MigrationCycleError,
    MigrationValidationError,
    MissingVersionError,
    NoMigrationPathError,
    UnknownVersionError,
    VersionedTypeAdapter,
)


class UserV1(BaseModel):
    version: int
    name: str


class UserV2(BaseModel):
    version: int
    full_name: str
    tags: list[str] = []


class UserV3(BaseModel):
    version: int
    full_name: str
    tags: list[str] = []


def migrate_1_to_2(data):
    return {'version': 2, 'full_name': data['name']}


def migrate_2_to_3(data):
    data = dict(data)
    data['version'] = 3
    return data


def build_adapter():
    return (
        VersionedTypeAdapter(UserV3, 3)
        .register_version(1, UserV1)
        .register_version(2, UserV2)
        .register_migration(1, 2, migrate_1_to_2)
        .register_migration(2, 3, migrate_2_to_3)
    )


def test_migrates_old_payload_to_target():
    adapter = build_adapter()
    result = adapter.validate_python({'version': 1, 'name': 'ada'})
    assert isinstance(result, UserV3)
    assert result.version == 3
    assert result.full_name == 'ada'
    assert result.tags == []


def test_migrates_intermediate_payload():
    adapter = build_adapter()
    result = adapter.validate_python({'version': 2, 'full_name': 'ada', 'tags': ['a']})
    assert isinstance(result, UserV3)
    assert result.version == 3
    assert result.tags == ['a']


def test_target_version_validated_directly_without_migration():
    calls = []

    def spy_migration(data):
        calls.append(data)
        return migrate_2_to_3(data)

    adapter = VersionedTypeAdapter(UserV3, 3).register_version(2, UserV2).register_migration(2, 3, spy_migration)
    result = adapter.validate_python({'version': 3, 'full_name': 'ada'})
    assert isinstance(result, UserV3)
    assert result.full_name == 'ada'
    assert calls == []


def test_target_version_invalid_data_raises_validation_error():
    adapter = build_adapter()
    with pytest.raises(ValidationError):
        adapter.validate_python({'version': 3})


def test_unknown_version_not_guessed():
    adapter = build_adapter()
    with pytest.raises(UnknownVersionError) as exc_info:
        adapter.validate_python({'version': 4, 'full_name': 'ada'})
    assert exc_info.value.version == 4


def test_unhashable_version_is_unknown():
    adapter = build_adapter()
    with pytest.raises(UnknownVersionError):
        adapter.validate_python({'version': [1]})


def test_missing_version_field():
    adapter = build_adapter()
    with pytest.raises(MissingVersionError):
        adapter.validate_python({'name': 'ada'})
    with pytest.raises(MissingVersionError):
        adapter.validate_python('not a mapping')


def test_custom_version_field():
    class PayloadV1(BaseModel):
        name: str

    class PayloadV2(BaseModel):
        name: str
        migrated: bool = False

    adapter = (
        VersionedTypeAdapter(PayloadV2, 2, version_field='v')
        .register_version(1, PayloadV1)
        .register_migration(1, 2, lambda data: {'name': data['name'], 'migrated': True})
    )
    with pytest.raises(MissingVersionError):
        adapter.validate_python({'version': 2, 'name': 'ada'})
    result = adapter.validate_python({'v': 1, 'name': 'ada'})
    assert result.migrated is True
    direct = adapter.validate_python({'v': 2, 'name': 'ada'})
    assert direct.migrated is False


def test_duplicate_version_registration():
    adapter = VersionedTypeAdapter(UserV3, 3).register_version(1, UserV1)
    with pytest.raises(DuplicateVersionError):
        adapter.register_version(1, UserV1)
    with pytest.raises(DuplicateVersionError):
        adapter.register_version(3, UserV3)


def test_duplicate_migration_edge():
    adapter = VersionedTypeAdapter(UserV3, 3).register_version(2, UserV2)
    adapter.register_migration(2, 3, migrate_2_to_3)
    with pytest.raises(DuplicateMigrationError):
        adapter.register_migration(2, 3, migrate_2_to_3)


def test_ambiguous_migration_path():
    adapter = VersionedTypeAdapter(UserV3, 3).register_version(1, UserV1).register_version(2, UserV2)
    adapter.register_migration(1, 2, migrate_1_to_2)
    with pytest.raises(AmbiguousMigrationError):
        adapter.register_migration(1, 3, migrate_1_to_2)


def test_migration_cycle():
    adapter = (
        VersionedTypeAdapter(UserV3, 3)
        .register_version(1, UserV1)
        .register_version(2, UserV2)
        .register_migration(1, 2, migrate_1_to_2)
        .register_migration(2, 3, migrate_2_to_3)
    )
    with pytest.raises(MigrationCycleError):
        adapter.register_migration(3, 1, migrate_2_to_3)


def test_migration_self_loop():
    adapter = VersionedTypeAdapter(UserV3, 3).register_version(1, UserV1)
    with pytest.raises(MigrationCycleError):
        adapter.register_migration(1, 1, migrate_1_to_2)


def test_migration_for_unregistered_version():
    adapter = VersionedTypeAdapter(UserV3, 3).register_version(2, UserV2)
    with pytest.raises(UnknownVersionError):
        adapter.register_migration(1, 2, migrate_1_to_2)
    with pytest.raises(UnknownVersionError):
        adapter.register_migration(2, 1, migrate_2_to_3)


def test_no_migration_path():
    adapter = (
        VersionedTypeAdapter(UserV3, 3)
        .register_version(1, UserV1)
        .register_version(2, UserV2)
        .register_migration(2, 3, migrate_2_to_3)
    )
    with pytest.raises(NoMigrationPathError) as exc_info:
        adapter.validate_python({'version': 1, 'name': 'ada'})
    assert exc_info.value.from_version == 1
    assert exc_info.value.to_version == 3


def test_step_validation_error_preserves_step_and_location():
    def bad_migration(data):
        return {'version': 2}  # missing full_name

    adapter = (
        VersionedTypeAdapter(UserV3, 3)
        .register_version(1, UserV1)
        .register_version(2, UserV2)
        .register_migration(1, 2, bad_migration)
        .register_migration(2, 3, migrate_2_to_3)
    )
    with pytest.raises(MigrationValidationError) as exc_info:
        adapter.validate_python({'version': 1, 'name': 'ada'})
    err = exc_info.value
    assert err.from_version == 1
    assert err.to_version == 2
    assert isinstance(err.validation_error, ValidationError)
    assert err.errors()[0]['loc'] == ('full_name',)


def test_step_validation_error_in_second_step():
    def bad_migration(data):
        data = dict(data)
        del data['full_name']
        return data

    adapter = (
        VersionedTypeAdapter(UserV3, 3)
        .register_version(1, UserV1)
        .register_version(2, UserV2)
        .register_migration(1, 2, migrate_1_to_2)
        .register_migration(2, 3, bad_migration)
    )
    with pytest.raises(MigrationValidationError) as exc_info:
        adapter.validate_python({'version': 1, 'name': 'ada'})
    err = exc_info.value
    assert (err.from_version, err.to_version) == (2, 3)
    assert err.errors()[0]['loc'] == ('full_name',)


def test_migration_cannot_mutate_caller_input():
    def destructive(data):
        data['full_name'] = data.pop('name')
        data['version'] = 2
        return data

    adapter = (
        VersionedTypeAdapter(UserV3, 3)
        .register_version(1, UserV1)
        .register_version(2, UserV2)
        .register_migration(1, 2, destructive)
        .register_migration(2, 3, migrate_2_to_3)
    )
    payload = {'version': 1, 'name': 'ada'}
    result = adapter.validate_python(payload)
    assert result.full_name == 'ada'
    assert payload == {'version': 1, 'name': 'ada'}


def test_defaults_not_shared_across_requests():
    def append_tag(data):
        data['tags'].append('migrated')
        data['version'] = 3
        return data

    adapter = (
        VersionedTypeAdapter(UserV3, 3)
        .register_version(1, UserV1)
        .register_version(2, UserV2)
        .register_migration(1, 2, migrate_1_to_2)
        .register_migration(2, 3, append_tag)
    )
    first = adapter.validate_python({'version': 1, 'name': 'ada'})
    second = adapter.validate_python({'version': 1, 'name': 'ada'})
    assert first.tags == ['migrated']
    assert second.tags == ['migrated']
    assert first.tags is not second.tags


def test_validate_json():
    adapter = build_adapter()
    result = adapter.validate_json('{"version": 1, "name": "ada"}')
    assert isinstance(result, UserV3)
    assert result.full_name == 'ada'


def test_non_model_types():
    adapter = (
        VersionedTypeAdapter(dict, 'v2')
        .register_version('v1', dict)
        .register_migration('v1', 'v2', lambda data: {**data, 'version': 'v2'})
    )
    result = adapter.validate_python({'version': 'v1', 'x': 1})
    assert result == {'version': 'v2', 'x': 1}
