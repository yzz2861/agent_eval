"""Reviewable descriptions of a restricted compilation.

An artifact describes *what* was compiled and *with which* environment it was
compiled.  It deliberately contains digests and configuration labels only:
source text, guards, globals and other host objects never become part of an
artifact or of an approval record.

The comparison API in this module only inspects those descriptions.  It never
executes the compiled code and it never evaluates the source.
"""

from __future__ import annotations

import ast
import collections.abc
import dataclasses
import enum
import hashlib
import json
import platform
import typing


ARTIFACT_SCHEMA = 'restrictedpython.compile-artifact/1'
APPROVAL_SCHEMA = ARTIFACT_SCHEMA

_DEFAULT_POLICY = object()

T_FeatureValue: typing.TypeAlias = bool | int | float | str | None


class LanguageFeatures(tuple):
    """Normalized feature switches.

    The value behaves like a tuple of ``(name, value)`` pairs, but also
    compares equal to an equivalent mapping.  This keeps textual artifacts
    deterministic while remaining convenient for hosts.
    """

    def __new__(
        cls,
        values: collections.abc.Iterable[
            tuple[str, T_FeatureValue]] = (),
    ) -> LanguageFeatures:
        return tuple.__new__(cls, tuple(values))

    def __eq__(self, other: typing.Any) -> bool:
        if isinstance(other, collections.abc.Mapping):
            return dict(self) == dict(other)
        return tuple.__eq__(self, other) is True

    __hash__ = tuple.__hash__

    def as_dict(self) -> dict[str, T_FeatureValue]:
        return dict(self)


T_Features: typing.TypeAlias = LanguageFeatures
T_FeatureInput: typing.TypeAlias = (
    collections.abc.Mapping[str, typing.Any]
    | collections.abc.Iterable[str | tuple[str, typing.Any]]
    | str
    | None
)
CompileArtifactLike: typing.TypeAlias = typing.Any


def _plain_text(value: typing.Any, name: str) -> str:
    """Return a textual configuration value without using an object repr."""
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return str(value)
    raise TypeError(
        f'{name} must be plain text or a number, '
        f'got {type(value).__name__}'
    )


def _feature_value(value: typing.Any, name: str) -> T_FeatureValue:
    if isinstance(value, enum.Enum):
        value = value.value
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(
        f'language feature {name!r} must have a plain value, '
        f'got {type(value).__name__}'
    )


def _normalize_language_features(features: T_FeatureInput) -> T_Features:
    """Normalize feature configuration to a deterministic, primitive tuple."""
    if features is None:
        return LanguageFeatures()
    if isinstance(features, str):
        return LanguageFeatures(((features, True),))

    items: collections.abc.Iterable[tuple[typing.Any, typing.Any]]
    if isinstance(features, collections.abc.Mapping):
        items = features.items()
    else:
        collected: list[tuple[typing.Any, typing.Any]] = []
        for item in features:
            if isinstance(item, str):
                collected.append((item, True))
                continue
            try:
                name, value = item
            except (TypeError, ValueError):
                raise TypeError(
                    'language features must be a mapping or an iterable of '
                    'names or (name, value) pairs'
                ) from None
            collected.append((name, value))
        items = collected

    normalized: list[tuple[str, T_FeatureValue]] = []
    for name, value in items:
        if not isinstance(name, str):
            raise TypeError('language feature names must be strings')
        normalized.append((name, _feature_value(value, name)))
    return LanguageFeatures(sorted(normalized))


def _language_features_dict(
        features: T_Features) -> dict[str, T_FeatureValue]:
    """Return normalized features as a mapping for host-side inspection."""
    return dict(features)


def _policy_name(policy: typing.Any) -> str:
    if policy is None:
        return 'none'
    if isinstance(policy, str):
        return policy
    module = getattr(policy, '__module__', None)
    qualname = getattr(policy, '__qualname__', None)
    if not isinstance(module, str) or not isinstance(qualname, str):
        module = type(policy).__module__
        qualname = type(policy).__qualname__
    return f'{module}.{qualname}'


def _restrictedpython_version() -> str:
    try:
        from importlib.metadata import version

        return version('RestrictedPython')
    except Exception:  # pragma: no cover - depends on installation layout
        return 'unknown'


def current_guard_version() -> str:
    """Return the version label of the guards shipped by this package."""
    from RestrictedPython import Guards

    version = getattr(Guards, 'GUARD_VERSION', 'unknown')
    return _plain_text(version, 'guard version')


def _source_identity(
        source: typing.Any,
        mode: str) -> tuple[str, str, ast.AST | None]:
    """Return ``(sha256, kind, parsed_tree)`` without executing the source."""
    tree: ast.AST | None = None
    if isinstance(source, ast.AST):
        kind = f'ast:{type(source).__name__}'
        dumped = ast.dump(
            source, annotate_fields=True, include_attributes=False)
        payload = dumped.encode('utf-8')
        tree = source
    elif isinstance(source, str):
        kind = 'str'
        payload = source.encode('utf-8')
        try:
            tree = ast.parse(source, '<artifact>', mode)
        except (SyntaxError, ValueError):
            tree = None
    elif isinstance(source, (bytes, bytearray)):
        kind = 'bytes'
        payload = bytes(source)
        try:
            parsed_source: str | bytes = (
                source.decode('utf-8')
                if isinstance(source, bytearray) else source)
            tree = ast.parse(parsed_source, '<artifact>', mode)
        except (SyntaxError, ValueError, UnicodeDecodeError):
            tree = None
    else:
        raise TypeError(
            'Not allowed source type: '
            f'"{type(source).__name__}".'
        )
    return hashlib.sha256(payload).hexdigest(), kind, tree


def _detect_features_used(tree: ast.AST | None) -> tuple[str, ...]:
    if tree is None:
        return ()

    features: set[str] = set()
    for node in ast.walk(tree):
        name = type(node).__name__
        if name in {'AsyncFunctionDef', 'AsyncFor', 'AsyncWith', 'Await'}:
            features.add('async')
        elif name == 'JoinedStr':
            features.add('f_string')
        elif name in {'TemplateStr', 'Interpolation'}:
            features.add('t_string')
        elif name == 'NamedExpr':
            features.add('walrus')
        elif name in {'Match', 'MatchCase'}:
            features.add('match')
        elif name == 'TryStar':
            features.add('except_star')
        elif name == 'TypeAlias':
            features.add('type_alias')
        elif name == 'comprehension':
            target = getattr(node, 'target', None)
            if isinstance(target, (ast.Tuple, ast.List)):
                features.add('comprehension_unpacking')
        elif name in {'Import', 'ImportFrom'} and getattr(
                node, 'lazy', False):
            features.add('lazy_import')
    return tuple(sorted(features))


@dataclasses.dataclass(frozen=True)
class CompileEnvironment:
    """The non-source inputs which make an approval applicable."""

    policy: str
    policy_version: str
    guard_version: str
    language_features: T_Features
    python_implementation: str
    python_version: str
    restrictedpython_version: str
    mode: str
    flags: int
    dont_inherit: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, 'policy', _policy_name(self.policy))
        object.__setattr__(
            self, 'policy_version',
            _plain_text(self.policy_version, 'policy_version'))
        object.__setattr__(
            self, 'guard_version',
            _plain_text(self.guard_version, 'guard_version'))
        object.__setattr__(
            self, 'language_features',
            _normalize_language_features(self.language_features))
        object.__setattr__(
            self, 'python_implementation',
            _plain_text(self.python_implementation,
                        'python_implementation'))
        object.__setattr__(
            self, 'python_version',
            _plain_text(self.python_version, 'python_version'))
        object.__setattr__(
            self, 'restrictedpython_version',
            _plain_text(self.restrictedpython_version,
                        'restrictedpython_version'))
        object.__setattr__(self, 'mode', _plain_text(self.mode, 'mode'))
        object.__setattr__(self, 'flags', int(self.flags))
        object.__setattr__(self, 'dont_inherit', bool(self.dont_inherit))

    def to_dict(self) -> dict[str, typing.Any]:
        return {
            'policy': self.policy,
            'policy_version': self.policy_version,
            'guard_version': self.guard_version,
            'language_features': [
                [name, value]
                for name, value in self.language_features],
            'python_implementation': self.python_implementation,
            'python_version': self.python_version,
            'restrictedpython_version': self.restrictedpython_version,
            'mode': self.mode,
            'flags': self.flags,
            'dont_inherit': self.dont_inherit,
        }

    def __getitem__(self, key: str) -> typing.Any:
        return getattr(self, key)


@dataclasses.dataclass(frozen=True)
class CompileArtifact:
    """A text-serializable description suitable for an approval record."""

    source_sha256: str
    source_kind: str
    policy: str
    policy_version: str
    guard_version: str
    language_features: T_Features
    python_implementation: str
    python_version: str
    restrictedpython_version: str
    mode: str
    flags: int
    dont_inherit: bool
    features_used: tuple[str, ...] = ()
    schema: str = ARTIFACT_SCHEMA

    def __post_init__(self) -> None:
        object.__setattr__(
            self, 'source_sha256',
            _plain_text(self.source_sha256, 'source_sha256'))
        object.__setattr__(
            self, 'source_kind',
            _plain_text(self.source_kind, 'source_kind'))
        object.__setattr__(self, 'policy', _policy_name(self.policy))
        object.__setattr__(
            self, 'policy_version',
            _plain_text(self.policy_version, 'policy_version'))
        object.__setattr__(
            self, 'guard_version',
            _plain_text(self.guard_version, 'guard_version'))
        object.__setattr__(
            self, 'language_features',
            _normalize_language_features(self.language_features))
        object.__setattr__(
            self, 'python_implementation',
            _plain_text(self.python_implementation,
                        'python_implementation'))
        object.__setattr__(
            self, 'python_version',
            _plain_text(self.python_version, 'python_version'))
        object.__setattr__(
            self, 'restrictedpython_version',
            _plain_text(self.restrictedpython_version,
                        'restrictedpython_version'))
        object.__setattr__(self, 'mode', _plain_text(self.mode, 'mode'))
        object.__setattr__(self, 'flags', int(self.flags))
        object.__setattr__(self, 'dont_inherit', bool(self.dont_inherit))
        object.__setattr__(
            self, 'features_used',
            tuple(sorted(_plain_text(item, 'feature name')
                         for item in self.features_used)))
        object.__setattr__(
            self, 'schema', _plain_text(self.schema, 'schema'))

    @property
    def source_digest(self) -> str:
        return self.source_sha256

    @property
    def digest(self) -> str:
        return self.source_sha256

    @property
    def source_hash(self) -> str:
        return self.source_sha256

    @property
    def sha256(self) -> str:
        return self.source_sha256

    @property
    def policy_name(self) -> str:
        return self.policy

    @property
    def policy_id(self) -> str:
        return self.policy

    @property
    def guards_version(self) -> str:
        return self.guard_version

    @property
    def features(self) -> tuple[str, ...]:
        return self.features_used

    @property
    def language_feature_map(self) -> dict[str, T_FeatureValue]:
        return _language_features_dict(self.language_features)

    @property
    def language_feature_settings(self) -> T_Features:
        return self.language_features

    @property
    def compile_flags(self) -> int:
        return self.flags

    @property
    def implementation(self) -> str:
        return self.python_implementation

    @property
    def environment(self) -> CompileEnvironment:
        return CompileEnvironment(
            policy=self.policy,
            policy_version=self.policy_version,
            guard_version=self.guard_version,
            language_features=self.language_features,
            python_implementation=self.python_implementation,
            python_version=self.python_version,
            restrictedpython_version=self.restrictedpython_version,
            mode=self.mode,
            flags=self.flags,
            dont_inherit=self.dont_inherit,
        )

    def to_dict(self) -> dict[str, typing.Any]:
        data: dict[str, typing.Any] = {
            'schema': self.schema,
            'source_sha256': self.source_sha256,
            'source_kind': self.source_kind,
            'features_used': list(self.features_used),
        }
        data.update(self.environment.to_dict())
        return data

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(',', ':'),
            sort_keys=True,
        )

    def __str__(self) -> str:
        return self.to_json()

    def describe(self) -> str:
        return self.to_json()

    @property
    def summary(self) -> str:
        return self.to_json()

    @property
    def text(self) -> str:
        return self.to_json()

    def approval_record(self) -> ApprovalRecord:
        return ApprovalRecord(self.to_json())

    def compare(self, other: CompileArtifactLike) -> ApprovalCheck:
        return compare_artifacts(self, other)

    def matches(self, approval: typing.Any) -> bool:
        return approval_applies(approval, self)

    def to_text(self) -> str:
        return self.to_json()

    def as_text(self) -> str:
        return self.to_json()

    def descriptor(self) -> str:
        return self.to_json()

    def as_dict(self) -> dict[str, typing.Any]:
        return self.to_dict()

    @property
    def description(self) -> str:
        return self.to_json()

    def __getitem__(self, key: str) -> typing.Any:
        return getattr(self, key)

    @classmethod
    def from_dict(cls, data: collections.abc.Mapping[str, typing.Any],
                  ) -> CompileArtifact:
        schema = data.get('schema', ARTIFACT_SCHEMA)
        if schema != ARTIFACT_SCHEMA:
            raise ValueError(f'unsupported artifact schema: {schema!r}')

        env_data = data.get('environment', data)
        if not isinstance(env_data, collections.abc.Mapping):
            raise ValueError('artifact environment must be a mapping')

        source_sha256 = data.get('source_sha256')
        source_kind = data.get('source_kind')
        if not isinstance(source_sha256, str):
            raise ValueError('artifact has no source digest')
        if not isinstance(source_kind, str):
            raise ValueError('artifact has no source kind')

        features_used = data.get('features_used', ())
        if not isinstance(features_used, (list, tuple)) or not all(
                isinstance(item, str) for item in features_used):
            raise ValueError('artifact has an invalid feature list')

        return cls(
            source_sha256=source_sha256,
            source_kind=source_kind,
            policy=_plain_text(env_data.get('policy'), 'policy'),
            policy_version=_plain_text(
                env_data.get('policy_version'), 'policy_version'),
            guard_version=_plain_text(
                env_data.get('guard_version'), 'guard_version'),
            language_features=_normalize_language_features(
                env_data.get('language_features')),
            python_implementation=_plain_text(
                env_data.get('python_implementation'),
                'python_implementation'),
            python_version=_plain_text(
                env_data.get('python_version'), 'python_version'),
            restrictedpython_version=_plain_text(
                env_data.get('restrictedpython_version'),
                'restrictedpython_version'),
            mode=_plain_text(env_data.get('mode'), 'mode'),
            flags=int(env_data.get('flags', 0)),
            dont_inherit=bool(env_data.get('dont_inherit', False)),
            features_used=tuple(sorted(features_used)),
            schema=schema,
        )

    @classmethod
    def from_json(cls, summary: str) -> CompileArtifact:
        try:
            data = json.loads(summary)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                'not a RestrictedPython artifact summary') from exc
        if not isinstance(data, collections.abc.Mapping):
            raise ValueError('not a RestrictedPython artifact summary')
        return cls.from_dict(data)


class ApprovalRecord(str):
    """A textual approval summary.

    The record is deliberately a ``str``: the only thing retained for review
    is the deterministic artifact summary.  Host objects are never stored.
    """

    def __new__(cls, summary: typing.Any = '') -> ApprovalRecord:
        if not isinstance(summary, str):
            summary = _coerce_artifact(summary).to_json()
        return str.__new__(cls, summary)

    @property
    def summary(self) -> str:
        return str(self)

    @property
    def text(self) -> str:
        return str(self)

    @property
    def artifact(self) -> CompileArtifact:
        return CompileArtifact.from_json(str(self))

    @classmethod
    def from_artifact(
            cls, artifact: CompileArtifactLike) -> ApprovalRecord:
        return cls(_coerce_artifact(artifact).to_json())

    @classmethod
    def from_text(cls, summary: str) -> ApprovalRecord:
        return cls(summary)


@dataclasses.dataclass(frozen=True)
class ApprovalCheck:
    """The result of comparing an approval summary with a new artifact."""

    applicable: bool
    changed_fields: tuple[str, ...]
    reasons: tuple[str, ...]
    differences: dict[str, tuple[typing.Any, typing.Any]]
    approved: CompileArtifact | None
    current: CompileArtifact

    @property
    def valid(self) -> bool:
        return self.applicable

    @property
    def ok(self) -> bool:
        return self.applicable

    @property
    def matched(self) -> bool:
        return self.applicable

    @property
    def mismatches(self) -> tuple[str, ...]:
        return self.changed_fields

    @property
    def invalidated_by(self) -> tuple[str, ...]:
        return self.changed_fields

    @property
    def changed(self) -> tuple[str, ...]:
        return self.changed_fields

    @property
    def mismatched_fields(self) -> tuple[str, ...]:
        return self.changed_fields

    @property
    def reason(self) -> str:
        return '; '.join(self.reasons)

    @property
    def details(self) -> dict[str, tuple[typing.Any, typing.Any]]:
        return self.differences

    @property
    def cause(self) -> str | None:
        return self.changed_fields[0] if self.changed_fields else None

    @property
    def approved_summary(self) -> str | None:
        return None if self.approved is None else self.approved.to_json()

    @property
    def current_summary(self) -> str:
        return self.current.to_json()

    def to_dict(self) -> dict[str, typing.Any]:
        return {
            'applicable': self.applicable,
            'changed_fields': list(self.changed_fields),
            'reasons': list(self.reasons),
            'differences': {
                field: list(values)
                for field, values in self.differences.items()
            },
            'approved': self.approved_summary,
            'current': self.current_summary,
        }

    @property
    def config_changes(self) -> tuple[str, ...]:
        non_config = {
            'source_sha256', 'source_kind', 'features_used',
        }
        return tuple(
            field for field in self.changed_fields
            if field not in non_config)

    def __bool__(self) -> bool:
        return self.applicable


_COMPARED_FIELDS = (
    'source_sha256',
    'source_kind',
    'policy',
    'policy_version',
    'guard_version',
    'language_features',
    'python_implementation',
    'python_version',
    'restrictedpython_version',
    'mode',
    'flags',
    'dont_inherit',
    'features_used',
)


def _coerce_artifact(value: typing.Any) -> CompileArtifact:
    if isinstance(value, CompileArtifact):
        return value
    artifact = getattr(value, 'artifact', None)
    if isinstance(artifact, CompileArtifact):
        return artifact
    if isinstance(value, str):
        return CompileArtifact.from_json(value)
    if isinstance(value, collections.abc.Mapping):
        return CompileArtifact.from_dict(value)
    raise TypeError('expected a CompileArtifact or a compile result')


def _coerce_approval(value: typing.Any) -> CompileArtifact:
    if isinstance(value, CompileArtifact):
        return value
    if isinstance(value, ApprovalRecord):
        return value.artifact
    if isinstance(value, str):
        return CompileArtifact.from_json(value)
    return _coerce_artifact(value)


def build_compile_environment(
        *,
        policy: typing.Any = _DEFAULT_POLICY,
        policy_version: str | None = None,
        guard_version: str | None = None,
        language_features: T_FeatureInput = None,
        mode: str = 'exec',
        flags: int = 0,
        dont_inherit: bool = False) -> CompileEnvironment:
    """Build the environment part of an artifact from primitive settings."""
    if policy is _DEFAULT_POLICY:
        from RestrictedPython.transformer import RestrictingNodeTransformer

        policy = RestrictingNodeTransformer
    if guard_version is None:
        guard_version = current_guard_version()
    return CompileEnvironment(
        policy=_policy_name(policy),
        policy_version=_plain_text(policy_version, 'policy_version'),
        guard_version=_plain_text(guard_version, 'guard_version'),
        language_features=_normalize_language_features(language_features),
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
        restrictedpython_version=_restrictedpython_version(),
        mode=_plain_text(mode, 'mode'),
        flags=int(flags),
        dont_inherit=bool(dont_inherit),
    )


def build_compile_artifact(
        source: typing.Any,
        *,
        mode: str = 'exec',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: typing.Any = _DEFAULT_POLICY,
        guard_version: str | None = None,
        policy_version: str | None = None,
        language_features: T_FeatureInput = None,
        environment: CompileEnvironment | collections.abc.Mapping[
            str, typing.Any] | None = None) -> CompileArtifact:
    """Describe a compilation without executing the source.

    ``policy`` is reduced to a module/qualified-name label.  The artifact
    never contains the policy object, guard objects, globals, builtins or the
    source text.
    """
    digest, source_kind, tree = _source_identity(source, mode)

    if policy is _DEFAULT_POLICY:
        from RestrictedPython.transformer import RestrictingNodeTransformer

        policy = RestrictingNodeTransformer

    if environment is None:
        env = build_compile_environment(
            policy=policy,
            policy_version=policy_version,
            guard_version=guard_version,
            language_features=language_features,
            mode=mode,
            flags=flags,
            dont_inherit=dont_inherit,
        )
    elif isinstance(environment, CompileEnvironment):
        env = environment
    elif isinstance(environment, collections.abc.Mapping):
        env_data = dict(environment)
        env_data.setdefault('policy', _policy_name(policy))
        env_data.setdefault('mode', mode)
        env_data.setdefault('flags', flags)
        env_data.setdefault('dont_inherit', dont_inherit)
        if guard_version is None:
            guard_version = current_guard_version()
        env_data.setdefault('guard_version', guard_version)
        env_data.setdefault(
            'language_features', language_features)
        env = CompileEnvironment(
            policy=_plain_text(env_data.get('policy'), 'policy'),
            policy_version=_plain_text(
                env_data.get('policy_version'), 'policy_version'),
            guard_version=_plain_text(
                env_data.get('guard_version'), 'guard_version'),
            language_features=_normalize_language_features(
                env_data.get('language_features')),
            python_implementation=_plain_text(
                env_data.get('python_implementation',
                             platform.python_implementation()),
                'python_implementation'),
            python_version=_plain_text(
                env_data.get('python_version', platform.python_version()),
                'python_version'),
            restrictedpython_version=_plain_text(
                env_data.get('restrictedpython_version',
                             _restrictedpython_version()),
                'restrictedpython_version'),
            mode=_plain_text(env_data.get('mode'), 'mode'),
            flags=int(env_data.get('flags', 0)),
            dont_inherit=bool(env_data.get('dont_inherit', False)),
        )
    else:
        raise TypeError('environment must be a CompileEnvironment or mapping')

    return CompileArtifact(
        source_sha256=digest,
        source_kind=source_kind,
        policy=env.policy,
        policy_version=env.policy_version,
        guard_version=env.guard_version,
        language_features=env.language_features,
        python_implementation=env.python_implementation,
        python_version=env.python_version,
        restrictedpython_version=env.restrictedpython_version,
        mode=env.mode,
        flags=env.flags,
        dont_inherit=env.dont_inherit,
        features_used=_detect_features_used(tree),
    )


def describe_compile(
        source: typing.Any,
        *,
        mode: str = 'exec',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: typing.Any = _DEFAULT_POLICY,
        guard_version: str | None = None,
        policy_version: str | None = None,
        language_features: T_FeatureInput = None,
        environment: CompileEnvironment | collections.abc.Mapping[
            str, typing.Any] | None = None) -> CompileArtifact:
    """Alias for :func:`build_compile_artifact`."""
    return build_compile_artifact(
        source,
        mode=mode,
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        guard_version=guard_version,
        policy_version=policy_version,
        language_features=language_features,
        environment=environment,
    )


def _display(value: typing.Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _change_reason(field: str, old: typing.Any, new: typing.Any) -> str:
    if field == 'source_sha256':
        return 'source digest changed'
    if field == 'source_kind':
        return f'source representation changed from {_display(old)} ' \
               f'to {_display(new)}'
    return f'{field} changed from {_display(old)} to {_display(new)}'


def compare_artifacts(
        approved: typing.Any,
        current: typing.Any) -> ApprovalCheck:
    """Compare two artifacts without executing any source code."""
    approved_artifact = _coerce_artifact(approved)
    current_artifact = _coerce_artifact(current)

    differences: dict[str, tuple[typing.Any, typing.Any]] = {}
    for field in _COMPARED_FIELDS:
        old = getattr(approved_artifact, field)
        new = getattr(current_artifact, field)
        if old != new:
            differences[field] = (old, new)

    changed_fields = tuple(differences)
    reasons = tuple(
        _change_reason(field, old, new)
        for field, (old, new) in differences.items()
    )
    return ApprovalCheck(
        applicable=not differences,
        changed_fields=changed_fields,
        reasons=reasons,
        differences=differences,
        approved=approved_artifact,
        current=current_artifact,
    )


def check_approval(
        approval: typing.Any,
        current: typing.Any) -> ApprovalCheck:
    """Return whether a textual approval still applies to ``current``.

    ``approval`` may be an :class:`ApprovalRecord`, its text, an artifact or a
    compile result.  A syntactically unusable approval is reported as invalid;
    its text is not copied into the result.
    """
    if (not isinstance(approval, (ApprovalRecord, str))
            and isinstance(current, (ApprovalRecord, str))):
        approval, current = current, approval
    current_artifact = _coerce_artifact(current)
    try:
        approved_artifact = _coerce_approval(approval)
    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
        return ApprovalCheck(
            applicable=False,
            changed_fields=('approval_record',),
            reasons=('approval record is not a usable artifact summary',),
            differences={},
            approved=None,
            current=current_artifact,
        )
    return compare_artifacts(approved_artifact, current_artifact)


def approval_applies(approval: typing.Any, current: typing.Any) -> bool:
    """Return ``True`` when the approval still applies to ``current``."""
    return check_approval(approval, current).applicable


def create_approval_record(artifact: typing.Any) -> ApprovalRecord:
    """Create the text-only approval record for an artifact."""
    return ApprovalRecord.from_artifact(artifact)


# Descriptive aliases used by hosts which prefer different terminology.
ArtifactDescriptor = CompileArtifact
CompilationArtifact = CompileArtifact
ApprovalDecision = ApprovalCheck


def artifact_summary(artifact: typing.Any) -> str:
    """Return the text summary of an artifact."""
    return _coerce_artifact(artifact).to_json()


describe_artifact = artifact_summary
approval_record = create_approval_record
is_approval_applicable = approval_applies
approval_still_applies = approval_applies
is_approval_valid = approval_applies
approval_matches = approval_applies
verify_approval = check_approval


__all__ = [
    'APPROVAL_SCHEMA',
    'ARTIFACT_SCHEMA',
    'ApprovalCheck',
    'ApprovalDecision',
    'ApprovalRecord',
    'ArtifactDescriptor',
    'CompilationArtifact',
    'CompileArtifact',
    'CompileEnvironment',
    'T_FeatureInput',
    'T_FeatureValue',
    'T_Features',
    'approval_applies',
    'approval_matches',
    'approval_record',
    'approval_still_applies',
    'artifact_summary',
    'build_compile_artifact',
    'build_compile_environment',
    'check_approval',
    'compare_artifacts',
    'create_approval_record',
    'current_guard_version',
    'describe_artifact',
    'describe_compile',
    'is_approval_applicable',
    'is_approval_valid',
    'verify_approval',
]
