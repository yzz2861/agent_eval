"""Optional provenance report for BaseModel.model_validate."""

from __future__ import annotations

import contextvars
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any, Literal
from weakref import WeakKeyDictionary

from pydantic_core import CoreSchema, SchemaValidator
from pydantic_core import core_schema as cs

__all__ = (
    'DefaultFactorySource',
    'DefaultSource',
    'InputPathSource',
    'ValidationReport',
    'ValueReport',
    'build_report_schema',
    'validate_with_report',
)

PathSegment = str | int


@dataclass(frozen=True, slots=True)
class InputPathSource:
    """The field value was read from the input at path."""

    kind: Literal['input_path'] = 'input_path'
    path: tuple[PathSegment, ...] = ()

    def __str__(self) -> str:
        return f'input path {_format_path(self.path)}'


@dataclass(frozen=True, slots=True)
class DefaultSource:
    """The field used its statically declared default value."""

    kind: Literal['default'] = 'default'

    def __str__(self) -> str:
        return 'default value'


@dataclass(frozen=True, slots=True)
class DefaultFactorySource:
    """The field used its declared default factory."""

    kind: Literal['default_factory'] = 'default_factory'

    def __str__(self) -> str:
        return 'default factory'


FieldSource = InputPathSource | DefaultSource | DefaultFactorySource


@dataclass(frozen=True, slots=True)
class AliasResolution:
    """Consumption state for one name/alias lookup candidate."""

    kind: Literal['name', 'alias']
    path: tuple[PathSegment, ...]
    consumed: bool


@dataclass(slots=True)
class ValueReport:
    """Provenance for a field value, including nested structures and union choices."""

    kind: Literal['value', 'model', 'list', 'tuple', 'set', 'frozenset', 'deque', 'union'] = 'value'
    model_name: str | None = None
    union_choice: int | str | None = None
    fields: dict[str, FieldReport] = dataclass_field(default_factory=dict)
    items: dict[int, ValueReport] = dataclass_field(default_factory=dict)


@dataclass(slots=True)
class FieldReport:
    """Provenance of one model field."""

    source: FieldSource
    value: ValueReport
    aliases: tuple[AliasResolution, ...] = ()


@dataclass(slots=True)
class ValidationReport:
    """Where each validated field's value came from.

    Only input key/index paths are stored; original input values are never retained.
    """

    root: ValueReport = dataclass_field(default_factory=lambda: ValueReport(kind='model'))

    @property
    def fields(self) -> dict[str, FieldReport]:
        return self.root.fields


def _format_path(path: tuple[PathSegment, ...]) -> str:
    rendered = ['<root>']
    for segment in path:
        if isinstance(segment, int):
            rendered.append(f'[{segment}]')
        else:
            rendered.append(repr(segment))
    return '.'.join(rendered)


_MISSING = object()


def _lookup_segment(value: Any, segment: PathSegment, *, first: bool, from_attributes: bool) -> tuple[bool, Any]:
    if isinstance(segment, str):
        if first and isinstance(value, MappingABC):
            try:
                found = value.get(segment, _MISSING)
            except TypeError:
                try:
                    return True, value[segment]
                except (KeyError, LookupError, TypeError):
                    return False, None
            return (False, None) if found is _MISSING else (True, found)
        if from_attributes and not isinstance(value, dict):
            attribute = getattr(value, segment, _MISSING)
            if attribute is not _MISSING:
                return True, attribute
            if not isinstance(value, MappingABC):
                return False, None
        try:
            return True, value[segment]
        except (KeyError, AttributeError, LookupError, TypeError):
            return False, None

    if isinstance(value, (str, bytes, bytearray)):
        return False, None
    try:
        return True, value[segment]
    except (IndexError, KeyError, LookupError, TypeError):
        return False, None


def _resolve_path(value: Any, path: tuple[PathSegment, ...], from_attributes: bool) -> tuple[bool, Any]:
    for index, segment in enumerate(path):
        found, value = _lookup_segment(value, segment, first=index == 0, from_attributes=from_attributes)
        if not found:
            return False, None
    return True, value


class _ModelFrame:
    __slots__ = ('model_name', 'raw_input', 'by_alias', 'by_name', 'from_attributes', 'path', 'report')

    def __init__(
        self,
        model_name: str | None,
        raw_input: Any,
        by_alias: bool,
        by_name: bool,
        from_attributes: bool,
        path: tuple[PathSegment, ...] = (),
    ) -> None:
        self.model_name = model_name
        self.raw_input = raw_input
        self.by_alias = by_alias
        self.by_name = by_name
        self.from_attributes = from_attributes
        self.path = path
        self.report = ValueReport(kind='model', model_name=model_name)


class _SequenceFrame:
    __slots__ = ('kind', 'items', 'next_index', 'path')

    def __init__(self, kind: str, path: tuple[PathSegment, ...]) -> None:
        self.kind = kind
        self.items: dict[int, ValueReport] = {}
        self.next_index = 0
        self.path = path


class _UnionFrame:
    __slots__ = ('attempts', 'attempt_outputs', 'attempt_reports', 'next_attempt', 'path')

    def __init__(self, path: tuple[PathSegment, ...]) -> None:
        self.attempts: dict[int, int | str] = {}
        self.attempt_outputs: dict[int, Any] = {}
        self.attempt_reports: dict[int, ValueReport] = {}
        self.next_attempt = 0
        self.path = path


class _UnionAttemptFrame:
    __slots__ = ('union_frame', 'attempt')

    def __init__(self, union_frame: _UnionFrame, attempt: int) -> None:
        self.union_frame = union_frame
        self.attempt = attempt


class _FieldFrame:
    __slots__ = (
        'name',
        'candidates',
        'default_kind',
        'selected_path',
        'prefix',
        'value_report',
    )

    def __init__(
        self,
        name: str,
        candidates: tuple[tuple[Literal['name', 'alias'], tuple[PathSegment, ...]], ...],
        default_kind: Literal['default', 'default_factory'] | None,
        selected_path: tuple[PathSegment, ...] | None,
        prefix: tuple[PathSegment, ...] = (),
    ) -> None:
        self.name = name
        self.candidates = candidates
        self.default_kind = default_kind
        self.selected_path = selected_path
        self.prefix = prefix
        self.value_report = ValueReport(kind='value')


class _ItemFrame:
    __slots__ = ('report', 'path')

    def __init__(self, path: tuple[PathSegment, ...]) -> None:
        self.report = ValueReport(kind='value')
        self.path = path


_Frame = _ModelFrame | _SequenceFrame | _UnionFrame | _UnionAttemptFrame | _FieldFrame | _ItemFrame


class _Tracker:
    __slots__ = ('frames', 'root_report', 'by_alias', 'by_name', 'from_attributes')

    def __init__(
        self,
        raw_input: Any,
        by_alias: bool,
        by_name: bool,
        from_attributes: bool,
    ) -> None:
        self.frames: list[_Frame] = []
        self.root_report: ValueReport | None = None
        self.by_alias = by_alias
        self.by_name = by_name
        self.from_attributes = from_attributes

    def model_frame(self) -> _ModelFrame:
        for frame in reversed(self.frames):
            if isinstance(frame, _ModelFrame):
                return frame
        raise AssertionError('No active model frame')

    def nearest_sequence(self) -> _SequenceFrame | None:
        for frame in reversed(self.frames):
            if isinstance(frame, _SequenceFrame):
                return frame
            if isinstance(frame, _ModelFrame):
                return None
        return None

    def active_path(self) -> tuple[PathSegment, ...]:
        for frame in reversed(self.frames):
            if isinstance(frame, _FieldFrame):
                if frame.selected_path is not None:
                    return (*frame.prefix, *frame.selected_path)
                return frame.prefix
            if isinstance(frame, _ItemFrame):
                return frame.path
            if isinstance(frame, (_SequenceFrame, _UnionFrame, _ModelFrame)):
                return frame.path
        return ()

    def place(self, report: ValueReport) -> None:
        for frame in reversed(self.frames):
            if isinstance(frame, _FieldFrame):
                frame.value_report = report
                return
            if isinstance(frame, _ItemFrame):
                frame.report = report
                return
            if isinstance(frame, _UnionAttemptFrame):
                frame.union_frame.attempt_reports[frame.attempt] = report
                return
            if isinstance(frame, _UnionFrame):
                continue
            return


_tracker_var: contextvars.ContextVar[_Tracker | None] = contextvars.ContextVar(
    'pydantic_validation_report_tracker', default=None
)


def _select_path(
    candidates: tuple[tuple[Literal['name', 'alias'], tuple[PathSegment, ...]], ...],
    model_frame: _ModelFrame,
) -> tuple[PathSegment, ...] | None:
    has_alias_candidates = any(kind == 'alias' for kind, _ in candidates)
    alias_paths = {path for kind, path in candidates if kind == 'alias'}
    for candidate_kind, candidate_path in candidates:
        if candidate_kind == 'alias' and not model_frame.by_alias:
            continue
        if (
            candidate_kind == 'name'
            and has_alias_candidates
            and candidate_path not in alias_paths
            and not model_frame.by_name
        ):
            continue
        found, _ = _resolve_path(model_frame.raw_input, candidate_path, model_frame.from_attributes)
        if found:
            return candidate_path
    return None


def _alias_resolutions(
    candidates: tuple[tuple[Literal['name', 'alias'], tuple[PathSegment, ...]], ...],
    selected_path: tuple[PathSegment, ...] | None,
    by_alias: bool,
) -> tuple[AliasResolution, ...]:
    return tuple(
        AliasResolution(
            kind=kind,
            path=path,
            consumed=by_alias and path == selected_path,
        )
        for kind, path in candidates
        if kind == 'alias'
    )


def _nearest_union_attempt(frames: list[_Frame]) -> _UnionAttemptFrame | None:
    for frame in reversed(frames):
        if isinstance(frame, _UnionAttemptFrame):
            return frame
        if isinstance(frame, (_ModelFrame, _SequenceFrame, _FieldFrame, _ItemFrame)):
            return None
    return None


def _make_model_wrap(
    model_name: str | None,
    field_specs: tuple[
        tuple[
            str,
            tuple[tuple[Literal['name', 'alias'], tuple[PathSegment, ...]], ...],
            Literal['default', 'default_factory'] | None,
        ],
        ...,
    ] = (),
):
    def wrap(value: Any, handler: cs.ValidatorFunctionWrapHandler) -> Any:
        tracker = _tracker_var.get()
        if tracker is None:
            return handler(value)
        parent = tracker.model_frame() if tracker.frames else None
        if tracker.frames:
            assert parent is not None
            by_alias, by_name = parent.by_alias, parent.by_name
            path = tracker.active_path()
        else:
            by_alias, by_name = tracker.by_alias, tracker.by_name
            path = ()
        raw_input = value
        if (
            tracker.frames
            and hasattr(value, '__pydantic_validator__')
            and hasattr(value, '__dict__')
        ):
            raw_input = vars(value)
        frame = _ModelFrame(
            model_name,
            raw_input,
            by_alias,
            by_name,
            parent.from_attributes if parent is not None else tracker.from_attributes,
            path,
        )
        tracker.frames.append(frame)
        try:
            result = handler(value)
            report = frame.report
        finally:
            tracker.frames.pop()
        if not tracker.frames:
            tracker.root_report = report
            return result
        if field_specs and hasattr(value, '__pydantic_fields_set__'):
            fields_set = set(getattr(value, '__pydantic_fields_set__', ()))
            for field_name, candidates, default_kind in field_specs:
                if field_name in report.fields:
                    continue
                if field_name in fields_set:
                    source: FieldSource = InputPathSource(path=(*path, field_name))
                else:
                    source = (
                        DefaultFactorySource()
                        if default_kind == 'default_factory'
                        else DefaultSource()
                    )
                report.fields[field_name] = FieldReport(
                    source=source,
                    value=ValueReport(kind='value'),
                    aliases=_alias_resolutions(candidates, None, frame.by_alias),
                )
        attempt = _nearest_union_attempt(tracker.frames)
        if attempt is not None:
            attempt.union_frame.attempt_reports[attempt.attempt] = report
            return result
        tracker.place(report)
        return result

    return wrap


def _make_root_model_wrap():
    def wrap(value: Any, handler: cs.ValidatorFunctionWrapHandler) -> Any:
        tracker = _tracker_var.get()
        if tracker is None:
            return handler(value)
        frame = _FieldFrame('root', (('name', ('root',)),), None, ('root',), ())
        tracker.frames.append(frame)
        try:
            result = handler(value)
        finally:
            tracker.frames.pop()
        model_frame = tracker.model_frame()
        model_frame.report.fields['root'] = FieldReport(
            source=InputPathSource(path=()),
            value=frame.value_report,
            aliases=(),
        )
        return result

    return wrap


def _make_field_wrap(
    field_name: str,
    candidates: tuple[tuple[Literal['name', 'alias'], tuple[PathSegment, ...]], ...],
    default_kind: Literal['default', 'default_factory'] | None,
):
    def wrap(value: Any, handler: cs.ValidatorFunctionWrapHandler) -> Any:
        tracker = _tracker_var.get()
        if tracker is None:
            return handler(value)

        frame = tracker.model_frame()
        selected_path = _select_path(candidates, frame)

        field_frame = _FieldFrame(field_name, candidates, default_kind, selected_path, frame.path)
        tracker.frames.append(field_frame)
        try:
            result = handler(value)
        finally:
            tracker.frames.pop()

        source = (
            InputPathSource(path=(*field_frame.prefix, *selected_path))
            if selected_path is not None
            else DefaultFactorySource()
            if default_kind == 'default_factory'
            else DefaultSource()
        )
        frame.report.fields[field_name] = FieldReport(
            source=source,
            value=field_frame.value_report,
            aliases=_alias_resolutions(candidates, selected_path, frame.by_alias),
        )
        return result

    return wrap


def _make_model_fields_wrap(
    field_specs: tuple[
        tuple[
            str,
            tuple[tuple[Literal['name', 'alias'], tuple[PathSegment, ...]], ...],
            Literal['default', 'default_factory'] | None,
        ],
        ...,
    ],
):
    def wrap(value: Any, handler: cs.ValidatorFunctionWrapHandler) -> Any:
        tracker = _tracker_var.get()
        if tracker is None:
            return handler(value)
        model_frame = tracker.model_frame()
        result = handler(value)
        for field_name, candidates, default_kind in field_specs:
            if field_name in model_frame.report.fields:
                continue
            selected_path = _select_path(candidates, model_frame)
            source = (
                InputPathSource(path=(*model_frame.path, *selected_path))
                if selected_path is not None
                else DefaultFactorySource()
                if default_kind == 'default_factory'
                else DefaultSource()
            )
            model_frame.report.fields[field_name] = FieldReport(
                source=source,
                value=ValueReport(kind='value'),
                aliases=_alias_resolutions(
                    candidates, selected_path, model_frame.by_alias
                ),
            )
        return result

    return wrap


def _make_sequence_wrap(kind: str):
    def wrap(value: Any, handler: cs.ValidatorFunctionWrapHandler) -> Any:
        tracker = _tracker_var.get()
        if tracker is None:
            return handler(value)
        path = tracker.active_path()
        frame = _SequenceFrame(kind, path)
        tracker.frames.append(frame)
        try:
            result = handler(value)
            items = frame.items
        finally:
            tracker.frames.pop()
        tracker.place(ValueReport(kind=kind, items=dict(sorted(items.items()))))  # type: ignore[arg-type]
        return result

    return wrap


def _make_item_wrap(index: int):
    def wrap(value: Any, handler: cs.ValidatorFunctionWrapHandler) -> Any:
        tracker = _tracker_var.get()
        if tracker is None:
            return handler(value)
        sequence = tracker.nearest_sequence()
        if sequence is None:
            return handler(value)
        index = sequence.next_index
        sequence.next_index += 1
        item_frame = _ItemFrame((*sequence.path, index))
        tracker.frames.append(item_frame)
        try:
            result = handler(value)
            sequence.items[index] = item_frame.report
        finally:
            tracker.frames.pop()
        return result

    return wrap


def _make_union_wrap():
    def wrap(value: Any, handler: cs.ValidatorFunctionWrapHandler) -> Any:
        tracker = _tracker_var.get()
        if tracker is None:
            return handler(value)
        target = tracker.frames[-1] if tracker.frames else None
        path = tracker.active_path()
        frame = _UnionFrame(path)
        tracker.frames.append(frame)
        try:
            result = handler(value)
            selected_attempt = None
            for attempt, output in frame.attempt_outputs.items():
                if output is result:
                    selected_attempt = attempt
                    break
            candidate_attempts = list(frame.attempt_outputs)
            if selected_attempt is None and len(candidate_attempts) == 1:
                selected_attempt = candidate_attempts[0]
            if selected_attempt is None:
                structural = [attempt for attempt in candidate_attempts if attempt in frame.attempt_reports]
                if structural:
                    selected_attempt = structural[0]
        finally:
            tracker.frames.pop()
        choice = frame.attempts.get(selected_attempt) if selected_attempt is not None else None
        inner_report = frame.attempt_reports.get(selected_attempt) if selected_attempt is not None else None
        if inner_report is None:
            inner_report = (
                target.value_report
                if isinstance(target, _FieldFrame)
                else target.report
                if isinstance(target, _ItemFrame)
                else None
            )
        if isinstance(target, (_FieldFrame, _ItemFrame)) and inner_report is not None:
            if inner_report.kind in {'model', 'list', 'tuple', 'set', 'frozenset', 'deque'}:
                report = ValueReport(
                    kind='union',
                    union_choice=choice,
                    fields=inner_report.fields,
                    items=inner_report.items,
                    model_name=inner_report.model_name,
                )
            else:
                report = ValueReport(kind='union', union_choice=choice)
        else:
            report = ValueReport(kind='union', union_choice=choice)
        if isinstance(target, _FieldFrame):
            target.value_report = report
        elif isinstance(target, _ItemFrame):
            target.report = report
            item_index = target.path[-1]
            sequence = tracker.nearest_sequence()
            if sequence is not None and isinstance(item_index, int):
                sequence.items[item_index] = report
        return result

    return wrap


def _make_choice_after(choice: int | str):
    def wrap(value: Any, handler: cs.ValidatorFunctionWrapHandler) -> Any:
        tracker = _tracker_var.get()
        if tracker is None:
            return handler(value)
        union_frame = tracker.frames[-1]
        if not isinstance(union_frame, _UnionFrame):
            return handler(value)
        attempt = union_frame.next_attempt
        union_frame.next_attempt += 1
        attempt_frame = _UnionAttemptFrame(union_frame, attempt)
        tracker.frames.append(attempt_frame)
        try:
            result = handler(value)
        except Exception:
            tracker.frames.pop()
            raise
        tracker.frames.pop()
        union_frame.attempts[attempt] = choice
        union_frame.attempt_outputs[attempt] = result
        return result

    return wrap


_SEQUENCE_KINDS = {'list', 'tuple', 'set', 'frozenset', 'deque'}
_CONTAINER_SCHEMA_KEYS = (
    'schema',
    'keys_schema',
    'values_schema',
    'lax_schema',
    'strict_schema',
    'json_schema',
    'python_schema',
    'return_schema',
    'var_args_schema',
    'var_kwargs_schema',
    'extras_schema',
    'extras_keys_schema',
)


def _clone_with(source_schema: CoreSchema, **changes: Any) -> CoreSchema:
    cloned = dict(source_schema)
    cloned.update(changes)
    return cloned  # type: ignore[return-value]


def _field_candidates(
    field_name: str, field_schema: CoreSchema
) -> tuple[tuple[Literal['name', 'alias'], tuple[PathSegment, ...]], ...]:
    validation_alias = field_schema.get('validation_alias')
    candidates: list[tuple[Literal['name', 'alias'], tuple[PathSegment, ...]]] = []
    if validation_alias is not None:
        alias_paths = validation_alias
        if alias_paths and isinstance(alias_paths[0], (str, int)):
            alias_paths = [alias_paths]
        for alias_path in alias_paths:
            alias_tuple = (alias_path,) if isinstance(alias_path, str) else tuple(alias_path)
            candidates.append(('alias', alias_tuple))
    candidates.append(('name', (field_name,)))
    return tuple(candidates)


def _default_kind(field_schema: CoreSchema) -> Literal['default', 'default_factory'] | None:
    inner = field_schema.get('schema')
    if isinstance(inner, dict) and inner.get('type') == 'default':
        if 'default_factory' in inner:
            return 'default_factory'
        if 'default' in inner:
            return 'default'
    return None


def _instrument(schema: Any) -> Any:
    if isinstance(schema, list):
        return [_instrument(item) for item in schema]
    if isinstance(schema, tuple):
        choice_schema, label = schema
        return (_instrument(choice_schema), label)
    if not isinstance(schema, dict) or 'type' not in schema:
        return schema

    schema_type = schema['type']

    if schema_type == 'definitions':
        return _clone_with(
            schema,
            schema=_instrument(schema['schema']),
            definitions=_instrument(schema['definitions']),
        )

    if schema_type == 'model-fields':
        field_specs = []
        instrumented_fields = {}
        for field_name, field_schema in schema['fields'].items():
            candidates = _field_candidates(field_name, field_schema)
            default_kind = _default_kind(field_schema)
            field_specs.append((field_name, candidates, default_kind))
            instrumented_field = dict(field_schema)
            original_inner = field_schema['schema']
            if original_inner.get('type') == 'default':
                instrumented_inner = dict(original_inner)
                instrumented_inner['schema'] = cs.no_info_wrap_validator_function(
                    _make_field_wrap(field_name, candidates, default_kind),
                    _instrument(original_inner['schema']),
                )
            else:
                instrumented_inner = cs.no_info_wrap_validator_function(
                    _make_field_wrap(field_name, candidates, default_kind),
                    _instrument(original_inner),
                )
            instrumented_field['schema'] = instrumented_inner
            instrumented_fields[field_name] = instrumented_field
        inner = _clone_with(schema, fields=instrumented_fields)
        return cs.no_info_wrap_validator_function(
            _make_model_fields_wrap(tuple(field_specs)),
            inner,
        )

    if schema_type in {'model', 'dataclass'}:
        cls = schema.get('cls')
        model_name = getattr(cls, '__name__', None) or schema.get('schema', {}).get('model_name')
        inner_schema = schema.get('schema')
        field_specs: tuple[Any, ...] = ()
        if isinstance(inner_schema, dict) and inner_schema.get('type') == 'model-fields':
            field_specs = tuple(
                (
                    field_name,
                    _field_candidates(field_name, field_schema),
                    _default_kind(field_schema),
                )
                for field_name, field_schema in inner_schema['fields'].items()
            )
        instrumented = {}
        for key, value in schema.items():
            if key == 'schema' and schema.get('root_model') and value.get('type') != 'model-fields':
                instrumented[key] = cs.no_info_wrap_validator_function(_make_root_model_wrap(), _instrument(value))
            else:
                instrumented[key] = _instrument(value)
        wrapped: dict[str, Any] = cs.no_info_wrap_validator_function(
            _make_model_wrap(model_name, field_specs),
            instrumented,
        )
        if 'ref' in schema:
            wrapped['ref'] = schema['ref']
        if 'metadata' in schema:
            wrapped['metadata'] = schema['metadata']
        if 'serialization' in schema:
            wrapped['serialization'] = schema['serialization']
        return wrapped

    return _instrument_other(schema, schema_type)


def build_report_schema(schema: CoreSchema) -> CoreSchema:
    """Return a copy of schema that records provenance while validating."""
    return _instrument(schema)


def _instrument_other(schema: dict[str, Any], schema_type: str) -> dict[str, Any]:
    if schema_type == 'union':
        choices = []
        for index, choice in enumerate(schema['choices']):
            if isinstance(choice, tuple):
                choice_schema, label = choice
            else:
                choice_schema, label = choice, index
            choices.append(
                cs.no_info_wrap_validator_function(
                    _make_choice_after(label),
                    _instrument(choice_schema),
                )
            )
        return cs.no_info_wrap_validator_function(
            _make_union_wrap(),
            _clone_with(schema, choices=choices),
        )

    if schema_type == 'tagged-union':
        choices = {}
        for tag, choice_schema in schema['choices'].items():
            label = tag if isinstance(tag, (str, int)) else str(tag)
            choices[tag] = cs.no_info_wrap_validator_function(
                _make_choice_after(label),
                _instrument(choice_schema),
            )
        return cs.no_info_wrap_validator_function(
            _make_union_wrap(),
            _clone_with(schema, choices=choices),
        )

    if schema_type in _SEQUENCE_KINDS:
        instrumented = dict(schema)
        if schema_type == 'tuple':
            instrumented['items_schema'] = [
                cs.no_info_wrap_validator_function(_make_item_wrap(index), _instrument(item))
                for index, item in enumerate(schema.get('items_schema', []))
            ]
        elif 'items_schema' in schema:
            instrumented['items_schema'] = cs.no_info_wrap_validator_function(
                _make_item_wrap(0), _instrument(schema['items_schema'])
            )
        return cs.no_info_wrap_validator_function(_make_sequence_wrap(schema_type), instrumented)

    if schema_type == 'arguments':
        instrumented = dict(schema)
        instrumented['arguments_schema'] = [_instrument(argument) for argument in schema.get('arguments_schema', [])]
        for key in ('var_args_schema', 'var_kwargs_schema'):
            if key in schema:
                instrumented[key] = _instrument(schema[key])
        return instrumented

    if schema_type == 'arguments-v3':
        instrumented = dict(schema)
        instrumented['arguments_schema'] = [_instrument(argument) for argument in schema.get('arguments_schema', [])]
        return instrumented

    instrumented = dict(schema)
    for key in _CONTAINER_SCHEMA_KEYS:
        if key in instrumented:
            instrumented[key] = _instrument(instrumented[key])
    if isinstance(instrumented.get('steps'), list):
        instrumented['steps'] = [_instrument(step) for step in instrumented['steps']]
    return instrumented


_report_validator_cache: WeakKeyDictionary[type[Any], tuple[int, SchemaValidator]] = WeakKeyDictionary()


def _resolve_by_alias_name(cls: type[Any], by_alias: bool | None, by_name: bool | None) -> tuple[bool, bool]:
    config = getattr(cls, 'model_config', {}) or {}
    resolved_alias = config.get('validate_by_alias', True)
    resolved_name = config.get(
        'validate_by_name',
        config.get('populate_by_name', False),
    )
    return bool(by_alias if by_alias is not None else resolved_alias), bool(
        by_name if by_name is not None else resolved_name
    )


def _get_report_validator(cls: type[Any]) -> SchemaValidator:
    schema = cls.__pydantic_core_schema__
    cache_entry = _report_validator_cache.get(cls)
    if cache_entry is None or cache_entry[0] != id(schema):
        from ._config import ConfigWrapper

        instrumented_schema = build_report_schema(schema)
        core_config = ConfigWrapper(cls.model_config, check=False).core_config(title=cls.__name__)
        validator = SchemaValidator(instrumented_schema, core_config, _use_prebuilt=False)
        _report_validator_cache[cls] = (id(schema), validator)
        return validator
    return cache_entry[1]


def validate_with_report(
    cls: type[Any],
    obj: Any,
    *,
    strict: bool | None,
    extra: Any,
    from_attributes: bool | None,
    context: Any,
    by_alias: bool | None,
    by_name: bool | None,
) -> tuple[Any, ValidationReport]:
    resolved_alias, resolved_name = _resolve_by_alias_name(cls, by_alias, by_name)
    default_from_attributes = bool(cls.model_config.get('from_attributes', False))
    resolved_from_attributes = default_from_attributes if from_attributes is None else bool(from_attributes)
    tracker = _Tracker(obj, resolved_alias, resolved_name, resolved_from_attributes)
    token = _tracker_var.set(tracker)
    validator = _get_report_validator(cls)
    try:
        instance = validator.validate_python(
            obj,
            strict=strict,
            extra=extra,
            from_attributes=from_attributes,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )
    finally:
        _tracker_var.reset(token)
    return instance, ValidationReport(root=tracker.root_report)
