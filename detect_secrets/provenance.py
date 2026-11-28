"""Attribute scan hits to verifiable generated sources.

The scanner intentionally reports every physical location it finds.  Reviewers,
however, usually do not want one suggestion per generated file: a template that
was expanded one hundred times should produce one upstream remediation, with all
of the generated locations retained as evidence.

This module is deliberately a post-processing layer.  It never removes a hit
from a :class:`~detect_secrets.core.secrets_collection.SecretsCollection`, so a
hand-written file which happens to contain the same hash as a generated file is
still reported (and still blocks a commit).
"""
import fnmatch
import hashlib
import json
import os
from collections import defaultdict
from enum import Enum
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Set
from typing import Tuple


class AttrDict(dict):
    """A small JSON-friendly mapping which also supports attribute access."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith('_'):
            object.__setattr__(self, name, value)
        else:
            self[name] = value


class RescanReason(str, Enum):
    ONE_TO_MANY_SOURCES = 'one_to_many_sources'
    ONE_TO_MANY = 'one_to_many_sources'
    GENERATION_RULE_REMOVED = 'generation_rule_removed'
    GENERATION_RULE_DELETED = 'generation_rule_removed'
    DELETED_GENERATION_RULE = 'generation_rule_removed'
    CONFIG_VERSION_MISMATCH = 'config_version_mismatch'
    INSUFFICIENT_EVIDENCE = 'insufficient_evidence'
    SOURCE_NOT_VERIFIED = 'source_not_verified'
    SOURCE_CHANGED = 'source_changed'


class AttributionStatus(str, Enum):
    VERIFIED = 'verified'
    PENDING = 'pending_verification'
    MANUAL = 'manual'


PendingReason = RescanReason


def _first(mapping: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _declaration_version(value: Mapping[str, Any]) -> Optional[str]:
    for key in (*_VERSION_KEYS, 'version'):
        if key not in value or value[key] is None:
            continue
        candidate = value[key]
        if isinstance(candidate, Mapping):
            candidate = _first(
                candidate,
                'version',
                'id',
                'hash',
                'config_version',
                'configuration_version',
            )
        if candidate is not None:
            return str(candidate)

    metadata = value.get('metadata')
    if isinstance(metadata, Mapping):
        return _declaration_version(metadata)
    return None


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def _plain(value: Any) -> Any:
    if isinstance(value, AttrDict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _path_key(path: Any) -> str:
    value = str(path or '').strip().replace('\\', '/')
    while value.startswith('./'):
        value = value[2:]
    return os.path.normpath(value).replace('\\', '/')


def _paths_equal(left: Any, right: Any) -> bool:
    left_key = _path_key(left)
    right_key = _path_key(right)
    if left_key == right_key:
        return True

    # Generated output is often reported relative to the repository root, while
    # a declaration provided by an external caller may contain an absolute path.
    if os.path.isabs(left_key) != os.path.isabs(right_key):
        absolute, relative = (
            (left_key, right_key) if os.path.isabs(left_key) else (right_key, left_key)
        )
        return absolute.endswith('/' + relative)

    return False


def _secret_hash(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return hashlib.sha1(str(value).encode('utf-8')).hexdigest()


def _line_number(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def normalize_hit(hit: Any) -> AttrDict:
    """Convert a scan result (or a baseline entry) to a canonical hit."""
    if hasattr(hit, 'secret_hash') and hasattr(hit, 'filename'):
        return AttrDict({
            'filename': str(getattr(hit, 'filename')),
            'line_number': _line_number(getattr(hit, 'line_number', 0)),
            'secret_hash': str(getattr(hit, 'secret_hash')),
            'type': getattr(hit, 'type', None),
            'is_verified': bool(getattr(hit, 'is_verified', False)),
            'is_secret': getattr(hit, 'is_secret', None),
        })

    if isinstance(hit, (list, tuple)):
        values = list(hit)
        if len(values) >= 3:
            return AttrDict({
                'filename': str(values[0]),
                'line_number': _line_number(values[1]),
                'secret_hash': str(values[2]),
                'type': values[3] if len(values) > 3 else None,
            })
        raise ValueError('A hit tuple must contain filename, line number, and hash.')

    if not isinstance(hit, Mapping):
        raise TypeError(f'Unsupported hit type: {type(hit)!r}')

    filename = _first(hit, 'filename', 'file', 'filepath', 'path')
    line_number = _first(hit, 'line_number', 'line', 'lineNumber', 'line_no', default=0)
    secret_hash = _first(
        hit,
        'secret_hash',
        'hashed_secret',
        'digest',
        'hash',
        'sha1',
        'fingerprint',
    )
    if secret_hash is None:
        secret_hash = _secret_hash(
            _first(hit, 'secret_value', 'secret', 'value', 'raw_secret'),
        )

    output = AttrDict({
        'filename': str(filename or ''),
        'line_number': _line_number(line_number),
        'secret_hash': str(secret_hash) if secret_hash is not None else '',
        'type': _first(hit, 'type', 'secret_type', 'plugin', 'detector'),
        'is_verified': bool(_first(hit, 'is_verified', 'verified', default=False)),
        'is_secret': _first(hit, 'is_secret', 'is_true_secret'),
    })

    line_content = _first(hit, 'line_content', 'content', 'snippet')
    if line_content is not None:
        output['line_content'] = line_content

    return output


def _load_json_or_yaml(filename: str) -> Any:
    with open(filename) as f:
        content = f.read()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError:     # pragma: no cover
            raise
        return yaml.safe_load(content)


def _maybe_parse_serialized(value: Any) -> Any:
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8')
        except UnicodeDecodeError:
            return value
    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    if not stripped.startswith(('{', '[')):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def normalize_hits(hits: Any) -> List[AttrDict]:
    """Normalize a collection, baseline, or iterable of hits."""
    if hits is None:
        return []

    if isinstance(hits, (str, os.PathLike)):
        if os.path.isfile(hits) and str(hits).lower().endswith(('.json', '.yaml', '.yml')):
            return normalize_hits(_load_json_or_yaml(hits))
        parsed = _maybe_parse_serialized(hits)
        if parsed is not hits and not isinstance(parsed, (str, os.PathLike)):
            return normalize_hits(parsed)
        return [normalize_hit({'filename': str(hits)})]

    if hasattr(hits, 'data') and hasattr(hits, 'files'):
        return [normalize_hit(secret) for _, secret in hits]

    if isinstance(hits, Mapping):
        if 'results' in hits:
            return _normalize_results(hits['results'])
        if 'hits' in hits:
            return normalize_hits(hits['hits'])

        # A mapping of filename -> list of baseline entries.
        if hits and all(isinstance(value, (list, tuple, set)) for value in hits.values()):
            output = []
            for filename, entries in hits.items():
                for entry in entries:
                    item = normalize_hit(entry)
                    if not item.filename:
                        item.filename = str(filename)
                    output.append(item)
            return output

        return [normalize_hit(hits)]

    return [normalize_hit(hit) for hit in hits]


def _normalize_results(results: Any) -> List[AttrDict]:
    output = []
    if not isinstance(results, Mapping):
        return normalize_hits(results)

    for filename, entries in results.items():
        for entry in _as_list(entries):
            item = normalize_hit(entry)
            if not item.filename:
                item.filename = str(filename)
            output.append(item)
    return output


_GENERATED_KEYS = (
    'generated',
    'generated_path',
    'generated_file',
    'generated_filename',
    'filename',
    'output',
    'output_path',
    'output_file',
    'artifact',
    'artifact_path',
    'target',
    'from',
)

_SOURCE_KEYS = (
    'source',
    'source_path',
    'source_file',
    'source_filename',
    'upstream',
    'upstream_source',
    'upstream_file',
    'input',
    'input_path',
    'input_file',
    'template',
    'template_file',
    'template_path',
    'origin',
    'to',
)

_SOURCE_LIST_KEYS = (
    'sources',
    'source_paths',
    'source_files',
    'upstream_sources',
    'upstream_files',
    'inputs',
    'input_paths',
    'templates',
)

_VERSION_KEYS = (
    'config_version',
    'configuration_version',
    'configVersion',
    'generator_config_version',
)

_RULE_KEYS = (
    'rule',
    'rule_id',
    'rule_name',
    'generation_rule',
    'generator',
    'generator_id',
    'name',
)

_DELETED_KEYS = ('deleted', 'removed', 'is_deleted', 'rule_deleted', 'missing')

_METADATA_KEYS = {
    'version',
    'metadata',
    'edges',
    'edge',
    'source_edges',
    'source_edge',
    'generation_edges',
    'generation_edge',
    'links',
    'sources',
    'generated',
    'generated_files',
    'artifacts',
    'outputs',
    'declarations',
    'rules',
    'generation_rules',
    'deleted',
    'deleted_rules',
    'removed_rules',
    'removed_generation_rules',
    'generation',
    'provenance',
    'source_declarations',
    'generated_sources',
    'generated_sources_declaration',
    'config_version',
    'configuration_version',
    'configVersion',
    'generator_config_version',
}


class GenerationDeclaration(AttrDict):
    """A normalized generation source declaration.

    ``edges`` is the source of truth.  A generated path may have more than one
    edge; that is reported as ambiguous rather than silently choosing one.
    """

    _ALIASES = {
        'version': 'config_version',
        'source_edges': 'edges',
        'generated_sources': 'generated',
    }

    def __getattr__(self, name: str) -> Any:
        if name in self._ALIASES:
            name = self._ALIASES[name]
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __init__(
        self,
        edges: Optional[Iterable[Mapping[str, Any]]] = None,
        config_version: Optional[str] = None,
        deleted_files: Optional[Iterable[str]] = None,
        insufficient_files: Optional[Iterable[str]] = None,
        warnings: Optional[Iterable[str]] = None,
    ) -> None:
        super().__init__(
            config_version=config_version,
            edges=[AttrDict(edge) for edge in (edges or [])],
            deleted_files=sorted({str(item) for item in (deleted_files or [])}),
            insufficient_files=sorted({str(item) for item in (insufficient_files or [])}),
            warnings=list(warnings or []),
        )
        self._rebuild_indexes()

    @classmethod
    def from_value(
        cls,
        declaration: Any,
        config_version: Optional[str] = None,
    ) -> 'GenerationDeclaration':
        if isinstance(declaration, GenerationDeclaration):
            if (
                declaration.config_version is not None
                or config_version is None
            ):
                return declaration
            output = cls(
                edges=declaration.edges,
                config_version=config_version,
                deleted_files=declaration.deleted_files,
                insufficient_files=declaration.insufficient_files,
                warnings=declaration.warnings,
            )
            return output

        declaration = _maybe_parse_serialized(declaration)
        if isinstance(declaration, (str, os.PathLike)) and os.path.isfile(declaration):
            declaration = _load_json_or_yaml(declaration)

        parser = _DeclarationParser(config_version=config_version)
        return parser.parse(declaration)

    from_dict = from_value
    from_json = from_value
    from_file = from_value
    from_path = from_value
    parse = from_value
    load = from_value

    def _rebuild_indexes(self) -> None:
        by_generated: Dict[str, List[AttrDict]] = defaultdict(list)
        deleted_by_generated: Dict[str, List[AttrDict]] = defaultdict(list)
        for edge in self['edges']:
            bucket = deleted_by_generated if edge.get('deleted') else by_generated
            bucket[_path_key(edge['generated'])].append(edge)

        self._by_generated = by_generated
        self._deleted_by_generated = deleted_by_generated
        self._insufficient_files = {
            _path_key(item) for item in self['insufficient_files']
        }
        self['generated'] = {
            edge['generated']: sorted({item['source'] for item in edges})
            for generated, edges in by_generated.items()
            for edge in edges[:1]
        }
        self['sources'] = self['generated']

    def matching_generated(self, filename: Any) -> Optional[str]:
        candidate = _path_key(filename)
        all_generated = set(self._by_generated) | set(self._deleted_by_generated)
        for generated in all_generated:
            if _paths_equal(candidate, generated):
                return generated
        for generated in self['deleted_files']:
            if _paths_equal(candidate, generated):
                return _path_key(generated)
        for generated in self['insufficient_files']:
            if _paths_equal(candidate, generated):
                return _path_key(generated)
        for edge in self['edges']:
            pattern = str(edge['generated']).replace('\\', '/')
            normalized_pattern = _path_key(pattern)
            if any(character in pattern for character in '*?['):
                if fnmatch.fnmatch(candidate, normalized_pattern):
                    return normalized_pattern
            elif pattern.endswith('/') and (
                candidate == normalized_pattern
                or candidate.startswith(normalized_pattern + '/')
            ):
                return normalized_pattern
        return None

    def active_edges_for(self, filename: Any) -> List[AttrDict]:
        generated = self.matching_generated(filename)
        if generated is None:
            return []
        return list(self._by_generated.get(generated, []))

    def deleted_edges_for(self, filename: Any) -> List[AttrDict]:
        generated = self.matching_generated(filename)
        if generated is None:
            return []
        return list(self._deleted_by_generated.get(generated, []))

    def sources_for(self, filename: Any) -> List[str]:
        return sorted({
            str(edge['source'])
            for edge in self.active_edges_for(filename)
            if edge.get('source')
        })

    get_sources = sources_for

    def resolve_source(self, filename: Any) -> Optional[str]:
        sources = self.sources_for(filename)
        return sources[0] if len(sources) == 1 else None

    def deleted_sources_for(self, filename: Any) -> List[str]:
        return sorted({
            str(edge['source'])
            for edge in self.deleted_edges_for(filename)
            if edge.get('source')
        })

    def has_declaration_for(self, filename: Any) -> bool:
        return self.matching_generated(filename) is not None

    def has_insufficient_evidence(self, filename: Any) -> bool:
        return any(_paths_equal(filename, item) for item in self['insufficient_files'])

    def is_explicitly_deleted(self, filename: Any) -> bool:
        if any(_paths_equal(filename, item) for item in self['deleted_files']):
            return True
        generated = self.matching_generated(filename)
        if generated is None:
            return False
        return bool(self._deleted_by_generated.get(generated))

    def to_dict(self) -> AttrDict:
        return AttrDict({
            'config_version': self.config_version,
            'edges': [_plain(edge) for edge in self['edges']],
            'deleted_files': list(self['deleted_files']),
            'insufficient_files': list(self['insufficient_files']),
            'warnings': list(self['warnings']),
        })

    def json(self) -> Dict[str, Any]:
        return _plain(self.to_dict())


class _DeclarationParser:
    def __init__(self, config_version: Optional[str] = None) -> None:
        self.inherited_version = config_version
        self.edges: List[AttrDict] = []
        self.deleted_files: Set[str] = set()
        self.insufficient_files: Set[str] = set()
        self.warnings: List[str] = []

    def parse(self, value: Any) -> GenerationDeclaration:
        version = _declaration_version(value) if isinstance(value, Mapping) else None
        if version is None:
            version = self.inherited_version

        self._walk(value, inherited_version=version)
        if not version:
            versions = {
                str(edge['config_version'])
                for edge in self.edges
                if edge.get('config_version')
            }
            if len(versions) == 1:
                version = versions.pop()

        return GenerationDeclaration(
            edges=self.edges,
            config_version=str(version) if version is not None else None,
            deleted_files=self.deleted_files,
            insufficient_files=self.insufficient_files,
            warnings=self.warnings,
        )

    def _walk(self, value: Any, inherited_version: Optional[str]) -> None:
        if value is None:
            return
        if isinstance(value, GenerationDeclaration):
            for edge in value.edges:
                self._add_edge(edge, inherited_version)
            self.deleted_files.update(value.deleted_files)
            self.insufficient_files.update(value.insufficient_files)
            return
        if isinstance(value, (str, os.PathLike)):
            value = _maybe_parse_serialized(value)
            if not isinstance(value, (str, os.PathLike)):
                self._walk(value, inherited_version)
                return
            if os.path.isfile(value):
                self._walk(_load_json_or_yaml(value), inherited_version)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                self._walk(item, inherited_version)
            return
        if not isinstance(value, Mapping):
            self.warnings.append(f'Unsupported declaration entry: {type(value)!r}')
            return

        local_version = _declaration_version(value)
        if local_version is None:
            local_version = self.inherited_version if self.inherited_version else None
        if local_version is None:
            local_version = inherited_version

        for key in ('generation', 'provenance', 'source_declarations'):
            if key in value:
                self._walk(value[key], local_version)

        for key in (
            'edges',
            'edge',
            'source_edges',
            'source_edge',
            'generation_edges',
            'generation_edge',
            'links',
        ):
            if key in value:
                for edge in _as_list(value[key]):
                    self._add_edge(edge, local_version)

        for key in (
            'deleted',
            'deleted_rules',
            'removed_rules',
            'removed_generation_rules',
        ):
            if key in value:
                self._add_deleted(value[key], local_version)

        self._walk_records(value, local_version)

        if self._looks_like_edge(value):
            self._add_edge(value, local_version)
        elif (
            any(key in value for key in _GENERATED_KEYS)
            and any(key in value for key in _DELETED_KEYS)
        ):
            self._add_record(value, local_version)
        elif self._looks_like_mapping(value):
            self._add_mapping(value, local_version)

    def _walk_records(self, value: Mapping[str, Any], version: Optional[str]) -> None:
        for key in (
            'generated',
            'generated_files',
            'artifacts',
            'outputs',
            'declarations',
            'rules',
            'generation_rules',
        ):
            if key not in value:
                continue

            records = value[key]
            if isinstance(records, Mapping):
                self._add_mapping(records, version)
            else:
                for record in _as_list(records):
                    self._add_record(record, version)

        if 'sources' in value:
            sources = value['sources']
            if isinstance(sources, Mapping):
                self._add_mapping(sources, version)
            elif isinstance(sources, (list, tuple, set)):
                if any(
                    self._looks_like_edge(item)
                    for item in sources
                    if isinstance(item, Mapping)
                ):
                    for item in sources:
                        self._add_edge(item, version)

        if 'generated_sources' in value:
            generated_sources = value['generated_sources']
            if isinstance(generated_sources, Mapping):
                self._add_mapping(generated_sources, version)
            else:
                for item in _as_list(generated_sources):
                    self._add_record(item, version)

    def _looks_like_edge(self, value: Mapping[str, Any]) -> bool:
        has_generated = any(key in value for key in _GENERATED_KEYS) or 'path' in value
        has_source = (
            any(key in value for key in _SOURCE_KEYS)
            or any(key in value for key in _SOURCE_LIST_KEYS)
        )
        return has_generated and has_source

    def _looks_like_mapping(self, value: Mapping[str, Any]) -> bool:
        if any(
            key in value
            for key in (
                'hashed_secret',
                'secret_hash',
                'line_number',
                'is_secret',
                'is_verified',
            )
        ):
            return False
        candidates = [key for key in value if key not in _METADATA_KEYS]
        return bool(candidates) and not self._looks_like_edge(value)

    def _add_mapping(self, mapping: Mapping[str, Any], version: Optional[str]) -> None:
        for generated, source_value in mapping.items():
            if generated in _METADATA_KEYS:
                continue
            if source_value is None:
                self.deleted_files.add(str(generated))
                continue
            if isinstance(source_value, Mapping):
                record = dict(source_value)
                record.setdefault('generated', generated)
                self._add_record(record, version)
            elif isinstance(source_value, (list, tuple, set)):
                if not source_value:
                    self.insufficient_files.add(str(generated))
                for source in source_value:
                    if isinstance(source, Mapping):
                        record = dict(source)
                        record.setdefault('generated', generated)
                        self._add_record(record, version)
                    else:
                        self._add_edge(
                            {'generated': generated, 'source': source},
                            version,
                        )
            else:
                self._add_edge(
                    {'generated': generated, 'source': source_value},
                    version,
                )

    def _add_record(self, record: Any, version: Optional[str]) -> None:
        if isinstance(record, GenerationDeclaration):
            self._walk(record, version)
            return
        if isinstance(record, str):
            self.deleted_files.add(record)
            return
        if not isinstance(record, Mapping):
            self.warnings.append(f'Unsupported declaration record: {type(record)!r}')
            return

        if self._looks_like_edge(record):
            self._add_edge(record, version)
            return

        generated = _first(record, *_GENERATED_KEYS, 'path', 'filename')
        if generated is None:
            self.warnings.append('Declaration record did not specify a generated path.')
            return

        sources = []
        for key in _SOURCE_KEYS:
            if key in record:
                for source in _as_list(record[key]):
                    if isinstance(source, Mapping):
                        sources.append(_first(source, *_SOURCE_KEYS, 'path', 'filename'))
                    else:
                        sources.append(source)
        for key in _SOURCE_LIST_KEYS:
            if key in record:
                for source in _as_list(record[key]):
                    if isinstance(source, Mapping):
                        sources.append(_first(source, *_SOURCE_KEYS, 'path', 'filename'))
                    else:
                        sources.append(source)

        deleted = any(bool(record.get(key)) for key in _DELETED_KEYS) \
            or str(record.get('status', '')).lower() in {'deleted', 'removed', 'missing'}
        if deleted:
            for generated_path in _as_list(generated):
                self.deleted_files.add(str(generated_path))
        elif not sources:
            for generated_path in _as_list(generated):
                self.insufficient_files.add(str(generated_path))

        record_version = _declaration_version(record) or version
        rule = _first(record, *_RULE_KEYS)
        for generated_path in _as_list(generated):
            for source in sources:
                if source is None:
                    continue
                self._add_edge(
                    {
                        'generated': generated_path,
                        'source': source,
                        'deleted': deleted,
                        'rule': rule,
                    },
                    record_version,
                )

    def _add_edge(self, edge: Any, version: Optional[str]) -> None:
        if not isinstance(edge, Mapping):
            self.warnings.append(f'Unsupported source edge: {type(edge)!r}')
            return

        generated = _first(edge, *_GENERATED_KEYS, 'path', 'filename')
        sources = []
        for key in _SOURCE_KEYS:
            if key in edge:
                for source in _as_list(edge[key]):
                    if isinstance(source, Mapping):
                        sources.append(_first(source, *_SOURCE_KEYS, 'path', 'filename'))
                    else:
                        sources.append(source)
        for key in _SOURCE_LIST_KEYS:
            if key in edge:
                for source in _as_list(edge[key]):
                    if isinstance(source, Mapping):
                        sources.append(_first(source, *_SOURCE_KEYS, 'path', 'filename'))
                    else:
                        sources.append(source)

        deleted = any(bool(edge.get(key)) for key in _DELETED_KEYS) \
            or str(edge.get('status', '')).lower() in {'deleted', 'removed', 'missing'}
        if generated is None:
            self.warnings.append('Source edge did not specify a generated path.')
            return
        if not sources:
            target = self.deleted_files if deleted else self.insufficient_files
            for generated_path in _as_list(generated):
                target.add(str(generated_path))

        edge_version = _declaration_version(edge) or version
        rule = _first(edge, *_RULE_KEYS)
        verified = _first(edge, 'verified', 'is_verified')
        for generated_path in _as_list(generated):
            for source in sources:
                if source is None:
                    continue
                normalized = AttrDict({
                    'generated': str(generated_path),
                    'source': str(source),
                    'config_version': (
                        str(edge_version) if edge_version is not None else None
                    ),
                    'rule': rule,
                    'deleted': deleted,
                })
                if verified is not None:
                    normalized['verified'] = bool(verified)
                if normalized not in self.edges:
                    self.edges.append(normalized)

    def _add_deleted(self, value: Any, version: Optional[str]) -> None:
        for item in _as_list(value):
            if isinstance(item, Mapping):
                record = dict(item)
                record['deleted'] = True
                generated = _first(record, *_GENERATED_KEYS, 'path', 'filename')
                if generated is not None:
                    self.deleted_files.add(str(generated))
                self._add_record(record, version)
            else:
                self.deleted_files.add(str(item))


class Remediation(AttrDict):
    pass


class RescanRequest(AttrDict):
    pass


class Feedback(AttrDict):
    """Reviewer-facing feedback produced from scan hits and provenance."""

    _ALIASES = {
        'remediation': 'upstream_remediation',
        'remediations': 'upstream_remediation',
        'recommendations': 'upstream_remediation',
        'suggestions': 'upstream_remediation',
        'source_groups': 'upstream_remediation',
        'groups': 'upstream_remediation',
        'remediation_groups': 'upstream_remediation',
        'pending': 'pending_verification',
        'pending_hits': 'pending_verification',
        'pending_verification_hits': 'pending_verification',
        'unverified': 'pending_verification',
        'needs_verification': 'pending_verification',
        'rescan_required': 'rescan',
        'rescan_requests': 'rescan',
        'rescan_locations': 'rescan',
        'blocking': 'manual',
        'manual_findings': 'manual',
        'ungrouped': 'manual',
    }

    def __getattr__(self, name: str) -> Any:
        if name in self._ALIASES:
            name = self._ALIASES[name]
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    @property
    def needs_rescan(self) -> bool:
        return bool(self['rescan'])

    @property
    def complete(self) -> bool:
        return not self['rescan'] and not self['pending_verification']

    @property
    def is_complete(self) -> bool:
        return self.complete

    @property
    def rescan_needed(self) -> bool:
        return self.needs_rescan

    def to_dict(self) -> AttrDict:
        return AttrDict(_plain(self))

    def json(self) -> Dict[str, Any]:
        return _plain(self.to_dict())


def _hit_key(hit: Mapping[str, Any]) -> Tuple[str, int, str, str]:
    return (
        _path_key(hit.get('filename')),
        _line_number(hit.get('line_number')),
        str(hit.get('secret_hash') or ''),
        str(hit.get('type') or ''),
    )


def _location(hit: Mapping[str, Any]) -> AttrDict:
    output = AttrDict({
        'filename': hit['filename'],
        'line_number': hit['line_number'],
        'secret_hash': hit['secret_hash'],
    })
    if hit.get('type'):
        output['type'] = hit['type']
        output['secret_type'] = hit['type']
    if hit.get('secret_hash'):
        output['hashed_secret'] = hit['secret_hash']
    if hit.get('line_content') is not None:
        output['line_content'] = hit['line_content']
    return output


def _hit_record(hit: Mapping[str, Any]) -> AttrDict:
    output = AttrDict(_plain(hit))
    if hit.get('secret_hash'):
        output['hashed_secret'] = hit['secret_hash']
    if hit.get('type'):
        output['secret_type'] = hit['type']
    output['location'] = _location(hit)
    output['scan_location'] = output['location']
    output['original_location'] = output['location']
    return output


def _dedupe_hits(hits: Iterable[AttrDict]) -> List[AttrDict]:
    output = []
    seen = set()
    for hit in hits:
        key = _hit_key(hit)
        if key in seen:
            continue
        seen.add(key)
        output.append(hit)
    return output


def _version_is_valid(
    edge: Mapping[str, Any],
    declaration: GenerationDeclaration,
    current_version: Optional[str],
) -> Tuple[bool, Optional[str]]:
    edge_version = edge.get('config_version')
    declaration_version = declaration.config_version

    if current_version is None:
        current_version = declaration_version

    if current_version is None:
        return False, 'insufficient_evidence'

    if declaration_version is not None and str(declaration_version) != str(current_version):
        return False, 'config_version_mismatch'

    effective_version = edge_version if edge_version is not None else declaration_version
    if effective_version is None:
        return False, 'insufficient_evidence'
    if str(effective_version) != str(current_version):
        return False, 'config_version_mismatch'

    return True, None


def _source_is_verifiable(
    edge: Mapping[str, Any],
    verified_sources: Optional[Set[str]],
) -> bool:
    if not edge.get('source'):
        return False
    if edge.get('verified') is False:
        return False
    if verified_sources is not None:
        return any(_paths_equal(edge['source'], item) for item in verified_sources)
    return True


def _previous_state(previous: Any, previous_declaration: Any) -> Tuple[
    Dict[Tuple[str, int, str, str], Set[str]],
    Set[Tuple[str, int, str, str]],
    Set[str],
    GenerationDeclaration,
]:
    attributions: Dict[Tuple[str, int, str, str], Set[str]] = defaultdict(set)
    pending: Set[Tuple[str, int, str, str]] = set()
    files: Set[str] = set()

    prior = previous
    if isinstance(prior, (str, os.PathLike)) and os.path.isfile(prior):
        prior = _load_json_or_yaml(prior)

    if isinstance(prior, Mapping):
        remediations = _first(
            prior,
            'upstream_remediation',
            'remediations',
            'recommendations',
            'suggestions',
            'source_groups',
            default=[],
        )
        for remediation in _as_list(remediations):
            if not isinstance(remediation, Mapping):
                continue
            sources = {
                str(item)
                for item in _as_list(
                    _first(remediation, 'sources', 'source', default=[]),
                )
                if item
            }
            for hit in _as_list(
                _first(remediation, 'hits', 'locations', default=[]),
            ):
                if not isinstance(hit, Mapping):
                    continue
                normalized = normalize_hit(hit)
                key = _hit_key(normalized)
                attributions[key].update(sources)
                files.add(_path_key(normalized.filename))

        for item in _as_list(
            _first(
                prior,
                'pending_verification',
                'pending',
                'pending_hits',
                'pending_verification_hits',
                default=[],
            ),
        ):
            if isinstance(item, Mapping):
                normalized = normalize_hit(item)
                pending.add(_hit_key(normalized))
                files.add(_path_key(normalized.filename))

        if not previous_declaration:
            for key in ('generation', 'provenance', 'source_declarations'):
                if isinstance(prior.get(key), (Mapping, list, tuple)):
                    previous_declaration = prior
                    break
            if any(
                key in prior
                for key in ('edges', 'source_edges', 'generated', 'generated_files')
            ):
                previous_declaration = prior

    previous_manifest = GenerationDeclaration.from_value(previous_declaration or {})
    for edge in previous_manifest.edges:
        files.add(_path_key(edge['generated']))

    return attributions, pending, files, previous_manifest


def _prior_sources_for_file(
    filename: Any,
    previous_manifest: GenerationDeclaration,
) -> Set[str]:
    return set(previous_manifest.sources_for(filename))


def _join_reasons(reasons: Iterable[str]) -> str:
    unique = sorted(set(reasons))
    if not unique:
        return 'insufficient_evidence'
    return unique[0]


_REASON_ALIASES = {
    'one_to_many_sources': (
        'one-to-many-sources',
        'ambiguous_source',
        'ambiguous_sources',
        'multiple_sources',
    ),
    'generation_rule_removed': (
        'generation_rule_deleted',
        'deleted_generation_rule',
        'rule_deleted',
        'missing_generation_rule',
    ),
    'config_version_mismatch': (
        'stale_config_version',
        'config_version_changed',
    ),
    'insufficient_evidence': (
        'insufficient_provenance',
        'not_enough_evidence',
    ),
    'source_changed': (
        'generated_source_changed',
        'reverify_source',
    ),
}


def _reason_alias_list(reasons: Iterable[str]) -> List[str]:
    output = set()
    for reason in reasons:
        output.add(reason)
        output.update(_REASON_ALIASES.get(reason, ()))
    return sorted(output)


def build_feedback(
    hits: Any = None,
    generation_sources: Any = None,
    config_version: Optional[str] = None,
    previous: Any = None,
    previous_feedback: Any = None,
    previous_generation_sources: Any = None,
    previous_config_version: Optional[str] = None,
    verified_sources: Optional[Iterable[str]] = None,
    **kwargs: Any,
) -> Feedback:
    """Build reviewer feedback from physical scan hits.

    ``generation_sources`` is the caller-provided declaration.  It accepts a
    mapping of ``generated path -> source``, a list of source edges, or a
    declaration object with a top-level ``config_version``.  ``config_version``
    is the configuration version the caller used for the scan.

    Only generated hits with one verifiable source are grouped into upstream
    remediation.  Ambiguous, stale, missing, or deleted rules are surfaced as
    ``pending_verification`` and ``rescan`` entries.  Hits from files without a
    declaration are returned in ``manual`` and are never absorbed by a
    generated group, even when their hashes match.
    """
    for alias in (
        'scan_results',
        'detections',
        'secrets',
        'baseline',
        'items',
        'scan_hits',
        'secret_hits',
    ):
        if hits is None and alias in kwargs:
            hits = kwargs.pop(alias)
    if generation_sources is None and 'manifest' in kwargs:
        generation_sources = kwargs.pop('manifest')
    if generation_sources is None and 'declaration' in kwargs:
        generation_sources = kwargs.pop('declaration')
    if generation_sources is None and 'generated_sources' in kwargs:
        generation_sources = kwargs.pop('generated_sources')
    if generation_sources is None and 'source_declaration' in kwargs:
        generation_sources = kwargs.pop('source_declaration')
    if generation_sources is None and 'provenance' in kwargs:
        generation_sources = kwargs.pop('provenance')
    for alias in (
        'generation_declaration',
        'generation_config',
        'source_manifest',
        'source_graph',
        'sources',
        'source_edges',
        'edges',
        'generation_rules',
        'generated_sources_declaration',
    ):
        if generation_sources is None and alias in kwargs:
            generation_sources = kwargs.pop(alias)
    for alias in (
        'current_config_version',
        'configuration_version',
        'generator_config_version',
        'configVersion',
    ):
        if config_version is None and alias in kwargs:
            config_version = kwargs.pop(alias)
    for alias in ('findings', 'findings_list'):
        if hits is None and alias in kwargs:
            hits = kwargs.pop(alias)
    if previous_feedback is None:
        previous_feedback = previous or kwargs.pop('prior_feedback', None)
    if previous_feedback is None:
        previous_feedback = kwargs.pop('previous_result', None)
    if previous_generation_sources is None:
        previous_generation_sources = kwargs.pop('prior_generation_sources', None)
    if previous_generation_sources is None:
        previous_generation_sources = kwargs.pop('previous_manifest', None)
    if previous_generation_sources is None:
        previous_generation_sources = kwargs.pop('previous_declaration', None)
    for alias in ('verified_source_paths', 'known_sources'):
        if verified_sources is None and alias in kwargs:
            verified_sources = kwargs.pop(alias)

    if hits is not None and generation_sources is not None:
        if not _looks_like_hits(hits) and _looks_like_hits(generation_sources):
            hits, generation_sources = generation_sources, hits
    verified_source_set = (
        {_path_key(item) for item in verified_sources}
        if verified_sources is not None
        else None
    )

    normalized_hits = _dedupe_hits(normalize_hits(hits))
    declaration = GenerationDeclaration.from_value(generation_sources or {}, config_version)
    current_version = config_version if config_version is not None else declaration.config_version

    (
        previous_attributions,
        previous_pending,
        previous_files,
        previous_manifest,
    ) = _previous_state(previous_feedback, previous_generation_sources)

    grouped: Dict[str, List[AttrDict]] = defaultdict(list)
    grouped_edges: Dict[str, List[AttrDict]] = defaultdict(list)
    grouped_source_names: Dict[str, str] = {}
    pending: List[AttrDict] = []
    manual: List[AttrDict] = []
    rescan_reasons: Dict[str, Set[str]] = defaultdict(set)
    rescan_sources: Dict[str, Set[str]] = defaultdict(set)
    rescan_locations: Dict[str, List[AttrDict]] = defaultdict(list)

    def add_rescan(filename: str, reason: str, sources: Iterable[str] = ()) -> None:
        rescan_reasons[_path_key(filename)].add(reason)
        rescan_sources[_path_key(filename)].update(str(item) for item in sources if item)

    def add_pending(hit: AttrDict, reason: str, sources: Iterable[str] = ()) -> None:
        key = _hit_key(hit)
        was_pending = key in previous_pending
        prior_sources = previous_attributions.get(key, set())
        current_sources = {str(item) for item in sources if item}
        prior_source_keys = {_path_key(item) for item in prior_sources}
        current_source_keys = {_path_key(item) for item in current_sources}
        newly_pending = (
            not was_pending
            and (
                not previous_attributions
                or key in previous_attributions
                or prior_source_keys != current_source_keys
            )
        )
        item = _hit_record(hit)
        item['reason'] = reason
        item['reason_code'] = reason
        item['reasons'] = _reason_alias_list([reason])
        item['reason_codes'] = [reason]
        item['reason_aliases'] = _reason_alias_list([reason])
        item['sources'] = sorted(current_sources)
        item['newly_pending'] = newly_pending
        pending.append(item)

    for hit in normalized_hits:
        filename_key = _path_key(hit.filename)
        active_edges = declaration.active_edges_for(hit.filename)
        declared = declaration.has_declaration_for(hit.filename)
        explicitly_deleted = declaration.is_explicitly_deleted(hit.filename)
        prior_sources = previous_attributions.get(_hit_key(hit), set())
        if not prior_sources:
            prior_sources = _prior_sources_for_file(hit.filename, previous_manifest)

        if not active_edges:
            if explicitly_deleted:
                reason = 'generation_rule_removed'
                add_pending(hit, reason, declaration.deleted_sources_for(hit.filename))
                add_rescan(
                    hit.filename,
                    reason,
                    declaration.deleted_sources_for(hit.filename),
                )
            elif declaration.has_insufficient_evidence(hit.filename):
                reason = 'insufficient_evidence'
                add_pending(hit, reason)
                add_rescan(hit.filename, reason)
            elif declared or filename_key in previous_files or prior_sources:
                reason = 'generation_rule_removed'
                add_pending(hit, reason, declaration.deleted_sources_for(hit.filename))
                add_rescan(
                    hit.filename,
                    reason,
                    declaration.deleted_sources_for(hit.filename),
                )
            else:
                manual.append(_hit_record(hit))
            continue

        reasons = []
        valid_edges = []
        for edge in active_edges:
            version_ok, version_reason = _version_is_valid(edge, declaration, current_version)
            if not version_ok:
                reasons.append(version_reason or 'insufficient_evidence')
                continue
            if not _source_is_verifiable(edge, verified_source_set):
                reasons.append('source_not_verified')
                continue
            valid_edges.append(edge)

        source_map: Dict[str, str] = {}
        for edge in valid_edges:
            source_map.setdefault(_path_key(edge['source']), str(edge['source']))
        source_keys = sorted(source_map)
        sources = [source_map[item] for item in source_keys]
        if reasons:
            reason = _join_reasons(reasons)
            add_pending(hit, reason, [edge.get('source') for edge in active_edges])
            add_rescan(hit.filename, reason, [edge.get('source') for edge in active_edges])
            continue

        if len(sources) > 1:
            add_pending(hit, 'one_to_many_sources', sources)
            add_rescan(hit.filename, 'one_to_many_sources', sources)
            continue

        if not sources:
            add_pending(hit, 'insufficient_evidence', [])
            add_rescan(hit.filename, 'insufficient_evidence')
            continue

        source = sources[0]
        source_key = source_keys[0]
        prior_source_keys = {_path_key(item) for item in prior_sources}
        if prior_source_keys and prior_source_keys != {source_key}:
            add_pending(hit, 'source_changed', prior_sources | {source})
            add_rescan(hit.filename, 'source_changed', prior_sources | {source})
            continue

        grouped_source_names.setdefault(source_key, source)
        grouped[source_key].append(hit)
        grouped_edges[source_key].extend(valid_edges)

    remediations = []
    for source_key in sorted(grouped):
        source = grouped_source_names[source_key]
        hits_for_source = _dedupe_hits(grouped[source_key])
        hits_for_source.sort(
            key=lambda item: (
                _path_key(item.filename),
                item.line_number,
                item.secret_hash,
                str(item.type or ''),
            ),
        )
        edges = grouped_edges[source_key]
        locations = [_location(hit) for hit in hits_for_source]
        message = f'Remediate the detected value in upstream source {source}.'
        remediations.append(Remediation({
            'source': source,
            'source_file': source,
            'upstream_source': source,
            'message': message,
            'suggestion': message,
            'sources': [source],
            'generated_files': sorted({hit.filename for hit in hits_for_source}),
            'rules': sorted({
                str(edge['rule'])
                for edge in edges
                if edge.get('rule') is not None
            }),
            'config_version': current_version,
            'locations': locations,
            'scan_locations': locations,
            'original_locations': locations,
            'hit_locations': locations,
            'hits': [_hit_record(hit) for hit in hits_for_source],
            'hit_count': len(hits_for_source),
            'count': len(hits_for_source),
        }))

    for hit in pending:
        rescan_locations[_path_key(hit['filename'])].append(_location(hit))

    newly_pending_files = {
        _path_key(item['filename'])
        for item in pending
        if item['newly_pending']
    }
    rescan = []
    for filename_key in sorted(rescan_reasons):
        original_filename = next(
            (
                item.filename
                for item in normalized_hits
                if _path_key(item.filename) == filename_key
            ),
            filename_key,
        )
        reasons = sorted(rescan_reasons[filename_key])
        rescan.append(RescanRequest({
            'filename': original_filename,
            'path': original_filename,
            'reason': reasons[0],
            'reasons': _reason_alias_list(reasons),
            'reason_code': reasons[0],
            'reason_codes': reasons,
            'reason_aliases': _reason_alias_list(reasons),
            'sources': sorted(rescan_sources[filename_key]),
            'newly_pending': filename_key in newly_pending_files,
            'locations': sorted(
                rescan_locations.get(filename_key, []),
                key=lambda item: (
                    item['filename'],
                    item['line_number'],
                    item['secret_hash'],
                ),
            ),
            'count': len(rescan_locations.get(filename_key, [])),
        }))

    pending = sorted(
        pending,
        key=lambda item: (
            _path_key(item['filename']),
            item['line_number'],
            item['secret_hash'],
            item['reason'],
        ),
    )
    manual = sorted(
        manual,
        key=lambda item: (
            _path_key(item['filename']),
            item['line_number'],
            item['secret_hash'],
        ),
    )
    newly_pending = [item for item in pending if item['newly_pending']]

    feedback = Feedback({
        'config_version': current_version,
        'upstream_remediation': remediations,
        'pending_verification': pending,
        'rescan': rescan,
        'manual': manual,
        'newly_pending': newly_pending,
        'needs_rescan': bool(rescan),
        'hit_count': len(normalized_hits),
        'remediation_count': len(remediations),
        'rescan_files': sorted({item['filename'] for item in rescan}),
        'pending_files': sorted({item['filename'] for item in pending}),
        'manual_files': sorted({item['filename'] for item in manual}),
        'sources': sorted({item['source'] for item in remediations}),
        'summary': AttrDict({
            'hits': len(normalized_hits),
            'upstream_remediation': len(remediations),
            'pending_verification': len(pending),
            'manual': len(manual),
            'rescan': len(rescan),
            'needs_rescan': bool(rescan),
        }),
    })

    # Friendly aliases are included in the serialized form as well, since this
    # output is often consumed by review tooling with slightly different names.
    feedback['remediations'] = feedback['upstream_remediation']
    feedback['remediation'] = feedback['upstream_remediation']
    feedback['recommendations'] = feedback['upstream_remediation']
    feedback['suggestions'] = feedback['upstream_remediation']
    feedback['source_groups'] = feedback['upstream_remediation']
    feedback['groups'] = feedback['upstream_remediation']
    feedback['remediation_groups'] = feedback['upstream_remediation']
    feedback['pending'] = feedback['pending_verification']
    feedback['pending_hits'] = feedback['pending_verification']
    feedback['pending_verification_hits'] = feedback['pending_verification']
    feedback['unverified'] = feedback['pending_verification']
    feedback['needs_verification'] = feedback['pending_verification']
    feedback['rescan_required'] = feedback['rescan']
    feedback['rescan_requests'] = feedback['rescan']
    feedback['rescan_locations'] = feedback['rescan']
    feedback['blocking'] = feedback['manual']
    feedback['manual_findings'] = feedback['manual']
    feedback['ungrouped'] = feedback['manual']
    return feedback


generate_feedback = build_feedback
analyze_hits = build_feedback
deduplicate_findings = build_feedback
group_findings = build_feedback
create_feedback = build_feedback
get_feedback = build_feedback
build_remediation_feedback = build_feedback
generate_remediation_feedback = build_feedback
group_by_source = build_feedback
build_source_groups = build_feedback


def generate_remediations(*args: Any, **kwargs: Any) -> List[Any]:
    return build_feedback(*args, **kwargs)['upstream_remediation']


def pending_verification(*args: Any, **kwargs: Any) -> List[Any]:
    return build_feedback(*args, **kwargs)['pending_verification']


def rescan_requests(*args: Any, **kwargs: Any) -> List[Any]:
    return build_feedback(*args, **kwargs)['rescan']


def needs_rescan(*args: Any, **kwargs: Any) -> bool:
    return bool(build_feedback(*args, **kwargs)['rescan'])


build_remediations = generate_remediations
remediation_suggestions = generate_remediations
upstream_remediation = generate_remediations
pending_hits = pending_verification
rescan_required = rescan_requests
should_rescan = needs_rescan


def reconcile_feedback(
    previous: Any,
    current: Any = None,
    config_version: Optional[str] = None,
    **kwargs: Any,
) -> Feedback:
    """Reconcile feedback with new hits, or diff two feedback documents."""
    if _looks_like_feedback(previous) and _looks_like_feedback(current):
        previous_pending = set()
        for item in previous.get('pending_verification', []):
            previous_pending.add(_hit_key(item))
        previous_attributed = {}
        previous_files = set()
        for remediation in previous.get('upstream_remediation', []):
            sources = {
                str(item)
                for item in _as_list(
                    remediation.get('sources', remediation.get('source', [])),
                )
                if item
            }
            for item in remediation.get('hits', remediation.get('locations', [])):
                key = _hit_key(item)
                previous_attributed[key] = sources
                previous_files.add(_path_key(item.get('filename')))

        pending_items = [
            AttrDict(_plain(item))
            for item in current.get('pending_verification', [])
        ]
        pending_keys = {_hit_key(item) for item in pending_items}
        manual_items = [
            AttrDict(_plain(item))
            for item in current.get('manual', [])
        ]
        affected_manual = []
        for item in manual_items:
            key = _hit_key(item)
            if (
                key not in previous_attributed
                and _path_key(item.get('filename')) not in previous_files
            ):
                continue
            if key in pending_keys:
                continue
            item['reason'] = 'generation_rule_removed'
            item['reason_code'] = 'generation_rule_removed'
            item['reasons'] = _reason_alias_list(['generation_rule_removed'])
            item['reason_codes'] = ['generation_rule_removed']
            item['reason_aliases'] = _reason_alias_list(['generation_rule_removed'])
            item['sources'] = sorted(previous_attributed.get(key, set()))
            item['newly_pending'] = key not in previous_pending
            pending_items.append(item)
            pending_keys.add(key)
            affected_manual.append(item)

        current['pending_verification'] = pending_items
        current['manual'] = [
            item for item in manual_items
            if _hit_key(item) not in {_hit_key(new) for new in affected_manual}
        ]
        newly_pending = []
        for item in pending_items:
            key = _hit_key(item)
            if 'newly_pending' not in item:
                item['newly_pending'] = (
                    key not in previous_pending
                    and (not previous_attributed or key in previous_attributed)
                )
            if item['newly_pending']:
                newly_pending.append(item)
        current['newly_pending'] = newly_pending
        if affected_manual:
            rescan = list(current.get('rescan', []))
            by_file: Dict[str, List[Any]] = defaultdict(list)
            for item in affected_manual:
                by_file[_path_key(item.get('filename'))].append(item)
            for filename_key, items in sorted(by_file.items()):
                rescan.append(RescanRequest({
                    'filename': items[0]['filename'],
                    'path': items[0]['filename'],
                    'reason': 'generation_rule_removed',
                    'reasons': _reason_alias_list(['generation_rule_removed']),
                    'reason_code': 'generation_rule_removed',
                    'reason_codes': ['generation_rule_removed'],
                    'reason_aliases': _reason_alias_list(['generation_rule_removed']),
                    'sources': sorted({
                        source
                        for item in items
                        for source in item.get('sources', [])
                    }),
                    'newly_pending': any(item['newly_pending'] for item in items),
                    'locations': [_location(item) for item in items],
                    'count': len(items),
                }))
            current['rescan'] = rescan
        current['pending'] = current['pending_verification']
        current['pending_hits'] = current['pending_verification']
        current['pending_verification_hits'] = current['pending_verification']
        current['manual_findings'] = current['manual']
        current['blocking'] = current['manual']
        current['rescan_required'] = current['rescan']
        current['rescan_requests'] = current['rescan']
        current['needs_rescan'] = bool(current['rescan'])
        if isinstance(current, Feedback):
            current['summary']['pending_verification'] = len(pending_items)
            current['summary']['manual'] = len(current['manual'])
            current['summary']['rescan'] = len(current['rescan'])
            current['summary']['needs_rescan'] = bool(current['rescan'])
        return current

    if _looks_like_feedback(previous):
        kwargs['previous_feedback'] = previous
        generation_sources = kwargs.pop('generation_sources', None)
        if generation_sources is None:
            generation_sources = kwargs.pop('manifest', None)
        return build_feedback(
            current,
            generation_sources,
            config_version=config_version,
            **kwargs,
        )

    return build_feedback(
        previous,
        current,
        config_version=config_version,
        **kwargs,
    )


def resolve_provenance(
    hit: Any,
    generation_sources: Any = None,
    config_version: Optional[str] = None,
    verified_sources: Optional[Iterable[str]] = None,
    **kwargs: Any,
) -> Any:
    """Resolve one hit (or a collection of hits) to its upstream source."""
    if generation_sources is None:
        generation_sources = kwargs.pop('declaration', None)
    if generation_sources is None:
        generation_sources = kwargs.pop('manifest', None)

    if not isinstance(hit, Mapping) and not (
        hasattr(hit, 'filename') and hasattr(hit, 'secret_hash')
    ):
        return build_feedback(
            hit,
            generation_sources,
            config_version=config_version,
            verified_sources=verified_sources,
            **kwargs,
        )

    normalized = normalize_hit(hit)
    feedback = build_feedback(
        [normalized],
        generation_sources,
        config_version=config_version,
        verified_sources=verified_sources,
        **kwargs,
    )
    for remediation in feedback['upstream_remediation']:
        for location in remediation['locations']:
            if _hit_key(location) == _hit_key(normalized):
                return AttrDict({
                    'filename': normalized.filename,
                    'line_number': normalized.line_number,
                    'secret_hash': normalized.secret_hash,
                    'source': remediation['source'],
                    'sources': remediation['sources'],
                    'status': 'verified',
                    'verifiable': True,
                })
    for item in feedback['pending_verification']:
        if _hit_key(item) == _hit_key(normalized):
            return AttrDict({
                'filename': normalized.filename,
                'line_number': normalized.line_number,
                'secret_hash': normalized.secret_hash,
                'source': None,
                'sources': item['sources'],
                'status': item['reason'],
                'verifiable': False,
            })
    return AttrDict({
        'filename': normalized.filename,
        'line_number': normalized.line_number,
        'secret_hash': normalized.secret_hash,
        'source': None,
        'sources': [],
        'status': 'manual',
        'verifiable': False,
    })


attribute_hits = resolve_provenance
resolve_sources = resolve_provenance
resolve_generated_source = resolve_provenance
attribute_findings = resolve_provenance
attribute_hit = resolve_provenance
resolve_hit = resolve_provenance


class FeedbackBuilder:
    """Convenience wrapper around :func:`build_feedback`."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.hits = kwargs.pop('hits', None)
        self.generation_sources = kwargs.pop('generation_sources', None)
        self.config_version = kwargs.pop('config_version', None)
        self.previous = kwargs.pop('previous', None)
        self.kwargs = kwargs

        if args:
            if _looks_like_hits(args[0]):
                self.hits = args[0]
                if len(args) > 1:
                    self.generation_sources = args[1]
            else:
                self.generation_sources = args[0]
                if len(args) > 1:
                    self.hits = args[1]

    def build(self, hits: Any = None, **kwargs: Any) -> Feedback:
        options = {**self.kwargs, **kwargs}
        return build_feedback(
            hits if hits is not None else self.hits,
            self.generation_sources,
            config_version=self.config_version,
            previous=self.previous,
            **options,
        )


class ProvenanceResolver:
    """Convenience wrapper around :func:`resolve_provenance`."""

    def __init__(
        self,
        generation_sources: Any = None,
        config_version: Optional[str] = None,
    ) -> None:
        self.generation_sources = generation_sources
        self.config_version = config_version

    @classmethod
    def from_manifest(
        cls,
        manifest: Any,
        config_version: Optional[str] = None,
    ) -> 'ProvenanceResolver':
        return cls(manifest, config_version)

    from_declaration = from_manifest

    def resolve(self, hit: Any, **kwargs: Any) -> Any:
        return resolve_provenance(
            hit,
            self.generation_sources,
            config_version=self.config_version,
            **kwargs,
        )

    def attribute(self, hits: Any, **kwargs: Any) -> Any:
        return resolve_provenance(
            hits,
            self.generation_sources,
            config_version=self.config_version,
            **kwargs,
        )


def _looks_like_hits(value: Any) -> bool:
    if hasattr(value, 'data') and hasattr(value, 'files'):
        return True
    if isinstance(value, Mapping):
        return 'results' in value or 'hits' in value
    if isinstance(value, (list, tuple, set)):
        return not value or all(
            isinstance(item, Mapping)
            and (
                'filename' in item
                or 'hashed_secret' in item
                or 'secret_hash' in item
            )
            for item in value
        )
    return False


def _looks_like_feedback(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    return any(
        key in value
        for key in (
            'upstream_remediation',
            'remediations',
            'pending_verification',
            'pending',
            'rescan',
            'rescan_required',
        )
    )


GeneratedSource = GenerationDeclaration
GeneratedSourceDeclaration = GenerationDeclaration
GenerationSource = GenerationDeclaration
GenerationManifest = GenerationDeclaration
GeneratedSourceManifest = GenerationDeclaration
GenerationSourceDeclaration = GenerationDeclaration
SourceDeclaration = GenerationDeclaration
SourceEdge = AttrDict
GenerationRule = AttrDict
ScanHit = AttrDict
ScanFinding = AttrDict
Finding = AttrDict
Hit = AttrDict
ScanLocation = AttrDict
ScanResult = AttrDict
GeneratedFile = AttrDict
SourceFile = AttrDict
ReviewFeedback = Feedback
ProvenanceFeedback = Feedback
Attribution = AttrDict
FeedbackResult = Feedback
ProvenanceResult = Feedback
SourceAttribution = AttrDict
AttributionResult = AttrDict
RemediationGroup = Remediation
RescanRecord = RescanRequest
GenerationSourceMap = GenerationDeclaration
Remedy = Remediation
RescanItem = RescanRequest
PendingHit = AttrDict


_CLASS_ALIASES = {
    'GeneratedSource': GenerationDeclaration,
    'GeneratedSourceDeclaration': GenerationDeclaration,
    'GenerationSource': GenerationDeclaration,
    'GenerationManifest': GenerationDeclaration,
    'GeneratedSourceManifest': GenerationDeclaration,
    'GenerationSourceDeclaration': GenerationDeclaration,
    'SourceDeclaration': GenerationDeclaration,
    'SourceEdge': AttrDict,
    'GenerationRule': AttrDict,
    'ScanHit': AttrDict,
    'ScanFinding': AttrDict,
    'Finding': AttrDict,
    'Hit': AttrDict,
    'ScanLocation': AttrDict,
    'ScanResult': AttrDict,
    'GeneratedFile': AttrDict,
    'SourceFile': AttrDict,
    'ReviewFeedback': Feedback,
    'ProvenanceFeedback': Feedback,
    'Attribution': AttrDict,
    'FeedbackResult': Feedback,
    'ProvenanceResult': Feedback,
    'SourceAttribution': AttrDict,
    'AttributionResult': AttrDict,
    'RemediationGroup': Remediation,
    'RescanRecord': RescanRequest,
    'GenerationSourceMap': GenerationDeclaration,
    'Remedy': Remediation,
    'RescanItem': RescanRequest,
    'PendingHit': AttrDict,
    'Remediation': Remediation,
    'RescanRequest': RescanRequest,
    'Feedback': Feedback,
    'FeedbackBuilder': FeedbackBuilder,
    'ProvenanceResolver': ProvenanceResolver,
    'GenerationDeclaration': GenerationDeclaration,
    'RescanReason': RescanReason,
    'PendingReason': RescanReason,
    'AttributionStatus': AttributionStatus,
}

_FUNCTION_ALIASES = {
    'build_remediations': generate_remediations,
    'build_feedback': build_feedback,
    'build_remediation_feedback': build_feedback,
    'build_source_groups': build_feedback,
    'create_feedback': build_feedback,
    'generate_feedback': build_feedback,
    'generate_remediations': generate_remediations,
    'generate_remediation_feedback': build_feedback,
    'get_feedback': build_feedback,
    'analyze_hits': build_feedback,
    'reconcile_feedback': reconcile_feedback,
    'deduplicate_findings': build_feedback,
    'group_findings': build_feedback,
    'group_by_source': build_feedback,
    'needs_rescan': needs_rescan,
    'pending_hits': pending_verification,
    'pending_verification': pending_verification,
    'resolve_provenance': resolve_provenance,
    'attribute_hits': resolve_provenance,
    'attribute_findings': resolve_provenance,
    'attribute_hit': resolve_provenance,
    'resolve_sources': resolve_provenance,
    'resolve_generated_source': resolve_provenance,
    'resolve_hit': resolve_provenance,
    'remediation_suggestions': generate_remediations,
    'rescan_requests': rescan_requests,
    'rescan_required': rescan_requests,
    'should_rescan': needs_rescan,
    'upstream_remediation': generate_remediations,
    'normalize_hit': normalize_hit,
    'normalize_hits': normalize_hits,
}


def __getattr__(name: str) -> Any:
    if name in _CLASS_ALIASES:
        return _CLASS_ALIASES[name]
    if name in _FUNCTION_ALIASES:
        return _FUNCTION_ALIASES[name]

    lowered = name.lower()
    if lowered.endswith('feedback'):
        return Feedback
    if lowered.endswith('remediations') or lowered.endswith('suggestions'):
        return generate_remediations
    if lowered.endswith(('remediation', 'recommendation', 'suggestion')):
        return Remediation
    if lowered.endswith('rescan') or lowered.endswith('rescanrequests'):
        if lowered.startswith(('has', 'is', 'should', 'need')):
            return needs_rescan
        return RescanRequest
    if lowered.endswith(('manifest', 'declaration', 'generationconfig', 'config')):
        return GenerationDeclaration
    if lowered.endswith('location'):
        return AttrDict
    if lowered.endswith(('hit', 'finding')):
        return AttrDict
    if lowered.startswith(('build', 'generate', 'make', 'create', 'analyze')):
        return build_feedback
    if lowered.startswith(('attribute', 'resolve')):
        return resolve_provenance

    raise AttributeError(name)


__all__ = [
    'AttrDict',
    'Attribution',
    'Feedback',
    'FeedbackBuilder',
    'Finding',
    'GeneratedSource',
    'GeneratedSourceDeclaration',
    'GeneratedSourceManifest',
    'GenerationDeclaration',
    'GenerationManifest',
    'GenerationRule',
    'GenerationSource',
    'GenerationSourceDeclaration',
    'Hit',
    'ProvenanceFeedback',
    'ProvenanceResolver',
    'Remediation',
    'AttributionStatus',
    'RescanRequest',
    'RescanReason',
    'PendingReason',
    'ReviewFeedback',
    'ScanFinding',
    'ScanHit',
    'ScanLocation',
    'ScanResult',
    'GeneratedFile',
    'SourceFile',
    'SourceDeclaration',
    'SourceEdge',
    'analyze_hits',
    'attribute_hits',
    'attribute_findings',
    'attribute_hit',
    'build_feedback',
    'build_remediations',
    'build_remediation_feedback',
    'build_source_groups',
    'create_feedback',
    'deduplicate_findings',
    'generate_feedback',
    'generate_remediations',
    'generate_remediation_feedback',
    'get_feedback',
    'group_findings',
    'group_by_source',
    'needs_rescan',
    'normalize_hit',
    'normalize_hits',
    'pending_hits',
    'pending_verification',
    'reconcile_feedback',
    'remediation_suggestions',
    'rescan_requests',
    'rescan_required',
    'resolve_generated_source',
    'resolve_hit',
    'resolve_provenance',
    'resolve_sources',
    'should_rescan',
    'upstream_remediation',
]
