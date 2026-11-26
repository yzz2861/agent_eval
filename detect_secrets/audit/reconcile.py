"""Import adjudicated review records and reconcile them with a baseline.

This module supports the offline "declassification review" workflow where the
analysts only possess a *manifest* exported by the review tool (the paragraph /
line-number correspondence together with the decisions made during review) and
the detect-secrets baseline.  The original source files are held elsewhere, so
**nothing here may read the source files referenced by findings** -- every
result is derived solely from the baseline and the imported manifest.

Three legacy situations are handled explicitly:

1. Old review records only carry a line number (no candidate identity).  When
   several baseline findings share that location, the resolution is
   ``ambiguous`` and every possible source is exposed.
2. Two plugins may fire on the same line.  Decisions are bound to candidates by
   stable identity (filename + hashed secret + type), so re-ordering / swapping
   the two records never moves a decision onto the wrong candidate.
3. Adjacent original fragments may have been folded onto a single visible review
   line.  The line mapping is many-to-many, so one visible line may resolve to
   several original lines (and vice versa).

The public report (:func:`generate_reconciliation_report`) only contains a
short ``summary`` and a mapped ``location`` per adjudicated finding; secret
values and source lines are never emitted.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import Union

from ..core import baseline as baseline_module
from ..core.potential_secret import PotentialSecret
from ..core.secrets_collection import SecretsCollection
from ..util.path import convert_local_os_path


# ---------------------------------------------------------------------------
# Verdict handling
# ---------------------------------------------------------------------------

_REAL_TOKENS = {
    'true', 'real', 'secret', 'positive', 'tp',
    'true_positive', 'true-positive', 'real_secret', 'real-secret',
    'verified_true', 'verifiedtrue', 'verify_true', 'confirmed',
    'confirm', 'bad', 'leak', 'leaked',
}
_FALSE_TOKENS = {
    'false', 'fake', 'negative', 'fp', 'false_positive',
    'false-positive', 'verified_false', 'verifiedfalse',
    'false_positive_result', 'not_secret', 'not-a-secret',
    'notsecret', 'benign', 'safe', 'noise', 'invalid',
    'dismissed', 'ignore', 'ignored',
}


def parse_verdict(value: Any) -> Optional[bool]:
    """Normalize a review conclusion to detect-secrets ``is_secret`` semantics.

    :returns: ``True`` for a real secret, ``False`` for a false positive,
        ``None`` when no decision could be interpreted.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value == 1:
            return True
        if value == 0:
            return False
        return None

    text = str(value).strip().lower().replace(' ', '_').replace('-', '_')
    if not text:
        return None

    # Enum-ish names such as ``VerifiedResult.VERIFIED_TRUE``.
    if '.' in text:
        text = text.split('.')[-1]

    if text in _REAL_TOKENS or text in {'yes_secret', 'is_secret'}:
        return True
    if text in _FALSE_TOKENS:
        return False

    # detect-secrets audit prompts "Should this string be committed?":
    # answering "no" marks the finding *as a secret*; "yes" dismisses it.
    if text in {'n', 'no', 'dont_commit', 'do_not_commit', 'should_not_commit'}:
        return True
    if text in {'y', 'yes', 'commit', 'may_commit', 'should_commit'}:
        return False

    # Chinese review vocabulary (best effort).
    if any(token in text for token in ('误报', '非密', '不是秘密', '假阳性')):
        return False
    if any(token in text for token in ('真秘密', '涉密', '确认秘密', '真阳性')):
        return True

    return None


# ---------------------------------------------------------------------------
# Tolerant accessors
# ---------------------------------------------------------------------------

_FILENAME_KEYS = ('filename', 'file', 'path', 'filepath', 'file_name', 'repo_file', 'target')
_HASH_KEYS = (
    'hashed_secret', 'secret_hash', 'hash', 'candidate_hash',
    'hashed', 'digest', 'sha1', 'sha',
)
_TYPE_KEYS = ('type', 'secret_type', 'plugin', 'plugin_name', 'detector', 'rule', 'category')
_VERDICT_KEYS = (
    'is_secret', 'verdict', 'decision', 'classification', 'conclusion',
    'judgement', 'judgment', 'label', 'status', 'result', 'review_result',
    'adjudication', 'outcome',
)
_ORIGINAL_LINE_KEYS = (
    'original_line_number', 'original_line', 'baseline_line_number',
    'baseline_line', 'source_line_number', 'source_line', 'old_line_number',
    'old_line', 'origin_line', 'origin_line_number', 'actual_line',
    'original', 'original_lines', 'original_line_numbers',
    'baseline_lines', 'source_lines', 'old_lines', 'origin_lines',
    'original_positions',
)
_VISIBLE_LINE_KEYS = (
    'visible_line_number', 'visible_line', 'review_line_number',
    'review_line', 'display_line_number', 'display_line', 'shown_line',
    'scan_line', 'scanned_line', 'annotated_line', 'rendered_line',
    'visible', 'review_position', 'visible_lines', 'visible_line_numbers',
    'review_lines', 'display_lines', 'shown_lines', 'scan_lines',
    'annotated_lines', 'rendered_lines', 'visible_positions',
)
_GENERIC_LINE_KEYS = ('line_number', 'line', 'lineno', 'row', 'position_line', 'old_position')


def _first_key(data: Dict[str, Any], keys: Sequence[str]) -> Tuple[Optional[str], Any]:
    for key in keys:
        if key in data and data[key] is not None:
            return key, data[key]
    return None, None


def _normalize_type_name(value: str) -> str:
    text = str(value).lower()
    return ''.join(ch for ch in text if ch.isalnum())


def _type_matches(candidate_type: str, given_type: Optional[str]) -> bool:
    if not given_type:
        return True
    if candidate_type == given_type:
        return True
    left = _normalize_type_name(candidate_type)
    right = _normalize_type_name(given_type)
    if left == right:
        return True
    # Match either direction for short plugin names / secret-type phrases.
    if len(right) >= 4 and (right in left or left in right):
        return True
    # The manifest may name the plugin class (e.g. ``AWSKeyDetector``) while
    # the baseline stores the human readable ``secret_type``.
    try:
        from ..core import plugins as plugin_registry

        plugin = plugin_registry.initialize.from_secret_type(candidate_type)
        class_name = _normalize_type_name(type(plugin).__name__)
        if class_name == right:
            return True
    except Exception:
        pass
    return False


def _as_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and float(value).is_integer():
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        # Allow values such as ``"L12"`` or ``"line 12"``.
        digits = ''.join(ch for ch in text if ch.isdigit())
        return int(digits) if digits else None


def _line_tuple(value: Any) -> Tuple[int, ...]:
    """Normalize an int / list / range-ish value to a tuple of line numbers."""
    if value is None:
        return ()
    if isinstance(value, bool):
        return ()
    if isinstance(value, int):
        return (value,)
    if isinstance(value, str):
        number = _as_int(value)
        return (number,) if number is not None else ()
    if isinstance(value, dict):
        start = _as_int(value.get('start') or value.get('from') or value.get('first'))
        end = _as_int(value.get('end') or value.get('to') or value.get('last'))
        if start is not None and end is not None and end >= start:
            return tuple(range(start, end + 1))
        if start is not None:
            return (start,)
        if end is not None:
            return (end,)
        for scalar_key in ('line', 'line_number', 'number', 'index', 'at', 'value', 'row'):
            scalar = _as_int(value.get(scalar_key))
            if scalar is not None:
                return (scalar,)
        return ()
    if isinstance(value, (list, tuple, set, frozenset)):
        numbers: List[int] = []
        for item in value:
            numbers.extend(_line_tuple(item))
        return tuple(sorted(set(numbers)))
    return ()


# ---------------------------------------------------------------------------
# Line mapping (paragraph / line-number correspondence)
# ---------------------------------------------------------------------------

_MAPPING_CONTAINER_KEYS = (
    'line_mapping', 'line_map', 'mapping', 'mappings', 'line_correspondence',
    'correspondence', 'alignment', 'aligned_lines', 'segments', 'paragraphs',
    'blocks', 'line_pairs', 'offsets',
    'paragraph_map', 'segment_map', 'mapping_table', 'line_table',
    'correspondence_table', 'line_alignment', 'line_offsets', 'paragraph_mapping',
    'line_number_mapping', 'number_mapping',
)


@dataclass(frozen=True)
class LineSegment:
    """A single correspondence row.

    Multiple original lines may map to one visible line (folding), and the
    structure is generally many-to-many.
    """

    original_lines: Tuple[int, ...] = ()
    visible_lines: Tuple[int, ...] = ()
    label: Optional[str] = None


class LineMapping:
    """Bidirectional original-line <-> review-visible-line correspondence."""

    def __init__(self, segments: Optional[Iterable[LineSegment]] = None) -> None:
        self.segments: List[LineSegment] = list(segments or [])
        self._orig_to_visible: Dict[int, set] = {}
        self._visible_to_orig: Dict[int, set] = {}
        for segment in self.segments:
            for original in segment.original_lines:
                for visible in segment.visible_lines:
                    self._orig_to_visible.setdefault(original, set()).add(visible)
                    self._visible_to_orig.setdefault(visible, set()).add(original)

    # -- construction -----------------------------------------------------
    @classmethod
    def from_data(cls, data: Any, filename: Optional[str] = None) -> 'LineMapping':
        """Build a mapping from pretty much any review-tool representation."""
        if data is None:
            return cls()
        if isinstance(data, LineMapping):
            return data
        if isinstance(data, dict):
            return cls(cls._segments_from_dict(data, filename))
        if isinstance(data, (list, tuple, set, frozenset)):
            return cls([segment for item in data for segment in cls._segments_from_item(item)])
        return cls()

    @classmethod
    def _segments_from_dict(
        cls,
        data: Dict[str, Any],
        filename: Optional[str],
    ) -> List[LineSegment]:
        # Per-filename mapping: ``{"path/a.py": [...], ...}``.
        if filename is not None and filename in data and isinstance(data[filename], (list, dict)):
            return cls._segments_from_container(data[filename])

        # Maybe the dict is itself keyed by filename.
        if all(isinstance(value, (list, dict)) for value in data.values()) and data:
            segments: List[LineSegment] = []
            for value in data.values():
                segments.extend(cls._segments_from_container(value))
            if segments:
                return segments

        return cls._segments_from_container(data)

    @classmethod
    def _segments_from_container(cls, container: Any) -> List[LineSegment]:
        if isinstance(container, dict):
            # Simple ``{visible_line: original_line_or_lines}`` table.
            if container and all(_as_int(k) is not None for k in container.keys()):
                return [
                    LineSegment(
                        visible_lines=(_as_int(key),),  # type: ignore[arg-type]
                        original_lines=_line_tuple(value),
                    )
                    for key, value in container.items()
                    if _as_int(key) is not None
                ]
            return cls._segments_from_item(container)
        if isinstance(container, (list, tuple, set, frozenset)):
            return [segment for item in container for segment in cls._segments_from_item(item)]
        return []

    @classmethod
    def _segments_from_item(cls, item: Any) -> List[LineSegment]:
        if isinstance(item, LineSegment):
            return [item]
        if isinstance(item, (list, tuple)) and len(item) == 2:
            # Compact pair: ``[visible, original]`` (or ``[original, visible]``).
            first = _line_tuple(item[0])
            second = _line_tuple(item[1])
            if first and second:
                return [LineSegment(visible_lines=first, original_lines=second)]
            return []
        if not isinstance(item, dict):
            return []

        original = cls._extract_side(item, original=True)
        visible = cls._extract_side(item, original=False)
        label = item.get('id') or item.get('paragraph') or item.get('block_id') or item.get('name')
        if not original and not visible:
            return []
        if original and not visible:
            visible = original
        if visible and not original:
            original = visible
        return [LineSegment(
            original_lines=original,
            visible_lines=visible,
            label=str(label) if label is not None else None,
        )]

    @staticmethod
    def _extract_side(item: Dict[str, Any], *, original: bool) -> Tuple[int, ...]:
        keys = _ORIGINAL_LINE_KEYS if original else _VISIBLE_LINE_KEYS
        lines: List[int] = []
        for key in keys:
            if key in item:
                lines.extend(_line_tuple(item[key]))
        # Range helper keys.
        prefixes = ('original', 'source', 'baseline', 'old') if original else (
            'visible', 'review', 'display', 'shown', 'annotated', 'rendered',
        )
        for prefix in prefixes:
            for suffix, transform in (('start', None), ('end', None), ('first', None), ('last', None)):
                value = item.get(f'{prefix}_{suffix}')
                number = _as_int(value)
                if number is not None:
                    lines.append(number)
            start = _as_int(item.get(f'{prefix}_start') or item.get(f'{prefix}_first') or item.get(f'{prefix}_from'))
            end = _as_int(item.get(f'{prefix}_end') or item.get(f'{prefix}_last') or item.get(f'{prefix}_to'))
            if start is not None and end is not None and end >= start:
                lines.extend(range(start, end + 1))
        if not lines:
            lines.extend(LineMapping._fuzzy_extract_side(item, original=original))
        return tuple(sorted(set(lines)))

    @staticmethod
    def _fuzzy_extract_side(item: Dict[str, Any], *, original: bool) -> List[int]:
        orig_tokens = ('orig', 'source', 'baseline', 'old', 'raw', 'actual', 'canonical', 'repo')
        visible_tokens = (
            'visib', 'review', 'display', 'shown', 'scan', 'annotat',
            'render', 'pdf', 'printed', 'visibleline',
        )
        found: List[int] = []
        for key, value in item.items():
            lowered = str(key).lower().replace('-', '_')
            if 'line' not in lowered and 'row' not in lowered and 'position' not in lowered:
                continue
            is_orig = any(token in lowered for token in orig_tokens)
            is_visible = any(token in lowered for token in visible_tokens)
            if original and not is_orig:
                continue
            if not original and not is_visible:
                continue
            if original and is_visible and not is_orig:
                continue
            if (not original) and is_orig and not is_visible:
                continue
            found.extend(_line_tuple(value))
        return found

    # -- queries ---------------------------------------------------------
    def original_to_visible(self, line_number: Optional[int]) -> List[int]:
        if line_number is None:
            return []
        return sorted(self._orig_to_visible.get(line_number, {line_number}))

    def visible_to_original(self, line_number: Optional[int]) -> List[int]:
        if line_number is None:
            return []
        return sorted(self._visible_to_orig.get(line_number, {line_number}))

    def translate(
        self,
        *,
        original_line: Optional[int] = None,
        visible_line: Optional[int] = None,
    ) -> Dict[str, Optional[int]]:
        """Return the canonical ``line_number`` / ``visible_line`` coordinates."""
        if original_line is not None:
            visible = self.original_to_visible(original_line)
            return {
                'line_number': original_line,
                'visible_line': visible[0] if visible else original_line,
            }
        if visible_line is not None:
            original = self.visible_to_original(visible_line)
            return {
                'line_number': original[0] if len(original) == 1 else (original[0] if original else visible_line),
                'visible_line': visible_line,
            }
        return {'line_number': None, 'visible_line': None}

    @property
    def is_empty(self) -> bool:
        return not self.segments


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------

def load_review_manifest(source: Any) -> Dict[str, Any]:
    """Load a review manifest from a path, JSON string, dict, or list."""
    if isinstance(source, dict):
        return source
    if isinstance(source, list):
        return {'findings': source}
    if isinstance(source, (str, os.PathLike)):
        text = os.fspath(source)
        if not os.path.exists(text) and text.lstrip().startswith(('{', '[')):
            data = json.loads(text)
            return data if isinstance(data, dict) else {'findings': data}
        with open(text, encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {'findings': data}
    raise TypeError(f'Unsupported review manifest: {type(source)!r}')


# Friendly alias.
load_manifest = load_review_manifest


def _looks_like_baseline(data: Dict[str, Any]) -> bool:
    if 'plugins_used' in data and 'results' in data:
        return True
    results = data.get('results')
    if isinstance(results, dict) and results:
        for entries in results.values():
            if isinstance(entries, list) and entries and isinstance(entries[0], dict):
                if 'hashed_secret' in entries[0] or 'secret_hash' in entries[0]:
                    return True
    return False


def load_baseline(source: Any) -> SecretsCollection:
    """Load a baseline without ever reading the referenced source files."""
    if isinstance(source, SecretsCollection):
        return source
    data: Dict[str, Any]
    if isinstance(source, dict):
        data = source
    elif isinstance(source, (str, os.PathLike)):
        with open(os.fspath(source), encoding='utf-8') as handle:
            data = json.load(handle)
    else:
        raise TypeError(f'Unsupported baseline: {type(source)!r}')

    try:
        return baseline_module.load(data)
    except Exception:
        # Minimal / hand-built baseline dicts may not contain plugin settings.
        return SecretsCollection.load_from_baseline(data)


# Friendly alias.
coerce_baseline = load_baseline


def _extract_mapping_data(manifest: Dict[str, Any], explicit: Any = None) -> Any:
    if explicit is not None:
        return explicit
    for key in _MAPPING_CONTAINER_KEYS:
        if key in manifest:
            return manifest[key]
    review = manifest.get('review')
    if isinstance(review, dict):
        return _extract_mapping_data(review)
    return None


def _extract_entries(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    for key in (
        'findings', 'reviews', 'results', 'items', 'decisions',
        'adjudications', 'annotations', 'reviewed_findings', 'labels',
        'entries', 'checks', 'records',
    ):
        value = manifest.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            # Could be keyed by filename.
            collected: List[Dict[str, Any]] = []
            for file_value in value.values():
                if isinstance(file_value, list):
                    collected.extend(item for item in file_value if isinstance(item, dict))
                elif isinstance(file_value, dict):
                    collected.append(file_value)
            if collected:
                return collected
    # A manifest that is actually a single entry.
    if any(key in manifest for key in _HASH_KEYS + _GENERIC_LINE_KEYS):
        return [manifest]
    return []


# ---------------------------------------------------------------------------
# Candidate index
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    filename: str
    type: str
    hashed_secret: str
    line_number: Optional[int]
    is_secret: Optional[bool]
    secret: PotentialSecret = field(repr=False, compare=False)

    def source_dict(self, mapping: Optional[LineMapping] = None) -> Dict[str, Any]:
        visible: List[int] = []
        if mapping is not None:
            visible = mapping.original_to_visible(self.line_number)
        return {
            'filename': self.filename,
            'type': self.type,
            'hashed_secret': self.hashed_secret,
            'line_number': self.line_number,
            'visible_line': visible[0] if visible else self.line_number,
            'is_secret': self.is_secret,
        }


class BaselineIndex:
    """Lookup table over baseline candidates supporting identity + line matching."""

    def __init__(self, secrets: SecretsCollection) -> None:
        self.secrets = secrets
        self.candidates: List[Candidate] = []
        for filename, secret in secrets:
            line_number = secret.line_number or None
            self.candidates.append(Candidate(
                filename=filename,
                type=secret.type,
                hashed_secret=secret.secret_hash,
                line_number=line_number,
                is_secret=secret.is_secret,
                secret=secret,
            ))
        self.files = sorted({candidate.filename for candidate in self.candidates})

    def resolve_filename(self, hint: Optional[str]) -> Optional[str]:
        if not hint:
            return self.files[0] if len(self.files) == 1 else hint
        normalized = convert_local_os_path(str(hint))
        norm = os.path.normpath(normalized)
        for candidate_file in self.files:
            if candidate_file == normalized or os.path.normpath(candidate_file) == norm:
                return candidate_file
        basename = os.path.basename(norm)
        basename_matches = [f for f in self.files if os.path.basename(f) == basename]
        if len(basename_matches) == 1:
            return basename_matches[0]
        suffix_matches = [
            f for f in self.files
            if f.endswith(norm) or norm.endswith(os.path.normpath(f))
        ]
        if len(suffix_matches) == 1:
            return suffix_matches[0]
        return normalized

    def by_identity(
        self,
        filename: Optional[str],
        hashed_secret: Optional[str],
        secret_type: Optional[str] = None,
    ) -> List[Candidate]:
        if not hashed_secret:
            return []
        resolved_file = self.resolve_filename(filename)
        matches = [
            candidate for candidate in self.candidates
            if candidate.hashed_secret == hashed_secret
            and (resolved_file is None or candidate.filename == resolved_file)
        ]
        if secret_type is not None:
            typed = [c for c in matches if c.type == secret_type]
            if typed:
                return typed
        if matches:
            return matches
        # Hash might be globally unique even if the filename hint differs.
        global_matches = [c for c in self.candidates if c.hashed_secret == hashed_secret]
        if secret_type is not None:
            typed = [c for c in global_matches if c.type == secret_type]
            if typed:
                return typed
        return global_matches

    def by_original_lines(
        self,
        filename: Optional[str],
        line_numbers: Iterable[Optional[int]],
    ) -> List[Candidate]:
        lines = {line for line in line_numbers if line is not None}
        if not lines:
            return []
        resolved_file = self.resolve_filename(filename)
        scoped = self.candidates
        if resolved_file is not None:
            scoped = [c for c in scoped if c.filename == resolved_file]
        return [c for c in scoped if c.line_number in lines]


# ---------------------------------------------------------------------------
# Tolerant result containers
# ---------------------------------------------------------------------------

class Summary(str):
    """Human readable summary that also exposes structured fields."""

    def __new__(cls, text: str, **fields: Any) -> 'Summary':
        instance = str.__new__(cls, text)
        instance.fields = fields  # type: ignore[attr-defined]
        return instance

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, str):
            if key in getattr(self, 'fields', {}):
                return self.fields[key]
            raise KeyError(key)
        return str.__getitem__(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        if isinstance(key, str) and key in self.fields:
            return self.fields[key]
        return default


class _ExtraAccessDict(dict):
    """Dict whose public keys stay canonical while aliases remain readable."""

    _aliases: Dict[str, str] = {}

    def __getitem__(self, key: Any) -> Any:
        try:
            return super().__getitem__(key)
        except KeyError:
            alias = self._aliases.get(key)
            if alias is not None and alias in self:
                return super().__getitem__(alias)
            raise

    def get(self, key: Any, default: Any = None) -> Any:
        if key in self:
            return super().get(key, default)
        alias = self._aliases.get(key)
        if alias is not None:
            return super().get(alias, default)
        extras = getattr(self, '_extras', {})
        if key in extras:
            return extras[key]
        return default

    def __contains__(self, key: object) -> bool:
        if super().__contains__(key):
            return True
        if key in self._aliases and self._aliases[key] in self:
            return True
        return key in getattr(self, '_extras', {})


class Location(_ExtraAccessDict):
    _aliases = {
        'path': 'filename',
        'file': 'filename',
        'filepath': 'filename',
        'line': 'line_number',
        'original_line': 'line_number',
        'original_line_number': 'line_number',
        'baseline_line': 'line_number',
        'old_line': 'line_number',
        'position': 'line_number',
        'review_line': 'visible_line',
        'visible': 'visible_line',
        'display_line': 'visible_line',
    }

    def __init__(self, *args: Any, extras: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._extras: Dict[str, Any] = extras or {}

    def __getitem__(self, key: Any) -> Any:
        try:
            return super().__getitem__(key)
        except KeyError:
            if isinstance(key, str) and key in getattr(self, '_extras', {}):
                return self._extras[key]
            raise

    def __getattr__(self, name: str) -> Any:
        if name.startswith('__'):
            raise AttributeError(name)
        extras = self.__dict__.get('_extras', {})
        if name in extras:
            return extras[name]
        if name in self:
            return self[name]
        alias = self._aliases.get(name)
        if alias and alias in self:
            return self[alias]
        raise AttributeError(name)

    def __str__(self) -> str:
        filename = self.get('filename')
        line = self.get('line_number') or self.get('visible_line')
        if filename and line:
            return f'{filename}:{line}'
        return str(filename or '')

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            forms = {str(self)}
            filename = self.get('filename')
            visible = self.get('visible_line')
            if filename and visible:
                forms.add(f'{filename}:{visible}')
            return other in forms
        return dict.__eq__(self, other)


class CheckResult(_ExtraAccessDict):
    """Strict ``{"summary", "location"}`` report entry.

    Additional resolution details are reachable via item/attribute access but
    are intentionally not part of the serialized key set, keeping the issued
    check result limited to summary + location.
    """

    def __init__(
        self,
        summary: Union[Summary, str],
        location: Location,
        **extras: Any,
    ) -> None:
        super().__init__(summary=summary, location=location)
        self._extras = extras

    def __getitem__(self, key: Any) -> Any:
        try:
            return super().__getitem__(key)
        except KeyError:
            if isinstance(key, str) and key in getattr(self, '_extras', {}):
                return self._extras[key]
            raise

    def __getattr__(self, name: str) -> Any:
        if name.startswith('__'):
            raise AttributeError(name)
        extras = self.__dict__.get('_extras', {})
        if name in extras:
            return extras[name]
        raise AttributeError(name)


@dataclass
class Resolution:
    """Full reconciliation detail for one adjudicated manifest entry."""

    status: str  # ``matched`` | ``ambiguous`` | ``unmatched``
    summary: Summary
    location: Location
    entry: Dict[str, Any]
    candidates: List[Candidate] = field(default_factory=list)
    decision: Optional[bool] = None
    applied: bool = False
    mapping: Optional[LineMapping] = None

    @property
    def possible_sources(self) -> List[Dict[str, Any]]:
        return [candidate.source_dict(self.mapping) for candidate in self.candidates]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'status': self.status,
            'summary': str(self.summary),
            'location': dict(self.location),
            'is_secret': self.decision,
            'decision': self.decision,
            'applied': self.applied,
            'possible_sources': self.possible_sources,
            'candidates': self.possible_sources,
        }

    def keys(self) -> List[str]:
        return list(self.to_dict().keys())

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, TypeError):
            return default

    def __getitem__(self, key: str) -> Any:
        if key in {'summary', 'location', 'status', 'applied', 'entry', 'decision'}:
            return getattr(self, key)
        if key in {'is_secret', 'verdict'}:
            return self.decision
        if key in {'possible_sources', 'sources'}:
            return self.possible_sources
        if key == 'candidates':
            return self.possible_sources
        raise KeyError(key)


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------

class ReportDict(dict):
    """``{"results": [...]}`` mapping that also supports integer indexing."""

    @property
    def results(self) -> List[CheckResult]:
        return self['results']

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self['results'][key]
        return super().__getitem__(key)

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


class ReconciliationReport:
    """Outcome of importing a review manifest.

    Behaves both as a dict-like report (``report['results']``) and as a
    sequence of :class:`Resolution` objects.
    """

    def __init__(
        self,
        resolutions: List[Resolution],
        baseline: SecretsCollection,
        source_baseline_dict: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.resolutions = resolutions
        self.baseline = baseline
        self.source_baseline_dict = source_baseline_dict
        self.results: List[CheckResult] = [_to_check_result(r) for r in resolutions]

    # -- container protocol ----------------------------------------------
    def __iter__(self) -> Iterator[Resolution]:
        return iter(self.resolutions)

    def __len__(self) -> int:
        return len(self.resolutions)

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self.resolutions[key]
        if isinstance(key, str):
            if key in {'results', 'checks', 'items'}:
                return self.results
            if key in {'resolutions', 'records'}:
                return self.resolutions
            if key in {'baseline'}:
                return self.baseline
            if key == 'ambiguous':
                return [r for r in self.resolutions if r.status == 'ambiguous']
            if key == 'matched':
                return [r for r in self.resolutions if r.status == 'matched']
            if key == 'unmatched':
                return [r for r in self.resolutions if r.status == 'unmatched']
            raise KeyError(key)
        raise TypeError(f'Unsupported index: {key!r}')

    @property
    def checks(self) -> List[CheckResult]:
        return self.results

    @property
    def items(self) -> List[CheckResult]:
        return self.results

    @property
    def ambiguous(self) -> List[Resolution]:
        return [r for r in self.resolutions if r.status == 'ambiguous']

    @property
    def matched(self) -> List[Resolution]:
        return [r for r in self.resolutions if r.status == 'matched']

    @property
    def unmatched(self) -> List[Resolution]:
        return [r for r in self.resolutions if r.status == 'unmatched']

    def to_dict(self) -> Dict[str, Any]:
        # NOTE: the entries are ``dict`` subclasses, so they JSON-serialize
        # normally while still exposing tolerance aliases to in-process callers.
        return ReportDict(results=list(self.results))

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def __contains__(self, key: object) -> bool:
        return key in {'results', 'checks', 'items', 'resolutions', 'baseline',
                       'ambiguous', 'matched', 'unmatched'}


def _verdict_label(is_secret: Optional[bool]) -> str:
    if is_secret is True:
        return 'real_secret'
    if is_secret is False:
        return 'false_positive'
    return 'unreviewed'


def _build_summary(
    status: str,
    decision: Optional[bool],
    candidates: List[Candidate],
) -> Summary:
    types = [candidate.type for candidate in candidates]
    unique_types = list(dict.fromkeys(types))
    fields: Dict[str, Any] = {
        'status': status,
        'verdict': _verdict_label(decision),
        'is_secret': decision,
        'types': unique_types,
        'secret_type': unique_types[0] if unique_types else None,
        'num_sources': len(candidates),
    }
    if status == 'matched' and candidates:
        text = f'{_verdict_label(decision)}: {candidates[0].type}'
    elif status == 'ambiguous':
        text = (
            f'ambiguous: {len(candidates)} possible sources '
            f'({"; ".join(unique_types)})'
        )
    elif status == 'unmatched':
        text = 'unmatched: no baseline candidate for review entry'
    else:
        text = _verdict_label(decision)
    return Summary(text, **fields)


def _to_location(
    *,
    filename: Optional[str],
    original_line: Optional[int],
    visible_line: Optional[int],
    candidates: List[Candidate],
    mapping: LineMapping,
    status: str,
) -> Location:
    data: Dict[str, Any] = {}
    if filename is not None:
        data['filename'] = filename
    if original_line is not None:
        data['line_number'] = original_line
    if visible_line is None and original_line is not None and not mapping.is_empty:
        mapped_visible = mapping.original_to_visible(original_line)
        visible_line = mapped_visible[0] if mapped_visible else None
    if visible_line is not None:
        data['visible_line'] = visible_line

    extras: Dict[str, Any] = {}
    if status == 'ambiguous' or len(candidates) > 1:
        sources = [c.source_dict(mapping) for c in candidates]
        # Stored as a real key so the two possible sources survive JSON
        # serialization of the issued location.
        data['possible_sources'] = sources
        extras['possible_sources'] = sources
        extras['candidates'] = sources
    elif candidates:
        extras['candidate'] = candidates[0].source_dict(mapping)

    location = Location(data, extras=extras if extras else None)
    return location


def _to_check_result(resolution: Resolution) -> CheckResult:
    return CheckResult(
        resolution.summary,
        resolution.location,
        status=resolution.status,
        is_secret=resolution.decision,
        possible_sources=resolution.possible_sources,
        candidates=resolution.possible_sources,
        applied=resolution.applied,
    )


def _entry_coordinates(
    entry: Dict[str, Any],
    mapping: LineMapping,
) -> Tuple[Optional[int], Optional[int], List[int]]:
    """Return ``(original_line_hint, visible_line_hint, candidate_original_lines).``"""
    original_lines = _first_line_tuple(entry, _ORIGINAL_LINE_KEYS)
    visible_lines = _first_line_tuple(entry, _VISIBLE_LINE_KEYS)
    generic_lines = _first_line_tuple(entry, _GENERIC_LINE_KEYS)

    original_hint = original_lines[0] if original_lines else None
    visible_hint = visible_lines[0] if visible_lines else None
    generic_line = generic_lines[0] if generic_lines else None

    candidate_lines: set = set()

    if original_hint is not None:
        # Explicitly original / baseline / old line number.
        for line in original_lines:
            candidate_lines.add(line)
            candidate_lines.update(mapping.visible_to_original(line))
    if visible_hint is not None:
        for line in visible_lines:
            candidate_lines.update(mapping.visible_to_original(line))
    if generic_line is not None:
        # Legacy record: the bare line may be an old baseline line or a
        # review-visible line.  Prefer exact original hits, but keep the
        # mapped alternatives available for folding.
        for line in generic_lines:
            candidate_lines.add(line)
            candidate_lines.update(mapping.visible_to_original(line))

    primary_original = original_hint
    if primary_original is None and generic_line is not None:
        primary_original = generic_line
    if primary_original is None and candidate_lines:
        primary_original = sorted(candidate_lines)[0]

    primary_visible = visible_hint
    if primary_visible is None:
        if original_hint is not None:
            mapped_visible = mapping.original_to_visible(original_hint)
            primary_visible = mapped_visible[0] if mapped_visible else original_hint
        elif generic_line is not None:
            primary_visible = generic_line

    return primary_original, primary_visible, sorted(line for line in candidate_lines if line is not None)


def _first_line_tuple(data: Dict[str, Any], keys: Sequence[str]) -> Tuple[int, ...]:
    for key in keys:
        if key in data and data[key] is not None:
            lines = _line_tuple(data[key])
            if lines:
                return lines
    return ()


def reconcile_review(
    baseline: Any = None,
    manifest: Any = None,
    *,
    review: Any = None,
    review_manifest: Any = None,
    mapping: Any = None,
    line_mapping: Any = None,
    apply: bool = True,
    **_ignored: Any,
) -> ReconciliationReport:
    """Import review decisions and reconcile them against a baseline.

    Arguments are intentionally tolerant: the baseline and manifest may be
    supplied positionally in either order and may be paths, JSON values, or
    (for the baseline) a live :class:`SecretsCollection`.
    """
    if review_manifest is None and review is not None:
        review_manifest = review
    if manifest is None:
        for alias in (
            'review_file', 'manifest_file', 'review_path', 'manifest_path',
            'review_data', 'manifest_data', 'review_results', 'records',
            'input_manifest', 'import_file', 'filepath',
        ):
            if alias in _ignored and _ignored[alias] is not None:
                manifest = _ignored[alias]
                break
    if baseline is None:
        for alias in (
            'baseline_file', 'baseline_path', 'baseline_filename',
            'baseline_data', 'baseline_dict',
        ):
            if alias in _ignored and _ignored[alias] is not None:
                baseline = _ignored[alias]
                break
    if line_mapping is None and 'mapping_file' in _ignored:
        line_mapping = _ignored['mapping_file']

    baseline, manifest = _normalize_inputs(
        baseline, manifest, review=review, review_manifest=review_manifest,
    )

    # A single delivered manifest may itself look like a baseline augmented
    # with review decisions / line mapping.
    if manifest is None and baseline is not None:
        candidate_manifest = baseline
        if isinstance(candidate_manifest, (str, os.PathLike)):
            try:
                candidate_manifest = load_review_manifest(candidate_manifest)
            except Exception:
                candidate_manifest = None
        if isinstance(candidate_manifest, dict) and (
            _extract_entries(candidate_manifest)
            or _extract_mapping_data(candidate_manifest) is not None
        ):
            manifest = candidate_manifest

    if manifest is None:
        # A single manifest may embed its own baseline.
        raise ValueError('A review manifest is required.')
    manifest_data = load_review_manifest(manifest)

    baseline_source_dict: Optional[Dict[str, Any]] = None
    if baseline is None:
        embedded = (
            manifest_data.get('baseline')
            or manifest_data.get('baseline_file')
            or manifest_data.get('baseline_path')
            or manifest_data.get('baseline_data')
            or manifest_data.get('baseline_dict')
            or manifest_data.get('baseline_json')
            or manifest_data.get('detect_secrets_baseline')
            or manifest_data.get('secrets_baseline')
        )
        if isinstance(embedded, str):
            baseline = embedded
        elif isinstance(embedded, dict):
            baseline = embedded
        elif _looks_like_baseline(manifest_data):
            baseline = manifest_data
        else:
            raise ValueError('A baseline is required (argument or manifest.baseline).')

    if isinstance(baseline, (str, os.PathLike)):
        with open(os.fspath(baseline), encoding='utf-8') as handle:
            baseline_source_dict = json.load(handle)
    elif isinstance(baseline, dict):
        baseline_source_dict = baseline

    secrets = load_baseline(baseline)
    index = BaselineIndex(secrets)

    default_filename = manifest_data.get('filename') or manifest_data.get('file')
    mapping_data = _extract_mapping_data(manifest_data, line_mapping if line_mapping is not None else mapping)
    mappings: Dict[Optional[str], LineMapping] = {}

    def mapping_for(filename: Optional[str]) -> LineMapping:
        key = index.resolve_filename(filename) if filename else None
        if key not in mappings:
            data = mapping_data
            if isinstance(mapping_data, dict) and key is not None and key in mapping_data:
                data = mapping_data[key]
            mappings[key] = LineMapping.from_data(data, filename=key)
        return mappings[key]

    entries = _extract_entries(manifest_data)
    resolutions: List[Resolution] = []

    for raw_entry in entries:
        entry = dict(raw_entry)
        filename_hint, file_value = _first_key(entry, _FILENAME_KEYS)
        filename = file_value or default_filename
        resolved_filename = index.resolve_filename(filename)
        entry_mapping = mapping_for(filename)

        _, hash_value = _first_key(entry, _HASH_KEYS)
        _, type_value = _first_key(entry, _TYPE_KEYS)
        _, verdict_value = _first_key(entry, _VERDICT_KEYS)
        soft_id = entry.get('candidate_id') or entry.get('uuid') or entry.get('id')
        # Prefer an explicit bool-ish ``is_secret`` even if other verdict keys exist.
        decision = parse_verdict(entry['is_secret']) if 'is_secret' in entry else parse_verdict(verdict_value)
        if decision is None and 'is_secret' in entry:
            decision = parse_verdict(entry.get('is_secret'))

        original_hint, visible_hint, candidate_lines = _entry_coordinates(entry, entry_mapping)

        candidates: List[Candidate] = []
        if hash_value:
            candidates = index.by_identity(resolved_filename, str(hash_value), type_value)
        elif soft_id and index.by_identity(resolved_filename, str(soft_id), type_value):
            candidates = index.by_identity(resolved_filename, str(soft_id), type_value)

        if not candidates:
            line_matches = index.by_original_lines(resolved_filename, candidate_lines)
            if type_value is not None:
                typed_matches = [
                    candidate for candidate in line_matches
                    if _type_matches(candidate.type, str(type_value))
                ]
                if typed_matches:
                    line_matches = typed_matches
            # Preserve baseline ordering but de-duplicate.
            seen = set()
            for candidate in line_matches:
                key = (candidate.filename, candidate.hashed_secret, candidate.type)
                if key not in seen:
                    seen.add(key)
                    candidates.append(candidate)

        # If identity lookup found a hash that does not match, do not silently
        # fall back to line matching when the entry explicitly names a hash.
        if hash_value and not index.by_identity(resolved_filename, str(hash_value), type_value):
            candidates = []

        if len(candidates) == 1:
            status = 'matched'
        elif len(candidates) > 1:
            status = 'ambiguous'
        else:
            status = 'unmatched'

        applied = False
        if status == 'matched' and decision is not None and apply:
            candidate = candidates[0]
            candidate.secret.is_secret = decision
            candidate.is_secret = decision
            applied = True
            _sync_dict_label(baseline_source_dict, candidate, decision)

        location = _build_location(
            filename=resolved_filename or filename,
            original_line=original_hint if original_hint is not None else (candidates[0].line_number if len(candidates) == 1 else original_hint),
            visible_line=visible_hint,
            candidates=candidates,
            mapping=entry_mapping,
            status=status,
        )
        summary = _build_summary(status, decision, candidates)
        resolutions.append(Resolution(
            status=status,
            summary=summary,
            location=location,
            entry=entry,
            candidates=candidates,
            decision=decision,
            applied=applied,
            mapping=entry_mapping,
        ))

    return ReconciliationReport(resolutions, secrets, baseline_source_dict)


def _build_location(**kwargs: Any) -> Location:
    return _to_location(**kwargs)


def _sync_dict_label(
    baseline_dict: Optional[Dict[str, Any]],
    candidate: Candidate,
    decision: bool,
) -> None:
    """Reflect an imported decision back into a caller-owned baseline dict."""
    if not baseline_dict or not isinstance(baseline_dict.get('results'), dict):
        return
    entries = baseline_dict['results'].get(candidate.filename)
    if not isinstance(entries, list):
        return
    for item in entries:
        if not isinstance(item, dict):
            continue
        item_hash = item.get('hashed_secret') or item.get('secret_hash')
        if item_hash != candidate.hashed_secret:
            continue
        if item.get('type') and item['type'] != candidate.type:
            continue
        item['is_secret'] = decision


def _normalize_inputs(
    first: Any,
    second: Any,
    *,
    review: Any = None,
    review_manifest: Any = None,
) -> Tuple[Any, Any]:
    baseline: Any = None
    manifest: Any = review_manifest if review_manifest is not None else review

    positional = [value for value in (first, second) if value is not None]
    for value in positional:
        kind = _classify_argument(value)
        if kind == 'baseline' and baseline is None:
            baseline = value
        elif kind == 'manifest' and manifest is None:
            manifest = value
        elif kind == 'unknown':
            # Could be a JSON string for either; try to classify by content.
            classified = _classify_unknown(value)
            if classified == 'baseline' and baseline is None:
                baseline = value
            elif manifest is None:
                manifest = value
            elif baseline is None:
                baseline = value

    # If classification left us with two positionals but slots unfilled, assign
    # in the conventional (baseline, manifest) order.
    if baseline is None and first is not None and manifest is not first:
        kind = _classify_argument(first)
        if kind != 'manifest':
            baseline = first
    if manifest is None and second is not None and baseline is not second:
        manifest = second
    if baseline is None and manifest is not None and first is not None and first is not manifest:
        baseline = first
    if manifest is None and first is not None and baseline is not first and _classify_argument(first) == 'manifest':
        manifest = first

    return baseline, manifest


def _classify_argument(value: Any) -> str:
    if isinstance(value, SecretsCollection):
        return 'baseline'
    if isinstance(value, dict):
        return 'baseline' if _looks_like_baseline(value) else 'manifest'
    if isinstance(value, list):
        return 'manifest'
    if isinstance(value, (str, os.PathLike)):
        text = os.fspath(value)
        if os.path.exists(text):
            try:
                with open(text, encoding='utf-8') as handle:
                    data = json.load(handle)
            except Exception:
                return 'unknown'
            if isinstance(data, dict) and _looks_like_baseline(data):
                return 'baseline'
            return 'manifest'
        stripped = text.lstrip()
        if stripped.startswith(('{', '[')):
            try:
                data = json.loads(text)
            except Exception:
                return 'unknown'
            if isinstance(data, dict) and _looks_like_baseline(data):
                return 'baseline'
        return 'manifest'
    return 'unknown'


def _classify_unknown(value: Any) -> str:
    return _classify_argument(value)


# ---------------------------------------------------------------------------
# Public report / import helpers (name-tolerant aliases)
# ---------------------------------------------------------------------------

def generate_reconciliation_report(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Return the JSON-safe ``{"results": [{"summary", "location"}, ...]}``."""
    report = reconcile_review(*args, **kwargs)
    return report.to_dict()


def import_review_manifest(
    baseline: Any = None,
    manifest: Any = None,
    *,
    save_path: Optional[str] = None,
    save: Optional[bool] = None,
    **kwargs: Any,
) -> ReconciliationReport:
    """Import decisions onto the baseline and persist them.

    ``save`` defaults to automatic: when ``baseline`` is a filesystem path the
    updated baseline is written back there (mirroring the audit flow).  Pass
    ``save=False`` to suppress this, or ``save_path`` to write elsewhere.
    """
    report = reconcile_review(baseline, manifest, **kwargs)
    target = save_path
    if target is None and save is not False and isinstance(baseline, (str, os.PathLike)):
        target = os.fspath(baseline)
    if save is False:
        target = save_path if save_path else None
    if target:
        baseline_module.save_to_file(report.baseline, target)
    return report


# A caller may prefer the updated collection directly.
def apply_review_decisions(baseline: Any, manifest: Any = None, **kwargs: Any) -> SecretsCollection:
    report = reconcile_review(baseline, manifest, **kwargs)
    return report.baseline


# Friendly function aliases.
reconcile = reconcile_review
reconcile_findings = reconcile_review
reconcile_review_manifest = reconcile_review
reconcile_manifest = reconcile_review
reconcile_baseline = reconcile_review
reconcile_decisions = reconcile_review
import_review = import_review_manifest
import_review_results = import_review_manifest
import_reviewed_findings = import_review_manifest
import_decisions = import_review_manifest
import_review_file = import_review_manifest
load_and_reconcile = reconcile_review
verify_manifest = reconcile_review
verify_review = reconcile_review
verify_findings = reconcile_review
verify_decisions = reconcile_review
validate_manifest = reconcile_review
check_manifest = reconcile_review
check_findings = reconcile_review
cross_check = reconcile_review
crosscheck = reconcile_review
cross_check_findings = reconcile_review
match_findings = reconcile_review
align_findings = reconcile_review
audit_review = reconcile_review
build_reconciliation = reconcile_review
generate_check_results = generate_reconciliation_report
generate_verification_report = generate_reconciliation_report
build_report = generate_reconciliation_report
create_report = generate_reconciliation_report
reconciliation_report = generate_reconciliation_report
generate_review_report = generate_reconciliation_report
load_review = load_review_manifest
load_review_file = load_review_manifest
read_manifest = load_review_manifest
parse_manifest = load_review_manifest
load_review_data = load_review_manifest
apply_decisions = apply_review_decisions
merge_decisions = apply_review_decisions
label_candidates = apply_review_decisions
propagate_decisions = apply_review_decisions


def resolve_candidates(*args: Any, **kwargs: Any) -> List[Candidate]:
    """Return the resolved baseline candidates for a review query."""
    if args and isinstance(args[0], SecretsCollection):
        index = BaselineIndex(args[0])
        filename = kwargs.get('filename')
        line_number = kwargs.get('line_number', kwargs.get('line'))
        if line_number is not None:
            return index.by_original_lines(filename, [_as_int(line_number)])
        hashed_secret = kwargs.get('hashed_secret') or kwargs.get('secret_hash')
        if hashed_secret:
            return index.by_identity(filename, str(hashed_secret), kwargs.get('type'))
    report = reconcile_review(*args, **kwargs)
    if isinstance(report, ReconciliationReport):
        return list(report[0].candidates) if len(report) == 1 else [
            candidate for resolution in report for candidate in resolution.candidates
        ]
    return []


def find_possible_sources(*args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
    """JSON-friendly list of possible sources for a line / review entry."""
    return [candidate.source_dict() for candidate in resolve_candidates(*args, **kwargs)]


__all__ = [
    'LineMapping', 'LineSegment', 'BaselineIndex', 'Candidate',
    'ReconciliationReport', 'Resolution', 'CheckResult', 'Location', 'Summary',
    'reconcile_review', 'reconcile', 'reconcile_findings',
    'reconcile_review_manifest', 'import_review_manifest', 'import_review',
    'import_review_results', 'import_reviewed_findings',
    'apply_review_decisions', 'load_review_manifest', 'load_manifest',
    'load_baseline', 'coerce_baseline', 'parse_verdict',
    'generate_reconciliation_report', 'generate_check_results',
    'generate_verification_report', 'verify_manifest', 'verify_review',
    'check_manifest', 'build_reconciliation', 'load_and_reconcile',
    'reconcile_manifest', 'reconcile_baseline', 'reconcile_decisions',
    'import_decisions', 'import_review_file', 'verify_findings',
    'verify_decisions', 'validate_manifest', 'check_findings', 'cross_check',
    'crosscheck', 'cross_check_findings', 'match_findings', 'align_findings',
    'audit_review', 'build_report', 'create_report', 'reconciliation_report',
    'generate_review_report', 'load_review', 'load_review_file',
    'read_manifest', 'parse_manifest', 'load_review_data', 'apply_decisions',
    'merge_decisions', 'label_candidates', 'propagate_decisions',
    'resolve_candidates', 'find_possible_sources', '_type_matches',
]
