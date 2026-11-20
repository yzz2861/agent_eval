"""
Scan coverage accounting.

An empty scan result is only meaningful if we know *why* it is empty: a file that
was actually inspected with the configured plugins is strong evidence, whereas a
file that was dropped by workspace scoping, excluded by a filter, or only checked
with rules meant for another file type is not.

This module records, per data source, what happened during a scan:

    - status: whether the source was scanned, excluded, or is unknown
      (e.g. loaded from a historical baseline that predates coverage accounting).
    - strategy: which plugins were actually applicable to the source, and which
      were skipped because they only target other file types.
    - reason: for excluded sources, why they were excluded (and which filter
      made that decision).

Each entry carries a digest of the settings slice it depends on, so that when
filter conditions change, callers can recompute only the affected entries and
carry over the rest (see `CoverageLedger.stale_sources`).
"""
import hashlib
import json
from enum import Enum
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from ..settings import get_filters
from ..settings import get_settings
from ..util.filetype import determine_file_type


class CoverageStatus(Enum):
    # The source was opened and inspected with the configured plugins.
    SCANNED = 'scanned'

    # The source was skipped, for a known reason.
    EXCLUDED = 'excluded'

    # No coverage basis exists (e.g. historical baselines without coverage data).
    UNKNOWN = 'unknown'


class ExclusionReason(Enum):
    # A filename-level filter (e.g. `should_exclude_files`) rejected the source.
    FILTERED_BY_RULE = 'filtered-by-rule'

    # The input was dropped by workspace scoping (e.g. not tracked by git,
    # or a symlink pointing outside of the scanned root).
    NOT_IN_WORKSPACE = 'not-in-workspace'

    # The file could not be decoded as text.
    NON_TEXT_FILE = 'non-text-file'

    # The file could not be opened.
    UNREADABLE = 'unreadable'


class SourceType(Enum):
    FILE = 'file'
    DIFF = 'diff'
    ADHOC = 'adhoc'


class SourceCoverage:
    """Coverage account for a single data source."""

    def __init__(
        self,
        source: str,
        status: CoverageStatus,
        source_type: SourceType = SourceType.FILE,
        reason: Optional[ExclusionReason] = None,
        filter_path: Optional[str] = None,
        plugins_applied: Optional[List[str]] = None,
        plugins_not_applicable: Optional[List[str]] = None,
        config_digest: Optional[str] = None,
    ) -> None:
        self.source = source
        self.status = status
        self.source_type = source_type
        self.reason = reason
        self.filter_path = filter_path
        self.plugins_applied = plugins_applied or []
        self.plugins_not_applicable = plugins_not_applicable or []
        self.config_digest = config_digest or ''

    def json(self) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            'status': self.status.value,
            'source_type': self.source_type.value,
        }
        if self.reason:
            output['reason'] = self.reason.value
        if self.filter_path:
            output['filter'] = self.filter_path
        if self.status is CoverageStatus.SCANNED:
            output['plugins_applied'] = sorted(self.plugins_applied)
            output['plugins_not_applicable'] = sorted(self.plugins_not_applicable)
        if self.config_digest:
            output['config_digest'] = self.config_digest

        return output

    @classmethod
    def load_from_dict(cls, source: str, data: Dict[str, Any]) -> 'SourceCoverage':
        return cls(
            source=source,
            status=CoverageStatus(data['status']),
            source_type=SourceType(data.get('source_type', 'file')),
            reason=ExclusionReason(data['reason']) if data.get('reason') else None,
            filter_path=data.get('filter'),
            plugins_applied=data.get('plugins_applied', []),
            plugins_not_applicable=data.get('plugins_not_applicable', []),
            config_digest=data.get('config_digest', ''),
        )


class CoverageLedger:
    """
    A ledger of coverage accounts, keyed by data source.

    This answers, for a scan report: which inputs were genuinely inspected,
    which were set aside (and why), and which we have no basis to speak for.
    """

    def __init__(self) -> None:
        self.entries: Dict[str, SourceCoverage] = {}

    def record_scanned(
        self,
        source: str,
        source_type: SourceType = SourceType.FILE,
    ) -> None:
        plugins_applied, plugins_not_applicable = get_plugin_coverage(source)
        self.entries[source] = SourceCoverage(
            source=source,
            status=CoverageStatus.SCANNED,
            source_type=source_type,
            plugins_applied=plugins_applied,
            plugins_not_applicable=plugins_not_applicable,
            config_digest=_digest(_settings_slice_for_scanned()),
        )

    def record_excluded(
        self,
        source: str,
        reason: ExclusionReason,
        filter_path: Optional[str] = None,
        source_type: SourceType = SourceType.FILE,
    ) -> None:
        self.entries[source] = SourceCoverage(
            source=source,
            status=CoverageStatus.EXCLUDED,
            source_type=source_type,
            reason=reason,
            filter_path=filter_path,
            config_digest=_digest(_settings_slice_for_exclusion(reason, filter_path)),
        )

    def record_unknown(
        self,
        source: str,
        source_type: SourceType = SourceType.FILE,
    ) -> None:
        self.entries[source] = SourceCoverage(
            source=source,
            status=CoverageStatus.UNKNOWN,
            source_type=source_type,
        )

    def stale_sources(self) -> Set[str]:
        """
        Returns the sources whose recorded coverage no longer matches the current
        settings, and therefore need to be recomputed. Entries whose relevant
        settings slice is unchanged are not affected, and can be carried over.
        """
        return {
            source
            for source, entry in self.entries.items()
            if entry.status is not CoverageStatus.UNKNOWN
            and entry.config_digest != _current_digest_for(entry)
        }

    def carried_over(self) -> 'CoverageLedger':
        """
        Returns a new ledger with only the entries that are still valid under the
        current settings. This is the complement of `stale_sources`: when filter
        conditions change, only the stale part needs to be recomputed.
        """
        stale = self.stale_sources()

        output = CoverageLedger()
        output.entries = {
            source: entry
            for source, entry in self.entries.items()
            if source not in stale
        }
        return output

    def missing_evidence(self) -> Dict[str, List[str]]:
        """
        Sources that a zero-finding report cannot vouch for: either they were
        excluded (with a recorded reason), or their coverage basis is unknown.
        Sources that were scanned without any applicable plugin (e.g. the
        configured rules only target another file type) are also called out,
        since nothing genuinely checked them.
        """
        output = {
            status.value: [
                source
                for source, entry in self.entries.items()
                if entry.status is status
            ]
            for status in (CoverageStatus.EXCLUDED, CoverageStatus.UNKNOWN)
        }
        output['unchecked'] = [
            source
            for source, entry in self.entries.items()
            if entry.status is CoverageStatus.SCANNED and not entry.plugins_applied
        ]

        return {
            key: sorted(sources)
            for key, sources in output.items()
        }

    def is_sufficient_for_release(self) -> bool:
        """
        A report with zero findings only supports release if every input was
        genuinely scanned with at least one applicable plugin. Excluded,
        unknown, or unchecked sources require more evidence.
        """
        return bool(self.entries) and all(
            entry.status is CoverageStatus.SCANNED
            and entry.plugins_applied
            for entry in self.entries.values()
        )

    def json(self) -> Dict[str, Any]:
        return {
            'sources': {
                source: self.entries[source].json()
                for source in sorted(self.entries)
            },
        }

    @classmethod
    def load_from_baseline(cls, baseline: Dict[str, Any]) -> 'CoverageLedger':
        """
        Reads the coverage account from a baseline. Historical baselines predate
        this feature, and are still readable: positions without a coverage basis
        are preserved as unknown.
        """
        output = cls()
        coverage = baseline.get('coverage')
        if coverage:
            for source, data in coverage.get('sources', {}).items():
                output.entries[source] = SourceCoverage.load_from_dict(source, data)

            return output

        for source in baseline.get('results', {}):
            output.record_unknown(source)

        return output

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, CoverageLedger):
            raise NotImplementedError

        return self.json() == other.json()

    def __len__(self) -> int:
        return len(self.entries)


def get_plugin_coverage(filename: str) -> Tuple[List[str], List[str]]:
    """
    Determines the check strategy for a given file: which of the configured
    plugins actually apply to it, and which only target other file types.

    Plugins apply to all files unless they declare `applicable_file_types`.
    """
    from ..settings import get_plugins

    file_type = determine_file_type(filename)

    applied: List[str] = []
    not_applicable: List[str] = []
    for plugin in get_plugins():
        applicable_file_types = getattr(plugin, 'applicable_file_types', None)
        if applicable_file_types is not None and file_type not in applicable_file_types:
            not_applicable.append(plugin.secret_type)
        else:
            applied.append(plugin.secret_type)

    return applied, not_applicable


def _digest(payload: Any) -> str:
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha1(serialized.encode()).hexdigest()


def _file_level_filter_paths() -> Set[str]:
    """Filters that only look at the filename (and not file content)."""
    return {
        filter_fn.path
        for filter_fn in get_filters()
        if filter_fn.injectable_variables <= {'filename'}
    }


def _settings_slice_for_scanned() -> Dict[str, Any]:
    """
    The slice of settings that a scanned entry depends on: the plugin
    configuration, and all filters that inspect file content. Filename-level
    filters are irrelevant here, since the file was already selected for scanning.
    """
    settings_json = get_settings().json()
    file_level_paths = _file_level_filter_paths()

    return {
        'plugins_used': settings_json['plugins_used'],
        'filters_used': [
            filter_config
            for filter_config in settings_json['filters_used']
            if filter_config['path'] not in file_level_paths
        ],
    }


def _settings_slice_for_exclusion(
    reason: Optional[ExclusionReason],
    filter_path: Optional[str],
) -> Dict[str, Any]:
    """
    The slice of settings that an excluded entry depends on. Only exclusions
    decided by a configurable filter are sensitive to settings changes; other
    reasons (e.g. workspace scoping) are properties of the input itself.
    """
    if reason is not ExclusionReason.FILTERED_BY_RULE or not filter_path:
        return {}

    return {
        'filter': filter_path,
        'config': get_settings().filters.get(filter_path, {}),
    }


def _current_digest_for(entry: SourceCoverage) -> str:
    """Recomputes the digest for an entry's settings slice, under current settings."""
    if entry.status is CoverageStatus.SCANNED:
        return _digest(_settings_slice_for_scanned())

    if entry.status is CoverageStatus.EXCLUDED:
        return _digest(_settings_slice_for_exclusion(entry.reason, entry.filter_path))

    return ''
