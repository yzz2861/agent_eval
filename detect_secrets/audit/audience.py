"""
Audience-scoped export support for audit reports.

The central security team often needs to hand a report to another party
(an on-call engineer, an outsourcing partner, a business owner) without
disclosing the parts of the report owned by somebody else.  It also needs
to be able to trace the same already-handled finding across a short
retention window.

The caller supplies an :class:`AudienceLedger`: a schedule of audience
periods, their allowed scopes, and the retention window in which a prior
report can still be linked to its successor.  Findings are identified to
an audience only by an :class:`AudiencePeriod`-scoped alias.  The alias is
an HMAC of the internal finding identity, keyed by the audience and the
period.  Consequently:

* the same finding re-exported in the same audience period keeps the
  same alias;
* a new period rotates the alias, but the ledger can attach the previous
  alias while the old report is still retainable;
* another audience receives a different alias, so it cannot merge old and
  new reports by alias;
* raw secret values and the baseline's stable cross-domain digest are
  never written to the export.

The module deliberately accepts both the baseline format and the existing
``audit --report`` output format, so callers can keep using the same
offline report pipeline.
"""
import fnmatch
import hashlib
import hmac
import json
import os
import time
from datetime import date
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Mapping
from typing import NamedTuple
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import Union

from ..constants import VerifiedResult
from ..core import baseline
from ..core.potential_secret import PotentialSecret
from ..core.secrets_collection import SecretsCollection


DEFAULT_PERIOD = timedelta(days=7)
DEFAULT_RETENTION = timedelta(days=7)
DEFAULT_MASTER_KEY = b'detect-secrets-audience-export-v1'

_TIMEZONE = timezone.utc
_ALIAS_LENGTH = 32

_FORBIDDEN_KEYS = {
    'secrets',
    'secret',
    'secret_value',
    'raw_secret',
    'hashed_secret',
    'secret_hash',
    'cross_domain_digest',
    'stable_digest',
    'stable_fingerprint',
    'finding_id',
    'internal_id',
    'lines',
    'line_content',
}


class AudienceLedgerError(ValueError):
    """Base class for ledger/export errors that do not expose secret data."""


class AudienceNotFoundError(AudienceLedgerError):
    pass


class AudienceRequiredError(AudienceLedgerError):
    pass


class PeriodNotFoundError(AudienceLedgerError):
    pass


class PeriodExpiredError(AudienceLedgerError):
    pass


class AudienceMismatchError(AudienceLedgerError):
    pass


class CrossAudienceLinkError(AudienceLedgerError):
    pass


class LinkWindowExpiredError(AudienceLedgerError):
    pass


class ReportLeakError(AudienceLedgerError):
    pass


class ReportVerificationError(AudienceLedgerError):
    pass


class _AliasedDict(dict):
    """A dict that accepts a few spelling variants without serializing them."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._alias_map: Dict[str, str] = kwargs.pop('_alias_map', {})
        super().__init__(*args, **kwargs)

    def _canonical(self, key: Any) -> Any:
        return self._alias_map.get(key, key) if isinstance(key, str) else key

    def __getitem__(self, key: Any) -> Any:
        return super().__getitem__(self._canonical(key))

    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(self._canonical(key), value)

    def __contains__(self, key: Any) -> bool:
        return super().__contains__(self._canonical(key))

    def get(self, key: Any, default: Any = None) -> Any:
        return super().get(self._canonical(key), default)

    def pop(self, key: Any, *args: Any) -> Any:
        return super().pop(self._canonical(key), *args)


_REPORT_ALIASES = {
    'scope_id': 'audience',
    'audience_id': 'audience',
    'epoch': 'period',
    'audience_period': 'period',
    'ledger_period': 'period',
    'findings': 'results',
    'entries': 'results',
    'tracking': 'results',
    'window_start': 'not_before',
    'window_end': 'not_after',
    'retired_findings': 'retired',
    'old_aliases': 'retired_aliases',
    'retired_alias': 'retired_aliases',
    'previous_epoch': 'previous_period',
    'link_until': 'retain_until',
    'link_deadline': 'retain_until',
    'tracking_ids': 'aliases',
    'tracked': 'aliases',
    'tracked_aliases': 'aliases',
}

_ENTRY_ALIASES = {
    'marker': 'alias',
    'tracking_id': 'alias',
    'tracking_token': 'alias',
    'token': 'alias',
    'tracking': 'alias',
    'id': 'alias',
    'file': 'filename',
    'line_number': 'line_numbers',
    'type': 'types',
    'old_alias': 'alias',
    'retired_alias': 'alias',
}


def _as_datetime(value: Any) -> Optional[datetime]:
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, date):
        result = datetime(value.year, value.month, value.day, tzinfo=_TIMEZONE)
    elif isinstance(value, (int, float)):
        result = datetime.fromtimestamp(float(value), tz=_TIMEZONE)
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            result = datetime.fromtimestamp(float(text), tz=_TIMEZONE)
        except (TypeError, ValueError, OverflowError):
            iso = text.replace('Z', '+00:00')
            try:
                result = datetime.fromisoformat(iso)
            except ValueError:
                try:
                    result = datetime.strptime(text, '%Y-%m-%d')
                except ValueError:
                    raise ValueError('Invalid audience period timestamp.')

    if result.tzinfo is None:
        result = result.replace(tzinfo=_TIMEZONE)
    return result.astimezone(_TIMEZONE)


def _as_epoch(value: Any) -> Optional[int]:
    parsed = _as_datetime(value)
    return int(parsed.timestamp()) if parsed else None


def _as_iso(value: Any) -> Optional[str]:
    parsed = _as_datetime(value)
    return _format_datetime(parsed) if parsed else None


def _format_datetime(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.astimezone(_TIMEZONE).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _as_timedelta(value: Any) -> Optional[timedelta]:
    if value is None:
        return None
    if isinstance(value, timedelta):
        return value
    if isinstance(value, (int, float)):
        return timedelta(seconds=float(value))
    text = str(value).strip().lower()
    if text.endswith('d'):
        return timedelta(days=float(text[:-1]))
    if text.endswith('h'):
        return timedelta(hours=float(text[:-1]))
    if text.endswith('s'):
        return timedelta(seconds=float(text[:-1]))
    return timedelta(seconds=float(text))


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value).encode('utf-8')


def _as_text_tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        value = value.keys()
    return tuple(str(item) for item in value)


def _as_ref_tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        value = [value]
    output = []
    for item in value:
        if isinstance(item, Mapping):
            reference = (
                item.get('alias') or item.get('tracking_id') or
                item.get('finding_id') or item.get('secret_hash') or
                item.get('hashed_secret')
            )
            if reference:
                output.append(str(reference))
        elif item is not None:
            output.append(str(item))
    return tuple(output)


def _looks_like_alias(value: str) -> bool:
    return (
        len(value) == _ALIAS_LENGTH and
        all(char in '0123456789abcdefABCDEF' for char in value)
    )


def _path_covers(prefix: str, filename: str) -> bool:
    if prefix == filename:
        return True
    if prefix.endswith(os.sep) or prefix.endswith('/'):
        return filename.startswith(prefix)
    return filename.startswith(prefix.rstrip('/\\') + '/') or filename.startswith(
        prefix.rstrip('/\\') + os.sep,
    )


class AudiencePeriod:
    """One audience's authorization/retention period."""

    def __init__(
        self,
        audience: Optional[str] = None,
        period: Optional[str] = None,
        *,
        scope_id: Optional[str] = None,
        epoch: Optional[str] = None,
        filenames: Optional[Iterable[str]] = None,
        files: Optional[Iterable[str]] = None,
        paths: Optional[Iterable[str]] = None,
        excluded: Optional[Iterable[str]] = None,
        exclude: Optional[Iterable[str]] = None,
        excluded_filenames: Optional[Iterable[str]] = None,
        findings: Optional[Iterable[str]] = None,
        hashed_secrets: Optional[Iterable[str]] = None,
        allowed: Optional[Iterable[str]] = None,
        tracked: Optional[Iterable[str]] = None,
        aliases: Optional[Iterable[str]] = None,
        tracked_aliases: Optional[Iterable[str]] = None,
        tracked_ids: Optional[Iterable[str]] = None,
        tracking_ids: Optional[Iterable[str]] = None,
        not_before: Any = None,
        not_after: Any = None,
        starts_at: Any = None,
        ends_at: Any = None,
        valid_from: Any = None,
        valid_until: Any = None,
        window_start: Any = None,
        window_end: Any = None,
        previous_period: Optional[str] = None,
        previous: Optional[str] = None,
        previous_audience: Optional[str] = None,
        retain_until: Any = None,
        link_until: Any = None,
        retired: Optional[Iterable[str]] = None,
        retired_findings: Optional[Iterable[str]] = None,
        retired_aliases: Optional[Iterable[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        **extra: Any,
    ) -> None:
        self.audience = str(
            audience or scope_id or extra.get('audience_id') or '',
        )
        if not self.audience:
            raise ValueError('An audience period requires an audience or scope_id.')

        start = not_before if not_before is not None else (
            starts_at if starts_at is not None else (
                valid_from if valid_from is not None else (
                    window_start if window_start is not None else (
                        extra.get('period_start', extra.get('start'))
                    )
                )
            )
        )
        end = not_after if not_after is not None else (
            ends_at if ends_at is not None else (
                valid_until if valid_until is not None else (
                    window_end if window_end is not None else (
                        extra.get('period_end', extra.get('end', extra.get('expires_at')))
                    )
                )
            )
        )

        self.not_before = _as_datetime(start)
        self.not_after = _as_datetime(end)
        days = extra.pop('valid_days', extra.pop('window_days', extra.pop('period_days', None)))
        if self.not_after is None and self.not_before is not None:
            self.not_after = self.not_before + (
                timedelta(days=float(days)) if days is not None else DEFAULT_PERIOD
            )

        self.period = str(
            period if period is not None else (
                epoch if epoch is not None else self._default_period()
            ),
        )

        self.filenames = _as_text_tuple(
            filenames if filenames is not None else (
                files if files is not None else (
                    paths if paths is not None else (
                        extra.get('approved_files', extra.get('scope_files', extra.get('scope')))
                    )
                )
            ),
        )
        self.excluded = _as_text_tuple(
            excluded if excluded is not None else (
                exclude if exclude is not None else excluded_filenames
            ),
        )
        raw_findings = _as_text_tuple(
            findings if findings is not None else (
                hashed_secrets if hashed_secrets is not None else (
                    allowed if allowed is not None else (
                        tracked if tracked is not None else extra.get('approved_findings')
                    )
                )
            ),
        )
        alias_mapping = (
            dict(aliases) if isinstance(aliases, Mapping) else dict(
                extra.get('alias_map', extra.get('aliases_by_finding', {})) or {},
            )
        )
        tracked_alias_values = _as_text_tuple(
            tracked_aliases if tracked_aliases is not None else (
                tracked_ids if tracked_ids is not None else tracking_ids
            ),
        )
        if isinstance(aliases, Mapping):
            aliases = tuple(aliases.values())
        alias_like = tuple(value for value in raw_findings if _looks_like_alias(value))
        self.findings = tuple(value for value in raw_findings if value not in alias_like)
        self.alias_map = {
            str(key): str(value)
            for key, value in alias_mapping.items()
        }
        self.aliases = tracked_alias_values or _as_text_tuple(aliases) or alias_like
        self.previous_period = (
            str(previous_period)
            if previous_period is not None
            else (str(previous) if previous is not None else None)
        )
        self.previous_audience = (
            str(previous_audience) if previous_audience is not None else None
        )
        self.retain_until = _as_datetime(
            retain_until if retain_until is not None else link_until,
        )
        self.retired = _as_ref_tuple(
            retired if retired is not None else (
                retired_findings if retired_findings is not None else retired_aliases
            ),
        )
        self.metadata = dict(metadata or {})

    def _default_period(self) -> str:
        if self.not_before is not None:
            return self.not_before.astimezone(_TIMEZONE).strftime('%Y-%m-%dT%H:%M:%SZ')
        return self.audience

    @classmethod
    def from_value(cls, value: Any) -> 'AudiencePeriod':
        if isinstance(value, AudiencePeriod):
            return value
        if isinstance(value, DisclosureScope):
            return audience_period_from_scope(value)
        if isinstance(value, Mapping):
            return cls(**dict(value))
        if isinstance(value, (list, tuple)) and len(value) == 5:
            return cls(
                audience=value[0],
                filenames=value[1],
                period=value[2],
                not_before=value[3],
                not_after=value[4],
            )
        raise TypeError('Expected an audience period mapping.')

    @property
    def scope_id(self) -> str:
        return self.audience

    @property
    def epoch(self) -> str:
        return self.period

    @property
    def starts_at(self) -> Optional[datetime]:
        return self.not_before

    @property
    def ends_at(self) -> Optional[datetime]:
        return self.not_after

    def covers(self, filename: str) -> bool:
        if any(_path_covers(item, filename) for item in self.excluded):
            return False
        if not self.filenames:
            return True
        return any(
            _path_covers(item, filename) or
            fnmatch.fnmatch(filename, item)
            for item in self.filenames
        )

    def is_active(self, at: Optional[Any] = None) -> bool:
        moment = _as_datetime(at) or datetime.now(_TIMEZONE)
        if self.not_before is not None and moment < self.not_before:
            return False
        if self.not_after is not None and moment > self.not_after:
            return False
        return True

    def _replace(self, **changes: Any) -> 'AudiencePeriod':
        aliases = {
            'scope_id': 'audience',
            'epoch': 'period',
            'files': 'filenames',
            'starts_at': 'not_before',
            'ends_at': 'not_after',
        }
        payload = self.as_dict()
        payload.update({aliases.get(key, key): value for key, value in changes.items()})
        return AudiencePeriod(**payload)

    def _asdict(self) -> Dict[str, Any]:
        return self.as_dict()

    def to_dict(self) -> Dict[str, Any]:
        return self.as_dict()

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True)

    def as_dict(self) -> Dict[str, Any]:
        return {
            'audience': self.audience,
            'period': self.period,
            'not_before': _as_epoch(self.not_before),
            'not_after': _as_epoch(self.not_after),
            'starts_at': _as_iso(self.not_before),
            'ends_at': _as_iso(self.not_after),
            'filenames': list(self.filenames),
            'excluded': list(self.excluded),
            'findings': list(self.findings),
            'aliases': list(self.aliases),
            'alias_map': dict(self.alias_map),
            'previous_period': self.previous_period,
            'previous_audience': self.previous_audience,
            'retain_until': _as_epoch(self.retain_until),
            'retired': list(self.retired),
        }

    def __repr__(self) -> str:
        return (
            'AudiencePeriod(audience={!r}, period={!r}, filenames={!r})'
            .format(self.audience, self.period, self.filenames)
        )


class DisclosureScope(NamedTuple):
    """Compatibility view of a single publication scope."""

    scope_id: str
    filenames: Tuple[str, ...]
    epoch: str
    not_before: int
    not_after: int

    def covers(self, filename: str) -> bool:
        return any(_path_covers(item, filename) for item in self.filenames)

    def is_active(self, at_time: int) -> bool:
        if isinstance(at_time, datetime):
            at_time = int(at_time.timestamp())
        return self.not_before <= at_time <= self.not_after


def audience_period_from_scope(scope: DisclosureScope) -> AudiencePeriod:
    return AudiencePeriod(
        audience=scope.scope_id,
        period=scope.epoch,
        filenames=scope.filenames,
        not_before=scope.not_before,
        not_after=scope.not_after,
    )


def disclosure_scope_from_period(period: AudiencePeriod) -> DisclosureScope:
    start = _as_epoch(period.not_before) or 0
    end = _as_epoch(period.not_after) or (2 ** 63 - 1)
    return DisclosureScope(
        scope_id=period.audience,
        filenames=period.filenames,
        epoch=period.period,
        not_before=start,
        not_after=end,
    )


class AudienceLedger:
    """Caller-provided schedule of audience periods and retention windows."""

    def __init__(
        self,
        periods: Optional[Any] = None,
        master_key: Any = None,
        key: Any = None,
        secret: Any = None,
        retention: Any = DEFAULT_RETENTION,
        link_retention: Any = None,
        period_length: Any = DEFAULT_PERIOD,
        clock: Optional[Callable[[], Any]] = None,
        retired_aliases: Optional[Iterable[str]] = None,
        retired_findings: Optional[Iterable[str]] = None,
        **extra: Any,
    ) -> None:
        if 'retention_days' in extra:
            retention = timedelta(days=float(extra.pop('retention_days')))
        if 'link_days' in extra:
            link_retention = timedelta(days=float(extra.pop('link_days')))
        if 'period_days' in extra:
            period_length = timedelta(days=float(extra.pop('period_days')))
        if isinstance(periods, os.PathLike):
            periods = os.fspath(periods)
        if isinstance(periods, str):
            text = periods.strip()
            if text.startswith('{') or text.startswith('['):
                periods = json.loads(text)
            else:
                with open(periods) as handle:
                    periods = json.load(handle)

        data = periods if isinstance(periods, Mapping) else {}

        raw_periods = periods
        if isinstance(periods, AudienceLedger):
            raw_periods = periods.periods
            master_key = master_key or periods.master_key
            retention = periods.retention
            period_length = periods.period_length
            retired_aliases = retired_aliases or periods.retired_aliases
            retired_findings = retired_findings or periods.retired_findings
            clock = clock or periods.clock
        elif isinstance(periods, Mapping):
            raw_periods = (
                periods.get('periods')
                if 'periods' in periods
                else (
                    periods.get('entries')
                    if 'entries' in periods
                    else (
                        periods.get('audience_periods')
                        if 'audience_periods' in periods
                        else (
                            periods.get('scopes', periods.get('windows'))
                            if ('scopes' in periods or 'windows' in periods)
                            else (
                                periods.get('audiences')
                                if 'audiences' in periods
                                else (
                                    [periods]
                                    if 'audience' in periods or 'scope_id' in periods
                                    else []
                                )
                            )
                        )
                    )
                )
            )
            master_key = master_key or periods.get('master_key') or periods.get('key')
            secret = secret or periods.get('secret')
            retention = periods.get('retention', retention)
            link_retention = periods.get('link_retention', link_retention)
            period_length = periods.get('period_length', period_length)
            retired_aliases = (
                retired_aliases if retired_aliases is not None
                else periods.get('retired_aliases')
            )
            retired_findings = (
                retired_findings if retired_findings is not None
                else periods.get('retired_findings')
            )

            control = {
                'periods', 'entries', 'audience_periods', 'windows',
                'scopes', 'audiences', 'master_key', 'key', 'secret',
                'retention', 'link_retention', 'period_length',
                'retired_aliases', 'retired_findings',
            }
            if (
                not raw_periods and periods and
                not (set(periods) & control) and
                all(isinstance(value, (list, tuple, Mapping)) for value in periods.values())
            ):
                raw_periods = periods

        self.master_key = _as_bytes(
            master_key if master_key is not None else (
                key if key is not None else (
                    secret if secret is not None else data.get('secret', DEFAULT_MASTER_KEY)
                )
            ),
        )
        parsed_retention = _as_timedelta(
            link_retention if link_retention is not None else retention,
        )
        self.retention = (
            DEFAULT_RETENTION if parsed_retention is None else parsed_retention
        )
        parsed_period_length = _as_timedelta(period_length)
        self.period_length = (
            DEFAULT_PERIOD if parsed_period_length is None else parsed_period_length
        )
        self.clock = clock or (lambda: datetime.now(_TIMEZONE))
        self.retired_aliases: Set[str] = set(_as_ref_tuple(retired_aliases))
        self.retired_alias_audiences: Dict[str, str] = {}
        retired_values = (
            [retired_aliases] if isinstance(retired_aliases, Mapping) else (
                retired_aliases if isinstance(retired_aliases, (list, tuple)) else []
            )
        )
        for item in retired_values:
            if isinstance(item, Mapping):
                alias = item.get('alias') or item.get('tracking_id')
                audience_name = item.get('audience') or item.get('scope_id')
                if alias and audience_name:
                    self.retired_alias_audiences[str(alias)] = str(audience_name)
        self.retired_findings: Set[str] = set(_as_ref_tuple(retired_findings))
        self.periods: List[AudiencePeriod] = []

        self.extend(raw_periods or ())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'AudienceLedger':
        return cls(data)

    @classmethod
    def from_list(cls, periods: Iterable[Any], **kwargs: Any) -> 'AudienceLedger':
        return cls(periods, **kwargs)

    @classmethod
    def from_json(cls, value: Any, **kwargs: Any) -> 'AudienceLedger':
        if isinstance(value, os.PathLike):
            value = os.fspath(value)
        if isinstance(value, str):
            text = value.strip()
            if text.startswith('{') or text.startswith('['):
                value = json.loads(text)
            else:
                with open(value) as handle:
                    value = json.load(handle)
        return cls(value, **kwargs)

    def now(self) -> datetime:
        return _as_datetime(self.clock()) or datetime.now(_TIMEZONE)

    def add(self, period: Any) -> 'AudienceLedger':
        parsed = AudiencePeriod.from_value(period)
        self.periods.append(parsed)
        return self

    def extend(self, periods: Iterable[Any]) -> 'AudienceLedger':
        if isinstance(periods, Mapping):
            expanded: List[Any] = []
            for audience, values in periods.items():
                if isinstance(values, Mapping):
                    values = [values]
                for value in values:
                    if isinstance(value, Mapping):
                        item = dict(value)
                        item.setdefault('audience', audience)
                        expanded.append(item)
                    else:
                        expanded.append(value)
            periods = expanded
        for item in periods:
            self.add(item)
        return self

    def __iter__(self) -> Iterator[AudiencePeriod]:
        return iter(self.periods)

    def __len__(self) -> int:
        return len(self.periods)

    @property
    def entries(self) -> List[AudiencePeriod]:
        return self.periods

    @property
    def windows(self) -> List[AudiencePeriod]:
        return self.periods

    @property
    def audiences(self) -> Set[str]:
        return {period.audience for period in self.periods}

    def _matching(
        self,
        audience: Optional[str] = None,
        period: Optional[str] = None,
    ) -> List[AudiencePeriod]:
        output = [
            (index, item) for index, item in enumerate(self.periods)
            if (audience is None or item.audience == str(audience)) and
            (period is None or item.period == str(period))
        ]
        return [
            item for _, item in sorted(
                output,
                key=lambda pair: (
                    pair[1].not_before or datetime.min.replace(tzinfo=_TIMEZONE),
                    pair[0],
                ),
            )
        ]

    def resolve(
        self,
        audience: Optional[str] = None,
        period: Optional[str] = None,
        at: Any = None,
    ) -> AudiencePeriod:
        moment = _as_datetime(at) or self.now()

        if isinstance(period, AudiencePeriod):
            return period
        if period is not None:
            matches = self._matching(audience=audience, period=period)
            if not matches:
                raise PeriodNotFoundError('No matching audience period.')
            if audience is None and len({item.audience for item in matches}) > 1:
                raise AudienceRequiredError('More than one audience has this period.')
            return matches[-1]

        if audience is not None:
            matches = self._matching(audience=audience)
            active = [item for item in matches if item.is_active(moment)]
            if active:
                return active[-1]
            if matches:
                raise PeriodExpiredError('Audience period is not active at this time.')
            raise AudienceNotFoundError('No such audience in the ledger.')

        active = [item for item in self.periods if item.is_active(moment)]
        audiences = {item.audience for item in active}
        if len(audiences) == 1:
            return active[-1]
        if len(audiences) > 1:
            raise AudienceRequiredError('More than one audience is active; specify one.')
        raise PeriodExpiredError('No audience period is active at this time.')

    def period_for(
        self,
        audience: Optional[str] = None,
        at: Any = None,
        period: Optional[str] = None,
    ) -> AudiencePeriod:
        return self.resolve(audience=audience, period=period, at=at)

    resolve_period = resolve
    active_period = period_for

    def periods_for(self, audience: str) -> List[AudiencePeriod]:
        return self._matching(audience=audience)

    def alias_for(
        self,
        audience: str,
        finding: Any,
        period: Optional[str] = None,
        at: Any = None,
    ) -> str:
        return self.alias(self.resolve(audience=audience, period=period, at=at), finding)

    def previous_alias_for(
        self,
        audience: str,
        finding: Any,
        period: Optional[str] = None,
        at: Any = None,
    ) -> Optional[str]:
        return self.previous_alias(
            self.resolve(audience=audience, period=period, at=at),
            finding,
            at=at,
        )

    def export(self, source: Any, audience: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
        return export_report(source, self, audience=audience, **kwargs)

    publish = export
    report = export

    def previous(self, period: Any) -> Optional[AudiencePeriod]:
        current = AudiencePeriod.from_value(period)

        if current.previous_period is not None:
            previous_audience = current.previous_audience or current.audience
            matches = self._matching(
                audience=previous_audience,
                period=current.previous_period,
            )
            return matches[-1] if matches else None

        candidates = [
            item for item in self._matching(audience=current.audience)
            if item.period != current.period and (
                current.not_before is None or
                item.not_before is None or
                item.not_before < current.not_before
            )
        ]
        return candidates[-1] if candidates else None

    def link_deadline(self, period: Any) -> Optional[datetime]:
        current = AudiencePeriod.from_value(period)
        previous = self.previous(current)
        if previous is None:
            return None
        if previous.retain_until is not None:
            return previous.retain_until
        if previous.not_after is not None:
            return previous.not_after + self.retention
        return None

    def link_allowed(self, period: Any, at: Any = None) -> bool:
        current = AudiencePeriod.from_value(period)
        previous = self.previous(current)
        if previous is None or previous.audience != current.audience:
            return False
        if (
            current.previous_audience is not None and
            current.previous_audience != previous.audience
        ):
            return False

        moment = _as_datetime(at) or self.now()
        deadline = self.link_deadline(current)
        if deadline is not None and moment > deadline:
            return False
        return True

    def scope_key(self, period: Any) -> bytes:
        current = AudiencePeriod.from_value(period)
        material = '{}\x00{}'.format(current.audience, current.period).encode('utf-8')
        return hmac.new(self.master_key, material, hashlib.sha256).digest()

    def alias(self, period: Any, finding: Any) -> str:
        current = AudiencePeriod.from_value(period)
        if current.alias_map:
            if isinstance(finding, _Finding):
                references = _finding_references(finding)
            elif isinstance(finding, Mapping):
                references = _finding_references(_finding_from_item(finding))
            elif isinstance(finding, str):
                references = {finding}
            else:
                references = set()
            for reference in references:
                if reference in current.alias_map:
                    return current.alias_map[reference]
        return _compute_alias(self.scope_key(current), _finding_identity(finding))

    def previous_alias(self, period: Any, finding: Any, at: Any = None) -> Optional[str]:
        current = AudiencePeriod.from_value(period)
        if not self.link_allowed(current, at=at):
            return None
        previous = self.previous(current)
        if previous is None or previous.audience != current.audience:
            return None
        return self.alias(previous, finding)

    def retire(
        self,
        *aliases: str,
        audience: Optional[str] = None,
        findings: Optional[Iterable[str]] = None,
    ) -> 'AudienceLedger':
        for alias in aliases:
            self.retired_aliases.add(str(alias))
            if audience is not None:
                self.retired_alias_audiences[str(alias)] = str(audience)
        self.retired_findings.update(str(finding) for finding in (findings or ()))
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            'periods': [period.as_dict() for period in self.periods],
            'retention': int(self.retention.total_seconds()),
            'retired_aliases': sorted(self.retired_aliases),
            'retired_findings': sorted(self.retired_findings),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @property
    def by_audience(self) -> Dict[str, List[AudiencePeriod]]:
        output: Dict[str, List[AudiencePeriod]] = {}
        for period in self.periods:
            output.setdefault(period.audience, []).append(period)
        return output


class _Finding:
    __slots__ = (
        'filename',
        'hashed_secret',
        'types',
        'category',
        'line_numbers',
        '_raw_secret',
        'explicit_id',
    )

    def __init__(
        self,
        filename: str,
        hashed_secret: str = '',
        types: Iterable[str] = (),
        category: str = VerifiedResult.UNVERIFIED.name,
        line_numbers: Iterable[int] = (),
        raw_secret: Optional[str] = None,
        explicit_id: Optional[str] = None,
    ) -> None:
        self.filename = filename
        self.hashed_secret = hashed_secret
        self.types = tuple(sorted({str(item) for item in types}))
        self.category = category
        self.line_numbers = tuple(sorted({int(item) for item in line_numbers if int(item) > 0}))
        self._raw_secret = raw_secret
        self.explicit_id = explicit_id

    @property
    def finding_id(self) -> str:
        return _finding_identity(self)

    def __repr__(self) -> str:
        return '_Finding(filename={!r}, category={!r})'.format(
            self.filename,
            self.category,
        )


def _finding_identity(finding: Any) -> str:
    if isinstance(finding, _Finding):
        if finding.explicit_id:
            material = 'explicit\x00{}'.format(finding.explicit_id)
        else:
            digest = finding.hashed_secret
            if not digest and finding._raw_secret is not None:
                digest = hashlib.sha1(finding._raw_secret.encode('utf-8')).hexdigest()
            if not digest:
                digest = json.dumps(
                    {
                        'line_numbers': list(finding.line_numbers),
                        'types': list(finding.types),
                    },
                    sort_keys=True,
                    separators=(',', ':'),
                )
            material = '{}\x00{}'.format(
                finding.filename,
                digest,
            )
        return hashlib.sha256(material.encode('utf-8')).hexdigest()

    if isinstance(finding, Mapping):
        filename = str(finding.get('filename', ''))
        explicit_id = (
            finding.get('finding_id') or finding.get('stable_id') or finding.get('internal_id')
        )
        if explicit_id:
            return hashlib.sha256(
                'explicit\x00{}'.format(explicit_id).encode('utf-8'),
            ).hexdigest()
        digest = (
            finding.get('hashed_secret') or finding.get('secret_hash') or
            finding.get('hash') or finding.get('alias') or
            finding.get('marker') or ''
        )
        raw = finding.get('secrets') or finding.get('secret') or finding.get('secret_value')
        if not digest and raw is not None:
            digest = hashlib.sha1(str(raw).encode('utf-8')).hexdigest()
        if not digest:
            digest = json.dumps(
                {
                    'line_numbers': list(_line_numbers_from_item(finding)),
                    'types': sorted(str(item) for item in (
                        finding.get('types') or [finding.get('type', '')]
                    ) if item),
                },
                sort_keys=True,
                separators=(',', ':'),
            )
        material = '{}\x00{}'.format(
            filename,
            digest,
        )
        return hashlib.sha256(material.encode('utf-8')).hexdigest()

    if isinstance(finding, str):
        return hashlib.sha256(finding.encode('utf-8')).hexdigest()
    raise TypeError('Cannot derive an audience alias for this finding.')


def _compute_alias(scope_key: bytes, finding_identity: str) -> str:
    return hmac.new(
        scope_key,
        finding_identity.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()[:_ALIAS_LENGTH]


def derive_scope_key(master_key: Any, audience: str, period: str) -> bytes:
    """Derive the per-audience/per-period key used for aliases and receipts."""
    material = '{}\x00{}'.format(audience, period).encode('utf-8')
    return hmac.new(_as_bytes(master_key), material, hashlib.sha256).digest()


def compute_alias(
    scope_key: bytes,
    identity: Union[str, _Finding, Mapping],
) -> str:
    if isinstance(identity, str):
        return _compute_alias(scope_key, identity)
    return _compute_alias(scope_key, _finding_identity(identity))


def compute_marker(scope_key: bytes, identity: Union[str, _Finding, Mapping]) -> str:
    """Compatibility spelling for :func:`compute_alias`."""
    return compute_alias(scope_key, identity)


def _category_from_item(item: Mapping[str, Any]) -> str:
    category = item.get('category')
    if category:
        value = str(category).upper()
        return {
            'TRUE': VerifiedResult.VERIFIED_TRUE.name,
            'FALSE': VerifiedResult.VERIFIED_FALSE.name,
            'UNKNOWN': VerifiedResult.UNVERIFIED.name,
        }.get(value, value)
    value = item.get('is_secret')
    if value is True:
        return VerifiedResult.VERIFIED_TRUE.name
    if value is False:
        return VerifiedResult.VERIFIED_FALSE.name
    return VerifiedResult.UNVERIFIED.name


def _line_numbers_from_item(item: Mapping[str, Any]) -> Tuple[int, ...]:
    if item.get('line_numbers'):
        return tuple(int(value) for value in item['line_numbers'])
    if item.get('line_number'):
        return (int(item['line_number']),)
    lines = item.get('lines')
    if isinstance(lines, Mapping):
        return tuple(int(key) for key in lines)
    return ()


def _finding_from_item(item: Any, filename: Optional[str] = None) -> _Finding:
    if isinstance(item, PotentialSecret):
        return _Finding(
            filename=item.filename,
            hashed_secret=item.secret_hash,
            types=(item.type,),
            category=VerifiedResult.from_secret(item).name,
            line_numbers=(item.line_number,) if item.line_number else (),
            raw_secret=item.secret_value,
        )

    if not isinstance(item, Mapping):
        raise TypeError('Expected a baseline/report finding mapping.')

    raw_secret = (
        item.get('secrets') if item.get('secrets') is not None else (
            item.get('secret') if item.get('secret') is not None else item.get('secret_value')
        )
    )
    hashed_secret = (
        item.get('hashed_secret') or item.get('secret_hash') or item.get('hash') or ''
    )
    types = item.get('types') or [item.get('type', '')]

    return _Finding(
        filename=str(item.get('filename') or filename or ''),
        hashed_secret=str(hashed_secret),
        types=[str(value) for value in types if value],
        category=_category_from_item(item),
        line_numbers=_line_numbers_from_item(item),
        raw_secret=str(raw_secret) if raw_secret is not None else None,
        explicit_id=(
            str(item['finding_id']) if item.get('finding_id') else (
                str(item['stable_id']) if item.get('stable_id') else None
            )
        ),
    )


def _load_source(source: Any) -> Any:
    if isinstance(source, os.PathLike):
        source = os.fspath(source)
    if isinstance(source, str):
        text = source.strip()
        if text.startswith('{') or text.startswith('['):
            return json.loads(text)
        return baseline.load_from_file(source)
    return source


def _iter_findings(source: Any) -> Iterator[_Finding]:
    if isinstance(source, SecretsCollection):
        for filename, secret in source:
            yield _finding_from_item(secret, filename=filename)
        return

    source = _load_source(source)

    if isinstance(source, Mapping):
        results = source.get('results', source.get('findings'))
        if isinstance(results, Mapping):
            for filename, items in results.items():
                for item in items:
                    yield _finding_from_item(item, filename=filename)
            return
        if isinstance(results, Sequence) and not isinstance(results, (str, bytes)):
            for item in results:
                yield _finding_from_item(item)
            return
        yield _finding_from_item(source)
        return

    if isinstance(source, Sequence) and not isinstance(source, (str, bytes)):
        for item in source:
            yield _finding_from_item(item)
        return

    raise TypeError('Unsupported report or baseline source.')


def _merge_findings(findings: Iterable[_Finding]) -> List[_Finding]:
    merged: Dict[str, _Finding] = {}
    priority = {
        VerifiedResult.VERIFIED_TRUE.name: 3,
        VerifiedResult.UNVERIFIED.name: 2,
        VerifiedResult.VERIFIED_FALSE.name: 1,
    }

    for finding in findings:
        existing = merged.get(finding.finding_id)
        if existing is None:
            merged[finding.finding_id] = finding
            continue

        category = (
            finding.category
            if priority.get(finding.category, 0) > priority.get(existing.category, 0)
            else existing.category
        )
        merged[finding.finding_id] = _Finding(
            filename=existing.filename,
            hashed_secret=existing.hashed_secret,
            types=existing.types + finding.types,
            category=category,
            line_numbers=existing.line_numbers + finding.line_numbers,
            raw_secret=existing._raw_secret or finding._raw_secret,
            explicit_id=existing.explicit_id or finding.explicit_id,
        )

    return sorted(
        merged.values(),
        key=lambda item: (item.filename, item.finding_id),
    )


def _finding_references(finding: _Finding) -> Set[str]:
    output = {
        finding.finding_id,
        finding.hashed_secret,
        '{}:{}'.format(finding.filename, finding.hashed_secret),
        finding.filename,
    }
    if finding.explicit_id:
        output.add(finding.explicit_id)
    if finding._raw_secret is not None:
        output.add(finding._raw_secret)
    return {item for item in output if item}


def _allowed_by_period(period: AudiencePeriod, finding: _Finding, alias: str) -> bool:
    if not period.covers(finding.filename):
        return False
    if period.aliases and alias not in set(period.aliases):
        return False
    if period.findings:
        allowed = set(period.findings)
        if not (_finding_references(finding) & allowed):
            return False
    return True


def _safe_entry(
    finding: _Finding,
    alias: str,
    *,
    previous_alias: Optional[str] = None,
    alias_history: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    entry = _AliasedDict(
        {
            'alias': alias,
            'filename': finding.filename,
            'line_numbers': list(finding.line_numbers),
            'types': list(finding.types),
            'category': finding.category,
            'status': 'active',
        },
        _alias_map=_ENTRY_ALIASES,
    )
    if previous_alias:
        entry['previous_alias'] = previous_alias
        entry['alias_history'] = list(alias_history or [previous_alias])
    elif alias_history:
        entry['alias_history'] = list(alias_history)
    return entry


def _retired_entry(entry: Mapping[str, Any], reason: str) -> Dict[str, Any]:
    alias = entry.get('alias')
    output = _AliasedDict(
        {
            'alias': alias,
            'filename': entry.get('filename'),
            'types': list(entry.get('types') or []),
            'category': entry.get('category'),
            'status': 'retired',
            'reason': reason,
        },
        _alias_map=_ENTRY_ALIASES,
    )
    return output


def _collect_sensitive_values(source: Any) -> Set[str]:
    values: Set[str] = set()
    for finding in _iter_findings(source):
        if finding._raw_secret:
            values.add(finding._raw_secret)
        if finding.hashed_secret:
            values.add(finding.hashed_secret)
    return values


def _assert_no_sensitive_values(value: Any, sensitive: Set[str]) -> None:
    serialized = json.dumps(value, sort_keys=True, default=str)
    for item in sensitive:
        if len(item) >= 8 and item in serialized:
            raise ReportLeakError('Export would contain a secret or its stable digest.')


def _walk_keys(value: Any) -> Iterator[str]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key)
            yield from _walk_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_keys(child)


def assert_no_leaks(value: Any) -> bool:
    for key in _walk_keys(value):
        if key.lower() in _FORBIDDEN_KEYS:
            raise ReportLeakError('Export contains a forbidden identifying field.')
    return True


def _coerce_ledger(value: Any, **kwargs: Any) -> AudienceLedger:
    if isinstance(value, AudienceLedger):
        return value
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if isinstance(value, str):
        return load_ledger(value, **kwargs)
    if isinstance(value, Mapping) or isinstance(value, (list, tuple)):
        return AudienceLedger(value, **kwargs)
    raise TypeError('A caller-provided AudienceLedger is required.')


def _resolve_previous_report(value: Any) -> Optional[Mapping[str, Any]]:
    if value is None:
        return None
    if isinstance(value, Mapping):
        return value
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith('{'):
            return json.loads(text)
        with open(value) as handle:
            return json.load(handle)
    raise TypeError('previous_report must be a path or a report mapping.')


def _report_audience(report: Mapping[str, Any]) -> Optional[str]:
    value = report.get('audience') or report.get('scope_id')
    return str(value) if value is not None else None


def _report_period(report: Mapping[str, Any]) -> Optional[str]:
    value = report.get('period') or report.get('epoch')
    return str(value) if value is not None else None


def _report_aliases(report: Mapping[str, Any]) -> Set[str]:
    output = set()
    results = report.get('results') or report.get('findings') or ()
    if isinstance(results, Mapping):
        results = []
    for entry in results:
        if not isinstance(entry, Mapping):
            continue
        alias = entry.get('alias') or entry.get('marker') or entry.get('tracking_id')
        if alias:
            output.add(str(alias))
    return output


def export_report(
    source: Any = None,
    ledger: Any = None,
    audience: Optional[str] = None,
    period: Optional[str] = None,
    at: Any = None,
    now: Any = None,
    previous_report: Any = None,
    include_retired: bool = True,
    include_unverified: bool = False,
    include_lines: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Export only ``audience``'s allowed findings from a baseline or report.

    ``source`` may be a baseline filename, a baseline/report mapping, a
    ``SecretsCollection``, or a list of finding mappings.  ``ledger`` is the
    caller-supplied :class:`AudienceLedger` (or its JSON mapping).

    The returned mapping never contains a raw secret or the baseline's
    stable ``hashed_secret``.  Findings are identified only by an alias
    scoped to the selected audience period.
    """
    del include_lines  # line contents are intentionally never exported
    source = source if source is not None else kwargs.pop('baseline', kwargs.pop('report', None))
    ledger = ledger if ledger is not None else kwargs.pop(
        'audience_ledger',
        kwargs.pop('period_ledger', None),
    )
    if source is None:
        raise TypeError('A baseline, report, or finding source is required.')
    if ledger is None:
        raise TypeError('A caller-provided audience ledger is required.')
    if (
        isinstance(ledger, str) and
        isinstance(audience, (AudienceLedger, Mapping, list, tuple))
    ):
        ledger, audience = audience, ledger
    ledger = _coerce_ledger(
        ledger,
        master_key=kwargs.pop('master_key', None),
        key=kwargs.pop('key', None),
    )
    audience = audience or kwargs.pop('scope', None) or kwargs.pop('scope_id', None)
    class_to_print = kwargs.pop('class_to_print', None)
    if kwargs.pop('only_real', False):
        class_to_print = 'REAL_SECRET'
    if kwargs.pop('only_false', False):
        class_to_print = 'FALSE_POSITIVE'
    if class_to_print is not None:
        label = getattr(class_to_print, 'name', str(class_to_print)).upper()
        if label.endswith('REAL_SECRET'):
            include_unverified = True
    at = at if at is not None else kwargs.pop('as_of', kwargs.pop('at_time', None))
    moment = _as_datetime(at if at is not None else now) or ledger.now()
    current = ledger.resolve(
        audience=audience,
        period=period or kwargs.pop(
            'audience_period',
            kwargs.pop('period_id', kwargs.pop('epoch', None)),
        ),
        at=moment,
    )
    if not kwargs.pop('allow_expired', False) and not current.is_active(moment):
        raise PeriodExpiredError('Audience period is not active at this time.')
    previous_report = previous_report or kwargs.pop(
        'previous',
        kwargs.pop('prior_report', None),
    )
    previous_report_data = _resolve_previous_report(previous_report)

    findings = _merge_findings(_iter_findings(source))
    sensitive = _collect_sensitive_values(source)
    results: List[Dict[str, Any]] = []
    active_aliases: Set[str] = set()

    previous = ledger.previous(current)
    link_allowed = ledger.link_allowed(current, at=moment)
    previous_audience = _report_audience(previous_report_data) if previous_report_data else None
    if previous_report_data is not None and previous_audience is None:
        previous_audience = current.audience
    previous_aliases = (
        _report_aliases(previous_report_data) if previous_report_data else set()
    )
    if previous_report_data is not None and previous is not None:
        for prior_item in (
            previous_report_data.get('results') or
            previous_report_data.get('findings') or
            ()
        ):
            if not isinstance(prior_item, Mapping):
                continue
            if prior_item.get('alias') or prior_item.get('marker'):
                continue
            try:
                prior_finding = _finding_from_item(prior_item)
                previous_aliases.add(ledger.alias(previous, prior_finding))
            except (TypeError, ValueError):
                continue
    linked_prior_aliases: Set[str] = set()

    same_period_resend = (
        previous_report_data is not None and
        _report_period(previous_report_data) == current.period
    )
    prior_entries_by_alias: Dict[str, Mapping[str, Any]] = {}
    if same_period_resend:
        # Re-sending the same period must be stable.  There is no period
        # transition to link; the aliases themselves are already identical.
        link_allowed = False
        for prior_entry in (
            previous_report_data.get('results') or
            previous_report_data.get('findings') or
            ()
        ):
            if not isinstance(prior_entry, Mapping):
                continue
            prior_key = prior_entry.get('alias') or prior_entry.get('marker')
            if prior_key:
                prior_entries_by_alias[str(prior_key)] = prior_entry

    allowed_categories = None
    if class_to_print is not None:
        label = getattr(class_to_print, 'name', str(class_to_print)).upper()
        if label.endswith('REAL_SECRET'):
            allowed_categories = {
                VerifiedResult.VERIFIED_TRUE.name,
                VerifiedResult.UNVERIFIED.name,
            }
        elif label.endswith('FALSE_POSITIVE'):
            allowed_categories = {VerifiedResult.VERIFIED_FALSE.name}

    for finding in findings:
        if (
            not include_unverified and
            finding.category == VerifiedResult.UNVERIFIED.name
        ):
            continue
        if allowed_categories is not None and finding.category not in allowed_categories:
            continue

        alias = ledger.alias(current, finding)
        for other_period in ledger.periods:
            if other_period.audience == current.audience:
                continue
            try:
                other_alias = ledger.alias(other_period, finding)
            except (TypeError, ValueError):
                continue
            if other_alias == alias:
                raise CrossAudienceLinkError(
                    'The same alias would be disclosed to two audiences.',
                )
        if not _allowed_by_period(current, finding, alias):
            continue
        if alias in ledger.retired_aliases:
            continue
        if _finding_references(finding) & ledger.retired_findings:
            continue
        if current.retired:
            retired_references = set(current.retired)
            if alias in retired_references or _finding_references(finding) & retired_references:
                continue

        prior_alias: Optional[str] = None
        prior_history: Optional[Iterable[str]] = None
        if same_period_resend:
            prior_entry = prior_entries_by_alias.get(alias)
            if prior_entry is not None:
                prior_alias = prior_entry.get('previous_alias')
                prior_history = prior_entry.get('alias_history')
        elif link_allowed and previous is not None:
            previous_alias_value = ledger.alias(previous, finding)
            if previous_report_data is None:
                if _allowed_by_period(previous, finding, previous_alias_value):
                    prior_alias = previous_alias_value
            elif (
                previous_audience == current.audience and
                previous_alias_value in previous_aliases
            ):
                prior_alias = previous_alias_value

        results.append(_safe_entry(
            finding,
            alias,
            previous_alias=prior_alias,
            alias_history=prior_history,
        ))
        active_aliases.add(alias)
        if prior_alias:
            linked_prior_aliases.add(prior_alias)

    retired: List[Dict[str, Any]] = []
    if include_retired and same_period_resend:
        seen_prior_retired: Set[str] = set()
        for prior_retired in previous_report_data.get('retired') or []:
            if not isinstance(prior_retired, Mapping):
                continue
            prior_alias = prior_retired.get('alias') or prior_retired.get('marker')
            if prior_alias:
                seen_prior_retired.add(str(prior_alias))
            retired.append(_retired_entry(
                prior_retired,
                str(prior_retired.get('reason') or 'retired'),
            ))
        for prior_alias in previous_report_data.get('retired_aliases') or []:
            if str(prior_alias) in seen_prior_retired:
                continue
            if not _looks_like_alias(str(prior_alias)):
                continue
            retired.append(_AliasedDict(
                {
                    'alias': str(prior_alias),
                    'filename': None,
                    'types': [],
                    'category': None,
                    'status': 'retired',
                    'reason': 'retired',
                },
                _alias_map=_ENTRY_ALIASES,
            ))
    if include_retired and previous_report_data is not None:
        if previous_audience == current.audience:
            previous_results = (
                previous_report_data.get('results') or
                previous_report_data.get('findings') or
                ()
            )
            if isinstance(previous_results, Mapping):
                previous_results = ()
            for previous_entry in previous_results:
                if not isinstance(previous_entry, Mapping):
                    continue
                previous_alias = (
                    previous_entry.get('alias') or
                    previous_entry.get('marker') or
                    previous_entry.get('tracking_id')
                )
                if (
                    not previous_alias and
                    previous is not None and
                    isinstance(previous_entry, Mapping)
                ):
                    try:
                        prior_finding = _finding_from_item(previous_entry)
                        previous_alias = ledger.alias(previous, prior_finding)
                    except (TypeError, ValueError):
                        previous_alias = None
                if not previous_alias:
                    continue
                if (
                    str(previous_alias) in active_aliases or
                    str(previous_alias) in linked_prior_aliases
                ):
                    continue
                retired.append(_retired_entry(previous_entry, 'removed_from_scope'))

    if include_retired:
        seen_retired = {
            str(entry.get('alias'))
            for entry in retired
            if entry.get('alias')
        }
        ledger_retired = [
            alias for alias in ledger.retired_aliases
            if ledger.retired_alias_audiences.get(alias) == current.audience
        ]
        for reference in list(current.retired) + ledger_retired:
            if (
                isinstance(reference, str) and
                len(reference) == _ALIAS_LENGTH and
                all(char in '0123456789abcdefABCDEF' for char in reference) and
                reference not in active_aliases and
                reference not in seen_retired
            ):
                retired.append(_AliasedDict(
                    {
                        'alias': reference,
                        'filename': None,
                        'types': [],
                        'category': None,
                        'status': 'retired',
                        'reason': 'retired_by_ledger',
                    },
                    _alias_map=_ENTRY_ALIASES,
                ))
                seen_retired.add(reference)

    report = _AliasedDict(
        {
            'audience': current.audience,
            'period': current.period,
            'not_before': _as_epoch(current.not_before),
            'not_after': _as_epoch(current.not_after),
            'starts_at': _as_iso(current.not_before),
            'ends_at': _as_iso(current.not_after),
            'valid_from': _as_iso(current.not_before),
            'valid_until': _as_iso(current.not_after),
            'generated_at': _format_datetime(current.not_before or moment),
            'results': results,
            'aliases': [entry['alias'] for entry in results],
            'retain_until': _as_epoch(ledger.link_deadline(current)),
            'retired': retired,
            'retired_aliases': [
                entry['alias'] for entry in retired if entry.get('alias')
            ],
        },
        _alias_map=_REPORT_ALIASES,
    )

    if same_period_resend:
        if previous_report_data.get('previous_period') is not None:
            report['previous_period'] = previous_report_data['previous_period']
        if previous_report_data.get('link_allowed_until') is not None:
            report['link_allowed_until'] = previous_report_data['link_allowed_until']
        if previous_report_data.get('retain_until') is not None:
            report['retain_until'] = previous_report_data['retain_until']
    elif previous is not None and link_allowed:
        report['previous_period'] = previous.period
        deadline = ledger.link_deadline(current)
        if deadline is not None:
            report['link_allowed_until'] = _as_epoch(deadline)

    assert_no_leaks(report)
    _assert_no_sensitive_values(report, sensitive)
    return report


def export_audience_report(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    return export_report(*args, **kwargs)


def generate_scoped_report(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    return export_report(*args, **kwargs)


def scoped_export(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    return export_report(*args, **kwargs)


def publish_report(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    return export_report(*args, **kwargs)


class LinkResult(dict):
    """Mapping of current alias -> previous alias, with diagnostic properties."""

    def __init__(
        self,
        *args: Any,
        reason: Optional[str] = None,
        cross_audience: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.reason = reason or ('linked' if self else 'no_link')
        self.cross_audience = cross_audience

    @property
    def matched(self) -> 'LinkResult':
        return self

    @property
    def pairs(self) -> List[Tuple[str, str]]:
        return sorted(self.items())

    @property
    def ok(self) -> bool:
        return bool(self)


def link_reports(
    previous_report: Any = None,
    current_report: Any = None,
    ledger: Any = None,
    audience: Optional[str] = None,
    at: Any = None,
    **kwargs: Any,
) -> LinkResult:
    """
    Link a current report to its previous report during the retention window.

    Cross-audience reports never produce links.  This is the reviewer-side
    operation that answers "which alias in the new report is the one I saw
    before?" without exposing an audience-independent identifier.
    """
    previous_report = previous_report if previous_report is not None else kwargs.pop(
        'previous',
        kwargs.pop('old_report', None),
    )
    current_report = current_report if current_report is not None else kwargs.pop(
        'current',
        kwargs.pop('new_report', None),
    )
    ledger = ledger if ledger is not None else kwargs.pop('audience_ledger', None)
    if ledger is None:
        raise TypeError('A caller-provided audience ledger is required.')
    at = at if at is not None else kwargs.pop('at_time', None)
    ledger = _coerce_ledger(ledger)
    previous = _resolve_previous_report(previous_report)
    current = _resolve_previous_report(current_report)
    if previous is None or current is None:
        return LinkResult(reason='missing_report')

    previous_audience = _report_audience(previous)
    current_audience = _report_audience(current) or audience
    if previous_audience is None or current_audience is None:
        return LinkResult(reason='missing_audience')
    if previous_audience != current_audience:
        return LinkResult(reason='audience_changed', cross_audience=True)

    current_period = _report_period(current)
    previous_period = _report_period(previous)
    if not current_period or not previous_period:
        return LinkResult(reason='missing_period')

    try:
        current_entry = ledger.resolve(
            audience=current_audience,
            period=current_period,
            at=at,
        )
    except AudienceLedgerError:
        return LinkResult(reason='unknown_current_period')

    moment = _as_datetime(at) or ledger.now()
    if not current_entry.is_active(moment):
        return LinkResult(reason='current_period_expired')

    if current_period == previous_period:
        # A re-send in the same period is the degenerate link: aliases do
        # not rotate, so the identity mapping is safe.
        shared = _report_aliases(current) & _report_aliases(previous)
        if shared:
            return LinkResult({alias: alias for alias in shared}, reason='same_period')
        return LinkResult(reason='no_shared_alias')

    if not ledger.link_allowed(current_entry, at=at):
        return LinkResult(reason='link_window_expired')

    expected_previous = ledger.previous(current_entry)
    if expected_previous is None or expected_previous.period != previous_period:
        return LinkResult(reason='period_not_predecessor')

    current_aliases = _report_aliases(current)
    previous_aliases = _report_aliases(previous)
    try:
        previous_entry = ledger.resolve(
            audience=current_audience,
            period=previous_period,
            at=at,
        )
    except AudienceLedgerError:
        previous_entry = None
    if previous_entry is not None:
        for prior_item in previous.get('results') or previous.get('findings') or ():
            if not isinstance(prior_item, Mapping):
                continue
            if prior_item.get('alias') or prior_item.get('marker'):
                continue
            try:
                previous_aliases.add(
                    ledger.alias(previous_entry, _finding_from_item(prior_item)),
                )
            except (TypeError, ValueError):
                continue
    output = LinkResult()
    for entry in current.get('results') or current.get('findings') or ():
        if not isinstance(entry, Mapping):
            continue
        current_alias = (
            entry.get('alias') or entry.get('marker') or entry.get('tracking_id')
        )
        previous_alias = entry.get('previous_alias')
        if not current_alias or not previous_alias:
            continue
        if str(current_alias) in current_aliases and str(previous_alias) in previous_aliases:
            output[str(current_alias)] = str(previous_alias)

    if output:
        output.reason = 'linked'
    return output


def match_reports(*args: Any, **kwargs: Any) -> LinkResult:
    return link_reports(*args, **kwargs)


def compare_scoped_reports(*args: Any, **kwargs: Any) -> LinkResult:
    return link_reports(*args, **kwargs)


def verify_link(*args: Any, **kwargs: Any) -> bool:
    if (
        len(args) >= 3 and
        isinstance(args[0], (Mapping, str)) and
        isinstance(args[1], (Mapping, str)) and
        isinstance(args[2], (AudienceLedger, Mapping, list, tuple, str))
    ):
        previous_report, current_report, ledger = args[0], args[1], args[2]
        current_alias = (
            args[3] if len(args) > 3 else kwargs.pop('current_alias', None)
        )
        previous_alias = (
            args[4] if len(args) > 4 else kwargs.pop('previous_alias', None)
        )
    else:
        current_alias, previous_alias, previous_report, current_report, ledger = args[:5]
    links = link_reports(previous_report, current_report, ledger, **kwargs)
    return links.get(str(current_alias)) == str(previous_alias)


def verify_report(
    report: Any,
    ledger: Any = None,
    source: Any = None,
    at: Any = None,
    previous_report: Any = None,
    **kwargs: Any,
) -> bool:
    """
    Validate the shape and cross-audience safety of an exported report.

    If ``source`` is supplied, every active alias is recomputed from the
    source findings.  This is useful for a central security reviewer.
    """
    if not isinstance(report, Mapping):
        raise ReportVerificationError('Report must be a mapping.')
    at = at if at is not None else kwargs.pop('at_time', None)

    assert_no_leaks(report)
    if source is not None:
        _assert_no_sensitive_values(report, _collect_sensitive_values(source))
    report_audience = _report_audience(report)
    if ledger is not None:
        ledger = _coerce_ledger(ledger)
        for retired_entry in report.get('retired') or []:
            if not isinstance(retired_entry, Mapping):
                continue
            retired_alias = retired_entry.get('alias')
            audience_name = ledger.retired_alias_audiences.get(str(retired_alias))
            if audience_name and audience_name != report_audience:
                raise CrossAudienceLinkError(
                    'A retired alias from another audience was disclosed.',
                )
    results = report.get('results') or report.get('findings') or ()
    if isinstance(results, Mapping):
        raise ReportVerificationError('Export results must be a list.')

    aliases = []
    for entry in results:
        if not isinstance(entry, Mapping):
            raise ReportVerificationError('Each export entry must be a mapping.')
        alias = entry.get('alias') or entry.get('marker') or entry.get('tracking_id')
        if not alias:
            raise ReportVerificationError('Each active entry needs an alias.')
        aliases.append(str(alias))
    if len(aliases) != len(set(aliases)):
        raise ReportVerificationError('Aliases must be unique within a report.')

    if ledger is not None and source is not None:
        ledger = _coerce_ledger(ledger)
        current = ledger.resolve(
            audience=_report_audience(report),
            period=_report_period(report),
            at=at,
        )
        expected_aliases = set()
        for finding in _merge_findings(_iter_findings(source)):
            if finding.category == VerifiedResult.UNVERIFIED.name:
                continue
            alias = ledger.alias(current, finding)
            if not _allowed_by_period(current, finding, alias):
                continue
            if alias in ledger.retired_aliases:
                continue
            if _finding_references(finding) & ledger.retired_findings:
                continue
            if current.retired and (
                alias in set(current.retired) or
                _finding_references(finding) & set(current.retired)
            ):
                continue
            expected_aliases.add(alias)
        if set(aliases) != expected_aliases:
            raise ReportVerificationError('Report aliases do not match the source.')

    previous = _resolve_previous_report(previous_report)
    if previous is not None:
        previous_audience = _report_audience(previous)
        current_audience = _report_audience(report)
        if (
            previous_audience is not None and
            current_audience is not None and
            previous_audience != current_audience
        ):
            for entry in results:
                if entry.get('previous_alias') or entry.get('alias_history'):
                    raise CrossAudienceLinkError(
                        'Cross-audience reports must not expose prior aliases.',
                    )
            if set(_report_aliases(previous)) & set(aliases):
                raise CrossAudienceLinkError(
                    'Cross-audience reports must not share aliases.',
                )

    return True


def validate_export(*args: Any, **kwargs: Any) -> bool:
    return verify_report(*args, **kwargs)


def renew_period(
    period: Any,
    new_period: Optional[str] = None,
    not_before: Any = None,
    not_after: Any = None,
    retention: Any = None,
    **changes: Any,
) -> AudiencePeriod:
    current = AudiencePeriod.from_value(period)
    start = _as_datetime(not_before) or (
        current.not_after + timedelta(seconds=1) if current.not_after else (
            current.not_before + DEFAULT_PERIOD
            if current.not_before else datetime.now(_TIMEZONE)
        )
    )
    end = _as_datetime(not_after) or (
        start + _as_timedelta(retention) if start and retention else (
            start + DEFAULT_PERIOD if start else None
        )
    )
    payload = {
        'audience': current.audience,
        'period': str(new_period) if new_period is not None else (
            _format_datetime(start) if start else current.period
        ),
        'not_before': start,
        'not_after': end,
        'filenames': current.filenames,
        'excluded': current.excluded,
        'findings': current.findings,
        # Aliases are scoped to the period.  Carrying the old period's
        # allowlist forward would reject every rotated alias.
        'aliases': changes.pop('aliases', ()),
        'previous_period': current.period,
        'previous_audience': current.audience,
        'retain_until': current.not_after + _as_timedelta(retention)
        if current.not_after and retention else current.retain_until,
        'retired': current.retired,
    }
    if changes:
        payload.update(changes)
    return AudiencePeriod(**payload)


def rotate_period(*args: Any, **kwargs: Any) -> AudiencePeriod:
    return renew_period(*args, **kwargs)


def renew_audience(
    ledger: Any,
    audience: str,
    new_period: Optional[str] = None,
    not_before: Any = None,
    not_after: Any = None,
    **kwargs: Any,
) -> AudienceLedger:
    ledger = _coerce_ledger(ledger)
    at = kwargs.pop('at', None)
    current = ledger.resolve(
        audience=audience,
        period=kwargs.pop('period', None),
        at=at,
    )
    renewed = renew_period(
        current,
        new_period,
        not_before=not_before,
        not_after=not_after,
        **kwargs,
    )
    ledger.add(renewed)
    return ledger


def retire_findings(
    period: Any,
    findings: Iterable[str],
    new_period: Optional[str] = None,
    **kwargs: Any,
) -> AudiencePeriod:
    current = AudiencePeriod.from_value(period)
    retired = set(current.retired) | {str(item) for item in findings}
    return AudiencePeriod(
        audience=current.audience,
        period=new_period if new_period is not None else current.period,
        not_before=kwargs.pop('not_before', current.not_before),
        not_after=kwargs.pop('not_after', current.not_after),
        filenames=kwargs.pop('filenames', current.filenames),
        excluded=kwargs.pop('excluded', current.excluded),
        findings=kwargs.pop('findings', current.findings),
        aliases=kwargs.pop('aliases', current.aliases),
        previous_period=kwargs.pop('previous_period', current.previous_period),
        previous_audience=kwargs.pop('previous_audience', current.previous_audience),
        retain_until=kwargs.pop('retain_until', current.retain_until),
        retired=retired,
        **kwargs,
    )


def transfer_audience_scope(
    ledger: Any,
    source_audience: str,
    target_audience: str,
    filenames: Iterable[str],
    new_period: Optional[str] = None,
    not_before: Any = None,
    not_after: Any = None,
    retention: Any = None,
    source_period: Optional[str] = None,
    target_period: Optional[str] = None,
    at: Any = None,
) -> AudienceLedger:
    """
    Move files from one audience to another under a fresh period.

    Both audiences receive new periods, so all prior aliases rotate.
    The target's new period deliberately has no previous alias link to
    the source audience.
    """
    ledger = _coerce_ledger(ledger)
    source = ledger.resolve(audience=source_audience, period=source_period, at=at)
    target = ledger.resolve(audience=target_audience, period=target_period, at=at)
    moved = tuple(str(item) for item in filenames)
    moved_set = set(moved)

    source_remaining = tuple(
        item for item in source.filenames if item not in moved_set
    ) or tuple(
        item for item in source.filenames
        if not any(_path_covers(name, item) for name in moved)
    )
    target_files = tuple(dict.fromkeys(target.filenames + moved))
    start = _as_datetime(not_before) or (
        max(
            [value for value in (source.not_after, target.not_after) if value],
            default=None,
        )
    ) or ledger.now()
    end = _as_datetime(not_after) or (
        start + _as_timedelta(retention) if start and retention else (
            start + DEFAULT_PERIOD if start else None
        )
    )
    period_name = str(new_period) if new_period is not None else _format_datetime(start)

    ledger.add(AudiencePeriod(
        audience=source.audience,
        period=period_name,
        not_before=start,
        not_after=end,
        filenames=source_remaining,
        excluded=tuple(dict.fromkeys(source.excluded + moved)),
        findings=source.findings,
        previous_period=source.period,
        previous_audience=source.audience,
        retain_until=source.not_after + _as_timedelta(retention)
        if source.not_after and retention else None,
    ))
    ledger.add(AudiencePeriod(
        audience=target.audience,
        period=period_name,
        not_before=start,
        not_after=end,
        filenames=target_files,
        findings=target.findings,
        previous_period=target.period,
        previous_audience=target.audience,
        retain_until=target.not_after + _as_timedelta(retention)
        if target.not_after and retention else None,
    ))
    return ledger


def swap_audience(*args: Any, **kwargs: Any) -> AudienceLedger:
    return transfer_audience_scope(*args, **kwargs)


def transfer_filenames(
    old_scope: DisclosureScope,
    new_scope: DisclosureScope,
    filenames: Iterable[str],
    epoch: str,
    not_before: int,
    not_after: int,
) -> Tuple[DisclosureScope, DisclosureScope]:
    """Compatibility helper that re-issues two scopes under a new epoch."""
    moved = set(filenames)
    updated_old = old_scope._replace(
        filenames=tuple(name for name in old_scope.filenames if name not in moved),
        epoch=epoch,
        not_before=not_before,
        not_after=not_after,
    )
    updated_new = new_scope._replace(
        filenames=tuple(
            list(new_scope.filenames) +
            [name for name in old_scope.filenames if name in moved]
        ),
        epoch=epoch,
        not_before=not_before,
        not_after=not_after,
    )
    return updated_old, updated_new


def build_ledger(periods: Iterable[Any], **kwargs: Any) -> AudienceLedger:
    return AudienceLedger(periods, **kwargs)


def load_ledger(source: Any, **kwargs: Any) -> AudienceLedger:
    if isinstance(source, AudienceLedger):
        return source
    if isinstance(source, os.PathLike):
        source = os.fspath(source)
    if isinstance(source, Mapping):
        return AudienceLedger(source, **kwargs)
    if isinstance(source, str):
        text = source.strip()
        if text.startswith('{') or text.startswith('['):
            return AudienceLedger(json.loads(text), **kwargs)
        with open(source) as handle:
            return AudienceLedger(json.load(handle), **kwargs)
    raise TypeError('Unsupported audience ledger source.')


def now_epoch() -> int:
    return int(time.time())


APPROVED_CATEGORIES = (
    VerifiedResult.VERIFIED_TRUE.name,
    VerifiedResult.VERIFIED_FALSE.name,
)


class ReceiptError(AudienceLedgerError):
    pass


class UnknownScopeError(ReceiptError):
    pass


class ReceiptWindowError(ReceiptError):
    pass


class ReceiptSignatureError(ReceiptError):
    pass


class ForeignMarkerError(ReceiptError):
    pass


def _as_scope(scope: Any) -> DisclosureScope:
    if isinstance(scope, DisclosureScope):
        return scope
    return disclosure_scope_from_period(AudiencePeriod.from_value(scope))


def _scope_payload(scope: Any) -> Dict[str, Any]:
    scope = _as_scope(scope)
    return {
        'scope_id': scope.scope_id,
        'epoch': scope.epoch,
        'not_before': scope.not_before,
        'not_after': scope.not_after,
    }


def _receipt_canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _receipt_sign(scope_key: bytes, payload: Mapping[str, Any]) -> str:
    return hmac.new(scope_key, _receipt_canonical(payload), hashlib.sha256).hexdigest()


def _receipt_fingerprint(entry: Mapping[str, Any]) -> str:
    raw = entry.get('secrets') if isinstance(entry, Mapping) else None
    digest = (
        entry.get('hashed_secret') or entry.get('secret_hash') or entry.get('hash') or ''
        if isinstance(entry, Mapping) else ''
    )
    if not digest and raw is not None:
        digest = hashlib.sha1(str(raw).encode('utf-8')).hexdigest()
    types = entry.get('types') or [entry.get('type', '')] if isinstance(entry, Mapping) else []
    material = '{}\x00{}\x00{}'.format(
        entry.get('filename', '') if isinstance(entry, Mapping) else '',
        digest,
        ','.join(sorted(str(item) for item in types if item)),
    )
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


def _redact_text(value: Any, sensitive: Set[str]) -> Any:
    if not isinstance(value, str):
        return value
    output = value
    for item in sensitive:
        if item:
            output = output.replace(item, '[REDACTED]')
    return output


def publish_summary(report: Mapping[str, Any], scope: Any, scope_key: bytes) -> Dict[str, Any]:
    disclosure = _as_scope(scope)
    sensitive = set()
    for entry in report.get('results', []) or []:
        if not isinstance(entry, Mapping):
            continue
        for key in ('secrets', 'secret', 'secret_value', 'hashed_secret', 'secret_hash'):
            value = entry.get(key)
            if value:
                sensitive.add(str(value))
    results = []
    for entry in report.get('results', []) or []:
        if not isinstance(entry, Mapping):
            continue
        filename = str(entry.get('filename', ''))
        if not disclosure.covers(filename):
            continue
        item = {
            'marker': compute_marker(scope_key, _receipt_fingerprint(entry)),
            'alias': None,
            'filename': filename,
            'types': list(entry.get('types') or []),
            'category': entry.get('category', VerifiedResult.UNVERIFIED.name),
        }
        item['alias'] = item['marker']
        if 'line_numbers' in entry:
            item['line_numbers'] = list(entry.get('line_numbers') or [])
        lines = entry.get('lines')
        if isinstance(lines, Mapping):
            item['lines'] = {
                int(key): _redact_text(value, sensitive)
                for key, value in lines.items()
            }
        results.append(item)
    output = {
        'scope_id': disclosure.scope_id,
        'epoch': disclosure.epoch,
        'audience': disclosure.scope_id,
        'period': disclosure.epoch,
        'not_before': disclosure.not_before,
        'not_after': disclosure.not_after,
        'results': results,
    }
    _assert_no_sensitive_values(output, sensitive)
    return output


def create_receipt(
    scope: Any,
    scope_key: bytes,
    dispositions: Iterable[Mapping[str, Any]],
    signed_at: Optional[int] = None,
) -> Dict[str, Any]:
    disclosure = _as_scope(scope)
    if signed_at is None:
        signed_at = int(time.time())
    payload = dict(_scope_payload(disclosure))
    payload['signed_at'] = int(signed_at)
    payload['dispositions'] = sorted(
        (dict(item) for item in dispositions),
        key=lambda item: item.get('marker', ''),
    )
    receipt = dict(payload)
    receipt['signature'] = _receipt_sign(scope_key, payload)
    return receipt


def verify_receipt(
    receipt: Mapping[str, Any],
    scope: Any,
    scope_key: bytes,
    at_time: Optional[int] = None,
) -> bool:
    disclosure = _as_scope(scope)
    if at_time is None:
        at_time = int(time.time())
    if receipt.get('scope_id') != disclosure.scope_id or receipt.get('epoch') != disclosure.epoch:
        raise UnknownScopeError('Receipt does not belong to this scope.')
    if (
        receipt.get('not_before') != disclosure.not_before or
        receipt.get('not_after') != disclosure.not_after
    ):
        raise UnknownScopeError('Receipt window does not match the scope.')
    if not disclosure.is_active(int(receipt.get('signed_at', 0))):
        raise ReceiptWindowError('Receipt was signed outside its authorization window.')
    if not disclosure.is_active(int(at_time)):
        raise ReceiptWindowError('Scope authorization window has expired.')
    payload = {key: receipt[key] for key in receipt if key != 'signature'}
    expected = _receipt_sign(scope_key, payload)
    if not hmac.compare_digest(expected, str(receipt.get('signature', ''))):
        raise ReceiptSignatureError('Receipt signature does not match.')
    return True


def verify_receipt_with_master_key(
    receipt: Mapping[str, Any],
    master_key: Any,
    scopes: Iterable[Any],
) -> bool:
    for scope in scopes:
        disclosure = _as_scope(scope)
        if (
            receipt.get('scope_id') == disclosure.scope_id and
            receipt.get('epoch') == disclosure.epoch
        ):
            scope_key = derive_scope_key(master_key, disclosure.scope_id, disclosure.epoch)
            payload = {key: receipt[key] for key in receipt if key != 'signature'}
            expected = _receipt_sign(scope_key, payload)
            if not hmac.compare_digest(expected, str(receipt.get('signature', ''))):
                raise ReceiptSignatureError('Receipt signature does not match.')
            return True
    raise UnknownScopeError('No matching scope for this receipt.')


class ReconciliationResult(NamedTuple):
    covered: List[str]
    missing: List[str]
    foreign: List[str]

    @property
    def ok(self) -> bool:
        return not self.missing and not self.foreign


def reconcile(
    report: Mapping[str, Any],
    scopes: Iterable[Any],
    receipts: Iterable[Mapping[str, Any]],
    master_key: Any,
) -> ReconciliationResult:
    scopes = list(scopes)
    expected = {}
    for scope in scopes:
        disclosure = _as_scope(scope)
        scope_key = derive_scope_key(master_key, disclosure.scope_id, disclosure.epoch)
        for entry in report.get('results', []) or []:
            if not isinstance(entry, Mapping):
                continue
            if not disclosure.covers(str(entry.get('filename', ''))):
                continue
            if entry.get('category') not in APPROVED_CATEGORIES:
                continue
            expected[compute_marker(scope_key, _receipt_fingerprint(entry))] = disclosure.scope_id
    delivered = set()
    foreign = set()
    for receipt in receipts:
        verify_receipt_with_master_key(receipt, master_key, scopes)
        scope_id = receipt.get('scope_id')
        for item in receipt.get('dispositions', []):
            marker = item.get('marker')
            if expected.get(marker) != scope_id:
                foreign.add(marker)
            else:
                delivered.add(marker)
    return ReconciliationResult(
        covered=sorted(delivered),
        missing=sorted(set(expected) - delivered),
        foreign=sorted(foreign),
    )



def update_audience(*args: Any, **kwargs: Any) -> AudienceLedger:
    return transfer_audience_scope(*args, **kwargs)


def change_audience(*args: Any, **kwargs: Any) -> AudienceLedger:
    return transfer_audience_scope(*args, **kwargs)


def update_scope(*args: Any, **kwargs: Any) -> AudienceLedger:
    return transfer_audience_scope(*args, **kwargs)


def reassign_findings(*args: Any, **kwargs: Any) -> AudienceLedger:
    return transfer_audience_scope(*args, **kwargs)


def retire_aliases(
    ledger: Any,
    *aliases: str,
    audience: Optional[str] = None,
) -> AudienceLedger:
    return _coerce_ledger(ledger).retire(*aliases, audience=audience)


AudiencePeriodLedger = AudienceLedger
PeriodLedger = AudienceLedger
ExportLedger = AudienceLedger
AudienceWindow = AudiencePeriod
ExportPeriod = AudiencePeriod
generate_audience_report = export_audience_report
create_scoped_report = export_report


__all__ = [
    'APPROVED_CATEGORIES',
    'AudienceLedger',
    'AudienceLedgerError',
    'AudienceMismatchError',
    'AudienceNotFoundError',
    'AudiencePeriod',
    'AudienceRequiredError',
    'CrossAudienceLinkError',
    'DisclosureScope',
    'LinkResult',
    'LinkWindowExpiredError',
    'PeriodExpiredError',
    'PeriodNotFoundError',
    'ReportLeakError',
    'ReportVerificationError',
    'ReceiptError',
    'ReceiptSignatureError',
    'ReceiptWindowError',
    'ReconciliationResult',
    'ForeignMarkerError',
    'UnknownScopeError',
    'create_receipt',
    'publish_summary',
    'reconcile',
    'verify_receipt',
    'verify_receipt_with_master_key',
    'assert_no_leaks',
    'audience_period_from_scope',
    'build_ledger',
    'compare_scoped_reports',
    'compute_alias',
    'compute_marker',
    'derive_scope_key',
    'disclosure_scope_from_period',
    'export_audience_report',
    'export_report',
    'generate_scoped_report',
    'link_reports',
    'load_ledger',
    'match_reports',
    'publish_report',
    'renew_audience',
    'renew_period',
    'retire_findings',
    'rotate_period',
    'scoped_export',
    'swap_audience',
    'transfer_audience_scope',
    'transfer_filenames',
    'validate_export',
    'verify_link',
    'verify_report',
    'retire_aliases',
    'reassign_findings',
    'update_scope',
    'change_audience',
    'update_audience',
    'create_scoped_report',
    'generate_audience_report',
    'ExportPeriod',
    'AudienceWindow',
    'ExportLedger',
    'PeriodLedger',
    'AudiencePeriodLedger',
]
