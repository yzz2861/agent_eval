"""Offline filter replay for STIX2 DataSources.

A search recorded against a data source can be replayed later without
consulting the current state of any data store.  The replay is bound to
three pieces of information captured at search time:

1. the original filters (the search conditions),
2. the object range that was provably available at search time (derived
   from a preservation record / manifest), and
3. the STIX specification version selected for the search.

If a preserved object is missing from the replay payload, the affected
part of the range is placed in a separate "quarantined" section instead of
being silently substituted with the current contents of a data store.
Objects that only entered the store after the preservation window are kept
out of scope; the replay receipt explains why they were excluded.

|
"""

import collections
import copy
from datetime import datetime

import simplejson as json

from stix2.datastore.filters import Filter, FilterSet, apply_common_filters
from stix2.parsing import parse
from stix2.serialization import STIXJSONEncoder
from stix2.utils import format_datetime, get_timestamp

# Reason codes used on replay receipt entries.
REASON_MATCHED = "matched"
REASON_FILTERED_OUT = "filtered-out"
REASON_MISSING_PRESERVED_OBJECT = "missing-preserved-object"
REASON_OUTSIDE_PRESERVATION_WINDOW = "outside-preservation-window"
REASON_VERSION_NOT_PRESERVED = "version-not-preserved"


class ReplayEntry(collections.namedtuple("ReplayEntry", ["id", "version", "reason", "details"])):
    """A single line item in a :class:`ReplayReceipt`.

    Args:
        id (str): STIX ID of the object the entry refers to.
        version (str): ``modified`` timestamp of the relevant object
            version, or None for unversioned objects / missing data.
        reason (str): machine-readable reason code explaining the entry.
        details (str): human-readable explanation.
    """
    __slots__ = ()


class ReplayReceipt(object):
    """Result of an offline filter replay.

    The receipt separates confirmed results from anything that could not be
    confirmed offline.  Nothing in the receipt is derived from the current
    state of a live data store.

    Attributes:
        search (SearchRecord): the search record that was replayed.
        results (list): STIX objects that matched the original filters
            within the preserved range.
        excluded (list[ReplayEntry]): preserved objects that failed one or
            more of the original filters.
        quarantined (list[ReplayEntry]): preserved-range entries whose
            objects are missing from the replay payload and therefore
            could not be evaluated.
        out_of_scope (list[ReplayEntry]): objects presented to the replay
            that were not part of the preserved range (e.g. ingested after
            the preservation window).
    """

    def __init__(self, search):
        self.search = search
        self.results = []
        self.excluded = []
        self.quarantined = []
        self.out_of_scope = []

    @property
    def unverifiable(self):
        """Alias for :attr:`quarantined`: the parts that cannot be
        confirmed with the available replay data."""
        return self.quarantined

    def explain(self, stix_id=None):
        """Explain why an object was included or excluded.

        Args:
            stix_id (str): STIX ID to explain. If None, explanations for
                every non-matching entry are returned.

        Returns:
            list[str]: human-readable explanation lines.
        """
        lines = []
        for entry in self._all_entries():
            if stix_id is None or entry.id == stix_id:
                lines.append(self._format_entry(entry))
        return lines

    def _all_entries(self):
        for stix_obj in self.results:
            yield ReplayEntry(
                stix_obj["id"],
                SearchRecord._timestamp_to_string(stix_obj.get("modified")),
                REASON_MATCHED,
                "object matched all original filters within the preserved range",
            )
        for entry in self.excluded:
            yield entry
        for entry in self.quarantined:
            yield entry
        for entry in self.out_of_scope:
            yield entry

    @staticmethod
    def _format_entry(entry):
        if entry.version:
            return "{id} (version {version}): {reason} - {details}".format(
                id=entry.id, version=entry.version,
                reason=entry.reason, details=entry.details,
            )
        return "{id}: {reason} - {details}".format(
            id=entry.id, reason=entry.reason, details=entry.details,
        )


class SearchRecord(object):
    """An offline-replayable record of a data source search.

    The record is self contained: it holds the original filters, the
    preserved object range and the STIX specification version selected at
    search time, together with frozen copies of the objects themselves.
    Replaying it never reaches back into a live data store.

    Args:
        filters (list): the original search filters.
        objects (list): STIX objects provably available at search time
            (the frozen preservation payload).
        manifest (dict): preservation manifest mapping each STIX ID in the
            preserved range to a list of preserved ``modified`` timestamps
            (an empty list denotes an unversioned object).
        search_time (str): timestamp at which the original search ran.
        spec_version (str): STIX specification version selected for the
            search (e.g. "2.0" or "2.1").
        record_id (str): optional identifier for the record.
    """

    def __init__(self, filters=None, objects=None, manifest=None,
                 search_time=None, spec_version=None, record_id=None):
        self.record_id = record_id
        self.search_time = search_time
        self.spec_version = spec_version
        self.filters = list(FilterSet(filters))
        self.manifest = {
            stix_id: [self._timestamp_to_string(version) for version in versions]
            for stix_id, versions in (manifest or {}).items()
        }
        self.objects = self._index_objects(objects)

    @staticmethod
    def _timestamp_to_string(version):
        if isinstance(version, datetime):
            return format_datetime(version)
        return version

    @staticmethod
    def _index_objects(objects):
        indexed = {}
        for stix_obj in objects or []:
            stix_id = stix_obj["id"]
            version = stix_obj.get("modified")
            if stix_id not in indexed:
                indexed[stix_id] = {}
            indexed[stix_id][SearchRecord._timestamp_to_string(version)] = stix_obj
        return indexed

    def preserved_ids(self):
        """Return the STIX IDs covered by the preservation manifest."""
        return list(self.manifest.keys())

    def has_object(self, stix_id, version=None):
        """Return whether a frozen copy of the given object (version) is
        held by this record."""
        family = self.objects.get(stix_id)
        if not family:
            return False
        if version is None:
            return True
        return self._timestamp_to_string(version) in family

    def get_object(self, stix_id, version=None):
        """Retrieve a frozen object copy. Raises KeyError if the object is
        not part of the replay payload."""
        family = self.objects[stix_id]
        if version is None:
            return next(iter(family.values()))
        return family[self._timestamp_to_string(version)]

    def to_dict(self):
        """Serialize the record to plain JSON-compatible data."""
        frozen_objects = []
        for family in self.objects.values():
            for stix_obj in family.values():
                frozen_objects.append(copy.deepcopy(dict(stix_obj)))

        return {
            "record_id": self.record_id,
            "search_time": self.search_time,
            "spec_version": self.spec_version,
            "filters": [
                {"property": f.property, "op": f.op, "value": f.value}
                for f in self.filters
            ],
            "manifest": copy.deepcopy(self.manifest),
            "objects": frozen_objects,
        }

    def to_json(self, **kwargs):
        """Serialize the record to a JSON string."""
        kwargs.setdefault('cls', STIXJSONEncoder)
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_dict(cls, data):
        """Rebuild a record from :meth:`to_dict` output."""
        filters = [
            Filter(f["property"], f["op"], f["value"])
            for f in data.get("filters", [])
        ]
        spec_version = data.get("spec_version")
        objects = [
            parse(stix_obj, allow_custom=True, version=spec_version)
            for stix_obj in data.get("objects", [])
        ]
        return cls(
            filters=filters,
            objects=objects,
            manifest=data.get("manifest", {}),
            search_time=data.get("search_time"),
            spec_version=spec_version,
            record_id=data.get("record_id"),
        )

    @classmethod
    def from_json(cls, json_str, **kwargs):
        """Rebuild a record from a :meth:`to_json` string."""
        return cls.from_dict(json.loads(json_str, **kwargs))


def record_search(source, query=None, search_time=None, spec_version=None):
    """Capture a data source search as an offline-replayable record.

    The preserved range is the full set of objects visible to the source at
    search time: the source is queried without filters, and the resulting
    objects are frozen into the record.  The preservation manifest is built
    from those same objects, so it only covers provably available data.

    Args:
        source (DataSource): the data source to record against.
        query (list): the original search filters.
        search_time (str): timestamp of the search; defaults to the current
            time.
        spec_version (str): STIX specification version selected for the
            search. If None, the parser's default version detection applies
            on replay.

    Returns:
        SearchRecord: the frozen, offline-replayable search record.
    """
    if search_time is None:
        search_time = get_timestamp()

    frozen_objects = list(source.query())

    manifest = {}
    for stix_obj in frozen_objects:
        stix_id = stix_obj["id"]
        manifest.setdefault(stix_id, [])
        if "modified" in stix_obj:
            modified = stix_obj["modified"]
            manifest[stix_id].append(
                format_datetime(modified)
                if isinstance(modified, datetime)
                else modified,
            )

    return SearchRecord(
        filters=query,
        objects=frozen_objects,
        manifest=manifest,
        search_time=search_time,
        spec_version=spec_version,
    )


def replay_search(record, extra_objects=None):
    """Replay a recorded search entirely offline.

    Only the frozen objects inside ``record`` are used to evaluate the
    original filters; no live data source is ever consulted.  Preserved
    range entries missing from the record's payload are quarantined rather
    than substituted from current store state.  Objects supplied via
    ``extra_objects`` that fall outside the preserved range (for example an
    object ingested only after the preservation window) are never filtered
    against the original query as candidates; they are reported separately
    with an explanation.

    Args:
        record (SearchRecord): the recorded search to replay.
        extra_objects (list): STIX objects that exist now but were not part
            of the original search, e.g. late-ingested objects.

    Returns:
        ReplayReceipt: confirmed results plus isolated, explained entries
        for everything that could not be confirmed or was out of range.
    """
    receipt = ReplayReceipt(record)
    filter_set = FilterSet(record.filters)

    # 1. Walk the preserved range from the manifest. Missing payloads are
    # quarantined; everything available is filtered offline.
    for stix_id, versions in record.manifest.items():
        if not versions:
            _replay_version(record, receipt, filter_set, stix_id, None)
        else:
            for version in versions:
                _replay_version(record, receipt, filter_set, stix_id, version)

    # 2. Account for objects presented now that were not preserved at
    # search time. They remain outside the replayable range.
    for stix_obj in extra_objects or []:
        _classify_outside_scope(record, receipt, stix_obj)

    return receipt


def _replay_version(record, receipt, filter_set, stix_id, version):
    if not record.has_object(stix_id, version):
        receipt.quarantined.append(
            ReplayEntry(
                stix_id, version,
                REASON_MISSING_PRESERVED_OBJECT,
                "object was inside the preserved search range but its "
                "replay payload is missing, so it cannot be evaluated "
                "offline",
            ),
        )
        return

    stix_obj = record.get_object(stix_id, version)
    matched = next(apply_common_filters([stix_obj], filter_set), None)

    if matched is not None:
        receipt.results.append(matched)
    else:
        receipt.excluded.append(
            ReplayEntry(
                stix_id, version, REASON_FILTERED_OUT,
                _filter_failure_details(stix_obj, filter_set),
            ),
        )


def _classify_outside_scope(record, receipt, stix_obj):
    stix_id = stix_obj["id"]
    version = SearchRecord._timestamp_to_string(stix_obj.get("modified"))
    preserved_versions = record.manifest.get(stix_id)

    if preserved_versions is None:
        detail = "object was ingested after the preservation window " \
            "(search time: {}) and was not part of the original search " \
            "range, so the original query excludes it".format(
                record.search_time or "unknown",
            )
        receipt.out_of_scope.append(
            ReplayEntry(
                stix_id, version,
                REASON_OUTSIDE_PRESERVATION_WINDOW, detail,
            ),
        )
    else:
        receipt.out_of_scope.append(
            ReplayEntry(
                stix_id, version,
                REASON_VERSION_NOT_PRESERVED,
                "this version was not part of the preserved search range; "
                "only the preserved versions are replayed",
            ),
        )


def _filter_failure_details(stix_obj, filter_set):
    for filter_ in filter_set:
        prop = filter_.property.split(".")[0]
        if prop not in stix_obj:
            return "failed filter {property} {op} {value!r}: property " \
                "'{property}' is absent".format(
                    property=filter_.property, op=filter_.op,
                    value=filter_.value,
                )
        if next(apply_common_filters([stix_obj], [filter_]), None) is None:
            return "failed filter {property} {op} {value!r}".format(
                property=filter_.property, op=filter_.op,
                value=filter_.value,
            )
    return "failed the original filters"
