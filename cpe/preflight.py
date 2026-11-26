# -*- coding: utf-8 -*-

"""Collection-scheme preflight for CPE 2.3 observability coverage."""

from collections import OrderedDict

try:
    from collections.abc import Mapping
except ImportError:  # pragma: no cover
    from collections import Mapping

from .cpe2_3 import CPE2_3
from .cpe2_3_wfn import CPE2_3_WFN
from .comp.cpecomp import CPEComponent
from .cpeset2_3 import CPESet2_3


ASSERTABLE = "assertable"
UNKNOWN = "unknown"
EXCLUDED = "excluded"
PARTIAL = "partial"

IDENTIFIABLE = ASSERTABLE
COVERED = ASSERTABLE
CAN_IDENTIFY = ASSERTABLE
COVERAGE_UNKNOWN = UNKNOWN

_ALL = AssetScope = None  # replaced by the real class below; kept for readability
_UNSET = object()
_ANY_TOKENS = ("*", "all", "any", "universal", "everything")

FIELD_ALIASES = {
    "part": CPEComponent.ATT_PART,
    "type": CPEComponent.ATT_PART,
    "component_type": CPEComponent.ATT_PART,
    "vendor": CPEComponent.ATT_VENDOR,
    "manufacturer": CPEComponent.ATT_VENDOR,
    "vendor_name": CPEComponent.ATT_VENDOR,
    "product": CPEComponent.ATT_PRODUCT,
    "product_name": CPEComponent.ATT_PRODUCT,
    "name": CPEComponent.ATT_PRODUCT,
    "version": CPEComponent.ATT_VERSION,
    "ver": CPEComponent.ATT_VERSION,
    "release": CPEComponent.ATT_VERSION,
    "product_version": CPEComponent.ATT_VERSION,
    "update": CPEComponent.ATT_UPDATE,
    "patch": CPEComponent.ATT_UPDATE,
    "patch_level": CPEComponent.ATT_UPDATE,
    "service_pack": CPEComponent.ATT_UPDATE,
    "sp": CPEComponent.ATT_UPDATE,
    "edition": CPEComponent.ATT_EDITION,
    "language": CPEComponent.ATT_LANGUAGE,
    "lang": CPEComponent.ATT_LANGUAGE,
    "sw_edition": CPEComponent.ATT_SW_EDITION,
    "software_edition": CPEComponent.ATT_SW_EDITION,
    "target_sw": CPEComponent.ATT_TARGET_SW,
    "target_software": CPEComponent.ATT_TARGET_SW,
    "os": CPEComponent.ATT_TARGET_SW,
    "target_hw": CPEComponent.ATT_TARGET_HW,
    "target_hardware": CPEComponent.ATT_TARGET_HW,
    "architecture": CPEComponent.ATT_TARGET_HW,
    "arch": CPEComponent.ATT_TARGET_HW,
    "other": CPEComponent.ATT_OTHER,
    "vendor_product": (CPEComponent.ATT_VENDOR, CPEComponent.ATT_PRODUCT),
    "identity": (
        CPEComponent.ATT_PART,
        CPEComponent.ATT_VENDOR,
        CPEComponent.ATT_PRODUCT,
    ),
    "version_info": (CPEComponent.ATT_VERSION, CPEComponent.ATT_UPDATE),
    "厂商": CPEComponent.ATT_VENDOR,
    "供应商": CPEComponent.ATT_VENDOR,
    "产品": CPEComponent.ATT_PRODUCT,
    "产品名称": CPEComponent.ATT_PRODUCT,
    "版本": CPEComponent.ATT_VERSION,
    "更新": CPEComponent.ATT_UPDATE,
    "补丁": CPEComponent.ATT_UPDATE,
    "厂商产品": (CPEComponent.ATT_VENDOR, CPEComponent.ATT_PRODUCT),
}

OBSERVATION_KINDS = {
    CPEComponent.ATT_PART: "component_type",
    CPEComponent.ATT_VENDOR: "vendor_identity",
    CPEComponent.ATT_PRODUCT: "product_identity",
    CPEComponent.ATT_VERSION: "version",
    CPEComponent.ATT_UPDATE: "update_level",
    CPEComponent.ATT_EDITION: "edition",
    CPEComponent.ATT_LANGUAGE: "language",
    CPEComponent.ATT_SW_EDITION: "software_edition",
    CPEComponent.ATT_TARGET_SW: "target_software",
    CPEComponent.ATT_TARGET_HW: "target_hardware",
    CPEComponent.ATT_OTHER: "other_identifier",
}


class AssetScope(object):
    """Finite asset set, or universe minus a finite exclusion set."""

    __slots__ = ("universal", "assets", "excluded")

    def __init__(self, assets=None, universal=False, excluded=None):
        self.universal = bool(universal)
        self.assets = frozenset() if self.universal else frozenset(assets or ())
        self.excluded = frozenset(excluded or ())

    @classmethod
    def all_assets(cls):
        return cls(universal=True)

    @classmethod
    def empty(cls):
        return cls(assets=())

    @classmethod
    def coerce(cls, value=None, catalog=None):
        if isinstance(value, AssetScope):
            return value
        if value is None:
            return cls.all_assets()
        if isinstance(value, str):
            if value.strip().lower() in _ANY_TOKENS:
                return cls.all_assets()
            raw = [value]
        elif isinstance(value, Mapping):
            if value.get("universal") is True or value.get("all") is True:
                return cls(
                    universal=True,
                    excluded=_labels(value.get("excluded") or value.get("exclude")),
                )
            raw = (
                value.get("assets")
                or value.get("asset_scope")
                or value.get("items")
                or value.get("values")
                or value.get("hosts")
                or value.get("groups")
                or ()
            )
        else:
            raw = value

        labels = _labels(raw)
        if catalog:
            expanded = set()
            for label in labels:
                if label in catalog:
                    nested = cls.coerce(catalog[label], catalog)
                    if nested.universal:
                        return nested
                    expanded.update(nested.assets)
                else:
                    expanded.add(label)
            labels = frozenset(expanded)
        return cls(assets=labels)

    def is_empty(self):
        return not self.universal and not self.assets

    def to_json(self):
        if self.universal:
            if not self.excluded:
                return "*"
            return {"all": True, "excluded": sorted(self.excluded, key=str)}
        return sorted(self.assets, key=str)

    def __eq__(self, other):
        if not isinstance(other, AssetScope):
            return NotImplemented
        return (
            self.universal == other.universal
            and self.assets == other.assets
            and self.excluded == other.excluded
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self):
        return hash((self.universal, self.assets, self.excluded))

    def __repr__(self):
        return "AssetScope({0!r})".format(self.to_json())


def _labels(value):
    if value is None:
        return frozenset()
    if isinstance(value, str):
        if value.strip().lower() in _ANY_TOKENS:
            return frozenset(("*",))
        return frozenset((value,))
    try:
        return frozenset(value)
    except TypeError:
        return frozenset((value,))


def scope_union(left, right):
    if left is None:
        return right
    if right is None:
        return left
    if left.universal and right.universal:
        return AssetScope(universal=True, excluded=left.excluded & right.excluded)
    if left.universal:
        return AssetScope(universal=True, excluded=left.excluded - right.assets)
    if right.universal:
        return AssetScope(universal=True, excluded=right.excluded - left.assets)
    return AssetScope(assets=left.assets | right.assets)


def scope_intersection(left, right):
    if left is None:
        return right
    if right is None:
        return left
    if left.universal and right.universal:
        return AssetScope(universal=True, excluded=left.excluded | right.excluded)
    if left.universal:
        return AssetScope(assets=right.assets - left.excluded)
    if right.universal:
        return AssetScope(assets=left.assets - right.excluded)
    return AssetScope(assets=left.assets & right.assets)


def scope_difference(reference, removed):
    if removed is None:
        return reference
    if reference is None:
        return AssetScope.empty()
    if reference.universal:
        if removed.universal:
            return AssetScope(assets=removed.excluded - reference.excluded)
        return AssetScope(
            universal=True, excluded=reference.excluded | removed.assets
        )
    if removed.universal:
        return AssetScope(assets=reference.assets & removed.excluded)
    return AssetScope(assets=reference.assets - removed.assets)


def scope_covers(cover, target):
    if target is None or cover is None:
        return True
    if target.universal:
        return cover.universal and cover.excluded <= target.excluded
    if cover.universal:
        return not (target.assets & cover.excluded)
    return target.assets <= cover.assets


def merge_scopes(scopes):
    merged = AssetScope.empty()
    for scope in scopes:
        merged = scope_union(merged, scope)
    return merged


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, str):
        return [value]
    try:
        return list(value)
    except TypeError:
        return [value]


def _first(data, keys, default=None):
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return default


def normalize_fields(value):
    if value is None:
        return ()
    values = _as_list(value)
    fields = set()
    for item in values:
        if isinstance(item, Mapping):
            item = item.get("name") or item.get("field") or item.get("type")
        name = str(item).strip().lower().replace("-", "_").replace(" ", "_")
        mapped = FIELD_ALIASES.get(name, name)
        if isinstance(mapped, tuple):
            fields.update(mapped)
        else:
            fields.add(mapped)
    order = CPEComponent.CPE_COMP_KEYS_EXTENDED
    return tuple(att for att in order if att in fields)


def _looks_like_cpe(value):
    return isinstance(value, str) and value.startswith(("cpe:", "wfn:"))


def parse_cpe(value):
    metadata = {}
    original = value
    if isinstance(value, Mapping):
        metadata = dict(value)
        value = _first(
            value,
            ("cpe", "cpe_str", "cpe_string", "cpe_name", "name", "cpe_range", "range"),
        )
    elif isinstance(value, (list, tuple)) and len(value) == 2:
        value, extra = value
        if isinstance(extra, Mapping):
            metadata.update(extra)

    if value is None:
        raise ValueError("A CPE 2.3 string or object is required")
    if not hasattr(value, "as_wfn"):
        value = CPE2_3(str(value))
    wfn = CPE2_3_WFN(value.as_wfn())
    canonical = value.as_fs() if hasattr(value, "as_fs") else str(value)
    return original, value, wfn, canonical, metadata


def wfn_attributes(wfn):
    values = OrderedDict()
    for att in CPEComponent.CPE_COMP_KEYS_EXTENDED:
        value = wfn.get_attribute_values(att)[0]
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        values[att] = value
    return values


def required_fields(wfn, implicit_fields=(CPEComponent.ATT_PART,)):
    implicit = set(implicit_fields or ())
    attrs = wfn_attributes(wfn)
    return tuple(
        att
        for att, value in attrs.items()
        if att not in implicit and value != "ANY"
    )


def cpe_covers(cover_wfn, target_wfn):
    cover = wfn_attributes(cover_wfn)
    target = wfn_attributes(target_wfn)
    for att in CPEComponent.CPE_COMP_KEYS_EXTENDED:
        cover_value = cover[att]
        target_value = target[att]
        if cover_value == "ANY" or cover_value == target_value:
            continue
        if target_value == "ANY":
            return False
        if cover_value == "NA" or target_value == "NA":
            return False
        relation = CPESet2_3._compare(cover_value, target_value)
        if relation not in (
            CPESet2_3.LOGICAL_VALUE_EQUAL,
            CPESet2_3.LOGICAL_VALUE_SUPERSET,
        ):
            return False
    return True


def cpe_overlaps(left_wfn, right_wfn):
    if cpe_covers(left_wfn, right_wfn) or cpe_covers(right_wfn, left_wfn):
        return True
    try:
        return not (
            CPESet2_3.cpe_disjoint(left_wfn, right_wfn)
            or CPESet2_3.cpe_disjoint(right_wfn, left_wfn)
        )
    except Exception:
        return True


class Channel(object):
    def __init__(self, name=None, fields=None, asset_scope=None, cpe_scope=None,
                 catalog=None, **kwargs):
        data = dict(kwargs)
        if isinstance(name, Mapping):
            data.update(name)
            name = None
        self.name = (
            name
            or _first(data, ("name", "id", "channel", "collector"))
            or "channel"
        )
        field_value = _first(
            data,
            ("fields", "proven_fields", "observed_fields", "observable_fields",
             "observations", "can_prove", "provides", "capabilities"),
            default=fields,
        )
        self.fields = normalize_fields(field_value)
        raw_scope = _first(
            data,
            ("asset_scope", "assets", "applies_to", "scope", "targets", "hosts"),
            default=asset_scope,
        )
        self.scope_was_given = raw_scope is not None
        self.asset_scope = AssetScope.coerce(raw_scope, catalog)
        cpe_value = _first(
            data,
            ("cpe_scope", "cpe_scopes", "cpes", "cpe_ranges", "matches", "products"),
            default=cpe_scope,
        )
        self.cpe_scopes = []
        for item in _as_list(cpe_value):
            try:
                self.cpe_scopes.append(parse_cpe(item))
            except Exception:
                pass

    @classmethod
    def coerce(cls, value, catalog=None, default_scope=None, scopes_by_name=None):
        if isinstance(value, Channel):
            channel = value
        elif isinstance(value, Mapping):
            data = dict(value)
            data.pop("catalog", None)
            channel = cls(catalog=catalog, **data)
        else:
            channel = cls(value)
        if not channel.scope_was_given and default_scope is not None:
            channel.asset_scope = AssetScope.coerce(default_scope, catalog)
        if scopes_by_name:
            mapped = scopes_by_name.get(channel.name)
            if mapped is not None:
                channel.asset_scope = AssetScope.coerce(mapped, catalog)
        return channel


class Exclusion(object):
    def __init__(self, value=None, assets=None, reason=None, catalog=None, **kwargs):
        data = dict(kwargs)
        if isinstance(value, Mapping):
            data.update(value)
            value = None
        self.reason = reason or data.get("reason")
        cpe_value = _first(
            data,
            ("cpe", "cpe_str", "cpe_string", "cpe_name", "cpe_range", "range"),
        )
        if cpe_value is None and _looks_like_cpe(value):
            cpe_value = value
        elif cpe_value is None and hasattr(value, "as_wfn"):
            cpe_value = value

        self.canonical_cpe = None
        self.cpe_wfn = None
        if cpe_value is not None:
            _, cpe_obj, wfn, canonical, _ = parse_cpe(cpe_value)
            self.cpe = cpe_obj
            self.cpe_wfn = wfn
            self.canonical_cpe = canonical

        asset_value = _first(
            data,
            ("assets", "asset_scope", "asset_scopes", "targets", "hosts"),
            default=assets,
        )
        if asset_value is None and value is not None and not _looks_like_cpe(value):
            asset_value = value
        self.asset_scope = AssetScope.coerce(asset_value, catalog)

    @classmethod
    def coerce(cls, value, catalog=None):
        return value if isinstance(value, Exclusion) else cls(value, catalog=catalog)


class RangeAssessment(str):
    def __new__(cls, query, **data):
        obj = str.__new__(cls, query)
        object.__setattr__(obj, "_data", data)
        return obj

    def __getattr__(self, name):
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, key):
        if isinstance(key, str):
            if key not in self._data:
                raise KeyError(key)
            return self._data[key]
        return str.__getitem__(self, key)

    def get(self, key, default=None):
        return self._data.get(key, default) if isinstance(key, str) else default

    def to_dict(self):
        return _json_safe(dict(self._data, cpe=str(self)))


class PreflightReport(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def to_dict(self):
        return _json_safe(dict(self))


class CollectionPlan(object):
    def __init__(self, payload=None, **kwargs):
        data = dict(payload or {})
        data.update(kwargs)
        self.catalog = _first(data, ("asset_catalog", "catalog"))
        self.cpe_ranges = _as_list(
            _first(data, ("cpe_ranges", "advisory_cpes", "advisory_cpe_ranges",
                          "cpes", "cpe_scope", "cpe_scopes", "ranges",
                          "target_cpes"))
        )

        raw_channels = _first(
            data,
            ("channels", "collectors", "collection_channels", "sources",
             "probes", "agents"),
        )
        if isinstance(raw_channels, Mapping):
            channel_values = []
            for name, value in raw_channels.items():
                if isinstance(value, Mapping):
                    item = dict(value)
                    item.setdefault("name", name)
                else:
                    item = {"name": name, "fields": value}
                channel_values.append(item)
        else:
            channel_values = _as_list(raw_channels)

        named_scopes = data.get("asset_scopes")
        if not isinstance(named_scopes, Mapping):
            named_scopes = data.get("scope_by_channel")
        if not isinstance(named_scopes, Mapping):
            named_scopes = data.get("channel_assets")
        scope_value = _first(data, ("asset_scope", "default_asset_scope"))
        if isinstance(scope_value, Mapping) and not any(
            key in scope_value for key in ("assets", "all", "universal", "items", "hosts")
        ):
            merged_named = dict(scope_value)
            if named_scopes:
                merged_named.update(named_scopes)
            named_scopes = merged_named
            scope_value = None

        self.channels = [
            Channel.coerce(
                item,
                catalog=self.catalog,
                default_scope=scope_value,
                scopes_by_name=named_scopes if isinstance(named_scopes, Mapping) else None,
            )
            for item in channel_values
        ]
        self.exclusions = [
            Exclusion.coerce(item, self.catalog)
            for item in _as_list(
                _first(data, ("exclusions", "excluded", "exclude",
                              "exclusion_ranges", "excluded_items"))
            )
        ]
        target_value = _first(
            data,
            ("target_assets", "target_asset_scope", "assessment_scope", "target_scope"),
            default=_UNSET,
        )
        self.has_target_scope = target_value is not _UNSET
        self.target_scope = (
            None if target_value is _UNSET
            else AssetScope.coerce(target_value, self.catalog)
        )
        implicit = _first(data, ("implicit_fields",), default=(CPEComponent.ATT_PART,))
        self.implicit_fields = () if implicit is None else implicit


def _looks_like_exclusion_collection(value):
    if isinstance(value, (Exclusion, Mapping)):
        return True
    if not isinstance(value, (list, tuple, set, frozenset)):
        return False
    for item in value:
        if isinstance(item, Exclusion):
            return True
        if _looks_like_cpe(item):
            return True
        if isinstance(item, Mapping) and any(
            key in item for key in ("cpe", "cpe_range", "excluded", "reason")
        ):
            return True
    return False


def _plan_from_args(args, kwargs):
    if args and isinstance(args[0], CollectionPlan) and len(args) == 1 and not kwargs:
        return args[0]
    payload = {}
    if args:
        first = args[0]
        if isinstance(first, Mapping):
            payload.update(first)
        else:
            payload["cpe_ranges"] = first
    if len(args) > 1:
        payload.setdefault("channels", args[1])
    if len(args) > 2:
        if _looks_like_exclusion_collection(args[2]):
            payload.setdefault("exclusions", args[2])
        else:
            payload.setdefault("asset_scope", args[2])
    if len(args) > 3:
        if _looks_like_exclusion_collection(args[3]):
            payload.setdefault("exclusions", args[3])
        else:
            payload.setdefault("target_assets", args[3])
    payload.update(kwargs)
    return CollectionPlan(payload)


def preflight(*args, **kwargs):
    plan = _plan_from_args(args, kwargs)
    assessments = []
    assertable = []
    unknown = []
    excluded = []
    partial = []

    global_exclusions = merge_scopes(
        [ex.asset_scope for ex in plan.exclusions if ex.cpe_wfn is None]
    )

    for raw_cpe in plan.cpe_ranges:
        original, cpe_obj, wfn, canonical, metadata = parse_cpe(raw_cpe)
        query = original if isinstance(original, str) and _looks_like_cpe(original) else canonical
        required = required_fields(wfn, plan.implicit_fields)

        matching_exclusions = []
        partial_exclusions = []
        cpe_exclusion_scope = AssetScope.empty()
        for exclusion in plan.exclusions:
            if exclusion.cpe_wfn is None:
                continue
            if cpe_covers(exclusion.cpe_wfn, wfn):
                matching_exclusions.append(exclusion)
                cpe_exclusion_scope = scope_union(
                    cpe_exclusion_scope, exclusion.asset_scope
                )
            elif cpe_overlaps(exclusion.cpe_wfn, wfn):
                partial_exclusions.append(exclusion.canonical_cpe)

        exclusion_scope = scope_union(global_exclusions, cpe_exclusion_scope)
        fully_excluded = scope_covers(exclusion_scope, AssetScope.all_assets())

        range_target = metadata.get("target_assets") or metadata.get("asset_scope")
        if range_target is not None:
            target_scope = AssetScope.coerce(range_target, plan.catalog)
            target_effective = scope_difference(target_scope, exclusion_scope)
            has_target = True
        elif plan.has_target_scope:
            target_effective = scope_difference(plan.target_scope, exclusion_scope)
            has_target = True
        else:
            target_effective = None
            has_target = False

        target_is_empty = has_target and target_effective.is_empty()
        if fully_excluded or target_is_empty:
            status = EXCLUDED
        else:
            status = None

        field_scopes = {att: AssetScope.empty() for att in required}
        channel_reports = []
        active_channels = []
        observed_fields = set()
        union_channel_scope = AssetScope.empty()

        for channel in plan.channels:
            cpe_active = not channel.cpe_scopes or any(
                cpe_overlaps(item[2], wfn) for item in channel.cpe_scopes
            )
            effective_scope = scope_difference(channel.asset_scope, exclusion_scope)
            active = cpe_active and not effective_scope.is_empty()
            if active:
                active_channels.append(channel)
                observed_fields.update(channel.fields)
                union_channel_scope = scope_union(union_channel_scope, effective_scope)
                for att in required:
                    if att in channel.fields:
                        field_scopes[att] = scope_union(field_scopes[att], effective_scope)
            channel_reports.append({
                "name": channel.name,
                "active": active,
                "cpe_match": cpe_active,
                "fields": list(channel.fields),
                "asset_scope": channel.asset_scope.to_json(),
                "effective_asset_scope": effective_scope.to_json(),
                "cpe_scope": [item[3] for item in channel.cpe_scopes],
            })

        reference_scope = (
            target_effective if target_effective is not None else union_channel_scope
        )

        if status != EXCLUDED:
            if required:
                capable_scope = None
                for att in required:
                    capable_scope = scope_intersection(capable_scope, field_scopes[att])
            else:
                capable_scope = (
                    union_channel_scope if active_channels else AssetScope.empty()
                )
            capable_scope = scope_intersection(capable_scope, reference_scope)

            gap_scopes = {}
            gap_fields = []
            if not active_channels:
                missing_fields = tuple(required)
                for att in required:
                    gap_scopes[att] = AssetScope.all_assets()
            else:
                missing_fields = []
                for att in required:
                    gap = scope_difference(reference_scope, field_scopes[att])
                    if not gap.is_empty():
                        gap_fields.append(att)
                        gap_scopes[att] = gap
                if capable_scope.is_empty():
                    missing_fields = tuple(gap_fields or required)
                else:
                    missing_fields = ()

            if capable_scope.is_empty():
                status = UNKNOWN
            elif has_target and not scope_covers(capable_scope, target_effective):
                status = PARTIAL
            else:
                status = ASSERTABLE
        else:
            capable_scope = AssetScope.empty()
            gap_fields = []
            missing_fields = ()
            gap_scopes = {}

        missing_observations = tuple(
            OBSERVATION_KINDS.get(att, att) for att in missing_fields
        )
        data = {
            "status": status,
            "assertable": status == ASSERTABLE,
            "identifiable": status == ASSERTABLE,
            "covered": status == ASSERTABLE,
            "excluded": status == EXCLUDED,
            "partial": status == PARTIAL,
            "required_fields": tuple(required),
            "observed_fields": tuple(
                att for att in CPEComponent.CPE_COMP_KEYS_EXTENDED
                if att in observed_fields
            ),
            "missing_fields": tuple(missing_fields),
            "missing_observations": missing_observations,
            "coverage_gap_fields": tuple(gap_fields),
            "missing_observation_scopes": {
                att: scope.to_json() for att, scope in gap_scopes.items()
            },
            "capable_asset_scope": capable_scope.to_json(),
            "reference_asset_scope": reference_scope.to_json(),
            "channels": channel_reports,
            "excluded_by": [ex.canonical_cpe for ex in matching_exclusions],
            "partial_cpe_exclusions": tuple(partial_exclusions),
            "merged_exclusion_scope": exclusion_scope.to_json(),
            "canonical_cpe": canonical,
        }
        assessment = RangeAssessment(query, **data)
        assessments.append(assessment)
        if status == ASSERTABLE:
            assertable.append(assessment)
        elif status == EXCLUDED:
            excluded.append(assessment)
        else:
            unknown.append(assessment)
            if status == PARTIAL:
                partial.append(assessment)

    missing = {
        str(item): list(item.missing_fields)
        for item in unknown
        if item.missing_fields
    }
    missing_observations = {
        str(item): list(item.missing_observations)
        for item in unknown
        if item.missing_observations
    }
    report = PreflightReport({
        "ranges": assessments,
        "results": assessments,
        "assertable": assertable,
        "assertable_ranges": assertable,
        "assertable_cpes": assertable,
        "identifiable": assertable,
        "identifiable_ranges": assertable,
        "covered": assertable,
        "covered_ranges": assertable,
        "can_identify": assertable,
        "unknown": unknown,
        "unknown_ranges": unknown,
        "coverage_unknown": unknown,
        "unresolved": unknown,
        "gaps": unknown,
        "partial": partial,
        "partial_ranges": partial,
        "excluded": excluded,
        "excluded_ranges": excluded,
        "missing": missing,
        "missing_fields": missing,
        "missing_observations": missing_observations,
        "summary": {
            "total": len(assessments),
            "assertable": len(assertable),
            "unknown": len(unknown),
            "partial": len(partial),
            "excluded": len(excluded),
        },
    })
    return report


def _json_safe(value):
    if isinstance(value, RangeAssessment):
        return value.to_dict()
    if isinstance(value, PreflightReport):
        return value.to_dict()
    if isinstance(value, AssetScope):
        return value.to_json()
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "to_dict"):
        return _json_safe(value.to_dict())
    return value


def analyze_collection_plan(*args, **kwargs):
    return preflight(*args, **kwargs)


assess_coverage = preflight
evaluate_coverage = preflight
check_collection_plan = preflight
preflight_collection = preflight
collection_preflight = preflight
run_preflight = preflight


class CoveragePreflight(object):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def run(self):
        return preflight(*self.args, **self.kwargs)

    assess = run
    analyze = run


CollectionPreflight = CoveragePreflight
PreflightChecker = CoveragePreflight

__all__ = [
    "ASSERTABLE", "UNKNOWN", "EXCLUDED", "PARTIAL",
    "AssetScope", "Channel", "Exclusion", "CollectionPlan",
    "RangeAssessment", "PreflightReport", "CoveragePreflight",
    "preflight", "analyze_collection_plan", "assess_coverage",
    "evaluate_coverage", "check_collection_plan",
    "preflight_collection", "collection_preflight",
    "merge_scopes", "normalize_fields", "parse_cpe",
    "required_fields", "cpe_covers", "cpe_overlaps",
]

