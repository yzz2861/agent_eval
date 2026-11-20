"""
Data model for the offline CPE review layer.

The model deliberately keeps CPE strings as their serialized form and only
turns them into :class:`cpe.CPE` objects inside the review engine.  Every
object is serializable to plain dictionaries so that inventory snapshots can
be stored on disk and compared between inventory updates without a network
service.
"""

from collections import OrderedDict


# ---------------------------------------------------------------------------
# Relation kinds
# ---------------------------------------------------------------------------

#: Same identity: two CPE names denote the same component instance.
#: This is the only relation that allows identifier folding.
REL_SAME = "same"

#: Containment: a parent component provably contains a child component.
REL_CONTAINED = "contained"

#: Supplier declaration: only the supplier's name backs the relation, there
#: is no independently queryable component record.
REL_SUPPLIED = "supplied"

RELATION_KINDS = (REL_SAME, REL_CONTAINED, REL_SUPPLIED)


# ---------------------------------------------------------------------------
# Disposition levels used in the remediation list
# ---------------------------------------------------------------------------

#: The asset is provably affected and can enter the remediation scope.
DISPOSITION_ACTIONABLE = "actionable"

#: The only evidence is a supplier declaration; human review is required.
DISPOSITION_REVIEW = "manual_review"

#: No relation could be proven (for example a bare enclosure sharing a
#: product-name layer); the asset stays out of the remediation scope.
DISPOSITION_EXCLUDED = "excluded"


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


class Evidence(object):
    """
    A single piece of evidence supporting or rejecting a relation.

    Evidence is never inferred from a product name alone.  ``source``
    identifies the record that backs it (for example ``inventory``,
    ``hierarchy`` or ``supplier-declaration``) and ``detail`` carries the
    machine-readable facts needed to audit the decision later.
    """

    def __init__(self, source, detail, supports=True):
        self.source = source
        self.detail = dict(detail)
        self.supports = bool(supports)

    def to_dict(self):
        return OrderedDict((
            ("source", self.source),
            ("supports", self.supports),
            ("detail", OrderedDict(sorted(self.detail.items()))),
        ))

    @classmethod
    def from_dict(cls, data):
        return cls(
            source=data["source"],
            detail=data.get("detail", {}),
            supports=data.get("supports", True),
        )

    def __repr__(self):
        return "Evidence(source={0!r}, supports={1})".format(
            self.source, self.supports)


class Relation(object):
    """
    A classified relation between an advisory entry and an asset component.

    ``chain`` holds the ordered CPE names walked for a containment proof
    (parent first, child last).  It is empty for ``same`` and ``supplied``
    relations because neither one walks a hierarchy.
    """

    def __init__(self, kind, subject_cpe, object_cpe, evidence, chain=None,
                 asset_id=None):
        if kind not in RELATION_KINDS:
            raise ValueError("Unknown relation kind: {0}".format(kind))
        self.kind = kind
        self.subject_cpe = subject_cpe
        self.object_cpe = object_cpe
        self.evidence = list(evidence)
        self.chain = list(chain or [])
        self.asset_id = asset_id

    def to_dict(self):
        return OrderedDict((
            ("asset_id", self.asset_id),
            ("kind", self.kind),
            ("subject_cpe", self.subject_cpe),
            ("object_cpe", self.object_cpe),
            ("chain", list(self.chain)),
            ("evidence", [item.to_dict() for item in self.evidence]),
        ))

    @classmethod
    def from_dict(cls, data):
        return cls(
            kind=data["kind"],
            subject_cpe=data["subject_cpe"],
            object_cpe=data["object_cpe"],
            evidence=[Evidence.from_dict(item)
                      for item in data.get("evidence", [])],
            chain=data.get("chain", []),
            asset_id=data.get("asset_id"),
        )

    def __repr__(self):
        return "Relation({0}, {1!r} -> {2!r})".format(
            self.kind, self.subject_cpe, self.object_cpe)


class Asset(object):
    """
    A fictional or real device stored in the inventory.

    Three kinds of CPE records are tracked separately:

    - ``device_cpe`` identifies the hardware/device itself.
    - ``component_cpes`` are queryable component records (firmware,
      distribution packages, package components).  Each one can appear in a
      containment chain.
    - ``enclosure_cpes`` are physical enclosures sharing the supplier's
      product-naming layer.  They are recorded so that the review can show
      why they must not be treated as affected software.

    ``supplier_claims`` maps a claimed component CPE to the supplier name
    recorded in a declaration, used when no queryable record exists.
    ``parent_links`` stores explicit containment edges
    ``parent_cpe -> [child_cpe, ...]`` extracted from inventory documents.
    """

    def __init__(self, asset_id, hostname, device_cpe,
                 component_cpes=None, enclosure_cpes=None,
                 supplier_claims=None, parent_links=None,
                 identity_aliases=None):
        self.asset_id = asset_id
        self.hostname = hostname
        self.device_cpe = device_cpe
        self.component_cpes = list(_as_list(component_cpes))
        self.enclosure_cpes = list(_as_list(enclosure_cpes))
        self.supplier_claims = dict(supplier_claims or {})
        self.parent_links = dict(
            (parent, list(_as_list(children)))
            for parent, children in (parent_links or {}).items())
        # Explicit same-identity alias groups: every CPE in a group is an
        # alternative name for the same component instance and may be folded.
        self.identity_aliases = [
            list(_as_list(group)) for group in (identity_aliases or [])]

    def all_known_cpes(self):
        """Every CPE backed by an inventory record (excludes claims)."""
        known = [self.device_cpe]
        known.extend(self.component_cpes)
        known.extend(self.enclosure_cpes)
        for group in self.identity_aliases:
            known.extend(group)
        return known

    def to_dict(self):
        return OrderedDict((
            ("asset_id", self.asset_id),
            ("hostname", self.hostname),
            ("device_cpe", self.device_cpe),
            ("component_cpes", list(self.component_cpes)),
            ("enclosure_cpes", list(self.enclosure_cpes)),
            ("supplier_claims", OrderedDict(sorted(self.supplier_claims.items()))),
            ("identity_aliases", [
                list(group) for group in self.identity_aliases]),
            ("parent_links", OrderedDict(sorted(self.parent_links.items()))),
        ))

    @classmethod
    def from_dict(cls, data):
        return cls(
            asset_id=data["asset_id"],
            hostname=data["hostname"],
            device_cpe=data["device_cpe"],
            component_cpes=data.get("component_cpes", []),
            enclosure_cpes=data.get("enclosure_cpes", []),
            supplier_claims=data.get("supplier_claims", {}),
            parent_links=data.get("parent_links", {}),
            identity_aliases=data.get("identity_aliases", []),
        )


class AdvisoryEntry(object):
    """A vulnerable CPE name published by an advisory, with its source."""

    def __init__(self, advisory_id, cpe_str, title=""):
        self.advisory_id = advisory_id
        self.cpe_str = cpe_str
        self.title = title

    def to_dict(self):
        return OrderedDict((
            ("advisory_id", self.advisory_id),
            ("cpe_str", self.cpe_str),
            ("title", self.title),
        ))

    @classmethod
    def from_dict(cls, data):
        return cls(
            advisory_id=data["advisory_id"],
            cpe_str=data["cpe_str"],
            title=data.get("title", ""),
        )


class DispositionItem(object):
    """
    One row of the remediation list.

    The item explains *why* an asset is in scope, out of scope or only
    eligible for manual review, keeping the supporting relations attached.
    """

    def __init__(self, asset_id, disposition, matched_cpe, relations, reason,
                 rejections=None):
        self.asset_id = asset_id
        self.disposition = disposition
        self.matched_cpe = matched_cpe
        self.relations = list(relations)
        self.reason = reason
        self.rejections = list(rejections or [])

    def to_dict(self):
        return OrderedDict((
            ("asset_id", self.asset_id),
            ("disposition", self.disposition),
            ("matched_cpe", self.matched_cpe),
            ("reason", self.reason),
            ("relations", [relation.to_dict() for relation in self.relations]),
            ("rejections", [item.to_dict() for item in self.rejections]),
        ))

    @classmethod
    def from_dict(cls, data):
        return cls(
            asset_id=data["asset_id"],
            disposition=data["disposition"],
            matched_cpe=data["matched_cpe"],
            relations=[Relation.from_dict(item)
                       for item in data.get("relations", [])],
            reason=data["reason"],
            rejections=[Evidence.from_dict(item)
                        for item in data.get("rejections", [])],
        )
