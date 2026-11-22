"""Policy-aware re-export of previously cleaned HTML fragments.

Customer service staff paste cleaned user comments into rich-text e-mails,
while the back office also allows the original comment to be edited.  To keep
the two flows safe we need more than the output of a single clean pass: we
need to remember *what the cleaning pass was allowed to keep*.  This module
packages that memory into a :class:`PolicyRecord` and re-applies it when the
same body is sent through a different, possibly wider, export policy.

The rules implemented here are deliberately conservative:

* The recorded capabilities (allowed tags, attributes and protocols) describe
  only what the previous pass actually permitted.  Anything that was removed
  (an attribute, a tag, a URI scheme, a link a callback dropped, ...) is not
  part of the record and can never be re-introduced by a later pass.
* On re-export the *effective* policy is the intersection of the recorded
  capabilities and the new export policy.  A wider export policy therefore
  never restores a capability that was removed the first time around, even if
  a :class:`~bleach.linkifier.Linker` or one of its callbacks would now add it
  (for example ``target_blank`` re-adding ``target="_blank"``).
* If the body no longer matches the recorded one, or the record was produced
  by an older/incompatible version, the material is treated as *unconfirmed*.
  Unconfirmed material is run through the new export policy as ordinary
  inbound material and the returned status says so.

The plain :func:`bleach.clean` and :func:`bleach.linkify` entry points are
unchanged; this module is an opt-in layer on top of them.
"""

import hashlib

from bleach import linkifier
from bleach.sanitizer import (
    ALLOWED_ATTRIBUTES,
    ALLOWED_PROTOCOLS,
    ALLOWED_TAGS,
    Cleaner,
)


#: Version of the PolicyRecord layout produced by this module.  Bump this when
#: the on-the-wire shape changes in a way older consumers cannot understand.
POLICY_RECORD_VERSION = 1


#: Re-export statuses
#: The body matched the record and the intersected policy was applied.
CONFIRMED = "confirmed"
#: The body was edited or the record was stale; full inbound rules were used.
UNCONFIRMED = "unconfirmed"


def _digest(text):
    """Returns a stable digest for a cleaned fragment."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalise_tags(tags):
    return sorted(tags)


def _normalise_protocols(protocols):
    return sorted(protocols)


def _normalise_attributes(attributes):
    """Returns a JSON-friendly {tag: [attr, ...]} mapping.

    Callable attribute policies cannot be serialised into a record, so they are
    rejected up front rather than silently broadened on the next export.
    """
    if callable(attributes):
        raise ValueError(
            "callable attribute policies cannot be recorded; use a list or "
            "dict of attribute names so the policy can be re-applied later"
        )

    if isinstance(attributes, dict):
        normalised = {}
        for tag, value in attributes.items():
            if callable(value):
                raise ValueError(
                    "callable attribute policies cannot be recorded; use a "
                    "list of attribute names so the policy can be re-applied"
                )
            normalised[tag] = sorted(value)
        return normalised

    if isinstance(attributes, (list, tuple)):
        return {"*": sorted(attributes)}

    raise ValueError("attributes needs to be a callable, a list or a dict")


def _intersect_tags(recorded, current):
    return sorted(set(recorded) & set(current))


def _intersect_protocols(recorded, current):
    return sorted(set(recorded) & set(current))


def _intersect_attributes(recorded, current):
    """Intersects two {tag: [attr, ...]} attribute policies.

    A wildcard entry (``"*"``) in either side applies to every tag mentioned
    on the other side.  Only attributes allowed by *both* policies survive.
    """
    recorded_tags = set(recorded)
    current_tags = set(current)

    tags = set()
    if "*" in recorded_tags:
        tags.update(tag for tag in current_tags if tag != "*")
    if "*" in current_tags:
        tags.update(tag for tag in recorded_tags if tag != "*")
    tags.update(recorded_tags & current_tags)

    result = {}
    for tag in sorted(tags):
        recorded_attrs = set(recorded.get(tag, recorded.get("*", [])))
        current_attrs = set(current.get(tag, current.get("*", [])))
        allowed = sorted(recorded_attrs & current_attrs)
        if allowed:
            result[tag] = allowed
    return result


class PolicyRecord:
    """Serializable description of what one cleaning pass was allowed to keep.

    A record captures the *capabilities* of a cleaning pass rather than every
    token it emitted.  It is plain-data friendly (``to_dict`` / ``from_dict``)
    so it can be stored next to the cleaned comment in a database.
    """

    def __init__(
        self,
        body_digest,
        tags,
        attributes,
        protocols,
        version=POLICY_RECORD_VERSION,
    ):
        self.version = version
        self.body_digest = body_digest
        self.tags = list(tags)
        self.attributes = attributes
        self.protocols = list(protocols)

    def to_dict(self):
        """Returns a plain dict suitable for JSON serialisation."""
        return {
            "version": self.version,
            "body_digest": self.body_digest,
            "tags": list(self.tags),
            "attributes": {
                tag: list(attrs) for tag, attrs in self.attributes.items()
            },
            "protocols": list(self.protocols),
        }

    @classmethod
    def from_dict(cls, data):
        """Rebuilds a record previously produced by :meth:`to_dict`."""
        if not isinstance(data, dict):
            raise ValueError("policy record must be a dict")

        try:
            return cls(
                body_digest=data["body_digest"],
                tags=list(data["tags"]),
                attributes={
                    tag: list(attrs) for tag, attrs in data["attributes"].items()
                },
                protocols=list(data["protocols"]),
                version=data["version"],
            )
        except KeyError as exc:
            raise ValueError(f"policy record is missing {exc.args[0]!r}") from exc

    def matches(self, body):
        """Whether ``body`` is exactly the fragment this record describes."""
        return (
            self.version == POLICY_RECORD_VERSION
            and _digest(body) == self.body_digest
        )

    def __eq__(self, other):
        if not isinstance(other, PolicyRecord):
            return NotImplemented
        return self.to_dict() == other.to_dict()

    def __repr__(self):
        return (
            "PolicyRecord("
            f"version={self.version!r}, body_digest={self.body_digest[:12]!r}, "
            f"tags={self.tags!r}, protocols={self.protocols!r})"
        )


class ReexportResult:
    """Outcome of an :func:`reexport` call."""

    def __init__(self, text, record, status, confirmed):
        #: Final fragment that is safe to send to the new export.
        self.text = text
        #: Fresh record describing the capabilities actually applied.
        self.record = record
        #: Either :data:`CONFIRMED` or :data:`UNCONFIRMED`.
        self.status = status
        #: Convenience bool mirroring :attr:`status`.
        self.confirmed = confirmed

    def __repr__(self):
        return f"ReexportResult(status={self.status!r}, text={self.text!r})"


def build_record(cleaned_text, cleaner):
    """Builds a :class:`PolicyRecord` for text produced by ``cleaner``.

    The digest is taken over the exact cleaned fragment so that any later edit
    invalidates the confirmation.

    :arg str cleaned_text: the fragment returned by the cleaning pass
    :arg Cleaner cleaner: the :class:`~bleach.sanitizer.Cleaner` that produced
        it; its configured capabilities are recorded

    :returns: a :class:`PolicyRecord`
    """
    return PolicyRecord(
        body_digest=_digest(cleaned_text),
        tags=_normalise_tags(cleaner.tags),
        attributes=_normalise_attributes(cleaner.attributes),
        protocols=_normalise_protocols(cleaner.protocols),
    )


def admit(
    text,
    tags=ALLOWED_TAGS,
    attributes=ALLOWED_ATTRIBUTES,
    protocols=ALLOWED_PROTOCOLS,
    strip=False,
    strip_comments=True,
    css_sanitizer=None,
    filters=None,
    linker=None,
):
    """First-pass cleaning of inbound material.

    The text is cleaned with the given policy (the same options as
    :class:`~bleach.sanitizer.Cleaner`) and, optionally, run through a
    :class:`~bleach.linkifier.Linker` before the final clean, so that links a
    callback drops or adjusts are governed by the same policy.  The returned
    record captures exactly what this pass was allowed to keep.

    :arg str text: the inbound, untrusted fragment
    :arg cleaner options: the cleaning policy; see
        :class:`bleach.sanitizer.Cleaner`
    :arg Linker linker: optional linker run before the final clean

    :returns: a :class:`ReexportResult` whose status is
        :data:`UNCONFIRMED` on the first pass, since the material has only
        just been admitted
    """
    cleaner = Cleaner(
        tags=tags,
        attributes=attributes,
        protocols=protocols,
        strip=strip,
        strip_comments=strip_comments,
        css_sanitizer=css_sanitizer,
        filters=filters,
    )

    cleaned = cleaner.clean(text)
    if linker is not None:
        cleaned = cleaner.clean(linker.linkify(cleaned))

    record = build_record(cleaned, cleaner)
    return ReexportResult(
        text=cleaned,
        record=record,
        status=UNCONFIRMED,
        confirmed=False,
    )


def _coerce_record(record):
    if isinstance(record, PolicyRecord):
        return record
    return PolicyRecord.from_dict(record)


def reexport(text, record, cleaner, linker=None):
    """Re-exports a previously cleaned fragment through a new policy.

    When ``text`` still matches ``record`` and the record is current, the
    effective policy is the *intersection* of the recorded capabilities and the
    ``cleaner`` policy: a wider export can never bring back something the
    original pass removed.  When the body was edited or the record is stale,
    the material is treated as unconfirmed and simply run through ``cleaner``
    (and, optionally, ``linker``) as fresh inbound material.

    :arg str text: the fragment to export (possibly edited since last clean)
    :arg record: a :class:`PolicyRecord` or its ``to_dict()`` form
    :arg Cleaner cleaner: the new export's cleaning policy
    :arg Linker linker: optional linker applied before the final clean

    :returns: a :class:`ReexportResult`
    """
    try:
        previous = _coerce_record(record)
    except (ValueError, TypeError):
        previous = None

    confirmed = previous is not None and previous.matches(text)

    if confirmed:
        effective_tags = _intersect_tags(previous.tags, cleaner.tags)
        effective_protocols = _intersect_protocols(
            previous.protocols, cleaner.protocols
        )
        effective_attributes = _intersect_attributes(
            previous.attributes, _normalise_attributes(cleaner.attributes)
        )
        effective_cleaner = Cleaner(
            tags=effective_tags,
            attributes=effective_attributes,
            protocols=effective_protocols,
            strip=cleaner.strip,
            strip_comments=cleaner.strip_comments,
            css_sanitizer=cleaner.css_sanitizer,
            filters=cleaner.filters,
        )
        status = CONFIRMED
    else:
        effective_cleaner = cleaner
        status = UNCONFIRMED

    output = text
    if linker is not None:
        output = linker.linkify(output)
    output = effective_cleaner.clean(output)

    new_record = build_record(output, effective_cleaner)
    return ReexportResult(
        text=output,
        record=new_record,
        status=status,
        confirmed=confirmed,
    )
