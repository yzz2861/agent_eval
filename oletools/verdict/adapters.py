"""Adapters between concrete oletools detectors and the verdict model.

Importing this module never imports the heavy detectors at module load time;
oleid/olevba are imported lazily inside functions so the verdict engine can
be embedded in a gateway even where a detector is unavailable.
"""

from .model import (
    Capability,
    ContainerNode,
    DetectorResult,
    NodeKind,
    Outcome,
    Severity,
)

# oleid indicator id -> (capability, severity when the indicator flags risk)
_OLEID_INDICATOR_MAP = {
    'macros': (Capability.MACRO, Severity.HIGH),
    'vba_macros': (Capability.MACRO, Severity.HIGH),
    'xlm_macros': (Capability.MACRO, Severity.HIGH),
    'flash': (Capability.FLASH, Severity.HIGH),
    'encrypted': (Capability.ENCRYPTION, Severity.MEDIUM),
    'external_relationships': (Capability.EXTERNAL_RELATIONSHIP, Severity.HIGH),
    'object_pool': (Capability.EMBEDDED_OBJECT, Severity.LOW),
    'ole_format': (Capability.OLE_STRUCTURE, Severity.MEDIUM),
    'ftype': (Capability.OLE_STRUCTURE, Severity.INFO),
}

# oleid RISK strings that mean a confirmed finding.
_RISK_LEVELS = frozenset(("HIGH", "Medium", "low"))
_CLEAN_LEVELS = frozenset(("none", "info"))
_ERROR_LEVELS = frozenset(("Error", "Unknown"))


def _risk_to_outcome(risk):
    if risk in _RISK_LEVELS:
        return Outcome.RISK
    if risk in _ERROR_LEVELS:
        return Outcome.ERROR
    return Outcome.CLEAN


def _risk_to_severity(risk, default):
    return {
        'HIGH': Severity.HIGH,
        'Medium': Severity.MEDIUM,
        'low': Severity.LOW,
        'Error': Severity.MEDIUM,
        'Unknown': Severity.MEDIUM,
        'none': Severity.INFO,
        'info': Severity.INFO,
    }.get(risk, default)


def indicator_to_result(node_id, indicator, detector="oleid"):
    """Convert one oleid Indicator into a DetectorResult (or None).

    Indicators that have no verdict-model capability mapping (purely
    informational metadata such as author names) are ignored by returning
    None, so callers can map an entire indicator list without special cases.
    """
    mapping = _OLEID_INDICATOR_MAP.get(indicator.id)
    if mapping is None:
        return None
    capability, default_severity = mapping
    outcome = _risk_to_outcome(indicator.risk)
    severity = _risk_to_severity(indicator.risk, default_severity)
    return DetectorResult(
        node_id=node_id,
        capability=capability,
        outcome=outcome,
        detector=detector,
        severity=severity,
        detail="{0}: {1!r}".format(indicator.id, indicator.value),
        signature=indicator.id,
    )


def results_from_oleid(node_id, oleid_instance, detector="oleid"):
    """Map every indicator of an OleID instance to DetectorResult objects."""
    out = []
    for indicator in oleid_instance.indicators:
        result = indicator_to_result(node_id, indicator, detector)
        if result is not None:
            out.append(result)
    return out


def run_oleid(node_id, data=None, filename=None, detector="oleid"):
    """Run oleid in-memory and return DetectorResult objects.

    Exactly one of ``data`` (bytes) or ``filename`` must be provided. The
    import is lazy, so the rest of the package works without oleid.
    """
    from oletools import oleid as _oleid

    if data is None and filename is None:
        raise ValueError('provide either data or filename')
    oleid_instance = _oleid.OleID(filename=filename, data=data)
    oleid_instance.check()
    return results_from_oleid(node_id, oleid_instance, detector)

_KIND_BY_HINT = {
    'ole': NodeKind.OLE,
    'ooxml': NodeKind.OOXML,
    'rtf': NodeKind.RTF,
    'ole_stream': NodeKind.OLE_STREAM,
    'ooxml_part': NodeKind.OOXML_PART,
    'embedded': NodeKind.EMBEDDED,
}


def node_from_bytes(node_id, data, name="", kind=None, encrypted=False):
    """Build a ContainerNode from raw bytes with a content_key hash."""
    if kind is None:
        kind = NodeKind.UNKNOWN
    elif isinstance(kind, str) and not isinstance(kind, NodeKind):
        kind = _KIND_BY_HINT.get(kind, NodeKind(kind))
    return ContainerNode(node_id=node_id, kind=kind, name=name,
                         encrypted=encrypted, payload=bytes(data))


def node_from_oleid(node_id, oleid_instance, name=""):
    """Build a ContainerNode reflecting encryption/format from oleid."""
    encrypted = False
    kind = NodeKind.OLE
    for indicator in oleid_instance.indicators:
        if indicator.id == 'encrypted' and indicator.risk in ('HIGH',):
            encrypted = True
        if indicator.id == 'container' and indicator.value:
            text = str(indicator.value).lower()
            if 'ooxml' in text or 'zip' in text:
                kind = NodeKind.OOXML
            elif 'rtf' in text:
                kind = NodeKind.RTF
    return ContainerNode(node_id=node_id, kind=kind, name=name,
                         encrypted=encrypted)
