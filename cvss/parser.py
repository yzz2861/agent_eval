import re

from .constants3 import METRICS_ABBREVIATIONS as METRICS_3
from .constants4 import METRICS_ABBREVIATIONS as METRICS_4
from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import (
    CVSSMultipleVectorsError,
    CVSSPrefixConfusionError,
    CVSSError,
    CVSSUnknownPrefixError,
    CVSSVersionMismatchError,
)

# Prefixes accepted by the individual CVSS implementations.
_PREFIX_3 = re.compile(r'^CVSS:3\.\d/')
_PREFIX_4 = re.compile(r'^CVSS:4\.0/')
# Any 'CVSS:x.y/' style prefix, used to surface unsupported versions.
_PREFIX_ANY = re.compile(r'^CVSS:(\d+\.\d+)/')

# Candidate substrings: either an explicitly versioned vector ('CVSS:x.y/...')
# or a raw, unprefixed CVSS2-style vector. Minimum length keeps false positives
# low, matching the previous behaviour.
_CANDIDATE_RE = re.compile(r'(?:CVSS:\d+\.\d/)?[A-Za-z:/]{26,}')

# Target versions accepted by the text parsing entry points.
_TARGET_VERSIONS = {
    2: 2,
    3: 3,
    4: 4,
    "2": 2,
    "3": 3,
    "4": 4,
    "3.0": 3,
    "3.1": 3,
}


def _metric_names(candidate):
    """Returns the set of metric abbreviations used in a vector candidate."""
    if _PREFIX_ANY.match(candidate):
        body = candidate.split("/", 1)[1]
    else:
        body = candidate
    names = set()
    for field in body.split("/"):
        if ":" in field:
            names.add(field.split(":", 1)[0])
    return names


def _detect_version(candidate):
    """
    Detects the CVSS version of a single vector candidate.

    A versioned candidate is accepted only when its prefix and its complete
    metric set describe the same CVSS specification.

    Returns:
        int: 2, 3 or 4

    Raises:
        CVSSUnknownPrefixError: prefix names an unsupported CVSS version
        CVSSPrefixConfusionError: prefix and metric set do not match
    """
    prefix_match = _PREFIX_ANY.match(candidate)
    if prefix_match is None:
        # Raw vectors without a prefix are CVSS2 vectors by specification.
        return 2

    version_text = prefix_match.group(1)
    if _PREFIX_4.match(candidate):
        detected = 4
        known_metrics = METRICS_4
    elif _PREFIX_3.match(candidate):
        detected = 3
        known_metrics = METRICS_3
    else:
        raise CVSSUnknownPrefixError(
            'Unknown or unsupported CVSS version prefix "CVSS:{0}/" in vector "{1}"'.format(
                version_text, candidate
            )
        )

    unknown_metrics = _metric_names(candidate) - set(known_metrics)
    if unknown_metrics:
        raise CVSSPrefixConfusionError(
            'CVSS{0} vector "{1}" mixes in metrics from another CVSS version: {2}'.format(
                detected, candidate, ", ".join(sorted(unknown_metrics))
            )
        )
    return detected


def _build_cvss(candidate, version):
    """Instantiates the CVSS object matching the already validated version."""
    if version == 2:
        return CVSS2(candidate)
    if version == 3:
        return CVSS3(candidate)
    return CVSS4(candidate)


def _check_target_version(target_version):
    """Normalizes a caller-supplied target version, rejecting unknown values."""
    if target_version not in _TARGET_VERSIONS:
        raise ValueError(
            "Unsupported target CVSS version \"{0}\", expected one of 2, 3, 4".format(
                target_version
            )
        )
    return _TARGET_VERSIONS[target_version]


def parse_cvss_vector(vector, target_version=None):
    """
    Parses a single CVSS vector string with explicit version detection.

    Unlike parse_cvss_from_text(), the whole input is treated as one vector and
    ambiguous or malformed input is reported with an exception instead of being
    silently ignored.

    Args:
        vector (str): a single CVSS vector, with or without a version prefix
        target_version: if given (2, 3 or 4, or "2", "3", "4", "3.0", "3.1"),
                        the detected vector version must match it; vectors of
                        other versions are never silently downgraded

    Returns:
        CVSS2, CVSS3 or CVSS4 object

    Raises:
        CVSSError: if the vector is malformed or incomplete
        CVSSUnknownPrefixError: unknown or unsupported version prefix
        CVSSPrefixConfusionError: prefix and metric set do not match
        CVSSVersionMismatchError: detected version differs from target_version
        ValueError: target_version is not a supported version
    """
    if target_version is not None:
        target_version = _check_target_version(target_version)

    detected_version = _detect_version(vector)
    if target_version is not None and detected_version != target_version:
        raise CVSSVersionMismatchError(
            "Vector \"{0}\" is CVSS{1} but target version CVSS{2} was requested".format(
                vector, detected_version, target_version
            )
        )
    return _build_cvss(vector, detected_version)


def parse_cvss_from_text(text, target_version=None):
    """
    Parses CVSS2, CVSS3 and CVSS4 vectors from arbitrary text.

    Every candidate is validated against the version named by its prefix: the
    prefix and the complete metric set must describe the same CVSS version.
    Ambiguous candidates are reported with a dedicated exception instead of
    being silently scored (or ignored). Plain malformed text still yields no
    match, preserving the previous best-effort behaviour.

    Args:
        text (str): arbitrary text, may be empty or None
        target_version: if given (2, 3 or 4, or "2", "3", "4", "3.0", "3.1"),
                        only vectors of that version are accepted and a vector
                        of another version raises instead of being downgraded

    Returns:
        A list of distinct CVSS objects in the order in which their vectors
        first appear in the text.

    Raises:
        CVSSUnknownPrefixError: a candidate uses an unknown version prefix
        CVSSPrefixConfusionError: a candidate mixes versions (prefix vs metrics)
        CVSSVersionMismatchError: target_version does not match a candidate
        CVSSMultipleVectorsError: more than one distinct vector is found while
                                  target_version requests a single vector
    """
    if not text:
        return []

    if target_version is not None:
        target_version = _check_target_version(target_version)

    matches = _CANDIDATE_RE.findall(text)

    cvsss = []
    seen = set()
    for match in matches:
        detected_version = _detect_version(match)

        if target_version is not None and detected_version != target_version:
            raise CVSSVersionMismatchError(
                "Vector \"{0}\" is CVSS{1} but target version CVSS{2} was requested".format(
                    match, detected_version, target_version
                )
            )

        try:
            cvss = _build_cvss(match, detected_version)
        except CVSSError:
            # Malformed or incomplete candidates simply do not produce a match.
            continue

        if cvss not in seen:
            seen.add(cvss)
            cvsss.append(cvss)

    if target_version is not None and len(cvsss) > 1:
        raise CVSSMultipleVectorsError(
            "Expected a single CVSS{0} vector but found {1} distinct vectors".format(
                target_version, len(cvsss)
            )
        )

    return cvsss
