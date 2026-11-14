import re

from .constants3 import METRICS_ABBREVIATIONS, METRICS_MANDATORY, METRICS_VALUES
from .exceptions import CVSS3MalformedError, CVSS3MandatoryError, CVSSError


def _cvss3_error(exception_class, message, metric=None, position=None, value=None):
    error = exception_class(message)
    if metric is not None:
        error.metric = metric
    if position is not None:
        error.position = position
        error.field_position = position
    if value is not None:
        error.value = value
    return error


def parse_cvss3_vector(vector):
    """
    Validates and parses a CVSS3.0 or CVSS3.1 vector without mutating a CVSS3 object.

    Returns:
        (tuple): dictionary with parsed metrics and minor version as an integer

    Raises:
        CVSS3MalformedError: if vector is not in expected format
        CVSS3MandatoryError: if a mandatory metric is missing
    """
    if vector == "":
        raise CVSS3MalformedError("Malformed CVSS3 vector, vector is empty")

    if vector.endswith("/"):
        raise CVSS3MalformedError('Malformed CVSS3 vector, trailing "/"')

    if vector.startswith("CVSS:3.0/"):
        minor_version = 0
    elif vector.startswith("CVSS:3.1/"):
        minor_version = 1
    else:
        raise CVSS3MalformedError(
            "Malformed CVSS3 vector, missing mandatory prefix or unsupported CVSS version"
        )

    fields = vector.split("/")[1:]
    metrics = {}

    for position, field in enumerate(fields, start=1):
        if field == "":
            raise _cvss3_error(
                CVSS3MalformedError,
                "Empty CVSS3 field at position {0}".format(position),
                position=position,
            )

        try:
            metric, value = field.split(":")
        except ValueError:
            raise _cvss3_error(
                CVSS3MalformedError,
                "Malformed CVSS3 field at position {0}".format(position),
                position=position,
            )

        if metric == "":
            raise _cvss3_error(
                CVSS3MalformedError,
                "Empty CVSS3 metric name at position {0}".format(position),
                metric="",
                position=position,
            )

        if metric not in METRICS_ABBREVIATIONS:
            raise _cvss3_error(
                CVSS3MalformedError,
                'Unknown CVSS3 metric "{0}" at position {1}'.format(metric, position),
                metric=metric,
                position=position,
            )

        if value == "":
            raise _cvss3_error(
                CVSS3MalformedError,
                'Empty CVSS3 value for metric "{0}" at position {1}'.format(metric, position),
                metric=metric,
                position=position,
                value="",
            )

        if value not in METRICS_VALUES[metric]:
            raise _cvss3_error(
                CVSS3MalformedError,
                'Unknown CVSS3 value "{0}" for metric "{1}" at position {2}'.format(
                    value, metric, position
                ),
                metric=metric,
                position=position,
                value=value,
            )

        if metric in metrics:
            raise _cvss3_error(
                CVSS3MalformedError,
                'Duplicate CVSS3 metric "{0}" at position {1}'.format(metric, position),
                metric=metric,
                position=position,
                value=value,
            )

        metrics[metric] = value

    missing = [metric for metric in METRICS_MANDATORY if metric not in metrics]
    if missing:
        metric_positions = {
            metric: list(METRICS_ABBREVIATIONS).index(metric) + 1 for metric in missing
        }
        descriptions = [
            '"{0}" at position {1}'.format(metric, metric_positions[metric]) for metric in missing
        ]
        error = CVSS3MandatoryError(
            "Missing mandatory CVSS3 metrics {0}".format(", ".join(descriptions))
        )
        error.metrics = missing
        error.positions = metric_positions
        error.metric = missing[0]
        error.position = metric_positions[missing[0]]
        error.field_position = error.position
        raise error

    return metrics, minor_version


def parse_cvss_from_text(text):
    """
    Parses CVSS2, CVSS3, and CVSS4 vectors from arbitrary text and returns a list of CVSS objects.

    Parses text for substrings that look similar to CVSS vector
    and feeds these matches to CVSS constructor.

    Args:
        text (str): arbitrary text
    Returns:
        A list of CVSS objects.
    """
    from .cvss2 import CVSS2
    from .cvss3 import CVSS3
    from .cvss4 import CVSS4

    # Looks for substrings that resemble CVSS2, CVSS3, or CVSS4 vectors.
    # CVSS3 and CVSS4 vectors start with a 'CVSS:x.x/' prefix and are matched by the optional
    # non-capturing group.
    # CVSS2 vectors do not include a prefix and are matched by raw vector pattern only.
    # Minimum total match length is 26 characters to reduce false positives.
    matches = re.compile(r"(?:CVSS:[3-4]\.\d/)?[A-Za-z:/]{26,}").findall(text)

    cvsss = set()
    for match in matches:
        try:
            if match.startswith("CVSS:4."):
                cvss = CVSS4(match)
            elif match.startswith("CVSS:3."):
                cvss = CVSS3(match)
            else:
                cvss = CVSS2(match)

            cvsss.add(cvss)
        except (CVSSError, KeyError):
            pass

    return list(cvsss)
