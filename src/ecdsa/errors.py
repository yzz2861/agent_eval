class MalformedPointError(AssertionError):
    """Raised in case the encoding of private or public key is malformed."""

    pass


class PointEncodingError(MalformedPointError):
    """Raised when the public point encoding itself is malformed."""

    pass


class CurveMismatchError(MalformedPointError):
    """Raised when the public point belongs to a different curve."""

    pass


class PointNotOnCurveError(MalformedPointError):
    """Raised when the public point does not satisfy the curve equation."""

    pass


class SubgroupMismatchError(MalformedPointError):
    """Raised when the public point is not in the expected subgroup."""

    pass


class PointAtInfinityError(MalformedPointError):
    """Raised when a public key encodes the point at infinity."""

    pass
