class CoseException(Exception):
    """Base class for all exceptions raised by pycose."""


class CoseIllegalAlgorithm(CoseException):
    pass


class CoseUnsupportedCurve(CoseException):
    pass


class CoseIllegalKeyOps(CoseException):
    pass


class CoseIllegalKeyType(CoseException):
    pass


class CoseMalformedMessage(CoseException):
    pass


class CoseInvalidKey(CoseException):
    pass
