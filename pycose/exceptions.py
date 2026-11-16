class CoseException(Exception):
    pass


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
