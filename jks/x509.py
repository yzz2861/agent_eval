from datetime import datetime

from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459
from pyasn1.type.useful import UTCTime, GeneralizedTime

from .util import BadKeystoreFormatException


class X509Certificate(object):
    """A small X.509 public certificate view built from DER-encoded data."""

    def __init__(self, der_bytes):
        try:
            certificate, _ = decoder.decode(der_bytes, asn1Spec=rfc2459.Certificate())
            validity = certificate['tbsCertificate']['validity']
            self.not_before = _parse_time(validity['notBefore'].getComponent())
            self.not_after = _parse_time(validity['notAfter'].getComponent())
        except Exception as e:
            raise BadKeystoreFormatException("Failed to parse X.509 certificate: %s" % e)


def _parse_time(value):
    text = str(value)
    if isinstance(value, UTCTime):
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        return datetime(year, int(text[2:4]), int(text[4:6]),
                        int(text[6:8]), int(text[8:10]),
                        int(text[10:12]) if len(text) >= 13 else 0)
    if isinstance(value, GeneralizedTime):
        return datetime(int(text[0:4]), int(text[4:6]), int(text[6:8]),
                        int(text[8:10]), int(text[10:12]),
                        int(text[12:14]) if len(text) >= 15 else 0)
    raise BadKeystoreFormatException("Unsupported X.509 time type: %s" % type(value).__name__)
