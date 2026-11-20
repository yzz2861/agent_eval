import socket
import struct
from fractions import Fraction


def pack_ipv4(data):
    return socket.inet_aton(data)


def unpack_ipv4(data):
    return socket.inet_ntoa(data)


def _get_pairs(data):
    """Return data in pairs

    This uses a clever hack, based on the fact that zip will consume
    items from the same iterator, for each reference found in each
    row.

    Example::

        >>> _get_pairs([1, 2, 3, 4])
        [(1, 2), (3, 4)]

    """
    return list(zip(*((iter(data),) * 2)))


def pack_ipv6(data):
    return socket.inet_pton(socket.AF_INET6, data)


def unpack_ipv6(data):
    return socket.inet_ntop(socket.AF_INET6, data)


def pack_macaddr(data):
    a = [int(x, 16) for x in data.split(":")]
    return struct.pack("!6B", *a)


def unpack_macaddr(data):
    return ":".join(format(x, "02x") for x in data)


def pack_euiaddr(data):
    a = [int(x, 16) for x in data.split(":")]
    return struct.pack("!8B", *a)


def unpack_euiaddr(data):
    return unpack_macaddr(data)


def unpack_timestamp_resolution(data):
    """
    Unpack a timestamp resolution.

    Returns a floating point number representing the timestamp
    resolution (multiplier).
    """
    if len(data) != 1:
        raise ValueError("Data must be exactly one byte")
    num = data[0]
    base = 2 if (num >> 7 & 1) else 10
    exponent = num & 0b01111111
    return base ** (-exponent)


def unpack_timestamp_resolution_exact(data):
    """
    Unpack a timestamp resolution without going through ``float``.

    pcap-ng stores a 64 bit timestamp as an integer count of clock ticks.
    The resolution is only a scale factor (10**-n or 2**-n), so it can be
    represented exactly as a :py:class:`fractions.Fraction`.  Keeping it
    exact matters when two adjacent ticks are indistinguishable as IEEE-754
    doubles (which happens beyond 2**53).

    :param data: the one-byte value of an ``if_tsresol`` option.
    :return: a :py:class:`fractions.Fraction` resolution in seconds.
    """
    if isinstance(data, int):
        if not 0 <= data <= 255:
            raise ValueError("Resolution byte must be in range 0..255")
        num = data
    else:
        if len(data) != 1:
            raise ValueError("Data must be exactly one byte")
        num = data[0]

    base = 2 if (num >> 7 & 1) else 10
    exponent = num & 0b01111111
    return Fraction(1, base**exponent)


def pack_timestamp_resolution(base, exponent):
    """
    Pack a timestamp resolution.

    :param base: 2 or 10
    :param exponent: negative power of the base to be encoded
    """
    exponent = abs(exponent)
    if base == 2:
        return struct.pack("B", exponent | 0b10000000)
    if base == 10:
        return struct.pack("B", exponent)
    raise ValueError("Supported bases are: 2, 10")
