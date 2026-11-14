import ipaddress
import functools
import hashlib
import re
import socket
import time
import zlib

from django.conf import settings
from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from django_ratelimit import ALL, UNSAFE


__all__ = ['is_ratelimited', 'get_usage', 'UnavailableClientIP']

_PERIODS = {
    's': 1,
    'm': 60,
    'h': 60 * 60,
    'd': 24 * 60 * 60,
}

# Extend the expiration time by a few seconds to avoid misses.
EXPIRATION_FUDGE = 5

# Maximum number of comma-separated hops accepted from a forwarding header.
MAX_CLIENT_IP_CHAIN = 64


class UnavailableClientIP(Exception):
    """The client IP cannot be derived from a trusted proxy chain.

    Raised when the explicit client IP resolution settings are enabled and a
    request carries a missing, ambiguous or malformed proxy header. The rate
    limiter converts this into a fail-closed decision instead of selecting an
    attacker-controlled bucket.
    """


def _explicit_client_ip_enabled():
    return bool(
        getattr(settings, 'RATELIMIT_TRUSTED_PROXIES', None)
        and getattr(settings, 'RATELIMIT_CLIENT_IP_HEADER', None)
    )


def _normalize_address(address):
    # Unwrap IPv4-mapped IPv6 addresses so both forms of the same client
    # produce the same rate limit key.
    if address.version == 6:
        mapped = address.ipv4_mapped
        if mapped is not None:
            return mapped
    return address


def _trusted_proxy_networks():
    configured = getattr(settings, 'RATELIMIT_TRUSTED_PROXIES', None)
    if isinstance(configured, str):
        configured = [configured]
    try:
        return [
            ipaddress.ip_network(str(entry).strip(), strict=False)
            for entry in configured
        ]
    except (TypeError, ValueError) as error:
        raise ImproperlyConfigured(
            'RATELIMIT_TRUSTED_PROXIES must contain only IP addresses or '
            'CIDR networks: %s' % error)


def _address_in_networks(address, networks):
    for network in networks:
        if network.version == address.version and address in network:
            return True
    return False


def _masked_address_key(address):
    if address.version == 6:
        mask = getattr(settings, 'RATELIMIT_IPV6_MASK', 64)
    else:
        mask = getattr(settings, 'RATELIMIT_IPV4_MASK', 32)
    network = ipaddress.ip_network(f'{address}/{mask}', strict=False)
    return str(network.network_address)


def _has_control_character(value):
    return any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)


def _parse_ip_hop(value):
    """Strictly parse one address from a proxy header."""
    if not isinstance(value, str):
        raise UnavailableClientIP('Proxy header value is not a string.')
    if _has_control_character(value):
        raise UnavailableClientIP(
            'Proxy header contains control characters.')
    token = value.strip()
    if not token:
        raise UnavailableClientIP(
            'Proxy header contains an empty address segment.')
    if '[' in token or ']' in token:
        raise UnavailableClientIP(
            'Bracketed addresses or embedded ports are not accepted in '
            'proxy headers.')
    if '%' in token:
        raise UnavailableClientIP(
            'Scoped (zone) IPv6 addresses are not accepted as client IPs.')
    if token.count(':') == 1 and '.' in token:
        raise UnavailableClientIP(
            'Ports are not allowed on proxy header addresses.')
    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        raise UnavailableClientIP(
            'Proxy header contains an unparseable address: %r' % token)
    return _normalize_address(address)


def _resolve_single_value_header(request, raw):
    if ',' in raw:
        raise UnavailableClientIP(
            'The configured client IP header must hold a single value but '
            'contains a comma.')
    if 'HTTP_X_FORWARDED_FOR' in request.META:
        raise UnavailableClientIP(
            'Both a single-value client IP header and X-Forwarded-For are '
            'present, so the client IP is ambiguous.')
    return _parse_ip_hop(raw)


def _resolve_forwarded_for(raw, trusted_networks):
    hops = raw.split(',')
    if len(hops) > MAX_CLIENT_IP_CHAIN:
        raise UnavailableClientIP(
            'X-Forwarded-For chain exceeds %d hops.'
            % MAX_CLIENT_IP_CHAIN)
    # Walk right-to-left: every hop the immediate trusted proxy adds is
    # trusted until the first address outside the trusted proxy set.
    for hop in reversed(hops):
        address = _parse_ip_hop(hop)
        if not _address_in_networks(address, trusted_networks):
            return address
    raise UnavailableClientIP(
        'Every X-Forwarded-For address belongs to a trusted proxy, so no '
        'client address is available.')


def _resolve_client_ip(request):
    trusted_networks = _trusted_proxy_networks()
    try:
        peer = _normalize_address(
            ipaddress.ip_address(request.META['REMOTE_ADDR']))
    except (KeyError, TypeError, ValueError):
        raise UnavailableClientIP(
            'REMOTE_ADDR does not contain a valid IP address.')

    # A direct (or untrusted) connection cannot influence its own client IP
    # through a forged proxy header.
    if not _address_in_networks(peer, trusted_networks):
        return _masked_address_key(peer)

    header = getattr(settings, 'RATELIMIT_CLIENT_IP_HEADER')
    raw = request.META.get(header)
    if raw is None:
        return _masked_address_key(peer)
    if not isinstance(raw, str) or _has_control_character(raw):
        raise UnavailableClientIP('Client IP header is malformed.')

    if header == 'HTTP_X_FORWARDED_FOR':
        client = _resolve_forwarded_for(raw, trusted_networks)
    else:
        client = _resolve_single_value_header(request, raw)
    return _masked_address_key(client)


def _get_ip(request):
    if _explicit_client_ip_enabled():
        return _resolve_client_ip(request)

    ip_meta = getattr(settings, 'RATELIMIT_IP_META_KEY', None)
    if not ip_meta:
        ip = request.META['REMOTE_ADDR']
        if not ip:
            raise ImproperlyConfigured(
                'IP address in REMOTE_ADDR is empty. This can happen when '
                'using a reverse proxy and connecting to the app server with '
                'Unix sockets. See the documentation for '
                'RATELIMIT_IP_META_KEY: https://bit.ly/3iIpy2x')
    elif callable(ip_meta):
        ip = ip_meta(request)
    elif isinstance(ip_meta, str) and '.' in ip_meta:
        ip_meta_fn = import_string(ip_meta)
        ip = ip_meta_fn(request)
    elif ip_meta in request.META:
        ip = request.META[ip_meta]
    else:
        raise ImproperlyConfigured(
            'Could not get IP address from "%s"' % ip_meta)

    if ':' in ip:
        # IPv6
        mask = getattr(settings, 'RATELIMIT_IPV6_MASK', 64)
    else:
        # IPv4
        mask = getattr(settings, 'RATELIMIT_IPV4_MASK', 32)

    network = ipaddress.ip_network(f'{ip}/{mask}', strict=False)

    return str(network.network_address)


def user_or_ip(request):
    if request.user.is_authenticated:
        return str(request.user.pk)
    return _get_ip(request)


_SIMPLE_KEYS = {
    'ip': lambda r: _get_ip(r),
    'user': lambda r: str(r.user.pk),
    'user_or_ip': user_or_ip,
}


def get_header(request, header):
    key = 'HTTP_' + header.replace('-', '_').upper()
    return request.META.get(key, '')


_ACCESSOR_KEYS = {
    'get': lambda r, k: r.GET.get(k, ''),
    'post': lambda r, k: r.POST.get(k, ''),
    'header': get_header,
}


def _method_match(request, method=ALL):
    if method == ALL:
        return True
    if not isinstance(method, (list, tuple)):
        method = [method]
    return request.method in [m.upper() for m in method]


rate_re = re.compile(r'([\d]+)/([\d]*)([smhd])?')


def _split_rate(rate):
    if isinstance(rate, tuple):
        return rate
    count, multi, period = rate_re.match(rate).groups()
    count = int(count)
    if not period:
        period = 's'
    seconds = _PERIODS[period.lower()]
    if multi:
        seconds = seconds * int(multi)
    return count, seconds


def _get_window(value, period):
    """
    Given a value, and time period return when the end of the current time
    period for rate evaluation is.
    """
    ts = int(time.time())
    if period == 1:
        return ts
    if not isinstance(value, bytes):
        value = value.encode('utf-8')
    # This logic determines either the last or current end of a time period.
    # Subtracting (ts % period) gives us the a consistent edge from the epoch.
    # We use (zlib.crc32(value) % period) to add a consistent jitter so that
    # all time periods don't end at the same time.
    w = ts - (ts % period) + (zlib.crc32(value) % period)
    if w < ts:
        return w + period
    return w


def _make_cache_key(group, window, rate, value, methods):
    count, period = _split_rate(rate)
    safe_rate = '%d/%ds' % (count, period)
    parts = [group, safe_rate, value, str(window)]
    if methods is not None:
        if methods == ALL:
            methods = ''
        elif isinstance(methods, (list, tuple)):
            methods = ''.join(sorted([m.upper() for m in methods]))
        parts.append(methods)
    prefix = getattr(settings, 'RATELIMIT_CACHE_PREFIX', 'rl:')
    attr = getattr(settings, 'RATELIMIT_HASH_ALGORITHM', hashlib.sha256)
    algo_cls = (import_string(f'{attr}')
                if isinstance(attr, str)
                else attr
                )
    return prefix + algo_cls(''.join(parts).encode('utf-8')).hexdigest()


def is_ratelimited(request, group=None, fn=None, key=None, rate=None,
                   method=ALL, increment=False):
    usage = get_usage(request, group, fn, key, rate, method, increment)
    if usage is None:
        return False

    return usage['should_limit']


def get_usage(request, group=None, fn=None, key=None, rate=None, method=ALL,
              increment=False):
    if group is None and fn is None:
        raise ImproperlyConfigured('get_usage must be called with either '
                                   '`group` or `fn` arguments')

    if not getattr(settings, 'RATELIMIT_ENABLE', True):
        return None

    if not _method_match(request, method):
        return None

    if group is None:
        parts = []

        if isinstance(fn, functools.partial):
            fn = fn.func

        # Django <2.1 doesn't use a partial. This is ugly and inelegant, but
        # throwing __qualname__ into the list below helps.
        if fn.__name__ == 'bound_func':
            fn = fn.__closure__[0].cell_contents

        if hasattr(fn, '__module__'):
            parts.append(fn.__module__)

        if hasattr(fn, '__self__'):
            parts.append(fn.__self__.__class__.__name__)

        parts.append(fn.__qualname__)
        group = '.'.join(parts)

    if callable(rate):
        rate = rate(group, request)
    elif isinstance(rate, str) and '.' in rate:
        ratefn = import_string(rate)
        rate = ratefn(group, request)

    if rate is None:
        return None
    limit, period = _split_rate(rate)
    if period <= 0:
        raise ImproperlyConfigured('Ratelimit period must be greater than 0')

    if not key:
        raise ImproperlyConfigured('Ratelimit key must be specified')
    # A malformed or untrusted proxy chain must never select an
    # attacker-controlled bucket: fail closed before touching the cache, so
    # RATELIMIT_FAIL_OPEN cannot allow the request either.
    try:
        if callable(key):
            value = key(group, request)
        elif key in _SIMPLE_KEYS:
            value = _SIMPLE_KEYS[key](request)
        elif ':' in key:
            accessor, k = key.split(':', 1)
            if accessor not in _ACCESSOR_KEYS:
                raise ImproperlyConfigured(
                    'Unknown ratelimit key: %s' % key)
            value = _ACCESSOR_KEYS[accessor](request, k)
        elif '.' in key:
            keyfn = import_string(key)
            value = keyfn(group, request)
        else:
            raise ImproperlyConfigured(
                'Could not understand ratelimit key: %s' % key)
    except UnavailableClientIP:
        return {
            'count': 0,
            'limit': 0,
            'should_limit': True,
            'time_left': -1,
        }

    window = _get_window(value, period)
    initial_value = 1 if increment else 0

    cache_name = getattr(settings, 'RATELIMIT_USE_CACHE', 'default')
    cache = caches[cache_name]
    cache_key = _make_cache_key(group, window, rate, value, method)

    count = None
    try:
        added = cache.add(cache_key, initial_value, period + EXPIRATION_FUDGE)
    except socket.gaierror:  # for redis
        added = False
    if added:
        count = initial_value
    else:
        if increment:
            try:
                # python3-memcached will throw a ValueError if the server is
                # unavailable or (somehow) the key doesn't exist. redis, on the
                # other hand, simply returns None.
                count = cache.incr(cache_key)
            except ValueError:
                pass
        else:
            count = cache.get(cache_key, initial_value)

    # Getting or setting the count from the cache failed
    if count is None or count is False:
        if getattr(settings, 'RATELIMIT_FAIL_OPEN', False):
            return None
        return {
            'count': 0,
            'limit': 0,
            'should_limit': True,
            'time_left': -1,
        }

    time_left = window - int(time.time())
    return {
        'count': count,
        'limit': limit,
        'should_limit': count > limit,
        'time_left': time_left,
    }


is_ratelimited.ALL = ALL
is_ratelimited.UNSAFE = UNSAFE
get_usage.ALL = ALL
get_usage.UNSAFE = UNSAFE
