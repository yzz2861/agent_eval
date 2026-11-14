# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os

from asn1crypto import core, ocsp, x509, algos

from . import errors
from . import http_policy as _http_policy
from ._types import str_cls, type_name
from .errors import OCSPFetchError, FetchPolicyError
from .version import __version__
from ._urllib import Request, urlopen, URLError


def fetch(cert, issuer, hash_algo='sha1', nonce=True, user_agent=None, timeout=10, http_policy=None, fetcher=None):
    """
    Fetches an OCSP response for a certificate

    :param cert:
        An asn1cyrpto.x509.Certificate object to get an OCSP reponse for

    :param issuer:
        An asn1crypto.x509.Certificate object that is the issuer of cert

    :param hash_algo:
        A unicode string of "sha1" or "sha256"

    :param nonce:
        A boolean - if the nonce extension should be used to prevent replay
        attacks

    :param user_agent:
        The HTTP user agent to use when requesting the OCSP response. If None,
        a default is used in the format "certvalidation 1.0.0".

    :param timeout:
        The number of seconds after which an HTTP request should timeout

    :param http_policy:
        None or a certvalidator.http_policy.FetchPolicy object constraining
        how the OCSP response may be fetched (allowed schemes/hosts/ports,
        blocked IP ranges, redirect, size and timeout limits). If None, the
        historical behavior of opening the URL directly is used.

    :param fetcher:
        None or a callable with the signature of urllib.request.urlopen(),
        accepting (request, data, timeout) and returning a response object.
        Allows callers to customize how HTTP requests are performed. When
        combined with http_policy, the fetcher must surface redirects as
        urllib.error.HTTPError instead of following them.

    :raises:
        urllib.error.URLError/urllib2.URLError - when a URL/HTTP error occurs
        socket.error - when a socket error occurs
        certvalidator.errors.OCSPFetchError - when the HTTP fetch policy
        rejects the request or response

    :return:
        An asn1crypto.ocsp.OCSPResponse object
    """

    if not isinstance(cert, x509.Certificate):
        raise TypeError('cert must be an instance of asn1crypto.x509.Certificate, not %s' % type_name(cert))

    if not isinstance(issuer, x509.Certificate):
        raise TypeError('issuer must be an instance of asn1crypto.x509.Certificate, not %s' % type_name(issuer))

    if hash_algo not in set(['sha1', 'sha256']):
        raise ValueError('hash_algo must be one of "sha1", "sha256", not %s' % repr(hash_algo))

    if not isinstance(nonce, bool):
        raise TypeError('nonce must be a bool, not %s' % type_name(nonce))

    if user_agent is None:
        user_agent = 'certvalidator %s' % __version__
    elif not isinstance(user_agent, str_cls):
        raise TypeError('user_agent must be a unicode string, not %s' % type_name(user_agent))

    if http_policy is not None and not isinstance(http_policy, _http_policy.FetchPolicy):
        raise TypeError(
            'http_policy must be a certvalidator.http_policy.FetchPolicy object, not %s' % type_name(http_policy)
        )

    if fetcher is not None and not callable(fetcher):
        raise TypeError('fetcher must be None or a callable, not %s' % type_name(fetcher))

    cert_id = ocsp.CertId({
        'hash_algorithm': algos.DigestAlgorithm({'algorithm': hash_algo}),
        'issuer_name_hash': getattr(cert.issuer, hash_algo),
        'issuer_key_hash': getattr(issuer.public_key, hash_algo),
        'serial_number': cert.serial_number,
    })

    request = ocsp.Request({
        'req_cert': cert_id,
    })
    tbs_request = ocsp.TBSRequest({
        'request_list': ocsp.Requests([request]),
    })

    if nonce:
        nonce_extension = ocsp.TBSRequestExtension({
            'extn_id': 'nonce',
            'critical': False,
            'extn_value': core.OctetString(core.OctetString(os.urandom(16)).dump())
        })
        tbs_request['request_extensions'] = ocsp.TBSRequestExtensions([nonce_extension])

    ocsp_request = ocsp.OCSPRequest({
        'tbs_request': tbs_request,
    })

    last_e = None
    for ocsp_url in cert.ocsp_urls:
        try:
            headers = {
                'Accept': 'application/ocsp-response',
                'Content-Type': 'application/ocsp-request',
                'User-Agent': user_agent,
            }
            if http_policy is not None:
                try:
                    result = _http_policy.fetch_url(
                        ocsp_url,
                        headers=headers,
                        data=ocsp_request.dump(),
                        timeout=timeout,
                        policy=http_policy,
                        opener=fetcher
                    )
                except FetchPolicyError as e:
                    raise OCSPFetchError(str_cls(e), reason=e.reason)
                response_data = result.body
            else:
                request = Request(ocsp_url)
                for name, value in headers.items():
                    request.add_header(name, value)
                opener = fetcher or urlopen
                response = opener(request, ocsp_request.dump(), timeout)
                response_data = response.read()
            ocsp_response = ocsp.OCSPResponse.load(response_data)
            request_nonce = ocsp_request.nonce_value
            response_nonce = ocsp_response.nonce_value
            if request_nonce and response_nonce and request_nonce.native != response_nonce.native:
                raise errors.OCSPValidationError(
                    'Unable to verify OCSP response since the request and response nonces do not match'
                )
            return ocsp_response

        except (URLError, OCSPFetchError) as e:
            last_e = e

    raise last_e
