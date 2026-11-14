# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto import crl, x509, cms, pem

from . import http_policy as _http_policy
from ._types import str_cls, type_name
from .errors import CRLFetchError, FetchPolicyError
from .version import __version__
from ._urllib import Request, urlopen


def fetch(cert, use_deltas=True, user_agent=None, timeout=10, http_policy=None, fetcher=None):
    """
    Fetches the CRLs for a certificate

    :param cert:
        An asn1cyrpto.x509.Certificate object to get the CRL for

    :param use_deltas:
        A boolean indicating if delta CRLs should be fetched

    :param user_agent:
        The HTTP user agent to use when requesting the CRL. If None,
        a default is used in the format "certvalidation 1.0.0".

    :param timeout:
        The number of seconds after which an HTTP request should timeout

    :param http_policy:
        None or a certvalidator.http_policy.FetchPolicy object constraining
        how the CRL may be fetched (allowed schemes/hosts/ports, blocked IP
        ranges, redirect, size and timeout limits). If None, the historical
        behavior of opening the URL directly is used.

    :param fetcher:
        None or a callable with the signature of urllib.request.urlopen(),
        accepting (request, data, timeout) and returning a response object.
        Allows callers to customize how HTTP requests are performed. When
        combined with http_policy, the fetcher must surface redirects as
        urllib.error.HTTPError instead of following them.

    :raises:
        urllib.error.URLError/urllib2.URLError - when a URL/HTTP error occurs
        socket.error - when a socket error occurs
        certvalidator.errors.CRLFetchError - when the HTTP fetch policy
        rejects the request or response

    :return:
        A list asn1crypto.crl.CertificateList objects
    """

    if not isinstance(cert, x509.Certificate):
        raise TypeError('cert must be an instance of asn1crypto.x509.Certificate, not %s' % type_name(cert))

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

    output = []

    sources = cert.crl_distribution_points
    if use_deltas:
        sources.extend(cert.delta_crl_distribution_points)

    for distribution_point in sources:
        url = distribution_point.url
        output.append(_grab_crl(user_agent, url, timeout, http_policy=http_policy, fetcher=fetcher))

    return output


def _grab_crl(user_agent, url, timeout, http_policy=None, fetcher=None):
    """
    Fetches a CRL and parses it

    :param user_agent:
        A unicode string of the user agent to use when fetching the URL

    :param url:
        A unicode string of the URL to fetch the CRL from

    :param timeout:
        The number of seconds after which an HTTP request should timeout

    :param http_policy:
        None or a certvalidator.http_policy.FetchPolicy object

    :param fetcher:
        None or a callable with the signature of urllib.request.urlopen()

    :return:
        An asn1crypto.crl.CertificateList object
    """

    headers = {
        'Accept': 'application/pkix-crl',
        'User-Agent': user_agent,
    }

    if http_policy is not None:
        try:
            result = _http_policy.fetch_url(
                url,
                headers=headers,
                timeout=timeout,
                policy=http_policy,
                opener=fetcher
            )
        except FetchPolicyError as e:
            raise CRLFetchError(str_cls(e), reason=e.reason)
        data = result.body
    else:
        request = Request(url)
        for name, value in headers.items():
            request.add_header(name, value)
        opener = fetcher or urlopen
        response = opener(request, None, timeout)
        data = response.read()

    if pem.detect(data):
        _, _, data = pem.unarmor(data)
    return crl.CertificateList.load(data)


def fetch_certs(certificate_list, user_agent=None, timeout=10, http_policy=None, fetcher=None):
    """
    Fetches certificates from the authority information access extension of
    an asn1crypto.crl.CertificateList object and places them into the
    cert registry.

    :param certificate_list:
        An asn1crypto.crl.CertificateList object

    :param user_agent:
        The HTTP user agent to use when requesting the CRL. If None,
        a default is used in the format "certvalidation 1.0.0".

    :param timeout:
        The number of seconds after which an HTTP request should timeout

    :param http_policy:
        None or a certvalidator.http_policy.FetchPolicy object constraining
        how the certificates may be fetched

    :param fetcher:
        None or a callable with the signature of urllib.request.urlopen(),
        accepting (request, data, timeout) and returning a response object

    :raises:
        urllib.error.URLError/urllib2.URLError - when a URL/HTTP error occurs
        socket.error - when a socket error occurs
        certvalidator.errors.CRLFetchError - when the HTTP fetch policy
        rejects the request or response

    :return:
        A list of any asn1crypto.x509.Certificate objects that were fetched
    """

    output = []

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

    for url in certificate_list.issuer_cert_urls:
        headers = {
            'Accept': 'application/pkix-cert,application/pkcs7-mime',
            'User-Agent': user_agent,
        }

        if http_policy is not None:
            try:
                result = _http_policy.fetch_url(
                    url,
                    headers=headers,
                    timeout=timeout,
                    policy=http_policy,
                    opener=fetcher
                )
            except FetchPolicyError as e:
                raise CRLFetchError(str_cls(e), reason=e.reason)
            response_data = result.body
            content_type = ''
            if result.headers is not None:
                content_type = (result.headers.get('Content-Type') or '').strip()
            if not content_type:
                # Custom openers may not expose headers - fall back to
                # detecting the payload structure
                try:
                    x509.Certificate.load(response_data)
                    content_type = 'application/pkix-cert'
                except (ValueError):
                    content_type = 'application/pkcs7-mime'
        else:
            request = Request(url)
            for name, value in headers.items():
                request.add_header(name, value)
            opener = fetcher or urlopen
            response = opener(request, None, timeout)

            content_type = response.headers['Content-Type'].strip()
            response_data = response.read()

        if content_type == 'application/pkix-cert':
            output.append(x509.Certificate.load(response_data))

        elif content_type == 'application/pkcs7-mime':
            signed_data = cms.SignedData.load(response_data)
            if isinstance(signed_data['certificates'], cms.CertificateSet):
                for cert_choice in signed_data['certificates']:
                    if cert_choice.name == 'certificate':
                        output.append(cert_choice.chosen)
        else:
            raise ValueError('Unknown content type of %s when fetching issuer certificate for CRL' % repr(content_type))

    return output
