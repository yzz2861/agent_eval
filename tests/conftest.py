import hashlib

import pytest


def _md4_supported():
    try:
        hashlib.new('md4', b'')
    except ValueError:
        return False
    return True


MD4_SUPPORTED = _md4_supported()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    # MD4 underpins both NTOWFv1 and NTOWFv2, so most end-to-end message
    # tests require it. Skip those tests cleanly on builds (e.g. modern
    # OpenSSL 3 without the legacy provider) where the algorithm is absent
    # instead of letting them error out.
    outcome = yield
    if MD4_SUPPORTED:
        return

    exc = outcome.excinfo
    if exc is None:
        return
    error = exc[1]
    if isinstance(error, ValueError) and 'md4' in str(error).lower():
        outcome.force_result(pytest.skip("MD4 is unavailable in this "
                                         "OpenSSL build"))
