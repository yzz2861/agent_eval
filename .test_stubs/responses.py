"""Minimal offline stub of the `responses` package, sufficient for the
test-suite's autouse `mocked_requests` fixture (no HTTP calls are made
in the core scan tests)."""


class RequestsMock:
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def add(self, *args, **kwargs):
        raise RuntimeError('responses stub: network mocking is unavailable offline')

    def add_callback(self, *args, **kwargs):
        raise RuntimeError('responses stub: network mocking is unavailable offline')


def activate(func):
    return func
