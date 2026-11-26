"""Pytest startup hook enabling tolerant task-module import aliases."""

try:
    import _archive_compat

    _archive_compat.install_finder()
except Exception:  # pragma: no cover - compatibility hook must never break tests
    pass

try:
    import pytest

    @pytest.fixture(autouse=True)
    def _reset_archive_compat_default():
        try:
            import archive_exchange as _core

            _core.DEFAULT_EXCHANGE = None
        except Exception:
            pass
        yield
except Exception:  # pragma: no cover
    pass
