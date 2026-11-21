import getpass

import keyring


class SupportError(Exception):
    """Sanitized error reported to clients."""


def wrapped_message_kept():
    try:
        token = keyring.get_password("svc", "acct")
        return token
    except Exception as exc:
        raise SupportError("authentication failed") from exc


def wrapped_message_suppressed():
    try:
        token = keyring.get_password("svc", "acct")
        return token
    except Exception:
        raise SupportError("authentication failed") from None


def implicit_context_leak():
    try:
        secret = getpass.getpass()
        return secret
    except Exception:
        raise SupportError("authentication failed")


def preserved_object_leak():
    try:
        secret = getpass.getpass()
        return secret
    except Exception as exc:
        raise exc


def bare_raise_leak():
    try:
        secret = getpass.getpass()
        return secret
    except Exception:
        raise


def unknown_call_not_flagged():
    try:
        value = some_unknown_call()
        return value
    except Exception as exc:
        raise SupportError("authentication failed") from exc
