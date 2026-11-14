# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)


class NoAuthContextError(Exception):
    pass


class MalformedMessageError(ValueError):
    """Raised when an NTLM message cannot be parsed safely.

    The message only contains structural information (message type, field
    name, offsets and lengths). Payload data such as user names, domain names
    or the server challenge is never included in the error text.
    """
