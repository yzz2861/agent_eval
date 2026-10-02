"""authlib.oauth2.rfc8628.client.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Client-side helpers for the OAuth 2.0 Device Authorization Grant.

https://www.rfc-editor.org/rfc/rfc8628
"""

import time

from .device_code import DEVICE_CODE_GRANT_TYPE

__all__ = [
    "DEVICE_CODE_GRANT_TYPE",
    "DeviceTokenPollState",
    "DEFAULT_POLL_INTERVAL",
    "SLOW_DOWN_INCREMENT",
    "DEFAULT_EXPIRES_IN",
    "INITIAL_TIMEOUT_BACKOFF",
    "MAX_TIMEOUT_BACKOFF",
]

#: Default seconds to wait between two polling requests when the device
#: authorization response did not contain an "interval" value.
DEFAULT_POLL_INTERVAL = 5

#: Seconds added to the polling interval on every "slow_down" response,
#: per RFC 8628 Section 3.5.
SLOW_DOWN_INCREMENT = 5

#: Fallback lifetime in seconds of a device code when the device
#: authorization response did not contain an "expires_in" value.
DEFAULT_EXPIRES_IN = 900

#: Initial delay in seconds before retrying a polling request that
#: failed with a network timeout.
INITIAL_TIMEOUT_BACKOFF = 1.0

#: Maximum delay in seconds between two polling requests retried after
#: network timeouts.
MAX_TIMEOUT_BACKOFF = 30.0


class DeviceTokenPollState:
    """Bookkeeping for RFC 8628 device token polling.

    The protocol polling interval (which grows on every "slow_down"
    response) and the network-timeout backoff are tracked separately:
    a network timeout never changes the protocol interval, and any
    HTTP response from the server resets the timeout backoff.

    :param interval: Initial polling interval in seconds.
    :param expires_in: Lifetime of the device code in seconds.
    :param clock: A monotonic clock callable, defaults to time.monotonic.
    :param initial_timeout_backoff: First delay in seconds before
        retrying a request that failed with a network timeout.
    :param max_timeout_backoff: Upper bound for the network-timeout
        backoff.
    """

    def __init__(
        self,
        interval=DEFAULT_POLL_INTERVAL,
        expires_in=DEFAULT_EXPIRES_IN,
        clock=None,
        initial_timeout_backoff=INITIAL_TIMEOUT_BACKOFF,
        max_timeout_backoff=MAX_TIMEOUT_BACKOFF,
    ):
        if clock is None:
            clock = time.monotonic
        self.clock = clock
        self.interval = interval
        self.deadline = clock() + expires_in
        self.initial_timeout_backoff = initial_timeout_backoff
        self.max_timeout_backoff = max_timeout_backoff
        #: current network-timeout backoff, None when the last
        #: request reached the server
        self.timeout_backoff = None

    @property
    def expired(self):
        """Whether the device code lifetime has been reached."""
        return self.clock() >= self.deadline

    def next_delay(self):
        """Seconds to wait before the next polling request.

        The delay never crosses the device code deadline, so that
        polling stops as soon as the device code expires.
        """
        if self.timeout_backoff is not None:
            delay = self.timeout_backoff
        else:
            delay = self.interval
        remaining = self.deadline - self.clock()
        return max(0.0, min(delay, remaining))

    def handle_network_timeout(self):
        """Record a network timeout, growing the backoff exponentially."""
        if self.timeout_backoff is None:
            self.timeout_backoff = self.initial_timeout_backoff
        else:
            self.timeout_backoff = min(
                self.timeout_backoff * 2, self.max_timeout_backoff
            )

    def handle_error(self, error):
        """Record an OAuth2 error response from the token endpoint.

        Returns True if polling should continue ("authorization_pending"
        and "slow_down"), False otherwise ("access_denied",
        "expired_token" and any other error).
        """
        # the server responded, so the network is fine
        self.timeout_backoff = None
        if error == "slow_down":
            self.interval += SLOW_DOWN_INCREMENT
            return True
        return error == "authorization_pending"
