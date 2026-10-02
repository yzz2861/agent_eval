from authlib.oauth2.rfc8628.client import SLOW_DOWN_INCREMENT
from authlib.oauth2.rfc8628.client import DeviceTokenPollState


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def test_initial_state():
    clock = FakeClock()
    state = DeviceTokenPollState(interval=5, expires_in=100, clock=clock)
    assert state.interval == 5
    assert state.timeout_backoff is None
    assert not state.expired
    assert state.next_delay() == 5


def test_expired_after_deadline():
    clock = FakeClock()
    state = DeviceTokenPollState(interval=5, expires_in=10, clock=clock)
    clock.now = 10
    assert state.expired
    assert state.next_delay() == 0


def test_next_delay_capped_by_deadline():
    clock = FakeClock()
    state = DeviceTokenPollState(interval=5, expires_in=12, clock=clock)
    clock.now = 10
    assert state.next_delay() == 2


def test_slow_down_increases_interval_persistently():
    state = DeviceTokenPollState(interval=5, expires_in=100, clock=FakeClock())
    assert state.handle_error("slow_down") is True
    assert state.interval == 5 + SLOW_DOWN_INCREMENT
    assert state.handle_error("authorization_pending") is True
    assert state.interval == 5 + SLOW_DOWN_INCREMENT
    assert state.handle_error("slow_down") is True
    assert state.interval == 5 + 2 * SLOW_DOWN_INCREMENT


def test_handle_error_stops_on_other_errors():
    state = DeviceTokenPollState(clock=FakeClock())
    assert state.handle_error("access_denied") is False
    assert state.handle_error("expired_token") is False
    assert state.handle_error("invalid_grant") is False


def test_timeout_backoff_grows_and_resets_separately():
    clock = FakeClock()
    state = DeviceTokenPollState(interval=5, expires_in=100, clock=clock)
    state.handle_network_timeout()
    assert state.next_delay() == 1.0
    state.handle_network_timeout()
    assert state.next_delay() == 2.0
    state.handle_network_timeout()
    assert state.next_delay() == 4.0
    # the protocol interval is not affected by network timeouts
    assert state.interval == 5
    # a server response resets the network backoff
    state.handle_error("authorization_pending")
    assert state.timeout_backoff is None
    assert state.next_delay() == 5
    state.handle_network_timeout()
    assert state.next_delay() == 1.0


def test_timeout_backoff_is_capped():
    state = DeviceTokenPollState(
        expires_in=10000, clock=FakeClock(), max_timeout_backoff=30.0
    )
    for _ in range(10):
        state.handle_network_timeout()
    assert state.timeout_backoff == 30.0
