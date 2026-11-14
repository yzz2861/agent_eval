import pytest

from .._events import (
    ConnectionClosed,
    Data,
    EndOfMessage,
    Event,
    InformationalResponse,
    Request,
    Response,
)
from .._state import (
    CLOSE_REASON_LOCAL_CLOSE,
    CLOSE_REASON_PROTOCOL_ERROR,
    CLOSE_REASON_REMOTE_CLOSE,
    _SWITCH_CONNECT,
    _SWITCH_UPGRADE,
    CLIENT,
    CLOSED,
    ConnectionState,
    DONE,
    ERROR,
    IDLE,
    MIGHT_SWITCH_PROTOCOL,
    MUST_CLOSE,
    SEND_BODY,
    SEND_RESPONSE,
    SERVER,
    SWITCHED_PROTOCOL,
)
from .._util import LocalProtocolError


def test_ConnectionState() -> None:
    cs = ConnectionState()

    # Basic event-triggered transitions

    assert cs.states == {CLIENT: IDLE, SERVER: IDLE}

    cs.process_event(CLIENT, Request)
    # The SERVER-Request special case:
    assert cs.states == {CLIENT: SEND_BODY, SERVER: SEND_RESPONSE}

    # Illegal transitions raise an error and nothing happens
    with pytest.raises(LocalProtocolError):
        cs.process_event(CLIENT, Request)
    assert cs.states == {CLIENT: SEND_BODY, SERVER: SEND_RESPONSE}

    cs.process_event(SERVER, InformationalResponse)
    assert cs.states == {CLIENT: SEND_BODY, SERVER: SEND_RESPONSE}

    cs.process_event(SERVER, Response)
    assert cs.states == {CLIENT: SEND_BODY, SERVER: SEND_BODY}

    cs.process_event(CLIENT, EndOfMessage)
    cs.process_event(SERVER, EndOfMessage)
    assert cs.states == {CLIENT: DONE, SERVER: DONE}

    # State-triggered transition

    cs.process_event(SERVER, ConnectionClosed)
    assert cs.states == {CLIENT: MUST_CLOSE, SERVER: CLOSED}


def test_ConnectionState_keep_alive() -> None:
    # keep_alive = False
    cs = ConnectionState()
    cs.process_event(CLIENT, Request)
    cs.process_keep_alive_disabled()
    cs.process_event(CLIENT, EndOfMessage)
    assert cs.states == {CLIENT: MUST_CLOSE, SERVER: SEND_RESPONSE}

    cs.process_event(SERVER, Response)
    cs.process_event(SERVER, EndOfMessage)
    assert cs.states == {CLIENT: MUST_CLOSE, SERVER: MUST_CLOSE}


def test_ConnectionState_keep_alive_in_DONE() -> None:
    # Check that if keep_alive is disabled when the CLIENT is already in DONE,
    # then this is sufficient to immediately trigger the DONE -> MUST_CLOSE
    # transition
    cs = ConnectionState()
    cs.process_event(CLIENT, Request)
    cs.process_event(CLIENT, EndOfMessage)
    assert cs.states[CLIENT] is DONE
    cs.process_keep_alive_disabled()
    assert cs.states[CLIENT] is MUST_CLOSE


def test_ConnectionState_switch_denied() -> None:
    for switch_type in (_SWITCH_CONNECT, _SWITCH_UPGRADE):
        for deny_early in (True, False):
            cs = ConnectionState()
            cs.process_client_switch_proposal(switch_type)
            cs.process_event(CLIENT, Request)
            cs.process_event(CLIENT, Data)
            assert cs.states == {CLIENT: SEND_BODY, SERVER: SEND_RESPONSE}

            assert switch_type in cs.pending_switch_proposals

            if deny_early:
                # before client reaches DONE
                cs.process_event(SERVER, Response)
                assert not cs.pending_switch_proposals

            cs.process_event(CLIENT, EndOfMessage)

            if deny_early:
                assert cs.states == {CLIENT: DONE, SERVER: SEND_BODY}
            else:
                assert cs.states == {
                    CLIENT: MIGHT_SWITCH_PROTOCOL,
                    SERVER: SEND_RESPONSE,
                }

                cs.process_event(SERVER, InformationalResponse)
                assert cs.states == {
                    CLIENT: MIGHT_SWITCH_PROTOCOL,
                    SERVER: SEND_RESPONSE,
                }

                cs.process_event(SERVER, Response)
                assert cs.states == {CLIENT: DONE, SERVER: SEND_BODY}
                assert not cs.pending_switch_proposals


_response_type_for_switch = {
    _SWITCH_UPGRADE: InformationalResponse,
    _SWITCH_CONNECT: Response,
    None: Response,
}


def test_ConnectionState_protocol_switch_accepted() -> None:
    for switch_event in [_SWITCH_UPGRADE, _SWITCH_CONNECT]:
        cs = ConnectionState()
        cs.process_client_switch_proposal(switch_event)
        cs.process_event(CLIENT, Request)
        cs.process_event(CLIENT, Data)
        assert cs.states == {CLIENT: SEND_BODY, SERVER: SEND_RESPONSE}

        cs.process_event(CLIENT, EndOfMessage)
        assert cs.states == {CLIENT: MIGHT_SWITCH_PROTOCOL, SERVER: SEND_RESPONSE}

        cs.process_event(SERVER, InformationalResponse)
        assert cs.states == {CLIENT: MIGHT_SWITCH_PROTOCOL, SERVER: SEND_RESPONSE}

        cs.process_event(SERVER, _response_type_for_switch[switch_event], switch_event)
        assert cs.states == {CLIENT: SWITCHED_PROTOCOL, SERVER: SWITCHED_PROTOCOL}


def test_ConnectionState_double_protocol_switch() -> None:
    # CONNECT + Upgrade is legal! Very silly, but legal. So we support
    # it. Because sometimes doing the silly thing is easier than not.
    for server_switch in [None, _SWITCH_UPGRADE, _SWITCH_CONNECT]:
        cs = ConnectionState()
        cs.process_client_switch_proposal(_SWITCH_UPGRADE)
        cs.process_client_switch_proposal(_SWITCH_CONNECT)
        cs.process_event(CLIENT, Request)
        cs.process_event(CLIENT, EndOfMessage)
        assert cs.states == {CLIENT: MIGHT_SWITCH_PROTOCOL, SERVER: SEND_RESPONSE}
        cs.process_event(
            SERVER, _response_type_for_switch[server_switch], server_switch
        )
        if server_switch is None:
            assert cs.states == {CLIENT: DONE, SERVER: SEND_BODY}
        else:
            assert cs.states == {CLIENT: SWITCHED_PROTOCOL, SERVER: SWITCHED_PROTOCOL}


def test_ConnectionState_inconsistent_protocol_switch() -> None:
    for client_switches, server_switch in [
        ([], _SWITCH_CONNECT),
        ([], _SWITCH_UPGRADE),
        ([_SWITCH_UPGRADE], _SWITCH_CONNECT),
        ([_SWITCH_CONNECT], _SWITCH_UPGRADE),
    ]:
        cs = ConnectionState()
        for client_switch in client_switches:  # type: ignore[attr-defined]
            cs.process_client_switch_proposal(client_switch)
        cs.process_event(CLIENT, Request)
        with pytest.raises(LocalProtocolError):
            cs.process_event(SERVER, Response, server_switch)


def test_ConnectionState_keepalive_protocol_switch_interaction() -> None:
    # keep_alive=False + pending_switch_proposals
    cs = ConnectionState()
    cs.process_client_switch_proposal(_SWITCH_UPGRADE)
    cs.process_event(CLIENT, Request)
    cs.process_keep_alive_disabled()
    cs.process_event(CLIENT, Data)
    assert cs.states == {CLIENT: SEND_BODY, SERVER: SEND_RESPONSE}

    # the protocol switch "wins"
    cs.process_event(CLIENT, EndOfMessage)
    assert cs.states == {CLIENT: MIGHT_SWITCH_PROTOCOL, SERVER: SEND_RESPONSE}

    # but when the server denies the request, keep_alive comes back into play
    cs.process_event(SERVER, Response)
    assert cs.states == {CLIENT: MUST_CLOSE, SERVER: SEND_BODY}


def test_ConnectionState_reuse() -> None:
    cs = ConnectionState()

    with pytest.raises(LocalProtocolError):
        cs.start_next_cycle()

    cs.process_event(CLIENT, Request)
    cs.process_event(CLIENT, EndOfMessage)

    with pytest.raises(LocalProtocolError):
        cs.start_next_cycle()

    cs.process_event(SERVER, Response)
    cs.process_event(SERVER, EndOfMessage)

    cs.start_next_cycle()
    assert cs.states == {CLIENT: IDLE, SERVER: IDLE}

    # No keepalive

    cs.process_event(CLIENT, Request)
    cs.process_keep_alive_disabled()
    cs.process_event(CLIENT, EndOfMessage)
    cs.process_event(SERVER, Response)
    cs.process_event(SERVER, EndOfMessage)

    with pytest.raises(LocalProtocolError):
        cs.start_next_cycle()

    # One side closed

    cs = ConnectionState()
    cs.process_event(CLIENT, Request)
    cs.process_event(CLIENT, EndOfMessage)
    cs.process_event(CLIENT, ConnectionClosed)
    cs.process_event(SERVER, Response)
    cs.process_event(SERVER, EndOfMessage)

    with pytest.raises(LocalProtocolError):
        cs.start_next_cycle()

    # Succesful protocol switch

    cs = ConnectionState()
    cs.process_client_switch_proposal(_SWITCH_UPGRADE)
    cs.process_event(CLIENT, Request)
    cs.process_event(CLIENT, EndOfMessage)
    cs.process_event(SERVER, InformationalResponse, _SWITCH_UPGRADE)

    with pytest.raises(LocalProtocolError):
        cs.start_next_cycle()

    # Failed protocol switch

    cs = ConnectionState()
    cs.process_client_switch_proposal(_SWITCH_UPGRADE)
    cs.process_event(CLIENT, Request)
    cs.process_event(CLIENT, EndOfMessage)
    cs.process_event(SERVER, Response)
    cs.process_event(SERVER, EndOfMessage)

    cs.start_next_cycle()
    assert cs.states == {CLIENT: IDLE, SERVER: IDLE}


def test_server_request_is_illegal() -> None:
    # There used to be a bug in how we handled the Request special case that
    # made this allowed...
    cs = ConnectionState()
    with pytest.raises(LocalProtocolError):
        cs.process_event(SERVER, Request)


def test_ConnectionState_close_reason_defaults() -> None:
    cs = ConnectionState()
    assert cs.get_close_reason(CLIENT) is None
    assert cs.get_close_reason(SERVER) is None


def test_ConnectionState_close_reason_records_and_persists() -> None:
    cs = ConnectionState()
    # An orderly local close is recorded when ConnectionClosed is processed.
    cs.process_event(CLIENT, ConnectionClosed)
    assert cs.get_close_reason(CLIENT) is CLOSE_REASON_LOCAL_CLOSE

    # Moving into ERROR afterwards must not erase the original close reason.
    cs.process_error(CLIENT)
    assert cs.states[CLIENT] is ERROR
    assert cs.get_close_reason(CLIENT) is CLOSE_REASON_LOCAL_CLOSE


def test_ConnectionState_close_reason_first_reason_wins() -> None:
    cs = ConnectionState()
    cs.set_close_reason(SERVER, CLOSE_REASON_REMOTE_CLOSE)
    cs.set_close_reason(SERVER, CLOSE_REASON_PROTOCOL_ERROR)
    assert cs.get_close_reason(SERVER) is CLOSE_REASON_REMOTE_CLOSE


def test_ConnectionState_error_without_reason_gets_protocol_error() -> None:
    cs = ConnectionState()
    cs.process_error(SERVER)
    assert cs.get_close_reason(SERVER) is CLOSE_REASON_PROTOCOL_ERROR


def test_ConnectionState_keep_alive_disabled_records_reason() -> None:
    cs = ConnectionState()
    cs.process_keep_alive_disabled_with_reason(CLIENT, CLOSE_REASON_LOCAL_CLOSE)
    assert cs.keep_alive is False
    assert cs.get_close_reason(CLIENT) is CLOSE_REASON_LOCAL_CLOSE


def test_ConnectionState_body_events_rejected_in_close_states() -> None:
    # Data/EndOfMessage may only be emitted from SEND_BODY. Every body-
    # forbidden state must reject them, for both roles, so bytes arriving
    # after a close can never be accepted by the state machine.
    from .._state import EVENT_TRIGGERED_TRANSITIONS

    body_events = (Data, EndOfMessage)
    body_forbidden = (DONE, MUST_CLOSE, CLOSED, ERROR)
    for role, table in EVENT_TRIGGERED_TRANSITIONS.items():
        for state, events in table.items():
            if state in body_forbidden:
                for event_type in body_events:
                    assert event_type not in events
            if state in (MIGHT_SWITCH_PROTOCOL, SWITCHED_PROTOCOL):
                # Protocol-switch states accept no message events at all.
                assert events == {}


def test_ConnectionState_roles_have_independent_tables() -> None:
    # Regression guard: the client and server must not share a default
    # transition table. Only the CLIENT waits in MIGHT_SWITCH_PROTOCOL, and
    # only the SERVER has SEND_RESPONSE and the (Request, CLIENT) special
    # case.
    from .._state import EVENT_TRIGGERED_TRANSITIONS

    assert MIGHT_SWITCH_PROTOCOL in EVENT_TRIGGERED_TRANSITIONS[CLIENT]
    assert MIGHT_SWITCH_PROTOCOL not in EVENT_TRIGGERED_TRANSITIONS[SERVER]
    assert SEND_RESPONSE in EVENT_TRIGGERED_TRANSITIONS[SERVER]
    assert SEND_RESPONSE not in EVENT_TRIGGERED_TRANSITIONS[CLIENT]
