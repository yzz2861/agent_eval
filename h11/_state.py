################################################################
# The core state machine
################################################################
#
# Rule 1: everything that affects the state machine and state transitions must
# live here in this file. As much as possible goes into the table-based
# representation, but for the bits that don't quite fit, the actual code and
# state must nonetheless live here.
#
# Rule 2: this file does not know about what role we're playing; it only knows
# about HTTP request/response cycles in the abstract. This ensures that we
# don't cheat and apply different rules to local and remote parties.
#
#
# Theory of operation
# ===================
#
# Possibly the simplest way to think about this is that we actually have 5
# different state machines here. Yes, 5. These are:
#
# 1) The client state, with its complicated automaton (see the docs)
# 2) The server state, with its complicated automaton (see the docs)
# 3) The keep-alive state, with possible states {True, False}
# 4) The SWITCH_CONNECT state, with possible states {False, True}
# 5) The SWITCH_UPGRADE state, with possible states {False, True}
#
# For (3)-(5), the first state listed is the initial state.
#
# (1)-(3) are stored explicitly in member variables. The last
# two are stored implicitly in the pending_switch_proposals set as:
#   (state of 4) == (_SWITCH_CONNECT in pending_switch_proposals)
#   (state of 5) == (_SWITCH_UPGRADE in pending_switch_proposals)
#
# And each of these machines has two different kinds of transitions:
#
# a) Event-triggered
# b) State-triggered
#
# Event triggered is the obvious thing that you'd think it is: some event
# happens, and if it's the right event at the right time then a transition
# happens. But there are somewhat complicated rules for which machines can
# "see" which events. (As a rule of thumb, if a machine "sees" an event, this
# means two things: the event can affect the machine, and if the machine is
# not in a state where it expects that event then it's an error.) These rules
# are:
#
# 1) The client machine sees all h11.events objects emitted by the client.
#
# 2) The server machine sees all h11.events objects emitted by the server.
#
#    It also sees the client's Request event.
#
#    And sometimes, server events are annotated with a _SWITCH_* event. For
#    example, we can have a (Response, _SWITCH_CONNECT) event, which is
#    different from a regular Response event.
#
# 3) The keep-alive machine sees the process_keep_alive_disabled() event
#    (which is derived from Request/Response events), and this event
#    transitions it from True -> False, or from False -> False. There's no way
#    to transition back.
#
# 4&5) The _SWITCH_* machines transition from False->True when we get a
#    Request that proposes the relevant type of switch (via
#    process_client_switch_proposals), and they go from True->False when we
#    get a Response that has no _SWITCH_* annotation.
#
# So that's event-triggered transitions.
#
# State-triggered transitions are less standard. What they do here is couple
# the machines together. The way this works is, when certain *joint*
# configurations of states are achieved, then we automatically transition to a
# new *joint* state. So, for example, if we're ever in a joint state with
#
#   client: DONE
#   keep-alive: False
#
# then the client state immediately transitions to:
#
#   client: MUST_CLOSE
#
# This is fundamentally different from an event-based transition, because it
# doesn't matter how we arrived at the {client: DONE, keep-alive: False} state
# -- maybe the client transitioned SEND_BODY -> DONE, or keep-alive
# transitioned True -> False. Either way, once this precondition is satisfied,
# this transition is immediately triggered.
#
# What if two conflicting state-based transitions get enabled at the same
# time?  In practice there's only one case where this arises (client DONE ->
# MIGHT_SWITCH_PROTOCOL versus DONE -> MUST_CLOSE), and we resolve it by
# explicitly prioritizing the DONE -> MIGHT_SWITCH_PROTOCOL transition.
#
# Implementation
# --------------
#
# The event-triggered transitions for the server and client machines are all
# stored explicitly in a table. Ditto for the state-triggered transitions that
# involve just the server and client state.
#
# The transitions for the other machines, and the state-triggered transitions
# that involve the other machines, are written out as explicit Python code.
#
# It'd be nice if there were some cleaner way to do all this. This isn't
# *too* terrible, but I feel like it could probably be better.
#
# WARNING
# -------
#
# The script that generates the state machine diagrams for the docs knows how
# to read out the EVENT_TRIGGERED_TRANSITIONS and STATE_TRIGGERED_TRANSITIONS
# tables. But it can't automatically read the transitions that are written
# directly in Python code. So if you touch those, you need to also update the
# script to keep it in sync!
from typing import cast, Dict, Optional, Set, Tuple, Type, Union

from ._events import *
from ._util import LocalProtocolError, Sentinel

# Everything in __all__ gets re-exported as part of the h11 public API.
__all__ = [
    "CLIENT",
    "SERVER",
    "IDLE",
    "SEND_RESPONSE",
    "SEND_BODY",
    "DONE",
    "MUST_CLOSE",
    "CLOSED",
    "MIGHT_SWITCH_PROTOCOL",
    "SWITCHED_PROTOCOL",
    "ERROR",
    "CLOSE_REASON_LOCAL_CLOSE",
    "CLOSE_REASON_REMOTE_CLOSE",
    "CLOSE_REASON_LOCAL_SHUTDOWN",
    "CLOSE_REASON_REMOTE_SHUTDOWN",
    "CLOSE_REASON_PROTOCOL_ERROR",
    "CLOSE_REASON_UNEXPECTED_PEER_CLOSE",
]


class CLIENT(Sentinel, metaclass=Sentinel):
    pass


class SERVER(Sentinel, metaclass=Sentinel):
    pass


# States
class IDLE(Sentinel, metaclass=Sentinel):
    pass


class SEND_RESPONSE(Sentinel, metaclass=Sentinel):
    pass


class SEND_BODY(Sentinel, metaclass=Sentinel):
    pass


class DONE(Sentinel, metaclass=Sentinel):
    pass


class MUST_CLOSE(Sentinel, metaclass=Sentinel):
    pass


class CLOSED(Sentinel, metaclass=Sentinel):
    pass


class ERROR(Sentinel, metaclass=Sentinel):
    pass


# Switch types
class MIGHT_SWITCH_PROTOCOL(Sentinel, metaclass=Sentinel):
    pass


class SWITCHED_PROTOCOL(Sentinel, metaclass=Sentinel):
    pass


class _SWITCH_UPGRADE(Sentinel, metaclass=Sentinel):
    pass


class _SWITCH_CONNECT(Sentinel, metaclass=Sentinel):
    pass


# Close reasons
# -----------
# These document *why* a connection is being driven towards CLOSED. They are
# recorded on the ConnectionState as soon as the relevant event is observed,
# so that the reason survives even if a later protocol violation (e.g. data
# arriving after a "Connection: close" message) moves the peer into ERROR.
#
# The two flavours track which direction of the TCP connection went away:
# - *_CLOSE      -> a full close was requested through the HTTP state machine
#                   (a ConnectionClosed event / Connection: close negotiation)
# - *_SHUTDOWN   -> the transport half carrying this role was shut down at
#                   the TCP level (an EOF observed on the receive side)
class CLOSE_REASON_LOCAL_CLOSE(Sentinel, metaclass=Sentinel):
    pass


class CLOSE_REASON_REMOTE_CLOSE(Sentinel, metaclass=Sentinel):
    pass


class CLOSE_REASON_LOCAL_SHUTDOWN(Sentinel, metaclass=Sentinel):
    pass


class CLOSE_REASON_REMOTE_SHUTDOWN(Sentinel, metaclass=Sentinel):
    pass


class CLOSE_REASON_PROTOCOL_ERROR(Sentinel, metaclass=Sentinel):
    pass


class CLOSE_REASON_UNEXPECTED_PEER_CLOSE(Sentinel, metaclass=Sentinel):
    pass


EventTransitionType = Dict[
    Type[Sentinel],
    Dict[
        Type[Sentinel],
        Dict[Union[Type[Event], Tuple[Type[Event], Type[Sentinel]]], Type[Sentinel]],
    ],
]

# Explicit event-triggered transition tables.
#
# Each inner dict maps an event to the state that role moves into. A state
# with no entry for an event (an empty dict, or simply a missing key) means
# that the event is a protocol violation in that state -- most importantly,
# Data/EndOfMessage only appear in SEND_BODY, so any body bytes that arrive
# in a body-forbidden state (DONE / MUST_CLOSE / CLOSED / ERROR / the
# protocol-switch states) are rejected rather than being silently accepted.
#
# Connection lifecycle events covered explicitly below:
#
# * Full close: ConnectionClosed is accepted from IDLE / DONE / MUST_CLOSE /
#   CLOSED and always lands in CLOSED (it is idempotent once CLOSED). It is
#   deliberately absent from SEND_BODY -- you cannot close while a message
#   body is still in flight; an EOF there is a truncated-body error instead.
#
# * Half close: a transport-level EOF observed while a role is IDLE is turned
#   into a ConnectionClosed event, so it follows the same IDLE -> CLOSED row.
#   A half close that interrupts a body never reaches this table: the body
#   reader raises first and the role goes to ERROR.
#
# * Upgrade: an Upgrade proposal puts the CLIENT into
#   MIGHT_SWITCH_PROTOCOL once its message ends, and a matching 101
#   InformationalResponse moves the SERVER straight to SWITCHED_PROTOCOL.
#
# * CONNECT: a CONNECT proposal uses the same MIGHT_SWITCH_PROTOCOL wait
#   state, and a successful 2xx Response moves the SERVER to
#   SWITCHED_PROTOCOL.
#
# The CLIENT and SERVER tables are intentionally *not* shared: only the
# CLIENT ever waits in MIGHT_SWITCH_PROTOCOL, only the SERVER has the
# SEND_RESPONSE state and sees the peer's Request events, and the events
# that drive each role differ. Giving each role its own table guarantees
# that neither inherits an incorrect default from the other.

EVENT_TRIGGERED_TRANSITIONS: EventTransitionType = {
    CLIENT: {
        # IDLE: either start a new request, or close the connection.
        IDLE: {Request: SEND_BODY, ConnectionClosed: CLOSED},
        # SEND_BODY: the only state in which body events are legal.
        SEND_BODY: {Data: SEND_BODY, EndOfMessage: DONE},
        # DONE: a finished message can only be followed by a full close.
        # Keep-alive reuse goes through start_next_cycle(), not an event.
        DONE: {ConnectionClosed: CLOSED},
        # MUST_CLOSE: keep-alive was disabled; the only legal next event is
        # the close itself. Any other data is a protocol violation.
        MUST_CLOSE: {ConnectionClosed: CLOSED},
        # CLOSED is terminal: ConnectionClosed stays idempotent.
        CLOSED: {ConnectionClosed: CLOSED},
        # Waiting for the server to answer an Upgrade/CONNECT proposal. No
        # events are accepted here -- the role pauses until the SERVER's
        # decision drives a state-triggered transition.
        MIGHT_SWITCH_PROTOCOL: {},
        # A protocol switch was completed; h11 no longer owns the bytes.
        SWITCHED_PROTOCOL: {},
        # Something went wrong; only process_error() touches this state.
        ERROR: {},
    },
    SERVER: {
        IDLE: {
            ConnectionClosed: CLOSED,
            Response: SEND_BODY,
            # Special case: server sees client Request events, in this form
            (Request, CLIENT): SEND_RESPONSE,
        },
        SEND_RESPONSE: {
            # Zero or more 1xx responses, then the final response.
            InformationalResponse: SEND_RESPONSE,
            Response: SEND_BODY,
            # Upgrade accepted: a matching 101 switches immediately.
            (InformationalResponse, _SWITCH_UPGRADE): SWITCHED_PROTOCOL,
            # CONNECT accepted: a 2xx response switches immediately.
            (Response, _SWITCH_CONNECT): SWITCHED_PROTOCOL,
        },
        # SEND_BODY: the only state in which the server may emit body events.
        SEND_BODY: {Data: SEND_BODY, EndOfMessage: DONE},
        # DONE / MUST_CLOSE / CLOSED mirror the client side: only a full
        # close remains legal, and CLOSED treats the event as idempotent.
        DONE: {ConnectionClosed: CLOSED},
        MUST_CLOSE: {ConnectionClosed: CLOSED},
        CLOSED: {ConnectionClosed: CLOSED},
        # The server never waits on a switch proposal and ERROR is terminal.
        SWITCHED_PROTOCOL: {},
        ERROR: {},
    },
}

StateTransitionType = Dict[
    Tuple[Type[Sentinel], Type[Sentinel]], Dict[Type[Sentinel], Type[Sentinel]]
]

# NB: there are also some special-case state-triggered transitions hard-coded
# into _fire_state_triggered_transitions below.
#
# These joint (CLIENT, SERVER) states encode the cross-role effects of close
# and half-close, plus the final Upgrade/CONNECT hand-off:
#
# * (MIGHT_SWITCH_PROTOCOL, SWITCHED_PROTOCOL): the client proposed a switch
#   and the server accepted it, so the client also moves to SWITCHED_PROTOCOL.
# * (CLOSED, DONE/IDLE) and (ERROR, DONE): once the client side is gone, a
#   server that has nothing left to send is forced to MUST_CLOSE (and vice
#   versa for the mirror-image rows). IDLE is the half-close case: the peer
#   shut down before starting any message.
STATE_TRIGGERED_TRANSITIONS: StateTransitionType = {
    # (Client state, Server state) -> new states
    # Protocol negotiation
    (MIGHT_SWITCH_PROTOCOL, SWITCHED_PROTOCOL): {CLIENT: SWITCHED_PROTOCOL},
    # Socket shutdown
    (CLOSED, DONE): {SERVER: MUST_CLOSE},
    (CLOSED, IDLE): {SERVER: MUST_CLOSE},
    (ERROR, DONE): {SERVER: MUST_CLOSE},
    (DONE, CLOSED): {CLIENT: MUST_CLOSE},
    (IDLE, CLOSED): {CLIENT: MUST_CLOSE},
    (DONE, ERROR): {CLIENT: MUST_CLOSE},
}


class ConnectionState:
    def __init__(self) -> None:
        # Extra bits of state that don't quite fit into the state model.

        # If this is False then it enables the automatic DONE -> MUST_CLOSE
        # transition. Don't set this directly; call .keep_alive_disabled()
        self.keep_alive = True

        # This is a subset of {UPGRADE, CONNECT}, containing the proposals
        # made by the client for switching protocols.
        self.pending_switch_proposals: Set[Type[Sentinel]] = set()

        self.states: Dict[Type[Sentinel], Type[Sentinel]] = {CLIENT: IDLE, SERVER: IDLE}

        # The reason each role is being closed, or None while the role is
        # still healthy. Keyed by role so that a local send-side failure and
        # a remote receive-side violation can coexist. The first reason
        # recorded for a role always wins, so the reason survives any later
        # transition (including into ERROR).
        self.close_reasons: Dict[Type[Sentinel], Optional[Type[Sentinel]]] = {
            CLIENT: None,
            SERVER: None,
        }

    def set_close_reason(self, role: Type[Sentinel], reason: Type[Sentinel]) -> None:
        # Record why a role is heading towards CLOSED. An existing reason is
        # deliberately preserved: e.g. data arriving after "Connection:
        # close" moves the peer to ERROR, but the original
        # CLOSE_REASON_*_CLOSE must not be overwritten.
        if self.close_reasons[role] is None:
            self.close_reasons[role] = reason

    def get_close_reason(self, role: Type[Sentinel]) -> Optional[Type[Sentinel]]:
        return self.close_reasons[role]

    def process_error(self, role: Type[Sentinel]) -> None:
        if self.close_reasons[role] is None:
            self.close_reasons[role] = CLOSE_REASON_PROTOCOL_ERROR
        self.states[role] = ERROR
        self._fire_state_triggered_transitions()

    def process_keep_alive_disabled(self) -> None:
        self.keep_alive = False
        self._fire_state_triggered_transitions()

    def process_keep_alive_disabled_with_reason(
        self, role: Type[Sentinel], reason: Type[Sentinel]
    ) -> None:
        # Keep-alive was disabled by an explicit negotiation (Connection:
        # close or an HTTP/1.0 peer). Record which side asked for it so that
        # the reason survives any later ERROR transition.
        self.set_close_reason(role, reason)
        self.process_keep_alive_disabled()

    def process_client_switch_proposal(self, switch_event: Type[Sentinel]) -> None:
        self.pending_switch_proposals.add(switch_event)
        self._fire_state_triggered_transitions()

    def process_event(
        self,
        role: Type[Sentinel],
        event_type: Type[Event],
        server_switch_event: Optional[Type[Sentinel]] = None,
    ) -> None:
        _event_type: Union[Type[Event], Tuple[Type[Event], Type[Sentinel]]] = event_type
        if server_switch_event is not None:
            assert role is SERVER
            if server_switch_event not in self.pending_switch_proposals:
                raise LocalProtocolError(
                    "Received server _SWITCH_UPGRADE event without a pending proposal"
                )
            _event_type = (event_type, server_switch_event)
        if server_switch_event is None and _event_type is Response:
            self.pending_switch_proposals = set()
        if _event_type is ConnectionClosed:
            # Default to an orderly local close; the Connection layer
            # overrides this with the remote reason for a peer-emitted close.
            self.set_close_reason(role, CLOSE_REASON_LOCAL_CLOSE)
        self._fire_event_triggered_transitions(role, _event_type)
        # Special case: the server state does get to see Request
        # events.
        if _event_type is Request:
            assert role is CLIENT
            self._fire_event_triggered_transitions(SERVER, (Request, CLIENT))
        self._fire_state_triggered_transitions()

    def _fire_event_triggered_transitions(
        self,
        role: Type[Sentinel],
        event_type: Union[Type[Event], Tuple[Type[Event], Type[Sentinel]]],
    ) -> None:
        state = self.states[role]
        try:
            new_state = EVENT_TRIGGERED_TRANSITIONS[role][state][event_type]
        except KeyError:
            event_type = cast(Type[Event], event_type)
            raise LocalProtocolError(
                "can't handle event type {} when role={} and state={}".format(
                    event_type.__name__, role, self.states[role]
                )
            ) from None
        self.states[role] = new_state

    def _fire_state_triggered_transitions(self) -> None:
        # We apply these rules repeatedly until converging on a fixed point
        while True:
            start_states = dict(self.states)

            # It could happen that both these special-case transitions are
            # enabled at the same time:
            #
            #    DONE -> MIGHT_SWITCH_PROTOCOL
            #    DONE -> MUST_CLOSE
            #
            # For example, this will always be true of a HTTP/1.0 client
            # requesting CONNECT.  If this happens, the protocol switch takes
            # priority. From there the client will either go to
            # SWITCHED_PROTOCOL, in which case it's none of our business when
            # they close the connection, or else the server will deny the
            # request, in which case the client will go back to DONE and then
            # from there to MUST_CLOSE.
            if self.pending_switch_proposals:
                if self.states[CLIENT] is DONE:
                    self.states[CLIENT] = MIGHT_SWITCH_PROTOCOL

            if not self.pending_switch_proposals:
                if self.states[CLIENT] is MIGHT_SWITCH_PROTOCOL:
                    self.states[CLIENT] = DONE

            if not self.keep_alive:
                for role in (CLIENT, SERVER):
                    if self.states[role] is DONE:
                        self.states[role] = MUST_CLOSE

            # Tabular state-triggered transitions
            joint_state = (self.states[CLIENT], self.states[SERVER])
            changes = STATE_TRIGGERED_TRANSITIONS.get(joint_state, {})
            self.states.update(changes)

            if self.states == start_states:
                # Fixed point reached
                return

    def start_next_cycle(self) -> None:
        if self.states != {CLIENT: DONE, SERVER: DONE}:
            raise LocalProtocolError(
                f"not in a reusable state. self.states={self.states}"
            )
        # Can't reach DONE/DONE with any of these active, but still, let's be
        # sure.
        assert self.keep_alive
        assert not self.pending_switch_proposals
        self.states = {CLIENT: IDLE, SERVER: IDLE}
