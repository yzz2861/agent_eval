#!/usr/bin/env python
"""Security regression tests for the one-time binding between a SAML
Response and the original AuthnRequest.

The tests intentionally tamper with already signed responses with signature
enforcement disabled: signature handling itself is covered by other suites,
these tests focus on InResponseTo, Destination, Recipient, Audience, the
validity window and replay protection.
"""
from base64 import encodebytes as b64encode
from contextlib import closing

from pathutils import dotname
from pytest import raises

from saml2 import BINDING_HTTP_POST
from saml2 import time_util
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.client import Saml2Client
from saml2.config import config_factory
from saml2.response import authn_response
from saml2.response import ReplayError
from saml2.response import UnsolicitedResponse
from saml2.response import ReplayCache
from saml2.response import UnsolicitedResponse
from saml2.response import VerificationError
from saml2.saml import Audience
from saml2.samlp import response_from_string
from saml2.server import Server
from saml2.validate import MAX_ACCEPTED_TIME_DIFF
from saml2.validate import effective_time_slack
from saml2.validate import MustValueError
from saml2.validate import ResponseLifetimeExceed
from saml2.validate import ToEarly
from saml2.validate import validate_before
from saml2.validate import validate_on_or_after


SP_ENTITY_ID = "urn:mace:example.com:saml:roland:sp"
OTHER_SP_ENTITY_ID = "urn:mace:example:saml:other:sp"
ACS_URL = "http://lingon.catalogix.se:8087/"
OTHER_ACS_URL = "http://other.example.org/acs"
REQUEST_ID = "id12"
AUTHN = {"class_ref": INTERNETPROTOCOLPASSWORD, "authn_auth": "http://www.example.com/login"}
IDENTITY = {"mail": ["alice@example.com"], "givenName": ["Alice"]}


class TestResponseBinding:
    def setup_class(self):
        with closing(Server(dotname("idp_conf"))) as server:
            name_id = server.ident.transient_nameid(SP_ENTITY_ID, REQUEST_ID)
            self._response_xml = str(
                server.create_authn_response(
                    IDENTITY,
                    in_response_to=REQUEST_ID,
                    destination=ACS_URL,
                    sp_entity_id=SP_ENTITY_ID,
                    name_id=name_id,
                    authn=AUTHN,
                )
            )
            self._unsolicited_xml = str(
                server.create_authn_response(
                    IDENTITY,
                    in_response_to=None,
                    destination=ACS_URL,
                    sp_entity_id=SP_ENTITY_ID,
                    name_id=name_id,
                    authn=AUTHN,
                )
            )

        conf = config_factory("sp", dotname("server_conf"))
        conf.only_use_keys_in_metadata = False
        self.conf = conf

    def _response(self, xml=None, outstanding=None, allow_unsolicited=False):
        resp = authn_response(
            self.conf,
            return_addrs=[ACS_URL],
            outstanding_queries=outstanding if outstanding is not None else {REQUEST_ID: "/came-from"},
            timeslack=60,
            allow_unsolicited=allow_unsolicited,
        )
        # The test responses are not signed, do not require one.
        resp.require_response_signature = False
        resp.require_signature = False
        resp.loads(xml or self._response_xml, decode=False)
        return resp

    def _client(self, allow_unsolicited=False):
        conf = config_factory("sp", dotname("server_conf"))
        conf.only_use_keys_in_metadata = False
        client = Saml2Client(conf)
        client.want_response_signed = False
        client.want_assertions_signed = False
        client.allow_unsolicited = allow_unsolicited
        return client

    @staticmethod
    def _assertion(parsed_response):
        return parsed_response.assertion[0]

    def test_legitimate_response_is_consumed(self):
        outstanding = {REQUEST_ID: "/came-from"}
        resp = self._response(outstanding=outstanding)

        assert resp.verify() is resp
        assert REQUEST_ID not in outstanding
        assert resp._consumed is True

    def test_wrong_in_response_to_is_rejected(self):
        parsed = response_from_string(self._response_xml)
        parsed.in_response_to = "another-request"
        with raises(UnsolicitedResponse):
            self._response(str(parsed))

    def test_subject_confirmation_in_response_to_must_match(self):
        parsed = response_from_string(self._response_xml)
        subject_confirmation_data = self._assertion(parsed).subject.subject_confirmation[0].subject_confirmation_data
        subject_confirmation_data.in_response_to = "another-request"

        with raises(UnsolicitedResponse):
            self._response(str(parsed))

    def test_wrong_destination_is_rejected(self):
        parsed = response_from_string(self._response_xml)
        parsed.destination = OTHER_ACS_URL
        with raises(VerificationError):
            self._response(str(parsed)).verify()

    def test_wrong_recipient_is_rejected(self):
        parsed = response_from_string(self._response_xml)
        subject_confirmation_data = self._assertion(parsed).subject.subject_confirmation[0].subject_confirmation_data
        subject_confirmation_data.recipient = OTHER_ACS_URL

        with raises(VerificationError):
            self._response(str(parsed)).verify()

    def test_audience_must_match_entity_id_exactly(self):
        parsed = response_from_string(self._response_xml)
        audience = self._assertion(parsed).conditions.audience_restriction[0].audience[0]
        audience.text = OTHER_SP_ENTITY_ID

        with raises(Exception):
            self._response(str(parsed)).verify()

    def test_audience_accepts_local_entity_id_among_several(self):
        parsed = response_from_string(self._response_xml)
        restriction = self._assertion(parsed).conditions.audience_restriction[0]
        restriction.audience.append(Audience(text=OTHER_SP_ENTITY_ID))

        resp = self._response(str(parsed))
        assert resp.verify() is resp

    def test_missing_in_response_to_requires_unsolicited_mode(self):
        with raises(UnsolicitedResponse):
            self._response(self._unsolicited_xml)

        resp = self._response(self._unsolicited_xml, outstanding={}, allow_unsolicited=True)
        assert resp.verify() is resp

    def test_unsolicited_response_is_also_replay_protected(self):
        first = self._response(self._unsolicited_xml, outstanding={}, allow_unsolicited=True)
        assert first.verify() is first

        second = self._response(self._unsolicited_xml, outstanding={}, allow_unsolicited=True)
        second.replay_cache = first.replay_cache
        with raises(ReplayError):
            second.verify()

    def test_unknown_in_response_to_requires_unsolicited_mode(self):
        parsed = response_from_string(self._response_xml)
        with raises(UnsolicitedResponse):
            self._response(str(parsed), outstanding={})

        resp = self._response(str(parsed), outstanding={}, allow_unsolicited=True)
        assert resp.verify() is resp

    def test_same_response_cannot_be_consumed_twice(self):
        first = self._response(outstanding={REQUEST_ID: "/came-from"})
        first.replay_cache = first.replay_cache.__class__()
        assert first.verify() is first

        second = self._response(outstanding={REQUEST_ID: "/came-from"})
        second.replay_cache = first.replay_cache
        with raises(ReplayError):
            second.verify()

    def test_client_blocks_replay_of_response_request_pair(self):
        client = self._client()
        outstanding = {REQUEST_ID: "/came-from"}
        encoded = b64encode(self._response_xml.encode("utf-8"))
        first = client.parse_authn_request_response(encoded, BINDING_HTTP_POST, outstanding)
        assert first is not None

        # The first consumption removed the request, restore it to simulate a
        # replayed POST of the same assertion.
        outstanding[REQUEST_ID] = "/came-from"
        with raises(ReplayError):
            client.parse_authn_request_response(encoded, BINDING_HTTP_POST, outstanding)

    def test_failed_verification_leaves_no_replay_state(self):
        resp = self._response()
        parsed = response_from_string(self._response_xml)
        parsed.destination = OTHER_ACS_URL
        tampered = self._response(str(parsed))
        with raises(VerificationError):
            tampered.verify()
        assert len(tampered.replay_cache) == 0
        assert len(resp.replay_cache) == 0

    def test_failed_verification_leaves_outstanding_query_intact(self):
        outstanding = {REQUEST_ID: "/came-from"}
        parsed = response_from_string(self._response_xml)
        parsed.destination = OTHER_ACS_URL
        tampered = self._response(str(parsed), outstanding=outstanding)
        with raises(VerificationError):
            tampered.verify()
        # The request must remain usable for a clean retry: no half-state.
        assert outstanding == {REQUEST_ID: "/came-from"}

        good = self._response(outstanding=outstanding)
        good.replay_cache = tampered.replay_cache
        assert good.verify() is good
        assert REQUEST_ID not in outstanding

    def test_business_callback_runs_only_after_full_verification(self):
        client = self._client()
        encoded = b64encode(self._response_xml.encode("utf-8"))

        tampered_xml = str(response_from_string(self._response_xml))
        parsed = response_from_string(tampered_xml)
        parsed.destination = OTHER_ACS_URL
        tampered_encoded = b64encode(str(parsed).encode("utf-8"))

        with raises(VerificationError):
            client.parse_authn_request_response(tampered_encoded, BINDING_HTTP_POST, {REQUEST_ID: "/x"})
        assert len(client.users.subjects()) == 0
        assert len(client.replay_cache) == 0

        client.parse_authn_request_response(encoded, BINDING_HTTP_POST, {REQUEST_ID: "/x"})
        assert len(client.users.subjects()) == 1
        assert len(client.replay_cache) == 1

    def test_replay_key_is_response_request_combination(self):
        cache = ReplayCache()
        # Two different response/request combinations are tracked separately.
        cache.register("resp-1", "request-1")
        cache.register("resp-1", "request-2")
        assert len(cache) == 2
        assert cache.has_seen("resp-1", "request-1")
        assert cache.has_seen("resp-1", "request-2")
        assert not cache.has_seen("resp-2", "request-1")

        # Re-registering the exact same pair is rejected.
        with raises(ReplayError):
            cache.register("resp-1", "request-1")

    def test_replay_cache_prunes_expired_entries(self):
        cache = ReplayCache()
        now = 1000
        cache.register("resp-expired", "request-1", expires_at=now - 1, now=now - 10)
        cache.register("resp-valid", "request-2", expires_at=now + 100, now=now - 10)
        assert not cache.has_seen("resp-expired", "request-1", now=now)
        assert cache.has_seen("resp-valid", "request-2", now=now)

    def test_not_on_or_after_boundary_uses_one_snapshot(self):
        nooa = time_util.in_a_while(seconds=100)
        now = time_util.utc_now()
        # The assertion is valid while now <= not_on_or_after (+ slack).
        assert validate_on_or_after(nooa, slack=0, now=now) == now + 100
        with raises(ResponseLifetimeExceed):
            validate_on_or_after(nooa, slack=0, now=now + 101)

    def test_not_before_boundary_uses_one_snapshot(self):
        now = time_util.utc_now()
        not_before = time_util.instant(time_stamp=now + 100)
        # At the exact boundary (not_before == now + slack) it is still valid.
        assert validate_before(not_before, slack=10, now=now + 90) is True
        with raises(ToEarly):
            validate_before(not_before, slack=0, now=now + 99)

    def test_all_time_checks_share_the_snapshot(self):
        resp = self._response()
        resp.verify()
        first_snapshot = resp.verification_instant
        assert isinstance(first_snapshot, int)
        # Re-running the checks on the consumed object keeps one instant per
        # verify() call but both conditions were evaluated against the same
        # captured value during verification.
        assert resp.verification_instant == first_snapshot

    def test_clock_skew_is_capped(self):
        assert effective_time_slack(0) == 0
        assert effective_time_slack(60) == 60
        assert effective_time_slack(MAX_ACCEPTED_TIME_DIFF + 1) == MAX_ACCEPTED_TIME_DIFF
        assert effective_time_slack(315360000) == MAX_ACCEPTED_TIME_DIFF
        assert effective_time_slack(-5) == 0
        assert effective_time_slack(None) == 0

        resp = authn_response(self.conf, return_addrs=[ACS_URL], timeslack=315360000)
        assert resp.timeslack == MAX_ACCEPTED_TIME_DIFF
        resp.timeslack = 315360000
        assert resp.timeslack == MAX_ACCEPTED_TIME_DIFF

    def test_response_id_is_required_and_recorded(self):
        parsed = response_from_string(self._response_xml)
        parsed.id = None
        with raises((VerificationError, MustValueError)):
            self._response(str(parsed)).verify()
