import threading
from unittest.mock import Mock

import pytest

from authlib.oauth2 import rfc9101
from authlib.oauth2.rfc9101.authorization_server import PROTECTED_REQUEST_PARAMETERS
from authlib.oauth2.rfc9101.errors import DuplicateRequestParameterError
from authlib.oauth2.rfc9101.errors import JTIReplayError


def create_extension(**kwargs):
    return rfc9101.JWTAuthenticationRequest(**kwargs)


def create_request(claims):
    payload = Mock()
    payload.data = {"client_id": "client-id", **claims}
    payload.state = None
    request = Mock()
    request.payload = payload
    return request


def test_conflict_check_rejects_diverging_security_parameters():
    extension = create_extension()
    request = create_request({"redirect_uri": "https://outer.test"})
    with pytest.raises(DuplicateRequestParameterError):
        extension._validate_parameter_conflicts(
            request,
            {"redirect_uri": "https://inner.test"},
        )


def test_conflict_check_accepts_identical_values():
    extension = create_extension()
    request = create_request({"state": "same"})
    # Must not raise.
    extension._validate_parameter_conflicts(request, {"state": "same"})


def test_protected_parameters_cover_core_security_fields():
    for name in (
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "code_challenge",
    ):
        assert name in PROTECTED_REQUEST_PARAMETERS


def test_jti_consumption_is_atomic():
    extension = create_extension(require_jti=True)
    client = Mock()
    client.get_client_id.return_value = "client-id"
    barrier = threading.Barrier(2)
    outcomes = []

    def worker():
        barrier.wait()
        try:
            extension._consume_jti(client, {"jti": "race"}, None)
            outcomes.append("won")
        except JTIReplayError:
            outcomes.append("lost")

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["lost", "won"]


def test_jti_replay_uses_persistent_hook_result():
    extension = create_extension(require_jti=True)
    client = Mock()
    client.get_client_id.return_value = "client-id"
    extension.consume_request_object_jti = Mock(side_effect=[True, False])

    extension._consume_jti(client, {"jti": "jti"}, None)
    with pytest.raises(JTIReplayError):
        extension._consume_jti(client, {"jti": "jti"}, None)


def test_empty_jti_rejected_without_calling_persistence():
    extension = create_extension(require_jti=True)
    client = Mock()
    extension.consume_request_object_jti = Mock()
    with pytest.raises(rfc9101.InvalidRequestObjectError):
        extension._consume_jti(client, {"jti": ""}, None)
    extension.consume_request_object_jti.assert_not_called()


def test_encrypted_and_nested_switches_default_off():
    extension = create_extension()
    assert extension.allow_encrypted_request_object is False
    assert extension.allow_nested_request_object is False


def test_strict_flags_default_off_for_backwards_compatibility():
    extension = create_extension()
    assert extension.require_iss is False
    assert extension.require_aud is False
    assert extension.require_exp is False
    assert extension.require_jti is False
