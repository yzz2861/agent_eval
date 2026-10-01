import pytest

from authlib.oauth2.rfc6749.errors import InvalidRequestError
from authlib.oauth2.rfc9396 import AuthorizationDetailsRegistry
from authlib.oauth2.rfc9396 import AuthorizationServerMetadata
from authlib.oauth2.rfc9396 import InvalidAuthorizationDetailsError
from authlib.oauth2.rfc9396 import dumps_authorization_details


class Payload:
    def __init__(self, data):
        self.data = data


class Request:
    def __init__(self, data):
        self.payload = Payload(data)


def make_registry(**kwargs):
    registry = AuthorizationDetailsRegistry(**kwargs)
    registry.register("payment")
    return registry


def test_error_attributes():
    error = InvalidAuthorizationDetailsError()
    assert error.error == "invalid_authorization_details"
    assert error.status_code == 400


def test_validate_request_absent():
    registry = make_registry()
    assert registry.validate_request(Request({})) is None


def test_validate_request_not_string():
    registry = make_registry()
    with pytest.raises(InvalidRequestError):
        registry.validate_request(Request({"authorization_details": []}))


def test_validate_request_malformed_json():
    registry = make_registry()
    with pytest.raises(InvalidRequestError):
        registry.validate_request(Request({"authorization_details": "[{"}))


def test_validate_request_too_long():
    registry = make_registry(max_data_length=10)
    raw = '[{"type": "payment"}]'
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_request(Request({"authorization_details": raw}))


def test_validate_request_ok():
    registry = make_registry()
    raw = '[{"type": "payment", "amount": 10}]'
    details = registry.validate_request(Request({"authorization_details": raw}))
    assert details == [{"type": "payment", "amount": 10}]


def test_structure_not_a_list():
    registry = make_registry()
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_details_structure({"type": "payment"})


def test_structure_element_not_object():
    registry = make_registry()
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_details_structure(["payment"])


def test_structure_missing_type():
    registry = make_registry()
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_details_structure([{"amount": 1}])
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_details_structure([{"type": ""}])
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_details_structure([{"type": 1}])


def test_structure_too_many_objects():
    registry = make_registry(max_details_count=1)
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_details_structure([{"type": "payment"}, {"type": "payment"}])


def test_structure_too_deep():
    registry = make_registry(max_data_depth=2)
    details = [{"type": "payment", "a": {"b": {"c": 1}}}]
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_details_structure(details)


def test_unknown_type():
    registry = make_registry()
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_details([{"type": "unknown"}])


def test_type_validate_callable():
    seen = []

    def validate(detail, request):
        seen.append(detail)
        if detail.get("amount", 0) <= 0:
            raise InvalidAuthorizationDetailsError()

    registry = AuthorizationDetailsRegistry()
    registry.register("payment", validate=validate)
    registry.validate_details([{"type": "payment", "amount": 1}])
    assert seen == [{"type": "payment", "amount": 1}]
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_details([{"type": "payment", "amount": 0}])


def test_type_validate_falsy_return():
    registry = AuthorizationDetailsRegistry()
    registry.register("payment", validate=lambda detail, request: False)
    with pytest.raises(InvalidAuthorizationDetailsError):
        registry.validate_details([{"type": "payment"}])


def test_register_invalid_type():
    registry = AuthorizationDetailsRegistry()
    with pytest.raises(ValueError):
        registry.register("")


def test_is_subsumed_default_exact_match():
    registry = make_registry()
    approved = [{"type": "payment", "amount": 10}]
    assert registry.is_subsumed([{"type": "payment", "amount": 10}], approved)
    assert not registry.is_subsumed([{"type": "payment", "amount": 5}], approved)
    assert not registry.is_subsumed([{"type": "payment", "amount": 10}], None)
    assert not registry.is_subsumed([{"type": "unknown"}], approved)


def test_is_subsumed_custom_callable():
    registry = AuthorizationDetailsRegistry()
    registry.register(
        "payment",
        is_subsumed=lambda req, app: req.get("amount", 0) <= app.get("amount", 0),
    )
    approved = [{"type": "payment", "amount": 10}]
    assert registry.is_subsumed([{"type": "payment", "amount": 5}], approved)
    assert not registry.is_subsumed([{"type": "payment", "amount": 15}], approved)


def test_is_subsumed_matches_across_objects():
    registry = AuthorizationDetailsRegistry()
    registry.register(
        "payment",
        is_subsumed=lambda req, app: req.get("amount", 0) <= app.get("amount", 0),
    )
    approved = [
        {"type": "payment", "amount": 10, "currency": "USD"},
        {"type": "payment", "amount": 100, "currency": "EUR"},
    ]
    requested = [{"type": "payment", "amount": 50, "currency": "USD"}]
    # the framework does not guess containment across business objects:
    # the registered callable decides per candidate of the same type
    assert registry.is_subsumed(requested, approved)
    registry.register(
        "payment",
        is_subsumed=lambda req, app: (
            req.get("currency") == app.get("currency")
            and req.get("amount", 0) <= app.get("amount", 0)
        ),
    )
    assert not registry.is_subsumed(requested, approved)


def test_dumps_authorization_details():
    assert dumps_authorization_details(None) is None
    assert dumps_authorization_details("raw") == "raw"
    assert dumps_authorization_details([{"type": "a"}]) == '[{"type":"a"}]'


def test_metadata():
    metadata = AuthorizationServerMetadata(
        {"authorization_details_types_supported": ["payment"]}
    )
    metadata.validate_authorization_details_types_supported()
    assert metadata.authorization_details_types_supported == ["payment"]

    metadata = AuthorizationServerMetadata(
        {"authorization_details_types_supported": "payment"}
    )
    with pytest.raises(ValueError):
        metadata.validate_authorization_details_types_supported()

    metadata = AuthorizationServerMetadata(
        {"authorization_details_types_supported": [1]}
    )
    with pytest.raises(ValueError):
        metadata.validate_authorization_details_types_supported()

    metadata = AuthorizationServerMetadata({})
    assert metadata.authorization_details_types_supported is None
