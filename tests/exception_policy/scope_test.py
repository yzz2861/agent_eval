import pytest

from detect_secrets.exception_policy import Scope


def test_containment_hierarchy():
    root = Scope.from_string("acme")
    payments = Scope.from_string("acme", "payments")
    nested = Scope.from_string("acme", "payments/v1/keys")

    assert root.contains(payments)
    assert payments.contains(nested)
    assert root.contains(nested)


def test_widening_fails_closed():
    approved = Scope.from_string("acme", "payments")
    wider = Scope.from_string("acme")
    assert approved.contains(wider) is False


def test_different_project_never_matches():
    assert Scope.from_string("acme").contains(Scope.from_string("other")) is False


def test_file_path_is_contained_by_its_directory():
    approved = Scope.from_string("acme", "config")
    finding = Scope.from_string("acme", "config/app.yaml")
    assert approved.contains(finding)


def test_rejects_escaping_and_absolute_paths():
    with pytest.raises(ValueError):
        Scope.from_string("acme", "../escape")
    with pytest.raises(ValueError):
        Scope.from_string("acme", "/etc/passwd")


def test_serialization_round_trip():
    scope = Scope.from_string("acme", "a/b")
    assert Scope.from_dict(scope.to_dict()) == scope
