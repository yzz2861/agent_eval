import pytest

import yaml

PLACEHOLDER = yaml.safeexport.DEFAULT_PLACEHOLDER


class CustomValue:
    pass


def collect_strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from collect_strings(key)
            yield from collect_strings(value)
    elif isinstance(node, (list, tuple, set)):
        for item in node:
            yield from collect_strings(item)


def test_external_redacts_marked_value_under_every_name():
    password = "s3cret-password"
    data = {
        "service": "billing",
        "credentials": yaml.Sensitive({"user": "svc", "password": password}),
        # The same object is referenced under another, unwrapped name.
        "debug": {"echo_password": password},
    }

    result = yaml.safe_export(data)

    external = yaml.safe_load(result.external)
    assert external["credentials"] == PLACEHOLDER
    assert external["debug"]["echo_password"] == PLACEHOLDER
    assert "s3cret-password" not in result.external
    assert "s3cret-password" not in set(collect_strings(external))

    internal = yaml.safe_load(result.internal)
    assert internal["credentials"] == {"user": "svc", "password": password}
    assert internal["debug"]["echo_password"] == password


def test_external_cuts_aliases_that_would_expose_marked_values():
    shared = {"token": yaml.Sensitive("tok-123"), "note": "shared"}
    plain = {"region": "cn"}
    data = {"first": shared, "second": shared, "p1": plain, "p2": plain}

    result = yaml.safe_export(data)

    external = yaml.safe_load(result.external)
    assert external["first"] == {"token": PLACEHOLDER, "note": "shared"}
    assert external["second"] == {"token": PLACEHOLDER, "note": "shared"}
    # The reference between the tainted nodes is cut...
    assert external["first"] is not external["second"]
    assert "tok-123" not in result.external
    # ...while ordinary sharing is preserved on both documents.
    assert external["p1"] is external["p2"]
    internal = yaml.safe_load(result.internal)
    assert internal["first"] is internal["second"]
    assert internal["p1"] is internal["p2"]
    assert internal["first"]["token"] == "tok-123"


def test_merge_mapping_shared_values_are_redacted():
    data = yaml.safe_load("""
defaults: &defaults
  user: admin
  password: s3cret
prod:
  <<: *defaults
  replicas: 3
staging:
  <<: *defaults
  replicas: 1
""")

    result = yaml.safe_export(data, sensitive=[data["defaults"]["password"]])

    external = yaml.safe_load(result.external)
    assert external["defaults"]["password"] == PLACEHOLDER
    assert external["prod"]["password"] == PLACEHOLDER
    assert external["staging"]["password"] == PLACEHOLDER
    assert external["prod"]["replicas"] == 3
    assert "s3cret" not in result.external

    internal = yaml.safe_load(result.internal)
    assert internal["prod"]["password"] == "s3cret"
    assert internal["staging"]["user"] == "admin"


def test_recursive_structure_survives_both_documents():
    node = {"name": "root", "secret": yaml.Sensitive("shh")}
    node["self"] = node
    data = {"tree": node}

    result = yaml.safe_export(data)

    external = yaml.safe_load(result.external)
    assert external["tree"]["self"] is external["tree"]
    assert external["tree"]["secret"] == PLACEHOLDER
    assert "shh" not in result.external

    internal = yaml.safe_load(result.internal)
    assert internal["tree"]["self"] is internal["tree"]
    assert internal["tree"]["secret"] == "shh"


def test_unserializable_values_are_substituted_and_reported():
    data = {"handler": CustomValue(), "count": 1}

    result = yaml.safe_export(data)

    assert any("CustomValue" in warning for warning in result.warnings)
    for document in (result.internal, result.external):
        loaded = yaml.safe_load(document)
        assert loaded["handler"] == "<unserializable: CustomValue>"
        assert loaded["count"] == 1


def test_caller_marked_container_is_redacted_wherever_referenced():
    token_store = {"api_token": "tok-abc"}
    data = {"primary": token_store, "replica": token_store}

    result = yaml.safe_export(data, sensitive=[token_store])

    external = yaml.safe_load(result.external)
    assert external["primary"] == PLACEHOLDER
    assert external["replica"] == PLACEHOLDER
    assert "tok-abc" not in result.external

    internal = yaml.safe_load(result.internal)
    assert internal["primary"] == {"api_token": "tok-abc"}
    assert internal["primary"] is internal["replica"]


def test_result_exposes_documents_and_review_information():
    result = yaml.safe_export({"key": yaml.Sensitive("value")})

    internal, external = result
    assert yaml.safe_load(internal) == {"key": "value"}
    assert yaml.safe_load(external) == {"key": PLACEHOLDER}
    assert result.redacted == 1
    assert result.warnings == []
