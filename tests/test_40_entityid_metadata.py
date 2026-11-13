"""Tests for normalized entityID indexing, conflict policy and metadata cache."""

import os

from pytest import raises
from xml.sax.saxutils import escape

from saml2.attribute_converter import ac_factory
from saml2.entityid import ENTITY_CACHE_VERSION
from saml2.entityid import DuplicateCertificate
from saml2.entityid import EntityConflict
from saml2.entityid import EntityDescriptorTooLarge
from saml2.entityid import MissingEntityID
from saml2.entityid import entity_id_cache_key
from saml2.entityid import entity_ids_equal
from saml2.entityid import normalize_entity_id
from saml2.metadata_cache import FileMetadataCache
from saml2.mdstore import InMemoryMetaData
from saml2.mdstore import MetaDataFile
from saml2.mdstore import MetaDataMDX
from saml2.mdstore import MetadataStore

from pathutils import full_path


ATTRCONV = ac_factory(full_path("attributemaps"))

CERT_A = "AAAACERTAAAACERTAAAACERTAAAACERTAAAACERTAAAACERTAAAACERT"
CERT_B = "BBBBCERTBBBBCERTBBBBCERTBBBBCERTBBBBCERTBBBBCERTBBBB"


def entity_xml(entity_id, cert=CERT_A, valid_until=None, organization="Example Org"):
    valid_until_attr = f' validUntil="{valid_until}"' if valid_until else ""
    return f"""<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  entityID="{escape(entity_id)}"{valid_until_attr}>
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
  <Organization>
    <OrganizationName xml:lang="en">{organization}</OrganizationName>
    <OrganizationDisplayName xml:lang="en">{organization}</OrganizationDisplayName>
    <OrganizationURL xml:lang="en">https://idp.example.com/</OrganizationURL>
  </Organization>
</EntityDescriptor>"""


def entity_xml_with_certs(entity_id, certs, **kwargs):
    key_descriptors = "".join(
        "<KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data>"
        f"<ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>"
        for cert in certs
    )
    valid_until = kwargs.get("valid_until")
    valid_until_attr = f' validUntil="{valid_until}"' if valid_until else ""
    return f"""<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  entityID="{escape(entity_id)}"{valid_until_attr}>
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    {key_descriptors}
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""


def entities_xml(*entity_descriptors):
    body = "".join(entity_descriptors)
    return (
        '<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">'
        + body
        + "</EntitiesDescriptor>"
    )


def make_store(xml_string, **kwargs):
    store = InMemoryMetaData(ATTRCONV, **kwargs)
    store.parse(xml_string)
    return store


def test_normalize_scheme_host_case_and_default_port():
    variants = [
        "HTTPS://IDP.Example.com:443/path",
        "https://idp.example.com/path",
        "https://idp.example.com:443/path",
    ]
    normalized = {normalize_entity_id(value) for value in variants}
    assert normalized == {"https://idp.example.com/path"}


def test_normalize_ipv6_and_userinfo():
    assert (
        normalize_entity_id("https://[2001:db8::1]:443/path") == "https://[2001:db8::1]/path"
    )
    assert (
        normalize_entity_id("http://user:pass@Example.COM:80/a")
        == "http://user:pass@example.com/a"
    )


def test_normalize_preserves_trailing_slash_distinction():
    with_slash = "https://idp.example.com/entity/"
    without_slash = "https://idp.example.com/entity"
    assert normalize_entity_id(with_slash) != normalize_entity_id(without_slash)
    assert normalize_entity_id("https://idp.example.com/") == "https://idp.example.com/"
    assert normalize_entity_id("http://idp.example.com:80/") == "http://idp.example.com/"


def test_normalize_percent_encoding():
    assert entity_ids_equal(
        "https://idp.example.com/%7euser/a%2fb",
        "https://idp.example.com/%7Euser/a%2Fb",
    )
    # Reserved characters keep their encoding and are not confused with literals.
    assert not entity_ids_equal(
        "https://idp.example.com/a%2Fb",
        "https://idp.example.com/a/b",
    )


def test_query_parameter_order_is_insignificant():
    assert entity_ids_equal(
        "https://idp.example.com/md?a=1&b=2",
        "https://idp.example.com/md?b=2&a=1",
    )


def test_non_url_identifiers_are_left_untouched():
    urn = "urn:mace:incommon:example.org"
    assert normalize_entity_id(urn) == urn
    assert normalize_entity_id("urn:mace:example?a=1&b=2") == "urn:mace:example?a=1&b=2"


def test_blank_identifier_is_rejected():
    for invalid in ("", "   ", None):
        with raises(MissingEntityID):
            normalize_entity_id(invalid)


def test_missing_entity_id_is_independent_outcome():
    xml = entities_xml(
        entity_xml("https://idp.example.com/good").replace(
            'entityID="https://idp.example.com/good"', ""
        )
    )
    store = make_store(xml)
    assert len(store) == 0
    assert store.missing_entity_id == [None]
    assert store.errors()["missing_entity_id"] == [None]


def test_expired_descriptor_is_independent_outcome():
    xml = entity_xml("https://idp.example.com/expired", valid_until="2000-01-01T00:00:00Z")
    store = make_store(xml)
    assert len(store) == 0
    assert store.expired == ["https://idp.example.com/expired"]
    assert store.to_old == ["https://idp.example.com/expired"]


def test_oversized_descriptor_is_independent_outcome():
    store = InMemoryMetaData(ATTRCONV, entity_descriptor_max_size=100)
    store.parse(entity_xml("https://idp.example.com/big"))
    assert store.oversized == ["https://idp.example.com/big"]
    assert len(store) == 0
    with raises(EntityDescriptorTooLarge):
        store.do_entity_descriptor(store.entity_descr)


def test_duplicate_certificate_is_independent_outcome():
    store = make_store(entity_xml_with_certs("https://idp.example.com/dup-cert", [CERT_A, CERT_B]))
    assert store.duplicate_certificates == []

    store = make_store(entity_xml_with_certs("https://idp.example.com/dup-cert", [CERT_A, CERT_A]))
    assert store.duplicate_certificates == ["https://idp.example.com/dup-cert"]
    assert store.errors()["duplicate_certificates"] == ["https://idp.example.com/dup-cert"]
    # A duplicate certificate is an independent, non-fatal result: the
    # descriptor is still indexed and remains queryable.
    assert len(store) == 1
    assert (
        store["https://idp.example.com/dup-cert"]["entity_id"] == "https://idp.example.com/dup-cert"
    )
    fresh = InMemoryMetaData(ATTRCONV)
    error = fresh._check_duplicate_certificates(
        "https://idp.example.com/dup-cert", store.entity_descr
    )
    assert isinstance(error, DuplicateCertificate)


def test_normalized_variants_share_one_index_entry():
    xml = entities_xml(
        entity_xml("HTTPS://IDP.Example.com:443/idp?b=2&a=1"),
        entity_xml("https://idp.example.com/idp?b=2&a=1"),
    )
    store = make_store(xml)
    assert len(store) == 1
    assert "HTTPS://IDP.Example.com:443/idp?b=2&a=1" in store
    assert (
        store["https://idp.example.com/idp?a=1&b=2"]["entity_id"]
        == "HTTPS://IDP.Example.com:443/idp?b=2&a=1"
    )
    assert list(store.keys()) == ["https://idp.example.com/idp?a=1&b=2"]


def test_certificate_conflict_rejected_in_strict_mode():
    first = entity_xml("HTTPS://IDP.Example.com:443/tenant", cert=CERT_A)
    second = entity_xml("https://idp.example.com/tenant", cert=CERT_B)

    permissive = make_store(entities_xml(first, second))
    assert permissive.conflicts == ["https://idp.example.com/tenant"]
    assert permissive.certs("https://idp.example.com/tenant", "idpsso")[0][1].strip() == CERT_A

    with raises(EntityConflict):
        make_store(entities_xml(first, second), strict_conflicts=True)


def test_identical_descriptors_with_variant_ids_do_not_override():
    first = entity_xml("HTTPS://IDP.Example.com:443/tenant")
    second = entity_xml("https://idp.example.com/tenant")
    store = make_store(entities_xml(first, second))
    assert len(store) == 1
    assert store.conflicts == []
    assert store["https://idp.example.com/tenant"]["entity_id"] == "HTTPS://IDP.Example.com:443/tenant"


def test_trailing_slash_variants_remain_distinct_entities():
    xml = entities_xml(
        entity_xml("https://idp.example.com/tenant/"),
        entity_xml("https://idp.example.com/tenant"),
    )
    store = make_store(xml)
    assert len(store) == 2
    assert "https://idp.example.com/tenant/" in store
    assert "https://idp.example.com/tenant" in store


def test_metadata_store_query_uses_normalized_entity_id():
    mds = MetadataStore(ATTRCONV, None)
    mds.load("inline", entities_xml(entity_xml("HTTPS://IDP.Example.com:443/idp?z=9&a=1")))
    assert "https://idp.example.com/idp?a=1&z=9" in mds
    assert "https://idp.example.com/unknown" not in mds
    services = mds.single_sign_on_service(
        "https://idp.example.com/idp?a=1&z=9",
    )
    assert services[0]["location"] == "https://idp.example.com/sso"


def test_file_cache_uses_normalized_hash_and_invalidates_legacy(tmp_path):
    cache_dir = tmp_path / "md-cache"
    legacy_file = cache_dir / "https:__idp.example.com_metadata.json"
    cache_dir.mkdir()
    legacy_file.write_text("{}")

    cache = FileMetadataCache(str(cache_dir))
    assert not legacy_file.exists()

    entity = {"entity_id": "https://idp.example.com/idp"}
    cache.set("HTTPS://IDP.Example.com:443/idp?b=2&a=1", entity)

    expected_name = entity_id_cache_key("https://idp.example.com/idp?a=1&b=2") + ".json"
    assert set(os.listdir(str(cache_dir))) == {expected_name}
    assert expected_name.startswith(ENTITY_CACHE_VERSION + "-")
    assert cache.get("https://idp.example.com/idp?a=1&b=2") == entity


def test_file_cache_never_builds_paths_from_raw_entity_id(tmp_path):
    cache = FileMetadataCache(str(tmp_path / "cache"))
    malicious = "https://idp.example.com/../../etc/passwd"
    cache.set(malicious, {"ok": True})
    entries = os.listdir(str(tmp_path / "cache"))
    assert entries == [entity_id_cache_key(malicious) + ".json"]
    assert "/" not in entries[0]
    assert cache.get(malicious) == {"ok": True}


def test_file_cache_collisions_resolve_to_one_entry(tmp_path):
    cache = FileMetadataCache(str(tmp_path / "cache"))
    cache.set("HTTPS://IDP.Example.com:443/idp?b=2&a=1", {"v": 1})
    cache.set("https://idp.example.com/idp?a=1&b=2", {"v": 2})
    assert len(cache) == 1
    assert cache.get("https://idp.example.com/idp?a=1&b=2") == {"v": 2}


def test_file_metadata_source_supports_normalized_lookup(tmp_path):
    path = tmp_path / "idp.xml"
    path.write_text(entity_xml("HTTPS://IDP.Example.com:443/idp"))
    source = MetaDataFile(ATTRCONV, str(path))
    source.load()
    assert source["https://idp.example.com/idp"]["entity_id"] == "HTTPS://IDP.Example.com:443/idp"


def test_cross_source_certificate_conflict_is_rejected_in_strict_mode(tmp_path):
    first_path = tmp_path / "tenant-a.xml"
    second_path = tmp_path / "tenant-b.xml"
    first_path.write_text(entity_xml("HTTPS://IDP.Example.com:443/tenant", cert=CERT_A))
    second_path.write_text(entity_xml("https://idp.example.com/tenant", cert=CERT_B))

    mds = MetadataStore(ATTRCONV, None, strict_conflicts=True)
    mds.load("local", str(first_path))
    with raises(EntityConflict):
        mds.load("local", str(second_path))

    # The first tenant's certificate remains authoritative; nothing overrode it.
    cert = mds.certs("https://idp.example.com/tenant", "idpsso")[0][1].strip()
    assert cert == CERT_A


def test_cross_source_identical_content_does_not_override(tmp_path):
    first_path = tmp_path / "a.xml"
    second_path = tmp_path / "b.xml"
    first_path.write_text(entity_xml("HTTPS://IDP.Example.com:443/tenant"))
    second_path.write_text(entity_xml("https://idp.example.com/tenant"))

    mds = MetadataStore(ATTRCONV, None, strict_conflicts=True)
    mds.load("local", str(first_path))
    mds.load("local", str(second_path))
    assert mds.conflicts == []
    assert mds["https://idp.example.com/tenant"]["entity_id"] == "HTTPS://IDP.Example.com:443/tenant"


def test_inline_load_honors_strict_conflicts():
    mds = MetadataStore(ATTRCONV, None, strict_conflicts=True)
    aggregate = entities_xml(
        entity_xml("HTTPS://IDP.Example.com:443/tenant", cert=CERT_A),
        entity_xml("https://idp.example.com/tenant", cert=CERT_B),
    )
    with raises(EntityConflict):
        mds.load("inline", aggregate)


def test_mdx_fetches_are_indexed_by_normalized_entity_id():
    mdx = MetaDataMDX("http://mdq.example.com")
    normalized = normalize_entity_id("HTTPS://IDP.Example.com:443/idp?b=2&a=1")
    mdx.entity[normalized] = {"idpsso_descriptor": []}
    mdx.expiration_date[normalized] = "2099-01-01T00:00:00Z"
    assert "https://idp.example.com/idp?a=1&b=2" in mdx
    assert mdx["https://idp.example.com/idp?a=1&b=2"] == {"idpsso_descriptor": []}
