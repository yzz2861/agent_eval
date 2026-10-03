# frozen_string_literal: false
require "test/unit"
require "uri"

class URI::TestURN < Test::Unit::TestCase
  def test_parse_components
    uri = URI.parse("URN:ISBN:978-0-13-110362-7?+r1?+r2?=q1?=q2#f1?+=f2")

    assert_instance_of(URI::URN, uri)
    assert_equal("urn", uri.scheme)
    assert_equal("ISBN", uri.nid)
    assert_equal("978-0-13-110362-7", uri.nss)
    assert_equal("r1?+r2", uri.r_component)
    assert_equal("q1?=q2", uri.q_component)
    assert_equal("r1?+r2", uri.r)
    assert_equal("q1?=q2", uri.q)
    assert_equal("f1?+=f2", uri.fragment)
    assert_nil(uri.query)
    assert_equal("ISBN:978-0-13-110362-7?+r1?+r2?=q1?=q2", uri.opaque)
    assert_equal("urn:ISBN:978-0-13-110362-7?+r1?+r2?=q1?=q2#f1?+=f2", uri.to_s)
    refute_predicate(uri, :hierarchical?)
  end

  def test_percent_encoded_separators_are_not_structural
    uri = URI.parse("urn:isbn:n%3F%2Bx%3F%3Dy%23z?+r%3F%2Br%3F%3D%23?=q%3F%2B%3D%23#f%23")

    assert_equal("n%3F%2Bx%3F%3Dy%23z", uri.nss)
    assert_equal("r%3F%2Br%3F%3D%23", uri.r_component)
    assert_equal("q%3F%2B%3D%23", uri.q_component)
    assert_equal("f%23", uri.fragment)
  end

  def test_build
    uri = URI::URN.build(["isbn", "ABC", "r?+x", "q?=y", "frag"])
    assert_equal("urn:isbn:ABC?+r?+x?=q?=y#frag", uri.to_s)

    uri = URI::URN.build(
      nid: "123",
      nss: "",
      r_component: "",
      q_component: "",
      fragment: nil
    )
    assert_equal("urn:123:?+?=", uri.to_s)
    assert_equal("", uri.nss)
    assert_equal("", uri.r_component)
    assert_equal("", uri.q_component)
  end

  def test_build2_and_component_aliases
    uri = URI::URN.build2(
      nid: "ex",
      nss: "a b#c?+x?=y:",
      r: "r r?=x",
      q_component: "q q?+x:",
      fragment: "f f#x"
    )

    assert_equal("urn:ex:a%20b%23c%3F+x%3F=y:?+r%20r%3F=x?=q%20q%3F+x:#f%20f%23x", uri.to_s)
    assert_equal(["ex", "r%20r%3F=x", "q%20q%3F+x:", "f%20f%23x"],
                 uri.select(:nid, :r, :q, :fragment))

    array_uri = URI::URN.build2(["ex", "a b#c?+x?=y:", "r r?=x", "q q?+x:", "f f#x"])
    assert_equal(uri.to_s, array_uri.to_s)
  end

  def test_modify_components
    uri = URI.parse("urn:isbn:abc?+old-r?=old-q#old-f")

    assert_equal("NID", uri.nid = "NID")
    assert_equal("new", uri.nss = "new")
    assert_equal("new-r", uri.r_component = "new-r")
    assert_equal("new-q", uri.q = "new-q")
    assert_equal("new-f", uri.fragment = "new-f")
    assert_equal("urn:NID:new?+new-r?=new-q#new-f", uri.to_s)

    uri.q_component = nil
    assert_equal("urn:NID:new?+new-r#new-f", uri.to_s)
    uri.r_component = nil
    assert_equal("urn:NID:new#new-f", uri.to_s)
    uri.fragment = nil
    assert_equal("urn:NID:new", uri.to_s)
  end

  def test_name_equivalence_and_full_equality
    name_one = URI.parse("URN:ISBN:Name%2a?+r?=q#f")
    name_two = URI.parse("urn:isbn:Name%2A")
    literal_different = URI.parse("urn:isbn:name%2a")
    full_one = URI.parse("urn:isbn:Name%2a?+r?=q#f")
    full_two = URI.parse("urn:isbn:Name%2A?+r?=q#f")

    assert_operator(name_one, :==, name_two)
    assert_equal(name_one.hash, name_two.hash)
    refute_operator(name_one, :eql?, name_two)
    refute_operator(name_one, :==, literal_different)
    assert_operator(full_one, :eql?, full_one.dup)
    refute_operator(full_one, :eql?, full_two)
  end

  def test_normalize_preserves_nss_letters
    uri = URI.parse("URN:ISBN:Name%2a?+r?=q#f").normalize

    assert_equal("urn:isbn:Name%2A?+r?=q#f", uri.to_s)
  end

  def test_invalid_components
    assert_raise(URI::InvalidComponentError) { URI.parse("urn:urn:nss") }
    assert_raise(URI::InvalidComponentError) { URI.parse("urn:urn-x:nss") }
    assert_raise(URI::InvalidComponentError) { URI.parse("urn:x:nss") }
    assert_raise(URI::InvalidComponentError) { URI.parse("urn:x-:nss") }
    assert_raise(URI::InvalidComponentError) { URI.parse("urn:ex:nss%XX") }
    assert_raise(URI::InvalidComponentError) { URI.parse("urn:ex:nss?=q?+r") }
    assert_raise(URI::InvalidComponentError) { URI.parse("urn:ex:nss?+r?=q?+x") }

    uri = URI.parse("urn:ex:nss")
    assert_raise(URI::InvalidComponentError) { uri.nid = "urn" }
    assert_raise(URI::InvalidComponentError) { uri.nss = "bad%xx" }
    assert_raise(URI::InvalidComponentError) { uri.r_component = "bad?=q" }
    assert_raise(URI::InvalidComponentError) { uri.q_component = "bad?+q" }
    assert_raise(URI::InvalidComponentError) { uri.fragment = "bad#f" }
    assert_raise(URI::InvalidComponentError) { uri.scheme = "http" }
    assert_raise(URI::InvalidURIError) { uri.query = "q" }
    assert_raise(URI::InvalidURIError) { uri.host = "example.com" }
    assert_raise(URI::InvalidURIError) { uri.path = "/path" }
  end

  def test_rfc2396_parser
    uri = URI::RFC2396_PARSER.parse("URN:ISBN:n%3F%2B?+r?=q#f")

    assert_instance_of(URI::URN, uri)
    assert_equal("n%3F%2B", uri.nss)
    assert_equal("r", uri.r_component)
    assert_equal("q", uri.q_component)
  end

  def test_unknown_scheme_remains_generic
    uri = URI.parse("foo:bar?=baz#frag")

    assert_instance_of(URI::Generic, uri)
    assert_equal("bar?=baz", uri.opaque)
    assert_nil(uri.query)
  end
end
