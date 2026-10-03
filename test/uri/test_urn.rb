# frozen_string_literal: false
require 'test/unit'
require 'uri'

class URI::TestURN < Test::Unit::TestCase
  def setup
    @u = URI::URN
  end

  def teardown
  end

  def uri_to_ary(uri)
    uri.class.component.collect {|c| uri.send(c)}
  end

  def test_build
    ok = []
    bad = []

    # urn:example:foo
    ok << ["urn:example:foo"]
    ok[-1] << ["example", "foo", nil, nil, nil]
    ok[-1] << {:nid => "example", :nss => "foo"}

    # urn:example:foo?+rcomponent
    ok << ["urn:example:foo?+rcomponent"]
    ok[-1] << ["example", "foo", "rcomponent", nil, nil]
    ok[-1] << {:nid => "example", :nss => "foo", :r_component => "rcomponent"}

    # urn:example:foo?=qcomponent
    ok << ["urn:example:foo?=qcomponent"]
    ok[-1] << ["example", "foo", nil, "qcomponent", nil]
    ok[-1] << {:nid => "example", :nss => "foo", :q_component => "qcomponent"}

    # urn:example:foo?+rr?=qq#frag
    ok << ["urn:example:foo?+rr?=qq#frag"]
    ok[-1] << ["example", "foo", "rr", "qq", "frag"]
    ok[-1] << {:nid => "example", :nss => "foo",
      :r_component => "rr", :q_component => "qq", :fragment => "frag"}

    # pct-encoded characters in nss
    ok << ["urn:example:a%20b%3Fc"]
    ok[-1] << ["example", "a%20b%3Fc", nil, nil, nil]
    ok[-1] << {:nid => "example", :nss => "a%20b%3Fc"}

    ok.each do |x|
      assert_equal(x[0], @u.build(x[1]).to_s)
      assert_equal(x[0], @u.build(x[2]).to_s)
    end

    # nid must be present
    bad << [nil, "foo", nil, nil, nil]
    # nss must be present
    bad << ["example", nil, nil, nil, nil]
    # nid must be at least 2 characters
    bad << ["x", "foo", nil, nil, nil]
    # nid must be at most 32 characters
    bad << ["a" * 33, "foo", nil, nil, nil]
    # nid allows only alphanum and "-"
    bad << ["ex_ample", "foo", nil, nil, nil]
    bad << ["-example", "foo", nil, nil, nil]
    # "urn" is reserved as nid
    bad << ["urn", "foo", nil, nil, nil]
    # nss must not contain a literal "?"
    bad << ["example", "fo?o", nil, nil, nil]
    # r-component and q-component must not be empty
    bad << ["example", "foo", "", nil, nil]
    bad << ["example", "foo", nil, "", nil]

    bad.each do |x|
      assert_raise(URI::InvalidComponentError) { @u.build(x) }
    end
  end

  def test_parse
    u = URI.parse("urn:example:foo")
    assert_kind_of(URI::URN, u)
    assert_equal("urn", u.scheme)
    assert_equal("example", u.nid)
    assert_equal("foo", u.nss)
    assert_nil(u.r_component)
    assert_nil(u.q_component)
    assert_nil(u.fragment)
    assert_equal("urn:example:foo", u.to_s)

    u = URI.parse("urn:example:foo?+rr?=qq#frag")
    assert_equal("example", u.nid)
    assert_equal("foo", u.nss)
    assert_equal("rr", u.r_component)
    assert_equal("qq", u.q_component)
    assert_equal("frag", u.fragment)
    assert_equal("urn:example:foo?+rr?=qq#frag", u.to_s)

    # "?+" and "?=" are allowed inside the r-component and q-component
    u = URI.parse("urn:example:foo?+a?+b?=c?=d")
    assert_equal("a?+b", u.r_component)
    assert_equal("c?=d", u.q_component)
    assert_equal("urn:example:foo?+a?+b?=c?=d", u.to_s)

    # the q-component may contain "?+"
    u = URI.parse("urn:example:foo?=q?+r")
    assert_nil(u.r_component)
    assert_equal("q?+r", u.q_component)
  end

  def test_parse_pct_encoded_delimiters
    # a pct-encoded "?" is data, not a delimiter
    u = URI.parse("urn:example:a%3Fb")
    assert_equal("a%3Fb", u.nss)
    assert_nil(u.r_component)
    assert_nil(u.q_component)
    assert_equal("urn:example:a%3Fb", u.to_s)

    # a pct-encoded "?+" does not start an r-component
    u = URI.parse("urn:example:a%3F%2Bb")
    assert_equal("a%3F%2Bb", u.nss)
    assert_nil(u.r_component)

    # a pct-encoded "=" does not start a q-component
    u = URI.parse("urn:example:foo?+r%3Dq")
    assert_equal("r%3Dq", u.r_component)
    assert_nil(u.q_component)

    # a pct-encoded ":" in nss is not a nid separator
    u = URI.parse("urn:example:a%3Ab")
    assert_equal("example", u.nid)
    assert_equal("a%3Ab", u.nss)
  end

  def test_parse_invalid
    [
      "urn:example",        # missing nss
      "urn:example:",       # empty nss
      "urn:x:foo",          # nid too short
      "urn:#{"a" * 33}:foo", # nid too long
      "urn:urn:foo",        # reserved nid
      "urn:ex_ample:foo",   # invalid nid character
      "urn:example:fo?o",   # literal "?" in nss
      "urn:example:foo?+",  # empty r-component
      "urn:example:foo?=",  # empty q-component
    ].each do |s|
      assert_raise(URI::InvalidComponentError, s) { URI.parse(s) }
    end

    # invalid percent escape is rejected by the parser
    assert_raise(URI::InvalidURIError) { URI.parse("urn:example:fo%2o") }
  end

  def test_name_equivalence
    # nid is case-insensitive
    assert_equal(URI.parse("urn:example:foo"), URI.parse("urn:EXAMPLE:foo"))
    assert(URI.parse("urn:example:foo").name_equivalent?(URI.parse("urn:EXAMPLE:foo")))

    # nss is case-sensitive
    assert_not_equal(URI.parse("urn:example:foo"), URI.parse("urn:example:FOO"))

    # case of pct-encoded triplets is insignificant
    assert_equal(URI.parse("urn:example:a%3fb"), URI.parse("urn:example:a%3Fb"))

    # r-component, q-component, and fragment are not taken into account
    assert_equal(URI.parse("urn:example:foo"),
                 URI.parse("urn:example:foo?+rr?=qq#frag"))

    # different nss is not equivalent
    assert_not_equal(URI.parse("urn:example:foo"), URI.parse("urn:example:bar"))
    # pct-encoded and literal characters are not equivalent
    assert_not_equal(URI.parse("urn:example:a%41b"), URI.parse("urn:example:aAb"))
  end

  def test_full_string_equality
    # eql? compares all components without normalization
    a = URI.parse("urn:example:foo?+rr")
    b = URI.parse("urn:example:foo")
    assert(a == b)
    assert_not_operator(a, :eql?, b)
    assert_not_equal(a.to_s, b.to_s)

    c = URI.parse("urn:EXAMPLE:foo")
    d = URI.parse("urn:example:foo")
    assert(c == d)
    assert_not_operator(c, :eql?, d)

    e = URI.parse("urn:example:foo")
    f = URI.parse("urn:example:foo")
    assert_operator(e, :eql?, f)
    assert_equal(e.hash, f.hash)
  end

  def test_setter
    u = URI.parse("urn:example:foo")

    u.nid = "other"
    assert_equal("other", u.nid)
    assert_equal("urn:other:foo", u.to_s)

    u.nss = "Bar%20baz"
    assert_equal("Bar%20baz", u.nss)
    assert_equal("urn:other:Bar%20baz", u.to_s)

    u.r_component = "rr"
    u.q_component = "qq"
    u.fragment = "frag"
    assert_equal("urn:other:Bar%20baz?+rr?=qq#frag", u.to_s)

    u.r_component = nil
    u.q_component = nil
    assert_equal("urn:other:Bar%20baz#frag", u.to_s)

    assert_raise(URI::InvalidComponentError) { u.nid = "urn" }
    assert_raise(URI::InvalidComponentError) { u.nid = "x" }
    assert_raise(URI::InvalidComponentError) { u.nss = "fo?o" }
    assert_raise(URI::InvalidComponentError) { u.nss = "" }
    assert_raise(URI::InvalidComponentError) { u.r_component = "" }
    assert_raise(URI::InvalidComponentError) { u.q_component = "a b" }
  end

  def test_normalize
    u = URI.parse("urn:EXAMPLE:a%3fb?+rr#frag")
    u.normalize!
    assert_equal("urn:example:a%3Fb?+rr#frag", u.to_s)
    # nss case is preserved
    u = URI.parse("urn:example:Foo")
    u.normalize!
    assert_equal("urn:example:Foo", u.to_s)
  end

  def test_select
    u = URI.parse("urn:example:foo?+rr?=qq#frag")
    assert_equal(["example", "foo", "rr", "qq", "frag"],
                 u.select(:nid, :nss, :r_component, :q_component, :fragment))
  end

  def test_unknown_scheme_still_generic
    assert_kind_of(URI::Generic, URI.parse("foo:bar"))
    assert_not_kind_of(URI::URN, URI.parse("foo:bar"))
    assert_equal(URI::URN, URI.scheme_list["URN"])
  end
end
