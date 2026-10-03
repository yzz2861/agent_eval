# frozen_string_literal: false
require 'test/unit'
require 'uri'

class URI::TestIRI < Test::Unit::TestCase
  def test_parse_iri_retains_unicode_components
    iri = URI.parse_iri('https://中文.test/路径?q=值#片段')

    assert_kind_of(URI::HTTPS, iri)
    assert_equal('中文.test', iri.host)
    assert_equal('/路径', iri.path)
    assert_equal('q=值', iri.query)
    assert_equal('片段', iri.fragment)
    assert_equal('https://中文.test/路径?q=值#片段', iri.to_s)
  end

  def test_to_uri_encodes_components_and_uses_injected_host_converter
    iri = URI.parse_iri('https://中文.test/路径/保留%2F字符?q=a%3D1&r=值#片段')
    calls = []
    converted = iri.to_uri(lambda do |host|
      calls << host
      'xn--fiq228c.test'
    end)

    assert_equal(['中文.test'], calls)
    assert_equal(
      'https://xn--fiq228c.test/%E8%B7%AF%E5%BE%84/%E4%BF%9D%E7%95%99%2F%E5%AD%97%E7%AC%A6?q=a%3D1&r=%E5%80%BC#%E7%89%87%E6%AE%B5',
      converted.to_s
    )
    assert_predicate(converted.to_s, :ascii_only?)
    assert_equal(URI::RFC3986_PARSER, converted.parser)
    assert_equal('https://中文.test/路径/保留%2F字符?q=a%3D1&r=值#片段', iri.to_s)
  end

  def test_existing_percent_escapes_are_preserved_without_case_normalization
    iri = URI.parse_iri('https://example.test/%c3%bc/%2f?q=%c3%bc%26#%c3%bc%3f')
    uri = iri.to_uri(lambda { |host| host })

    assert_equal('/%c3%bc/%2f', uri.path)
    assert_equal('q=%c3%bc%26', uri.query)
    assert_equal('%c3%bc%3f', uri.fragment)
  end

  def test_encode_iri_accepts_block_host_converter
    uri = URI.encode_iri('https://中文.test/路径') { |host| 'xn--fiq228c.test' }

    assert_equal('https://xn--fiq228c.test/%E8%B7%AF%E5%BE%84', uri.to_s)
  end

  def test_to_iri_restores_unicode_but_preserves_encoded_reserved_characters
    uri = URI.parse(
      'https://example.test/%E8%B7%AF%2F%E5%BE%84?q=%E5%80%BC%2F%3D#%E7%89%87%2F%3F'
    )
    iri = uri.to_iri

    assert_equal('/路%2F径', iri.path)
    assert_equal('q=值%2F%3D', iri.query)
    assert_equal('片%2F%3F', iri.fragment)
    assert_equal(Encoding::UTF_8, iri.path.encoding)
    assert_equal(
      'https://example.test/%E8%B7%AF%2F%E5%BE%84?q=%E5%80%BC%2F%3D#%E7%89%87%2F%3F',
      uri.to_s
    )
  end

  def test_decode_iri_returns_unicode_uri
    iri = URI.decode_iri('https://example.test/%E8%B7%AF%E5%BE%84#%E7%89%87')

    assert_equal('/路径', iri.path)
    assert_equal('片', iri.fragment)
  end

  def test_ascii_host_is_not_sent_to_converter
    called = false
    iri = URI.parse_iri('https://example.test/path')
    uri = iri.to_uri(lambda { |host| called = true; 'changed.test' })

    assert_equal('example.test', uri.host)
    assert_not_predicate(called, :itself)
  end

  def test_unicode_host_requires_converter
    error = assert_raise(URI::InvalidIRIError) do
      URI.parse_iri('https://中文.test/').to_uri
    end

    assert_equal(:host, error.component)
    assert_equal(0, error.position)
  end

  def test_converter_result_must_be_ascii_host
    error = assert_raise(URI::InvalidIRIError) do
      URI.parse_iri('https://中文.test/').to_uri(lambda { |host| host })
    end

    assert_equal(:host, error.component)
    assert_equal(0, error.position)
  end

  def test_malformed_utf8_reports_component_and_position
    path = "/\xE3\x81".dup.force_encoding(Encoding::UTF_8)
    iri = URI.parse_iri('https://example.test/').dup
    iri.instance_variable_set(:@path, path)

    error = assert_raise(URI::InvalidIRIError) { iri.to_uri }
    assert_equal(:path, error.component)
    assert_equal(1, error.position)
    assert_equal(path, iri.path)
  end

  def test_malformed_utf8_in_query_and_fragment_reports_component
    query_error = assert_raise(URI::InvalidIRIError) do
      URI.parse_iri("https://example.test/?q=\xE3".dup.force_encoding(Encoding::UTF_8))
    end
    assert_equal(:query, query_error.component)
    assert_equal(2, query_error.position)

    fragment_error = assert_raise(URI::InvalidIRIError) do
      URI.parse_iri("https://example.test/#\xE3".dup.force_encoding(Encoding::UTF_8))
    end
    assert_equal(:fragment, fragment_error.component)
    assert_equal(0, fragment_error.position)
  end

  def test_incomplete_percent_escape_reports_component_and_position
    error = assert_raise(URI::InvalidIRIError) do
      URI.parse_iri('https://example.test/abc%2?ok#frag')
    end
    assert_equal(:path, error.component)
    assert_equal(4, error.position)
  end

  def test_conversion_does_not_modify_original_uri
    iri = URI.parse_iri('https://中文.test/路径?q=值#片')
    snapshot = [iri.host, iri.path, iri.query, iri.fragment]
    iri.to_uri(lambda { |host| 'xn--fiq228c.test' })

    assert_equal(snapshot, [iri.host, iri.path, iri.query, iri.fragment])
  end
end
