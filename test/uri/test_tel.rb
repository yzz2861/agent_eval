# frozen_string_literal: false
require 'test/unit'
require 'uri/tel'

class URI::TestTel < Test::Unit::TestCase
  def uri_to_ary(uri)
    uri.class.component.collect { |component| uri.send(component) }
  end

  def test_parse_global
    uri = URI.parse('tel:+1-202-555-0100;ext=01-42;unknown=value;flag')

    assert_instance_of(URI::Tel, uri)
    assert_equal('+1-202-555-0100', uri.number)
    assert_equal('01-42', uri.ext)
    assert_equal('01-42', uri.extension)
    assert_nil(uri.isub)
    assert_nil(uri.phone_context)
    assert_equal([['unknown', 'value'], ['flag', nil]], uri.params)
    assert_predicate(uri, :global?)
    assert_not_predicate(uri, :local?)
    assert_equal(
      ['tel', '+1-202-555-0100', '01-42', nil, nil, [['unknown', 'value'], ['flag', nil]]],
      uri_to_ary(uri)
    )
  end

  def test_parse_local
    uri = URI.parse('tel:7042;phone-context=example.com')

    assert_equal('7042', uri.number)
    assert_equal('example.com', uri.phone_context)
    assert_predicate(uri, :local?)
    assert_not_predicate(uri, :global?)
  end

  def test_build_array
    uri = URI::Tel.build([
      '7042',
      nil,
      '1234',
      'example.com',
      [['unknown', 'value'], ['flag', nil]],
    ])

    assert_equal(
      'tel:7042;isub=1234;phone-context=example.com;unknown=value;flag',
      uri.to_s
    )
    assert_equal('1234', uri.isdn_subaddress)
    assert_equal([['unknown', 'value'], ['flag', nil]], uri.parameters)
  end

  def test_build_hash_and_encoded_values
    uri = URI::Tel.build(
      number: '7042',
      phone_context: 'private.example',
      isdn_subaddress: 'a;b',
      params: {
        'X': 'A%20B',
      }
    )

    assert_equal(
      'tel:7042;isub=a%3Bb;phone-context=private.example;X=A%20B',
      uri.to_s
    )
  end

  def test_build_encodes_reserved_characters
    uri = URI::Tel.build(
      number: '123',
      phone_context: '%@44-118',
      params: [['x', 'a;b']]
    )

    assert_equal('tel:123;phone-context=%@44-118;x=a%3Bb', uri.to_s)
  end

  def test_equivalence_ignores_separators_and_parameter_order
    first = URI.parse('tel:+1-202-555-0100;ext=0142;unknown=value')
    second = URI.parse('tel:+1.(202)555-0100;UNKNOWN=value;EXT=01-42')

    assert_equal(first, second)
    assert_equal(first.hash, second.hash)
    assert_equal('tel:+12025550100;ext=0142;unknown=value', first.normalize.to_s)
    assert_equal('tel:+12025550100;ext=0142;unknown=value', second.normalize.to_s)
  end

  def test_equivalence_normalizes_phone_context
    first = URI.parse('tel:7042;phone-context=EXAMPLE.COM;unknown=value')
    second = URI.parse('tel:70-42;UNKNOWN=value;phone-context=example.com')

    assert_equal(first, second)
    assert_equal('tel:7042;phone-context=example.com;unknown=value', first.normalize.to_s)
  end

  def test_global_and_private_phone_contexts_are_normalized
    by_global_context = URI.parse('tel:70-42;phone-context=+1-(202)')
    by_private_context = URI.parse('tel:70-42;phone-context=%25@44-(118)')

    assert_equal('tel:7042;phone-context=+1202', by_global_context.normalize.to_s)
    assert_equal('tel:7042;phone-context=%@44118', by_private_context.normalize.to_s)
    assert_not_equal(by_global_context, by_private_context)
  end

  def test_different_phone_contexts_are_not_equivalent
    first = URI.parse('tel:7042;phone-context=a.example')
    second = URI.parse('tel:7042;phone-context=b.example')

    assert_not_equal(first, second)
  end

  def test_unknown_parameters_affect_equivalence
    first = URI.parse('tel:+12025550100;unknown=value')
    second = URI.parse('tel:+12025550100;other=value')

    assert_not_equal(first, second)
  end

  def test_local_number_requires_phone_context
    assert_invalid_component('tel:7042')
  end

  def test_global_number_rejects_phone_context
    assert_invalid_component('tel:+12025550100;phone-context=example.com')
  end

  def test_ext_and_isub_are_mutually_exclusive
    assert_invalid_component('tel:+12025550100;ext=1;isub=2')
    assert_invalid_component('tel:+12025550100;ext=1;isdn-subaddress=2')
  end

  def test_duplicate_parameters_are_rejected
    assert_invalid_component('tel:+12025550100;unknown=1;UNKNOWN=2')
    assert_invalid_component('tel:+12025550100;ext=1;ext=2')
    assert_invalid_component('tel:7042;phone-context=a.example;phone-context=b.example')
  end

  def test_known_parameters_require_values
    assert_invalid_component('tel:+12025550100;ext')
    assert_invalid_component('tel:7042;phone-context')
  end

  def test_bad_percent_encoding_is_rejected
    assert_invalid_uri('tel:+12025550100;unknown=%zz')
    assert_invalid_uri('tel:+12025550100;unknown=a%2')
    assert_raise(URI::InvalidComponentError) do
      URI::Tel.build(['+12025550100', nil, nil, nil, [['unknown', '%zz']]])
    end
  end

  def test_bad_numbers_are_rejected
    assert_invalid_component('tel:+abc')
    assert_invalid_component('tel:+')
    assert_invalid_uri('tel:704 2;phone-context=example.com')
  end

  def test_bad_extension_is_rejected
    assert_invalid_component('tel:+12025550100;ext=xyz')
    assert_raise(URI::InvalidComponentError) do
      URI::Tel.build(['+12025550100', '%zz', nil, nil, nil])
    end
  end

  private

  def assert_invalid_component(value)
    assert_raise(URI::InvalidComponentError) do
      URI.parse(value)
    end
  end

  def assert_invalid_uri(value)
    URI.parse(value)
    flunk "expected URI::Error but nothing was raised"
  rescue URI::Error
  end
end
