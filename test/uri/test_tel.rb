# frozen_string_literal: false
require 'test/unit'
require 'uri/tel'

class URI::TestTel < Test::Unit::TestCase
  def test_parse_global_number
    uri = URI.parse('tel:+1-234(567);isub=12;x-foo=bar')

    assert_kind_of(URI::Tel, uri)
    assert_equal('tel', uri.scheme)
    assert_equal('+1-234(567)', uri.number)
    assert_nil(uri.ext)
    assert_equal('12', uri.isub)
    assert_nil(uri.phone_context)
    assert_equal([['x-foo', 'bar']], uri.params)
    assert_equal(true, uri.global?)
    assert_equal(false, uri.local?)
    assert_equal('tel:+1-234(567);isub=12;x-foo=bar', uri.to_s)
  end

  def test_parse_scheme_is_case_insensitive
    uri = URI.parse('TEL:+1234')

    assert_kind_of(URI::Tel, uri)
    assert_equal('tel', uri.scheme)
  end

  def test_parse_local_number_requires_phone_context
    uri = URI.parse('tel:123-456;x-foo=bar;phone-context=example.com')

    assert_equal('123-456', uri.number)
    assert_equal('example.com', uri.phone_context)
    assert_equal([['x-foo', 'bar']], uri.params)
    assert_equal(false, uri.global?)
    assert_equal(true, uri.local?)
  end

  def test_parse_local_number_without_phone_context
    error = assert_raise(URI::InvalidComponentError) do
      URI.parse('tel:1234')
    end

    assert_equal('local telephone number requires phone-context',
                 error.message)
  end

  def test_global_number_cannot_have_phone_context
    assert_raise(URI::InvalidComponentError) do
      URI.parse('tel:+1234;phone-context=example.com')
    end
  end

  def test_local_number_cannot_have_ext
    error = assert_raise(URI::InvalidComponentError) do
      URI.parse('tel:1234;ext=5;phone-context=example.com')
    end

    assert_equal('ext can only be used with a global telephone number',
                 error.message)
  end

  def test_phone_context_accepts_rfc3966_param_characters
    uri = URI.parse('tel:1234;phone-context=[host]?x=1;x-a=a[]?=')

    assert_equal('[host]?x=1', uri.phone_context)
    assert_equal([['x-a', 'a[]?=']], uri.params)
  end

  def test_build
    uri = URI::Tel.build(
      number: '+1-234(567)',
      ext: '890',
      params: [['x-foo', 'bar'], ['x-empty', nil]]
    )

    assert_equal(
      'tel:+1-234(567);ext=890;x-foo=bar;x-empty',
      uri.to_s
    )
  end

  def test_build_local_number
    uri = URI::Tel.build([
      '123-456', nil, nil, 'example.com', [['x-foo', 'bar']]
    ])

    assert_equal('tel:123-456;phone-context=example.com;x-foo=bar',
                 uri.to_s)
  end

  def test_normalize_removes_visual_separators
    uri = URI.parse('tel:+1(234)-567;ext=89;x-foo=%2D')
    normalized = uri.normalize

    assert_equal('+1234567', normalized.number)
    assert_equal('89', normalized.ext)
    assert_nil(normalized.isub)
    assert_equal([['x-foo', '-']], normalized.params)
    assert_equal('tel:+1234567;ext=89;x-foo=-',
                 normalized.to_s)
    assert_equal('tel:+1(234)-567;ext=89;x-foo=%2D',
                 uri.to_s)
  end

  def test_equality_ignores_separators_and_parameter_order
    left = URI.parse('tel:+1(234)-567;X-Foo=bar;x-baz=qux;isub=a%7ab')
    right = URI.parse('tel:+1234567;x-baz=qux;x-foo=bar;isub=a%7Ab')

    assert_equal(left, right)
    assert_equal(left.hash, right.hash)
    assert_equal(true, left.eql?(right))
  end

  def test_local_equality_requires_same_phone_context
    left = URI.parse('tel:123-456;phone-context=example.com')
    same_context = URI.parse('tel:1(2)3-4-5-6;phone-context=example.com')
    other_context = URI.parse('tel:123456;phone-context=other.example')

    assert_equal(left, same_context)
    assert_not_equal(left, other_context)
    assert_not_equal(left, URI.parse('tel:+123456'))
  end

  def test_unknown_parameters_are_part_of_equality
    left = URI.parse('tel:+1234;x-foo=bar')
    right = URI.parse('tel:+1234;x-foo=baz')

    assert_not_equal(left, right)
  end

  def test_ext_and_isub_are_mutually_exclusive
    error = assert_raise(URI::InvalidComponentError) do
      URI.parse('tel:+1234;ext=1;isub=2')
    end

    assert_equal('ext and isub are mutually exclusive', error.message)
  end

  def test_duplicate_parameters_are_invalid
    assert_raise(URI::InvalidComponentError) do
      URI.parse('tel:+1234;x-foo=1;x-foo=2')
    end

    assert_raise(URI::InvalidComponentError) do
      URI.parse('tel:+1234;ext=1;EXT=2')
    end
  end

  def test_unknown_mandatory_extensions_are_rejected
    assert_raise(URI::InvalidComponentError) do
      URI.parse('tel:+1234;x-unknown=+value')
    end

    assert_raise(URI::InvalidComponentError) do
      URI::Tel.build(number: '+1234', params: [['x-unknown', '+value']])
    end

    assert_raise(URI::InvalidComponentError) do
      URI.parse('tel:+1234;x-unknown=+')
    end
  end

  def test_unknown_valueless_parameter_is_retained
    uri = URI.parse('tel:+1234;x-empty')

    assert_equal([['x-empty', nil]], uri.params)
    assert_equal('tel:+1234;x-empty', uri.to_s)

    assert_raise(URI::InvalidComponentError) do
      URI.parse('tel:+1234;x-empty=')
    end
  end

  def test_required_parameter_values
    [
      'tel:+1234;ext',
      'tel:+1234;isub=',
      'tel:1234;phone-context;phone-context=x'
    ].each do |uri|
      assert_raise(URI::InvalidComponentError, uri) do
        URI.parse(uri)
      end
    end
  end

  def test_percent_encoding
    uri = URI.parse('tel:+1234;isub=%2d%7e')

    assert_equal('%2d%7e', uri.isub)
    assert_equal('-~', uri.normalize.isub)

    %w[
      tel:+1234;isub=%zz
      tel:+1234;isub=%2
      tel:+1234;isub=%
    ].each do |bad|
      assert_raise(URI::InvalidComponentError, bad) do
        URI.parse(bad)
      end
    end
  end

  def test_setters_update_opaque
    uri = URI.parse('tel:1234;phone-context=example.com')
    uri.number = '5678'
    uri.params = [['x-foo', 'bar']]

    assert_equal('tel:5678;phone-context=example.com;x-foo=bar',
                 uri.to_s)
  end

  def test_select_components
    uri = URI.parse('tel:+1234;ext=5')

    assert_equal(
      ['tel', '+1234', '5', nil, nil, []],
      uri.select(*URI::Tel.component)
    )
  end
end
