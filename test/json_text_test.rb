require 'test_helper'

class JsonTextTest < Minitest::Test
  def result(schema, data, **options)
    schemer = JSONSchemer.schema(schema, **options)
    [
      schemer.valid_json_text?(data),
      schemer.validate_json_text(data, :output_format => 'basic').fetch('valid'),
      JSONSchemer.valid_json_text?(schema, data, **options)
    ]
  end

  def assert_text_invalid(schema, data, **options)
    assert_equal([false, false, false], result(schema, data, **options))
  end

  def assert_text_valid(schema, data, **options)
    assert_equal([true, true, true], result(schema, data, **options))
  end

  def test_parse_preserves_exact_numbers
    parsed = JSONSchemer.parse_json_text('{"big": 10000000000000000000001, "small": 0.000000000000000000001, "exp": 1.5e3, "negzero": -0}')
    assert_instance_of(BigDecimal, parsed.fetch('big'))
    assert_instance_of(BigDecimal, parsed.fetch('small'))
    assert_equal(BigDecimal('10000000000000000000001'), parsed.fetch('big'))
    refute_equal(BigDecimal('10000000000000000000000'), parsed.fetch('big'))
    assert_equal(BigDecimal('1500'), parsed.fetch('exp'))
    assert_equal(BigDecimal('0'), parsed.fetch('negzero'))
    assert_equal('0.0', parsed.fetch('negzero').to_s)
  end

  def test_object_interface_is_unchanged
    schemer = JSONSchemer.schema({
      'type' => 'number',
      'multipleOf' => 0.0001,
      'enum' => [0.0075, 1.0]
    })
    assert(schemer.valid?(0.0075))
    assert(schemer.valid?(1.0))
    refute(schemer.valid?(BigDecimal('1.01')))
    assert(schemer.valid?(1))
  end

  def test_multiple_of_exact
    schema = { 'multipleOf' => '0.01' }
    assert_text_valid(schema, '1.00')
    assert_text_invalid(schema, '0.001')
    assert_text_valid(schema, '0.30')
    assert_text_invalid(schema, '0.000000000000000000001')

    tiny = { 'multipleOf' => '0.000000000000000000001' }
    assert_text_valid(tiny, '0.000000000000000000003')
    assert_text_invalid(tiny, '0.0000000000000000000035')

    integer_multiple = { 'type' => 'integer', 'multipleOf' => '0.00000001' }
    assert_text_valid(integer_multiple, '12391239123')

    large = { 'type' => 'integer', 'multipleOf' => '0.123456789' }
    assert_text_invalid(large, '100000000000000000000000000000000')
  end

  def test_multiple_of_float_confusables
    schema = { 'multipleOf' => 0.01 }
    assert_text_invalid(schema, '0.299999999999999988897769753748434595763683319091796875')
    assert_text_valid(schema, '0.30')
  end

  def test_tenth_arithmetic_is_exact
    schema = { 'multipleOf' => '0.1' }
    assert_text_valid(schema, '0.3')
    assert_text_invalid(schema, '0.30000000000000004')

    enum = { 'enum' => [0.3] }
    assert_text_valid(enum, '0.3')
    assert_text_invalid(enum, '0.30000000000000004')

    bounds = { 'maximum' => 0.3 }
    assert_text_valid(bounds, '0.3')
    assert_text_invalid(bounds, '0.30000000000000004')
  end

  def test_bounds_exact
    maximum = { 'maximum' => '10000000000000000000000' }
    assert_text_valid(maximum, '10000000000000000000000')
    assert_text_invalid(maximum, '10000000000000000000001')

    exclusive = { 'exclusiveMaximum' => '1.00000000000000010' }
    assert_text_valid(exclusive, '1.00000000000000009')
    assert_text_invalid(exclusive, '1.00000000000000010')

    minimum = { 'minimum' => '0.000000000000000000001' }
    assert_text_valid(minimum, '0.000000000000000000001')
    assert_text_invalid(minimum, '0.0000000000000000000009')

    exclusive_minimum = { 'exclusiveMinimum' => 1 }
    assert_text_valid(exclusive_minimum, '1.0000000000000001')
    assert_text_invalid(exclusive_minimum, '1')
  end

  def test_enum_and_const_exact
    enum = { 'enum' => [1.0000000000000002, 10000000000000000000000, 'x'] }
    assert_text_valid(enum, '1.0000000000000002')
    assert_text_invalid(enum, '1.0000000000000004')
    assert_text_valid(enum, '10000000000000000000000')
    assert_text_invalid(enum, '10000000000000000000001')
    assert_text_valid(enum, '"x"')

    const = { 'const' => 0.0001 }
    assert_text_valid(const, '0.0001')
    assert_text_invalid(const, '0.000100000000000000001')

    object_enum = { 'enum' => [{ 'a' => 1.0 }] }
    assert_text_valid(object_enum, '{"a": 1.00}')
    assert_text_invalid(object_enum, '{"a": 1.01}')

    array_const = { 'const' => [1, 2.5e-3] }
    assert_text_valid(array_const, '[1.0, 0.00250]')
    assert_text_invalid(array_const, '[1, 0.0026]')
  end

  def test_unique_items_exact
    schema = { 'uniqueItems' => true }
    assert_text_invalid(schema, '[1, 1.0, 1E0]')
    assert_text_invalid(schema, '[0, -0, -0.0]')
    assert_text_valid(schema, '[1.0000000000000001, 1]')
    assert_text_valid(schema, '[0, false]')
    assert_text_valid(schema, '[1, true]')
    assert_text_invalid(schema, '[{"a": 1}, {"a": 1.0}]')

    nested = { 'uniqueItems' => true, 'items' => { 'uniqueItems' => true } }
    assert_text_invalid(nested, '[[1, 1.0], [2], [1E0]]')

    disabled = { 'uniqueItems' => false }
    assert_text_valid(disabled, '[1, 1]')
  end

  def test_exact_key_handles_ruby_numerics
    key = JSONSchemer::JsonText.exact_key([1.0, BigDecimal('1.0'), 0.0, { 'n' => 2.0 }])
    assert_equal([BigDecimal('1'), BigDecimal('1'), BigDecimal('0'), { 'n' => BigDecimal('2') }], key)
  end

  def test_parse_object_comma_error_location
    error = assert_raises(JSONSchemer::JsonText::ParseError) do
      JSONSchemer.parse_json_text('{"a": 1 "b": 2}')
    end
    assert_equal('/a', error.instance_location)
  end

  def test_parse_string_escapes_and_invalid_byte
    assert_equal('"/', JSONSchemer.parse_json_text('"\\"\\/"'))
    assert_raises(JSONSchemer::JsonText::ParseError) do
      JSONSchemer.parse_json_text('"pre \xff post"'.b.dup)
    end
    error = assert_raises(JSONSchemer::JsonText::ParseError) do
      JSONSchemer.parse_json_text("\"pre \xff post\"".force_encoding(Encoding::BINARY))
    end
    assert_match('invalid UTF-8', error.message)
  end

  def test_integer_type
    schema = { 'type' => 'integer' }
    assert_text_valid(schema, '3.0')
    assert_text_valid(schema, '3E0')
    assert_text_invalid(schema, '3.5')
    assert_text_valid(schema, '3.5E1')
    assert_text_invalid(schema, '3.51E1')
    assert_text_invalid(schema, '"3"')

    types = { 'type' => ['string', 'integer'] }
    assert_text_valid(types, '3.0')
    assert_text_valid(types, '"3"')
  end

  def test_draft4_integer_and_exclusive_bounds
    options = { :meta_schema => JSONSchemer.draft4 }
    assert_text_valid({ 'type' => 'integer' }, '3.0', **options)
    assert_text_invalid({ 'type' => 'integer' }, '3.5', **options)

    schema = { 'maximum' => 3, 'exclusiveMaximum' => true }
    assert_text_invalid(schema, '3.0', **options)
    assert_text_valid(schema, '2.9999999999999999', **options)

    schema = { 'minimum' => 3, 'exclusiveMinimum' => true }
    assert_text_invalid(schema, '3.0', **options)
    assert_text_valid(schema, '3.0000000000000001', **options)
  end

  def test_draft4_object_interface_exclusive_bounds_unchanged
    options = { :meta_schema => JSONSchemer.draft4 }
    schema = JSONSchemer.schema({ 'minimum' => 3, 'exclusiveMinimum' => true }, **options)
    assert(schema.valid?(4))
    refute(schema.valid?(3))
    schema = JSONSchemer.schema({ 'maximum' => 3, 'exclusiveMaximum' => true }, **options)
    assert(schema.valid?(2))
    refute(schema.valid?(3))
  end

  def test_non_numbers_are_ignored
    schema = { 'multipleOf' => 1, 'minimum' => 0, 'maximum' => 10 }
    assert_text_valid(schema, '"foo"')
    assert_text_valid(schema, 'null')
    assert_text_valid(schema, '[1, 2]')
  end

  def test_parse_error_locations
    error = assert_raises(JSONSchemer::JsonText::ParseError) do
      JSONSchemer.parse_json_text("[1, 2,\n 3x]")
    end
    assert_equal(2, error.line)
    assert_equal(3, error.column)
    assert_equal(9, error.offset)
    assert_equal('/2', error.instance_location)
    assert_match('line 2, column 3', error.message)

    error = assert_raises(JSONSchemer::JsonText::ParseError) do
      JSONSchemer.parse_json_text('{"a/b": {"b": tru}}')
    end
    assert_equal('/a~1b/b', error.instance_location)
  end

  def test_parse_limit_errors
    big_integer = '1' + '0' * JSONSchemer::JsonText::MAX_NUMBER_DIGITS
    error = assert_raises(JSONSchemer::JsonText::ParseError) { JSONSchemer.parse_json_text(big_integer) }
    assert_match('digit limit', error.message)

    big_fraction = '0.' + '1' * (JSONSchemer::JsonText::MAX_NUMBER_DIGITS + 1)
    error = assert_raises(JSONSchemer::JsonText::ParseError) { JSONSchemer.parse_json_text(big_fraction) }
    assert_match('digit limit', error.message)

    exponent = (JSONSchemer::JsonText::MAX_NUMBER_EXPONENT + 1).to_s
    error = assert_raises(JSONSchemer::JsonText::ParseError) { JSONSchemer.parse_json_text("1E#{exponent}") }
    assert_match('exponent exceeds limit', error.message)

    assert_equal(BigDecimal('1E100000'), JSONSchemer.parse_json_text('1e+100000'))
  end

  def test_parse_syntax_errors
    invalid = ['', '   ', '12 3', '{', '[', 'tru', 'nil', '"unterminated', '{"a" 1}', '[1,]', '1.', '1.e2',
      '"unterminated\n', '"open\\', '"bad \q"', '"\u12"', '"\uD800"', '"\uD800x"', '"\uDC00"', '"\uD800\u1234"',
      'fals', 0, []]
    invalid.each do |data|
      next unless data.is_a?(String)
      assert_raises(JSONSchemer::JsonText::ParseError) { JSONSchemer.parse_json_text(data) }
    end
    assert_raises(TypeError) { JSONSchemer.parse_json_text(0) }
    assert_raises(TypeError) { JSONSchemer.parse_json_text([]) }
  end

  def test_parse_valid_literals_and_escapes
    assert_nil(JSONSchemer.parse_json_text('null'))
    assert_equal(true, JSONSchemer.parse_json_text('true'))
    assert_equal(false, JSONSchemer.parse_json_text('false'))
    assert_equal([], JSONSchemer.parse_json_text('[ ]'))
    assert_equal({}, JSONSchemer.parse_json_text('{ }'))
    parsed = JSONSchemer.parse_json_text('"a\\\/\b\f\n\r\t\u00e9\uD834\uDD1E"')
    assert_equal("a\\/\b\f\n\r\t\u00e9\u{1D11E}", parsed)
  end

  def test_text_errors_point_to_instance_location
    errors = JSONSchemer
      .schema({ 'properties' => { 'a' => { 'properties' => { 'b' => { 'type' => 'integer' } } } } })
      .validate_json_text('{"a": {"b": 3.5}}', :output_format => 'classic')
      .to_a
    assert_equal('/a/b', errors.first.fetch('data_pointer'))
  end

  def test_module_level_text_methods
    schema = { 'type' => 'number', 'multipleOf' => '0.1' }
    assert(JSONSchemer.valid_json_text?(schema, '1.0'))
    refute(JSONSchemer.valid_json_text?(schema, '0.01'))
    basic = JSONSchemer.validate_json_text(schema, '0.01', :output_format => 'basic')
    assert_equal(false, basic.fetch('valid'))
  end

  def test_text_with_insert_property_defaults
    schema = JSONSchemer.schema(
      { 'properties' => { 'a' => { 'default' => 1.0, 'type' => 'number' } } },
      :insert_property_defaults => true
    )
    assert(schema.valid_json_text?('{}'))
  end
end
