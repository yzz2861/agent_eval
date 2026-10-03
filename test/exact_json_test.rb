# frozen_string_literal: true
require 'test_helper'
require 'bigdecimal'

class ExactJSONTest < Minitest::Test
  def test_valid_json_entry_preserves_high_precision_numbers
    schemer = JSONSchemer.schema({
      'multipleOf' => 0.01,
      'minimum' => BigDecimal('9007199254740990'),
      'maximum' => BigDecimal('9007199254740993.0001')
    })

    assert(schemer.valid_json?('9007199254740992'))
    assert(schemer.valid_json?('9007199254740992.00'))
    refute(schemer.valid_json?('9007199254740992.001'))
    refute(schemer.valid_json?('9007199254740994'))
  end

  def test_valid_json_entry_checks_multiple_of_with_float_confusable_decimal
    schemer = JSONSchemer.schema({ 'multipleOf' => 0.1 })

    assert(schemer.valid_json?('0.3'))
    refute(schemer.valid_json?('0.30000000000000004'))

    schemer = JSONSchemer.schema({ 'multipleOf' => 0.01 })
    refute(schemer.valid_json?('8.666'))
  end

  def test_small_decimal_and_exponent_boundaries
    schemer = JSONSchemer.schema({
      'minimum' => BigDecimal('1e-20'),
      'exclusiveMinimum' => BigDecimal('0'),
      'maximum' => 100,
      'exclusiveMaximum' => BigDecimal('101')
    })

    assert(schemer.valid_json?('1e-20'))
    assert(schemer.valid_json?('10.0e1'))
    refute(schemer.valid_json?('1e-21'))
    refute(schemer.valid_json?('1.01e2'))
  end

  def test_enum_and_const_compare_numbers_mathematically
    enum_schemer = JSONSchemer.schema({ 'enum' => [1, BigDecimal('2.5')] })
    const_schemer = JSONSchemer.schema({ 'const' => 1 })

    assert(enum_schemer.valid_json?('1.00'))
    assert(enum_schemer.valid_json?('2.50'))
    refute(enum_schemer.valid_json?('true'))
    assert(const_schemer.valid_json?('1e0'))
    refute(const_schemer.valid_json?('1.0000000000000001'))
  end

  def test_unique_items_uses_deep_numeric_equality
    schemer = JSONSchemer.schema({ 'uniqueItems' => true })

    assert(schemer.valid_json?('[0, false]'))
    assert(schemer.valid_json?('[1, true]'))
    refute(schemer.valid_json?('[1, 1.0, 1.00, 1e0]'))
    refute(schemer.valid_json?('[{"x": 1}, {"x": 1.00}]'))
  end

  def test_negative_zero_matches_positive_zero
    assert(JSONSchemer.schema({ 'const' => 0 }).valid_json?('-0'))
    assert(JSONSchemer.schema({ 'const' => 0.0 }).valid_json?('-0.0'))
    assert(JSONSchemer.schema({ 'enum' => [0] }).valid_json?('-0.0e2'))
    assert(JSONSchemer.schema({ 'minimum' => 0, 'maximum' => 0 }).valid_json?('-0.0'))
    refute(JSONSchemer.schema({ 'uniqueItems' => true }).valid_json?('[-0.0, 0]'))
  end

  def test_integer_type_preserves_json_number_lexical_form
    draft4 = JSONSchemer.schema({ 'type' => 'integer' }, :meta_schema => JSONSchemer.draft4)
    modern = JSONSchemer.schema({ 'type' => 'integer' })

    assert(draft4.valid_json?('1'))
    refute(draft4.valid_json?('1.0'))
    refute(draft4.valid_json?('1e2'))
    assert(modern.valid_json?('1'))
    assert(modern.valid_json?('1.0'))
    assert(modern.valid_json?('1e2'))
  end

  def test_validation_errors_include_source_text_positions
    schemer = JSONSchemer.schema({
      'properties' => {
        'number' => { 'maximum' => 10 },
        'items' => { 'uniqueItems' => true }
      }
    })

    error = schemer.validate_json(
      "{
        \"number\": 86.66,
        \"items\": [1, 1.0]
      }",
      :output_format => 'classic'
    ).to_a.first

    assert_equal(2, error.fetch('data_location').fetch(:line))
    assert_equal(19, error.fetch('data_location').fetch(:column))
    assert_equal(20, error.fetch('data_location').fetch(:offset))
    assert_equal(5, error.fetch('data_location').fetch(:length))
    basic = schemer.validate_json(
      "{\n        \"number\": 86.66\n      }",
      :output_format => 'basic',
      :resolve_enumerators => true
    )
    assert_equal(2, basic.fetch('errors').first.fetch('instanceSourceLocation').fetch(:line))
  end

  def test_nested_validation_errors_use_absolute_json_pointer
    schemer = JSONSchemer.schema({
      'properties' => {
        'a' => {
          'properties' => {
            'items' => {
              'prefixItems' => [{ 'maximum' => 1 }]
            }
          }
        }
      }
    })

    error = schemer.validate_json(
      '{"a":{"items":[2,1]}}',
      :output_format => 'classic'
    ).to_a.first

    assert_equal('/a/items/0', error.fetch('data_pointer'))
    assert_equal(15, error.fetch('data_location').fetch(:offset))
    assert_equal(1, error.fetch('data_location').fetch(:length))
  end

  def test_syntax_and_numeric_limits_raise_positioned_errors
    error = assert_raises(JSONSchemer::InvalidJSON) do
      JSONSchemer::ExactJSON.parse_with_locations(
        "{
        \"bad\": x
      }"
      ).first
    end

    assert_equal(2, error.line)
    assert_equal(16, error.column)
    assert_equal(17, error.offset)

    assert_raises(JSONSchemer::InvalidJSON) { JSONSchemer::ExactJSON.parse('1' + '0' * 1000) }
    assert_raises(JSONSchemer::InvalidJSON) { JSONSchemer::ExactJSON.parse('1e1001') }
    assert_raises(JSONSchemer::InvalidJSON) { JSONSchemer::ExactJSON.parse('1e-1001') }
    assert_raises(JSONSchemer::InvalidJSON) { JSONSchemer::ExactJSON.parse('1e10000') }
  end

  def test_configurable_limits
    assert_raises(JSONSchemer::InvalidJSON) { JSONSchemer::ExactJSON.parse('123', :max_number_digits => 2) }
    assert_equal(123, JSONSchemer::ExactJSON.parse('123', :max_number_digits => 3))
    assert_raises(JSONSchemer::InvalidJSON) { JSONSchemer::ExactJSON.parse('1e3', :max_exponent_absolute => 2) }
    assert_equal(BigDecimal('1000.0'), JSONSchemer::ExactJSON.parse('1e3', :max_exponent_absolute => 3))
    assert_raises(ArgumentError) { JSONSchemer::ExactJSON.parse('1', :max_number_digits => 0) }
    assert_raises(ArgumentError) { JSONSchemer::ExactJSON.parse('1', :max_exponent_absolute => -1) }
  end

  def test_utf8_byte_order_mark
    assert_equal(
      { 'bom' => BigDecimal('1.0') },
      JSONSchemer::ExactJSON.parse("﻿{\"bom\": 1.0}")
    )
  end

  def test_existing_ruby_object_interface_remains_supported
    schemer = JSONSchemer.schema({ 'type' => 'integer' })

    assert(schemer.valid?(1))
    refute(schemer.valid?('1'))
    assert_equal({ 'valid' => true }, schemer.validate(1, :output_format => 'flag'))
  end

  def test_module_level_json_entrypoint_and_limits
    assert(JSONSchemer.valid_json?({ 'type' => 'integer' }, '1'))
    assert_raises(JSONSchemer::InvalidJSON) do
      JSONSchemer.validate_json(
        { 'type' => 'integer' },
        '123',
        :output_format => 'flag',
        :max_number_digits => 2
      )
    end
  end
end
