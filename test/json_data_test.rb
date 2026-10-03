require 'test_helper'

class JSONDataTest < Minitest::Test
  def test_valid_json_data
    data = {
      'string' => 'value',
      'integer' => 1,
      'float' => 1.5,
      'true' => true,
      'false' => false,
      'null' => nil,
      'array' => [1, 'two', 3.0],
      'object' => { 'nested' => [] },
      'empty_object' => {}
    }
    assert_empty(JSONSchemer::JSONData.validate(data))
  end

  def test_valid_root_scalars
    assert_empty(JSONSchemer::JSONData.validate('string'))
    assert_empty(JSONSchemer::JSONData.validate(1))
    assert_empty(JSONSchemer::JSONData.validate(1.5))
    assert_empty(JSONSchemer::JSONData.validate(true))
    assert_empty(JSONSchemer::JSONData.validate(false))
    assert_empty(JSONSchemer::JSONData.validate(nil))
  end

  def test_shared_subobjects_are_allowed
    shared = { 'shared' => [1, 2] }
    data = { 'one' => shared, 'two' => [shared, { 'three' => shared }] }
    assert_empty(JSONSchemer::JSONData.validate(data))
  end

  def test_circular_reference_in_hash
    data = { 'a' => 1 }
    data['self'] = data
    errors = JSONSchemer::JSONData.validate(data)
    assert_equal(1, errors.size)
    assert_error(errors.first, '/self', 'circular_reference')
  end

  def test_circular_reference_in_array
    data = []
    data << data
    errors = JSONSchemer::JSONData.validate(data)
    assert_equal(1, errors.size)
    assert_error(errors.first, '/0', 'circular_reference')
  end

  def test_circular_reference_through_ancestors
    data = { 'a' => { 'b' => {} } }
    data['a']['b']['c'] = data['a']
    errors = JSONSchemer::JSONData.validate(data)
    assert_equal(1, errors.size)
    assert_error(errors.first, '/a/b/c', 'circular_reference')
  end

  def test_symbol_keys
    errors = JSONSchemer::JSONData.validate({ :one => 1, 'two' => { :three => 3 } })
    assert_equal(2, errors.size)
    assert_error(errors[0], '/one', 'symbol_key')
    assert_error(errors[1], '/two/three', 'symbol_key')
  end

  def test_unsupported_key_type
    errors = JSONSchemer::JSONData.validate({ 1 => 'one' })
    assert_equal(1, errors.size)
    assert_error(errors.first, '/1', 'unsupported_key_type')
    assert_includes(errors.first.message, 'Integer')
  end

  def test_nan
    errors = JSONSchemer::JSONData.validate({ 'nan' => Float::NAN })
    assert_equal(1, errors.size)
    assert_error(errors.first, '/nan', 'nan')
  end

  def test_infinity
    errors = JSONSchemer::JSONData.validate([Float::INFINITY, -Float::INFINITY])
    assert_equal(2, errors.size)
    assert_error(errors[0], '/0', 'infinity')
    assert_error(errors[1], '/1', 'infinity')
  end

  def test_unsupported_types
    time = Time.now
    object = Object.new
    errors = JSONSchemer::JSONData.validate({ 'symbol' => :sym, 'time' => time, 'object' => object })
    assert_equal(3, errors.size)
    assert_error(errors[0], '/symbol', 'unsupported_type')
    assert_includes(errors[0].message, 'Symbol')
    assert_error(errors[1], '/time', 'unsupported_type')
    assert_includes(errors[1].message, 'Time')
    assert_error(errors[2], '/object', 'unsupported_type')
    assert_includes(errors[2].message, 'Object')
  end

  def test_does_not_coerce_objects
    object = Object.new
    def object.to_json(*) = raise('must not be called')
    def object.to_hash = raise('must not be called')
    def object.to_ary = raise('must not be called')
    errors = JSONSchemer::JSONData.validate({ 'object' => object })
    assert_equal(1, errors.size)
    assert_error(errors.first, '/object', 'unsupported_type')
  end

  def test_root_error_path
    errors = JSONSchemer::JSONData.validate(Float::NAN)
    assert_equal(1, errors.size)
    assert_error(errors.first, '', 'nan')
    assert_equal('invalid JSON data: NaN at root', invalid_json_data_message(errors))
  end

  def test_max_depth
    data = [[['x']]]
    assert_empty(JSONSchemer::JSONData.validate(data, :max_depth => 3))
    errors = JSONSchemer::JSONData.validate(data, :max_depth => 2)
    assert_equal(1, errors.size)
    assert_error(errors.first, '/0/0', 'max_depth_exceeded')
  end

  def test_max_depth_in_hash
    errors = JSONSchemer::JSONData.validate({ 'a' => { 'b' => {} } }, :max_depth => 2)
    assert_equal(1, errors.size)
    assert_error(errors.first, '/a/b', 'max_depth_exceeded')
  end

  def test_max_nodes
    data = { 'a' => 1, 'b' => 2 }
    assert_empty(JSONSchemer::JSONData.validate(data, :max_nodes => 3))
    errors = JSONSchemer::JSONData.validate(data, :max_nodes => 2)
    assert_equal(1, errors.size)
    assert_error(errors.first, '/b', 'max_nodes_exceeded')
  end

  def test_frozen_and_unmodified_input
    data = { 'a' => [1, 'two'], 'b' => { 'c' => nil } }
    copy = Marshal.load(Marshal.dump(data))
    data.each_value { |value| value.freeze }
    data.freeze
    assert_empty(JSONSchemer::JSONData.validate(data))
    assert_equal(copy, data)
    assert(data.frozen?)
  end

  def test_errors_are_frozen
    errors = JSONSchemer::JSONData.validate({ :one => 1 })
    assert(errors.all?(&:frozen?))
  end

  def test_error_attributes
    error = JSONSchemer::JSONData.validate({ :one => 1 }).first
    assert_equal('/one', error.path)
    assert_equal('symbol_key', error.type)
    assert_equal('Symbol key at `/one`', error.message)
    assert_equal({ :path => '/one', :type => 'symbol_key', :message => 'Symbol key at `/one`' }, error.to_h)
  end

  def test_validate_bang_returns_data_when_valid
    data = { 'a' => 1 }
    assert_same(data, JSONSchemer::JSONData.validate!(data))
  end

  def test_validate_bang_raises_with_single_error
    error = assert_raises(JSONSchemer::InvalidJSONData) { JSONSchemer::JSONData.validate!({ :one => 1 }) }
    assert_equal(1, error.errors.size)
    assert_equal('invalid JSON data: Symbol key at `/one`', error.message)
  end

  def test_validate_bang_raises_with_multiple_errors
    error = assert_raises(JSONSchemer::InvalidJSONData) { JSONSchemer::JSONData.validate!({ :one => 1, :two => 2 }) }
    assert_equal(2, error.errors.size)
    assert_equal('invalid JSON data: Symbol key at `/one` (and 1 more)', error.message)
  end

  def test_schema_validate_raises_before_evaluation
    schemer = JSONSchemer.schema({ 'type' => 'object' }, :strict_json_data => true)
    error = assert_raises(JSONSchemer::InvalidJSONData) { schemer.validate({ :one => 1 }) }
    assert_equal('symbol_key', error.errors.first.type)
  end

  def test_schema_valid_raises
    schemer = JSONSchemer.schema(true, :strict_json_data => true)
    assert_raises(JSONSchemer::InvalidJSONData) { schemer.valid?(Float::NAN) }
  end

  def test_schema_valid_data
    schemer = JSONSchemer.schema({ 'type' => 'object' }, :strict_json_data => true)
    assert(schemer.valid?({ 'one' => 1 }))
    refute(schemer.valid?('one'))
  end

  def test_schema_strict_json_data_with_limits
    schemer = JSONSchemer.schema(true, :strict_json_data => { :max_depth => 2 })
    assert(schemer.valid?([['x']]))
    error = assert_raises(JSONSchemer::InvalidJSONData) { schemer.valid?([[['x']]]) }
    assert_equal('max_depth_exceeded', error.errors.first.type)
  end

  def test_schema_strict_json_data_with_string_keyed_limits
    schemer = JSONSchemer.schema(true, :strict_json_data => { 'max_nodes' => 2 })
    error = assert_raises(JSONSchemer::InvalidJSONData) { schemer.valid?([1, 2, 3]) }
    assert_equal('max_nodes_exceeded', error.errors.first.type)
  end

  def test_schema_strict_json_data_disabled_by_default
    schemer = JSONSchemer.schema({ 'type' => 'object' })
    assert(schemer.valid?({ :one => 1 }))
  end

  def test_global_configuration
    JSONSchemer.configure { |config| config.strict_json_data = true }
    schemer = JSONSchemer.schema(true)
    assert_raises(JSONSchemer::InvalidJSONData) { schemer.valid?(:symbol) }
    assert(schemer.valid?('symbol'))
  ensure
    JSONSchemer.configure { |config| config.strict_json_data = false }
  end

private

  def assert_error(error, path, type)
    assert_equal(path, error.path)
    assert_equal(type, error.type)
    refute_includes(error.message, '#<')
  end

  def invalid_json_data_message(errors)
    JSONSchemer::InvalidJSONData.new(errors).message
  end
end
