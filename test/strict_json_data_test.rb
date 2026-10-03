require 'test_helper'

class StrictJSONDataTest < Minitest::Test
  BUSINESS_OBJECT = Class.new do
    def to_json(*)
      raise 'to_json must not be called'
    end

    def to_hash
      raise 'to_hash must not be called'
    end
  end

  def strict_schema(options = true)
    JSONSchemer.schema(true, :strict_json_data => options)
  end

  def test_disabled_by_default
    assert(JSONSchemer.schema({ 'required' => ['a'] }).valid?({ :a => 1 }))
    assert(JSONSchemer.schema(true).valid?(Float::NAN))
  end

  def test_valid_json_data
    data = {
      'string' => 'value',
      'integer' => 1,
      'float' => 1.5,
      'big_decimal' => BigDecimal('1.5'),
      'true' => true,
      'false' => false,
      'null' => nil,
      'array' => [1, 'two', 3.0],
      'object' => { 'nested' => 'ok' }
    }
    assert(strict_schema.valid?(data))
  end

  def test_does_not_modify_frozen_input
    data = { 'a' => [1, { 'b' => 'c' }.freeze].freeze }.freeze
    assert(strict_schema.valid?(data))
    assert_equal({ 'a' => [1, { 'b' => 'c' }] }, data)
  end

  def test_shared_subobject_is_allowed
    shared = { 'x' => 1 }
    assert(strict_schema.valid?({ 'a' => shared, 'b' => [shared] }))
  end

  def test_circular_reference_hash
    data = {}
    data['self'] = data
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?(data) }
    assert_equal(:circular_reference, error.reason)
    assert_equal('/self', error.path)
    assert_equal('Hash', error.offending_type)
    assert_match(%r{circular reference to Hash at /self}, error.message)
  end

  def test_circular_reference_array
    data = []
    data << data
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?({ 'a' => data }) }
    assert_equal(:circular_reference, error.reason)
    assert_equal('/a/0', error.path)
    assert_equal('Array', error.offending_type)
  end

  def test_indirect_circular_reference
    data = { 'a' => { 'b' => {} } }
    data['a']['b']['c'] = data['a']
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?(data) }
    assert_equal(:circular_reference, error.reason)
    assert_equal('/a/b/c', error.path)
  end

  def test_symbol_key
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?({ :a => 1 }) }
    assert_equal(:invalid_key, error.reason)
    assert_equal('/a', error.path)
    assert_equal('Symbol', error.offending_type)
    assert_match(%r{JSON object key at /a is a Symbol}, error.message)
  end

  def test_key_path_escaping
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?({ :'a/b' => 1 }) }
    assert_equal('/a~1b', error.path)
  end

  def test_integer_key
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?({ 1 => 'x' }) }
    assert_equal(:invalid_key, error.reason)
    assert_equal('/1', error.path)
    assert_equal('Integer', error.offending_type)
  end

  def test_object_key
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?({ Object.new => 1 }) }
    assert_equal(:invalid_key, error.reason)
    assert_equal('/<Object>', error.path)
    assert_equal('Object', error.offending_type)
  end

  def test_symbol_value
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?({ 'a' => :sym }) }
    assert_equal(:invalid_type, error.reason)
    assert_equal('/a', error.path)
    assert_equal('Symbol', error.offending_type)
  end

  def test_business_object
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?({ 'obj' => BUSINESS_OBJECT.new }) }
    assert_equal(:invalid_type, error.reason)
    assert_equal('/obj', error.path)
    assert_match(/is not a valid JSON type/, error.message)
  end

  def test_business_object_at_root
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?(BUSINESS_OBJECT.new) }
    assert_equal('', error.path)
    assert_match(%r{at / is not a valid JSON type}, error.message)
  end

  def test_nan
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?({ 'x' => Float::NAN }) }
    assert_equal(:non_finite_number, error.reason)
    assert_equal('/x', error.path)
    assert_equal('Float', error.offending_type)
    assert_match(%r{non-finite Float at /x}, error.message)
  end

  def test_infinity
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?([Float::INFINITY]) }
    assert_equal(:non_finite_number, error.reason)
    assert_equal('/0', error.path)
  end

  def test_big_decimal_nan
    error = assert_raises(JSONSchemer::InvalidJSONData) { strict_schema.valid?(BigDecimal('NaN')) }
    assert_equal(:non_finite_number, error.reason)
    assert_equal('BigDecimal', error.offending_type)
  end

  def test_max_depth
    schemer = strict_schema(:max_depth => 2)
    assert(schemer.valid?({ 'a' => { 'b' => 1 } }))
    error = assert_raises(JSONSchemer::InvalidJSONData) { schemer.valid?({ 'a' => { 'b' => { 'c' => 1 } } }) }
    assert_equal(:max_depth, error.reason)
    assert_equal('/a/b/c', error.path)
    assert_match(/maximum depth of 2/, error.message)
  end

  def test_max_nodes
    schemer = strict_schema(:max_nodes => 3)
    assert(schemer.valid?({ 'a' => 1, 'b' => 2 }))
    error = assert_raises(JSONSchemer::InvalidJSONData) { schemer.valid?({ 'a' => 1, 'b' => 2, 'c' => 3 }) }
    assert_equal(:max_nodes, error.reason)
    assert_match(/maximum node count of 3/, error.message)
  end

  def test_check_runs_before_schema_evaluation
    schemer = JSONSchemer.schema(false, :strict_json_data => true)
    assert_raises(JSONSchemer::InvalidJSONData) { schemer.valid?({ 'a' => :b }) }
  end

  def test_error_does_not_leak_data
    error = assert_raises(JSONSchemer::InvalidJSONData) do
      strict_schema.valid?({ 'secret' => 'sensitive-value', 'obj' => BUSINESS_OBJECT.new })
    end
    refute_includes(error.message, 'sensitive-value')
  end

  def test_global_configuration
    assert_equal(false, JSONSchemer.configuration.strict_json_data)
    JSONSchemer.configure { |config| config.strict_json_data = true }
    begin
      assert_raises(JSONSchemer::InvalidJSONData) { JSONSchemer.schema(true).valid?(:sym) }
    ensure
      JSONSchemer.configure { |config| config.strict_json_data = false }
    end
  end
end
