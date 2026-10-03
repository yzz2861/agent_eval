require 'test_helper'
require 'weakref'

class StreamTest < Minitest::Test
  class CountingEventSource
    include Enumerable

    attr_reader :pulled

    def initialize(item_count)
      @item_count = item_count
      @pulled = 0
      @closed = false
      @samples = []
    end

    def each(&block)
      return enum_for(:each) unless block
      emit([:array_start], &block)
      @item_count.times do |index|
        event = [:scalar, "item-#{index}"]
        @samples << WeakRef.new(event) if (index % 1000).zero?
        emit(event, &block)
      end
      emit([:container_end], &block)
      emit([:document_end], &block)
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end

    def sample_count
      @samples.size
    end

    def surviving_samples
      @samples.count(&:weakref_alive?)
    end

  private

    def emit(event)
      @pulled += 1
      yield event
    end
  end

  def doc(*events)
    events + [[:document_end]]
  end

  def object_events(*events)
    doc([:object_start], *events, [:container_end])
  end

  def array_events(*events)
    doc([:array_start], *events, [:container_end])
  end

  def test_stream_returns_validator
    assert_instance_of(JSONSchemer::Stream::Validator, JSONSchemer.stream({}))
  end

  def test_valid_object_document
    schema = {
      'type' => 'object',
      'required' => ['name'],
      'properties' => {
        'name' => { 'type' => 'string', 'minLength' => 2 },
        'tags' => { 'type' => 'array', 'items' => { 'type' => 'string' }, 'minItems' => 1, 'contains' => { 'const' => 'x' } }
      }
    }
    events = object_events(
      [:key, 'name'], [:scalar, 'Ada'],
      [:key, 'tags'], [:array_start], [:scalar, 'x'], [:scalar, 'y'], [:container_end]
    )
    validator = JSONSchemer.stream(schema)
    assert(validator.valid?(events))
    result = validator.validate(events)
    assert(result.valid?)
    assert(result.completed?)
    assert_empty(result.schema_errors)
    assert_empty(result.structural_errors)
  end

  def test_enumerator_source
    events = doc([:scalar, 1])
    assert(JSONSchemer.stream({ 'type' => 'integer' }).valid?(events.each))
  end

  def test_scalar_root_values
    assert(JSONSchemer.stream({ 'type' => 'null' }).valid?(doc([:scalar, nil])))
    assert(JSONSchemer.stream({ 'type' => 'boolean' }).valid?(doc([:scalar, true])))
    assert(JSONSchemer.stream({ 'type' => 'boolean' }).valid?(doc([:scalar, false])))
    assert(JSONSchemer.stream({ 'type' => 'number' }).valid?(doc([:scalar, 1.5])))
    assert(JSONSchemer.stream({ 'type' => 'integer' }).valid?(doc([:scalar, 3])))
    assert(JSONSchemer.stream({ 'type' => 'integer' }).valid?(doc([:scalar, 2.0])))
    assert(JSONSchemer.stream({ 'type' => 'string' }).valid?(doc([:scalar, 'x'])))
    assert(JSONSchemer.stream({ 'type' => ['string', 'integer'] }).valid?(doc([:scalar, 5])))
    assert(JSONSchemer.stream({ 'type' => 'unregistered' }).valid?(doc([:scalar, 5])))
  end

  def test_scalar_type_mismatches
    error = JSONSchemer.stream({ 'type' => 'integer' }).validate(doc([:scalar, 2.5])).schema_errors.first
    assert_equal('', error['data_pointer'])
    assert_equal('/type', error['schema_pointer'])
    assert_equal('type', error['type'])
    assert_equal('number', error['details']['actual'])

    error = JSONSchemer.stream({ 'type' => 'integer' }).validate(doc([:scalar, 'x'])).schema_errors.first
    assert_equal('string', error['details']['actual'])

    error = JSONSchemer.stream({ 'type' => 'string' }).validate(doc([:scalar, nil])).schema_errors.first
    assert_equal('null', error['details']['actual'])

    error = JSONSchemer.stream({ 'type' => 'string' }).validate(doc([:scalar, true])).schema_errors.first
    assert_equal('boolean', error['details']['actual'])

    error = JSONSchemer.stream({ 'type' => 'boolean' }).validate(doc([:scalar, 1])).schema_errors.first
    assert_equal('number', error['details']['actual'])

    refute(JSONSchemer.stream({ 'type' => 'null' }).valid?(doc([:scalar, 1])))
    refute(JSONSchemer.stream({ 'type' => 'number' }).valid?(doc([:scalar, 'x'])))
    refute(JSONSchemer.stream({ 'type' => 'object' }).valid?(doc([:scalar, 1])))
    refute(JSONSchemer.stream({ 'type' => 'array' }).valid?(doc([:scalar, 1])))
    refute(JSONSchemer.stream({ 'type' => ['integer', 'string'] }).valid?(doc([:scalar, nil])))
  end

  def test_object_type_mismatch_consumes_children_without_cascade
    schema = { 'type' => 'array', 'properties' => { 'a' => { 'type' => 'integer' } } }
    result = JSONSchemer.stream(schema).validate(object_events([:key, 'a'], [:scalar, 'not-an-integer']))
    assert(result.completed?)
    assert_equal(['type'], result.schema_errors.map { |error| error['type'] })
    assert_equal('object', result.schema_errors.first['details']['actual'])
  end

  def test_array_type_mismatch
    schema = { 'type' => 'object', 'items' => { 'type' => 'integer' } }
    result = JSONSchemer.stream(schema).validate(array_events([:scalar, 'x']))
    assert_equal(['type'], result.schema_errors.map { |error| error['type'] })
    assert_equal('array', result.schema_errors.first['details']['actual'])
    assert(JSONSchemer.stream({ 'type' => ['object'] }).valid?(object_events))
    refute(JSONSchemer.stream({ 'type' => ['string'] }).valid?(object_events))
  end
  def test_nested_errors_keep_full_json_pointers
    schema = {
      'properties' => {
        'a/b' => {
          'properties' => {
            'c~d' => { 'type' => 'integer' }
          }
        }
      }
    }
    events = object_events(
      [:key, 'a/b'], [:object_start],
      [:key, 'c~d'], [:scalar, 'x'],
      [:container_end]
    )
    error = JSONSchemer.stream(schema).validate(events).schema_errors.first
    assert_equal('/a~1b/c~0d', error['data_pointer'])
    assert_equal('/properties/a~1b/properties/c~0d/type', error['schema_pointer'])
  end

  def test_required
    schema = { 'required' => ['one', 'two'] }
    result = JSONSchemer.stream(schema).validate(object_events([:key, 'one'], [:scalar, 1]))
    error = result.schema_errors.first
    assert_equal('required', error['type'])
    assert_equal('', error['data_pointer'])
    assert_equal(['two'], error['details']['missing_keys'])
    assert(JSONSchemer.stream(schema).valid?(object_events([:key, 'one'], [:scalar, 1], [:key, 'two'], [:scalar, 2])))
  end

  def test_additional_properties_false
    schema = { 'properties' => { 'known' => true }, 'additionalProperties' => false }
    events = object_events(
      [:key, 'known'], [:scalar, 1],
      [:key, 'extra'], [:array_start], [:scalar, 1], [:container_end]
    )
    result = JSONSchemer.stream(schema).validate(events)
    assert_equal(1, result.schema_errors.size)
    error = result.schema_errors.first
    assert_equal('additionalProperties', error['type'])
    assert_equal('/extra', error['data_pointer'])
    assert_equal('/additionalProperties', error['schema_pointer'])
  end

  def test_additional_properties_schema
    schema = { 'properties' => { 'known' => true }, 'additionalProperties' => { 'type' => 'integer' } }
    events = object_events([:key, 'extra'], [:scalar, 'x'])
    error = JSONSchemer.stream(schema).validate(events).schema_errors.first
    assert_equal('/extra', error['data_pointer'])
    assert_equal('/additionalProperties/type', error['schema_pointer'])
    valid = object_events([:key, 'extra'], [:scalar, 1])
    assert(JSONSchemer.stream(schema).valid?(valid))
  end

  def test_property_without_matching_subschema_is_consumed
    schema = { 'properties' => { 'a' => { 'type' => 'integer' } } }
    events = object_events(
      [:key, 'b'], [:object_start], [:key, 'c'], [:scalar, 'x'], [:container_end],
      [:key, 'a'], [:scalar, 1]
    )
    assert(JSONSchemer.stream(schema).valid?(events))
  end

  def test_min_max_properties
    schema = { 'minProperties' => 1, 'maxProperties' => 2 }
    result = JSONSchemer.stream(schema).validate(object_events)
    assert_equal('minProperties', result.schema_errors.first['type'])
    assert_equal(0, result.schema_errors.first['details']['count'])

    events = object_events([:key, 'a'], [:scalar, 1], [:key, 'b'], [:scalar, 2], [:key, 'c'], [:scalar, 3])
    result = JSONSchemer.stream(schema).validate(events)
    assert_equal('maxProperties', result.schema_errors.first['type'])
    assert_equal(3, result.schema_errors.first['details']['count'])

    assert(JSONSchemer.stream(schema).valid?(object_events([:key, 'a'], [:scalar, 1])))
  end

  def test_items
    schema = { 'items' => { 'type' => 'integer' } }
    result = JSONSchemer.stream(schema).validate(array_events([:scalar, 1], [:scalar, 'x'], [:scalar, 2]))
    assert_equal(1, result.schema_errors.size)
    error = result.schema_errors.first
    assert_equal('/1', error['data_pointer'])
    assert_equal('/items/type', error['schema_pointer'])
    assert(JSONSchemer.stream(schema).valid?(array_events([:scalar, 1], [:scalar, 2])))
  end

  def test_array_without_items_consumes_anything
    assert(JSONSchemer.stream({ 'type' => 'array' }).valid?(array_events([:scalar, 1], [:array_start], [:container_end])))
  end

  def test_items_false
    schema = { 'items' => false }
    result = JSONSchemer.stream(schema).validate(array_events([:object_start], [:container_end]))
    error = result.schema_errors.first
    assert_equal('false_schema', error['type'])
    assert_equal('/0', error['data_pointer'])
    assert(JSONSchemer.stream(schema).valid?(array_events))
  end

  def test_min_max_items
    schema = { 'minItems' => 1, 'maxItems' => 2 }
    result = JSONSchemer.stream(schema).validate(array_events)
    assert_equal('minItems', result.schema_errors.first['type'])
    assert_equal(0, result.schema_errors.first['details']['count'])

    events = array_events([:scalar, 1], [:scalar, 2], [:scalar, 3], [:scalar, 4])
    result = JSONSchemer.stream(schema).validate(events)
    assert_equal(1, result.schema_errors.count { |error| error['type'] == 'maxItems' })
    assert_equal('', result.schema_errors.first['data_pointer'])

    assert(JSONSchemer.stream(schema).valid?(array_events([:scalar, 1], [:scalar, 2])))
  end
  def test_contains
    schema = { 'contains' => { 'type' => 'integer' } }
    assert(JSONSchemer.stream(schema).valid?(array_events([:scalar, 'a'], [:scalar, 1], [:scalar, 'b'])))

    result = JSONSchemer.stream(schema).validate(array_events([:scalar, 'a'], [:scalar, 'b']))
    error = result.schema_errors.first
    assert_equal('contains', error['type'])
    assert_equal('', error['data_pointer'])
    assert_equal(0, error['details']['count'])
  end

  def test_contains_min_and_max_contains
    schema = { 'contains' => { 'type' => 'integer' }, 'minContains' => 2, 'maxContains' => 2 }
    result = JSONSchemer.stream(schema).validate(array_events([:scalar, 1], [:scalar, 'a']))
    assert_equal('contains', result.schema_errors.first['type'])
    assert_equal(1, result.schema_errors.first['details']['count'])

    result = JSONSchemer.stream(schema).validate(array_events([:scalar, 1], [:scalar, 2], [:scalar, 3]))
    assert_equal('maxContains', result.schema_errors.first['type'])
    assert_equal(3, result.schema_errors.first['details']['count'])

    assert(JSONSchemer.stream(schema).valid?(array_events([:scalar, 1], [:scalar, 2], [:scalar, 'a'])))
  end

  def test_contains_with_items
    schema = { 'items' => { 'type' => 'string' }, 'contains' => { 'const' => 'x' } }
    assert(JSONSchemer.stream(schema).valid?(array_events([:scalar, 'a'], [:scalar, 'x'])))

    result = JSONSchemer.stream(schema).validate(array_events([:scalar, 5]))
    assert_equal(%w[type contains], result.schema_errors.map { |error| error['type'] })
    assert_equal('/0', result.schema_errors.first['data_pointer'])
  end

  def test_contains_false
    schema = { 'contains' => false, 'minContains' => 0 }
    assert(JSONSchemer.stream(schema).valid?(array_events([:scalar, 1])))
    refute(JSONSchemer.stream({ 'contains' => false }).valid?(array_events([:scalar, 1])))
  end

  def test_nested_contains
    schema = { 'contains' => { 'contains' => { 'const' => 1 } } }
    events = array_events(
      [:array_start], [:scalar, 2], [:container_end],
      [:array_start], [:scalar, 1], [:container_end]
    )
    assert(JSONSchemer.stream(schema).valid?(events))
  end

  def test_number_keywords
    schema = {
      'minimum' => 1,
      'maximum' => 10,
      'exclusiveMinimum' => 0,
      'exclusiveMaximum' => 11,
      'multipleOf' => 0.5
    }
    assert(JSONSchemer.stream(schema).valid?(doc([:scalar, 2.5])))
    assert(JSONSchemer.stream({}).valid?(doc([:scalar, 7])))

    {
      { 'minimum' => 5 } => [4, 'minimum'],
      { 'maximum' => 5 } => [6, 'maximum'],
      { 'exclusiveMinimum' => 5 } => [5, 'exclusiveMinimum'],
      { 'exclusiveMaximum' => 5 } => [5, 'exclusiveMaximum'],
      { 'multipleOf' => 2 } => [3, 'multipleOf']
    }.each do |subschema, (value, type)|
      error = JSONSchemer.stream(subschema).validate(doc([:scalar, value])).schema_errors.first
      assert_equal(type, error['type'])
      assert_equal('', error['data_pointer'])
      assert_equal("/#{type}", error['schema_pointer'])
    end

    refute(JSONSchemer.stream({ 'multipleOf' => 0.1 }).valid?(doc([:scalar, 0.35])))
  end

  def test_string_keywords
    schema = { 'minLength' => 2, 'maxLength' => 3, 'pattern' => '^a' }
    assert(JSONSchemer.stream(schema).valid?(doc([:scalar, 'abc'])))
    assert(JSONSchemer.stream({}).valid?(doc([:scalar, 'anything'])))

    {
      { 'minLength' => 2 } => ['a', 'minLength'],
      { 'maxLength' => 2 } => ['abc', 'maxLength'],
      { 'pattern' => '^a' } => ['xyz', 'pattern']
    }.each do |subschema, (value, type)|
      error = JSONSchemer.stream(subschema).validate(doc([:scalar, value])).schema_errors.first
      assert_equal(type, error['type'])
      assert_equal("/#{type}", error['schema_pointer'])
    end
  end

  def test_enum_and_const
    assert(JSONSchemer.stream({ 'const' => 'x' }).valid?(doc([:scalar, 'x'])))
    error = JSONSchemer.stream({ 'const' => 'x' }).validate(doc([:scalar, 'y'])).schema_errors.first
    assert_equal('const', error['type'])
    assert_equal('x', error['details']['const'])

    assert(JSONSchemer.stream({ 'enum' => [1, 2] }).valid?(doc([:scalar, 2])))
    error = JSONSchemer.stream({ 'enum' => [1, 2] }).validate(doc([:scalar, 3])).schema_errors.first
    assert_equal('enum', error['type'])
    assert_equal([1, 2], error['details']['enum'])
  end

  def test_true_and_false_subschemas
    schema = { 'properties' => { 'blocked' => false, 'open' => true } }
    events = object_events(
      [:key, 'blocked'], [:object_start], [:key, 'x'], [:scalar, 1], [:container_end],
      [:key, 'open'], [:array_start], [:scalar, 'y'], [:container_end]
    )
    result = JSONSchemer.stream(schema).validate(events)
    assert_equal(1, result.schema_errors.size)
    error = result.schema_errors.first
    assert_equal('false_schema', error['type'])
    assert_equal('/blocked', error['data_pointer'])
    assert_equal('/properties/blocked', error['schema_pointer'])
  end

  def test_boolean_root_schemas
    assert(JSONSchemer.stream(true).valid?(doc([:scalar, 1])))
    result = JSONSchemer.stream(false).validate(doc([:scalar, 1]))
    assert_equal('false_schema', result.schema_errors.first['type'])
    refute(result.valid?)
  end

  def test_validate_collects_all_errors
    schema = { 'items' => { 'type' => 'integer' } }
    events = array_events([:scalar, 'a'], [:scalar, 'b'], [:scalar, 1])
    result = JSONSchemer.stream(schema).validate(events)
    assert_equal(['/0', '/1'], result.schema_errors.map { |error| error['data_pointer'] })
  end
  def test_structural_errors_are_reported_separately_from_schema_errors
    result = JSONSchemer.stream({}).validate([[:object_start]])
    refute(result.valid?)
    refute(result.completed?)
    assert_empty(result.schema_errors)
    assert_equal(['unexpected end of input'], result.structural_errors)
  end

  def test_missing_document_end_marker_is_not_valid
    validator = JSONSchemer.stream({ 'type' => 'integer' })
    refute(validator.valid?([[:scalar, 1]]))
    result = validator.validate([[:scalar, 1]])
    assert_empty(result.schema_errors)
    assert_equal(['unexpected end of input'], result.structural_errors)
  end

  def test_structural_unexpected_events_at_root
    {
      [[:container_end]] => 'container_end',
      [[:key, 'a']] => 'key',
      [[:document_end]] => 'document_end'
    }.each do |events, name|
      result = JSONSchemer.stream({}).validate(events)
      assert_equal(["unexpected event '#{name}' at ''"], result.structural_errors)
    end
  end

  def test_structural_document_end_inside_object
    result = JSONSchemer.stream({}).validate([[:object_start], [:document_end]])
    assert_equal(["expected object key at '' but got 'document_end'"], result.structural_errors)
  end

  def test_structural_non_string_key
    result = JSONSchemer.stream({}).validate([[:object_start], [:key, 5], [:scalar, 1], [:container_end], [:document_end]])
    assert_equal(["expected object key at '' but got 'key'"], result.structural_errors)
  end

  def test_structural_scalar_inside_object
    result = JSONSchemer.stream({}).validate([[:object_start], [:scalar, 1], [:container_end], [:document_end]])
    assert_equal(["expected object key at '' but got 'scalar'"], result.structural_errors)
  end

  def test_structural_missing_document_end_after_root
    result = JSONSchemer.stream({}).validate([[:scalar, 1], [:scalar, 2]])
    assert_equal(["expected document end but got 'scalar'"], result.structural_errors)
  end

  def test_structural_trailing_events_after_document_end
    result = JSONSchemer.stream({}).validate([[:scalar, 1], [:document_end], [:scalar, 2]])
    assert_equal(['unexpected events after document end'], result.structural_errors)
    refute(result.valid?)
  end

  def test_structural_malformed_events
    result = JSONSchemer.stream({}).validate(['nope'])
    assert_equal(['malformed event "nope"'], result.structural_errors)

    result = JSONSchemer.stream({}).validate([[1, 2]])
    assert_equal(['malformed event [1, 2]'], result.structural_errors)
  end

  def test_structural_invalid_scalar_value
    result = JSONSchemer.stream({}).validate(doc([:scalar, :symbol]))
    assert_equal(["invalid scalar value :symbol at ''"], result.structural_errors)
  end

  def test_prepare_rejects_unsupported_keywords
    error = assert_raises(JSONSchemer::Stream::UnsupportedKeyword) do
      JSONSchemer.stream({ 'allOf' => [] })
    end
    assert_includes(error.message, "unsupported keyword 'allOf'")
    assert_includes(error.message, "at schema pointer ''")

    error = assert_raises(JSONSchemer::Stream::UnsupportedKeyword) do
      JSONSchemer.stream({ 'properties' => { 'a' => { '$ref' => '#' } } })
    end
    assert_includes(error.message, "unsupported keyword '$ref'")
    assert_includes(error.message, "at schema pointer '/properties/a'")

    assert_raises(JSONSchemer::Stream::UnsupportedKeyword) do
      JSONSchemer.stream({ 'items' => { 'contains' => { 'uniqueItems' => true } } })
    end
  end

  def test_prepare_rejects_tuple_items
    error = assert_raises(JSONSchemer::Stream::UnsupportedKeyword) do
      JSONSchemer.stream({ 'items' => [{ 'type' => 'integer' }] })
    end
    assert_includes(error.message, "tuple form of 'items'")
  end

  def test_prepare_rejects_invalid_schema_shapes
    assert_raises(JSONSchemer::Stream::UnsupportedKeyword) { JSONSchemer.stream('nope') }
    assert_raises(JSONSchemer::Stream::UnsupportedKeyword) { JSONSchemer.stream({ 'properties' => [] }) }
    assert_raises(JSONSchemer::Stream::UnsupportedKeyword) { JSONSchemer.stream({ 'required' => 'a' }) }
    assert_raises(JSONSchemer::Stream::UnsupportedKeyword) { JSONSchemer.stream({ 'type' => 5 }) }
    assert_raises(JSONSchemer::Stream::UnsupportedKeyword) { JSONSchemer.stream({ 'type' => ['string', 5] }) }
  end
  def test_early_stop_closes_source_without_draining_it
    source = CountingEventSource.new(100_000)
    schema = { 'type' => 'array', 'items' => { 'type' => 'string' }, 'maxItems' => 10 }
    refute(JSONSchemer.stream(schema).valid?(source))
    assert(source.closed?)
    assert_operator(source.pulled, :<=, 20)
  end

  def test_validate_closes_source
    source = CountingEventSource.new(3)
    assert(JSONSchemer.stream({ 'type' => 'array' }).valid?(source))
    assert(source.closed?)
  end

  def test_large_stream_is_validated_without_retaining_events
    source = CountingEventSource.new(100_000)
    schema = { 'type' => 'array', 'items' => { 'type' => 'string' } }
    result = validate_in_isolation(schema, source)
    assert(result.valid?)
    assert(result.completed?)
    assert_equal(100_003, source.pulled)
    assert(source.closed?)
    GC.start
    survivors = source.surviving_samples
    assert_operator(survivors, :<=, source.sample_count / 10, "expected most sampled events to be collected, #{survivors} survived")
  end

  def test_large_stream_contains_counting
    source = CountingEventSource.new(100_000)
    schema = { 'type' => 'array', 'contains' => { 'type' => 'string' }, 'minContains' => 100_000 }
    assert(JSONSchemer.stream(schema).valid?(source))
  end

  def validate_in_isolation(schema, source)
    JSONSchemer.stream(schema).validate(source)
  end
end
