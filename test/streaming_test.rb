require "test_helper"

class StreamingTest < Minitest::Test
  class ListEventSource
    include Enumerable

    attr_reader :closed

    def initialize(events)
      @events = events
      @closed = false
    end

    def each(&block)
      @events.each(&block)
    end

    def close
      @closed = true
    end
  end

  class CountingArraySource
    include Enumerable

    attr_reader :closed, :yielded_count

    def initialize(count)
      @count = count
      @closed = false
      @yielded_count = 0
    end

    def each
      yield [:start_array]
      @count.times do |index|
        yield [:scalar, index]
        @yielded_count += 1
      end
      yield [:end]
    end

    def close
      @closed = true
    end
  end

  def validate(schema, events, **options)
    validator = JSONSchemer::Streaming.validator(schema, **options)
    events.each { |event| validator << event }
    validator.finish
    validator
  end

  def test_valid_object_stream
    schema = {
      "type" => "object",
      "required" => ["id"],
      "properties" => {
        "id" => { "type" => "integer" },
        "name" => { "type" => "string" }
      }
    }
    validator = validate(schema, [
      [:start_object],
      [:key, "id"], [:scalar, 1],
      [:key, "name"], [:scalar, "x"],
      [:end]
    ])
    assert validator.valid?
    assert_empty validator.errors
  end

  def test_items_required_and_full_json_pointers
    schema = {
      "type" => "array",
      "items" => {
        "type" => "object",
        "required" => ["id"],
        "properties" => { "id" => { "type" => "integer" } }
      }
    }
    validator = validate(schema, [
      [:start_array],
      [:start_object], [:key, "id"], [:scalar, 1], [:end],
      [:start_object], [:key, "id"], [:scalar, "x"], [:end],
      [:start_object], [:key, "other"], [:scalar, 1], [:end],
      [:end]
    ])
    refute validator.valid?
    assert_equal 2, validator.errors.size
    type_error, required_error = validator.errors
    assert_equal "/1/id", type_error["data_pointer"]
    assert_equal "integer", type_error["type"]
    assert_equal "/items/properties/id", type_error["schema_pointer"]
    assert_equal "/2", required_error["data_pointer"]
    assert_equal "required", required_error["type"]
    assert_equal({ "missing_keys" => ["id"] }, required_error["details"])
    assert_equal schema, required_error["root_schema"]
  end

  def test_json_pointer_escaping
    schema = { "properties" => { "a/b~c" => { "type" => "integer" } } }
    validator = validate(schema, [
      [:start_object], [:key, "a/b~c"], [:scalar, "x"], [:end]
    ])
    assert_equal "/a~1b~0c", validator.errors.first["data_pointer"]
    assert_equal "/properties/a~1b~0c", validator.errors.first["schema_pointer"]
  end

  def test_min_and_max_items
    schema = { "minItems" => 2, "maxItems" => 3 }
    validator = validate(schema, [[:start_array], [:scalar, 1], [:end]])
    assert_equal "minItems", validator.errors.first["type"]
    assert_equal "", validator.errors.first["data_pointer"]
    assert_equal({ "minItems" => 2, "count" => 1 }, validator.errors.first["details"])

    validator = validate(schema, [[:start_array], [:scalar, 1], [:scalar, 2], [:end]])
    assert validator.valid?

    validator = validate(schema, [[:start_array], [:scalar, 1], [:scalar, 2], [:scalar, 3], [:scalar, 4], [:end]])
    assert_equal 1, validator.errors.size
    assert_equal "maxItems", validator.errors.first["type"]
    assert_equal({ "maxItems" => 3 }, validator.errors.first["details"])
  end

  def test_contains
    schema = { "contains" => { "type" => "string" } }
    validator = validate(schema, [[:start_array], [:scalar, 1], [:scalar, "a"], [:end]])
    assert validator.valid?

    validator = validate(schema, [[:start_array], [:scalar, 1], [:end]])
    refute validator.valid?
    assert_equal "contains", validator.errors.first["type"]
    assert_equal "", validator.errors.first["data_pointer"]
  end

  def test_contains_with_object_items
    schema = { "contains" => { "required" => ["id"] } }
    validator = validate(schema, [
      [:start_array],
      [:start_object], [:key, "other"], [:scalar, 1], [:end],
      [:start_object], [:key, "id"], [:scalar, 1], [:end],
      [:end]
    ])
    assert validator.valid?
  end

  def test_min_contains
    schema = { "contains" => { "type" => "string" }, "minContains" => 2 }
    validator = validate(schema, [[:start_array], [:scalar, "a"], [:scalar, "b"], [:end]])
    assert validator.valid?

    validator = validate(schema, [[:start_array], [:scalar, "a"], [:scalar, 1], [:end]])
    assert_equal "minContains", validator.errors.first["type"]
    assert_equal({ "minContains" => 2, "count" => 1 }, validator.errors.first["details"])
  end

  def test_max_contains
    schema = { "contains" => { "type" => "integer" }, "maxContains" => 1 }
    validator = validate(schema, [[:start_array], [:scalar, 1], [:scalar, 2], [:end]])
    assert_equal "maxContains", validator.errors.first["type"]
    assert_equal({ "maxContains" => 1, "count" => 2 }, validator.errors.first["details"])

    schema = { "contains" => { "type" => "integer" }, "maxContains" => 2 }
    validator = validate(schema, [[:start_array], [:scalar, 1], [:scalar, 2], [:end]])
    assert validator.valid?
  end

  def test_max_contains_without_min_contains_still_requires_one_match
    schema = { "contains" => { "type" => "string" }, "maxContains" => 2 }
    validator = validate(schema, [[:start_array], [:scalar, 1], [:end]])
    assert_equal "minContains", validator.errors.first["type"]
  end

  def test_nested_contains
    schema = { "contains" => { "contains" => { "type" => "string" } } }
    validator = validate(schema, [
      [:start_array],
      [:start_array], [:scalar, 1], [:scalar, "a"], [:end],
      [:end]
    ])
    assert validator.valid?

    validator = validate(schema, [
      [:start_array],
      [:start_array], [:scalar, 1], [:end],
      [:end]
    ])
    refute validator.valid?
    assert_equal "contains", validator.errors.first["type"]
  end

  def test_contains_in_items
    schema = { "items" => { "contains" => { "type" => "string" } } }
    validator = validate(schema, [
      [:start_array],
      [:start_array], [:scalar, "a"], [:end],
      [:start_array], [:scalar, 1], [:end],
      [:end]
    ])
    refute validator.valid?
    assert_equal 1, validator.errors.size
    assert_equal "/1", validator.errors.first["data_pointer"]
  end

  def test_scalar_type_validation
    assert_scalar_errors({ "type" => "string" }, [[:scalar, 1]], "string")
    assert_scalar_errors({ "type" => "null" }, [[:scalar, 1]], "null")
    assert_scalar_errors({ "type" => "boolean" }, [[:scalar, 1]], "boolean")
    assert_scalar_errors({ "type" => "integer" }, [[:scalar, 1.5]], "integer")
    assert_scalar_errors({ "type" => "integer" }, [[:scalar, "a"]], "integer")
    assert_scalar_errors({ "type" => "integer" }, [[:scalar, Float::INFINITY]], "integer")
    assert_scalar_errors({ "type" => "number" }, [[:scalar, "a"]], "number")
    assert_scalar_errors({ "type" => "number" }, [[:scalar, Complex(1, 0)]], "number")
    assert_scalar_errors({ "type" => "object" }, [[:scalar, 1]], "object")
    assert_scalar_errors({ "type" => "bogus" }, [[:scalar, 1]], "bogus")
    assert_scalar_errors({ "type" => ["string", "null"] }, [[:scalar, 1]], "type")

    assert_scalar_valid({ "type" => "null" }, [[:scalar, nil]])
    assert_scalar_valid({ "type" => "boolean" }, [[:scalar, true]])
    assert_scalar_valid({ "type" => "boolean" }, [[:scalar, false]])
    assert_scalar_valid({ "type" => "integer" }, [[:scalar, 1]])
    assert_scalar_valid({ "type" => "integer" }, [[:scalar, 1.0]])
    assert_scalar_valid({ "type" => "integer" }, [[:scalar, BigDecimal("2")]])
    assert_scalar_valid({ "type" => "number" }, [[:scalar, 1.5]])
    assert_scalar_valid({ "type" => "number" }, [[:scalar, Rational(1, 2)]])
    assert_scalar_valid({ "type" => ["string", "null"] }, [[:scalar, nil]])
  end

  def test_enum_and_const
    assert_scalar_errors({ "enum" => [1, "a", nil] }, [[:scalar, 2]], "enum")
    assert_scalar_valid({ "enum" => [1, "a", nil] }, [[:scalar, "a"]])
    assert_scalar_valid({ "enum" => [1, "a", nil] }, [[:scalar, nil]])

    assert_scalar_errors({ "const" => nil }, [[:scalar, 1]], "const")
    assert_scalar_valid({ "const" => nil }, [[:scalar, nil]])
    assert_scalar_errors({ "const" => "x" }, [[:scalar, "y"]], "const")
    assert_scalar_valid({ "const" => "x" }, [[:scalar, "x"]])
  end

  def test_numeric_keywords
    assert_scalar_errors({ "minimum" => 5 }, [[:scalar, 3]], "minimum")
    assert_scalar_valid({ "minimum" => 5 }, [[:scalar, 5]])
    assert_scalar_errors({ "maximum" => 5 }, [[:scalar, 6]], "maximum")
    assert_scalar_valid({ "maximum" => 5 }, [[:scalar, 5]])
    assert_scalar_errors({ "exclusiveMinimum" => 5 }, [[:scalar, 5]], "exclusiveMinimum")
    assert_scalar_valid({ "exclusiveMinimum" => 5 }, [[:scalar, 6]])
    assert_scalar_errors({ "exclusiveMaximum" => 5 }, [[:scalar, 5]], "exclusiveMaximum")
    assert_scalar_valid({ "exclusiveMaximum" => 5 }, [[:scalar, 4]])
  end

  def test_string_keywords
    assert_scalar_errors({ "minLength" => 2 }, [[:scalar, "a"]], "minLength")
    assert_scalar_valid({ "minLength" => 2 }, [[:scalar, "ab"]])
    assert_scalar_errors({ "maxLength" => 2 }, [[:scalar, "abc"]], "maxLength")
    assert_scalar_valid({ "maxLength" => 2 }, [[:scalar, "ab"]])
    assert_scalar_errors({ "pattern" => "^a" }, [[:scalar, "ba"]], "pattern")
    assert_scalar_valid({ "pattern" => "^a" }, [[:scalar, "ab"]])
  end

  def test_boolean_schemas
    assert_scalar_valid(true, [[:scalar, 1]])

    validator = validate(false, [[:scalar, 1]])
    refute validator.valid?
    assert_equal "falseSchema", validator.errors.first["type"]
    assert_equal "", validator.errors.first["data_pointer"]

    schema = { "properties" => { "a" => false } }
    validator = validate(schema, [[:start_object], [:key, "a"], [:scalar, 1], [:end]])
    assert_equal "falseSchema", validator.errors.first["type"]
    assert_equal "/a", validator.errors.first["data_pointer"]

    validator = validate(schema, [[:start_object], [:key, "a"], [:start_object], [:end], [:end]])
    assert_equal "falseSchema", validator.errors.first["type"]
  end

  def test_container_type_mismatch_makes_children_permissive
    schema = { "type" => "array", "items" => { "type" => "integer" } }
    validator = validate(schema, [[:start_object], [:key, "a"], [:scalar, "x"], [:end]])
    refute validator.valid?
    assert_equal 1, validator.errors.size
    assert_equal "array", validator.errors.first["type"]
    assert_equal "", validator.errors.first["data_pointer"]
  end

  def test_array_type_mismatch_on_object_keywords
    schema = { "type" => "object", "required" => ["a"] }
    validator = validate(schema, [[:start_array], [:scalar, 1], [:end]])
    assert_equal 1, validator.errors.size
    assert_equal "object", validator.errors.first["type"]
  end

  def test_object_without_properties_allows_any_value
    schema = { "required" => ["a"] }
    validator = validate(schema, [[:start_object], [:key, "a"], [:scalar, 1], [:key, "b"], [:scalar, "x"], [:end]])
    assert validator.valid?
  end

  def test_object_with_unknown_property
    schema = { "properties" => { "a" => { "type" => "integer" } } }
    validator = validate(schema, [[:start_object], [:key, "b"], [:scalar, "x"], [:end]])
    assert validator.valid?
  end

  def test_array_without_items_allows_any_value
    validator = validate({ "type" => "array" }, [[:start_array], [:scalar, "x"], [:start_object], [:end], [:end]])
    assert validator.valid?
  end

  def test_root_scalar
    assert_scalar_valid({ "type" => "integer" }, [[:scalar, 1]])
  end

  def test_symbol_keys
    schema = { :type => "object", :properties => { :a => { :type => "integer" } }, :required => [:a] }
    validator = validate(schema, [[:start_object], [:key, "a"], [:scalar, "x"], [:end]])
    assert_equal "integer", validator.errors.first["type"]

    validator = validate(schema, [[:start_object], [:end]])
    assert_equal "required", validator.errors.first["type"]
    assert_equal({ "missing_keys" => ["a"] }, validator.errors.first["details"])
  end

  def test_ignored_annotation_keywords
    schema = {
      "$schema" => "https://json-schema.org/draft/2020-12/schema",
      "$id" => "https://example.com/root",
      "$comment" => "note",
      "$defs" => { "unused" => { "$ref" => "#" } },
      "definitions" => {},
      "title" => "title",
      "description" => "description",
      "default" => 1,
      "examples" => [1],
      "deprecated" => false,
      "readOnly" => false,
      "writeOnly" => false,
      "type" => "integer"
    }
    assert_scalar_valid(schema, [[:scalar, 1]])
  end

  def test_unsupported_keywords_rejected_at_prepare_time
    error = assert_raises(JSONSchemer::Streaming::UnsupportedKeyword) do
      JSONSchemer::Streaming.validator({ "allOf" => [] })
    end
    assert_includes error.message, "allOf"

    error = assert_raises(JSONSchemer::Streaming::UnsupportedKeyword) do
      JSONSchemer::Streaming.validator({ "properties" => { "a" => { "$ref" => "#" } } })
    end
    assert_includes error.message, "/properties/a"

    error = assert_raises(JSONSchemer::Streaming::UnsupportedKeyword) do
      JSONSchemer::Streaming.validator({ "uniqueItems" => true })
    end
    assert_includes error.message, "uniqueItems"

    assert_raises(JSONSchemer::Streaming::UnsupportedKeyword) do
      JSONSchemer::Streaming.validator({ "items" => [{ "type" => "integer" }] })
    end

    assert_raises(JSONSchemer::Streaming::UnsupportedKeyword) do
      JSONSchemer::Streaming.validator({ "enum" => [[1, 2]] })
    end

    assert_raises(JSONSchemer::Streaming::UnsupportedKeyword) do
      JSONSchemer::Streaming.validator({ "const" => { "a" => 1 } })
    end

    assert_raises(JSONSchemer::Streaming::UnsupportedKeyword) do
      JSONSchemer::Streaming.validator("not a schema")
    end
  end

  def test_structure_errors_are_raised_not_collected
    validator = JSONSchemer::Streaming.validator({ "type" => "array" })
    validator << [:start_array]
    assert_raises(JSONSchemer::Streaming::StructureError) { validator << [:key, "a"] }
    assert_empty validator.errors
    assert_equal 0, validator.error_count
  end

  def test_structure_error_cases
    assert_structure_error(true, [[:key, "a"]])
    assert_structure_error(true, [[:start_array], [:key, "a"]])
    assert_structure_error(true, [[:start_object], [:key, 1]])
    assert_structure_error(true, [[:start_object], [:key, "a"], [:key, "b"]])
    assert_structure_error(true, [[:start_object], [:scalar, 1]])
    assert_structure_error(true, [[:end]])
    assert_structure_error(true, [[:start_array], [:end_object]])
    assert_structure_error(true, [[:start_object], [:key, "a"], [:scalar, 1], [:end_array]])
    assert_structure_error(true, [[:start_object], [:key, "a"], [:end]])
    assert_structure_error(true, [[:scalar, 1], [:scalar, 2]])
    assert_structure_error(true, [[:scalar, {}]])
    assert_structure_error(true, [[:scalar, [1]]])
    assert_structure_error(true, [[:bogus]])
  end

  def test_incomplete_document
    validator = JSONSchemer::Streaming.validator({ "type" => "array" })
    validator << [:start_array]
    validator << [:scalar, 1]
    refute validator.complete?
    refute validator.valid?
    assert_empty validator.errors
    assert_raises(JSONSchemer::Streaming::IncompleteDocument) { validator.finish }

    validator = JSONSchemer::Streaming.validator(true)
    assert_raises(JSONSchemer::Streaming::IncompleteDocument) { validator.finish }
  end

  def test_validate_events
    schema = { "type" => "array", "items" => { "type" => "integer" } }
    events = Enumerator.new do |yielder|
      yielder << [:start_array]
      yielder << [:scalar, 1]
      yielder << [:end]
    end
    validator = JSONSchemer::Streaming.validator(schema)
    assert_same validator, validator.validate_events(events)
    assert validator.valid?
  end

  def test_validate_events_truncated_source
    validator = JSONSchemer::Streaming.validator(true)
    source = ListEventSource.new([[:start_array]])
    assert_raises(JSONSchemer::Streaming::IncompleteDocument) { validator.validate_events(source) }
    refute source.closed
  end

  def test_validate_events_structure_error_closes_source
    validator = JSONSchemer::Streaming.validator(true)
    source = ListEventSource.new([[:start_array], [:key, "a"], [:scalar, 1]])
    assert_raises(JSONSchemer::Streaming::StructureError) { validator.validate_events(source) }
    assert source.closed
  end

  def test_fail_fast_early_stop_closes_source
    schema = { "type" => "array", "items" => { "type" => "integer" }, "maxItems" => 10 }
    validator = JSONSchemer::Streaming.validator(schema, :fail_fast => true)
    source = CountingArraySource.new(100_000)
    validator.validate_events(source)
    assert validator.aborted?
    refute validator.valid?
    assert source.closed
    assert_operator source.yielded_count, :<=, 11
    assert_equal 1, validator.errors.size
    assert_equal "maxItems", validator.errors.first["type"]

    assert_same validator, validator << [:scalar, 1]
    assert_equal 1, validator.error_count
  end

  def test_fail_fast_without_closeable_source
    events = Enumerator.new do |yielder|
      yielder << [:start_array]
      100.times { |index| yielder << [:scalar, index] }
      yielder << [:end]
    end
    validator = JSONSchemer::Streaming.validator({ "maxItems" => 2 }, :fail_fast => true)
    validator.validate_events(events)
    assert validator.aborted?
    refute validator.valid?
  end

  def test_large_array_streaming
    schema = { "type" => "array", "items" => { "type" => "integer" }, "maxItems" => 100_000 }
    validator = JSONSchemer::Streaming.validator(schema)
    validator.validate_events(CountingArraySource.new(100_000))
    assert validator.valid?
    assert_empty validator.errors
  end

  def test_large_array_does_not_accumulate_state_or_claim_validity_early
    validator = JSONSchemer::Streaming.validator({ "type" => "array", "items" => { "type" => "integer" } })
    max_depth = 0
    validator << [:start_array]
    100_000.times do |index|
      validator << [:scalar, index]
      max_depth = [max_depth, validator.instance_variable_get(:@stack).size].max
    end
    refute validator.valid?, "must not claim validity before the end marker arrives"
    refute validator.complete?
    assert_empty validator.errors
    validator << [:end]
    validator.finish
    assert validator.valid?
    assert_equal 1, max_depth
  end

  def test_schema_streaming_validator
    schema = JSONSchemer.schema({ "type" => "array", "items" => { "type" => "integer" } })
    validator = schema.streaming_validator
    validator.validate_events(ListEventSource.new([[:start_array], [:scalar, "x"], [:end]]))
    refute validator.valid?
    assert_equal "/0", validator.errors.first["data_pointer"]
  end

  def test_streaming_validator_entry_point
    assert_instance_of JSONSchemer::Streaming::Validator, JSONSchemer::Streaming.validator(true)
  end

  def test_explicit_end_markers
    validator = validate({ "type" => "object" }, [
      [:start_object],
      [:key, "a"], [:start_array], [:scalar, 1], [:end_array],
      [:end_object]
    ])
    assert validator.valid?
  end

private

  def assert_scalar_errors(schema, events, expected_type)
    validator = validate(schema, events)
    refute validator.valid?
    assert validator.errors.any? { |error| error["type"] == expected_type }, "expected a #{expected_type} error in #{validator.errors.inspect}"
  end

  def assert_scalar_valid(schema, events)
    validator = validate(schema, events)
    assert validator.valid?, "expected valid, got #{validator.errors.inspect}"
  end

  def assert_structure_error(schema, events)
    validator = JSONSchemer::Streaming.validator(schema)
    assert_raises(JSONSchemer::Streaming::StructureError) do
      events.each { |event| validator << event }
    end
  end
end
