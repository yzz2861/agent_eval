# frozen_string_literal: true
module JSONSchemer
  # Streaming, event-driven validation for large JSON documents.
  #
  # Instead of parsing a whole document into memory, a Stream::Validator
  # consumes a sequence of events:
  #
  #   [:object_start]
  #   [:key, 'name']       - string, inside an object only
  #   [:scalar, value]     - nil, true, false, Numeric, String
  #   [:array_start]
  #   [:container_end]     - closes the innermost object/array
  #   [:document_end]      - marks the end of the document
  #
  # Only a subset of JSON Schema keywords can be guaranteed in a single
  # streaming pass (see SUPPORTED_KEYWORDS). Anything else is rejected when
  # the validator is prepared.
  module Stream
    # Raised for malformed event input (structural problems), as opposed to
    # schema mismatches which are reported as schema errors.
    class EventError < StandardError; end

    # Raised at preparation time when a schema uses keywords or forms that
    # cannot be guaranteed in a single streaming pass.
    class UnsupportedKeyword < StandardError; end

    SUPPORTED_KEYWORDS = %w[
      type enum const
      properties required additionalProperties minProperties maxProperties
      items minItems maxItems contains minContains maxContains
      minimum maximum exclusiveMinimum exclusiveMaximum multipleOf
      minLength maxLength pattern
    ].freeze

    module Compiler
      module_function

      def check!(schema, schema_pointer = '')
        case schema
        when true, false
          nil
        when Hash
          schema.each_key do |keyword|
            unless SUPPORTED_KEYWORDS.include?(keyword)
              raise UnsupportedKeyword, "unsupported keyword '#{keyword}' at schema pointer '#{schema_pointer}'; streaming supports: #{SUPPORTED_KEYWORDS.join(', ')}"
            end
          end
          check_type(schema, schema_pointer)
          check_subschema(schema, 'items', schema_pointer)
          check_subschema(schema, 'contains', schema_pointer)
          check_subschema(schema, 'additionalProperties', schema_pointer)
          check_properties(schema, schema_pointer)
          check_required(schema, schema_pointer)
          nil
        else
          raise UnsupportedKeyword, "schema at '#{schema_pointer}' must be an object or boolean"
        end
      end

      def check_type(schema, schema_pointer)
        return unless schema.key?('type')
        type = schema['type']
        valid = type.is_a?(String) || (type.is_a?(Array) && type.all? { |entry| entry.is_a?(String) })
        unless valid
          raise UnsupportedKeyword, "'type' at schema pointer '#{schema_pointer}' must be a string or an array of strings"
        end
      end

      def check_subschema(schema, keyword, schema_pointer)
        return unless schema.key?(keyword)
        subschema = schema[keyword]
        if keyword == 'items' && subschema.is_a?(Array)
          raise UnsupportedKeyword, "tuple form of 'items' at schema pointer '#{schema_pointer}' cannot be validated in a single streaming pass"
        end
        check!(subschema, "#{schema_pointer}/#{keyword}")
      end

      def check_properties(schema, schema_pointer)
        return unless schema.key?('properties')
        properties = schema['properties']
        unless properties.is_a?(Hash)
          raise UnsupportedKeyword, "'properties' at schema pointer '#{schema_pointer}' must be an object"
        end
        properties.each do |name, subschema|
          check!(subschema, "#{schema_pointer}/properties/#{Location.escape_json_pointer_token(name)}")
        end
      end

      def check_required(schema, schema_pointer)
        return unless schema.key?('required')
        unless schema['required'].is_a?(Array)
          raise UnsupportedKeyword, "'required' at schema pointer '#{schema_pointer}' must be an array"
        end
      end
    end

    class Result
      attr_reader :schema_errors, :structural_errors

      def initialize(schema_errors, structural_errors, completed)
        @schema_errors = schema_errors
        @structural_errors = structural_errors
        @completed = completed
      end

      # True only when the document was fully validated without errors.
      # A stream that stops before the document end marker always records
      # a structural error, so this is never true for incomplete input.
      def valid?
        @structural_errors.empty? && @schema_errors.empty?
      end

      # True when the event stream was fully consumed and balanced.
      def completed?
        @completed
      end
    end

    class Validator
      def initialize(schema)
        Compiler.check!(schema)
        @schema = schema
      end

      # Fail-fast boolean check. Stops reading at the first error and closes
      # the source (when it responds to close).
      def valid?(source)
        run(source, true).valid?
      end

      # Collects all schema errors. Structural (event stream) errors are
      # reported separately from schema mismatches on the returned Result.
      def validate(source)
        run(source, false)
      end

    private

      def run(source, fail_fast)
        Machine.new(@schema, fail_fast).run(source)
      ensure
        source.close if source.respond_to?(:close)
      end
    end

    class Machine
      def initialize(schema, fail_fast)
        @schema = schema
        @fail_fast = fail_fast
        @schema_errors = []
        @structural_errors = []
        @completed = false
        @recorders = []
        @pending = nil
      end

      def run(source)
        @events = source.to_enum(:each)
        catch(:fail_fast) do
          begin
            validate_value(@schema, '', '')
            expect_document_end
            check_trailing_events
            @completed = true
          rescue EventError => error
            @structural_errors << error.message
          end
        end
        Result.new(@schema_errors, @structural_errors, @completed)
      end

      # Validates a single buffered value (used for contains matching).
      def value_valid?(events)
        @events = events.to_enum(:each)
        validate_value(@schema, '', '')
        @schema_errors.empty?
      end

    private

      def validate_value(node, data_pointer, schema_pointer)
        if node == false
          schema_error('false_schema', data_pointer, schema_pointer)
          node = true
        end
        node = {} if node == true
        event = next_event
        case event[0]
        when :scalar
          validate_scalar(node, event[1], data_pointer, schema_pointer)
        when :object_start
          validate_object(node, data_pointer, schema_pointer)
        when :array_start
          validate_array(node, data_pointer, schema_pointer)
        else
          raise EventError, "unexpected event '#{event[0]}' at '#{data_pointer}'"
        end
      end

      def validate_object(node, data_pointer, schema_pointer)
        type = node['type']
        if type && !type_allowed?(type, 'object')
          schema_error('type', data_pointer, "#{schema_pointer}/type", 'expected' => type, 'actual' => 'object')
          node = {}
        end
        properties = node['properties']
        additional = node['additionalProperties']
        required = node['required']
        seen = {}
        property_count = 0
        loop do
          event = next_event
          break if event[0] == :container_end
          key = event[1]
          unless event[0] == :key && key.is_a?(String)
            raise EventError, "expected object key at '#{data_pointer}' but got '#{event[0]}'"
          end
          property_count += 1
          seen[key] = true
          child_pointer = "#{data_pointer}/#{Location.escape_json_pointer_token(key)}"
          if properties && properties.key?(key)
            validate_value(properties[key], child_pointer, "#{schema_pointer}/properties/#{Location.escape_json_pointer_token(key)}")
          elsif additional == false
            schema_error('additionalProperties', child_pointer, "#{schema_pointer}/additionalProperties")
            validate_value(true, child_pointer, schema_pointer)
          elsif additional.is_a?(Hash)
            validate_value(additional, child_pointer, "#{schema_pointer}/additionalProperties")
          else
            validate_value(true, child_pointer, schema_pointer)
          end
        end
        if required
          missing = required.reject { |name| seen[name] }
          unless missing.empty?
            schema_error('required', data_pointer, "#{schema_pointer}/required", 'missing_keys' => missing)
          end
        end
        min_properties = node['minProperties']
        if min_properties && property_count < min_properties
          schema_error('minProperties', data_pointer, "#{schema_pointer}/minProperties", 'count' => property_count)
        end
        max_properties = node['maxProperties']
        if max_properties && property_count > max_properties
          schema_error('maxProperties', data_pointer, "#{schema_pointer}/maxProperties", 'count' => property_count)
        end
      end

      def validate_array(node, data_pointer, schema_pointer)
        type = node['type']
        if type && !type_allowed?(type, 'array')
          schema_error('type', data_pointer, "#{schema_pointer}/type", 'expected' => type, 'actual' => 'array')
          node = {}
        end
        items = node['items']
        contains = node['contains']
        max_items = node['maxItems']
        subschema = items.nil? ? true : items
        index = 0
        contains_count = 0
        max_items_reported = false
        loop do
          if peek_event[0] == :container_end
            next_event
            break
          end
          item_pointer = "#{data_pointer}/#{index}"
          if contains.nil?
            validate_value(subschema, item_pointer, "#{schema_pointer}/items")
          else
            buffer = []
            @recorders << buffer
            begin
              validate_value(subschema, item_pointer, "#{schema_pointer}/items")
            ensure
              @recorders.pop
            end
            contains_count += 1 if Machine.new(contains, false).value_valid?(buffer)
          end
          index += 1
          if max_items && index > max_items && !max_items_reported
            max_items_reported = true
            schema_error('maxItems', data_pointer, "#{schema_pointer}/maxItems", 'count' => index)
          end
        end
        min_items = node['minItems']
        if min_items && index < min_items
          schema_error('minItems', data_pointer, "#{schema_pointer}/minItems", 'count' => index)
        end
        unless contains.nil?
          min_contains = node['minContains'] || 1
          if contains_count < min_contains
            schema_error('contains', data_pointer, "#{schema_pointer}/contains", 'count' => contains_count)
          end
          max_contains = node['maxContains']
          if max_contains && contains_count > max_contains
            schema_error('maxContains', data_pointer, "#{schema_pointer}/maxContains", 'count' => contains_count)
          end
        end
      end

      def validate_scalar(node, value, data_pointer, schema_pointer)
        unless value.nil? || value == true || value == false || value.is_a?(Numeric) || value.is_a?(String)
          raise EventError, "invalid scalar value #{value.inspect} at '#{data_pointer}'"
        end
        type = node['type']
        if type && !scalar_type_allowed?(type, value)
          schema_error('type', data_pointer, "#{schema_pointer}/type", 'expected' => type, 'actual' => json_type(value))
          return
        end
        if node.key?('const') && node['const'] != value
          schema_error('const', data_pointer, "#{schema_pointer}/const", 'const' => node['const'])
        end
        enum = node['enum']
        if enum && !enum.include?(value)
          schema_error('enum', data_pointer, "#{schema_pointer}/enum", 'enum' => enum)
        end
        validate_number(node, value, data_pointer, schema_pointer) if value.is_a?(Numeric)
        validate_string(node, value, data_pointer, schema_pointer) if value.is_a?(String)
      end

      def validate_number(node, value, data_pointer, schema_pointer)
        minimum = node['minimum']
        if minimum && value < minimum
          schema_error('minimum', data_pointer, "#{schema_pointer}/minimum", 'minimum' => minimum)
        end
        maximum = node['maximum']
        if maximum && value > maximum
          schema_error('maximum', data_pointer, "#{schema_pointer}/maximum", 'maximum' => maximum)
        end
        exclusive_minimum = node['exclusiveMinimum']
        if exclusive_minimum && value <= exclusive_minimum
          schema_error('exclusiveMinimum', data_pointer, "#{schema_pointer}/exclusiveMinimum", 'exclusiveMinimum' => exclusive_minimum)
        end
        exclusive_maximum = node['exclusiveMaximum']
        if exclusive_maximum && value >= exclusive_maximum
          schema_error('exclusiveMaximum', data_pointer, "#{schema_pointer}/exclusiveMaximum", 'exclusiveMaximum' => exclusive_maximum)
        end
        multiple_of = node['multipleOf']
        if multiple_of && !BigDecimal(value.to_s).modulo(multiple_of).zero?
          schema_error('multipleOf', data_pointer, "#{schema_pointer}/multipleOf", 'multipleOf' => multiple_of)
        end
      end

      def validate_string(node, value, data_pointer, schema_pointer)
        min_length = node['minLength']
        if min_length && value.length < min_length
          schema_error('minLength', data_pointer, "#{schema_pointer}/minLength", 'minLength' => min_length)
        end
        max_length = node['maxLength']
        if max_length && value.length > max_length
          schema_error('maxLength', data_pointer, "#{schema_pointer}/maxLength", 'maxLength' => max_length)
        end
        pattern = node['pattern']
        if pattern && !Regexp.new(EcmaRegexp.ruby_equivalent(pattern)).match?(value)
          schema_error('pattern', data_pointer, "#{schema_pointer}/pattern", 'pattern' => pattern)
        end
      end

      def type_allowed?(type, actual)
        if type.is_a?(String)
          type == actual
        else
          type.include?(actual)
        end
      end

      def scalar_type_allowed?(type, value)
        types = type.is_a?(String) ? [type] : type
        types.any? { |entry| scalar_type_matches?(entry, value) }
      end

      def scalar_type_matches?(type, value)
        case type
        when 'null'
          value.nil?
        when 'boolean'
          value == true || value == false
        when 'number'
          value.is_a?(Numeric)
        when 'integer'
          value.is_a?(Integer) || (value.is_a?(Numeric) && value.floor == value)
        when 'string'
          value.is_a?(String)
        when 'object', 'array'
          false
        else
          true
        end
      end

      def json_type(value)
        case value
        when nil
          'null'
        when true, false
          'boolean'
        when Numeric
          'number'
        else
          'string'
        end
      end

      def schema_error(type, data_pointer, schema_pointer, details = {})
        @schema_errors << {
          'data_pointer' => data_pointer,
          'schema_pointer' => schema_pointer,
          'type' => type,
          'details' => details
        }
        throw(:fail_fast) if @fail_fast
      end

      def pull_event
        event = @events.next
        unless event.is_a?(Array) && event[0].is_a?(Symbol)
          raise EventError, "malformed event #{event.inspect}"
        end
        event
      rescue StopIteration
        raise EventError, 'unexpected end of input'
      end

      def peek_event
        @pending ||= pull_event
      end

      def next_event
        event = peek_event
        @pending = nil
        @recorders.each { |recorder| recorder << event }
        event
      end

      def expect_document_end
        event = next_event
        unless event[0] == :document_end
          raise EventError, "expected document end but got '#{event[0]}'"
        end
      end

      def check_trailing_events
        @events.next
        raise EventError, 'unexpected events after document end'
      rescue StopIteration
        nil
      end
    end
  end
end
