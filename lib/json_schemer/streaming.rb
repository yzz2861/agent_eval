# frozen_string_literal: true
module JSONSchemer
  # Streaming, event-driven validation for large JSON documents.
  #
  # Instead of parsing the whole document into memory, events are pushed to a
  # validator as they are produced by a parser/decoder:
  #
  #   validator = JSONSchemer::Streaming.validator(schema)
  #   validator << [:start_array]
  #   validator << [:scalar, 1]
  #   validator << [:end]
  #   validator.finish
  #   validator.valid? # => true
  #
  # Events:
  #
  # - [:start_object]            opens an object
  # - [:key, "name"]             next value belongs to object key "name"
  # - [:scalar, value]           a complete null/boolean/number/string value
  # - [:start_array]             opens an array
  # - [:end]                     closes the innermost open container
  #                              ([:end_object] / [:end_array] are also accepted
  #                              and checked against the open container)
  #
  # Only a subset of JSON Schema can be guaranteed in a single streaming pass
  # with bounded memory (SUPPORTED_KEYWORDS). Schemas using anything else are
  # rejected when the validator is prepared (UnsupportedKeyword). Malformed
  # event streams are reported separately from schema mismatches by raising
  # StructureError; schema mismatches are collected in #errors.
  module Streaming
    EVENTS = %i[start_object key scalar start_array end].freeze

    # Keywords that can be validated incrementally with O(depth) memory.
    SUPPORTED_KEYWORDS = %w[
      type enum const
      properties required
      items minItems maxItems
      contains minContains maxContains
      minimum maximum exclusiveMinimum exclusiveMaximum
      minLength maxLength pattern
    ].freeze

    # Annotation keywords that carry no validation semantics and are ignored.
    IGNORED_KEYWORDS = %w[
      $schema $id $comment $defs definitions
      title description default examples deprecated readOnly writeOnly
    ].freeze

    JSON_POINTER_TOKEN_ESCAPE_CHARS = { '~' => '~0', '/' => '~1' }.freeze
    JSON_POINTER_TOKEN_ESCAPE_REGEX = Regexp.union(JSON_POINTER_TOKEN_ESCAPE_CHARS.keys)

    class UnsupportedKeyword < StandardError; end
    class StructureError < StandardError; end
    class IncompleteDocument < StructureError; end

    Node = Struct.new(
      :schema_pointer,
      :source_schema,
      :false_schema,
      :types,
      :enum,
      :const,
      :const_set,
      :minimum,
      :maximum,
      :exclusive_minimum,
      :exclusive_maximum,
      :min_length,
      :max_length,
      :pattern,
      :properties,
      :required,
      :items,
      :min_items,
      :max_items,
      :contains,
      :min_contains,
      :max_contains,
      :keyword_init => true
    )

    Frame = Struct.new(:node, :kind, :token, :index, :pending_key, :seen_keys, :contains_count)
    Probe = Struct.new(:validator, :frame)

    class << self
      def validator(schema, **options)
        Validator.new(schema, **options)
      end

      def escape_json_pointer_token(token)
        token.gsub(JSON_POINTER_TOKEN_ESCAPE_REGEX, JSON_POINTER_TOKEN_ESCAPE_CHARS)
      end

      def compile(schema, schema_pointer = '')
        case schema
        when Hash
          compile_hash(schema.transform_keys(&:to_s), schema_pointer)
        when false
          Node.new(:schema_pointer => schema_pointer, :source_schema => schema, :false_schema => true, :types => [], :required => [])
        when true, nil
          Node.new(:schema_pointer => schema_pointer, :source_schema => schema, :types => [], :required => [])
        else
          raise UnsupportedKeyword, "schema at #{pointer_label(schema_pointer)} must be an object or boolean"
        end
      end

    private

      def pointer_label(schema_pointer)
        schema_pointer.empty? ? 'root' : "`#{schema_pointer}`"
      end

      def container_value?(value)
        value.is_a?(Array) || value.is_a?(Hash)
      end

      def compile_hash(schema, schema_pointer)
        schema.each_key do |keyword|
          next if SUPPORTED_KEYWORDS.include?(keyword) || IGNORED_KEYWORDS.include?(keyword)
          raise UnsupportedKeyword, "keyword `#{keyword}` at #{pointer_label(schema_pointer)} cannot be guaranteed in streaming validation"
        end

        if schema['items'].is_a?(Array)
          raise UnsupportedKeyword, "tuple form of `items` at #{pointer_label(schema_pointer)} cannot be guaranteed in streaming validation"
        end

        enum = schema['enum']
        if enum.is_a?(Array) && enum.any? { |value| container_value?(value) }
          raise UnsupportedKeyword, "`enum` with container values at #{pointer_label(schema_pointer)} cannot be guaranteed in streaming validation"
        end

        if schema.key?('const') && container_value?(schema['const'])
          raise UnsupportedKeyword, "`const` with a container value at #{pointer_label(schema_pointer)} cannot be guaranteed in streaming validation"
        end

        properties = nil
        if schema['properties'].is_a?(Hash)
          properties = {}
          schema['properties'].each do |property, subschema|
            properties[property.to_s] = compile(subschema, "#{schema_pointer}/properties/#{escape_json_pointer_token(property.to_s)}")
          end
        end

        Node.new(
          :schema_pointer => schema_pointer,
          :source_schema => schema,
          :false_schema => false,
          :types => Array(schema['type']),
          :enum => enum,
          :const => schema['const'],
          :const_set => schema.key?('const'),
          :minimum => schema['minimum'],
          :maximum => schema['maximum'],
          :exclusive_minimum => schema['exclusiveMinimum'],
          :exclusive_maximum => schema['exclusiveMaximum'],
          :min_length => schema['minLength'],
          :max_length => schema['maxLength'],
          :pattern => schema['pattern'] && Regexp.new(schema['pattern']),
          :properties => properties,
          :required => Array(schema['required']).map(&:to_s),
          :items => schema.key?('items') ? compile(schema['items'], "#{schema_pointer}/items") : nil,
          :min_items => schema['minItems'],
          :max_items => schema['maxItems'],
          :contains => schema.key?('contains') ? compile(schema['contains'], "#{schema_pointer}/contains") : nil,
          :min_contains => schema['minContains'],
          :max_contains => schema['maxContains']
        )
      end
    end

    class Validator
      attr_reader :errors, :error_count

      def initialize(schema, fail_fast: false, collect_errors: true)
        @root_schema = schema
        @root_node = schema.is_a?(Node) ? schema : Streaming.compile(schema)
        @fail_fast = fail_fast
        @collect_errors = collect_errors
        @errors = []
        @error_count = 0
        @stack = []
        @probes = []
        @pointer_tokens = []
        @root_started = false
        @complete = false
        @aborted = false
      end

      def <<(event)
        return self if @aborted

        type, payload = event
        case type
        when :start_object then start_container(:object)
        when :start_array then start_container(:array)
        when :key then key(payload)
        when :scalar then scalar(payload)
        when :end then end_container(nil)
        when :end_object then end_container(:object)
        when :end_array then end_container(:array)
        else
          raise StructureError, "unknown event: #{type.inspect}"
        end
        forward_to_probes(event)
        self
      end

      def validate_events(source)
        consumed = false
        begin
          source.each do |event|
            self << event
            break if @aborted
          end
          consumed = !@aborted
        ensure
          source.close if !consumed && source.respond_to?(:close)
        end
        finish unless @aborted
        self
      end

      def finish
        raise IncompleteDocument, 'event stream ended before the document was complete' unless @complete
        self
      end

      def complete?
        @complete
      end

      def valid?
        @complete && @error_count.zero?
      end

      def aborted?
        @aborted
      end

    private

      def begin_value
        if @stack.empty?
          raise StructureError, 'multiple root values in event stream' if @root_started
          @root_started = true
          return [@root_node, nil]
        end

        frame = @stack.last
        if frame.kind == :array
          node = frame.node
          if node
            if node.max_items && frame.index == node.max_items
              record_error(node, 'maxItems', current_pointer, nil, { 'maxItems' => node.max_items })
            end
            start_probe(node, frame) if node.contains
          end
          [node && node.items, frame.index.to_s]
        else
          key = frame.pending_key
          raise StructureError, 'value event without a preceding key event' unless key
          node = frame.node
          property_node = node && node.properties ? node.properties[key] : nil
          [property_node, key]
        end
      end

      def complete_value
        if @stack.empty?
          @complete = true
          return
        end
        frame = @stack.last
        if frame.kind == :array
          frame.index += 1
        else
          frame.pending_key = nil
        end
      end

      def start_container(kind)
        node, token = begin_value
        @pointer_tokens << token if token

        effective_node = node
        if node
          if node.false_schema
            record_error(node, 'falseSchema', current_pointer, nil)
            effective_node = nil
          elsif node.types.any? && !node.types.include?(kind.to_s)
            record_error(node, type_error_type(node), current_pointer, nil)
            effective_node = nil
          end
        end

        @stack << Frame.new(effective_node, kind, token, 0, nil, kind == :object ? Set.new : nil, 0)
      end

      def end_container(kind)
        frame = @stack.last
        raise StructureError, 'end event without a matching start event' unless frame
        raise StructureError, "end_#{kind} event does not match open #{frame.kind}" if kind && frame.kind != kind
        raise StructureError, 'object ended before the value for its last key' if frame.kind == :object && frame.pending_key

        node = frame.node
        if node
          if frame.kind == :array
            check_array_bounds(node, frame)
          else
            check_required(node, frame)
          end
        end

        @stack.pop
        @pointer_tokens.pop if frame.token
        complete_value
      end

      def key(name)
        frame = @stack.last
        raise StructureError, 'key event outside of an object' unless frame && frame.kind == :object
        raise StructureError, "key event payload must be a string, got: #{name.inspect}" unless name.is_a?(String)
        raise StructureError, 'consecutive key events without a value' if frame.pending_key
        frame.pending_key = name
        frame.seen_keys << name
      end

      def scalar(value)
        unless value.nil? || value == true || value == false || value.is_a?(String) || value.is_a?(Numeric)
          raise StructureError, "scalar event payload must be a JSON scalar, got: #{value.class}"
        end
        node, token = begin_value
        validate_scalar(node, value, pointer_with(token)) if node
        complete_value
      end

      def validate_scalar(node, value, pointer)
        if node.false_schema
          record_error(node, 'falseSchema', pointer, value)
          return
        end

        record_error(node, type_error_type(node), pointer, value) if node.types.any? && !scalar_type_matches?(node.types, value)

        record_error(node, 'enum', pointer, value) if node.enum && !node.enum.include?(value)
        record_error(node, 'const', pointer, value) if node.const_set && node.const != value

        if value.is_a?(Numeric)
          record_error(node, 'minimum', pointer, value) if node.minimum && value < node.minimum
          record_error(node, 'maximum', pointer, value) if node.maximum && value > node.maximum
          record_error(node, 'exclusiveMinimum', pointer, value) if node.exclusive_minimum && value <= node.exclusive_minimum
          record_error(node, 'exclusiveMaximum', pointer, value) if node.exclusive_maximum && value >= node.exclusive_maximum
        end

        if value.is_a?(String)
          record_error(node, 'minLength', pointer, value) if node.min_length && value.length < node.min_length
          record_error(node, 'maxLength', pointer, value) if node.max_length && value.length > node.max_length
          record_error(node, 'pattern', pointer, value) if node.pattern && !node.pattern.match?(value)
        end
      end

      def check_array_bounds(node, frame)
        if node.min_items && frame.index < node.min_items
          record_error(node, 'minItems', current_pointer, nil, { 'minItems' => node.min_items, 'count' => frame.index })
        end
        return unless node.contains
        min_contains = node.min_contains || 1
        if frame.contains_count < min_contains
          type = node.min_contains.nil? && node.max_contains.nil? ? 'contains' : 'minContains'
          record_error(node, type, current_pointer, nil, { 'minContains' => min_contains, 'count' => frame.contains_count })
        elsif node.max_contains && frame.contains_count > node.max_contains
          record_error(node, 'maxContains', current_pointer, nil, { 'maxContains' => node.max_contains, 'count' => frame.contains_count })
        end
      end

      def check_required(node, frame)
        missing_keys = node.required.reject { |name| frame.seen_keys.include?(name) }
        record_error(node, 'required', current_pointer, nil, { 'missing_keys' => missing_keys }) if missing_keys.any?
      end

      def start_probe(node, frame)
        @probes << Probe.new(Validator.new(node.contains, :collect_errors => false), frame)
      end

      def forward_to_probes(event)
        @probes.each { |probe| probe.validator << event }
        while @probes.any? && @probes.last.validator.complete?
          probe = @probes.pop
          probe.frame.contains_count += 1 if probe.validator.valid?
        end
      end

      def record_error(node, type, pointer, value, details = nil)
        @error_count += 1
        if @collect_errors
          error = {
            'data' => value,
            'data_pointer' => pointer,
            'schema' => node.source_schema,
            'schema_pointer' => node.schema_pointer,
            'root_schema' => @root_schema,
            'type' => type
          }
          error['details'] = details if details
          @errors << error
        end
        @aborted = true if @fail_fast
      end

      def type_error_type(node)
        node.types.size == 1 ? node.types.first : 'type'
      end

      def scalar_type_matches?(types, value)
        types.any? do |type|
          case type
          when 'null' then value.nil?
          when 'boolean' then value == true || value == false
          when 'string' then value.is_a?(String)
          when 'number' then value.is_a?(Numeric) && !value.is_a?(Complex)
          when 'integer' then integer_value?(value)
          when 'object', 'array' then false
          else false
          end
        end
      end

      def integer_value?(value)
        case value
        when Integer then true
        when Float, BigDecimal then value.finite? && value == value.to_i
        else false
        end
      end

      def current_pointer
        pointer_with(nil)
      end

      def pointer_with(token)
        tokens = token ? @pointer_tokens + [token] : @pointer_tokens
        return '' if tokens.empty?
        tokens.map { |part| "/#{Streaming.escape_json_pointer_token(part)}" }.join
      end
    end
  end
end
