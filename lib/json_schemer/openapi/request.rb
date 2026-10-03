# frozen_string_literal: true
class JSONSchemer::OpenAPI
  ParameterSource = Struct.new(
    :location,
    :name,
    :field,
    :pair,
    :key_offset,
    :value_offset,
    :offset,
    :length,
    :raw
  ) do
    def to_h
      members.each_with_object({}) do |member, hash|
        value = self[member]
        hash[member.to_s] = value unless value.nil?
      end
    end
  end

  ParameterResult = Struct.new(:parameter, :value, :sources, :errors) do
    def present?
      !value.nil? && errors.empty?
    end
  end

  QueryField = Struct.new(:name, :value, :pair, :key_offset, :value_offset, :base_offset) do
    def base_offset
      self[:base_offset] || 0
    end
  end

  class Operation
    attr_reader :path, :method, :parameters

    def initialize(openapi, path, method, parameters)
      @openapi = openapi
      @path = path
      @method = method
      @parameters = parameters
    end

    def request(query: nil, path: nil, headers: nil)
      Request.new(self, query, path, headers)
    end
  end

  class PreparedParameter
    SUPPORTED_STYLES = {
      'query' => %w[form deepObject],
      'path' => %w[simple],
      'header' => %w[simple]
    }.freeze

    DEFAULT_STYLE = {
      'query' => 'form',
      'path' => 'simple',
      'header' => 'simple'
    }.freeze

    DEFAULT_EXPLODE = {
      'form' => true,
      'deepObject' => true,
      'simple' => false
    }.freeze

    attr_reader :name, :in, :style, :explode, :required, :allow_empty_value, :schema_pointer, :schema

    def initialize(openapi, definition, definition_pointer)
      @openapi = openapi
      @name = definition.is_a?(Hash) ? definition['name'] : definition.inspect
      @in = definition.is_a?(Hash) ? definition['in'] : nil
      unless definition.is_a?(Hash) && SUPPORTED_STYLES.key?(@in)
        raise JSONSchemer::UnsupportedOpenAPIParameterLocation,
          "unsupported parameter location: #{@in.inspect} (#{@name.inspect})"
      end
      @required = definition.fetch('required', false)
      @allow_empty_value = definition.fetch('allowEmptyValue', false)
      if definition.key?('content') || !definition.key?('schema')
        raise JSONSchemer::UnsupportedOpenAPIParameterContent,
          "parameter content is not supported (#{@name.inspect})"
      end
      @style = definition.fetch('style') { DEFAULT_STYLE.fetch(@in) }
      unless SUPPORTED_STYLES.fetch(@in).include?(@style)
        raise JSONSchemer::UnsupportedOpenAPIParameterStyle,
          "unsupported parameter style: #{@style.inspect} (#{@name.inspect})"
      end
      @explode = definition.fetch('explode') { DEFAULT_EXPLODE.fetch(@style) }
      if @style == 'deepObject' && @explode != true
        raise JSONSchemer::UnsupportedOpenAPIParameterStyle,
          "deepObject parameters must use explode: true (#{@name.inspect})"
      end

      @schema_pointer = "#{definition_pointer}/schema" if definition_pointer
      @schema = if @schema_pointer
        openapi.document_schema_for_pointer(@schema_pointer)
      else
        JSONSchemer.schema(definition.fetch('schema'))
      end
      @resolved_schema = resolve_schema(@schema)
      @type = schema_type(@resolved_schema)
      @property_names = object_property_names(@resolved_schema)
    end

    def object?
      @type == 'object'
    end

    def array?
      @type == 'array'
    end

    def property_names
      @property_names
    end

    def build_result(fields)
      Decoder.new(self, fields).decode
    end

    private

    def resolve_schema(schema)
      ref = schema.parsed['$ref']
      if ref && ref.respond_to?(:ref_schema)
        resolve_schema(ref.ref_schema)
      else
        schema
      end
    end

    def schema_type(schema)
      type_keyword = schema.parsed['type']
      parsed_type = type_keyword.parsed
      case parsed_type
      when Array
        %w[object array].find { |type| parsed_type.include?(type) }
      else
        parsed_type
      end
    end

    def object_property_names(schema)
      properties_keyword = schema.parsed['properties']
      properties = properties_keyword ? properties_keyword.parsed : nil
      properties ? properties.keys.map(&:to_s) : []
    end
  end

  class Request
    def initialize(operation, query, path, headers)
      @operation = operation
      @query_fields = parse_query(query)
      @header_fields = parse_headers(headers)
      @path_fields = parse_path(path)
    end

    def valid?
      validate.first.nil?
    end

    def validate
      Enumerator.new do |yielder|
        parameter_results.each do |result|
          result.errors.each { |error| yielder << error }
          next unless result.errors.empty?
          validate_parameter(result).each { |error| yielder << error }
        end
      end
    end

    def parameters
      parameter_results.each_with_object({}) do |result, parameters|
        if result.present?
          parameters[result.parameter.name] = Coercer.coerce(result.value, result.parameter.schema)
        end
      end
    end

    private

    def parameter_results
      @parameter_results ||= @operation.parameters.map do |parameter|
        fields = if parameter.in == 'query'
          @query_fields
        elsif parameter.in == 'header'
          @header_fields[parameter.name.downcase] || []
        else
          @path_fields[parameter.name] || []
        end
        parameter.build_result(fields)
      end
    end

    def validate_parameter(result)
      parameter = result.parameter
      return [] if result.value.nil?
      parameter.schema.validate(Coercer.coerce(result.value, parameter.schema)).map do |error|
        pointer = error['data_pointer'].to_s
        source = result.sources[pointer] || result.sources['']
        error.merge(
          'parameter' => parameter.name,
          'parameter_in' => parameter.in,
          'parameter_pointer' => parameter.schema_pointer,
          'source' => source.to_h
        )
      end
    end

    def parse_query(query)
      case query
      when nil
        []
      when String
        split_query(query)
      when Array
        query.each_with_index.flat_map do |pair, pair_index|
          name, value = pair
          Array(value).map { |item| QueryField.new(name.to_s, value_to_s(item), pair_index, nil, nil) }
        end
      when Hash
        query.flat_map do |name, value|
          Array(value).map { |item| QueryField.new(name.to_s, value_to_s(item), nil, nil, nil) }
        end
      else
        raise ArgumentError, "unsupported query input: #{query.class}"
      end
    end

    def parse_headers(headers)
      case headers
      when nil
        {}
      when Array
        headers.each_with_index.with_object({}) do |(pair, index), fields|
          name, value = pair
          (fields[name.to_s.downcase] ||= []) << QueryField.new(name.to_s, value_to_s(value), index, nil, nil)
        end
      when Hash
        headers.each_with_object({}) do |(name, value), fields|
          fields[name.to_s.downcase] = [QueryField.new(name.to_s, value_to_s(value), nil, nil, nil)]
        end
      else
        raise ArgumentError, "unsupported headers input: #{headers.class}"
      end
    end

    def value_to_s(value)
      value.to_s
    end

    def split_query(query)
      bytes = query.b.sub(/\A\?/, '')
      fields = []
      pair = 0
      position = 0
      while position <= bytes.bytesize
        amp_index = bytes.index('&', position) || bytes.bytesize
        segment = bytes.byteslice(position, amp_index - position)
        unless segment.empty?
          equal_index = segment.index('=')
          if equal_index
            name = segment.byteslice(0, equal_index)
            value = segment.byteslice(equal_index + 1, segment.bytesize - equal_index - 1)
            value_offset = position + equal_index + 1
          else
            name = segment
            value = ''.b
            value_offset = nil
          end
          fields << QueryField.new(name, value, pair, position, value_offset)
          pair += 1
        end
        break if amp_index == bytes.bytesize
        position = amp_index + 1
      end
      fields
    end

    def parse_path(path)
      return {} unless path
      names = []
      regex = template_path_regex(@operation.path, names)
      match = path.match(regex)
      raise ArgumentError, "path #{path.inspect} does not match template #{@operation.path.inspect}" unless match
      names.each_with_index.with_object({}) do |(name, index), fields|
        start = char_offset_to_byte_offset(path, match.begin(index + 1))
        fields[name] = [QueryField.new(name, match[index + 1].to_s.b, 0, nil, 0, start)]
      end
    end

    def template_path_regex(template, names)
      Regexp.new(template.split(/(\{[^}]+\})/).map do |part|
        if part.start_with?('{') && part.end_with?('}')
          names << part[1..-2]
          '([^/]+)'
        else
          Regexp.escape(part)
        end
      end.join)
    end

    def char_offset_to_byte_offset(string, character_offset)
      string[0, character_offset].bytesize
    end
  end

  class Decoder
    def initialize(parameter, fields)
      @parameter = parameter
      @fields = fields
      @sources = {}
      @errors = []
    end

    def decode
      if @parameter.in == 'query'
        decode_query
      else
        decode_simple
      end
      ParameterResult.new(@parameter, @value, @sources, @errors)
    end

    private

    def decode_query
      @parameter.style == 'deepObject' ? decode_deep_object : decode_form
    end

    def decode_form
      name_matches = @fields.reject { |field| percent_error(field.name) }
      exact = name_matches.select { |field| decoded_query_name(field) == @parameter.name }
      property_fields = if @parameter.object? && @parameter.explode
        name_matches.select do |field|
          @parameter.property_names.include?(decoded_query_name(field))
        end
      else
        []
      end
      object_fields = property_fields.reject { |field| exact.include?(field) }

      if !object_fields.empty?
        decode_form_object(object_fields)
      elsif exact.empty?
        if @parameter.required
          if (invalid = @fields.find { |field| percent_error(field.name) })
            invalid_percent!(invalid, percent_error(invalid.name), :key)
          else
            missing!
          end
        end
      elsif @parameter.array? && @parameter.explode
        decode_form_array(exact)
      elsif @parameter.array? && !@parameter.explode
        decoded, error = percent_decode(exact.first.value, true)
        if error
          invalid_percent!(exact.first, error)
        else
          if decoded.empty?
            check_empty!(exact.first)
          else
            @value, @sources = split_terms(exact.first, decoded, ',')
          end
        end
      elsif @parameter.object? && !@parameter.explode
        decoded, error = percent_decode(exact.first.value, true)
        if error
          invalid_percent!(exact.first, error)
        else
          if decoded.empty?
            check_empty!(exact.first)
          else
            @value, @sources = split_object_form(decoded, exact.first)
          end
        end
      elsif exact.size > 1
        duplicate_parameter!(exact.last)
      else
        decode_primitive(exact.first, true)
      end
    end

    def decode_form_array(matches)
      matches.each do |field|
        if field.value.empty?
          check_empty!(field)
        elsif (error = percent_error(field.value))
          invalid_percent!(field, error)
        end
      end
      return unless @errors.empty?
      @value = matches.each_with_index.map do |field, index|
        decoded = percent_decode(field.value, true).first
        @sources["/#{index}"] = make_source(field, 0, field.value.bytesize)
        decoded
      end
    end

    def decode_form_object(matches)
      object = {}
      matches.each do |field|
        property = decoded_query_name(field)
        error = percent_error(field.value)
        if error
          invalid_percent!(field, error)
        elsif object.key?(property)
          key_conflict!(field, property)
        else
          check_empty!(field)
          object[property] = percent_decode(field.value, true).first
          @sources["/#{escape(property)}"] = make_source(field, 0, field.value.bytesize)
        end
      end
      @value = object
    end

    def decode_deep_object
      prefix = "#{@parameter.name}["
      matches = @fields.select do |field|
        name = field.name.b
        name.start_with?(prefix.b) && name.getbyte(name.bytesize - 1) == ']'.ord
      end
      if matches.empty?
        missing! if @parameter.required
        return
      end
      object = {}
      matches.each do |field|
        raw_name = field.name.b
        raw_key = raw_name.byteslice(prefix.bytesize, raw_name.bytesize - prefix.bytesize - 1)
        key_error = percent_error(raw_key)
        value_error = percent_error(field.value)
        decoded_key = percent_decode(raw_key, true).first
        if key_error
          invalid_percent!(field, key_error, :key)
        elsif value_error
          invalid_percent!(field, value_error, :value)
        elsif object.key?(decoded_key)
          key_conflict!(field, decoded_key)
        else
          check_empty!(field)
          object[decoded_key] = percent_decode(field.value, true).first
          @sources["/#{escape(decoded_key)}"] = make_source(field, 0, field.value.bytesize)
        end
      end
      @value = object
    end

    def decode_simple
      if @fields.empty?
        missing! if @parameter.required
        return
      end
      field = @fields.first
      if @fields.size > 1
        duplicate_parameter!(field)
        return
      end
      error = percent_error(field.value)
      if error
        invalid_percent!(field, error)
        return
      end
      decoded = percent_decode(field.value, false).first
      check_empty!(field)
      return unless @errors.empty?
      if @parameter.array?
        @value, @sources = split_terms(field, decoded, ',')
      elsif @parameter.object?
        @value, @sources = split_object_simple(decoded, field)
      else
        @value = decoded
        @sources[''] = make_source(field, 0, field.value.bytesize)
      end
    end

    def decode_primitive(field, form)
      error = percent_error(field.value)
      if error
        invalid_percent!(field, error)
        return
      end
      check_empty!(field)
      return unless @errors.empty?
      @value = percent_decode(field.value, form).first
      @sources[''] = make_source(field, 0, field.value.bytesize)
    end

    def split_terms(field, decoded, delimiter)
      values = []
      sources = {}
      offset = 0
      decoded.b.split(delimiter, -1).each_with_index do |term, index|
        values << term.force_encoding(Encoding::UTF_8)
        sources["/#{index}"] = make_source(field, offset, term.bytesize)
        offset += term.bytesize + delimiter.bytesize
      end
      [values, sources]
    end

    def split_object_form(decoded, field)
      split_key_value_tokens(decoded, field, ',')
    end

    def split_object_simple(decoded, field)
      @parameter.explode ? split_key_value_pairs(decoded, field) : split_key_value_tokens(decoded, field, ',')
    end

    # non-explode objects: key,value,key,value separated by commas
    def split_key_value_tokens(decoded, field, _property_delimiter)
      object = {}
      sources = {}
      offset = 0
      tokens = decoded.split(',', -1)
      tokens.each_slice(2) do |key, value|
        if value.nil?
          invalid_structure!(field, offset, key.bytesize)
        else
          duplicate = object.key?(key)
          object[key] = value
          sources["/#{escape(key)}"] = make_source(field, offset, key.bytesize + 1 + value.bytesize)
          key_conflict!(field, key) if duplicate
        end
        offset += key.bytesize + 1 + (value&.bytesize || 0) + 1
      end
      [object, sources]
    end

    # explode simple objects: key=value pairs separated by commas
    def split_key_value_pairs(decoded, field)
      object = {}
      sources = {}
      offset = 0
      decoded.split(',', -1).each do |pair|
        key, value = pair.split('=', 2)
        if value.nil?
          invalid_structure!(field, offset, pair.bytesize)
        else
          duplicate = object.key?(key)
          object[key] = value
          sources["/#{escape(key)}"] = make_source(field, offset, pair.bytesize)
          key_conflict!(field, key) if duplicate
        end
        offset += pair.bytesize + 1
      end
      [object, sources]
    end

    def percent_decode(value, form)
      bytes = value.b
      out = String.new.b
      index = 0
      while index < bytes.bytesize
        byte = bytes.getbyte(index)
        if form && byte == '+'.ord
          out << ' '.ord
          index += 1
        elsif byte == '%'.ord
          hex = bytes.byteslice(index + 1, 2)
          if hex.nil? || !hex.match?(/\A[0-9a-fA-F]{2}\z/)
            return [nil, index]
          end
          out << hex.to_i(16)
          index += 3
        else
          out << byte
          index += 1
        end
      end
      [out.force_encoding(Encoding::UTF_8), nil]
    end

    def percent_error(value)
      percent_decode(value, @parameter.in == 'query').last
    end

    def decoded_query_name(field)
      percent_decode(field.name, true).first
    end

    def check_empty!(field)
      return unless field.value.empty?
      return if @parameter.in == 'query' && @parameter.allow_empty_value
      @errors << error_hash('empty_value', field, 0, 0, "parameter '#{@parameter.name}' is empty")
    end

    def missing!
      @errors << error_hash(nil, nil, nil, nil, "missing required parameter '#{@parameter.name}'", 'missing_parameter')
    end

    def duplicate_parameter!(field)
      @errors << error_hash('duplicate_parameter', field, 0, field.value.bytesize, "duplicate parameter '#{@parameter.name}'")
    end

    def key_conflict!(field, key)
      @errors << error_hash('object_key_conflict', field, 0, field.value.bytesize, "duplicate object key #{key.inspect} for parameter '#{@parameter.name}'")
    end

    def invalid_percent!(field, offset, part = :value)
      base = part == :key ? field.key_offset : (field.value_offset || field.base_offset)
      @errors << error_hash('invalid_percent_encoding', field, base + offset, 1, "invalid percent encoding in parameter '#{@parameter.name}'")
    end

    def invalid_structure!(field, offset, length)
      @errors << error_hash('invalid_parameter_value', field, field.value_offset.to_i + offset, length, "malformed object parameter '#{@parameter.name}'")
    end

    def error_hash(type, field, offset, length, message, error_type = nil)
      hash = {
        'data' => nil,
        'data_pointer' => '',
        'schema' => @parameter.schema.value,
        'schema_pointer' => @parameter.schema_pointer,
        'root_schema' => @parameter.schema.root.value,
        'type' => error_type || type,
        'error' => message,
        'parameter' => @parameter.name,
        'parameter_in' => @parameter.in,
        'parameter_pointer' => @parameter.schema_pointer
      }
      if field
        hash['source'] = error_source(field, offset, length).to_h
      end
      hash
    end

    def error_source(field, absolute_offset, length)
      ParameterSource.new(
        @parameter.in,
        @parameter.name,
        nil,
        field.pair,
        field.key_offset,
        field.value_offset,
        absolute_offset,
        length,
        field.value.dup.force_encoding(Encoding::UTF_8)
      )
    end

    def make_source(field, offset, length)
      absolute = field.value_offset.nil? ? field.base_offset + offset : field.value_offset + offset
      ParameterSource.new(
        @parameter.in,
        @parameter.name,
        nil,
        field.pair,
        field.key_offset,
        field.value_offset,
        absolute,
        length,
        field.value.dup.force_encoding(Encoding::UTF_8)
      )
    end

    def escape(token)
      JSONSchemer::Location.escape_json_pointer_token(token)
    end
  end

  class Coercer
    class << self
      def coerce(value, schema)
        resolve(schema) { |resolved| coerce_value(value, resolved) }
      end

      private

      def resolve(schema)
        ref = schema.parsed['$ref']
        if ref && ref.respond_to?(:ref_schema)
          resolve(ref.ref_schema) { |resolved| yield(resolved) }
        else
          yield(schema)
        end
      end

      def coerce_value(value, schema)
        case value
        when Array
          item_schema = schema.parsed['items']&.parsed
          item_schema ? value.map { |item| coerce(item, item_schema) } : value
        when Hash
          properties = schema.parsed['properties']&.parsed
          return value unless properties
          value.each_with_object({}) do |(key, item), out|
            property_schema = properties[key]
            out[key] = property_schema ? coerce(item, property_schema) : item
          end
        when String
          coerce_scalar(value, schema)
        else
          value
        end
      end

      def coerce_scalar(value, schema)
        type_keyword = schema.parsed['type']
        types = type_keyword ? Array(type_keyword.parsed) : []
        if types.include?('integer') && (integer = to_integer(value))
          integer
        elsif types.include?('number') && (number = to_number(value))
          number
        elsif types.include?('boolean') && boolean?(value)
          value == 'true'
        else
          value
        end
      end

      def to_integer(value)
        value.match?(/\A-?\d+\z/) ? value.to_i : nil
      end

      def to_number(value)
        value.match?(/\A-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\z/) ? Float(value) : nil
      end

      def boolean?(value)
        value == 'true' || value == 'false'
      end
    end
  end
end
