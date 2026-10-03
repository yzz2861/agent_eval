# frozen_string_literal: true
module JSONSchemer
  class OpenAPI
    # Validates HTTP request parameters (query, path, and header) against the
    # parameter definitions of a single OpenAPI operation.
    #
    # Supported serialization styles (https://spec.openapis.org/oas/v3.1.0#style-values):
    #
    # - query: `form` (default) and `deepObject`
    # - path: `simple` (default)
    # - header: `simple` (default)
    #
    # Each style honors its `explode` setting. Unsupported styles, locations,
    # and `deepObject` with `explode: false` are reported when the operation
    # is prepared. Raw inputs keep duplicate fields and their original
    # (encoded) positions so that missing parameters, empty values, invalid
    # percent-encoding, and object key conflicts can be told apart.
    class Operation
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

      INVALID_PERCENT_ENCODING = /%(?![0-9A-Fa-f]{2})/n
      PERCENT_ENCODED_BYTE = /%([0-9A-Fa-f]{2})/n
      INTEGER_PATTERN = /\A[+-]?\d+\z/

      Pair = Struct.new(:name, :value, :position)

      class Parameter
        attr_reader :name, :location, :style, :explode, :schema, :schemer

        def initialize(name, location, style, explode, required, schema, schemer)
          @name = name
          @location = location
          @style = style
          @explode = explode
          @required = required
          @schema = schema
          @schemer = schemer
        end

        def required?
          @required
        end

        def shape
          @shape ||= begin
            types = Array(schema['type'])
            if types.include?('array') || schema.key?('items')
              :array
            elsif types.include?('object') || schema.key?('properties')
              :object
            else
              :primitive
            end
          end
        end

        def property_names
          properties = schema['properties']
          properties.is_a?(Hash) ? properties.keys : []
        end

        def deep_object_key(pair_name)
          match = deep_object_regex.match(pair_name)
          match && match[1]
        end

        def owns_pair_name?(pair_name)
          if style == 'deepObject'
            !deep_object_key(pair_name).nil?
          elsif shape == :object && explode
            property_names.include?(pair_name)
          else
            pair_name == name
          end
        end

      private

        def deep_object_regex
          @deep_object_regex ||= /\A#{Regexp.escape(name)}\[([^\[\]]+)\]\z/
        end
      end

      attr_reader :parameters

      def initialize(document_schema, document, path, method)
        paths = document['paths']
        raise UnknownOperation, path.to_s unless paths.is_a?(Hash)
        path_item = paths[path]
        raise UnknownOperation, path.to_s unless path_item.is_a?(Hash)
        method = method.to_s.downcase
        operation = path_item[method]
        raise UnknownOperation, "#{method.upcase} #{path}" unless operation.is_a?(Hash)

        parameters = {}
        escaped_path = escape_pointer(path)
        collect_parameters(document_schema, path_item, "/paths/#{escaped_path}/parameters", parameters)
        collect_parameters(document_schema, operation, "/paths/#{escaped_path}/#{method}/parameters", parameters)
        @parameters = parameters.values
      end

      def valid?(query: nil, path: nil, headers: nil)
        validate(:query => query, :path => path, :headers => headers).empty?
      end

      def validate(query: nil, path: nil, headers: nil)
        errors = []
        query_pairs, invalid_query_names = tokenize_query(query, errors)
        query_pairs_by_name = query_pairs.group_by(&:name)
        path_values = index_values(path)
        header_values = index_header_values(headers)

        parameters.each do |parameter|
          case parameter.location
          when 'query'
            validate_query_parameter(parameter, query_pairs, query_pairs_by_name, invalid_query_names, errors)
          when 'path'
            raw = path_values[parameter.name]
            if raw.nil?
              missing_parameter(parameter, errors)
            else
              validate_simple_parameter(parameter, raw, errors) { |segment| percent_decode(segment, false) }
            end
          when 'header'
            raws = header_values[parameter.name.downcase]
            if raws.empty?
              missing_parameter(parameter, errors)
            else
              validate_simple_parameter(parameter, raws.join(','), errors) { |segment| segment }
            end
          end
        end
        errors
      end

    private

      def collect_parameters(document_schema, container, pointer_base, parameters)
        definitions = container['parameters']
        return unless definitions.is_a?(Array)
        definitions.each_with_index do |definition, index|
          pointer_ref = "##{JSONSchemer::URI_PARSER.escape("#{pointer_base}/#{index}")}"
          seen = {}
          while definition.is_a?(Hash) && (ref = definition['$ref']).is_a?(String) && !seen.key?(ref)
            seen[ref] = true
            definition = document_schema.ref(ref).value
            pointer_ref = ref
          end
          unless definition.is_a?(Hash) && definition['name'].is_a?(String) && definition['in'].is_a?(String)
            raise InvalidParameter, pointer_ref
          end
          parameter = build_parameter(document_schema, definition, pointer_ref)
          parameters[[parameter.name, parameter.location]] = parameter
        end
      end

      def build_parameter(document_schema, definition, pointer_ref)
        name = definition['name']
        location = definition['in']
        unless SUPPORTED_STYLES.key?(location)
          raise UnsupportedParameterLocation, "unsupported location `#{location}` for parameter `#{name}`"
        end
        style = definition['style'] || DEFAULT_STYLE.fetch(location)
        unless SUPPORTED_STYLES.fetch(location).include?(style)
          raise UnsupportedParameterStyle, "unsupported style `#{style}` for #{location} parameter `#{name}`"
        end
        explode = definition.key?('explode') ? definition['explode'] : DEFAULT_EXPLODE.fetch(style)
        if style == 'deepObject' && !explode
          raise UnsupportedParameterStyle, "unsupported explode `false` for deepObject parameter `#{name}`"
        end
        schemer = definition.key?('schema') ? document_schema.ref("#{pointer_ref}/schema") : nil
        schema = schemer ? effective_schema(schemer) : {}
        Parameter.new(name, location, style, explode, definition['required'] == true, schema, schemer)
      end

      def effective_schema(schemer)
        seen = {}
        while schemer.value.is_a?(Hash) && schemer.value.key?('$ref')
          location = schemer.absolute_keyword_location
          break if seen.key?(location)
          seen[location] = true
          schemer = schemer.parsed.fetch('$ref').ref_schema
        end
        schemer.value.is_a?(Hash) ? schemer.value : {}
      end

      def validate_query_parameter(parameter, pairs, pairs_by_name, invalid_names, errors)
        return if invalid_names.any? { |name| parameter.owns_pair_name?(name) }
        if parameter.style == 'deepObject'
          validate_deep_object_parameter(parameter, pairs, errors)
        else
          validate_form_parameter(parameter, pairs_by_name, errors)
        end
      end

      def validate_form_parameter(parameter, pairs_by_name, errors)
        case parameter.shape
        when :array
          pairs = pairs_by_name.fetch(parameter.name, [])
          return missing_parameter(parameter, errors) if pairs.empty?
          values = parameter.explode ? pairs.map(&:value) : pairs.first.value.split(',', -1)
          finish_parameter(parameter, values, errors)
        when :object
          if parameter.explode
            object = {}
            parameter.property_names.each do |property|
              property_pairs = pairs_by_name.fetch(property, [])
              if property_pairs.size > 1
                errors << key_conflict_error(parameter, property)
                return
              elsif property_pairs.size == 1
                object[property] = property_pairs.first.value
              end
            end
            return missing_parameter(parameter, errors) if object.empty?
            finish_parameter(parameter, object, errors)
          else
            pairs = pairs_by_name.fetch(parameter.name, [])
            return missing_parameter(parameter, errors) if pairs.empty?
            object = parse_object_segments(parameter, pairs.first.value.split(',', -1), errors)
            finish_parameter(parameter, object, errors) if object
          end
        else
          pairs = pairs_by_name.fetch(parameter.name, [])
          return missing_parameter(parameter, errors) if pairs.empty?
          finish_parameter(parameter, pairs.first.value, errors)
        end
      end

      def validate_deep_object_parameter(parameter, pairs, errors)
        object = {}
        pairs.each do |pair|
          key = parameter.deep_object_key(pair.name)
          next unless key
          if object.key?(key)
            errors << key_conflict_error(parameter, key)
            return
          end
          object[key] = pair.value
        end
        return missing_parameter(parameter, errors) if object.empty?
        finish_parameter(parameter, object, errors)
      end

      def validate_simple_parameter(parameter, raw, errors, &decode)
        case parameter.shape
        when :array
          values = decode_segments(parameter, raw.split(',', -1), errors, &decode) or return
          finish_parameter(parameter, values, errors)
        when :object
          if parameter.explode
            object = {}
            raw.split(',', -1).each do |segment|
              raw_key, separator, raw_value = segment.partition('=')
              if separator.empty?
                errors << invalid_object_error(parameter)
                return
              end
              key = decode.call(raw_key)
              value = decode.call(raw_value)
              if key.nil? || value.nil?
                errors << invalid_percent_encoding_error(parameter)
                return
              end
              if object.key?(key)
                errors << key_conflict_error(parameter, key)
                return
              end
              object[key] = value
            end
            finish_parameter(parameter, object, errors)
          else
            values = decode_segments(parameter, raw.split(',', -1), errors, &decode) or return
            object = parse_object_segments(parameter, values, errors) or return
            finish_parameter(parameter, object, errors)
          end
        else
          value = decode.call(raw)
          if value.nil?
            errors << invalid_percent_encoding_error(parameter)
          else
            finish_parameter(parameter, value, errors)
          end
        end
      end

      def decode_segments(parameter, segments, errors, &decode)
        segments.map do |segment|
          decoded = decode.call(segment)
          if decoded.nil?
            errors << invalid_percent_encoding_error(parameter)
            return
          end
          decoded
        end
      end

      def parse_object_segments(parameter, segments, errors)
        if segments.size.odd?
          errors << invalid_object_error(parameter)
          return
        end
        object = {}
        segments.each_slice(2) do |key, value|
          if object.key?(key)
            errors << key_conflict_error(parameter, key)
            return
          end
          object[key] = value
        end
        object
      end

      def missing_parameter(parameter, errors)
        if parameter.required?
          errors << {
            'type' => 'required',
            'parameter' => parameter.name,
            'in' => parameter.location,
            'error' => "missing required #{parameter.location} parameter `#{parameter.name}`"
          }
        end
        nil
      end

      def finish_parameter(parameter, value, errors)
        return unless parameter.schemer
        parameter.schemer.validate(coerce(value, parameter.schema)).each do |error|
          errors << error.merge('parameter' => parameter.name, 'in' => parameter.location)
        end
        nil
      end

      def coerce(value, schema)
        return value unless schema.is_a?(Hash)
        case value
        when Hash
          properties = schema['properties']
          return value unless properties.is_a?(Hash)
          value.to_h { |key, item| [key, coerce(item, properties[key])] }
        when Array
          items = schema['items']
          return value unless items.is_a?(Hash)
          value.map { |item| coerce(item, items) }
        else
          coerce_scalar(value, schema)
        end
      end

      def coerce_scalar(value, schema)
        types = Array(schema['type'])
        if types.include?('integer')
          value.match?(INTEGER_PATTERN) ? value.to_i : value
        elsif types.include?('number')
          Float(value, exception: false) || value
        elsif types.include?('boolean')
          value == 'true' ? true : value == 'false' ? false : value
        else
          value
        end
      end

      def tokenize_query(query, errors)
        return [[], []] if query.nil?
        raw_pairs = query.is_a?(String) ? split_query_string(query) : query.to_a
        pairs = []
        invalid_names = []
        raw_pairs.each_with_index do |(raw_name, raw_value), position|
          raw_name = raw_name.to_s
          next if raw_name.empty?
          name = percent_decode(raw_name, true)
          value = percent_decode(raw_value.to_s, true)
          if name.nil? || value.nil?
            error = {
              'type' => 'invalid_percent_encoding',
              'in' => 'query',
              'position' => position,
              'error' => "invalid percent-encoding in query parameter at position #{position}"
            }
            if name
              error['parameter'] = name
              invalid_names << name
            end
            errors << error
          else
            pairs << Pair.new(name, value, position)
          end
        end
        [pairs, invalid_names]
      end

      def split_query_string(query)
        query.sub(/\A\?/, '').split('&', -1).map { |segment| segment.split('=', 2) }
      end

      def index_values(input)
        return {} if input.nil?
        pairs = input.is_a?(Hash) ? input.to_a : input
        pairs.each_with_object({}) do |(key, value), out|
          out[key.to_s] = value.to_s
        end
      end

      def index_header_values(input)
        values = Hash.new { |hash, key| hash[key] = [] }
        return values if input.nil?
        pairs = input.is_a?(Hash) ? input.to_a : input
        pairs.each_with_object(values) do |(key, value), out|
          out[key.to_s.downcase] << value.to_s
        end
      end

      def percent_decode(raw, plus_as_space)
        source = raw.b
        source = source.tr('+', ' ') if plus_as_space
        return if source.match?(INVALID_PERCENT_ENCODING)
        decoded = source.gsub(PERCENT_ENCODED_BYTE) { [::Regexp.last_match(1)].pack('H2') }
        decoded.force_encoding(Encoding::UTF_8)
        decoded if decoded.valid_encoding?
      end

      def escape_pointer(path)
        path.to_s.gsub('~', '~0').gsub('/', '~1')
      end

      def invalid_percent_encoding_error(parameter)
        {
          'type' => 'invalid_percent_encoding',
          'parameter' => parameter.name,
          'in' => parameter.location,
          'error' => "invalid percent-encoding in #{parameter.location} parameter `#{parameter.name}`"
        }
      end

      def invalid_object_error(parameter)
        {
          'type' => 'invalid_object',
          'parameter' => parameter.name,
          'in' => parameter.location,
          'error' => "invalid object serialization for #{parameter.location} parameter `#{parameter.name}`"
        }
      end

      def key_conflict_error(parameter, key)
        {
          'type' => 'key_conflict',
          'parameter' => parameter.name,
          'in' => parameter.location,
          'key' => key,
          'error' => "conflicting values for key `#{key}` of #{parameter.location} parameter `#{parameter.name}`"
        }
      end
    end
  end
end
