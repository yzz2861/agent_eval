# frozen_string_literal: true

require_relative 'bad_request'
require 'uri'

module Rack
  class QueryParser
    DEFAULT_SEP = /& */n
    COMMON_SEP = { ";" => /; */n, ";," => /[;,] */n, "&" => /& */n }
    DUPLICATE_SCALAR_REJECT = :reject
    DUPLICATE_SCALAR_FIRST = :first
    DUPLICATE_SCALAR_LAST = :last
    DUPLICATE_SCALAR_HANDLINGS = {
      nil => :overwrite,
      reject: DUPLICATE_SCALAR_REJECT,
      first: DUPLICATE_SCALAR_FIRST,
      last: DUPLICATE_SCALAR_LAST,
    }.freeze

    # ParameterTypeError is the error that is raised when incoming structural
    # parameters (parsed by parse_nested_query) contain conflicting types.
    class ParameterTypeError < TypeError
      include BadRequest
    end

    class ConflictingParameterError < ParameterTypeError
      attr_reader :parameter_name, :first_position, :second_position

      def initialize(message, parameter_name:, first_position:, second_position:)
        super(message)
        @parameter_name = parameter_name
        @first_position = first_position
        @second_position = second_position
      end
    end

    # InvalidParameterError is the error that is raised when incoming structural
    # parameters (parsed by parse_nested_query) contain invalid format or byte
    # sequence.
    class InvalidParameterError < ArgumentError
      include BadRequest
    end

    # QueryLimitError is for errors raised when the query provided exceeds one
    # of the query parser limits.
    class QueryLimitError < RangeError
      include BadRequest
    end

    class IncompatibleEncodingError < EncodingError
      include BadRequest
    end

    class DuplicateParameterError < InvalidParameterError
      attr_reader :parameter_name, :first_position, :second_position

      def initialize(message, parameter_name:, first_position:, second_position:)
        super(message)
        @parameter_name = parameter_name
        @first_position = first_position
        @second_position = second_position
      end
    end

    DuplicateScalarParameterError = DuplicateParameterError

    class NormalizationContext # :nodoc: all
      attr_reader :duplicate_scalar_handling, :structural_assignment_handling

      def initialize(duplicate_scalar_handling, structural_assignment_handling = duplicate_scalar_handling)
        @duplicate_scalar_handling = duplicate_scalar_handling
        @structural_assignment_handling = structural_assignment_handling
        @assignments = {}
      end

      def location_for(params, key)
        @assignments.dig(params.object_id, key)
      end

      def register!(params, key, type, position, parameter_name)
        @assignments[params.object_id] ||= {}
        @assignments[params.object_id][key] = [type, position, parameter_name]
      end
    end

    # ParamsTooDeepError is the old name for the error that is raised when params
    # are recursively nested over the specified limit. Make it the same as
    # as QueryLimitError, so that code that rescues ParamsTooDeepError error
    # to handle bad query strings also now handles other limits.
    ParamsTooDeepError = QueryLimitError

    def self.make_default(param_depth_limit, **options)
      new(Params, param_depth_limit, **options)
    end

    attr_reader :param_depth_limit, :duplicate_scalar_handling

    env_int = lambda do |key, val|
      if str_val = ENV[key]
        begin
          val = Integer(str_val, 10)
        rescue ArgumentError
          raise ArgumentError, "non-integer value provided for environment variable #{key}"
        end
      end

      val if val >= 0
    end

    BYTESIZE_LIMIT = env_int.call("RACK_QUERY_PARSER_BYTESIZE_LIMIT", 4194304)
    private_constant :BYTESIZE_LIMIT

    PARAMS_LIMIT = env_int.call("RACK_QUERY_PARSER_PARAMS_LIMIT", 4096)
    private_constant :PARAMS_LIMIT

    attr_reader :bytesize_limit

    def initialize(
      params_class,
      param_depth_limit,
      bytesize_limit: BYTESIZE_LIMIT,
      params_limit: PARAMS_LIMIT,
      duplicate_scalar_handling: nil
    )
      @params_class = params_class
      @param_depth_limit = param_depth_limit
      @bytesize_limit = bytesize_limit
      @params_limit = params_limit
      @duplicate_scalar_handling = duplicate_scalar_handling
    end

    # Stolen from Mongrel, with some small modifications:
    # Parses a query string by breaking it up at the '&'.  You can also use this
    # to parse cookies by changing the characters used in the second parameter
    # (which defaults to '&').
    def parse_query(qs, separator = nil, &unescaper)
      params = make_params

      each_query_pair(qs, separator, unescaper) do |k, v|
        if cur = params[k]
          if cur.class == Array
            params[k] << v
          else
            params[k] = [cur, v]
          end
        else
          params[k] = v
        end
      end

      return params.to_h
    end

    # Parses a query string by breaking it up at the '&', returning all key-value
    # pairs as an array of [key, value] arrays. Unlike parse_query, this preserves
    # all duplicate keys rather than collapsing them.
    def parse_query_pairs(qs, separator = nil)
      pairs = []

      each_query_pair(qs, separator) do |k, v|
        pairs << [k, v]
      end

      pairs
    end

    # parse_nested_query expands a query string into structural types. Supported
    # types are Arrays, Hashes and basic value types. It is possible to supply
    # query strings with parameters of conflicting types, in this case a
    # ParameterTypeError is raised. Users are encouraged to return a 400 in this
    # case.
    # +duplicate_scalar_handling+ can be +:reject+, +:first+, or +:last+. The
    # default of +nil+ preserves historical query parser behavior.
    def parse_nested_query(qs, separator = nil, duplicate_scalar_handling: @duplicate_scalar_handling)
      params = make_params
      context = make_normalize_context(duplicate_scalar_handling)
      position = 0

      each_query_pair(qs, separator) do |k, v|
        position += 1
        _normalize_params(params, k, v, 0, nil, nil, position, context)
      end

      return params.to_h
    end

    # normalize_params recursively expands parameters into structural types. If
    # the structural types represented by two different parameter names are in
    # conflict, a ParameterTypeError is raised.  The depth argument is deprecated
    # and should no longer be used, it is kept for backwards compatibility with
    # earlier versions of rack.
    def normalize_params(
      params,
      name,
      v,
      _depth = nil,
      position: nil,
      context: nil,
      duplicate_scalar_handling: @duplicate_scalar_handling
    )
      context ||= make_normalize_context(duplicate_scalar_handling)
      result = _normalize_params(params, name, v, 0, nil, nil, position, context)
      result.equal?(SKIP_ASSIGNMENT) ? params : result
    end

    def make_normalize_context(duplicate_scalar_handling = @duplicate_scalar_handling)
      handling = self.class.send(:duplicate_scalar_handling_for, duplicate_scalar_handling)
      structural_handling = handling == :overwrite ? :overwrite : handling
      NormalizationContext.new(handling, structural_handling)
    end

    SKIP_ASSIGNMENT = :skip_assignment
    private_constant :SKIP_ASSIGNMENT

    private def _normalize_params(params, name, v, depth, full_parameter_name, path, position, context)
      raise ParamsTooDeepError if depth >= param_depth_limit
      full_parameter_name = name.to_s if depth == 0

      if !name
        # nil name, treat same as empty string (required by tests)
        k = after = ''
      elsif depth == 0
        # Start of parsing, don't treat [] or [ at start of string specially
        if start = name.index('[', 1)
          # Start of parameter nesting, use part before brackets as key
          k = name[0, start]
          after = name[start, name.length]
        else
          # Plain parameter with no nesting
          k = name
          after = ''
        end
      elsif name.start_with?('[]')
        # Array nesting
        k = '[]'
        after = name[2, name.length]
      elsif name.start_with?('[') && (start = name.index(']', 1))
        # Hash nesting, use the part inside brackets as the key
        k = name[1, start-1]
        after = name[start+1, name.length]
      else
        # Probably malformed input, nested but not starting with [
        # treat full name as key for backwards compatibility.
        k = name
        after = ''
      end

      return if k.empty?

      if after == ''
        if k == '[]' && depth != 0
          return [v]
        else
          assign_scalar(params, k, v, position, full_parameter_name, context)
        end
      elsif after == "["
        assign_scalar(params, name, v, position, full_parameter_name, context)
      elsif after == "[]"
        container_name = nested_parameter_name(path, depth, k)
        array = use_array(params, k, position, container_name, context) or return SKIP_ASSIGNMENT
        array << v
      elsif after.start_with?('[]')
        # Recognize x[][y] (hash inside array) parameters
        unless after[2] == '[' && after.end_with?(']') && (child_key = after[3, after.length-4]) && !child_key.empty? && !child_key.index('[') && !child_key.index(']')
          # Handle other nested array parameters
          child_key = after[2, after.length]
        end
        container_name = nested_parameter_name(path, depth, k)
        array = use_array(params, k, position, container_name, context) or return SKIP_ASSIGNMENT
        if params_hash_type?(array.last) && !params_hash_has_key?(array.last, child_key)
          result = _normalize_params(array.last, child_key, v, depth + 1, full_parameter_name, "#{container_name}[]", position, context)
          return SKIP_ASSIGNMENT if result.equal?(SKIP_ASSIGNMENT)
        else
          child_params = make_params
          result = _normalize_params(child_params, child_key, v, depth + 1, full_parameter_name, "#{container_name}[]", position, context)
          return SKIP_ASSIGNMENT if result.equal?(SKIP_ASSIGNMENT)
          array << (child_params.empty? ? result : child_params)
        end
      else
        child_name = nested_parameter_name(path, depth, k)
        child_params = use_params_hash(params, k, position, child_name, context) or return SKIP_ASSIGNMENT
        result = _normalize_params(child_params, after, v, depth + 1, full_parameter_name, child_name, position, context)
        return SKIP_ASSIGNMENT if result.equal?(SKIP_ASSIGNMENT)
      end

      params
    rescue Encoding::CompatibilityError
      raise IncompatibleEncodingError
    end

    private def assign_scalar(params, key, value, position, parameter_name, context)
      existing = context.location_for(params, key)

      if existing
        existing_type, existing_position, existing_name = existing

        if existing_type == :scalar
          case context.duplicate_scalar_handling
          when :first
            return
          when :reject
            raise_duplicate_parameter(existing_name || parameter_name, existing_position, position)
          end
        else
          case context.structural_assignment_handling
          when :first
            return SKIP_ASSIGNMENT
          when :reject
            raise_conflicting_parameter(existing_name || parameter_name, existing_position, position)
          end
        end
      end

      params[key] = value
      context.register!(params, key, :scalar, position, parameter_name)
    end

    private def nested_parameter_name(parameter_name, depth, key)
      return key if depth.zero? || parameter_name.nil?
      "#{parameter_name}[#{key}]"
    end

    private def use_array(params, key, position, parameter_name, context)
      existing = context.location_for(params, key)

      if existing
        array = params[key]
        return array if array.is_a?(Array)

        case context.structural_assignment_handling
        when :first
          return nil
        when :reject
          _, existing_position, existing_name = existing
          raise_conflicting_parameter(existing_name || parameter_name, existing_position, position)
        when :overwrite
          raise ParameterTypeError, "expected Array (got #{array.class.name}) for param `#{key}'"
        end
      end

      array = []
      params[key] = array
      context.register!(params, key, :array, position, parameter_name)
      array
    end

    private def use_params_hash(params, key, position, parameter_name, context)
      existing = context.location_for(params, key)

      if existing
        child_params = params[key]
        return child_params if params_hash_type?(child_params)

        case context.structural_assignment_handling
        when :first
          return nil
        when :reject
          _, existing_position, existing_name = existing
          raise_conflicting_parameter(existing_name || parameter_name, existing_position, position)
        when :overwrite
          raise ParameterTypeError, "expected Hash (got #{child_params.class.name}) for param `#{key}'"
        end
      end

      child_params = make_params
      params[key] = child_params
      context.register!(params, key, :hash, position, parameter_name)
      child_params
    end

    private def raise_duplicate_parameter(parameter_name, first_position, second_position)
      raise DuplicateParameterError.new(
        "duplicate scalar parameter `#{parameter_name}' assigned at positions #{first_position} and #{second_position}",
        parameter_name: parameter_name,
        first_position: first_position,
        second_position: second_position
      )
    end

    private def raise_conflicting_parameter(parameter_name, first_position, second_position)
      message =
        "conflicting parameter types for `#{parameter_name}' " \
        "assigned at positions #{first_position} and #{second_position}"
      raise ConflictingParameterError.new(
        message,
        parameter_name: parameter_name,
        first_position: first_position,
        second_position: second_position
      )
    end

    def self.duplicate_scalar_handling_for(value)
      value = value.to_sym if value.respond_to?(:to_sym)
      handling = DUPLICATE_SCALAR_HANDLINGS.fetch(value, nil)
      return handling if handling

      raise ArgumentError,
        "invalid duplicate scalar handling: #{value.inspect} " \
        "(expected nil, :reject, :first, or :last)"
    end
    private_class_method :duplicate_scalar_handling_for

    def make_params
      @params_class.new
    end

    def new_depth_limit(param_depth_limit)
      self.class.new(
        @params_class,
        param_depth_limit,
        bytesize_limit: @bytesize_limit,
        params_limit: @params_limit,
        duplicate_scalar_handling: @duplicate_scalar_handling
      )
    end

    private

    def params_hash_type?(obj)
      obj.kind_of?(@params_class)
    end

    def params_hash_has_key?(hash, key)
      return false if /\[\]/.match?(key)

      key.split(/[\[\]]+/).inject(hash) do |h, part|
        next h if part == ''
        return false unless params_hash_type?(h) && h.key?(part)
        h[part]
      end

      true
    end

    def each_query_pair(qs, separator, unescaper = nil)
      return if !qs || qs.empty?

      if @bytesize_limit && qs.bytesize > @bytesize_limit
        raise QueryLimitError, "total query size exceeds limit (#{@bytesize_limit})"
      end

      sep = separator ? (COMMON_SEP[separator] || /[#{separator}] */n) : DEFAULT_SEP
      pairs = @params_limit ? qs.split(sep, @params_limit + 1) : qs.split(sep)

      if @params_limit && pairs.size > @params_limit
        param_count = pairs.size + pairs.last.count(separator || "&")
        raise QueryLimitError, "total number of query parameters (#{param_count}) exceeds limit (#{@params_limit})"
      end

      if unescaper
        pairs.each do |p|
          next if p.empty?
          k, v = p.split('=', 2).map!(&unescaper)
          yield k, v
        end
      else
        pairs.each do |p|
          next if p.empty?
          k, v = p.split('=', 2).map! { |s| unescape(s) }
          yield k, v
        end
      end
    rescue ArgumentError => e
      raise if e.is_a?(BadRequest)
      raise InvalidParameterError, e.message, e.backtrace
    end

    def unescape(string, encoding = Encoding::UTF_8)
      URI.decode_www_form_component(string, encoding)
    end

    class Params < Hash
      alias_method :to_params_hash, :to_h
    end
  end
end
