# frozen_string_literal: true

require_relative 'constants'
require_relative 'utils'

module Rack
  # RFC 7240 Prefer request preferences and Preference-Applied responses.
  class Prefer
    PREFER = "prefer"
    PREFERENCE_APPLIED = "preference-applied"
    RETURN = "return"
    MINIMAL = "minimal"
    REPRESENTATION = "representation"

    REPRESENTATION_HEADERS = %w[
      content-disposition
      content-encoding
      content-language
      content-length
      content-location
      content-md5
      content-type
      transfer-encoding
    ].freeze

    STATUS_NO_ENTITY_HEADERS = %w[
      content-encoding
      content-language
      content-length
      content-location
      content-md5
      content-type
      transfer-encoding
    ].freeze

    TOKEN = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/

    # A single preference and its extension parameters.
    class Preference
      attr_reader :name, :value, :params

      def initialize(name, value = true, params = {})
        @name = name.to_s.downcase
        @value = normalize_value(value)
        @params = params.each_with_object({}) do |(key, param_value), normalized|
          normalized[key.to_s.downcase] = param_value
        end.freeze
        freeze
      end

      def to_s
        serialized = +@name.dup
        serialized << "=" << serialize_value(@value) unless @value.equal?(true)
        @params.sort.each do |key, value|
          serialized << "; " << key
          serialized << "=" << serialize_value(value) unless value.equal?(true)
        end
        serialized
      end

      def to_h
        {name: @name, value: @value, params: @params}
      end

      private

      def normalize_value(value)
        return true if value.nil?
        value.is_a?(Symbol) ? value.to_s.downcase : value
      end

      def serialize_value(value)
        string = value.to_s
        return string if string.match?(TOKEN)

        quoted = string.gsub(/(["\\\x7f\x00-\x1f])/) { "\\#{$1}" }
        "\"" + quoted + "\""
      end
    end

    # Parsed request preferences and preferences explicitly applied by the app.
    class Collection
      include Enumerable

      # Parse a Prefer header value. Conflicting values resolve to the first
      # occurrence. Extension parameters of equal duplicate values are merged,
      # with the first occurrence of each parameter winning.
      def self.parse(header)
        Array(header).flat_map { |value| split(value.to_s) }
      end

      def self.split(value)
        tokens = []
        token = +""
        quoted = false
        escaped = false

        value.each_char do |character|
          if escaped
            token << character
            escaped = false
          elsif character == "\\" && quoted
            token << character
            escaped = true
          elsif character == '"'
            token << character
            quoted = !quoted
          elsif character == "," && !quoted
            tokens << token
            token = +""
          else
            token << character
          end
        end
        tokens << token unless token.strip.empty?
        tokens.filter_map { |part| parse_token(part) }
      end

      def self.parse_token(value)
        parts = split_parameters(value)
        name, preference_value, bare = parse_parameter(parts.shift.to_s)
        return unless name

        params = {}
        parts.each do |part|
          param_name, param_value, param_bare = parse_parameter(part)
          next unless param_name
          next unless param_value || param_bare
          params[param_name] ||= param_value
        end

        return unless preference_value || bare
        preference_value = preference_value.downcase if name == Prefer::RETURN
        Preference.new(name, preference_value, params)
      end

      def self.split_parameters(value)
        parameters = []
        parameter = +""
        quoted = false
        escaped = false

        value.each_char do |character|
          if escaped
            parameter << character
            escaped = false
          elsif character == "\\" && quoted
            parameter << character
            escaped = true
          elsif character == '"'
            parameter << character
            quoted = !quoted
          elsif character == ";" && !quoted
            parameters << parameter
            parameter = +""
          else
            parameter << character
          end
        end
        parameters << parameter
      end

      def self.parse_parameter(value)
        name, raw_value = value.strip.split("=", 2)
        name = name.to_s.strip
        return if name.empty? || !name.match?(TOKEN)

        if raw_value.nil?
          [name.downcase, true, true]
        else
          [name.downcase, parse_parameter_value(raw_value.strip), false]
        end
      end

      def self.parse_parameter_value(value)
        if value.start_with?('"') && value.end_with?('"') && value.length >= 2
          unquote(value[1...-1])
        elsif value.match?(TOKEN)
          value
        end
      end

      def self.unquote(value)
        unquoted = +""
        escaped = false
        value.each_char do |character|
          if escaped
            unquoted << character
            escaped = false
          elsif character == "\\"
            escaped = true
          else
            unquoted << character
          end
        end
        unquoted
      end

      private_class_method :parse_token, :split_parameters, :parse_parameter,
        :parse_parameter_value, :unquote

      def initialize(header = nil)
        @preferences = self.class.parse(header)
        @by_name = {}
        @applied = {}

        @preferences.each do |preference|
          existing = @by_name[preference.name]
          if existing.nil?
            @by_name[preference.name] = preference
          elsif existing.value == preference.value
            merge_duplicate(existing, preference)
          end
        end
      end

      def each(&block)
        return to_enum(__method__) unless block
        @preferences.each(&block)
      end

      def [](name)
        @by_name[name.to_s.downcase]
      end

      def value(name)
        self[name]&.value
      end

      def include?(name)
        @by_name.key?(name.to_s.downcase)
      end
      alias key? include?
      alias has? include?

      def minimal?
        value(Prefer::RETURN) == Prefer::MINIMAL
      end

      def representation?
        value(Prefer::RETURN) == Prefer::REPRESENTATION
      end

      # Record a preference that the application actually applied. Unlike the
      # values parsed from the request, this is the only input used to generate
      # the Preference-Applied response header.
      def apply(name, value = true, **params)
        name = name.to_s.downcase
        raise ArgumentError, "invalid preference name: #{name.inspect}" unless name.match?(TOKEN)
        value = value.to_s.downcase if name == Prefer::RETURN && value.is_a?(Symbol)
        value = value.downcase if name == Prefer::RETURN && value.is_a?(String)
        @applied[name] = Preference.new(name, value, params)
      end

      def applied?(name = nil)
        name.nil? ? !@applied.empty? : @applied.key?(name.to_s.downcase)
      end

      def applied
        @applied.values
      end

      def to_a
        @preferences.dup
      end

      private

      def merge_duplicate(existing, duplicate)
        params = duplicate.params.reject { |key, _| existing.params.key?(key) }
        return if params.empty?

        @by_name[existing.name] = Preference.new(
          existing.name,
          existing.value,
          existing.params.merge(params)
        )
      end
    end

    def initialize(app)
      @app = app
    end

    def call(env)
      request = ::Rack::Request.new(env)
      status, headers, body = @app.call(env)
      applied = request.preferences.applied

      response = [status, headers, body]
      headers = response[1] = headers.dup if headers.frozen?
      headers.delete_if { |key, _| key.is_a?(String) && key.downcase == PREFERENCE_APPLIED }
      return response if applied.empty?

      headers[PREFERENCE_APPLIED] = applied.map(&:to_s).join(", ")

      return_preference = applied.find { |preference| preference.name == RETURN }
      if return_preference&.value == MINIMAL
        minimize(response, request.head?)
      end

      response
    end

    private

    def minimize(response, head_request)
      status, headers, body = response
      body.close if body.respond_to?(:close)
      response[2] = []
      return if head_request

      removable_headers =
        if status.to_i == 204
          STATUS_NO_ENTITY_HEADERS + %w[content-range]
        elsif Utils::STATUS_WITH_NO_ENTITY_BODY.key?(status.to_i)
          STATUS_NO_ENTITY_HEADERS
        else
          REPRESENTATION_HEADERS
        end
      removable_headers.each { |header| headers.delete(header) }
    end
  end
end

require_relative 'request' unless defined?(::Rack::Request)
