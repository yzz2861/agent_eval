# frozen_string_literal: false
# = uri/tel.rb
#
# License:: You can redistribute it and/or modify it under the same term as Ruby.
#
# See URI for general documentation
#

require_relative 'generic'

module URI

  # RFC3966, the tel URL scheme.
  class Tel < Generic
    COMPONENT = [
      :scheme,
      :number,
      :ext,
      :isub,
      :phone_context,
      :params
    ].freeze

    # :stopdoc:
    HEXDIG = '0-9A-Fa-f'
    PCT_ENCODED = "(?:%[#{HEXDIG}]{2})".freeze
    VISUAL_SEPARATOR = /[-.()]/
    GLOBAL_NUMBER_REGEXP = /\A\+[0-9()\-.]*[0-9][0-9()\-.]*\z/.freeze
    LOCAL_NUMBER_REGEXP = /\A[0-9A-D*#pw()\-.]*[0-9A-D*#pw][0-9A-D*#pw()\-.]*\z/.freeze
    GLOBAL_CONTEXT_REGEXP = /\A\+[0-9()\-.]*[0-9][0-9()\-.]*\z/.freeze
    PRIVATE_CONTEXT_CHAR = "A-Za-z0-9\\-._~!*'():@&=+$,/?\\[\\]"
    PRIVATE_CONTEXT_REGEXP =
      /\A(?:[#{PRIVATE_CONTEXT_CHAR}]|#{PCT_ENCODED})+\z/.freeze
    PARAM_NAME_REGEXP = /\A-?[A-Za-z0-9-]*[A-Za-z0-9][A-Za-z0-9-]*\z/.freeze
    PARAM_VALUE_CHAR = "A-Za-z0-9\\-._~!*'()\\[\\]/?:@&+$,="
    PARAM_VALUE_REGEXP =
      /\A(?:[#{PARAM_VALUE_CHAR}]|#{PCT_ENCODED})+\z/.freeze
    RESERVED_PARAM_NAMES = %w[ext isub phone-context].freeze
    Ractor.make_shareable(RESERVED_PARAM_NAMES) if defined?(Ractor)
    # :startdoc:

    def self.build(args)
      components = Util.make_components_hash(self, args)
      components[:phone_context] ||= components[:'phone-context']
      components.delete(:'phone-context')
      opaque = build_opaque(
        components.delete(:number),
        components.delete(:ext),
        components.delete(:isub),
        components.delete(:phone_context),
        components.delete(:params)
      )
      components[:opaque] = opaque
      super(components)
    end

    def initialize(*args)
      super(*args)

      if @fragment
        raise InvalidComponentError, 'tel URI cannot have a fragment'
      end

      @ext = nil
      @isub = nil
      @phone_context = nil
      @params = []
      parse_opaque(@opaque)
    end

    attr_reader :number, :ext, :isub, :phone_context, :params

    def number=(value)
      check_number(value)
      check_combination(value, @ext, @isub, @phone_context)
      @number = value
      update_opaque
      value
    end

    def ext=(value)
      check_ext(value)
      check_extension_parameters(value, @isub)
      check_combination(@number, value, @isub, @phone_context)
      @ext = value
      update_opaque
      value
    end

    def isub=(value)
      check_isub(value)
      check_extension_parameters(@ext, value)
      @isub = value
      update_opaque
      value
    end

    def phone_context=(value)
      check_phone_context(value)
      check_combination(@number, @ext, @isub, value)
      @phone_context = value
      update_opaque
      value
    end

    def params=(value)
      params = coerce_params(value)
      check_params(params)
      @params = params
      update_opaque
      value
    end

    def global?
      @number.start_with?('+')
    end

    def local?
      !global?
    end

    def normalize!
      @number = remove_visual_separators(@number)
      @isub = @isub && canonicalize_percent_encoding(@isub)
      @phone_context = normalize_phone_context(@phone_context)
      @params = @params.map { |name, value|
        [name.downcase, value.nil? ? nil : canonicalize_percent_encoding(value)]
      }.sort_by(&:first)
      update_opaque
      super
      self
    end

    def ==(other)
      return false unless other.is_a?(Tel)

      semantic_components == other.semantic_components
    end

    def hash
      semantic_components.hash
    end

    def eql?(other)
      other.is_a?(Tel) && semantic_components.eql?(other.semantic_components)
    end

    def to_s
      "#{@scheme}:#{@opaque}"
    end

    protected

    def semantic_components
      normalized = normalize
      [
        normalized.global?,
        normalized.number,
        normalized.ext,
        normalized.isub,
        normalized.phone_context,
        normalized.params
      ]
    end

    private

    def self.build_opaque(number, ext, isub, phone_context, raw_params)
      raise InvalidComponentError, 'missing telephone number' if number.nil?

      unless number.is_a?(String)
        raise InvalidComponentError, "bad telephone number: #{number.inspect}"
      end
      params = coerce_params(raw_params)
      check_number(number)
      check_ext(ext)
      check_isub(isub)
      check_phone_context(phone_context)
      check_extension_parameters(ext, isub)
      check_params(params)
      check_combination(number, ext, isub, phone_context)

      opaque = number.dup
      append_known_param(opaque, 'ext', ext)
      append_known_param(opaque, 'isub', isub)
      append_known_param(opaque, 'phone-context', phone_context)
      params.each { |name, value| append_param(opaque, name, value) }
      opaque
    end

    def self.append_known_param(result, name, value)
      return if value.nil?

      result << ';' << name << '=' << value
    end

    def self.append_param(result, name, value)
      result << ';' << name
      result << '=' << value unless value.nil?
    end

    def self.coerce_params(params)
      case params
      when nil
        []
      when Array
        params.map { |param| coerce_param_entry(param) }
      when Hash
        params.map { |name, value| [name.to_s, value.nil? ? nil : value.to_s] }
      when String
        params.split(';').map { |param| coerce_param_entry(param) }
      else
        raise InvalidComponentError, "bad tel parameters: #{params.inspect}"
      end
    end

    def self.coerce_param_entry(param)
      case param
      when Array
        unless (param.length == 1 || param.length == 2) && param[0]
          raise InvalidComponentError, "bad tel parameter: #{param.inspect}"
        end
        [param[0].to_s, param[1].nil? ? nil : param[1].to_s]
      when String
        entry = param.split('=', 2)
        unless !entry[0].empty? && (entry.length == 1 || !entry[1].empty?)
          raise InvalidComponentError, "bad tel parameter: #{param.inspect}"
        end
        entry << nil if entry.length == 1
      else
        raise InvalidComponentError, "bad tel parameter: #{param.inspect}"
      end
    end

    def self.check_number(value)
      unless value.is_a?(String) &&
             (GLOBAL_NUMBER_REGEXP =~ value || LOCAL_NUMBER_REGEXP =~ value)
        raise InvalidComponentError, "bad telephone number: #{value.inspect}"
      end

      if value.include?('%')
        raise InvalidComponentError,
              "bad percent-encoding in telephone number: #{value.inspect}"
      end
    end

    def self.check_ext(value)
      return if value.nil?

      unless value.is_a?(String) &&
             /\A[0-9*#pw]+\z/ =~ value &&
             value.count('0-9').positive?
        raise InvalidComponentError, "bad ext: #{value.inspect}"
      end

      if value.include?('%')
        raise InvalidComponentError,
              "bad percent-encoding in ext: #{value.inspect}"
      end
    end

    def self.check_isub(value)
      check_param_value(value, 'isub')
    end

    def self.check_phone_context(value)
      return if value.nil?

      check_param_value(value, 'phone-context')
      unless GLOBAL_CONTEXT_REGEXP =~ value ||
             PRIVATE_CONTEXT_REGEXP =~ value
        raise InvalidComponentError,
              "bad phone-context: #{value.inspect}"
      end
    end

    def self.check_params(params)
      names = []

      params.each do |name, value|
        unless PARAM_NAME_REGEXP =~ name
          raise InvalidComponentError,
                "bad tel parameter name: #{name.inspect}"
        end

        check_param_value(value, name)
        if value == '+'
          raise InvalidComponentError,
                "missing required extension value: #{name}"
        elsif value&.start_with?('+')
          raise InvalidComponentError,
                "unknown mandatory tel parameter: #{name}"
        end

        normalized_name = name.downcase
        if RESERVED_PARAM_NAMES.include?(normalized_name) ||
           names.include?(normalized_name)
          raise InvalidComponentError,
                "duplicate tel parameter: #{name}"
        end
        names << normalized_name
      end
    end

    def self.check_param_value(value, name)
      return if value.nil?

      unless value.is_a?(String) && !value.empty? &&
             PARAM_VALUE_REGEXP =~ value
        raise InvalidComponentError,
              "bad #{name} value: #{value.inspect}"
      end

      check_percent_encoding(value, name)
    end

    def self.check_extension_parameters(ext, isub)
      if ext && isub
        raise InvalidComponentError,
              'ext and isub are mutually exclusive'
      end
    end

    def self.check_combination(number, _ext, _isub, phone_context)
      if number.nil?
        return
      elsif number.start_with?('+')
        if phone_context
          raise InvalidComponentError,
                'global telephone number cannot have phone-context'
        end
      else
        if phone_context.nil?
          raise InvalidComponentError,
                'local telephone number requires phone-context'
        end
        if _ext
          raise InvalidComponentError,
                'ext can only be used with a global telephone number'
        end
      end
    end

    def self.check_percent_encoding(value, component)
      if value.is_a?(String) && value.match?(/%(?![0-9A-Fa-f]{2})/)
        raise InvalidComponentError,
              "bad percent-encoding in #{component}: #{value.inspect}"
      end
    end

    def parse_opaque(opaque)
      raise InvalidComponentError,
            'missing opaque part for tel URL' unless opaque

      number, *parameters = opaque.split(';', -1)
      params = []
      seen_params = {}

      parameters.each do |parameter|
        if parameter.empty?
          raise InvalidComponentError, 'empty tel parameter'
        end

        name, value = parameter.split('=', 2)
        has_value = parameter.include?('=')
        normalized_name = name.downcase
        unless PARAM_NAME_REGEXP =~ name
          raise InvalidComponentError,
                "bad tel parameter name: #{name.inspect}"
        end

        if seen_params[normalized_name]
          raise InvalidComponentError,
                "duplicate tel parameter: #{name}"
        end
        seen_params[normalized_name] = true

        case normalized_name
        when 'ext'
          unless has_value && !value.empty?
            raise InvalidComponentError, 'ext requires a value'
          end
          @ext = value
        when 'isub'
          unless has_value && !value.empty?
            raise InvalidComponentError, 'isub requires a value'
          end
          @isub = value
        when 'phone-context'
          unless has_value && !value.empty?
            raise InvalidComponentError, 'phone-context requires a value'
          end
          @phone_context = value
        else
          if has_value && value.empty?
            raise InvalidComponentError, "#{name} requires a value"
          end
          params << [name, value]
        end
      end

      self.class.send(:check_number, number)
      self.class.send(:check_ext, @ext)
      self.class.send(:check_isub, @isub)
      self.class.send(:check_phone_context, @phone_context)
      self.class.send(:check_extension_parameters, @ext, @isub)
      self.class.send(:check_params, params)
      self.class.send(:check_combination, number, @ext, @isub, @phone_context)

      @number = number
      @params = params
    end

    def check_number(value)
      self.class.send(:check_number, value)
    end

    def check_ext(value)
      self.class.send(:check_ext, value)
    end

    def check_isub(value)
      self.class.send(:check_isub, value)
    end

    def check_phone_context(value)
      self.class.send(:check_phone_context, value)
    end

    def check_params(value)
      self.class.send(:check_params, value)
    end

    def check_extension_parameters(ext, isub)
      self.class.send(:check_extension_parameters, ext, isub)
    end

    def check_combination(number, ext, isub, phone_context)
      self.class.send(:check_combination, number, ext, isub, phone_context)
    end

    def coerce_params(value)
      self.class.send(:coerce_params, value)
    end

    def update_opaque
      @opaque = self.class.send(
        :build_opaque,
        @number, @ext, @isub, @phone_context, @params
      )
    end

    def remove_visual_separators(value)
      value.gsub(VISUAL_SEPARATOR, '')
    end

    def normalize_phone_context(value)
      return nil if value.nil?

      if value.start_with?('+')
        remove_visual_separators(value)
      else
        canonicalize_unreserved_percent_encoding(value)
      end
    end

    def canonicalize_percent_encoding(value)
      value.gsub(/%([0-9A-Fa-f]{2})/) do
        byte = $1.to_i(16).chr
        if byte.match?(/[A-Za-z0-9\-._~!*'()\/:&+$,]/)
          byte
        else
          "%#{$1.upcase}"
        end
      end
    end

    def canonicalize_unreserved_percent_encoding(value)
      value.gsub(/%([0-9A-Fa-f]{2})/) do
        byte = $1.to_i(16).chr
        if byte.match?(/[A-Za-z0-9\-._~]/)
          byte
        else
          "%#{$1.upcase}"
        end
      end
    end
  end

  register_scheme 'TEL', Tel
end
