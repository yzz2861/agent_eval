# frozen_string_literal: false
# = uri/tel.rb
#
# License:: You can redistribute it and/or modify it under the same term as Ruby.
#
# See URI for general documentation
#

require_relative 'generic'

module URI

  # RFC3966, the tel URI for telephone numbers.
  class Tel < Generic
    # A Default port of nil for URI::Tel.
    DEFAULT_PORT = nil

    # An Array of the available components for URI::Tel.
    COMPONENT = [
      :scheme,
      :number,
      :ext,
      :isdn_subaddress,
      :phone_context,
      :params,
    ].freeze

    VISUAL_SEPARATOR = /[.()\-]/
    private_constant :VISUAL_SEPARATOR

    GLOBAL_NUMBER = /\A\+[0-9.()\-]*[0-9][0-9.()\-]*\z/
    LOCAL_NUMBER = /\A[0-9A-Dpw*#.()\-]*[0-9A-Dpw*#][0-9A-Dpw*#.()\-]*\z/i
    EXTENSION = /\A(?:[0-9A-Dpw*#.()\-]|%\h\h)*[0-9A-Dpw*#%](?:[0-9A-Dpw*#.()\-]|%\h\h)*\z/i
    LOCAL_NETWORK_CONTEXT =
      /\A(?:%[@$])?[0-9A-Dpw*#.()@\-]*[0-9A-Dpw*#][0-9A-Dpw*#.()@\-]*\z/i
    private_constant :GLOBAL_NUMBER, :LOCAL_NUMBER, :EXTENSION, :LOCAL_NETWORK_CONTEXT

    PCT_ENCODED = /%\h\h/
    PARAM_NAME = %r{\A(?:#{PCT_ENCODED}|[A-Za-z0-9\-._~!$&'()*+,/:;=?@\[\]])+\z}
    PARAM_NAME_SAFE = %r{\A(?:[A-Za-z0-9\-._~!$&'()*+,/:?@])+\z}
    PARAM_VALUE = %r{\A(?:#{PCT_ENCODED}|[A-Za-z0-9\-._~*!'()&:@/\[\]?=])+\z}
    PARAM_VALUE_SAFE = %r{\A(?:[A-Za-z0-9\-._~!$&'()*+,:@?/])+\z}
    DOMAIN_NAME = /\A[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\.?\z/i
    private_constant :PCT_ENCODED, :PARAM_NAME, :PARAM_NAME_SAFE, :PARAM_VALUE,
                   :PARAM_VALUE_SAFE, :DOMAIN_NAME

    KNOWN_PARAMS = {
      'ext' => :ext,
      'isub' => :isdn_subaddress,
      'isdn-subaddress' => :isdn_subaddress,
      'phone-context' => :phone_context,
    }.freeze
    private_constant :KNOWN_PARAMS

    # Creates a new URI::Tel object from components, with syntax checking.
    #
    # Components can be provided as <code>[number, ext, isdn_subaddress,
    # phone_context, params]</code>, or as a Hash. Unknown parameters can be
    # supplied as an Array of <code>[name, value]</code> pairs or a Hash.
    def self.build(args)
      tmp = Util.make_components_hash(self, args)
      tmp[:ext] ||= tmp.delete(:extension) if tmp.key?(:extension)
      tmp[:isdn_subaddress] ||= tmp.delete(:isub) if tmp.key?(:isub)
      if tmp.key?(:'phone-context')
        tmp[:phone_context] ||= tmp.delete(:'phone-context')
      end
      if tmp.key?(:parameters) && !tmp.key?(:params)
        tmp[:params] = tmp.delete(:parameters)
      end

      number = string_component(tmp[:number])
      check_dialed_number(number)
      parameters = []

      if tmp[:ext]
        extension = string_component(tmp[:ext])
        check_percent_encoding(extension)
        unless EXTENSION.match?(extension)
          raise InvalidComponentError, "bad Tel extension: #{extension}"
        end
        parameters << ['ext', extension]
      end
      if tmp[:isdn_subaddress]
        parameters << ['isub', encode_token(string_component(tmp[:isdn_subaddress]), PARAM_VALUE_SAFE)]
      end
      if tmp[:phone_context]
        context = string_component(tmp[:phone_context])
        parameters << ['phone-context', encode_phone_context(context)]
      end
      parameter_pairs(tmp[:params]).each do |name, value|
        parameter_name = string_component(name)
        check_percent_encoding(parameter_name)
        known = KNOWN_PARAMS[percent_decode(parameter_name).downcase]
        if known
          if value.nil?
            raise InvalidComponentError, "Tel parameter #{parameter_name} requires a value"
          end
          value = string_component(value)
          value =
            case known
            when :phone_context then encode_phone_context(value)
            when :isdn_subaddress then encode_token(value, PARAM_VALUE_SAFE)
            else value
            end
          parameters << [known_parameter_name(known), value]
          next
        end

        name = encode_token(parameter_name, PARAM_NAME_SAFE)
        value = value.nil? ? nil : encode_token(string_component(value), PARAM_VALUE_SAFE)
        parameters << [name, value]
      end

      tmp[:opaque] = number
      parameters.each do |name, value|
        tmp[:opaque] << ';' << name
        tmp[:opaque] << '=' << value unless value.nil?
      end

      super(tmp)
    end

    def self.string_component(value) # :nodoc:
      unless value.respond_to?(:to_str)
        raise InvalidComponentError, "bad component(expected Tel component): #{value.inspect}"
      end
      value.to_str
    end
    private_class_method :string_component

    def self.known_parameter_name(component) # :nodoc:
      case component
      when :ext then 'ext'
      when :isdn_subaddress then 'isub'
      when :phone_context then 'phone-context'
      end
    end
    private_class_method :known_parameter_name

    def self.parameter_pairs(value) # :nodoc:
      return [] if value.nil?

      case value
      when Array
        value.flat_map do |item|
          case item
          when Array
            [[item.fetch(0).to_s, item[1]&.to_s]]
          when Hash
            item.to_a
          else
            text = item.to_s
            name, parameter_value = text.split('=', 2)
            [[name, parameter_value]]
          end
        end
      when Hash
        value.collect { |name, parameter_value| [name.to_s, parameter_value] }
      when String
        value.split(';').map do |parameter|
          name, parameter_value = parameter.split('=', 2)
          [name, parameter_value]
        end
      else
        raise InvalidComponentError, "bad Tel parameters: #{value.inspect}"
      end
    end
    private_class_method :parameter_pairs

    def self.encode_phone_context(value) # :nodoc:
      check_phone_context_percent_encoding(value)
      decoded = percent_decode(value)
      if GLOBAL_NUMBER.match?(decoded) || DOMAIN_NAME.match?(decoded)
        return value
      elsif (prefix = decoded_raw_context_prefix(decoded))
        suffix = decoded[2..-1]
        return prefix + suffix if raw_context_prefix(value)
        return encoded_context_prefix(prefix) + suffix
      elsif LOCAL_NETWORK_CONTEXT.match?(decoded)
        decoded.gsub('%', '%25')
      end
      raise InvalidComponentError, "bad Tel phone-context: #{value}"
    end
    private_class_method :encode_phone_context

    def self.check_phone_context_percent_encoding(value) # :nodoc:
      value = value[2..-1] if raw_context_prefix(value)
      check_percent_encoding(value)
    end
    private_class_method :check_phone_context_percent_encoding

    def self.raw_context_prefix(value) # :nodoc:
      value[0, 2] if %w[%@ %$].include?(value[0, 2])
    end
    private_class_method :raw_context_prefix

    def self.decoded_raw_context_prefix(value) # :nodoc:
      value[0, 2] if %w[%@ %$].include?(value[0, 2])
    end
    private_class_method :decoded_raw_context_prefix

    def self.encoded_context_prefix(prefix) # :nodoc:
      '%25%' + format('%02X', prefix[1].ord)
    end
    private_class_method :encoded_context_prefix

    def self.encode_token(value, allowed) # :nodoc:
      check_percent_encoding(value)
      value = percent_decode(value)
      encoded = String.new
      value.each_byte do |byte|
        character = byte.chr
        encoded << (allowed.match?(character) ? character : format('%%%02X', byte))
      end
      encoded.force_encoding(Encoding::US_ASCII)
    end
    private_class_method :encode_token

    def self.check_percent_encoding(value) # :nodoc:
      if /%(?!\h\h)/.match?(value)
        raise InvalidComponentError, "bad percent encoding: #{value}"
      end
    end
    private_class_method :check_percent_encoding

    def self.percent_decode(value) # :nodoc:
      value.gsub(/(%\h\h)/) { [$1[1, 2].to_i(16)].pack('C') }
    end
    private_class_method :percent_decode

    def self.check_dialed_number(value) # :nodoc:
      unless (value.start_with?('+') ? GLOBAL_NUMBER : LOCAL_NUMBER).match?(value)
        raise InvalidComponentError, "bad telephone number: #{value}"
      end
    end
    private_class_method :check_dialed_number

    def initialize(*arg)
      super(*arg)

      @number = nil
      @ext = nil
      @isdn_subaddress = nil
      @phone_context = nil
      @params = []
      @all_params = []

      parse_opaque(@opaque)
    end

    # The telephone number, including a leading "+" for global numbers.
    attr_reader :number

    # The extension, from the +ext+ parameter.
    attr_reader :ext
    alias extension ext

    # The ISDN subaddress, from the +isub+ parameter.
    attr_reader :isdn_subaddress
    alias isub isdn_subaddress

    # The context of a local number, from the +phone-context+ parameter.
    attr_reader :phone_context

    # Unknown parameters as an Array of +[name, value]+ pairs.
    attr_reader :params
    alias parameters params

    def global?
      @number.start_with?('+')
    end

    def local?
      !global?
    end

    def normalize
      uri = dup
      uri.normalize!
      uri
    end

    def normalize!
      @scheme = 'tel'
      @number = normalized_number
      @ext = normalized_extension if @ext
      @isdn_subaddress = canonical_param_value(@isdn_subaddress) if @isdn_subaddress
      @phone_context = normalized_phone_context if @phone_context
      @params = @params.collect {
        |name, value| [canonical_name(name), canonical_param_value(value)]
      }.sort_by { |name, value| [name, value.to_s] }
      @all_params = normalized_parameter_list
      @opaque = serialized_opaque
      self
    end

    def to_s
      str = @scheme + ':' + @opaque
      str << '#' << @fragment if @fragment
      str
    end

    def ==(other)
      other.is_a?(Tel) && normalize.component_ary == other.normalize.component_ary
    end
    alias eql? ==

    def hash
      normalize.component_ary.hash
    end

    private

    def parse_opaque(opaque)
      unless opaque
        raise InvalidComponentError, "missing opaque part for tel URL"
      end

      number, *raw_params = opaque.split(';')
      self.class.send(:check_dialed_number, number)
      @number = number

      seen = {}
      raw_params.each do |raw_parameter|
        name, value = raw_parameter.split('=', 2)
        if name.empty? || !PARAM_NAME.match?(name)
          raise InvalidComponentError, "bad Tel parameter: #{raw_parameter}"
        end
        self.class.send(:check_percent_encoding, name)
        check_parameter_value(name, value)

        canonical_name = canonical_name(name)
        if seen.key?(canonical_name)
          raise InvalidComponentError, "duplicate Tel parameter: #{name}"
        end
        seen[canonical_name] = true

        if (component = KNOWN_PARAMS[canonical_name])
          instance_variable_set("@#{component}", value)
        else
          @params << [name, value]
        end
        @all_params << [name, value]
      end

      if global? && @phone_context
        raise InvalidComponentError, "global telephone number cannot have phone-context"
      end
      if local? && !@phone_context
        raise InvalidComponentError, "local telephone number requires phone-context"
      end
      if @ext && @isdn_subaddress
        raise InvalidComponentError, "ext and isub parameters are mutually exclusive"
      end

      @params.freeze
      @all_params.freeze
    end

    def check_parameter_value(name, value)
      canonical_name = canonical_name(name)
      if KNOWN_PARAMS.key?(canonical_name) && value.nil?
        raise InvalidComponentError, "Tel parameter #{name} requires a value"
      end
      return if value.nil?

      case canonical_name
      when 'ext'
        self.class.send(:check_percent_encoding, value)
        unless EXTENSION.match?(value)
          raise InvalidComponentError, "bad Tel extension: #{value}"
        end
      when 'phone-context'
        check_phone_context(value)
      else
        self.class.send(:check_percent_encoding, value)
        unless PARAM_VALUE.match?(value)
          raise InvalidComponentError, "bad Tel parameter value: #{name}=#{value}"
        end
      end
    end

    def check_phone_context(value)
      self.class.send(:check_phone_context_percent_encoding, value)
      decoded = percent_decode(value)
      valid = GLOBAL_NUMBER.match?(decoded) ||
              DOMAIN_NAME.match?(decoded) ||
              LOCAL_NETWORK_CONTEXT.match?(decoded)
      unless valid
        raise InvalidComponentError, "bad Tel phone-context: #{value}"
      end
    end

    def canonical_name(name)
      percent_decode(name).downcase
    end

    def percent_decode(value)
      self.class.send(:percent_decode, value)
    end

    def canonical_param_value(value)
      return nil unless value
      self.class.send(:encode_token, value, PARAM_VALUE_SAFE)
    end

    def remove_visual_separators(value)
      value.gsub(VISUAL_SEPARATOR, '')
    end

    def normalized_number
      if global?
        '+' + remove_visual_separators(@number[1..-1]).upcase
      else
        normalize_local_number(@number)
      end
    end

    def normalize_local_number(value)
      normalize_dialed(remove_visual_separators(value))
    end

    def normalized_extension
      decoded = percent_decode(@ext)
      unless /\A[0-9A-Dpw*#.()\-]*[0-9A-Dpw*#][0-9A-Dpw*#.()\-]*\z/i.match?(decoded)
        raise InvalidComponentError, "bad Tel extension: #{@ext}"
      end
      normalize_dialed(remove_visual_separators(decoded))
    end

    def normalized_phone_context
      decoded = percent_decode(@phone_context)
      if GLOBAL_NUMBER.match?(decoded)
        '+' + remove_visual_separators(decoded[1..-1])
      else
        if DOMAIN_NAME.match?(decoded)
          decoded.downcase
        elsif (marker = private_context_prefix(decoded))
          marker + normalize_dialed(remove_visual_separators(decoded[2..-1]))
        else
          normalize_dialed(remove_visual_separators(decoded))
        end
      end
    end

    def private_context_prefix(value)
      self.class.send(:decoded_raw_context_prefix, value)
    end

    def normalize_dialed(value)
      value.gsub(/[a-dpw]/i) do |character|
        ['p', 'w'].include?(character.downcase) ? character.downcase : character.upcase
      end
    end

    def normalized_parameter_list
      parameters = []
      parameters << ['ext', @ext] if @ext
      parameters << ['isub', @isdn_subaddress] if @isdn_subaddress
      parameters << ['phone-context', @phone_context] if @phone_context
      parameters.concat(@params)
      parameters
    end

    def serialized_opaque
      opaque = @number.dup
      @all_params.each do |name, value|
        opaque << ';' << name
        opaque << '=' << value unless value.nil?
      end
      opaque
    end
  end

  register_scheme 'TEL', Tel
end
