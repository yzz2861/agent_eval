# encoding: utf-8
# frozen_string_literal: true
require 'mail/constants'
require 'mail/indifferent_hash'
require 'mail/encodings'

module Mail
  # ParameterHash is an intelligent Hash that allows you to add
  # parameter values including the MIME extension paramaters that
  # have the name*0="blah", name*1="bleh" keys, and will just return
  # a single key called name="blahbleh" and do any required un-encoding
  # to make that happen
  #
  # Parameters are defined in RFC2045. Split keys are in RFC2231.
  class ParameterHash < IndifferentHash #:nodoc:
    PARAMETER_KEY = /\A(?<base>[^*=]+)(?:\*(?<section>\d+))?(?<extended>\*)?\z/

    StrictResult = Struct.new(:parameters, :diagnostics) do
      def to_h
        {
          parameters: parameters.to_h,
          diagnostics: diagnostics.map(&:to_h)
        }
      end
    end
    StrictDiagnostic = Struct.new(:type, :parameter, :message, :raw_fragments, :details) do
      def to_h
        {
          type: type,
          parameter: parameter,
          message: message,
          raw_fragments: raw_fragments,
          details: details
        }
      end
    end
    RawFragment = Struct.new(:key, :base_name, :value, :occurrence, :section, :extended) do
      def to_h
        {
          key: key,
          base_name: base_name,
          value: value,
          occurrence: occurrence,
          section: section,
          extended: extended
        }
      end
    end

    def initialize(*args)
      @raw_fragments = []
      super
    end

    def []=(key, value)
      key = convert_key(key)
      @raw_fragments << RawFragment.new(key, key, value, @raw_fragments.length, nil, false)
      regular_writer(key, convert_value(value))
    end

    def update(other_hash)
      other_hash.each_pair do |key, value|
        key = convert_key(key)
        @raw_fragments << RawFragment.new(key, key, value, @raw_fragments.length, nil, false)
        regular_writer(key, convert_value(value))
      end
      self
    end
    alias_method :merge!, :update

    def delete(key)
      converted_key = convert_key(key)
      @raw_fragments.reject! { |fragment| fragment.key == converted_key }
      super
    end

    def self.strict_decode(pairs, key_name = nil)
      hash = new
      pairs.each do |pair|
        pair.each do |key, value|
          hash[key] = value
        end
      end
      hash.strict_decode(key_name)
    end

    def [](key_name)
      key_pattern = Regexp.escape(key_name.to_s)
      pairs = []
      exact = nil

      each do |k,v|
        if k =~ /^#{key_pattern}(\*|$)/i
          if $1 == Constants::ASTERISK
            pairs << [k, v]
          else
            exact = k
          end
        end
      end

      if pairs.empty? # Just dealing with a single value pair
        super(exact || key_name)
      else # Dealing with a multiple value pair or a single encoded value pair
        string = pairs.sort { |a,b| a.first.to_s <=> b.first.to_s }.map { |v| v.last }.join('')
        if mt = string.match(/([\w\-]+)?'(\w\w)?'(.*)/)
          string = mt[3]
          encoding = mt[1]
        else
          encoding = nil
        end
        Mail::Encodings.param_decode(string, encoding)
      end
    end

    def strict_decode(key_name = nil)
      groups = grouped_fragments
      if key_name
        groups = groups.select { |group_name, _| group_name == key_name.to_s.downcase }
      end

      parameters = IndifferentHash.new
      diagnostics = []

      groups.each_value do |group|
        value, group_diagnostics = strict_group_value(group)
        diagnostics.concat(group_diagnostics)
        parameters[group[:canonical_name]] = value if group_diagnostics.empty?
      end

      StrictResult.new(parameters, diagnostics)
    end

    def encoded
      map.sort_by { |a| a.first.to_s }.map! do |key_name, value|
        unless value.ascii_only?
          value = Mail::Encodings.param_encode(value)
          key_name = "#{key_name}*"
        end
        %Q{#{key_name}=#{Utilities.quote_token(value)}}
      end.join(";\r\n\s")
    end

    def decoded
      map.sort_by { |a| a.first.to_s }.map! do |key_name, value|
        %Q{#{key_name}=#{Utilities.quote_token(value)}}
      end.join("; ")
    end

    private

    def grouped_fragments
      groups = Hash.new { |hash, key| hash[key] = { canonical_name: nil, fragments: [] } }

      @raw_fragments.each do |raw|
        match = raw.key.match(PARAMETER_KEY)
        next unless match

        base_name = match[:base]
        group_name = base_name.downcase
        fragment = RawFragment.new(
          raw.key,
          base_name,
          raw.value,
          raw.occurrence,
          match[:section] && match[:section].to_i,
          !match[:extended].nil?
        )
        groups[group_name][:canonical_name] ||= base_name
        groups[group_name][:fragments] << fragment
      end

      groups
    end

    def strict_group_value(group)
      fragments = group[:fragments].sort_by { |fragment| [fragment.section || 0, fragment.occurrence] }
      plain_fragments = fragments.select { |fragment| fragment.section.nil? && !fragment.extended }
      extended_fragments = fragments.select(&:extended)
      sectioned_fragments = fragments.select(&:section)
      diagnostics = []
      structurally_invalid = false

      if plain_fragments.length == fragments.length
        return [plain_fragments.last.value, diagnostics]
      end

      if !plain_fragments.empty? && (!extended_fragments.empty? || !sectioned_fragments.empty?)
        structurally_invalid = true
        diagnostics << diagnostic(
          :parameter_conflict,
          group,
          "ordinary and extended parameters conflict",
          fragments,
          plain_fragments: plain_fragments.map(&:to_h),
          extended_fragments: extended_fragments.map(&:to_h),
          sectioned_fragments: sectioned_fragments.map(&:to_h)
        )
      end

      unsectioned_extended = extended_fragments.select { |fragment| fragment.section.nil? }
      if !unsectioned_extended.empty? && !sectioned_fragments.empty?
        structurally_invalid = true
        diagnostics << diagnostic(
          :parameter_conflict,
          group,
          "unsectioned and sectioned extended parameters conflict",
          fragments,
          unsectioned_fragments: unsectioned_extended.map(&:to_h),
          sectioned_fragments: sectioned_fragments.map(&:to_h)
        )
      end

      sectioned_fragments.group_by(&:section).each do |section, duplicates|
        next unless duplicates.length > 1

        structurally_invalid = true
        diagnostics << diagnostic(
          :duplicate_section,
          group,
          "parameter section #{section} occurs #{duplicates.length} times",
          duplicates,
          section: section,
          occurrences: duplicates.map(&:occurrence)
        )
      end

      unless sectioned_fragments.empty?
        present_sections = sectioned_fragments.map(&:section).uniq.sort
        maximum_section = [present_sections.max, 1000].min
        missing_sections = (0..maximum_section).to_a - present_sections
        unless missing_sections.empty?
          structurally_invalid = true
          diagnostics << diagnostic(
            :broken_sections,
            group,
            "parameter sections have gaps: #{missing_sections.join(', ')}",
            sectioned_fragments,
            missing_sections: missing_sections.first(10),
            missing_count: missing_sections.length,
            present_sections: present_sections
          )
        end
      end

      initial_fragment = fragments.find { |fragment| fragment.section == 0 && fragment.extended }
      initial_fragment ||= unsectioned_extended.first if sectioned_fragments.empty?
      if sectioned_fragments.any? { |fragment| fragment.section == 0 } && initial_fragment.nil?
        structurally_invalid = true
        diagnostics << diagnostic(
          :invalid_extended_parameter,
          group,
          "section 0 of an extended parameter must use the asterisk marker",
          sectioned_fragments,
          section: 0,
          occurrence: sectioned_fragments.first.occurrence
        )
      end
      charset = nil
      encoded_fragments = {}

      unless structurally_invalid
        payload_fragments = fragments.select do |fragment|
          fragment.extended ||
            (fragment.section && initial_fragment&.extended && fragment.section > 0)
        end

        payload_fragments.each do |fragment|
          payload = fragment.value.to_s
          if fragment.equal?(initial_fragment)
            prefix = payload.match(/\A([^']*)'([^']*)'(.*)\z/m)
            unless prefix
              diagnostics << diagnostic(
                :invalid_extended_parameter,
                group,
                "extended parameter must include charset and language delimiters",
                [fragment],
                section: fragment.section,
                occurrence: fragment.occurrence
              )
              next
            end
            charset = prefix[1]
            charset = nil if charset.empty?
            payload = prefix[3]
          end

          encoded_fragments[fragment] = payload
        end

        encoded_fragments.each do |fragment, payload|
          binary_payload = binary_string(payload)
          prefix_length = fragment.equal?(initial_fragment) ? fragment.value.bytesize - payload.bytesize : 0
          offset = 0
          while offset < binary_payload.bytesize
            percent_index = binary_payload.index('%', offset)
            break unless percent_index

            first_byte = binary_payload.getbyte(percent_index + 1)
            second_byte = binary_payload.getbyte(percent_index + 2)
            unless first_byte && second_byte &&
                     hex_byte?(first_byte) && hex_byte?(second_byte)
              diagnostics << diagnostic(
                :invalid_percent_encoding,
                group,
                "invalid percent-encoding at byte offset #{percent_index}",
                [fragment],
                section: fragment.section,
                occurrence: fragment.occurrence,
                byte_offset: prefix_length + percent_index
              )
            end

            offset = percent_index + 1
          end
        end

        if charset && !charset_supported?(charset)
          diagnostics << diagnostic(
            :unsupported_charset,
            group,
            "unsupported charset: #{charset}",
            extended_fragments,
            charset: charset,
            section: initial_fragment && initial_fragment.section,
            occurrence: initial_fragment && initial_fragment.occurrence
          )
        end
      end

      return [nil, diagnostics] unless diagnostics.empty?

      bytes = String.new.force_encoding(Encoding::ASCII_8BIT)
      fragments.each do |fragment|
        if encoded_fragments.key?(fragment)
          bytes << percent_decode(encoded_fragments.fetch(fragment))
        else
          bytes << binary_string(fragment.value.to_s)
        end
      end

      [decode_param_bytes(bytes, charset), diagnostics]
    rescue Encoding::InvalidByteSequenceError, Encoding::UndefinedConversionError, ArgumentError => error
      diagnostics << diagnostic(
        :invalid_byte_sequence,
        group,
        "parameter bytes are not valid for charset #{charset || 'UTF-8'}: #{error.message}",
        fragments,
        charset: charset
      )
      [nil, diagnostics]
    end

    def diagnostic(type, group, message, raw_fragments, details)
      StrictDiagnostic.new(
        type,
        group[:canonical_name],
        message,
        raw_fragments.map(&:to_h),
        details
      )
    end

    def binary_string(string)
      string.dup.force_encoding(Encoding::ASCII_8BIT)
    end

    def hex_byte?(byte)
      (byte >= 48 && byte <= 57) ||
        (byte >= 65 && byte <= 70) ||
        (byte >= 97 && byte <= 102)
    end

    def percent_decode(string)
      string.gsub(/%([0-9A-Fa-f]{2})/) { [Regexp.last_match(1)].pack('H2') }
    end

    def charset_supported?(charset)
      return true if charset =~ /\Autf-?7\z/i

      encoding = Utilities.pick_encoding(charset)
      if encoding == Encoding::ASCII_8BIT && !%w[8bit binary].include?(charset.downcase)
        return false
      end

      Encoding.find(encoding)
      true
    rescue ArgumentError
      false
    end

    def decode_param_bytes(bytes, charset)
      decoded = if charset
                  Utilities.charset_encoder.encode(bytes, charset)
                else
                  bytes.dup.force_encoding(Encoding::UTF_8)
                end
      decoded = decoded.encode(Encoding::UTF_8) unless decoded.encoding == Encoding::UTF_8
      raise Encoding::InvalidByteSequenceError, "invalid byte sequence" unless decoded.valid_encoding?
      decoded
    end
  end
end
