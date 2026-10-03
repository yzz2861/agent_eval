# frozen_string_literal: true

module URI
  class InvalidIRIError < InvalidComponentError
    attr_reader :component
    attr_reader :position
    alias index position

    def initialize(message, component = nil, position = nil)
      super(message)
      @component = component
      @position = position
    end
  end

  module IRI
    module_function

    def encode_component(value, component)
      return value if value.nil?

      bytes = String(value).b
      ascii = String.new(encoding: Encoding::US_ASCII)
      index = 0

      while index < bytes.bytesize
        byte = bytes.getbyte(index)

        if byte == 0x25
          triplet = percent_triplet(bytes, index, component)
          decoded_byte = Integer(triplet[1, 2], 16)
          if decoded_byte < 0x80
            ascii << triplet
            index += 3
          else
            sequence = [decoded_byte]
            start = index
            index = collect_percent_sequence(bytes, index, component, sequence)
            valid_utf8!(sequence, component, start)
            ascii << bytes.byteslice(start, index - start)
          end
        elsif ascii_allowed?(byte, component)
          ascii << byte.chr
          index += 1
        elsif byte < 0x80
          ascii << format('%%%02X', byte)
          index += 1
        else
          sequence = utf8_sequence(bytes, index, component)
          sequence.each { |item| ascii << format('%%%02X', item) }
          index += sequence.length
        end
      end

      ascii
    end

    def decode_component(value, component)
      return value if value.nil?

      bytes = String(value).b
      decoded = String.new(encoding: Encoding::UTF_8)
      index = 0

      while index < bytes.bytesize
        byte = bytes.getbyte(index)

        if byte == 0x25
          triplet = percent_triplet(bytes, index, component)
          decoded_byte = Integer(triplet[1, 2], 16)

          if decoded_byte < 0x80
            if keep_encoded_ascii?(decoded_byte, component)
              decoded << triplet
            else
              decoded << decoded_byte.chr(Encoding::BINARY)
            end
            index += 3
          else
            sequence = [decoded_byte]
            start = index
            index = collect_percent_sequence(bytes, index, component, sequence)

            codepoint = valid_utf8!(sequence, component, start)
            append_unicode(decoded, codepoint, sequence, component, bytes, start, index)
          end
        elsif byte < 0x80
          unless ascii_allowed?(byte, component)
            invalid!(component, index, 'contains an ASCII character not allowed')
          end
          decoded << byte.chr
          index += 1
        else
          sequence = utf8_sequence(bytes, index, component)
          codepoint = valid_utf8!(sequence, component, index)
          append_unicode(decoded, codepoint, sequence, component, bytes, index, index + sequence.length)
          index += sequence.length
        end
      end

      decoded
    end

    def percent_triplet(bytes, index, component)
      triplet = bytes.byteslice(index, 3)
      unless triplet&.bytesize == 3 &&
             hex_byte?(triplet.getbyte(1)) && hex_byte?(triplet.getbyte(2))
        invalid!(component, index, 'contains an incomplete percent escape')
      end
      triplet
    end

    def hex_byte?(byte)
      byte && (byte.between?(0x30, 0x39) || byte.between?(0x41, 0x46) ||
        byte.between?(0x61, 0x66))
    end

    def collect_percent_sequence(bytes, index, component, sequence)
      expected = begin
        utf8_length(sequence.first)
      rescue ArgumentError
        invalid!(component, index, 'contains malformed UTF-8')
      end
      next_index = index + 3
      while sequence.length < expected
        if next_index >= bytes.bytesize || bytes.getbyte(next_index) != 0x25
          invalid!(component, index, 'contains malformed UTF-8')
        end
        triplet = percent_triplet(bytes, next_index, component)
        decoded_byte = Integer(triplet[1, 2], 16)
        invalid!(component, next_index, 'contains malformed UTF-8') if decoded_byte < 0x80
        sequence << decoded_byte
        next_index += 3
      end
      next_index
    end

    def ascii_allowed?(byte, component)
      return true if unreserved?(byte) || subdelimiter?(byte) ||
        byte == 0x40 || byte == 0x3D || byte == 0x24
      return true if component == :path && byte == 0x2F
      if (component == :query || component == :fragment) &&
         (byte == 0x2F || byte == 0x3F)
        return true
      end
      false
    end

    def keep_encoded_ascii?(byte, component)
      reserved_ascii?(byte) || !ascii_allowed?(byte, component)
    end

    def unreserved?(byte)
      byte.between?(0x30, 0x39) || byte.between?(0x41, 0x5A) ||
        byte.between?(0x61, 0x7A) ||
        byte == 0x2D || byte == 0x2E || byte == 0x5F || byte == 0x7E
    end

    def subdelimiter?(byte)
      case byte
      when 0x21, 0x24, 0x26, 0x27, 0x28, 0x29,
           0x2A, 0x2B, 0x2C, 0x3B, 0x3D then true
      else false
      end
    end

    def reserved_ascii?(byte)
      case byte
      when 0x21..0x2F, 0x3A..0x40, 0x5B..0x5E, 0x60, 0x7B..0x7E then true
      else false
      end
    end

    def utf8_sequence(bytes, index, component)
      first = bytes.getbyte(index)
      width =
        if first >= 0xF0 then 4
        elsif first >= 0xE0 then 3
        elsif first >= 0xC0 then 2
        else
          invalid!(component, index, 'contains malformed UTF-8')
        end

      sequence = bytes.byteslice(index, width)&.bytes
      if sequence.nil? || sequence.length != width
        invalid!(component, index, 'contains malformed UTF-8')
      end
      valid_utf8!(sequence, component, index)
      sequence
    end

    def valid_utf8!(bytes, component, position)
      first = bytes.first
      length = utf8_length(first)
      raise ArgumentError unless bytes.length == length
      raise ArgumentError unless bytes[1...length].all? { |byte| (byte & 0xC0) == 0x80 }

      codepoint = first & (length == 2 ? 0x1F : length == 3 ? 0x0F : 0x07)
      bytes[1...length].each { |byte| codepoint = (codepoint << 6) | (byte & 0x3F) }

      minimum = [0x80, 0x800, 0x10000][length - 2]
      raise ArgumentError if codepoint < minimum
      raise ArgumentError if (0xD800..0xDFFF).cover?(codepoint) || codepoint > 0x10FFFF
      codepoint
    rescue ArgumentError
      invalid!(component, position, 'contains malformed UTF-8')
    end

    def utf8_length(byte)
      return 2 if byte&.between?(0xC2, 0xDF)
      return 3 if byte&.between?(0xE0, 0xEF)
      return 4 if byte&.between?(0xF0, 0xF4)
      raise ArgumentError
    end

    def append_unicode(result, codepoint, sequence, component, bytes = nil, start = nil, finish = nil)
      if unicode_allowed?(codepoint, component)
        result << sequence.pack('C*').force_encoding(Encoding::UTF_8)
      elsif bytes && start && finish
        result << bytes.byteslice(start, finish - start)
      else
        sequence.each { |byte| result << format('%%%02X', byte) }
      end
    end

    def unicode_allowed?(codepoint, component)
      return true if component != :path && iprivate?(codepoint)
      ucschar?(codepoint)
    end

    def iprivate?(codepoint)
      (0xE000..0xF8FF).cover?(codepoint) ||
        (0xF0000..0xFFFFD).cover?(codepoint) ||
        (0x100000..0x10FFFD).cover?(codepoint)
    end

    def ucschar?(codepoint)
      (0x00A0..0xD7FF).cover?(codepoint) ||
        (0xF900..0xFDCF).cover?(codepoint) ||
        (0xFDF0..0xFFEF).cover?(codepoint) ||
        (0x10000..0x1FFFD).cover?(codepoint) ||
        (0x20000..0x2FFFD).cover?(codepoint) ||
        (0x30000..0x3FFFD).cover?(codepoint) ||
        (0x40000..0x4FFFD).cover?(codepoint) ||
        (0x50000..0x5FFFD).cover?(codepoint) ||
        (0x60000..0x6FFFD).cover?(codepoint) ||
        (0x70000..0x7FFFD).cover?(codepoint) ||
        (0x80000..0x8FFFD).cover?(codepoint) ||
        (0x90000..0x9FFFD).cover?(codepoint) ||
        (0xA0000..0xAFFFD).cover?(codepoint) ||
        (0xB0000..0xBFFFD).cover?(codepoint) ||
        (0xC0000..0xCFFFD).cover?(codepoint) ||
        (0xD0000..0xDFFFD).cover?(codepoint) ||
        (0xE1000..0xEFFFD).cover?(codepoint)
    end

    def invalid!(component, position, message)
      raise InvalidIRIError.new(
        "invalid #{component} component at byte position #{position}: #{message}",
        component,
        position
      )
    end
  end
  private_constant :IRI
end
