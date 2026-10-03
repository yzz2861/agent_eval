# frozen_string_literal: true
require 'mustermann/error'

module Mustermann
  # Unicode normalization support for pattern matching.
  #
  # Enabled per pattern instance via the +unicode_normalize+ option. Currently
  # only NFC is supported. Normalization is applied to the pattern's literal
  # text and to the strings being matched, never to regular expression syntax,
  # and it never changes the case of any characters.
  #
  # @!visibility private
  module Normalizer
    module_function

    # Canonicalizes the option value.
    #
    # @param [nil, false, true, Symbol] value the option value
    # @return [Symbol, nil] the normalization form (+:nfc+) or nil if disabled
    # @raise [ArgumentError] if the form is not supported
    def form(value)
      case value
      when nil, false then nil
      when true, :nfc   then :nfc
      else raise ArgumentError, "unsupported unicode normalization form %p (only :nfc is supported)" % value
      end
    end

    # @param [String] string the string to normalize
    # @param [Symbol] form the normalization form
    # @return [String] the normalized string
    # @raise [Mustermann::Error] if the string has an invalid or unsupported encoding
    def normalize(string, form = :nfc)
      encode(string).unicode_normalize(form)
    rescue ArgumentError, Encoding::CompatibilityError => error
      raise Mustermann::Error, "cannot unicode normalize %p: %s" % [string, error.message]
    end

    # Normalizes a string and computes a map from character offsets in the
    # normalized string to character offsets in the original string, so capture
    # ranges can be translated back to the original (unnormalized) string.
    #
    # @param [String] string the string to normalize
    # @param [Symbol] form the normalization form
    # @return [Array(String, String, Array<Integer>, nil)]
    #   the original string (re-encoded if necessary), the normalized string,
    #   and the offset map (nil if normalization did not change the string)
    # @raise [Mustermann::Error] if the string has an invalid or unsupported encoding
    def normalize_with_map(string, form = :nfc)
      original   = encode(string)
      normalized = normalize(original, form)
      return [original, normalized, nil] if normalized == original
      [original, normalized, boundary_map(original, normalized, form)]
    end

    # Brings the string into an encoding suitable for unicode normalization.
    # Binary strings are treated as UTF-8, which is what web frameworks
    # typically mean when handing over raw request paths.
    #
    # @param [String] string the string to encode
    # @return [String] the string in a normalization-capable encoding
    # @!visibility private
    def encode(string)
      string.encoding == Encoding::BINARY ? string.dup.force_encoding(Encoding::UTF_8) : string
    end

    # Builds a map from character offsets in the normalized string to
    # character offsets in the original string. Offsets that fall inside a
    # composed character cluster are mapped to the end of that cluster.
    #
    # @param [String] original the original string
    # @param [String] normalized the normalized string
    # @param [Symbol] form the normalization form
    # @return [Array<Integer>] offset map with normalized.length + 1 entries
    # @!visibility private
    def boundary_map(original, normalized, form)
      map          = { 0 => 0 }
      buffer       = +''
      buffer_start = 0
      offset       = 0

      original.each_char do |char|
        buffer  << char
        offset  += 1
        segment  = normalize(buffer, form)
        next unless normalized[buffer_start, segment.length] == segment

        buffer_start += segment.length
        map[buffer_start] = offset
        buffer = +''
      end

      (normalized.length - 1).downto(0) { |index| map[index] ||= map[index + 1] }
      map.values_at(*(0..normalized.length))
    end
  end
end
