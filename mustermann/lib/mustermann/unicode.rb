# frozen_string_literal: true

require 'uri'

module Mustermann
  # Unicode normalization helpers shared by matching and expansion.
  # @see file:mustermann/README.md[Available Options] in the README
  # @!visibility private
  module Unicode
    # Normalization forms accepted by the +normalization+ option.
    # New forms (e.g. :nfd, :nfkc, :nfkd) can be added here in the future.
    SUPPORTED_FORMS = %i[nfc].freeze

    # @return [Boolean] whether the given form is a supported normalization form
    def self.supported?(form)
      SUPPORTED_FORMS.include? form.to_sym
    end

    # Applies the requested Unicode normalization form to a string.
    #
    # @param string [String] the string to normalize
    # @param form [Symbol] normalization form (currently only +:nfc+)
    # @return [String] the normalized string
    # @raise [Mustermann::NormalizeError] if the string is not validly encoded
    def self.normalize(string, form = :nfc)
      string.unicode_normalize(form)
    rescue ArgumentError, EncodingError, Encoding::CompatibilityError => error
      raise NormalizeError, "cannot apply Unicode #{form.to_s.upcase} normalization: #{error.message}"
    end

    # @return [Array<String>] the distinct canonical compositions/decompositions of
    #   the character for the given normalization form, starting with the given form.
    def self.forms(char, form)
      nfc = char.unicode_normalize(form)
      nfd = nfc.unicode_normalize(:nfd)
      [nfc, nfd].uniq
    end

    # URI parser used for building percent-encoded variants.
    URI_PARSER = defined?(URI::RFC2396_PARSER) ? URI::RFC2396_PARSER : URI::RFC2396_Parser.new

    # All raw/percent-encoded representations of a literal pattern character
    # that should match when the given normalization form is enabled.
    #
    # Includes the character's other canonical form (e.g. an NFC pattern
    # character also matches its NFD counterpart) and any mix of percent
    # encoded and raw code points (relevant for decomposed sequences).
    #
    # @param char [String] the pattern character
    # @param form [Symbol] the normalization form
    # @param uri_decode [Boolean] whether percent-encoded variants are included
    # @return [Array<String>] distinct representations of the character
    def self.representations(char, form = :nfc, uri_decode: true)
      return forms(char, form).uniq unless uri_decode

      forms(char, form).flat_map { |variant| escaped_forms(variant) }.uniq
    end

    # Produces raw/percent-encoded representations of one canonical form without
    # ever splitting characters that compose together (otherwise the
    # alternatives for "e\u0301" could accidentally match a bare "e"). This
    # covers combining marks and Hangul jamo, which are letters, not marks.
    # @!visibility private
    def self.escaped_forms(variant)
      clusters = canonical_clusters(variant)
      variants_per_cluster = clusters.map do |cluster|
        codepoints = cluster.chars
        escaped    = codepoints.map { |c| URI_PARSER.escape(c, /./) }
        # Enumerate every subset of escaped code points, so that e.g. "e\u0301"
        # also matches "e%CC%81" and "%65%CC%81".
        subset_count = codepoints.size > 10 ? nil : 1 << codepoints.size
        subsets = subset_count ? 0.upto(subset_count - 1).to_a : [0, (1 << codepoints.size) - 1]
        subsets.map do |mask|
          codepoints.each_with_index.map do |codepoint, index|
            mask[index] == 1 ? escaped[index] : codepoint
          end.join
        end
      end

      return variants_per_cluster.first if variants_per_cluster.size == 1
      variants_per_cluster.first.product(*variants_per_cluster[1..]).map(&:join)
    end

    # Splits a (possibly decomposed) string into substrings that each compose to
    # a single NFC character (e.g. "e\u0301", Hangul lead+jungseong).
    # @!visibility private
    def self.canonical_clusters(string)
      clusters = []
      string.each_char do |char|
        if clusters.empty? || !attaches?(clusters[-1], char)
          clusters << char.dup
        else
          clusters[-1] << char
        end
      end
      clusters
    end

    # @return [Boolean] whether +char+ belongs to the same canonical cluster as
    #   +prefix+ (a combining mark or a Hangul jamo composing with the prefix)
    # @!visibility private
    def self.attaches?(prefix, char)
      return true if char =~ /\A\p{Mark}+\z/
      merged = prefix + char
      merged.unicode_normalize(:nfc).size < merged.size
    end
  end
end
