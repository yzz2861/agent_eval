# frozen_string_literal: true

require 'concurrent/map'
require 'i18n/locale/tag/rfc4646'

module I18n
  module Locale
    # Maps application supplied locale identifiers onto a single canonical
    # identity. Equivalent identifiers (legacy language codes, inconsistently
    # cased script tags, locales carrying extension subtags, ...) resolve to the
    # same canonical tag and therefore share lookups, fallbacks and caches.
    #
    # The alias table is provided by the application and never fetched from the
    # network. It supports four kinds of replacements:
    #
    #   I18n::Locale::Canonical.new(
    #     language: { iw: :he, in: :id },        # legacy language codes
    #     script:   { hant: :'Hant' },           # script casing
    #     region:   { us: :US },                 # region casing
    #     tag:      { :'zh-TW' => :'zh-Hant-TW' } # explicit whole-tag aliases
    #   )
    #
    # Aliases may form chains (e.g. <tt>a => b => c</tt>) but must never form a
    # cycle; a cycle raises I18n::LocaleAliasCycle while the table is built.
    #
    # Canonicalization only normalizes the language/script/region subtags and
    # resolves aliases. Variant, extension and private use subtags are preserved
    # verbatim so that locales such as <tt>de-DE-u-ca-gregory</tt> keep their
    # extension throughout fallback generation.
    class Canonical
      ALIAS_KEYS = [:language, :script, :region, :tag].freeze

      def self.coerce(aliases)
        aliases.is_a?(Canonical) ? aliases : new(aliases || {})
      end

      attr_reader :aliases

      def initialize(aliases = {})
        @aliases = {}
        ALIAS_KEYS.each { |key| @aliases[key] = normalize_table(aliases[key], key) }
        detect_cycles!
        @cache = I18n.new_double_nested_cache
      end

      # Returns the canonical Symbol for the given locale. Inputs that cannot be
      # parsed as RFC 4646 tags are returned unchanged (as Symbols).
      def canonical(locale)
        case locale
        when Symbol
          canonical_string(locale.to_s).to_sym
        when String
          canonical_string(locale).to_sym
        else
          locale
        end
      end

      private

      def canonical_string(input)
        @cache[:locale][input] ||= build(input)
      end

      def build(input)
        tag = Tag::Rfc4646.tag(input)
        return input unless tag

        # Explicit whole-tag aliases take precedence and may chain.
        primary = join_primary(tag)
        explicit, matched = resolve_tag(primary)
        base_tag =
          if matched
            target_tag = Tag::Rfc4646.tag(explicit)
            target_tag ? primary_alias(target_tag) : explicit
          else
            primary_alias(tag)
          end

        attach_suffix(base_tag, tag)
      end

      def primary_alias(tag)
        language = follow(:language, raw(tag, :language)&.downcase)
        script   = follow(:script, capitalize(raw(tag, :script)))
        region   = follow(:region, raw(tag, :region)&.upcase)
        join(language, script, region)
      end

      # Explicit whole-tag aliases may chain but must never cycle; cycles are
      # rejected up front in #detect_cycles!. Returns the final tag in the
      # replacement chain together with a flag indicating a match.
      def resolve_tag(primary)
        seen = []
        current = primary
        loop do
          replacement = @aliases[:tag][current]
          break unless replacement
          return [current, true] if seen.include?(current)
          seen << current
          current = tag_key(replacement)
        end
        [current, !seen.empty?]
      end

      def follow(kind, value)
        return value unless value
        seen = []
        current = value
        while @aliases[kind].key?(current)
          return current if seen.include?(current)
          seen << current
          current = @aliases[kind][current]
        end
        current
      end

      def attach_suffix(base_tag, source_tag)
        suffix = suffix(source_tag)
        return base_tag if suffix.empty?
        base_tag.empty? ? suffix[1..] : "#{base_tag}#{suffix}"
      end

      def suffix(tag)
        [:variant, :extension, :privateuse].filter_map do |part|
          value = raw(tag, part)
          value && "-#{value}"
        end.join
      end

      def join(language, script, region)
        [language, script, region].compact.join('-')
      end

      def join_primary(tag)
        join(raw(tag, :language)&.downcase, capitalize(raw(tag, :script)), raw(tag, :region)&.upcase)
      end

      def raw(tag, part)
        tag[part]
      end

      def capitalize(value)
        value && value.downcase.capitalize
      end

      # Whole-tag aliases are matched against the normalized primary subtags
      # (language/script/region casing) so that the alias table itself does not
      # need to enumerate every input casing.
      def tag_key(tag)
        string = tag.to_s
        parsed = Tag::Rfc4646.tag(string)
        parsed ? "#{join_primary(parsed)}#{suffix(parsed)}" : string
      end

      def normalize_table(table, kind)
        Array(table).each_with_object({}) do |(from, to), result|
          next if from.nil? || to.nil?
          from = from.to_s
          to = Array(to).first
          result[case_key(from, kind)] = to.to_s
        end
      end

      def case_key(value, kind)
        case kind
        when :language then value.downcase
        when :script   then value.downcase.capitalize
        when :region   then value.upcase
        else                tag_key(value)
        end
      end

      def detect_cycles!
        @aliases.each do |kind, table|
          table.each_key do |start|
            seen = []
            current = start
            while current
              if seen.include?(current)
                cycle = (seen + [current]).join(' -> ')
                raise I18n::LocaleAliasCycle.new(kind, cycle)
              end
              seen << current
              replacement = table[current]
              break unless replacement
              replacement_key = kind == :tag ? tag_key(replacement) : case_key(replacement, kind)
              break if replacement_key == current
              current = replacement_key
            end
          end
        end
      end
    end
  end
end
