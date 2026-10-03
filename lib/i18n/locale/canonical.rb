# frozen_string_literal: true

# Canonicalizes locale tags based on an application-provided alias table, so
# that equivalent locale identifiers (legacy language codes, inconsistently
# cased script names, explicit whole-tag aliases) share the same lookup and
# cache identity.
#
# The alias table may contain two kinds of entries:
#
# * Whole-tag aliases, mapping a complete tag to another tag:
#     I18n.locale_aliases = { :"zh-Hant-TW" => :"zh-TW" }
# * Subtag aliases, mapping a single language, script or region subtag to a
#   replacement. They apply to whichever of those positions the subtag
#   occurs in:
#     I18n.locale_aliases = { :iw => :he, :Cyrl => :Latn, :BU => :MM }
#
# Matching is case-insensitive; canonicalization normalizes the casing of
# language, script and region subtags following BCP 47 conventions. Variant,
# extension and private use subtags are never dropped: whole-tag aliases
# match the base of a tag and any extension or private use subtags are
# carried over (lowercased), so no information is silently lost.
#
# Alias chains are resolved transitively when the table is compiled. Circular
# aliases are detected at the same time and raise I18n::CircularLocaleAlias.
# The table is only ever consulted locally - no registry is fetched.
module I18n
  module Locale
    class Canonical
      SCRIPT_PATTERN = /\A[a-z]{4}\z/i
      REGION_PATTERN = /\A(?:[a-z]{2}|\d{3})\z/i

      def initialize(aliases = nil)
        @tag_aliases = {}
        @subtag_aliases = {}
        compile(aliases) if aliases && !aliases.empty?
      end

      # Returns the canonical form of the given locale tag as a Symbol.
      def canonicalize(tag)
        string = apply_tag_alias(canonical_form(tag.to_s.tr('_', '-')))

        language, script, region, variants, extensions = split_subtags(string)
        unless @subtag_aliases.empty?
          language = substitute(language, :language) if language
          script   = substitute(script, :script)     if script
          region   = substitute(region, :region)     if region
        end

        join_subtags(language, script, region, variants, extensions).to_sym
      end

      protected

      def compile(aliases)
        tags = {}
        subtags = {}
        aliases.each do |from, to|
          from = from.to_s
          if from.include?('-') || from.include?('_')
            tags[canonical_form(from.tr('_', '-'))] = canonical_form(to.to_s.tr('_', '-'))
          else
            subtags[from.downcase] = to.to_s.downcase
          end
        end
        @tag_aliases = resolve(tags)
        @subtag_aliases = resolve(subtags)
      end

      # Resolves alias chains transitively, raising CircularLocaleAlias when
      # a cycle is found.
      def resolve(aliases)
        resolved = {}
        aliases.each_key { |key| walk(key, aliases, resolved, []) }
        resolved
      end

      def walk(key, aliases, resolved, trail)
        return resolved[key] if resolved.key?(key)
        raise CircularLocaleAlias.new([*trail, key]) if trail.include?(key)

        target = aliases[key]
        target = walk(target, aliases, resolved, [*trail, key]) if aliases.key?(target)
        resolved[key] = target
      end

      # Applies a whole-tag alias. Tags carrying extension or private use
      # subtags are matched on their base (language, script, region, variant)
      # so that the extension subtags are preserved instead of being dropped.
      def apply_tag_alias(string)
        return @tag_aliases[string] if @tag_aliases.key?(string)
        return string if @tag_aliases.empty?

        language, script, region, variants, extensions = split_subtags(string)
        return string if extensions.empty?

        target = @tag_aliases[join_subtags(language, script, region, variants, [])]
        target ? join_subtags(target, nil, nil, [], extensions) : string
      end

      # Normalizes subtag casing without applying any aliases.
      def canonical_form(string)
        join_subtags(*split_subtags(string))
      end

      # Splits a tag into [language, script, region, variants, extensions].
      # Extension and private use subtags (everything from the first
      # singleton subtag on) are preserved, lowercased.
      def split_subtags(string)
        subtags = string.split('-')
        language = subtags.shift

        if language.nil? || language.empty? || language.downcase == 'x'
          return [nil, nil, nil, [], [language, *subtags].compact.map!(&:downcase)]
        end

        language = language.downcase
        script = subtags.first =~ SCRIPT_PATTERN ? subtags.shift.downcase.capitalize : nil
        region = subtags.first =~ REGION_PATTERN ? subtags.shift.upcase : nil
        variants = []
        variants << subtags.shift.downcase while subtags.first && subtags.first.length > 1
        [language, script, region, variants, subtags.map!(&:downcase)]
      end

      def join_subtags(language, script, region, variants, extensions)
        [language, script, region, *variants, *extensions].compact.join('-')
      end

      def substitute(subtag, position)
        replacement = @subtag_aliases[subtag.downcase]
        return subtag unless replacement

        case position
        when :script then replacement.capitalize
        when :region then replacement.upcase
        else replacement
        end
      end
    end
  end
end
