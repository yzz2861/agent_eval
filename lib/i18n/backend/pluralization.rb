# frozen_string_literal: true

# I18n Pluralization are useful when you want your application to
# customize pluralization rules.
#
# To enable locale specific pluralizations you can simply include the
# Pluralization module to the Simple backend - or whatever other backend you
# are using.
#
#   I18n::Backend::Simple.include(I18n::Backend::Pluralization)
#
# You also need to make sure to provide pluralization algorithms to the
# backend, i.e. include them to your I18n.load_path accordingly.
module I18n
  module Backend
    module Pluralization
      # Overwrites the Base backend translate method so that it will check the
      # translation meta data space (:i18n) for a locale specific pluralization
      # rule and use it to pluralize the given entry. I.e., the library expects
      # pluralization rules to be stored at I18n.t(:'i18n.plural.rule')
      #
      # Pluralization rules are expected to respond to #call(count) and
      # return a pluralization key. Valid keys depend on the pluralization
      # rules for the locale, as defined in the CLDR.
      # As of v41, 6 locale-specific plural categories are defined:
      #   :few, :many, :one, :other, :two, :zero
      #
      # n.b., The :one plural category does not imply the number 1.
      # Instead, :one is a category for any number that behaves like 1 in
      # that locale. For example, in some locales, :one is used for numbers
      # that end in "1" (like 1, 21, 151) but that don't end in
      # 11 (like 11, 111, 10311).
      # Similar notes apply to the :two, and :zero plural categories.
      #
      # If you want to have different strings for the categories of count == 0
      # (e.g. "I don't have any cars") or count == 1 (e.g. "I have a single car")
      # use the explicit `"0"` and `"1"` keys.
      # https://unicode-org.github.io/cldr/ldml/tr35-numbers.html#Explicit_0_1_rules
      def pluralize(locale, entry, count)
        return entry unless entry.is_a?(Hash) && count

        pluralizer = pluralizer(locale)
        if pluralizer.respond_to?(:call)
          # Deprecation: The use of the `zero` key in this way is incorrect.
          # Users that want a different string for the case of `count == 0` should use the explicit "0" key instead.
          # We keep this incorrect behaviour for now for backwards compatibility until we can remove it.
          # Ref: https://github.com/ruby-i18n/i18n/issues/629
          return entry[:zero] if count == 0 && entry.has_key?(:zero)

          # "0" and "1" are special cases
          # https://unicode-org.github.io/cldr/ldml/tr35-numbers.html#Explicit_0_1_rules
          if count == 0 || count == 1
            value = entry[symbolic_count(count)]
            return value if value
          end

          # Lateral Inheritance of "count" attribute (http://www.unicode.org/reports/tr35/#Lateral_Inheritance):
          # > If there is no value for a path, and that path has a [@count="x"] attribute and value, then:
          # > 1. If "x" is numeric, the path falls back to the path with [@count=«the plural rules category for x for that locale»], within that the same locale.
          # > 2. If "x" is anything but "other", it falls back to a path [@count="other"], within that the same locale.
          # > 3. If "x" is "other", it falls back to the path that is completely missing the count item, within that the same locale.
          # Note: We don't yet implement #3 above, since we haven't decided how lateral inheritance attributes should be represented.
          plural_rule_category = pluralizer.call(count)

          value = if entry.has_key?(plural_rule_category) || entry.has_key?(:other)
            entry[plural_rule_category] || entry[:other]
          else
            raise InvalidPluralizationData.new(entry, count, plural_rule_category)
          end
        else
          super
        end
      end

      def pluralize_count_range(locale, entry, count_range)
        return entry unless entry.is_a?(Hash) && count_range
        # A single-value range uses the same priority as :count:
        # explicit "0"/"1", then the locale plural category.
        return pluralize(locale, entry, count_range.begin) if count_range.begin == count_range.end

        pluralizer = pluralizer(locale)
        return super unless pluralizer.respond_to?(:call)

        start_category = pluralizer.call(count_range.begin)
        end_category = pluralizer.call(count_range.end)
        range_category = plural_range_category(locale, start_category, end_category)

        if entry.has_key?(range_category) || entry.has_key?(:other)
          entry[range_category] || entry[:other]
        else
          raise InvalidPluralizationData.new(entry, count_range, range_category)
        end
      end

      protected

      def pluralizers
        @pluralizers ||= {}
      end

      def pluralizer(locale)
        pluralizers[locale] ||= I18n.t(:'i18n.plural.rule', :locale => locale, :resolve => false)
      end

      # Range rules are application-supplied locale data at
      # i18n.plural.range.rule. A hash maps start/end category pairs to the
      # entry category; a callable receives the two categories.
      def plural_range_category(locale, start_category, end_category)
        range_rule = I18n.t(:'i18n.plural.range.rule', :locale => locale, :resolve => false)
        if range_rule.respond_to?(:call)
          return range_rule.call(start_category, end_category).to_sym
        end

        unless range_rule.is_a?(Hash)
          raise I18n::ArgumentError,
            "plural range rule is missing for locale #{locale.inspect}. Configure i18n.plural.range.rule."
        end

        category = range_rule.dig(start_category.to_sym, end_category.to_sym) ||
          range_rule.dig(start_category.to_s, end_category.to_s)

        unless category
          raise I18n::ArgumentError,
            "plural range rule for locale #{locale.inspect} is missing #{start_category.inspect} => #{end_category.inspect}."
        end

        category.to_sym
      end

      private

      # Normalizes categories of 0.0 and 1.0
      # and returns the symbolic version
      def symbolic_count(count)
        count = 0 if count == 0
        count = 1 if count == 1
        count.to_s.to_sym
      end
    end
  end
end
