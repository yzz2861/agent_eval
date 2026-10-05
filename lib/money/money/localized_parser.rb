# frozen_string_literal: true

require "bigdecimal"
require "money/money/localized_parser/region_rules"
require "money/money/localized_parser/token_scanner"

class Money
  # Parses one explicitly localized monetary string without using Float.
  class LocalizedParser
    InvalidAmount = Class.new(ArgumentError)

    include RegionRules
    include TokenScanner

    def self.parse(input, given_locale = nil, given_currency = nil, locale: nil, region: nil, currency: nil, **options)
      if locale && region && locale != region
        raise InvalidAmount, "provide either locale: or region:, not both"
      end
      chosen_locale = locale || region || given_locale
      chosen_currency = currency || given_currency
      new(input, locale: chosen_locale, currency: chosen_currency, **options).parse
    end

    def initialize(input, locale:, currency: nil, **options)
      @input = input
      @locale = RegionRules.find(locale)
      @explicit_currency = Currency.wrap(currency) if currency
      @options = options
    end

    def parse
      raise InvalidAmount, "amount must be a String" unless @input.is_a?(String)

      text = normalize(@input)
      raise InvalidAmount, "amount can't be blank" if text.empty?

      parts = tokenize(text)
      negative = parts.fetch(:parenthesized)
      currency = resolve_currency(parts[:prefix_marker], parts[:suffix_marker])
      validate_signs!(negative, parts[:sign])

      amount = parse_number(parts.fetch(:number))
      amount = -amount if negative || parts[:sign] == "-"
      Money.from_amount(amount, currency, @options)
    end

    private

    def normalize(value)
      value
        .gsub("\u2013", "-")
        .gsub("\u2014", "-")
        .gsub("\u2212", "-")
        .gsub("\uFEFF", "")
        .strip
    end

    def marker_keys
      @marker_keys ||= currency_index.keys.reject(&:empty?).sort_by { |item| -item.length }
    end

    def currency_index
      @currency_index ||= Currency.table.each_with_object({}) do |(_, data), index|
        add_marker(index, data.fetch(:iso_code), data[:iso_code])
        add_marker(index, data[:symbol], data[:iso_code]) unless data[:symbol].to_s.empty?
        unless data[:disambiguate_symbol].to_s.empty?
          add_marker(index, data[:disambiguate_symbol], data[:iso_code])
        end
        Array(data[:alternate_symbols]).each do |marker|
          add_marker(index, marker, data[:iso_code])
        end
      end
    end

    def add_marker(index, marker, iso_code)
      normalized = normalize_marker(marker)
      return if normalized.empty?
      index[normalized] ||= []
      index[normalized] << iso_code unless index[normalized].include?(iso_code)
    end

    def normalize_marker(marker)
      marker.to_s.gsub(/[\u00A0\u202F\u2009\u2008\u2007\u3000]+/, " ").strip
    end

    def resolve_currency(prefix_marker, suffix_marker)
      if prefix_marker && suffix_marker && prefix_marker != suffix_marker
        raise InvalidAmount, "conflicting currency markers"
      end

      marker = prefix_marker || suffix_marker
      candidates = marker ? currency_index.fetch(marker) : []
      currency = @explicit_currency

      if marker
        if currency && !candidates.include?(currency.iso_code)
          raise InvalidAmount, "currency marker conflicts with #{currency.iso_code}"
        end
        currency ||= resolve_marker_currency(candidates)
      end

      currency ||= Currency.wrap(@locale.fetch(:currency))
      currency
    end

    def resolve_marker_currency(candidates)
      default = @locale.fetch(:currency)
      return Currency.new(default) if candidates.include?(default)
      return Currency.new(candidates.first) if candidates.length == 1

      raise InvalidAmount, "ambiguous currency marker; specify :currency"
    end

    def validate_signs!(parenthesized, sign)
      raise InvalidAmount, "parentheses can only denote a negative amount" if parenthesized && sign
    end

    def parse_number(value)
      decimal = Regexp.escape(@locale.fetch(:decimal))
      group = @locale.fetch(:group)
      group_pattern = group.start_with?("[") ? group : Regexp.escape(group)
      pattern = /\A[+\-]?\d+(?:#{group_pattern}\d+)*(?:#{decimal}\d+)?\z/
      raise InvalidAmount, "invalid localized amount" unless value.match?(pattern)
      raise InvalidAmount, "invalid localized amount" unless value.match?(/\d/)

      whole, fraction = value.split(@locale.fetch(:decimal), 2)
      validate_grouping!(whole.to_s.sub(/\A[+-]/, ""))
      normalized = whole.to_s.gsub(/#{group_pattern}/, "")
      BigDecimal("#{normalized}#{fraction && ".#{fraction}"}")
    end

    def validate_grouping!(whole)
      group = @locale.fetch(:group)
      group_pattern = group.start_with?("[") ? group : Regexp.escape(group)
      parts = whole.split(/#{group_pattern}/, -1)
      return if parts.length == 1

      valid =
        if @locale[:first_group] == :indian
          parts.first.length <= 2 &&
            (parts.length == 2 ? parts.last.length == 3 : parts[1...-1].all? { |part| part.length == 2 }) &&
            parts.last.length == 3
        else
          parts.first.length.between?(1, 3) &&
            parts.drop(1).all? { |part| part.length == 3 }
        end
      raise InvalidAmount, "invalid digit grouping" unless valid
    end
  end
end
