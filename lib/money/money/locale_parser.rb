# frozen_string_literal: true

require "bigdecimal"

class Money
  class LocaleParser
    class InvalidFormat < ArgumentError; end

    WESTERN_DOT_COMMA = {
      decimal_mark: ".",
      group_separator: ",",
      grouping: :western,
      symbol_position: :before,
    }.freeze

    REGIONS = {
      "en-us" => WESTERN_DOT_COMMA.merge(default_currency: "USD"),
      "en-ca" => WESTERN_DOT_COMMA.merge(default_currency: "CAD"),
      "en-au" => WESTERN_DOT_COMMA.merge(default_currency: "AUD"),
      "en-hk" => WESTERN_DOT_COMMA.merge(default_currency: "HKD"),
      "en-gb" => WESTERN_DOT_COMMA.merge(default_currency: "GBP"),
      "pt-br" => {
        decimal_mark: ",",
        group_separator: ".",
        grouping: :western,
        default_currency: "BRL",
        symbol_position: :before,
      },
      "de-de" => {
        decimal_mark: ",",
        group_separator: ". \u00A0\u202F",
        grouping: :western,
        default_currency: "EUR",
        symbol_position: :after,
      },
      "nl-nl" => {
        decimal_mark: ",",
        group_separator: ". \u00A0\u202F",
        grouping: :western,
        default_currency: "EUR",
        symbol_position: :before,
      },
      "es-es" => {
        decimal_mark: ",",
        group_separator: ". \u00A0\u202F",
        grouping: :western,
        default_currency: "EUR",
        symbol_position: :after,
      },
      "fr-fr" => {
        decimal_mark: ",",
        group_separator: "\u00A0\u202F",
        grouping: :western,
        default_currency: "EUR",
        symbol_position: :after,
      },
      "it-it" => {
        decimal_mark: ",",
        group_separator: ". \u00A0\u202F",
        grouping: :western,
        default_currency: "EUR",
        symbol_position: :before,
      },
      "sv-se" => {
        decimal_mark: ",",
        group_separator: " \u00A0\u202F",
        grouping: :western,
        default_currency: "SEK",
        symbol_position: :after,
      },
      "nb-no" => {
        decimal_mark: ",",
        group_separator: ".",
        grouping: :western,
        default_currency: "NOK",
        symbol_position: :after,
      },
      "pl-pl" => {
        decimal_mark: ",",
        group_separator: " \u00A0\u202F",
        grouping: :western,
        default_currency: "PLN",
        symbol_position: :after,
      },
      "ru-ru" => {
        decimal_mark: ",",
        group_separator: " \u00A0\u202F",
        grouping: :western,
        default_currency: "RUB",
        symbol_position: :after,
      },
      "de-ch" => {
        decimal_mark: ".",
        group_separator: "'\u2019",
        grouping: :western,
        default_currency: "CHF",
        symbol_position: :before,
      },
      "en-in" => {
        decimal_mark: ".",
        group_separator: ",",
        grouping: :indian,
        default_currency: "INR",
        symbol_position: :before,
      },
    }.freeze

    SIGN_PATTERN = /[+\u2212\u2010\u2011\u2012\u2013\u2014-]/
    EDGE_SPACE_CHARACTERS = " \t\u00A0\u202F"

    def self.parse(input, region:, currency: nil)
      new(input, region: region, currency: currency).parse
    end

    def initialize(input, region:, currency: nil)
      raise InvalidFormat, "input must be a String" unless input.is_a?(String)

      @input = input
      @region = resolve_region(region)
      @explicit_currency = wrap_currency(currency) unless currency.nil?
      @markers = []
      @signs = []
      @parenthesized = false
    end

    def parse
      raise InvalidFormat, "input must not be empty" if input.empty? || input.strip.empty?
      raise InvalidFormat, "input contains an unsupported line break" if input.match?(/\R/)

      working = input.dup

      collect_markers(working)
      collect_signs(working)
      @parenthesized = enclosing_parentheses?(working)
      validate_parentheses_balance(working)
      validate_markers(working)
      validate_signs(working)

      normalized, fraction_length = number_without_markers(working)
      currency = resolve_currency
      fractional = amount_to_fractional(BigDecimal(normalized), currency, fraction_length)

      [fractional, currency]
    end

    private

    attr_reader :input, :region, :explicit_currency, :markers, :signs, :parenthesized

    def resolve_region(region)
      unless region.is_a?(Hash)
        key = region.to_s.downcase.tr("_", "-")
        return REGIONS.fetch(key) { raise InvalidFormat, "unknown region #{region.inspect}" }
      end

      required_keys = %i[decimal_mark group_separator grouping symbol_position]
      missing_keys = required_keys.reject { |key| region.key?(key) }
      unless missing_keys.empty?
        raise InvalidFormat, "region rules are missing #{missing_keys.join(", ")}"
      end

      region
    end

    def wrap_currency(currency)
      Money::Currency.wrap(currency)
    rescue Money::Currency::UnknownCurrency => error
      raise InvalidFormat, error.message
    end

    def collect_markers(value)
      code_ranges = collect_code_markers(value)
      collect_symbol_markers(value, code_ranges)
    end

    def collect_code_markers(value)
      pattern = /\b(?:#{currency_codes.map { |code| Regexp.escape(code) }.join("|")})\b/i
      ranges = []

      value.scan(pattern) do
        match = Regexp.last_match
        range = match.begin(0)...match.end(0)
        markers << { range: range, currencies: [Money::Currency.new(match[0].upcase)], code: true }
        ranges << range
      end

      ranges
    end

    def collect_symbol_markers(value, code_ranges)
      currency_symbols.each do |symbol, currencies|
        value.scan(Regexp.new(Regexp.escape(symbol))) do
          match = Regexp.last_match
          range = match.begin(0)...match.end(0)
          next if code_ranges.any? { |code_range| code_range.cover?(range.begin) }
          next if markers.any? { |marker| marker[:range].cover?(range.begin) }

          markers << { range: range, currencies: currencies, code: false }
        end
      end
    end

    def currency_codes
      @currency_codes ||= Money::Currency.all.map(&:iso_code).compact.uniq
    end

    def currency_symbols
      @currency_symbols ||= Money::Currency.all.each_with_object({}) do |currency, result|
        markers_for_currency = [currency.symbol, currency.disambiguate_symbol]
        markers_for_currency.concat(Array(currency.alternate_symbols))
        markers_for_currency.compact.reject(&:empty?).each do |symbol|
          (result[symbol] ||= []) << currency
        end
      end.sort_by { |symbol, _| -symbol.length }.to_h
    end

    def collect_signs(value)
      value.scan(SIGN_PATTERN) do
        match = Regexp.last_match
        range = match.begin(0)...match.end(0)
        next if markers.any? { |marker| marker[:range].cover?(range.begin) }

        signs << { range: range, positive: match[0] == "+" }
      end
    end

    def validate_markers(value)
      symbols = markers.reject { |marker| marker[:code] }
      codes = markers.select { |marker| marker[:code] }
      raise InvalidFormat, "multiple currency symbols are not allowed" if symbols.length > 1
      raise InvalidFormat, "multiple currency codes are not allowed" if codes.length > 1
      raise InvalidFormat, "multiple currency markers are not allowed" if markers.length > 2
      return if symbols.empty? || marker_currencies.empty?

      position = marker_position(symbols.first, value)
      expected_position = region.fetch(:symbol_position)
      return if position == expected_position

      raise InvalidFormat, "currency symbol is in the wrong position for the selected region"
    end

    def marker_currencies
      markers.map { |marker| marker[:currencies] }.reduce(:&) || []
    end

    def marker_position(marker, value)
      range = marker[:range]
      number_start = first_digit(value)
      number_end = last_digit(value)
      before = range.end <= number_start && gap_allowed?(value, range.end, number_start)
      after = range.begin > number_end && gap_allowed?(value, number_end + 1, range.begin)

      if before && !after
        :before
      elsif after && !before
        :after
      else
        raise_invalid
      end
    end

    def validate_signs(value)
      raise InvalidFormat, "multiple amount signs are not allowed" if signs.length > 1
      return if signs.empty?

      sign = signs.first
      if parenthesized
        raise InvalidFormat, "parentheses cannot be combined with an explicit sign"
      end

      range = sign[:range]
      number_start = first_digit(value)
      number_end = last_digit(value)
      before = range.end <= number_start && gap_allowed?(value, range.end, number_start)
      after = range.begin > number_end && gap_allowed?(value, number_end + 1, range.begin)
      raise_invalid unless before || after
      validate_sign_position(value, range, before ? :before : :after)
    end

    def validate_sign_position(value, range, position)
      outside = position == :before ? value[0...range.begin] : value[range.end..]
      raise_invalid unless outside.match?(/\A[#{EDGE_SPACE_CHARACTERS}]*\z/)
    end

    def enclosing_parentheses?(value)
      first = first_digit(value)
      last = last_digit(value)
      return false if first.nil? || last.nil?

      opening = value.rindex("(", first)
      closing = value.index(")", last)
      return false if opening.nil? || closing.nil?
      return false unless opening < first && closing > last
      return false unless enclosed_gap_allowed?(value, (opening + 1)...first)
      enclosed_gap_allowed?(value, (last + 1)...closing)
    end

    def validate_parentheses_balance(value)
      depth = 0
      value.each_char do |character|
        depth += 1 if character == "("
        depth -= 1 if character == ")"
        raise_invalid if depth.negative?
      end
      raise_invalid unless depth.zero?
    end

    def enclosed_gap_allowed?(value, range)
      range.all? do |index|
        value[index].match?(/[#{EDGE_SPACE_CHARACTERS}]/) ||
          markers.any? { |marker| marker[:range].cover?(index) }
      end
    end

    def first_digit(value)
      value.index(/\d/)
    end

    def last_digit(value)
      value.rindex(/\d/)
    end

    def gap_allowed?(value, start_position, end_position)
      return false if start_position.nil? || end_position.nil?
      return true if start_position == end_position

      (start_position...end_position).all? do |index|
        value[index].match?(/[#{EDGE_SPACE_CHARACTERS}()]/) ||
          markers.any? { |marker| marker[:range].cover?(index) } ||
          signs.any? { |sign| sign[:range].cover?(index) }
      end
    end

    def number_without_markers(value)
      ranges = markers.map { |marker| marker[:range] } + signs.map { |sign| sign[:range] }
      if parenthesized
        first = first_digit(value)
        last = last_digit(value)
        opening = value.rindex("(", first)
        closing = value.index(")", last)
        ranges << (opening...(opening + 1))
        ranges << (closing...(closing + 1))
      end
      number = value.chars.reject.with_index { |_, index| ranges.any? { |range| range.cover?(index) } }.join
      number = number.gsub(/\A[#{EDGE_SPACE_CHARACTERS}]+|[#{EDGE_SPACE_CHARACTERS}]+\z/, "")

      decimal_characters = region.fetch(:decimal_mark)
      group_characters = "#{region.fetch(:group_separator)}#{region[:alternative_group_separator]}"
      allowed = "0-9#{Regexp.escape(decimal_characters)}#{Regexp.escape(group_characters)}"
      raise_invalid if number.empty? || number.match?(/[^#{allowed}]/)

      parts = number.split(/[#{Regexp.escape(decimal_characters)}]/, -1)
      raise_invalid if parts.length > 2

      whole = parts.first
      fraction = parts.length == 2 ? parts.last : ""
      raise_invalid if whole.empty? || (parts.length == 2 && fraction.empty?) ||
        fraction.match?(/[#{Regexp.escape(group_characters)}]/)
      validate_groups(whole)

      normalized_whole = whole.delete(group_characters)
      normalized = normalized_whole
      normalized = "#{normalized}.#{fraction}" unless fraction.empty?
      normalized = "-#{normalized}" if negative?

      [normalized, fraction.length]
    end

    def negative?
      signs.any? { |sign| !sign[:positive] } || parenthesized
    end

    def validate_groups(whole)
      separators = "#{region.fetch(:group_separator)}#{region[:alternative_group_separator]}"
      groups = whole.split(/[#{Regexp.escape(separators)}]/, -1)
      return if groups.one?
      raise_invalid if groups.any?(&:empty?)
      raise_invalid if whole.scan(/[#{Regexp.escape(separators)}]/).uniq.length > 1

      case region.fetch(:grouping)
      when :western
        raise_invalid unless groups.first.length <= 3 && groups.drop(1).all? { |group| group.length == 3 }
      when :indian
        raise_invalid unless groups.first.length.between?(1, 3) &&
          groups.last.length == 3 &&
          groups[1...-1].all? { |group| group.length == 2 }
      else
        raise_invalid
      end
    end

    def resolve_currency
      detected = markers.flat_map { |marker| marker[:currencies] }.uniq
      matching = marker_currencies
      if explicit_currency
        if matching.any? && matching.none? { |candidate| candidate == explicit_currency }
          raise InvalidFormat, "currency markers conflict"
        end

        return explicit_currency
      end
      return matching.first if matching.one?
      raise InvalidFormat, "currency markers conflict" if markers.length > 1 && matching.empty?

      default_currency = region[:default_currency]
      if default_currency
        default_currency = wrap_currency(default_currency)
        return default_currency if markers.empty? || matching.include?(default_currency)
      end

      raise InvalidFormat, "currency marker is ambiguous" if matching.length > 1
      matching.first || Money.default_currency || raise(Money::Currency::NoCurrency, "must provide a currency")
    end

    def amount_to_fractional(amount, currency, fraction_length)
      fractional = amount * BigDecimal(currency.subunit_to_unit)
      return fractional if Money.default_infinite_precision
      raise InvalidFormat, "amount has more than #{currency.decimal_places} decimal places" if fraction_length > currency.decimal_places

      fractional.to_i
    end

    def raise_invalid
      raise InvalidFormat, "#{input.inspect} is not a valid localized amount"
    end
  end
end
