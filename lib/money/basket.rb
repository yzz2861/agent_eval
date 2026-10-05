# frozen_string_literal: true

class Money
  # An immutable collection of monetary amounts in multiple currencies.
  #
  # A Basket keeps one net balance per currency and never implicitly
  # converts between currencies. Merging two baskets sums the balances of
  # each currency independently, and scaling multiplies every balance by
  # the same factor.
  #
  # Converting the whole basket into a single currency is a separate
  # valuation operation that requires an explicit set of quotes.
  #
  # Basket is a value object and is immutable.
  class Basket
    include Comparable

    # Raised when a valuation is requested but one or more currencies have
    # no quote. Reports every missing currency, not just the first one.
    class MissingQuotesError < StandardError
      # @return [Array<Money::Currency>] currencies without a quote
      attr_reader :missing_currencies

      def initialize(missing_currencies)
        @missing_currencies = missing_currencies.freeze
        ids = missing_currencies.map { |currency| currency.id.to_s.upcase }
        super("Missing quotes for: #{ids.join(', ')}")
      end
    end

    class << self
      # An empty basket holding no balances.
      #
      # @return [Money::Basket]
      def empty
        new
      end
    end

    # Builds a basket from a list of Money objects. Amounts sharing the
    # same currency are netted into a single balance. Balances that net
    # to zero are dropped and do not affect the basket's identity.
    #
    # @param [Enumerable<Money>] monies
    #
    # @return [Money::Basket]
    #
    # @example
    #   Money::Basket.new([Money.new(100, "USD"), Money.new(50, "EUR")])
    def initialize(monies = [])
      balances = {}
      monies.each do |money|
        unless money.is_a?(Money)
          raise TypeError, "Unsupported argument type: #{money.class.name}"
        end

        currency = money.currency
        balances[currency] = balances.key?(currency) ? balances[currency] + money : money
      end
      @balances = normalize(balances).freeze
      freeze
    end

    # Net balance per currency. Zero balances are never stored.
    #
    # @return [Hash{Money::Currency => Money}]
    def to_h
      @balances.dup
    end

    # Balances sorted by currency id, for deterministic enumeration.
    #
    # @return [Array<Money>]
    def monies
      @balances.values.sort_by { |money| money.currency.id.to_s }
    end

    # Currencies with a non-zero balance, sorted by currency id.
    #
    # @return [Array<Money::Currency>]
    def currencies
      @balances.keys.sort_by { |currency| currency.id.to_s }
    end

    # @return [Boolean]
    def empty?
      @balances.empty?
    end

    # A basket is zero when it holds no non-zero balance.
    #
    # @return [Boolean]
    def zero?
      @balances.empty?
    end

    # Merges this basket with another basket (or a single Money object),
    # netting balances per currency. No currency conversion takes place.
    #
    # @param [Money::Basket, Money] other
    #
    # @return [Money::Basket]
    def +(other)
      case other
      when Basket
        self.class.new(@balances.values + other.to_h.values)
      when Money
        self.class.new(@balances.values + [other])
      else
        raise TypeError, "Unsupported argument type: #{other.class.name}"
      end
    end
    alias merge +

    # Subtracts another basket (or a single Money object) from this
    # basket, netting balances per currency.
    #
    # @param [Money::Basket, Money] other
    #
    # @return [Money::Basket]
    def -(other)
      case other
      when Basket, Money
        self + (-other)
      else
        raise TypeError, "Unsupported argument type: #{other.class.name}"
      end
    end

    # Returns a basket with every balance negated.
    #
    # @return [Money::Basket]
    def -@
      self.class.new(@balances.values.map(&:-@))
    end

    # Scales every balance by the same factor.
    #
    # @param [Numeric] factor
    #
    # @return [Money::Basket]
    #
    # @raise [TypeError] If +factor+ is NOT a number.
    def *(factor)
      unless factor.is_a?(Numeric)
        raise TypeError, "Can't multiply a #{self.class.name} by a #{factor.class.name}'s value"
      end

      self.class.new(@balances.values.map { |money| money * factor })
    end

    # Two baskets are equal when they hold the same net balance for every
    # currency. The order in which currencies were added is irrelevant,
    # and zero balances never take part in the comparison.
    #
    # @param [Object] other
    #
    # @return [Boolean]
    def ==(other)
      other.is_a?(Basket) && @balances == other.to_h
    end
    alias eql? ==

    # @return [Integer]
    def hash
      @balances.hash
    end

    # Compares two baskets per currency, without any implicit conversion.
    # Baskets are only comparable when they hold balances in the same set
    # of currencies, and only when every per-currency comparison agrees
    # in direction; otherwise the baskets are incomparable.
    #
    # @param [Money::Basket] other
    #
    # @return [Integer, nil] 0 when equal, -1 or 1 when every balance is
    #   respectively smaller or greater, nil when incomparable.
    def <=>(other)
      return unless other.is_a?(Basket)

      other_balances = other.to_h
      same_currencies =
        @balances.size == other_balances.size &&
        @balances.each_key.all? { |currency| other_balances.key?(currency) }
      return unless same_currencies

      comparisons = @balances.map do |currency, money|
        money.fractional <=> other_balances[currency].fractional
      end

      return 0 if comparisons.all? { |comparison| comparison == 0 }
      return -1 if comparisons.all? { |comparison| comparison <= 0 }
      return 1 if comparisons.all? { |comparison| comparison >= 0 }

      nil
    end

    # Values the whole basket in a single currency using caller-provided
    # quotes. This is a valuation operation: it does not change the
    # basket, and it never consults a bank or an implicit rate.
    #
    # @param [Currency, String, Symbol] currency The target currency.
    # @param [Hash] quotes Maps each held currency to its price in the
    #   target currency (1 unit of the quoted currency = quote units of
    #   the target currency). Balances already in the target currency
    #   need no quote.
    #
    # @raise [Money::Basket::MissingQuotesError] listing every currency
    #   without a quote.
    #
    # @return [Money]
    #
    # @example
    #   basket.value_in("EUR", "USD" => BigDecimal("1.1"), "JPY" => BigDecimal("0.006"))
    def value_in(currency, quotes)
      target = Currency.wrap(currency)
      raise Currency::NoCurrency, "must provide a currency" if target.nil?

      rates = normalize_quotes(quotes)

      missing = []
      total = BigDecimal("0")
      @balances.each_value do |money|
        if money.currency == target
          total += money.amount
        elsif rates.key?(money.currency)
          total += money.amount * rates[money.currency]
        else
          missing << money.currency
        end
      end

      unless missing.empty?
        raise MissingQuotesError, missing.sort_by { |currency| currency.id.to_s }
      end

      Money.from_amount(total, target)
    end

    # @return [String]
    def inspect
      balances = monies.map { |money| "#{money.currency.id.to_s.upcase}:#{money.fractional}" }
      "#<#{self.class.name} #{balances.join(' ')}>"
    end

    private

    def normalize(balances)
      balances.reject { |_currency, money| money.zero? }
    end

    def normalize_quotes(quotes)
      raise ArgumentError, "quotes must be a Hash" unless quotes.is_a?(Hash)

      quotes.each_with_object({}) do |(quoted_currency, rate), rates|
        raise ArgumentError, "quote rates must be numeric" unless rate.is_a?(Numeric)

        rates[Currency.wrap(quoted_currency)] =
          rate.is_a?(Rational) ? rate.to_d(Money.conversion_precision) : rate.to_d
      end
    end
  end
end
