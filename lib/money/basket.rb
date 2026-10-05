# frozen_string_literal: true

class Money
  # An immutable collection of monetary amounts in multiple currencies.
  #
  # A Basket keeps a net balance per currency, so amounts in different
  # currencies are never implicitly exchanged when they are combined.
  # Balances are normalized when the basket is built: currencies whose net
  # amount is zero are dropped, which means adding or removing a zero entry
  # never changes the identity of a basket, and the order in which amounts
  # were added is irrelevant.
  #
  # Conversion to a single currency is an explicit valuation operation,
  # see #value_in.
  #
  # @example
  #   basket = Money::Basket.new([Money.new(100, "USD"), Money.new(50, "EUR")])
  #   basket + Money.new(25, "USD") #=> #<Money::Basket ...> with USD 125, EUR 50
  class Basket
    include Comparable
    include Enumerable

    # Raised when #value_in is called without all the exchange rates needed
    # to value every currency held by the basket.
    class MissingRatesError < StandardError
      # @return [Array<Money::Currency>] the currencies for which no rate
      #   was provided.
      attr_reader :missing_currencies

      # @return [Money::Currency] the currency the basket was being valued in.
      attr_reader :target_currency

      def initialize(missing_currencies, target_currency)
        @missing_currencies = missing_currencies.sort_by(&:id).freeze
        @target_currency = target_currency

        list = @missing_currencies.map(&:to_s).join(", ")
        super("Missing exchange rates for #{list} to value the basket in #{target_currency}")
      end
    end

    class << self
      # Returns an empty basket.
      #
      # @return [Money::Basket]
      def empty
        new
      end
    end

    # Builds a basket from a list of Money objects. Amounts sharing the same
    # currency are netted together; no currency conversion is performed.
    #
    # @param [Enumerable<Money>] monies The amounts to seed the basket with.
    #
    # @raise [TypeError] when an element is not a Money object.
    def initialize(monies = [])
      balances = {}

      monies.each do |money|
        unless money.is_a?(Money)
          raise TypeError, "Unsupported argument type: #{money.class.name}"
        end

        currency = money.currency
        balances[currency] = balances.key?(currency) ? balances[currency] + money : money
      end

      @balances = balances.reject { |_currency, money| money.zero? }.freeze
    end

    # Returns the currencies held by the basket, sorted by currency id so the
    # result does not depend on insertion order.
    #
    # @return [Array<Money::Currency>]
    def currencies
      @balances.keys.sort_by(&:id)
    end

    # Returns one Money object per currency held by the basket, sorted by
    # currency id.
    #
    # @return [Array<Money>]
    def monies
      currencies.map { |currency| @balances[currency] }
    end

    # Iterates over the Money objects held by the basket.
    def each(&block)
      monies.each(&block)
    end

    # Returns the net amount held in the given currency, or a zero Money in
    # that currency when the basket holds none.
    #
    # @param [Money::Currency, String, Symbol] currency
    #
    # @return [Money]
    def [](currency)
      currency = Currency.wrap(currency)
      @balances.fetch(currency) { Money.new(0, currency) }
    end

    # Returns true when the basket holds no currency.
    #
    # @return [Boolean]
    def empty?
      @balances.empty?
    end

    # Returns true when the basket holds no non-zero amount. Equivalent to
    # #empty? since zero balances are dropped when the basket is built.
    #
    # @return [Boolean]
    def zero?
      @balances.empty?
    end

    # Returns a new basket combining the balances of this basket with another
    # basket or a single Money object. Amounts are netted per currency; no
    # currency conversion is performed.
    #
    # @param [Money::Basket, Money] other
    #
    # @return [Money::Basket]
    #
    # @raise [TypeError] when other is neither a Basket nor a Money.
    def merge(other)
      case other
      when Basket
        self.class.new(monies + other.monies)
      when Money
        self.class.new(monies + [other])
      else
        raise TypeError, "Unsupported argument type: #{other.class.name}"
      end
    end

    # Synonym for #merge.
    #
    # @see #merge
    def +(other)
      merge(other)
    end

    # Returns a new basket with the balances of other subtracted from this
    # basket, per currency.
    #
    # @param [Money::Basket, Money] other
    #
    # @return [Money::Basket]
    #
    # @raise [TypeError] when other is neither a Basket nor a Money.
    def -(other)
      case other
      when Basket, Money
        merge(-other)
      else
        raise TypeError, "Unsupported argument type: #{other.class.name}"
      end
    end

    # Returns a new basket with every balance negated.
    #
    # @return [Money::Basket]
    def -@
      self.class.new(monies.map(&:-@))
    end

    # Returns a new basket with every balance scaled by the given ratio.
    #
    # @param [Numeric] ratio The ratio to scale each balance by.
    #
    # @return [Money::Basket]
    #
    # @raise [TypeError] when ratio is not a Numeric.
    def *(ratio)
      unless ratio.is_a?(Numeric)
        raise TypeError, "Can't multiply a #{self.class.name} by a #{ratio.class.name}'s value"
      end

      self.class.new(monies.map { |money| money * ratio })
    end

    # Compares two baskets per currency. A basket is smaller than another
    # when every per-currency balance is smaller or equal, and greater when
    # every balance is greater or equal. Baskets whose balances are not
    # consistently ordered across currencies are not comparable.
    #
    # @param [Object] other
    #
    # @return [Integer, nil] -1, 0 or 1, or nil when the baskets are not
    #   comparable.
    def <=>(other)
      return unless other.is_a?(Basket)

      directions = (currencies | other.currencies).map do |currency|
        fractional_for(currency) <=> other.send(:fractional_for, currency)
      end.uniq

      if directions.all? { |direction| direction <= 0 }
        directions.all? { |direction| direction == 0 } ? 0 : -1
      elsif directions.all? { |direction| direction >= 0 }
        1
      end
    end

    # Checks whether two baskets hold the same net balance for every
    # currency. Zero balances are dropped when baskets are built, so adding
    # or removing a zero entry does not change equality, and the order in
    # which amounts were added is irrelevant.
    #
    # @param [Object] other
    #
    # @return [Boolean]
    def ==(other)
      other.is_a?(Basket) && balances == other.balances
    end

    # Checks whether two baskets hold the same net balance for every
    # currency, suitable for use as Hash keys together with #hash.
    #
    # @param [Object] other
    #
    # @return [Boolean]
    def eql?(other)
      other.is_a?(Basket) && balances.eql?(other.balances)
    end

    # Returns an Integer hash value based on the per-currency balances. The
    # value does not depend on the order in which amounts were added.
    #
    # @return [Integer]
    def hash
      balances.hash
    end

    # Returns the total value of the basket expressed in a single currency.
    # This is an explicit valuation operation: every currency held by the
    # basket (other than the target currency itself) requires a rate to be
    # provided.
    #
    # @param [Money::Currency, String, Symbol] currency The target currency.
    # @param [Hash] rates A hash mapping each held currency to its price in
    #   the target currency, i.e. how many units of the target currency one
    #   unit of the held currency is worth. Keys may be Currency objects,
    #   Strings or Symbols.
    #
    # @return [Money] The total value in the target currency.
    #
    # @raise [Money::Basket::MissingRatesError] listing every currency for
    #   which no rate was provided.
    #
    # @example
    #   basket.value_in("USD", "EUR" => 1.2, "JPY" => 0.009)
    def value_in(currency, rates)
      target = Currency.wrap(currency)
      rates = normalize_rates(rates)

      missing = currencies.reject { |held| held == target || rates.key?(held) }
      raise MissingRatesError.new(missing, target) unless missing.empty?

      total = monies.sum do |money|
        rate = money.currency == target ? 1 : rates.fetch(money.currency)
        money.amount * rate
      end

      Money.from_amount(total, target)
    end

    # Returns a human readable representation.
    #
    # @return [String]
    def inspect
      "#<#{self.class.name} #{monies.map(&:inspect).join(', ')}>"
    end

    protected

    # @return [Hash{Money::Currency => Money}] net balance per currency,
    #   without zero entries.
    attr_reader :balances

    private

    def fractional_for(currency)
      money = @balances[currency]
      money ? money.fractional : 0
    end

    def normalize_rates(rates)
      unless rates.respond_to?(:each_pair)
        raise TypeError, "rates must be a collection of currency/rate pairs"
      end

      normalized = {}
      rates.each_pair do |currency, rate|
        unless rate.is_a?(Numeric)
          raise TypeError, "Rate for #{currency} is not a Numeric: #{rate.inspect}"
        end

        normalized[Currency.wrap(currency)] = rate
      end
      normalized
    end
  end
end
