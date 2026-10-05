# frozen_string_literal: true

require "bigdecimal"
require "date"
require "monitor"
require "money/bank/base"

class Money
  module Bank
    # Bank that keeps the full history of exchange rates instead of only the
    # latest value. Every rate is registered with a validity interval and a
    # source version, so a conversion made for a given point in time can
    # always be traced back to the exact inputs that produced it.
    #
    # Conversions are requested through +#quote+, which returns an immutable
    # +Quote+ snapshot. The quote records the conversion path and the actual
    # rate values used, so later updates to the bank never change an
    # already-issued quote and the result can be recomputed at any time.
    #
    # Multi-hop conversions are possible by passing an explicit +via+ path.
    # Every edge of the path must be covered by a rate that is valid at the
    # requested time, and the legs may not be stitched together from
    # different source versions unless one explicit +source+ is requested
    # for the whole path.
    #
    # Intermediate amounts are kept as exact +BigDecimal+ values; rounding
    # happens exactly once, at the final step, according to the target
    # currency.
    #
    # @example
    #   bank = Money::Bank::HistoricalExchange.new
    #   bank.add_rate("USD", "EUR", 0.9, valid_from: Time.utc(2024, 1, 1), source: "ecb-2024")
    #   bank.add_rate("EUR", "JPY", 160, valid_from: Time.utc(2024, 1, 1), source: "ecb-2024")
    #
    #   quote = bank.quote(Money.new(100_00, "USD"), "JPY",
    #                      at: Time.utc(2024, 6, 1), via: ["EUR"])
    #   quote.to_money #=> #<Money fractional:1440000 currency:JPY>
    #   quote.rate     #=> 144.0
    class HistoricalExchange < Base
      # A single registered exchange rate, valid over a half-open interval
      # [valid_from, valid_to). A +nil+ +valid_to+ means the rate is
      # open-ended.
      class Rate
        attr_reader :from, :to, :rate, :valid_from, :valid_to, :source

        def initialize(from:, to:, rate:, valid_from:, valid_to:, source:)
          @from = from
          @to = to
          @rate = rate
          @valid_from = valid_from
          @valid_to = valid_to
          @source = source
          freeze
        end

        # Whether this rate covers the given point in time.
        #
        # @param [Time] time
        #
        # @return [Boolean]
        def covers?(time)
          valid_from <= time && (valid_to.nil? || time < valid_to)
        end

        def ==(other)
          other.is_a?(Rate) &&
            from == other.from &&
            to == other.to &&
            rate == other.rate &&
            valid_from == other.valid_from &&
            valid_to == other.valid_to &&
            source == other.source
        end
        alias eql? ==

        def hash
          [from, to, rate, valid_from, valid_to, source].hash
        end
      end

      # Immutable snapshot of a conversion quoted at a specific point in
      # time. Stores the conversion path and the actual rate values used,
      # so the result stays reproducible even after the bank is updated.
      class Quote
        # @return [Money] the original amount that was quoted.
        attr_reader :amount

        # @return [Money::Currency] the target currency.
        attr_reader :to_currency

        # @return [Time] the point in time the quote was generated for.
        attr_reader :at

        # @return [Array<Rate>] the conversion path, one rate per hop.
        attr_reader :legs

        # @return [BigDecimal] exact result in target fractional units,
        #   before rounding.
        attr_reader :exact_fractional

        # @return [Integer, BigDecimal] the rounded result in target
        #   fractional units.
        attr_reader :fractional

        def initialize(amount:, to_currency:, at:, legs:, exact_fractional:, fractional:, rounding: nil)
          @amount = amount
          @to_currency = to_currency
          @at = at
          @legs = legs.freeze
          @exact_fractional = exact_fractional
          @fractional = fractional
          @rounding = rounding
          freeze
        end

        # @return [Money::Currency] the currency of the quoted amount.
        def from_currency
          amount.currency
        end

        # The combined rate of the whole path (product of the leg rates).
        #
        # @return [BigDecimal]
        def rate
          legs.reduce(BigDecimal("1")) { |product, leg| product * leg.rate }
        end

        # The quoted amount converted to the target currency.
        #
        # @return [Money]
        def to_money
          Money.new(fractional, to_currency, bank: amount.bank)
        end

        # Recomputes the result from the stored amount, path and rates.
        # A quote is deterministic, so the recomputed quote always equals
        # the original one, regardless of later changes to the bank.
        #
        # @return [Quote]
        def recompute
          self.class.build(
            amount: amount,
            to_currency: to_currency,
            at: at,
            legs: legs,
            rounding: @rounding,
          )
        end

        def ==(other)
          other.is_a?(Quote) &&
            amount == other.amount &&
            to_currency == other.to_currency &&
            at == other.at &&
            legs == other.legs &&
            exact_fractional == other.exact_fractional &&
            fractional == other.fractional
        end
        alias eql? ==

        def hash
          [amount, to_currency, at, legs, exact_fractional, fractional].hash
        end

        # Builds a quote from an amount and a fully-resolved path of rates.
        # Intermediate values stay exact; only the final result is rounded
        # to the target currency's fractional unit.
        #
        # @api private
        def self.build(amount:, to_currency:, at:, legs:, rounding: nil, &block)
          units = BigDecimal(amount.fractional.to_s) /
                  BigDecimal(amount.currency.subunit_to_unit.to_s)
          legs.each { |leg| units *= leg.rate }
          exact = units * BigDecimal(to_currency.subunit_to_unit.to_s)

          rounding = block || rounding
          fractional =
            if rounding
              rounding.call(exact)
            else
              exact.round(0, Money.rounding_mode).to_i
            end

          new(
            amount: amount,
            to_currency: to_currency,
            at: at,
            legs: legs,
            exact_fractional: exact,
            fractional: fractional,
            rounding: rounding,
          )
        end
      end

      def initialize(&)
        @rates = []
        @guard = Monitor.new
        super(&)
      end

      # Registers a conversion rate together with its validity interval and
      # source version, and returns the created +Rate+.
      #
      # @param [Currency, String, Symbol] from Currency to exchange from.
      # @param [Currency, String, Symbol] to Currency to exchange to.
      # @param [Numeric] rate Rate to use when exchanging currencies.
      # @param [Time, Date, DateTime] valid_from Start of the validity
      #   interval (inclusive).
      # @param [Time, Date, DateTime, nil] valid_to End of the validity
      #   interval (exclusive). +nil+ means the rate is open-ended.
      # @param [String] source Version tag identifying where this rate
      #   comes from (e.g. a provider snapshot name).
      #
      # @return [Rate]
      #
      # @example
      #   bank.add_rate("USD", "EUR", 0.9,
      #                 valid_from: Time.utc(2024, 1, 1),
      #                 valid_to: Time.utc(2024, 7, 1),
      #                 source: "ecb-2024-h1")
      def add_rate(from, to, rate, valid_from:, source:, valid_to: nil)
        entry = Rate.new(
          from: Currency.wrap(from).iso_code,
          to: Currency.wrap(to).iso_code,
          rate: BigDecimal(rate.to_s),
          valid_from: coerce_time(valid_from),
          valid_to: valid_to && coerce_time(valid_to),
          source: source,
        )
        @guard.synchronize { @rates << entry }
        entry
      end

      # Returns a snapshot of all registered rates.
      #
      # @return [Array<Rate>]
      def rates
        @guard.synchronize { @rates.dup }
      end

      # Retrieves the single rate covering the given point in time.
      #
      # @param [Currency, String, Symbol] from Currency to exchange from.
      # @param [Currency, String, Symbol] to Currency to exchange to.
      # @param [Time, Date, DateTime] at Point in time the rate must cover.
      # @param [String, nil] source Restrict the lookup to one source version.
      #
      # @return [BigDecimal, nil] the rate, or +nil+ when no rate covers +at+.
      #
      # @raise +Money::Bank::AmbiguousRate+ if several rates cover +at+ and
      #   no explicit +source+ disambiguates them.
      def get_rate(from, to, at:, source: nil)
        find_rate(Currency.wrap(from).iso_code, Currency.wrap(to).iso_code,
                  coerce_time(at), source)&.rate
      end

      # Generates an immutable, recomputable quote for exchanging +money+
      # into +to_currency+ at the given point in time.
      #
      # @param [Money] money The amount to exchange.
      # @param [Currency, String, Symbol] to_currency The target currency.
      # @param [Time, Date, DateTime] at Point in time every rate used must
      #   cover.
      # @param [Array<Currency, String, Symbol>] via Explicit intermediate
      #   currencies for multi-hop conversions. Every hop must be covered by
      #   a rate valid at +at+.
      # @param [String, nil] source Explicit source version. When given,
      #   every leg of the path must come from this source.
      #
      # @yield [n] Optional block to use when rounding the final result.
      # @yieldparam [BigDecimal] n The exact result in target fractional units.
      # @yieldreturn [Integer]
      #
      # @return [Quote]
      #
      # @raise +Money::Bank::UnknownRate+ if a hop has no rate covering +at+.
      # @raise +Money::Bank::AmbiguousRate+ if a hop is covered by several
      #   source versions, or if the resolved path would mix different
      #   source versions without an explicit +source+.
      def quote(money, to_currency, at:, via: [], source: nil, &block)
        to_currency = Currency.wrap(to_currency)
        at = coerce_time(at)

        path = [money.currency, *via, to_currency].map { |c| Currency.wrap(c).iso_code }
        legs = path.each_cons(2).map do |from_iso, to_iso|
          rate = find_rate(from_iso, to_iso, at, source)
          unless rate
            raise UnknownRate,
                  "No conversion rate known for '#{from_iso}' -> '#{to_iso}' at #{at}"
          end
          rate
        end

        if source.nil? && legs.map(&:source).uniq.size > 1
          raise AmbiguousRate,
                "Conversion path #{path.join(' -> ')} would mix rates from different " +                "source versions at #{at}; pass an explicit source: to quote it"
        end

        Quote.build(
          amount: money,
          to_currency: to_currency,
          at: at,
          legs: legs,
          rounding: rounding_method,
          &block
        )
      end

      # Exchanges the given +Money+ object to a new +Money+ object in
      # +to_currency+, using the rates covering the given point in time.
      #
      # @param [Money] from The +Money+ object to exchange.
      # @param [Currency, String, Symbol] to_currency The currency to
      #   exchange to.
      # @param [Time, Date, DateTime] at Point in time the rates must cover.
      #   Defaults to the current time.
      # @param [Array<Currency, String, Symbol>] via Explicit intermediate
      #   currencies for multi-hop conversions.
      # @param [String, nil] source Explicit source version for the whole path.
      #
      # @yield [n] Optional block to use when rounding the final result.
      #
      # @return [Money]
      def exchange_with(from, to_currency, at: Time.now, via: [], source: nil, &block)
        to_currency = Currency.wrap(to_currency)
        if from.currency == to_currency
          from
        else
          quote(from, to_currency, at: at, via: via, source: source, &block).to_money
        end
      end

      private

      def find_rate(from_iso, to_iso, at, source)
        candidates = @guard.synchronize do
          @rates.select do |rate|
            rate.from == from_iso && rate.to == to_iso && rate.covers?(at) &&
              (source.nil? || rate.source == source)
          end
        end

        return nil if candidates.empty?
        return candidates.first if candidates.one?

        raise AmbiguousRate,
              "Several rates cover '#{from_iso}' -> '#{to_iso}' at #{at} " +              "(sources: #{candidates.map(&:source).uniq.join(', ')}); " +              "pass an explicit source: to pick one"
      end

      def coerce_time(value)
        case value
        when Time then value
        when DateTime then value.to_time
        when Date then Time.utc(value.year, value.month, value.day)
        else value
        end
      end
    end
  end
end
