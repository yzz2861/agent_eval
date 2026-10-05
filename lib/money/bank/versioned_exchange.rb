# frozen_string_literal: true

require "money/bank/base"

class Money
  module Bank
    # Raised when registering a rate whose validity interval overlaps an
    # already registered rate for the same currency pair. Rejecting overlaps
    # guarantees that at most one rate version is effective for a pair at any
    # given moment, so multi-hop quotes can never stitch edges together from
    # conflicting historical versions.
    class OverlappingRate < Error
    end

    # A bank that stores caller-supplied exchange rates together with their
    # validity interval and source version, and produces reproducible quotes
    # for a specific point in time.
    #
    # Rates are registered with +#add_rate+ along with the interval during
    # which they were effective (+valid_from+ is inclusive, +valid_to+ is
    # exclusive, either may be nil for an open interval) and a +source+
    # identifying the version of the rate feed they came from.
    #
    # +#quote+ resolves every edge of the conversion path at the same moment
    # +at+. Multi-hop conversions only happen when an explicit +strategy+
    # (the ordered list of currencies to pass through) is given. Intermediate
    # amounts are kept as exact BigDecimal values; rounding to the target
    # currency happens once, in the final step.
    #
    # The returned +Quote+ snapshots the path and the actual rate values used,
    # so later updates to the bank never change an existing quote.
    #
    # @example
    #   bank = Money::Bank::VersionedExchange.new
    #   bank.add_rate("USD", "EUR", 0.9, valid_from: t0, valid_to: t1, source: "feed-v1")
    #   bank.add_rate("EUR", "JPY", 160.0, valid_from: t0, valid_to: t1, source: "feed-v1")
    #
    #   quote = bank.quote(Money.new(100_00, "USD"), "JPY",
    #                      at: t0 + 3600, strategy: ["USD", "EUR", "JPY"])
    #   quote.amount #=> #<Money fractional:14400 currency:JPY>
    #   quote.path   #=> ["USD", "EUR", "JPY"]
    class VersionedExchange < Base
      # A single registered rate with its validity interval and source.
      RateVersion = Struct.new(:from, :to, :rate, :valid_from, :valid_to, :source) do
        # Whether this version is the effective rate at the given moment.
        def covers?(time)
          (valid_from.nil? || valid_from <= time) &&
            (valid_to.nil? || time < valid_to)
        end

        # Whether the validity intervals of two versions overlap.
        def overlaps?(other)
          (valid_from.nil? || other.valid_to.nil? || valid_from < other.valid_to) &&
            (other.valid_from.nil? || valid_to.nil? || other.valid_from < valid_to)
        end
      end

      def initialize(&)
        @rate_versions = Hash.new { |hash, key| hash[key] = [] }
        @rate_versions_mutex = Mutex.new
        super(&)
      end

      # Registers a conversion rate together with its validity interval and
      # source version.
      #
      # @param [Currency, String, Symbol] from Currency to exchange from.
      # @param [Currency, String, Symbol] to Currency to exchange to.
      # @param [Numeric] rate Rate to use when exchanging currencies.
      # @param [#<=>, nil] valid_from Start of the validity interval (inclusive), nil for open.
      # @param [#<=>, nil] valid_to End of the validity interval (exclusive), nil for open.
      # @param [Object] source Version identifier of the rate feed this rate came from.
      #
      # @return [RateVersion] The registered rate version.
      #
      # @raise +Money::Bank::OverlappingRate+ if the validity interval overlaps
      #  an already registered rate for the same currency pair.
      def add_rate(from, to, rate, valid_from: nil, valid_to: nil, source: nil)
        if valid_from && valid_to && valid_from >= valid_to
          raise ArgumentError, "valid_from must be before valid_to"
        end

        version = RateVersion.new(
          Currency.wrap(from).iso_code,
          Currency.wrap(to).iso_code,
          BigDecimal(rate.to_s),
          valid_from,
          valid_to,
          source,
        )

        @rate_versions_mutex.synchronize do
          versions = @rate_versions[[version.from, version.to]]
          if (conflict = versions.find { |other| other.overlaps?(version) })
            raise OverlappingRate,
                  "Rate for '#{version.from}' -> '#{version.to}' overlaps " \
                  "already registered rate from source #{conflict.source.inspect}"
          end
          versions << version
        end

        version
      end

      # Returns the rate version effective at the given moment for the given
      # currency pair, or nil if no registered rate covers it.
      #
      # @param [Currency, String, Symbol] from Currency to exchange from.
      # @param [Currency, String, Symbol] to Currency to exchange to.
      # @param [#<=>] at The moment the rate must cover.
      #
      # @return [RateVersion, nil]
      def rate_at(from, to, at)
        pair = [Currency.wrap(from).iso_code, Currency.wrap(to).iso_code]
        @rate_versions_mutex.synchronize do
          @rate_versions[pair].find { |version| version.covers?(at) }
        end
      end

      # Builds a reproducible quote for exchanging the given +Money+ object to
      # +to_currency+ at the moment +at+.
      #
      # Without a +strategy+, only a direct rate is used. With a +strategy+,
      # the conversion hops through the given currencies in order; every edge
      # of the path must have a registered rate covering +at+.
      #
      # @param [Money] money The +Money+ object to exchange.
      # @param [Currency, String, Symbol] to_currency The currency to exchange to.
      # @param [#<=>] at The moment all edges of the path must cover.
      # @param [Array<Currency, String, Symbol>, nil] strategy Explicit
      #  conversion path, from the source currency to the target currency.
      #
      # @return [Quote]
      #
      # @raise +Money::Bank::UnknownRate+ if any edge of the path has no rate
      #  covering +at+.
      def quote(money, to_currency, at:, strategy: nil)
        to_currency = Currency.wrap(to_currency)
        path = quote_path(money.currency, to_currency, strategy)

        hops = path.each_cons(2).map do |from_code, to_code|
          version = rate_at(from_code, to_code, at)
          unless version
            raise UnknownRate,
                  "No conversion rate known for '#{from_code}' -> '#{to_code}' at #{at.inspect}"
          end
          Quote::Hop.new(
            from: version.from,
            to: version.to,
            rate: version.rate,
            source: version.source,
            valid_from: version.valid_from,
            valid_to: version.valid_to,
          )
        end

        Quote.new(
          from: money,
          to_currency: to_currency,
          at: at,
          hops: hops,
          rounding_method: rounding_method,
        )
      end

      # Exchanges the given +Money+ object to a new +Money+ object in
      # +to_currency+, using the rates effective at +at+ (defaults to now).
      #
      # @param [Money] from The +Money+ object to exchange.
      # @param [Currency, String, Symbol] to_currency The currency to exchange to.
      # @param [#<=>] at The moment all edges of the path must cover.
      # @param [Array<Currency, String, Symbol>, nil] strategy Explicit
      #  conversion path, from the source currency to the target currency.
      #
      # @yield [n] Optional block to use when rounding after exchanging one
      #  currency for another.
      # @yieldparam [BigDecimal] n The exact resulting fractional amount.
      # @yieldreturn [Integer]
      #
      # @return [Money]
      def exchange_with(from, to_currency, at: Time.now, strategy: nil, &block)
        to_currency = Currency.wrap(to_currency)
        return from if strategy.nil? && from.currency == to_currency

        quoted = quote(from, to_currency, at: at, strategy: strategy)
        if block
          from.dup_with(
            fractional: block.call(quoted.exact_fractional),
            currency: to_currency,
          )
        else
          quoted.amount
        end
      end

      private

      def quote_path(from_currency, to_currency, strategy)
        if strategy.nil?
          return [from_currency.iso_code] if from_currency == to_currency

          [from_currency.iso_code, to_currency.iso_code]
        else
          path = strategy.map { |currency| Currency.wrap(currency).iso_code }
          if path.length < 2 || path.first != from_currency.iso_code || path.last != to_currency.iso_code
            raise ArgumentError,
                  "strategy must list at least the source and target currencies in order"
          end

          path
        end
      end
    end
  end
end

require "money/bank/versioned_exchange/quote"
