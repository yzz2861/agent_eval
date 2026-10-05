# frozen_string_literal: true

class Money
  module Bank
    class VersionedExchange < Base
      # An immutable snapshot of a conversion quoted by
      # +Money::Bank::VersionedExchange#quote+.
      #
      # A quote records the conversion path and the actual rate values that
      # were effective at the quoted moment, together with the source version
      # of each rate. Because every value needed for the conversion is
      # snapshotted here, later updates to the bank never change an existing
      # quote, and +#recalculate+ always replays the exact same computation.
      #
      # Intermediate hop amounts are kept as exact BigDecimal values; the
      # result is rounded to the target currency only in the final step.
      class Quote
        # A single conversion leg of a quote, with the rate value and the
        # source version that were effective at the quoted moment.
        Hop = Struct.new(:from, :to, :rate, :source, :valid_from, :valid_to, keyword_init: true)

        # @return [Money] The original +Money+ object the quote was made for.
        attr_reader :from

        # @return [Money::Currency] The target currency of the quote.
        attr_reader :to_currency

        # @return [Object] The moment the quote was made for.
        attr_reader :at

        # @return [Array<Hop>] The conversion legs, in order.
        attr_reader :hops

        def initialize(from:, to_currency:, at:, hops:, rounding_method: nil)
          @from = from
          @to_currency = Currency.wrap(to_currency)
          @at = at
          @hops = hops.freeze
          @rounding_method = rounding_method
        end

        # The ordered list of currency iso codes the conversion passes
        # through, including the source and target currencies.
        #
        # @return [Array<String>]
        def path
          [from.currency.iso_code, *hops.map(&:to)]
        end

        # The combined exact rate of the whole path (the product of the
        # rates of all hops).
        #
        # @return [BigDecimal]
        def rate
          hops.reduce(BigDecimal("1")) { |combined, hop| combined * hop.rate }
        end

        # The exact, unrounded fractional amount in the target currency
        # after applying every hop. Intermediate values are never rounded.
        #
        # @return [BigDecimal]
        def exact_fractional
          hops.reduce(BigDecimal(from.fractional.to_s)) do |value, hop|
            hop_from = Currency.wrap(hop.from)
            hop_to = Currency.wrap(hop.to)
            value * hop.rate *
              BigDecimal(hop_to.subunit_to_unit.to_s) /
              BigDecimal(hop_from.subunit_to_unit.to_s)
          end
        end

        # The resulting +Money+ object in the target currency. Rounding to
        # the target currency happens here, in the final step only.
        #
        # @return [Money]
        def amount
          fractional = exact_fractional
          fractional = @rounding_method.call(fractional) if @rounding_method
          from.dup_with(fractional: fractional, currency: to_currency)
        end

        # Replays the conversion from the snapshotted path and rate values.
        # Always equals +#amount+, regardless of later bank updates.
        #
        # @return [Money]
        def recalculate
          amount
        end

        # A serializable snapshot of the quote, keeping rate values as
        # strings so no precision is lost.
        #
        # @return [Hash]
        def to_h
          {
            from_currency: from.currency.iso_code,
            to_currency: to_currency.iso_code,
            from_fractional: from.fractional.to_s,
            at: at,
            path: path,
            hops: hops.map do |hop|
              {
                from: hop.from,
                to: hop.to,
                rate: hop.rate.to_s("F"),
                source: hop.source,
                valid_from: hop.valid_from,
                valid_to: hop.valid_to,
              }
            end,
            rate: rate.to_s("F"),
            fractional: amount.fractional.to_s,
          }
        end
      end
    end
  end
end

