# encoding: utf-8
# frozen_string_literal: true
require 'mail/elements/received_hop'

module Mail
  # An ordered list of ReceivedHop entries built from a message's Received
  # headers, used to read the relay chain when investigating delivery
  # delays.
  #
  # Hops are kept in the order the Received fields appear in the header
  # (most recent relay first); they are never re-sorted by timestamp, so a
  # relay with a skewed clock cannot scramble the chain. Delay estimates
  # between adjacent hops flag negative values (clock went backwards) and
  # hops with missing or unparsable timestamps instead of hiding them.
  #
  #  chain = Mail::ReceivedChain.new(received_header_values)
  #  chain.hops.each { |hop| puts "#{hop.by} at #{hop.date_time}" }
  #  chain.delays.each do |delay|
  #    if delay.missing_time?
  #      puts "cannot compare #{delay.previous_hop.by} -> #{delay.hop.by}: missing timestamp"
  #    elsif delay.negative?
  #      puts "negative delay #{delay.seconds}s: clock skew?"
  #    end
  #  end
  class ReceivedChain
    include Enumerable

    # The estimated time a message spent between two adjacent hops.
    # +hop+ is the later (more recently added) Received entry and
    # +previous_hop+ the one before it in the delivery path.
    class Delay
      attr_reader :hop, :previous_hop, :seconds

      def initialize(hop, previous_hop)
        @hop = hop
        @previous_hop = previous_hop
        @seconds = compute_seconds
      end

      # True when the later hop carries an earlier timestamp than the
      # previous hop, which usually means a relay's clock is wrong.
      def negative?
        !seconds.nil? && seconds < 0
      end

      # True when either hop is missing a usable timestamp, so no delay
      # could be estimated.
      def missing_time?
        seconds.nil?
      end

      def to_s
        if missing_time?
          "#{previous_hop.by} -> #{hop.by}: unknown (missing timestamp)"
        else
          "#{previous_hop.by} -> #{hop.by}: #{seconds}s#{' (negative, clock skew?)' if negative?}"
        end
      end

      private
        def compute_seconds
          return nil if hop.date_time.nil? || previous_hop.date_time.nil?
          ((hop.date_time - previous_hop.date_time) * 86_400).to_f
        end
    end

    attr_reader :hops

    def initialize(values = [])
      @hops = values.map { |value| coerce_hop(value) }
    end

    def each(&block)
      hops.each(&block)
    end

    # One Delay per adjacent pair of hops, in header order.
    def delays
      hops.each_cons(2).map { |newer, older| Delay.new(newer, older) }
    end

    private
      # A broken hop must not take down the rest of the chain, so each
      # value is parsed in isolation and failures degrade to an empty hop
      # that only keeps the raw text.
      def coerce_hop(value)
        case value
        when ReceivedHop
          value
        else
          ReceivedHop.new(value)
        end
      rescue => error
        hop = ReceivedHop.new(nil)
        hop.errors << error
        hop
      end
  end
end
