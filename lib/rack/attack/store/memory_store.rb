# frozen_string_literal: true

require 'monitor'

module Rack
  class Attack
    class MemoryStore
      include MonitorMixin

      def initialize
        super
        @counters = {}
        @reservations = {}
      end

      def read(key)
        synchronize do
          prune
          read_counter(key)
        end
      end

      def write(key, value, options = {})
        synchronize do
          prune
          write_counter(key, value, options)
          value
        end
      end

      def delete(key)
        synchronize do
          prune
          @counters.delete(key)
          true
        end
      end

      def increment(key, amount = 1, options = {})
        synchronize do
          prune
          value = read_counter(key).to_i + amount
          write_counter(key, value, options)
          value
        end
      end

      def reserve(key, amount, limit, expires_in, token, epoch_time)
        synchronize do
          prune
          current = read_counter(key).to_i
          return [false, current, epoch_time] if current + amount > limit

          value = current + amount
          write_counter(key, value, expires_in: expires_in)
          @reservations[token] = {
            counter_key: key,
            amount: amount,
            expires_at: Process.clock_gettime(Process::CLOCK_MONOTONIC) + expires_in
          }
          [true, value, epoch_time]
        end
      end

      def settle(token, keep)
        synchronize do
          prune
          reservation = @reservations.delete(token)
          return false unless reservation

          unless keep
            counter = @counters[reservation[:counter_key]]
            if counter
              if counter[:value] > reservation[:amount]
                counter[:value] -= reservation[:amount]
              else
                @counters.delete(reservation[:counter_key])
              end
            end
          end

          true
        end
      end

      def delete_matched(pattern)
        synchronize do
          @counters.delete_if { |key, _| key.match?(pattern) }
          @reservations.delete_if { |_, reservation| reservation[:counter_key].match?(pattern) }
          true
        end
      end

      def clear
        synchronize do
          @counters.clear
          @reservations.clear
        end
      end

      private

      def expires_at_from(options)
        expires_in = options[:expires_in]
        return unless expires_in

        Process.clock_gettime(Process::CLOCK_MONOTONIC) + expires_in
      end

      def read_counter(key)
        counter = @counters[key]
        counter && counter[:value]
      end

      def write_counter(key, value, options = {})
        expires_at = expires_at_from(options)
        if expires_at
          @counters[key] = { value: value, expires_at: expires_at }
        else
          @counters[key] = { value: value }
        end
      end

      def prune
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        @counters.delete_if { |_, counter| counter[:expires_at] && counter[:expires_at] <= now }
        @reservations.delete_if { |_, reservation| reservation[:expires_at] <= now }
      end
    end
  end
end
