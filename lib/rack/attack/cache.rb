# frozen_string_literal: true

require 'securerandom'

module Rack
  class Attack
    class Cache
      attr_accessor :prefix
      attr_reader :last_epoch_time

      def self.default_store
        if Object.const_defined?(:Rails) && Rails.respond_to?(:cache)
          ::Rails.cache
        end
      end

      def initialize(store: self.class.default_store)
        self.store = store
        @prefix = 'rack::attack'
        @settle_mutex = Mutex.new
      end

      attr_reader :store

      def store=(store)
        @store =
          if (proxy = BaseProxy.lookup(store))
            proxy.new(store)
          else
            store
          end
        if @store
          check_store_methods_presence(:read, :write, :delete, :increment)
        end
      end

      def count(unprefixed_key, period)
        key, expires_in = key_and_expiry(unprefixed_key, period)
        do_count(key, expires_in)
      end

      # Reserve one unit of quota in the current window and return a
      # Reservation credential for it. The reservation record remembers
      # the exact window key that was incremented, so a late settlement
      # can never touch a different (e.g. newer) window.
      def reserve(unprefixed_key, period)
        unless store.respond_to?(:decrement)
          raise(
            Rack::Attack::IncompatibleStoreError,
            "Configured store #{store.class.name} doesn't respond to #decrement, " \
            "which is required for reserve-and-settle throttles"
          )
        end

        key, expires_in = key_and_expiry(unprefixed_key, period)
        count = do_count(key, expires_in)
        token = SecureRandom.hex(16)
        write("reservation:#{token}", key, expires_in)

        Reservation.new(cache: self, token: token, count: count)
      end

      # Settle the reservation identified by +token+. Only the first call
      # for a given token takes effect: claiming the reservation record is
      # atomic, so repeated or concurrent settlements are no-ops. When
      # +refund+ is true, the reserved unit is returned to the window it
      # was originally taken from -- never to whatever window is current
      # now. Returns true when this call took effect.
      def settle(token, refund:)
        raise Rack::Attack::MissingStoreError if store.nil?

        reservation_key = "#{prefix}:reservation:#{token}"
        window_key = store.read(reservation_key)
        return false unless window_key

        # Atomic claim: only the caller whose delete removes the record
        # gets to act on it.
        return false unless store.delete(reservation_key)

        decrement(window_key) if refund
        true
      end

      def read(unprefixed_key)
        raise Rack::Attack::MissingStoreError if store.nil?

        store.read("#{prefix}:#{unprefixed_key}")
      end

      def write(unprefixed_key, value, expires_in)
        raise Rack::Attack::MissingStoreError if store.nil?

        store.write("#{prefix}:#{unprefixed_key}", value, expires_in: expires_in)
      end

      def reset_count(unprefixed_key, period)
        key, _ = key_and_expiry(unprefixed_key, period)
        store.delete(key)
      end

      def delete(unprefixed_key)
        store.delete("#{prefix}:#{unprefixed_key}")
      end

      def reset!
        if store.respond_to?(:delete_matched)
          store.delete_matched(/#{prefix}*/)
        else
          raise(
            Rack::Attack::IncompatibleStoreError,
            "Configured store #{store.class.name} doesn't respond to #delete_matched method"
          )
        end
      end

      private

      def key_and_expiry(unprefixed_key, period)
        @last_epoch_time = Time.now.to_i
        # Add 1 to expires_in to avoid timing error: https://github.com/rack/rack-attack/pull/85
        expires_in = (period - (@last_epoch_time % period) + 1).to_i
        ["#{prefix}:#{(@last_epoch_time / period).to_i}:#{unprefixed_key}", expires_in]
      end

      def do_count(key, expires_in)
        raise Rack::Attack::MissingStoreError if store.nil?

        result = store.increment(key, 1, expires_in: expires_in)

        # NB: Some stores return nil when incrementing uninitialized values
        if result.nil?
          store.write(key, 1, expires_in: expires_in)
        end
        result || 1
      end

      # Decrement a fully-prefixed window key, guarded so the counter can
      # never go negative and a missing (e.g. expired) key is never
      # recreated. The mutex makes the check-and-decrement atomic for
      # in-process stores such as ActiveSupport::Cache::MemoryStore.
      def decrement(key)
        @settle_mutex.synchronize do
          current = store.read(key)
          return unless current && current.to_i > 0

          result = store.decrement(key, 1)

          # Some stores (e.g. ActiveSupport::Cache::MemoryStore) create the
          # key when it vanished between the check and the decrement; undo
          # that so an expired window never leaves a negative counter.
          store.delete(key) if result && result.to_i < 0
        end
      end

      def check_store_methods_presence(*method_names)
        missing = method_names.reject { |m| store.respond_to?(m) }
        unless missing.empty?
          missing = missing.map { |m| "##{m}" }.join(", ")
          warn "[rack-attack] Configured store #{store.class.name} doesn't respond to #{missing}"
        end
      end
    end
  end
end
