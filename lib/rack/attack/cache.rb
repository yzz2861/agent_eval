# frozen_string_literal: true

module Rack
  class Attack
    class Cache
      attr_accessor :prefix

      def self.default_store
        if Object.const_defined?(:Rails) && Rails.respond_to?(:cache)
          ::Rails.cache
        end
      end

      def initialize(store: self.class.default_store)
        self.store = store
        @prefix = 'rack::attack'
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

      # Increments the counter for the current time window and returns both
      # the count and the epoch time of the window that produced it. The
      # epoch is returned instead of being kept in shared state so that
      # concurrent requests can never observe each other's window.
      def count(unprefixed_key, period)
        key, expires_in, epoch_time = key_and_expiry(unprefixed_key, period)
        count = do_count(key, expires_in)
        [count, epoch_time]
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
        key, _expires_in, _epoch_time = key_and_expiry(unprefixed_key, period)
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
        epoch_time = Time.now.to_i
        # Add 1 to expires_in to avoid timing error: https://github.com/rack/rack-attack/pull/85
        expires_in = (period - (epoch_time % period) + 1).to_i
        ["#{prefix}:#{(epoch_time / period).to_i}:#{unprefixed_key}", expires_in, epoch_time]
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
