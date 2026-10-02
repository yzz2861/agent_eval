# frozen_string_literal: true

module Rack
  class Attack
    # Minimal contract a cache store must implement to be usable with
    # Rack::Attack::WeightedThrottle.
    #
    # Implementations must provide:
    #
    #   atomic_update(key, expires_in: nil) { |current_value| new_value } -> new_value
    #
    # The block receives the current (unexpired) value stored at +key+, or nil
    # when the key is missing or expired, and returns the value to store.
    # Reading the current value, invoking the block and writing the result must
    # happen atomically with respect to any other +atomic_update+ call for the
    # same key. Returning nil from the block removes the key. +expires_in+ is a
    # TTL in seconds applied to the stored value.
    #
    # Stores that only expose #read/#write cannot emulate this contract: a
    # read-modify-write sequence built on top of them races under concurrency
    # and would silently lose updates. Such stores are rejected with
    # Rack::Attack::IncompatibleStoreError instead of pretending to be atomic.
    #
    # See Rack::Attack::MemoryStore for a reference implementation.
    module AtomicStore
      def atomic_update(_key, expires_in: nil)
        raise NotImplementedError, "#{self.class.name} must implement #atomic_update to be used as an atomic store"
      end
    end
  end
end
