# frozen_string_literal: true

require 'rack/attack/atomic_store'

module Rack
  class Attack
    # In-memory cache store implementing the Rack::Attack::AtomicStore
    # contract (plus the classic read/write/increment/delete store interface,
    # so it can be used as a drop-in Rack::Attack.cache.store).
    #
    # Atomicity is guaranteed per process through a mutex, which makes this
    # store suitable for single-process deployments, tests and as a reference
    # for other Rack::Attack::AtomicStore implementations.
    class MemoryStore
      include Rack::Attack::AtomicStore

      def initialize
        @data = {}
        @mutex = Mutex.new
      end

      def read(key)
        @mutex.synchronize do
          entry = @data[key]
          entry && !expired?(entry) ? entry.first : nil
        end
      end

      def write(key, value, options = {})
        @mutex.synchronize do
          @data[key] = [value, expires_at(options[:expires_in])]
        end
        value
      end

      def increment(key, amount = 1, options = {})
        atomic_update(key, expires_in: options[:expires_in]) do |current|
          (current || 0) + amount
        end
      end

      def delete(key, _options = {})
        @mutex.synchronize { @data.delete(key) }
        nil
      end

      def delete_matched(matcher, _options = nil)
        @mutex.synchronize { @data.delete_if { |key, _entry| key =~ matcher } }
        nil
      end

      def atomic_update(key, expires_in: nil)
        @mutex.synchronize do
          entry = @data[key]
          current = entry && !expired?(entry) ? entry.first : nil
          new_value = yield(current)

          if new_value.nil?
            @data.delete(key)
          else
            @data[key] = [new_value, expires_at(expires_in)]
          end

          new_value
        end
      end

      private

      def expired?(entry)
        expires_at = entry[1]
        !expires_at.nil? && expires_at <= monotonic_now
      end

      def expires_at(expires_in)
        expires_in ? monotonic_now + expires_in : nil
      end

      def monotonic_now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end
  end
end
