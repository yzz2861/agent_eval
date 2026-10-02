# frozen_string_literal: true

module Rack
  class Attack
    # Thread-safe in-memory store used to demonstrate escalating bans.
    #
    # It accepts an injectable clock so the expiry behavior is fully
    # deterministic, and it implements #merge which applies a block to the
    # current value of a key atomically (inside a mutex).
    class BanMemoryStore
      Entry = Struct.new(:value, :expires_at)

      attr_accessor :clock

      def initialize(clock: -> { Time.now.to_i })
        @clock = clock
        @mutex = Mutex.new
        @entries = {}
      end

      def read(key)
        @mutex.synchronize do
          entry = @entries[key]
          return nil unless entry
          return nil if expired?(entry)

          entry.value
        end
      end

      def write(key, value, expires_in: nil)
        @mutex.synchronize do
          @entries[key] = Entry.new(value, expires_at(expires_in))
          value
        end
      end

      def delete(key)
        @mutex.synchronize do
          existed = @entries.delete(key)
          !existed.nil?
        end
      end

      def increment(key, amount = 1, expires_in: nil)
        @mutex.synchronize do
          entry = @entries[key]
          entry = nil if entry && expired?(entry)

          value = entry ? entry.value.to_i + amount : amount
          @entries[key] = Entry.new(value, entry ? entry.expires_at : expires_at(expires_in))
          value
        end
      end

      # Atomically read the current value of +key+, yield it along with the
      # current clock time, and persist whatever the block returns.
      #
      # The block is invoked while holding the store lock, so concurrent
      # violations for the same discriminator are merged one at a time.
      def merge(key, expires_in: nil)
        raise ArgumentError, 'Must pass a block to #merge' unless block_given?

        @mutex.synchronize do
          entry = @entries[key]
          entry = nil if entry && expired?(entry)

          value = yield(entry&.value, now)
          @entries[key] = Entry.new(value, expires_at(expires_in))
          value
        end
      end

      def clear
        @mutex.synchronize { @entries.clear }
      end

      private

      def now
        @clock.call.to_i
      end

      def expires_at(expires_in)
        return nil if expires_in.nil?

        now + expires_in.to_i
      end

      def expired?(entry)
        entry.expires_at && entry.expires_at <= now
      end
    end
  end
end
