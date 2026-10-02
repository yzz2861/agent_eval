# frozen_string_literal: true

require 'thread'

module Rack
  class Attack
    module Store
      # Thread-safe, single process in-memory store.
      #
      # Besides the regular read/write/increment/delete interface used by
      # classic throttles, it implements the minimal atomic operation required
      # by Rack::Attack::SmoothThrottle:
      #
      #   update(key, expires_in:) { |current_value| [new_value, result] }
      #
      # The read-compute-write sequence runs while holding a mutex, so the
      # block is guaranteed to observe and replace the value atomically.
      # Returning +nil+ as the new value deletes the key. Values are passed to
      # the block exactly as they were stored (typically serialized strings).
      #
      # Key expiration is tracked with a monotonic clock, so housekeeping is
      # not affected by wall clock adjustments.
      class Memory
        Entry = Struct.new(:value, :expires_at)

        # +clock+ defaults to a monotonic process clock and may be overridden
        # (e.g. in tests) with a zero-argument callable returning seconds.
        def initialize(clock: nil)
          @mutex = Mutex.new
          @entries = {}
          @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
        end

        def read(key)
          @mutex.synchronize do
            entry = @entries[key]
            return nil unless entry

            if expired?(entry)
              @entries.delete(key)
              nil
            else
              entry.value
            end
          end
        end

        def write(key, value, options = {})
          @mutex.synchronize do
            @entries[key] = Entry.new(value, expires_at(options[:expires_in]))
            value
          end
        end

        def increment(key, amount = 1, options = {})
          @mutex.synchronize do
            entry = @entries[key]
            if entry && expired?(entry)
              @entries.delete(key)
              entry = nil
            end

            value = entry ? Integer(entry.value) + Integer(amount) : Integer(amount)
            expires_at = entry ? entry.expires_at : expires_at(options[:expires_in])
            @entries[key] = Entry.new(value, expires_at)
            value
          end
        end

        def delete(key, _options = nil)
          @mutex.synchronize { @entries.delete(key) }
        end

        def delete_matched(matcher, _options = nil)
          pattern = matcher.is_a?(Regexp) ? matcher : /\A#{Regexp.escape(matcher.to_s)}/

          @mutex.synchronize do
            @entries.delete_if { |key, _entry| pattern.match?(key) }
          end
        end

        # Atomically read +key+, yield its current value (nil when absent) and
        # store the first element of the returned pair. The second element is
        # returned to the caller. A nil new value removes the key. The block
        # never runs concurrently with another operation on the same store.
        def update(key, options = {})
          raise ArgumentError, 'block required' unless block_given?

          @mutex.synchronize do
            entry = @entries[key]
            if entry && expired?(entry)
              @entries.delete(key)
              entry = nil
            end

            new_value, result = yield(entry&.value)

            if new_value.nil?
              @entries.delete(key)
            else
              @entries[key] = Entry.new(new_value, expires_at(options[:expires_in]))
            end

            result
          end
        end

        private

        def expires_at(expires_in)
          monotonic_now + Float(expires_in) if expires_in
        end

        def expired?(entry)
          entry.expires_at && entry.expires_at <= monotonic_now
        end

        def monotonic_now
          @clock.call
        end
      end
    end
  end
end
