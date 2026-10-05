require 'set'

module Flipper
  module Exposure
    module Collectors
      # Public: In-memory exposure collector. Thread safe and idempotent:
      # events carrying the same idempotency key (or the same credential id)
      # are recorded only once.
      class Memory
        # Public: All recorded Flipper::Exposure::Event instances.
        attr_reader :events

        def initialize
          @events = []
          @seen_keys = Set.new
          @mutex = Mutex.new
        end

        # Public: Record an exposure event.
        #
        # Returns true if the event was recorded, false if it was a duplicate.
        def record(event)
          key = event.idempotency_key || event.credential_id

          @mutex.synchronize do
            return false if @seen_keys.include?(key)

            @seen_keys << key
            @events << event
          end

          true
        end

        # Public: Remove all recorded events and idempotency keys.
        def clear
          @mutex.synchronize do
            @events.clear
            @seen_keys.clear
          end
        end
      end
    end
  end
end
