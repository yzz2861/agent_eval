# frozen_string_literal: true

module StateMachines
  class DeferredEventQueue
    Entry = Struct.new(:event_name, :args, :bang, :callback, keyword_init: true)

    attr_reader :items, :capacity
    attr_accessor :performing_event, :active_event, :draining, :last_add_failed

    def initialize(capacity)
      unless capacity.is_a?(Integer) && capacity.positive?
        raise ArgumentError, 'deferred event queue capacity must be greater than 0'
      end

      @capacity = capacity
      @items = []
      @performing_event = nil
      @active_event = nil
      @draining = false
      @last_add_failed = false
    end

    def initialize_copy(orig)
      super
      @items = orig.items.map do |item|
        item.dup.tap do |copied_item|
          copied_item.args = item.args.map { |arg| arg.is_a?(Hash) ? arg.dup : arg }
        end
      end
      @performing_event = nil
      @active_event = nil
      @draining = false
      @last_add_failed = false
    end

    def add(event_name, args, bang, callback: false)
      if full?
        @last_add_failed = true
        return false
      end

      @last_add_failed = false
      @items << Entry.new(event_name: event_name, args: args.dup, bang: bang, callback: callback)
      true
    end

    def any?
      @items.any?
    end

    def full?
      length >= capacity
    end

    def length
      @items.length
    end

    def shift
      @items.shift
    end

    def unshift(item)
      @items.unshift(item)
    end
  end
end
