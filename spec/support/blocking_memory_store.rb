# frozen_string_literal: true

require "active_support/cache"

class BlockingMemoryStore < ActiveSupport::Cache::MemoryStore
  attr_reader :window_started, :window_continue
  attr_accessor :key_pattern

  def initialize
    super()
    @window_started = Queue.new
    @window_continue = Queue.new
  end

  def increment(key, amount = 1, **options)
    if key_pattern && key.include?(key_pattern)
      window_started << true
      window_continue.pop
    end

    super
  end
end
