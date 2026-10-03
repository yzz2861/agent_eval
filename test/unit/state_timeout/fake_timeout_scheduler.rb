# frozen_string_literal: true

# A test scheduler that records armed timeouts and lets tests fire their
# callbacks manually -- early, on time, or late.  It never runs anything in
# the background.
class FakeTimeoutScheduler
  Entry = Struct.new(:delay, :fire_at, :callback, :cancelled)

  attr_accessor :now
  attr_reader :entries

  def initialize
    @now = 0
    @entries = []
  end

  def schedule(delay, &callback)
    entry = Entry.new(delay, @now + delay, callback, false)
    @entries << entry
    entry
  end

  def cancel(entry)
    entry.cancelled = true
  end

  # Advances the clock, firing any armed entries that come due
  def advance(to)
    @now = to
    @entries.each { |entry| entry.callback.call if !entry.cancelled && entry.fire_at <= to }
  end

  # Directly fires the entry's callback, even if it is early or was already
  # cancelled (simulating a callback that was already in flight)
  def trigger(entry)
    entry.callback.call
  end
end
