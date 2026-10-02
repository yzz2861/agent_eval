# frozen_string_literal: true

# Deterministic clock for tests: time only moves when #advance is called.
class ManualClock
  def initialize(time = 1_000_000)
    @now = time
  end

  def call
    @now
  end

  def advance(seconds)
    @now += seconds
    self
  end

  def now
    @now
  end
end
