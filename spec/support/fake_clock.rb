# frozen_string_literal: true

# Manually advanced clock for specs that need deterministic control over time.
class FakeClock
  def initialize(now = 0.0)
    @now = now
  end

  def call
    @now
  end

  def advance(seconds)
    @now += seconds
  end

  def rewind(seconds)
    @now -= seconds
  end
end
