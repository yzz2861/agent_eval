# frozen_string_literal: true

require 'thread'

# A minimal Rack::Attack cache backend whose failures follow a script.
#
# Each scripted entry is matched against the store calls in the exact order
# they happen, keyed by the call number (1-based). An entry can be:
#   true  -> the call raises RuntimeError (simulating a backend outage)
#   false -> the call succeeds
#
# Recovery is therefore observable immediately: once the script is exhausted,
# calls hit the real in-memory counters again.
class ScriptedStore
  class BackendUnavailable < StandardError; end

  attr_reader :calls

  def initialize(script: {})
    @script = script
    @calls = []
    @counter = 0
    @mutex = Mutex.new
    @values = {}
  end

  def increment(key, amount = 1, _options = {})
    record_and_maybe_fail(:increment, key)
    @mutex.synchronize { @values[key] = (@values[key] || 0) + amount }
  end

  def write(key, value, _options = {})
    record_and_maybe_fail(:write, key)
    @mutex.synchronize { @values[key] = value }
  end

  def read(key, _options = {})
    record_and_maybe_fail(:read, key)
    @mutex.synchronize { @values[key] }
  end

  def delete(key, _options = {})
    record_and_maybe_fail(:delete, key)
    @mutex.synchronize { @values.delete(key) }
  end

  def reset!
    @mutex.synchronize { @values.clear }
  end

  private

  def record_and_maybe_fail(operation, key)
    number = @mutex.synchronize { @counter += 1 }
    @calls << { number: number, operation: operation, key: key }

    return unless @script.fetch(number, false)

    raise BackendUnavailable, "scripted store failure on call ##{number}"
  end
end
