# frozen_string_literal: true

# Simple reusable barrier so concurrency specs can release a known number of
# threads simultaneously instead of relying on sleep-based timing.
class Barrier
  def initialize(count)
    @count = count
    @waiting = 0
    @mutex = Mutex.new
    @condition = ConditionVariable.new
  end

  def wait
    @mutex.synchronize do
      @waiting += 1
      if @waiting >= @count
        @condition.broadcast
      else
        @condition.wait(@mutex) while @waiting < @count
      end
    end
  end
end
