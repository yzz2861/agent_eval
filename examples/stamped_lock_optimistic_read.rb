#!/usr/bin/env ruby
# Optimistic reads with Concurrent::StampedLock.
#
# Scenario: a read-mostly in-memory index holding two *related* fields
# (low and high water marks) that must always be read as a consistent pair.
#
# This example shows why "read the fields, read them again, and compare the
# values" is NOT a safe optimistic-read check:
#
#   1. A writer can change both fields and then change them back (the "ABA"
#      problem). The final values look untouched, so a value comparison
#      passes -- even though the index was rewritten in between.
#   2. While the writer is halfway through, the reader can observe a torn
#      pair (new low, old high) that never existed.
#
# A StampedLock stamp detects both cases: releasing a write lock bumps the
# lock version, so every stamp issued before the release stops validating,
# no matter what the field values look like.

$LOAD_PATH.unshift File.expand_path('../lib/concurrent-ruby', __dir__)

require 'concurrent/atomic/stamped_lock'

# A tiny read-mostly index with two related fields guarded by a StampedLock.
class WaterMarkIndex
  def initialize
    @lock  = Concurrent::StampedLock.new
    @low   = 1
    @high  = 10
    @build = 0 # internal generation, not visible to value comparisons
  end

  attr_reader :lock

  # Optimistic read: take a stamp, read both fields, validate.
  # Falls back to a real read lock only if a writer interfered.
  def read_marks
    stamp = @lock.try_optimistic_read
    if stamp == 0
      optimistic = false
    else
      low, high = @low, @high
      optimistic = @lock.validate(stamp)
    end

    if optimistic
      [low, high, :optimistic]
    else
      @lock.with_read_lock { [@low, @high, :locked] }
    end
  end

  # Naive "optimistic" read: compare the values before and after.
  # Returns [low, high, verdict] where verdict is :unchanged or :changed.
  def read_marks_naive
    low1, high1 = @low, @high
    yield if block_given? # let a writer run in between (for the demo)
    low2, high2 = @low, @high
    verdict = (low1 == low2 && high1 == high2) ? :unchanged : :changed
    [[low1, high1], [low2, high2], verdict]
  end

  def rebuild!(low, high)
    @lock.with_write_lock do
      @low   = low
      @high  = high
      @build += 1
    end
  end

  def build
    @lock.with_read_lock { @build }
  end
end

index = WaterMarkIndex.new

puts "1) Fast path: no writer around, the optimistic read succeeds"
low, high, how = index.read_marks
puts "   read (#{low}, #{high}) via #{how} read"
puts

puts "2) ABA: a writer rewrites the index and then restores the SAME values"
puts "   naive value comparison is fooled, the stamp is not"

stamp = index.lock.try_optimistic_read

naive_result = index.read_marks_naive do
  index.rebuild!(2, 20)  # writer changes both fields...
  index.rebuild!(1, 10)  # ...and then restores the original values
end
(low1, high1), (low2, high2), verdict = naive_result
puts "   naive check: (#{low1}, #{high1}) vs (#{low2}, #{high2}) => #{verdict} (WRONG: index was rebuilt twice)"
puts "   stamp validates: #{index.lock.validate(stamp)} (correctly detects the writes)"
puts "   index generation is now #{index.build}, but the values look untouched"
puts

puts "3) Torn pair: a reader can observe (new low, old high) mid-write"
reader_sees = nil
writer_midway = Queue.new
writer_finish = Queue.new

writer = Thread.new do
  index.lock.with_write_lock do
    index.instance_variable_set(:@low, 5)   # first field written...
    writer_midway << true                    # ...reader runs here...
    writer_finish.pop                        # ...then the second field
    index.instance_variable_set(:@high, 50)
  end
end

writer_midway.pop
stamp = index.lock.try_optimistic_read
puts "   optimistic stamp while a writer is active: #{stamp} (0 means 'not possible')"
low  = index.instance_variable_get(:@low)
high = index.instance_variable_get(:@high)
puts "   torn pair visible to a lock-free reader: (#{low}, #{high}) -- never a real state"
writer_finish << true
writer.join

low, high, how = index.read_marks
puts "   after the writer finished: (#{low}, #{high}) via #{how} read"
