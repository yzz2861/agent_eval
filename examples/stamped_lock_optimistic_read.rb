#!/usr/bin/env ruby

#$: << File.expand_path('../../lib', __FILE__)

require 'concurrent/atomic/stamped_lock'

# An in-memory index with two related fields guarded by one invariant:
# checking + savings must always equal 100. A writer moves money between
# the two accounts, which briefly makes the pair inconsistent, and may even
# move the money back so the final values look exactly like the initial ones.
#
# This example shows why a reader cannot detect such a write by comparing
# the values it read before and after (the "ABA" problem), and how
# Concurrent::StampedLock's optimistic-read stamps solve it.

lock     = Concurrent::StampedLock.new
checking = 50
savings  = 50

# ---------------------------------------------------------------------------
# 1. The naive approach: snapshot the values, read again, compare.
# ---------------------------------------------------------------------------

writer_changed  = Queue.new
writer_restored = Queue.new
reader_proceed  = Queue.new

writer = Thread.new do
  lock.with_write_lock do
    checking, savings = 10, 90   # transfer 40: checking + savings is still 100,
    writer_changed << true       # but the pair briefly differs from what the
    reader_proceed.pop           # reader saw, and a mid-write reader could even
    checking, savings = 50, 50   # observe a torn pair like [50, 90] (sum 140).
    writer_restored << true      # finally the original values are restored.
  end
end

before = [checking, savings]
writer_changed.pop               # let the writer change (and restore) the fields
reader_proceed << true
writer_restored.pop
after = [checking, savings]
writer.join

puts "naive reader: before=#{before.inspect} after=#{after.inspect}"
if before == after
  puts '  -> values look unchanged, but a write DID happen in between.'
  puts '  -> comparing final values cannot detect it (ABA problem).'
end

# ---------------------------------------------------------------------------
# 2. The StampedLock approach: take a stamp, read, validate.
# ---------------------------------------------------------------------------

writer_changed  = Queue.new
writer_restored = Queue.new
reader_proceed  = Queue.new
writer_start    = Queue.new

writer = Thread.new do
  writer_start.pop
  lock.with_write_lock do
    checking, savings = 10, 90
    writer_changed << true
    reader_proceed.pop
    checking, savings = 50, 50   # restore the original values
    writer_restored << true
  end
end

stamp = lock.try_optimistic_read # 1. take the version stamp
read_checking, read_savings = checking, savings # 2. read the fields lock-free

writer_start << true
writer_changed.pop
reader_proceed << true
writer_restored.pop
writer.join

puts "stamped reader: read=#{[read_checking, read_savings].inspect} " \
     "current=#{[checking, savings].inspect}"

# 3. only proceed if no writer acquired the lock in the meantime
if lock.validate(stamp)
  puts '  -> stamp valid: the values can be used as-is.'
else
  puts '  -> stamp invalid: a write happened, even though the values are back'
  puts '     to [50, 50]. Falling back to a locked re-read:'
  lock.with_read_lock do
    puts "     re-read under read lock: #{[checking, savings].inspect}"
  end
end
