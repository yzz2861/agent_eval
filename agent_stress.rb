$LOAD_PATH.unshift File.expand_path('lib/concurrent-ruby')
require 'concurrent'

# Stress: capacity 1 with many producer threads and slow action
pool   = Concurrent::FixedThreadPool.new(8)
agent  = Concurrent::Agent.new(0, max_pending_actions: 1)
accepted = Concurrent::AtomicFixnum.new(0)
full     = Concurrent::AtomicFixnum.new(0)
threads = 8.times.map do
  Thread.new do
    200.times do
      r = agent.try_send_via(pool) { |v| sleep(0.0005); v + 1 }
      if r == :accepted
        accepted.increment
      elsif r == :full
        full.increment
      else
        raise "unexpected #{r}"
      end
    end
  end
end
threads.each(&:join)
agent.await_for(10)
200.times { break if agent.pending_action_count.zero?; sleep(0.01) }
unless agent.pending_action_count.zero?
  q = agent.instance_variable_get(:@queue)
  p = agent.instance_variable_get(:@processing)
  busy = agent.instance_variable_get(:@busy)
  abort "pending not drained: #{agent.pending_action_count} qsize=#{q.size} processing=#{p} busy=#{busy} failed=#{agent.failed?} value=#{agent.value}"
end
abort "value mismatch: #{agent.value} vs #{accepted.value}" unless agent.value == accepted.value
abort "value mismatch: #{agent.value} vs accepted #{agent.value}" unless agent.value == accepted.value
puts "stress OK: accepted=#{accepted.value} full=#{full.value} value=#{agent.value}"

# max_pending_actions 1, many successes interleaved with errors in :continue
agent2 = Concurrent::Agent.new(0, error_mode: :continue, max_pending_actions: 1)
100.times do |i|
  until (r = agent2.try_send { i.even? ? (raise 'boom') : 1 }) == :accepted
    raise "unexpected #{r}" unless r == :full
  end
end
agent2.await_for(10)
abort "pending2=#{agent2.pending_action_count}" unless agent2.pending_action_count.zero?
puts "continue errors OK pending=#{agent2.pending_action_count} value=#{agent2.value}"

# invalid options
begin; Concurrent::Agent.new(0, max_pending_actions: -1); abort 'no raise'; rescue ArgumentError; end
begin; Concurrent::Agent.new(0, max_pending_actions: 'x'); abort 'no raise'; rescue ArgumentError; end
begin; agent.try_send_via(pool); abort 'no raise'; rescue ArgumentError; end
puts "validation OK"
pool.shutdown
