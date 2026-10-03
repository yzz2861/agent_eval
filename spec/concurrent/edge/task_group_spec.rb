require 'concurrent-edge'
require 'thread'

RSpec.describe Concurrent::TaskGroup, edge: true do
  it 'waits for accepted tasks and returns their futures' do
    group = described_class.new
    futures = 3.times.map { group.submit { |_group, cancellation| [cancellation.canceled?, :done] } }

    expect(group.close).to eq group
    expect(futures.map(&:value!)).to eq Array.new(3) { [false, :done] }
  end

  it 'passes cancellation to a one-argument task and nothing to a zero-argument task' do
    group = described_class.new
    cancellation_arg = group.submit { |cancellation| cancellation }
    no_arguments = group.submit { :no_arguments }

    group.close

    expect(cancellation_arg.value!).to equal(group.cancellation)
    expect(no_arguments.value!).to eq :no_arguments
  end

  it 'can run a block scope and return the block value' do
    result = described_class.start do |group, _cancellation|
      group.submit { 1 }
      group.submit { 2 }
      :block_value
    end

    expect(result).to eq :block_value
  end

  it 'passes the group to a one-argument scope block' do
    observed_group = nil

    described_class.start do |group|
      observed_group = group
      group.submit { :done }
    end

    expect(observed_group).to be_a described_class
  end

  it 'supports an immediate executor without deadlock' do
    result = described_class.start(:immediate) do |group, _cancellation|
      group.submit { |task_group, cancellation| task_group.submit { [cancellation.canceled?, :nested] } }
      :immediate
    end

    expect(result).to eq :immediate
  end

  it 'cancels other tasks after the first failure and preserves each failure source' do
    ready = Concurrent::CountDownLatch.new(3)
    start = Concurrent::Event.new

    group = described_class.new
    failing = group.submit do |_group, _cancellation|
      ready.count_down
      start.wait(1)
      raise 'first failure'
    end
    cooperating = group.submit do |_group, cancellation|
      ready.count_down
      start.wait(1) until cancellation.canceled?
      cancellation.check!
    end
    independent = group.submit do |_group, cancellation|
      ready.count_down
      start.wait(1) until cancellation.canceled?
      raise 'second failure'
    end

    expect(ready.wait(1)).to be_truthy
    start.set

    expect { group.close }.to raise_error(Concurrent::MultipleErrors) do |error|
      expect(error.errors.map(&:message)).to contain_exactly('first failure', 'second failure')
    end
    expect(failing).to be_rejected
    expect(cooperating.reason).to be_a Concurrent::CancelledOperationError
    expect(independent).to be_rejected
  end

  it 'raises the original error when only one task fails' do
    group = described_class.new
    future = group.submit { raise 'only failure' }

    expect { group.close }.to raise_error(RuntimeError, 'only failure')
    expect(future.reason.message).to eq 'only failure'
  end

  it 'accepts nested tasks submitted by an already running accepted task' do
    started = Concurrent::CountDownLatch.new(1)
    submit_child = Queue.new

    group = described_class.new
    parent = group.submit do |task_group, cancellation|
      started.count_down
      submit_child.pop
      task_group.submit { cancellation.check! unless false; :child }
    end

    started.wait(1)
    closer = Thread.new { group.close }
    sleep 0.01 until group.state == :closing
    submit_child.push(:go)

    expect(closer.join(1)).to be_truthy
    expect(parent.value!).to be_a Concurrent::Promises::Future
    expect(parent.value!.value!).to eq :child
  end

  it 'rejects nested submissions after cancellation starts' do
    ready = Concurrent::CountDownLatch.new(2)
    start = Concurrent::Event.new
    group = described_class.new

    failing = group.submit do
      ready.count_down
      start.wait(1)
      raise 'parent failure'
    end
    nested_parent = group.submit do |task_group, cancellation|
      ready.count_down
      start.wait(1) until cancellation.canceled?
      task_group.submit { :never }
    end

    expect(ready.wait(1)).to be_truthy
    start.set
    nested_child = nested_parent.value!

    expect { group.close }.to raise_error(RuntimeError, 'parent failure')
    expect(failing.reason.message).to eq 'parent failure'
    expect(nested_parent).to be_fulfilled
    expect(nested_child).to be_rejected
    expect(nested_child.reason).to be_a Concurrent::CancelledOperationError
  end

  it 'rejects new external tasks after close starts' do
    release = Queue.new
    group = described_class.new
    accepted = group.submit { release.pop }
    closer = Thread.new { group.close }

    sleep 0.01
    rejected = group.submit { :never }
    release.push(:done)
    closer.join(1)

    expect(accepted.value!).to eq :done
    expect(rejected).to be_rejected
    expect(rejected.reason).to be_a Concurrent::RejectedExecutionError
  end

  it 'does not invoke a queued task which starts after cancellation' do
    executor = Concurrent::FixedThreadPool.new(1)
    release = Queue.new

    begin
      group = described_class.new(executor)
      blocker = group.submit do
        release.pop
        raise 'queued failure'
      end
      queued = group.submit { |_group, cancellation| cancellation.check! }
      trigger = Thread.new { release.push(:go) }

      expect { group.close }.to raise_error(RuntimeError, 'queued failure')
      trigger.join(1)
      expect(blocker.reason.message).to eq 'queued failure'
      expect(queued.reason).to be_a Concurrent::CancelledOperationError
    ensure
      executor.shutdown
      executor.wait_for_termination(1)
    end
  end

  it 'treats a task rejected by the executor as the only accepted failure' do
    executor = Concurrent::FixedThreadPool.new(1)
    executor.shutdown
    expect(executor.wait_for_termination(1)).to be_truthy

    group = described_class.new(executor)
    future = group.submit { :never }

    expect { group.close }.to raise_error(Concurrent::RejectedExecutionError)
    expect(future).to be_rejected
    expect(future.reason).to be_a Concurrent::RejectedExecutionError
  end

  it 'gives every close and submission race exactly one resolution path', retry: 3 do
    25.times do
      group = described_class.new
      barrier = Concurrent::Event.new
      futures = Queue.new
      close_error = nil

      submitters = Array.new(4) do
        Thread.new do
          barrier.wait(1)
          5.times { futures << group.submit { Thread.pass } }
        end
      end
      closer = Thread.new do
        barrier.wait(1)
        begin
          group.close
        rescue StandardError => error
          close_error = error
        end
      end

      barrier.set
      submitters.each { |thread| expect(thread.join(1)).to be_truthy }
      expect(closer.join(1)).to be_truthy
      expect(close_error).to be_nil

      until futures.empty?
        future = futures.pop(true)
        expect(future).to be_resolved
        expect(future.reason).to be_nil unless future.fulfilled?
      end
    end
  end

  it 'includes an error raised in the group block' do
    future = nil

    expect do
      described_class.start do |group, _cancellation|
        future = group.submit { :done }
        raise 'block failure'
      end
    end.to raise_error(RuntimeError, 'block failure')

    expect(future).to be_rejected
    expect(future.reason).to be_a Concurrent::CancelledOperationError
  end
end
