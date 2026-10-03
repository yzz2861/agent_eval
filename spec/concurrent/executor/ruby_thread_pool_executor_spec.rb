require_relative 'thread_pool_executor_shared'
require 'concurrent/executor/thread_pool_executor'

module Concurrent

  RSpec.describe RubyThreadPoolExecutor, :type=>:mri do

    after(:each) do
      subject.shutdown
      expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
    end

    subject do
      RubyThreadPoolExecutor.new(
        min_threads: 2,
        max_threads: 5,
        idletime: 60,
        max_queue: 10,
        fallback_policy: :discard
      )
    end

    it_should_behave_like :thread_pool

    it_should_behave_like :thread_pool_executor

    context :prune, if: !Concurrent.on_jruby? do # pruning is flaky on JRuby
      subject do
        RubyThreadPoolExecutor.new(idletime: 5, min_threads: 2, max_threads: 10)
      end

      Group = Struct.new :waiting_threads, :threads, :mutex, :cond

      def prepare_thread_group(size)
        cond = ConditionVariable.new
        mutex = Mutex.new
        threads = []
        size.times do
          subject.post do
            mutex.synchronize do
              threads << Thread.current
              cond.wait(mutex)
              threads.delete(Thread.current)
            end
          end
        end
        eventually(mutex: mutex) { expect(threads).to have_attributes(size: size) }
        Group.new(threads, threads.dup, mutex, cond)
      end

      def wakeup_thread_group(group)
        group.cond.broadcast
        eventually(mutex: group.mutex) do
          expect(group.waiting_threads).to have_attributes(size: 0)
        end
      end

      before(:each) do
        @group1 = prepare_thread_group(5)
        @group2 = prepare_thread_group(5)
      end

      def eventually(mutex: nil, timeout: 5, &block)
        start = Time.now
        while Time.now - start < timeout
          begin
            if mutex
              mutex.synchronize do
                return yield
              end
            else
              return yield
            end
          rescue Exception => last_failure
          end
          Thread.pass
        end
        raise last_failure
      end

      it "triggers pruning if the thread idletimes have elapsed" do
        wakeup_thread_group(@group1)
        sleep 6
        wakeup_thread_group(@group2)

        eventually { expect(@group1.threads).to all(have_attributes(status: false)) }
        eventually { expect(@group2.threads).to all(have_attributes(status: 'sleep')) }
      end

      it "does not trigger pruning if the thread idletimes have not elapsed " do
        wakeup_thread_group(@group1)
        wakeup_thread_group(@group2)

        eventually { expect(@group1.threads).to all(have_attributes(status: 'sleep')) }
        eventually { expect(@group2.threads).to all(have_attributes(status: 'sleep')) }
      end

      it "keeps at least min_length workers" do
        wakeup_thread_group(@group1)
        wakeup_thread_group(@group2)
        sleep 6
        all_threads = @group1.threads + @group2.threads
        eventually do
          finished_threads = all_threads.find_all { |t| !t.status }
          expect(finished_threads).to have_attributes(size: 8)
        end
      end
    end

    context '#remaining_capacity' do

      let!(:expected_max){ 100 }
      let(:latch) { Concurrent::CountDownLatch.new }

      subject do
        RubyThreadPoolExecutor.new(
          min_threads: 10,
          max_threads: 20,
          idletime: 60,
          max_queue: expected_max,
          fallback_policy: :discard
        )
      end

      it 'returns :max_length when no tasks are enqueued' do
        5.times{ subject.post{ nil } }
        subject.post { latch.count_down }
        latch.wait(0.1)
        expect(subject.remaining_capacity).to eq expected_max
      end

      it 'returns the remaining capacity when tasks are enqueued' do
        block = Concurrent::CountDownLatch.new
        100.times{ subject.post{ block.wait } }
        subject.post { latch.count_down }
        latch.wait(0.1)
        expect(subject.remaining_capacity).to be < expected_max
        block.count_down
      end
    end

    context 'threads naming' do
      subject do
        opts = { min_threads: 2 }
        opts[:name] = pool_name if pool_name
        described_class.new(opts)
      end

      let(:names) do
        require 'concurrent/set'
        Concurrent::Set.new
      end

      before do
        subject.post(names) { |names| names << Thread.current.name }
        subject.post(names) { |names| names << Thread.current.name }
        subject.shutdown
        subject.wait_for_termination(pool_termination_timeout)
        expect(names.size).to eq 2
      end

      context 'without pool name' do
        let(:pool_name) { }
        it 'sets counted name' do
          expect(names.all? { |name| name =~ /^worker-\d+$/ }).to be true
        end
      end

      context 'with pool name' do
        let(:pool_name) { 'MyExecutor' }
        it 'sets counted name' do
          expect(names.all? { |name| name =~ /^MyExecutor-worker-\d+$/ }).to be true
        end
      end
    end
    context '#managed_block' do
      subject do
        described_class.new(
          min_threads: 1,
          max_threads: 1,
          max_queue: 2,
          idletime: 60,
          fallback_policy: :abort
        )
      end

      it 'temporarily replaces a blocked worker for a child task' do
        child_started = Queue.new
        release_child = Queue.new
        child_finished = Queue.new
        parent_finished = Queue.new
        observed_length = Queue.new

        subject.post do
          subject.managed_block do
            subject.post do
              child_started << true
              release_child.pop
              child_finished << true
            end

            child_started.pop
            observed_length << subject.length
            release_child << true
            child_finished.pop
          end
          parent_finished << true
        end

        expect(parent_finished.pop).to be true
        expect(observed_length.pop).to eq 2
        repeat_until_success { expect(subject.length).to eq 1 }
      end

      it 'counts nested blocks only once' do
        first_started = Queue.new
        release_first = Queue.new
        first_finished = Queue.new
        second_started = Queue.new
        nested_finished = Queue.new
        observed_length = Queue.new
        observed_queue_length = Queue.new

        subject.post do
          subject.managed_block do
            subject.managed_block do
              subject.post do
                first_started << true
                release_first.pop
                first_finished << true
              end

              first_started.pop
              observed_length << subject.length
              subject.post { second_started << true }
              observed_queue_length << subject.queue_length
              release_first << true
              second_started.pop
            end
          end
          nested_finished << true
        end

        expect(nested_finished.pop).to be true
        expect(observed_length.pop).to eq 2
        expect(observed_queue_length.pop).to eq 1
        repeat_until_success { expect(subject.length).to eq 1 }
      end

      it 'rejects calls from threads outside the pool' do
        expect { subject.managed_block { } }
          .to raise_error(Concurrent::IllegalOperationError)
      end

      it 'keeps ordinary work at the configured capacity while blocked' do
        child_started = Queue.new
        release_child = Queue.new
        active_count = Queue.new

        subject.post do
          subject.managed_block do
            subject.post do
              child_started << true
              release_child.pop
            end

            child_started.pop
            active_count << subject.active_count
          end
        end

        expect(active_count.pop).to eq 1
        release_child << true
      end

      it 'returns compensation when the block exits with an exception' do
        child_finished = Queue.new
        allow_failure = Queue.new
        failure_observed = Queue.new

        subject.post do
          begin
            subject.managed_block do
              subject.post { child_finished.pop }
              allow_failure.pop
              raise 'managed block failure'
            end
          rescue RuntimeError => error
            failure_observed << error.message
          end
        end

        repeat_until_success { expect(subject.length).to eq 2 }
        child_finished << true
        allow_failure << true
        expect(failure_observed.pop).to eq 'managed block failure'
        repeat_until_success { expect(subject.length).to eq 1 }
      end

      it 'does not add compensation after shutdown starts' do
        block_entered = Queue.new
        release_block = Queue.new

        subject.post do
          subject.managed_block do
            block_entered << true
            release_block.pop
          end
        end

        block_entered.pop
        subject.shutdown

        expect { subject.post { } }
          .to raise_error(Concurrent::RejectedExecutionError)
        expect(subject.length).to eq 1

        release_block << true
        expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
      end

      it 'drains queued work before stopping after shutdown inside a block' do
        first_started = Queue.new
        release_first = Queue.new
        second_finished = Queue.new
        release_block = Queue.new
        parent_inside_block = Queue.new

        subject.post do
          subject.managed_block do
            subject.post do
              first_started << true
              release_first.pop
            end

            subject.post { second_finished << true }
            first_started.pop
            parent_inside_block << true
            release_block.pop
          end
        end

        parent_inside_block.pop
        repeat_until_success { expect(subject.length).to eq 2 }
        subject.shutdown
        release_first << true
        expect(second_finished.pop).to be true
        release_block << true

        expect(subject.wait_for_termination(pool_termination_timeout)).to eq true
      end
    end
  end
end
