# frozen_string_literal: true

RSpec.describe "Parallel step adapter" do
  subject(:transaction) {
    branch_definitions = branches
    concurrency_limit = max_concurrency

    Class.new do
      include Dry::Transaction()

      parallel :quote, branches: branch_definitions, max_concurrency: concurrency_limit
      step :total

      def total(quote)
        Success(quote[:shipping] + quote[:tax] - quote[:discount])
      end
    end.new
  }

  let(:max_concurrency) { 3 }

  it "collects named results and passes the same read-only input to each branch" do
    input = {price: 100}
    received_inputs = ConcurrentArray.new
    branches = {
      shipping: transaction_branch(:shipping, received_inputs) do |branch_input|
        Success(branch_input[:price] / 10)
      end,
      tax: transaction_branch(:tax, received_inputs) do |branch_input|
        Success(branch_input[:price] / 20)
      end,
      discount: transaction_branch(:discount, received_inputs) do |branch_input|
        Success(branch_input[:price] / 50)
      end
    }

    result = build_transaction(branches, 3).call(input)

    expect(result).to eql(Success(13))
    names = received_inputs.to_a.map(&:first)
    branch_inputs = received_inputs.to_a.map(&:last)
    expect(names).to match_array(%i[shipping tax discount])
    expect(branch_inputs).to all(equal(input))
  end

  it "requires an explicit concurrency limit" do
    adapter = Dry::Transaction::StepAdapters::Parallel.new
    branches = {shipping: transaction_branch(:shipping) { Success(10) }}

    expect {
      adapter.call(nil, {step_name: :quote, branches: branches}, [{}])
    }.to raise_error(
      ArgumentError,
      /parallel step \+quote\+ requires \+max_concurrency:\+/
    )
  end

  context "when a branch fails" do
    let(:max_concurrency) { 2 }
    let(:coordinator) { Coordinator.new }

    let(:branches) {
      {
        shipping: gated_transaction_branch(:shipping) { Failure("shipping unavailable") },
        tax: gated_transaction_branch(:tax) { Failure("tax unavailable") },
        discount: gated_transaction_branch(:discount) { Success(2) }
      }
    }

    it "stops pending branches and waits for started branches" do
      call = Thread.new { transaction.call(price: 100) }

      wait_for_events(coordinator, 2)
      started = drain_events(coordinator)
      expect(started.map { |event| event[:name] }).to match_array(%i[shipping tax])

      coordinator.release(:shipping)
      coordinator.release(:tax)

      expect(call.value).to eql(
        Failure(shipping: "shipping unavailable", tax: "tax unavailable")
      )
      expect(call).not_to be_alive
      expect(threads_from(started)).to all(be_finished)
      expect(drain_events(coordinator)).to be_empty
    end
  end

  context "with the concurrency limit" do
    let(:max_concurrency) { 2 }
    let(:coordinator) { Coordinator.new }

    let(:branches) {
      {
        shipping: gated_transaction_branch(:shipping) { Success(10) },
        tax: gated_transaction_branch(:tax) { Success(5) },
        discount: gated_transaction_branch(:discount) { Success(2) }
      }
    }

    it "limits active branches and does not leave workers for the next call" do
      first_call = Thread.new { transaction.call(price: 100) }

      wait_for_events(coordinator, 2)
      first_started = drain_events(coordinator)
      first_names = first_started.map { |event| event[:name] }
      expect(first_names).to match_array(%i[shipping tax])

      coordinator.release(:shipping)
      wait_for_events(coordinator, 1)
      expect(drain_events(coordinator).map { |event| event[:name] }).to eq([:discount])

      coordinator.release(:tax)
      coordinator.release(:discount)
      expect(first_call.value).to eql(Success(13))
      first_call.join

      first_threads = first_started.map { |event| event[:thread] }
      expect(first_threads).to all(be_finished)

      coordinator.clear_events
      second_call = Thread.new { transaction.call(price: 100) }

      wait_for_events(coordinator, 2)
      second_started = drain_events(coordinator)
      second_names = second_started.map { |event| event[:name] }
      second_threads = threads_from(second_started)
      expect(second_names).to match_array(%i[shipping tax])
      expect(second_threads).not_to include(*first_threads)

      coordinator.release_all
      expect(second_call.value).to eql(Success(13))
      expect(second_call).not_to be_alive
      expect(second_threads).to all(be_finished)
    end
  end

  private

  def build_transaction(branch_definitions, concurrency_limit)
    Class.new do
      include Dry::Transaction()

      parallel :quote, branches: branch_definitions, max_concurrency: concurrency_limit
      step :total

      def total(quote)
        Success(quote[:shipping] + quote[:tax] - quote[:discount])
      end
    end.new
  end

  def transaction_branch(name, received_inputs = nil, &operation)
    branch_operation = operation

    Class.new do
      include Dry::Transaction()

      define_method(name, &branch_operation)
      step name
    end.new.tap do |branch_transaction|
      next unless received_inputs

      branch_transaction.singleton_class.alias_method(:original_call, :call)
      branch_transaction.define_singleton_method(:call) do |input|
        received_inputs << [name, input]
        original_call(input)
      end
    end
  end

  def gated_transaction_branch(name, &result)
    branch_coordinator = coordinator
    branch_result = result

    transaction_branch(name) do |input|
      branch_coordinator.enter(name, input)
      branch_result.call
    end
  end

  def wait_for_events(branch_coordinator, count)
    deadline = Time.now + 2

    until branch_coordinator.event_count >= count
      raise "timed out waiting for #{count} branches to start" if Time.now >= deadline

      sleep 0.01
    end
  end

  def drain_events(branch_coordinator)
    branch_coordinator.drain_events
  end

  def threads_from(events)
    events.map { |event| event[:thread] }
  end

  def be_finished
    satisfy("be finished") { |branch_thread| !branch_thread.alive? }
  end

  class ConcurrentArray
    def initialize
      @values = []
      @mutex = Mutex.new
    end

    def <<(value)
      @mutex.synchronize { @values << value }
      self
    end

    def to_a
      @mutex.synchronize { @values.dup }
    end
  end

  class Barrier
    def initialize
      @queue = Queue.new
    end

    def release
      @queue << true
    end

    def wait
      @queue.pop
    end
  end

  class Coordinator
    attr_reader :events

    def initialize
      @mutex = Mutex.new
      reset
    end

    def clear_events
      @mutex.synchronize do
        @events = Queue.new
      end
    end

    def reset
      @mutex.synchronize do
        @events = Queue.new
        @barriers = Hash.new { |hash, key| hash[key] = Barrier.new }
      end
    end

    def enter(name, input)
      @events << {name: name, input: input, thread: Thread.current}
      barrier(name).wait
    end

    def release(name)
      barrier(name).release
    end

    def release_all
      @mutex.synchronize { @barriers.each_key.to_a }.each { |name| release(name) }
    end

    def event_count
      @events.size
    end

    def drain_events
      values = []
      values << @events.pop(true) until @events.empty?
      values
    rescue ThreadError
      values
    end

    private

    def barrier(name)
      @mutex.synchronize { @barriers[name] }
    end
  end
end
