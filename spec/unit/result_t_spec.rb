# frozen_string_literal: true

RSpec.describe(Dry::Monads::ResultT) do
  include Dry::Monads::Result::Mixin
  include Dry::Monads::Task::Mixin

  result_t = described_class
  result = Dry::Monads::Result

  let(:service) do
    Class.new do
      include Dry::Monads::Result::Mixin
      include Dry::Monads::Task::Mixin

      attr_reader :calls

      def initialize
        @calls = []
        @mutex = Mutex.new
      end

      def successful_first_step
        async(:first) { Success(1) }
      end

      def rejected_first_step
        async(:first) { Failure(:rejected) }
      end

      def exceptional_first_step
        async(:first) { raise "execution failure" }
      end

      def successful_second_step(value)
        async(:second) { Success(value + 1) }
      end

      def successful_third_step(value)
        async(:third) { Success(value * 3) }
      end

      private

      def async(name, &block)
        record(name, :scheduled)

        Task do
          record(name, :called)
          block.call
        ensure
          record(name, :returned)
        end
      end

      def record(name, event)
        @mutex.synchronize { @calls << [name, event] }
      end
    end.new
  end

  describe "three-step asynchronous service" do
    def run(service)
      described_class.from_task(service.successful_first_step)
        .bind { |value| service.successful_second_step(value) }
        .bind { |value| service.successful_third_step(value) }
        .wait
    end

    it "runs all three steps on the happy path" do
      expect(run(service).value!).to eql(result::Success.new(6))

      expect(service.calls).to eql([
        [:first, :scheduled],
        [:first, :called],
        [:first, :returned],
        [:second, :scheduled],
        [:second, :called],
        [:second, :returned],
        [:third, :scheduled],
        [:third, :called],
        [:third, :returned]
      ])
    end

    it "short-circuits the remaining steps on a business Failure" do
      chain = result_t.from_task(service.rejected_first_step)
        .bind { |value| service.successful_second_step(value) }
        .bind { |value| service.successful_third_step(value) }
        .wait

      expect(chain.value!).to eql(result::Failure.new(:rejected))

      expect(service.calls).to eql([
        [:first, :scheduled],
        [:first, :called],
        [:first, :returned]
      ])
    end

    it "keeps an execution exception on the Task channel and skips later steps" do
      chain = result_t.from_task(service.exceptional_first_step)
        .bind { |value| service.successful_second_step(value) }
        .bind { |value| service.successful_third_step(value) }
        .wait

      expect { chain.value! }.to raise_error(RuntimeError, "execution failure")

      expect(service.calls).to eql([
        [:first, :scheduled],
        [:first, :called],
        [:first, :returned]
      ])
    end
  end

  describe ".new" do
    it "accepts a plain Result" do
      lifted = result_t.new(Success(:ok))

      expect(lifted.value!).to eql(result::Success.new(:ok))
    end

    it "accepts a Task<Result>" do
      lifted = result_t.new(Dry::Monads::Task.pure(Success(:ok)))

      expect(lifted.wait.value!).to eql(result::Success.new(:ok))
    end
  end

  describe ".lift" do
    it "lifts a plain Result without scheduling a Task block" do
      lifted = result_t.lift(Success(:ok))

      expect(lifted.value!).to eql(result::Success.new(:ok))
    end

    it "lifts a Task<Result> without blocking" do
      queue = Queue.new
      lifted = result_t.lift(Dry::Monads::Task.new { Success(queue.pop) })

      expect(lifted).not_to be_complete

      queue << :ok
      expect(lifted.wait.value!).to eql(result::Success.new(:ok))
    end

    it "keeps Result and Task failure channels separate" do
      business_failure = result_t.lift(Failure(:rejected))
      execution_failure = result_t.lift(Dry::Monads::Task.new { raise "boom" })

      expect(business_failure.wait.value!).to eql(result::Failure.new(:rejected))
      expect { execution_failure.wait.value! }.to raise_error(RuntimeError, "boom")
    end

    it "gives a useful message for an invalid plain value" do
      expect { result_t.lift(:not_a_result) }.to raise_error(
        TypeError,
        /expected a Dry::Monads::Result or a Dry::Monads::Task<Result>, got Symbol/
      )
    end
  end

  describe ".from_task" do
    it "does not wait for the given Task" do
      queue = Queue.new
      lifted = result_t.from_task(Dry::Monads::Task.new { Success(queue.pop) })

      expect(lifted).not_to be_complete
    end

    it "rejects a plain Task value immediately with guidance" do
      expect { result_t.from_task(Success(:ok)) }.to raise_error(
        TypeError,
        /expected a Dry::Monads::Task<Result>.*got Dry::Monads::Result::Success.*\.from_result/m
      )
    end

    it "reports a Task that fulfills with a non-Result without converting it" do
      lifted = result_t.from_task(Dry::Monads::Task.new { :not_a_result })

      expect { lifted.wait.value! }.to raise_error(
        TypeError,
        /expected the Task to fulfill with a Dry::Monads::Result.*got Symbol/
      )
    end
  end

  describe ".from_result" do
    it "rejects a Task immediately with guidance" do
      expect { result_t.from_result(Dry::Monads::Task.pure(Success(:ok))) }.to raise_error(
        TypeError,
        /expected a Dry::Monads::Result.*got Dry::Monads::Task.*\.from_task/m
      )
    end
  end

  describe "#fmap" do
    it "transforms Success values and wraps the plain block result" do
      lifted = result_t.pure(2).fmap { |value| value * 3 }

      expect(lifted.value!).to eql(result::Success.new(6))
    end

    it "does not call the block for Failure" do
      called = false

      lifted = result_t.lift(Failure(:rejected)).fmap { called = true }
      lifted.wait

      expect(lifted.value!).to eql(result::Failure.new(:rejected))
      expect(called).to be(false)
    end

    it "does not call the block when the Task is rejected" do
      called = false
      lifted = result_t.lift(Dry::Monads::Task.new { raise "boom" }).fmap { called = true }

      expect { lifted.wait.value! }.to raise_error(RuntimeError, "boom")
      expect(called).to be(false)
    end

    it "reports a block returning a Result and points users to bind" do
      lifted = result_t.pure(1).fmap { Success(_1) }

      expect { lifted.wait.value! }.to raise_error(
        TypeError,
        /block passed to ResultT#fmap returned Success\(1\).*Use #bind/m
      )
    end

    it "does not force a pending computation" do
      queue = Queue.new
      called = false
      result_t.lift(Dry::Monads::Task.new { Success(queue.pop) }).fmap { called = true }

      sleep 0.01
      expect(called).to be(false)

      queue << :ok
    end
  end

  describe "#bind" do
    it "composes a Task<Result> returned by the block" do
      lifted = result_t.pure(2).bind { |value| Dry::Monads::Task.pure(Success(value + 1)) }

      expect(lifted.value!).to eql(result::Success.new(3))
    end

    it "composes a plain Result returned by the block" do
      lifted = result_t.pure(2).bind { |value| Failure([:bad, value]) }

      expect(lifted.value!).to eql(result::Failure.new([:bad, 2]))
    end

    it "does not call the block for Failure" do
      called = false
      lifted = result_t.lift(Failure(:rejected)).bind { called = true; Success(:never) }

      lifted.wait
      expect(called).to be(false)
    end

    it "does not call the block when the Task is rejected" do
      called = false
      lifted = result_t.lift(Dry::Monads::Task.new { raise "boom" })
        .bind { called = true; Success(:never) }

      expect { lifted.wait.value! }.to raise_error(RuntimeError, "boom")
      expect(called).to be(false)
    end

    it "reports an invalid block result" do
      lifted = result_t.pure(1).bind { :not_a_result }

      expect { lifted.wait.value! }.to raise_error(
        TypeError,
        /block passed to ResultT#bind returned :not_a_result \(Symbol\).*expected Result/m
      )
    end

    it "does not force a pending computation" do
      queue = Queue.new
      called = false
      result_t.lift(Dry::Monads::Task.new { Success(queue.pop) }).bind do
        called = true
        Dry::Monads::Task.pure(Success(:ok))
      end

      sleep 0.01
      expect(called).to be(false)

      queue << :ok
    end
  end

  describe "mixing bind and fmap" do
    it "keeps a later business Failure as the inner Result" do
      lifted = result_t.pure(1)
        .fmap { |value| value + 1 }
        .bind { |value| Dry::Monads::Task.pure(Failure([:rejected, value])) }
        .fmap { raise "must not be called" }

      expect(lifted.value!).to eql(result::Failure.new([:rejected, 2]))
    end
  end

  describe "mixin" do
    let(:klass) do
      Class.new do
        include Dry::Monads[:result, :result_t, :task]

        def call
          ResultT(Success(:ok))
        end
      end
    end

    it "includes a ResultT constructor" do
      expect(klass.new.call.value!).to eql(result::Success.new(:ok))
    end
  end
end
