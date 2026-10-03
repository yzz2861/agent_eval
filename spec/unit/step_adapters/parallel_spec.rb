# frozen_string_literal: true

require "concurrent"

RSpec.describe Dry::Transaction::StepAdapters::Parallel, :adapter do
  subject { described_class.new }

  let(:options) { {step_name: "unit", max_concurrency: 2} }

  describe "#call" do
    it "returns a Success of named branch results in branch definition order" do
      operation = -> _input {
        {
          shipping: -> _input { Success(10) },
          tax: -> _input { Success(3) },
          discount: -> _input { Success(-2) }
        }
      }

      expect(subject.(operation, options, ["input"])).to eql(
        Success(shipping: 10, tax: 3, discount: -2)
      )
    end

    it "hands the very same input object to every branch without copying it" do
      input = Object.new
      seen = []
      seen_mutex = Mutex.new
      branch = -> { -> i { seen_mutex.synchronize { seen << i } && Success(i) } }
      operation = -> _input { {a: branch.call, b: branch.call, c: branch.call} }

      subject.(operation, options, [input])

      expect(seen.length).to eq(3)
      expect(seen).to all(equal(input))
    end

    it "runs branches concurrently but never more than max_concurrency at once" do
      running = 0
      max_seen = 0
      state = Mutex.new
      barrier = Concurrent::CyclicBarrier.new(options[:max_concurrency])

      branch = -> {
        -> _input {
          state.synchronize { running += 1; max_seen = [max_seen, running].max }
          barrier.wait(5)
          state.synchronize { running -= 1 }
          Success(true)
        }
      }
      operation = -> _input { {a: branch.call, b: branch.call, c: branch.call, d: branch.call} }

      subject.(operation, options, ["input"])

      expect(max_seen).to eq(2)
    end

    context "when a branch fails" do
      it "skips unstarted branches, awaits started ones and locates the failure" do
        b_started = Queue.new
        a_failed = Queue.new
        b_finished = false
        c_ran = false

        a = -> _input {
          b_started.pop
          a_failed << true
          Failure("a broke")
        }
        b = -> _input {
          b_started << true
          a_failed.pop
          b_finished = true
          Success("b done")
        }
        c = -> _input {
          c_ran = true
          Success("c done")
        }
        operation = -> _input { {a: a, b: b, c: c} }

        result = subject.(operation, options, ["input"])

        expect(result).to eql(Failure(a: "a broke"))
        expect(b_finished).to be(true)
        expect(c_ran).to be(false)
      end

      it "reports every failed branch by name" do
        barrier = Concurrent::CyclicBarrier.new(2)

        a = -> _input { barrier.wait(5) && Failure("a broke") }
        b = -> _input { barrier.wait(5) && Failure("b broke") }
        c = -> _input { Success("c done") }
        operation = -> _input { {a: a, b: b, c: c} }

        expect(subject.(operation, options, ["input"])).to eql(
          Failure(a: "a broke", b: "b broke")
        )
      end
    end

    it "does not leak background threads into subsequent calls" do
      threads = Queue.new
      branch = -> { -> _input { threads << Thread.current && Success(true) } }
      operation = -> _input { {a: branch.call, b: branch.call, c: branch.call} }

      subject.(operation, options, ["input"])

      branch_threads = 3.times.map { threads.pop }
      expect(branch_threads).to all(satisfy { |thread| !thread.alive? })

      baseline = Thread.list.size
      subject.(operation, options, ["input"])
      expect(Thread.list.size).to eq(baseline)
    end

    it "requires an explicit max_concurrency option" do
      operation = -> _input { {a: -> _input { Success(1) }} }

      expect { subject.(operation, {step_name: "unit"}, ["input"]) }
        .to raise_error(Dry::Transaction::MissingConcurrencyLimitError, /max_concurrency/)
    end

    it "rejects branches that are not callable" do
      operation = -> _input { {a: "not callable"} }

      expect { subject.(operation, options, ["input"]) }
        .to raise_error(Dry::Transaction::InvalidBranchesError, /branch name => callable/)
    end
  end
end
