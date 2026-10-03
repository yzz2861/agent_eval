# frozen_string_literal: true

RSpec.describe(Dry::Monads::ResultT) do
  include Dry::Monads::Result::Mixin
  include Dry::Monads::ResultT::Mixin

  result_t = described_class

  describe ".from_result" do
    it "lifts Success" do
      expect(result_t.from_result(Success(1)).value!).to eql(Success(1))
    end

    it "lifts Failure" do
      expect(result_t.from_result(Failure(:bad)).value!).to eql(Failure(:bad))
    end

    it "rejects plain values" do
      expect { result_t.from_result(1) }.to raise_error(
        TypeError,
        "Expected a Result, got Integer: 1"
      )
    end
  end

  describe ".new" do
    it "lifts a plain Result" do
      expect(result_t.new(Success(1)).value!).to eql(Success(1))
    end

    it "lifts a Task" do
      expect(result_t.new(Dry::Monads::Task.pure(Success(1))).value!)
        .to eql(Success(1))
    end
  end

  describe ".from_task" do
    it "lifts a Task that fulfills with a Result" do
      expect(result_t.from_task(Dry::Monads::Task.pure(Success(1))).value!)
        .to eql(Success(1))
    end

    it "validates the Task value without forcing execution" do
      input = Thread::Queue.new
      task = Dry::Monads::Task.new { input.pop }
      transformed = result_t.from_task(task)

      expect(transformed).not_to be_complete
      input << 1

      expect { result_t.from_task(task).value! }.to raise_error(
        TypeError,
        "Expected the Task wrapped by ResultT to fulfill with a Result, got Integer: 1"
      )
    end

    it "rejects a plain Task value synchronously" do
      expect { result_t.from_task(1) }.to raise_error(
        TypeError,
        "Expected a Task, got Integer: 1"
      )
    end

    it "keeps a rejected Task on the exception channel" do
      error = RuntimeError.new("boom")
      transformed = result_t.from_task(Dry::Monads::Task.failed(error))

      expect { transformed.value! }.to raise_error(error)
    end
  end

  describe ".[]" do
    it "lifts a plain Result" do
      expect(result_t[Success(1)].value!).to eql(Success(1))
    end

    it "lifts a Task" do
      expect(result_t[Dry::Monads::Task.pure(Failure(:bad))].value!)
        .to eql(Failure(:bad))
    end

    it "returns an existing ResultT" do
      transformed = result_t.pure(1)

      expect(result_t[transformed]).to be(transformed)
    end

    it "gives a useful lift error" do
      expect { result_t[1] }.to raise_error(
        TypeError,
        "Expected Result, Task, or ResultT, got Integer: 1"
      )
    end
  end

  describe "#fmap" do
    it "maps Success values" do
      transformed = result_t.pure(1).fmap { |value| value + 1 }

      expect(transformed.value!).to eql(Success(2))
    end

    it "does not call the block for Failure" do
      called = false
      transformed = result_t.failure(:bad).fmap { called = true }

      expect(transformed.value!).to eql(Failure(:bad))
      expect(called).to be(false)
    end

    it "does not call the block when the Task is rejected" do
      called = false
      transformed = result_t.from_task(
        Dry::Monads::Task.failed(RuntimeError.new("boom"))
      ).fmap { called = true }

      expect { transformed.value! }.to raise_error(RuntimeError, "boom")
      expect(called).to be(false)
    end
  end

  describe "#bind" do
    it "binds a plain Result" do
      transformed = result_t.pure(1).bind { |value| Success(value + 1) }

      expect(transformed.value!).to eql(Success(2))
    end

    it "binds a Task that fulfills with a Result" do
      transformed = result_t.pure(1).bind do |value|
        Dry::Monads::Task.pure(Success(value + 1))
      end

      expect(transformed.value!).to eql(Success(2))
    end

    it "binds another ResultT" do
      transformed = result_t.pure(1).bind { |value| result_t.pure(value + 1) }

      expect(transformed.value!).to eql(Success(2))
    end

    it "short-circuits Failure" do
      called = false
      transformed = result_t.failure(:bad).bind { called = true }

      expect(transformed.value!).to eql(Failure(:bad))
      expect(called).to be(false)
    end

    it "keeps a rejected inner Task on the exception channel" do
      called = false
      transformed = result_t.pure(1).bind do
        Dry::Monads::Task.failed(RuntimeError.new("boom"))
      end.bind { called = true }

      expect { transformed.value! }.to raise_error(RuntimeError, "boom")
      expect(called).to be(false)
    end

    it "gives a useful error when the block returns the wrong type" do
      transformed = result_t.pure(1).bind { 2 }

      expect { transformed.value! }.to raise_error(
        TypeError,
        "ResultT#bind block must return a Result, Task, or ResultT, got Integer: 2"
      )
    end

    it "gives a useful async error when a returned Task has the wrong value" do
      transformed = result_t.pure(1).bind { Dry::Monads::Task.pure(2) }

      expect { transformed.value! }.to raise_error(
        TypeError,
        "ResultT#bind block returned a Task that must fulfill with a Result, " \
        "got Integer: 2"
      )
    end
  end

  describe "delayed execution" do
    it "does not run chained blocks before the first Task fulfills" do
      calls = []
      input = Thread::Queue.new
      first = Dry::Monads::Task.new do
        result = input.pop
        calls << :first
        result
      end
      chain = result_t.from_task(first)
        .bind { |value| calls << :second; Dry::Monads::Task.pure(Success(value + 1)) }
        .fmap { |value| calls << :third; value + 1 }

      expect(calls).to be_empty
      input << Success(1)
      expect(chain.value!).to eql(Success(3))
      expect(calls).to eq(%i[first second third])
    end
  end

  describe "three asynchronous services" do
    let(:calls) { [] }

    def service(name, outcome)
      ->(value = nil) do
        Dry::Monads::Task.new do
          calls << name

          case outcome
          when :success
            Success(value ? value + 1 : 1)
          when :failure
            Failure(:business_rejection)
          else
            raise "execution failure"
          end
        end
      end
    end

    def chain(first:, second:, third:)
      described_class.from_task(service(:first, first).call)
        .fmap { |value| value }
        .bind { |value| service(:second, second).call(value) }
        .fmap { |value| value }
        .bind { |value| service(:third, third).call(value) }
    end

    it "runs every service on success" do
      expect(chain(first: :success, second: :success, third: :success).value!)
        .to eql(Success(3))
      expect(calls).to eq(%i[first second third])
    end

    it "stops after the rejecting service on business Failure" do
      expect(chain(first: :success, second: :failure, third: :success).value!)
        .to eql(Failure(:business_rejection))
      expect(calls).to eq(%i[first second])
    end

    it "stops after the raising service and keeps the exception channel" do
      expect { chain(first: :success, second: :error, third: :success).value! }
        .to raise_error(RuntimeError, "execution failure")
      expect(calls).to eq(%i[first second])
    end
  end

  describe "Mixin constructor" do
    it "lifts an async block returning a Result" do
      expect(ResultT { Success(1) }.value!).to eql(Success(1))
    end

    it "lifts a plain Result" do
      expect(ResultT(Failure(:bad)).value!).to eql(Failure(:bad))
    end
  end
end
