# frozen_string_literal: true

RSpec.describe(Dry::Monads::State) do
  include Dry::Monads::State::Mixin
  include Dry::Monads::Result::Mixin

  state = described_class
  unit = Dry::Monads::Unit

  subject(:computation) { state.pure(1) }

  it_behaves_like "a monad"

  describe ".pure" do
    it "lifts a value and leaves the state untouched" do
      expect(state.pure(42).run(:state)).to eql([42, :state])
    end
  end

  describe ".get" do
    it "exposes the current state as the value" do
      expect(state.get.run({balance: 100})).to eql([{balance: 100}, {balance: 100}])
    end
  end

  describe ".put" do
    it "replaces the state" do
      expect(state.put(:new).run(:old)).to eql([unit, :new])
    end
  end

  describe ".modify" do
    it "updates the state with a function" do
      expect(state.modify { |n| n + 1 }.run(1)).to eql([unit, 2])
    end

    it "accepts a callable" do
      expect(state.modify(:succ.to_proc).run(1)).to eql([unit, 2])
    end
  end

  describe ".gets" do
    it "derives a value from the state without changing it" do
      expect(state.gets { |s| s[:balance] * 2 }.run({balance: 10})).to eql([20, {balance: 10}])
    end
  end

  describe ".step" do
    it "builds a computation from a raw step function" do
      counter = state.step { |n| [n, n + 1] }
      expect(counter.run(5)).to eql([5, 6])
    end
  end

  describe "State() constructor" do
    it "lifts a value" do
      expect(State(5).run(nil)).to eql([5, nil])
    end

    it "builds a computation from a step block" do
      expect(State { |s| [s, s * 2] }.run(3)).to eql([3, 6])
    end
  end

  describe "#fmap" do
    it "maps the value without touching the state" do
      expect(state.pure(1).fmap { _1 * 2 }.run(:s)).to eql([2, :s])
    end

    it "accepts a callable" do
      expect(state.pure(1).fmap(:succ.to_proc).run(:s)).to eql([2, :s])
    end
  end

  describe "#bind" do
    it "sequences computations and threads the state" do
      computation = state.get.bind { |n| state.put(n + 1) }.bind { state.get }
      expect(computation.run(0)).to eql([1, 1])
    end

    it "accepts a callable" do
      increment = ->(n) { state.pure(n + 1) }
      expect(state.pure(1).bind(increment).run(:s)).to eql([2, :s])
    end
  end

  describe "laziness" do
    it "executes nothing while composing" do
      effects = []
      computation = state.modify { |s| effects << :modify; s }
        .bind { state.step { |s| effects << :step; [nil, s] } }
        .fmap { effects << :fmap }

      expect(effects).to be_empty

      computation.run(nil)
      expect(effects).to eql(%i[modify step fmap])
    end
  end

  describe "state immutability" do
    it "does not mutate the initial state" do
      initial = {count: 0}.freeze
      computation = state.modify { |s| s.merge(count: s[:count] + 1) }

      value, new_state = computation.run(initial)

      expect(value).to be(unit)
      expect(new_state).to eql(count: 1)
      expect(new_state).not_to be(initial)
      expect(initial).to eql(count: 0)
    end

    it "keeps repeated runs of the same computation independent" do
      initial = {log: []}
      computation = state.modify { |s| s.merge(log: s[:log] + [:ran]) }

      expect(computation.exec_state(initial)).to eql(log: [:ran])
      expect(computation.exec_state(initial)).to eql(log: [:ran])
      expect(initial).to eql(log: [])
    end
  end

  describe "#run" do
    it "returns the value and the final state" do
      expect(state.pure(:value).run(:state)).to eql([:value, :state])
    end
  end

  describe "#eval_state" do
    it "returns the final value" do
      expect(state.get.fmap { _1 + 1 }.eval_state(1)).to be(2)
    end
  end

  describe "#exec_state" do
    it "returns the final state" do
      expect(state.get.fmap { _1 + 1 }.exec_state(1)).to be(1)
    end
  end

  describe "#bind_result" do
    it "continues with the unwrapped value on Success" do
      computation = state.pure(1).bind_result { |v| Success(v + 1) }.fmap { |v| v * 10 }
      expect(computation.run(:s)).to eql([20, :s])
    end

    it "halts on Failure and returns it as the value" do
      computation = state.pure(1).bind_result { Failure(:boom) }.bind { state.put(:unreachable) }

      value, final_state = computation.run(:initial)

      expect(value).to eql(Failure(:boom))
      expect(final_state).to be(:initial)
    end

    it "keeps the state reached at the point of failure instead of rolling back" do
      computation = state.modify { |n| n + 1 }
        .bind_result { Failure(:boom) }
        .bind { state.modify { |n| n + 100 } }

      value, final_state = computation.run(0)

      expect(value).to eql(Failure(:boom))
      expect(final_state).to be(1)
    end

    it "accepts a callable" do
      check = ->(v) { v.positive? ? Success(v) : Failure(:negative) }
      expect(state.pure(1).bind_result(check).run(:s)).to eql([1, :s])
      expect(state.pure(-1).bind_result(check).run(:s)).to eql([Failure(:negative), :s])
    end
  end

  describe ".from_result" do
    it "lifts a Success" do
      expect(state.from_result(Success(1)).run(:s)).to eql([1, :s])
    end

    it "halts with a Failure keeping the current state" do
      computation = state.put(:checkpoint).bind { state.from_result(Failure(:boom)) }
      expect(computation.run(:initial)).to eql([Failure(:boom), :checkpoint])
    end
  end

  describe "stack safety" do
    it "runs long left-nested bind chains without overflowing the stack" do
      computation = 1.upto(100_000).reduce(state.pure(0)) { |acc, _|
        acc.bind { |n| state.pure(n + 1) }
      }

      expect(computation.eval_state(nil)).to be(100_000)
    end

    it "runs long right-nested bind chains without overflowing the stack" do
      computation = state.pure(0)
      50_000.times do
        previous = computation
        computation = state.pure(1).bind { |x| previous.fmap { |y| x + y } }
      end

      expect(computation.eval_state(nil)).to be(50_000)
    end

    it "runs long state-threading chains without overflowing the stack" do
      computation = 1.upto(50_000).reduce(state.get) { |acc, _|
        acc.bind { state.modify { |s| s + 1 } }
      }

      expect(computation.exec_state(0)).to be(50_000)
    end
  end

  describe "#to_s" do
    it "returns the string representation" do
      expect(state.pure(1).to_s).to eql("State(?)")
    end

    it "is an alias for #inspect" do
      expect(computation.method(:to_s)).to eql(computation.method(:inspect))
    end
  end
end
