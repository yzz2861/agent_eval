# frozen_string_literal: true

RSpec.describe(Dry::Monads::State) do
  include Dry::Monads[:result]

  subject(:computation) { described_class }

  describe "constructors" do
    it "creates a pure computation" do
      expect(computation.pure(1).run(:state)).to eql([1, :state])
    end

    it "gets the current state" do
      expect(computation.get.run(42)).to eql([42, 42])
    end

    it "replaces the current state" do
      expect(computation.put(42).run(0)).to eql([Dry::Monads::Unit, 42])
    end

    it "modifies the current state" do
      expect(computation.modify(&:succ).run(1)).to eql([Dry::Monads::Unit, 2])
    end

    it "creates a computation from a transition function" do
      state = computation.new { |current| [:value, current + 1] }

      expect(state.run(1)).to eql([:value, 2])
    end

    it "requires a callable transition" do
      expect { computation.new(1) }.to raise_error(TypeError, /callable state transition/)
    end

    it "validates transition function results" do
      state = computation.new { :invalid }

      expect { state.run(0) }.to raise_error(
        TypeError, /state transition must return \[value, state\], got :invalid/
      )
    end

    it "does not execute modifier blocks while composing" do
      executed = 0

      computation.modify { executed += 1 }.fmap { executed += 1 }

      expect(executed).to be(0)
    end

    it "requires a callable modification" do
      expect { computation.modify(1) }.to raise_error(TypeError, /callable state modification/)
    end
  end

  describe "#fmap" do
    it "changes the value without changing the state" do
      state = computation.pure(1).fmap(&:succ)

      expect(state.run(:unchanged)).to eql([2, :unchanged])
    end

    it "does not call the function until run" do
      executed = false
      computation.pure(1).fmap { executed = true }

      expect(executed).to be(false)
    end
  end

  describe "#bind" do
    it "composes stateful computations" do
      state = computation.pure(1).bind do |value|
        computation.modify { |current| current + value }
      end

      expect(state.run(10)).to eql([Dry::Monads::Unit, 11])
    end

    it "does not call the block until run" do
      executed = false
      computation.pure(1).bind { executed = true; computation.pure(2) }

      expect(executed).to be(false)
    end

    it "requires the block to return a State" do
      expect { computation.pure(1).bind { 2 }.run(0) }.to raise_error(
        TypeError, /expected State, got 2/
      )
    end
  end

  describe "#run_value and #run_state" do
    let(:state) do
      computation.get.bind do |initial|
        computation.put(initial + 1).fmap { :done }
      end
    end

    it "returns the final value" do
      expect(state.run_value(1)).to be(:done)
    end

    it "returns the final state" do
      expect(state.run_state(1)).to be(2)
    end
  end

  describe "state isolation" do
    it "does not mutate the input state" do
      initial = { stock: 2, reserved: 0 }
      state = computation.modify do |current|
        current.merge(stock: current.fetch(:stock) - 1)
      end

      state.run(initial)

      expect(initial).to eql(stock: 2, reserved: 0)
    end

    it "keeps repeated runs independent" do
      state = computation.modify(&:succ)

      expect(state.run(0)).to eql([Dry::Monads::Unit, 1])
      expect(state.run(0)).to eql([Dry::Monads::Unit, 1])
    end
  end

  describe "#bind_result" do
    def reserve(item, quantity)
      described_class.get.bind do |inventory|
        available = inventory.fetch(item)

        if available < quantity
          described_class.pure(Failure(:insufficient_stock))
        else
          described_class.put(inventory.merge(item => available - quantity)).fmap do
            Success(quantity)
          end
        end
      end
    end

    it "passes successful values through in sequence" do
      program = reserve(:widgets, 2).bind_result do |first|
        reserve(:widgets, 1).bind_result do |second|
          described_class.pure(Success([first, second]))
        end
      end

      expect(program.run(widgets: 3)).to eql([Success([2, 1]), widgets: 0])
    end

    it "shows order-dependent inventory reservations" do
      program = reserve(:widgets, 2).bind_result do
        reserve(:gadgets, 1).bind_result { described_class.pure(Success(:done)) }
      end

      expect(program.run(widgets: 2, gadgets: 1)).to eql([Success(:done), widgets: 0, gadgets: 0])
      expect(program.run(widgets: 1, gadgets: 1)).to eql([Failure(:insufficient_stock), widgets: 1, gadgets: 1])

      reversed = reserve(:gadgets, 1).bind_result do
        reserve(:widgets, 2).bind_result { described_class.pure(Success(:done)) }
      end

      expect(reversed.run(widgets: 1, gadgets: 1)).to eql([Failure(:insufficient_stock), widgets: 1, gadgets: 0])
    end

    it "retains state changes from earlier successful steps without rolling back" do
      program = reserve(:widgets, 1).bind_result do
        reserve(:widgets, 1).bind_result { described_class.pure(Success(:done)) }
      end

      expect(program.run(widgets: 1)).to eql([Failure(:insufficient_stock), widgets: 0])
    end

    it "retains an explicit state carried by a failure transition" do
      program = described_class
        .put(stock: 0, hold: 1)
        .fmap { Failure(:rejected) }
        .bind_result { raise "must not run" }

      expect(program.run(stock: 0, hold: 0)).to eql([Failure(:rejected), stock: 0, hold: 1])
    end

    it "requires the preceding value to be a Result" do
      program = described_class.pure(1).bind_result { described_class.pure(Success(2)) }

      expect { program.run(0) }.to raise_error(TypeError, /expected Result, got 1/)
    end

    it "requires the continuation to produce a Result" do
      program = described_class
        .pure(Success(1))
        .bind_result { described_class.pure(2) }

      expect { program.run(0) }.to raise_error(TypeError, /expected Result, got 2/)
    end

    it "keeps Result short-circuiting local to an explicit result binding" do
      failing_state = described_class.pure(Failure(:stopped))
      program = described_class
        .pure(1)
        .bind { failing_state }
        .fmap { |result| "received #{result}" }

      expect(program.run_value(0)).to eql("received Failure(:stopped)")
    end
  end

  describe "stack safety" do
    it "keeps long fmap chains iterative" do
      chain = (1..50_000).reduce(described_class.pure(0)) { |state, _| state.fmap(&:succ) }

      expect(chain.run_value(0)).to be(50_000)
    end

    it "keeps long bind chains iterative" do
      chain = (1..50_000).reduce(described_class.pure(0)) do |state, _|
        state.bind { |value| described_class.pure(value + 1) }
      end

      expect(chain.run_value(0)).to be(50_000)
    end

    it "keeps long result-binding chains iterative" do
      chain = (1..10_000).reduce(described_class.pure(Success(0))) do |state, _|
        state.bind_result { |value| described_class.pure(Success(value + 1)) }
      end

      expect(chain.run_value(0)).to eql(Success(10_000))
    end
  end
end
