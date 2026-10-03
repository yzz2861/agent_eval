# frozen_string_literal: true

RSpec.describe(Dry::Monads::Writer) do
  writer = described_class.method(:new)
  unit = Dry::Monads::Unit

  subject { writer.(1) }

  it_behaves_like "a monad"
  it_behaves_like "a functor"
  it_behaves_like "a constructor"

  describe ".pure" do
    it "wraps a value with an empty log" do
      expect(described_class.pure(1)).to eql(writer.(1, []))
    end

    it "accepts a block" do
      fn = -> x { x }
      expect(described_class.pure(&fn)).to eql(writer.(fn, []))
    end
  end

  describe ".tell" do
    it "records a log with Unit as the value" do
      expect(described_class.tell([:a])).to eql(writer.(unit, [:a]))
    end
  end

  describe "#value!" do
    it "extracts the value" do
      expect(writer.(1, [:a]).value!).to eql(1)
    end
  end

  describe "#log" do
    it "returns the accumulated log" do
      expect(writer.(1, [:a]).log).to eql([:a])
    end
  end

  describe "#fmap" do
    it "maps the value and keeps the log intact" do
      expect(writer.(1, [:a]).fmap { _1 + 1 }).to eql(writer.(2, [:a]))
    end
  end

  describe "#bind" do
    it "sequences computations concatenating logs in order" do
      result = writer.(1, [:first])
        .bind { |x| writer.(x + 1, [:second]) }
        .bind { |x| writer.(x * 10, [:third]) }

      expect(result).to eql(writer.(20, [:first, :second, :third]))
    end

    it "accepts a callable" do
      expect(writer.(1, [:a]).bind(-> x { writer.(x + 1, [:b]) }))
        .to eql(writer.(2, [:a, :b]))
    end
  end

  describe "#tell" do
    it "appends to the log keeping the value" do
      expect(writer.(1, [:a]).tell([:b])).to eql(writer.(1, [:a, :b]))
    end
  end

  describe "#listen" do
    it "exposes the log as part of the value" do
      expect(writer.(1, [:a]).listen).to eql(writer.([1, [:a]], [:a]))
    end

    it "observes only the log of the sub-computation" do
      result = writer.(1, [:outer]).bind { |x|
        writer.(x + 1, [:inner]).listen
      }

      expect(result.value!).to eql([2, [:inner]])
      expect(result.log).to eql([:outer, :inner])
    end
  end

  describe "#censor" do
    it "transforms the log" do
      expect(writer.(1, [:a, :b]).censor { |log| log.take(1) })
        .to eql(writer.(1, [:a]))
    end

    it "modifies only its own scope" do
      result = writer.(1, [:outer]).bind { |x|
        writer.(x + 1, [:inner, :secret]).censor { |log| log - [:secret] }
      }

      expect(result).to eql(writer.(2, [:outer, :inner]))
    end
  end

  describe "#inspect" do
    it "returns the string representation" do
      expect(writer.(1, [:a]).inspect).to eql("Writer(1, [:a])")
    end
  end

  describe "#===" do
    it "matches on value and log" do
      expect(writer.(1, [:a]) === writer.(1, [:a])).to be(true)
      expect(writer.(Integer, Array) === writer.(1, [:a])).to be(true)
      expect(writer.(1, [:a]) === writer.(1, [:b])).to be(false)
      expect(writer.(1, [:a]) === 1).to be(false)
    end
  end

  describe "pattern matching" do
    it "matches value and log as an array" do
      expect((writer.(1, [:a]) in [1, [:a]])).to be(true)
    end

    it "matches value and log as keys" do
      expect((writer.(1, [:a]) in {value: 1, log: [:a]})).to be(true)
    end

    it "matches with the class name" do
      expect((writer.(1, [:a]) in Dry::Monads::Writer[Integer, Array])).to be(true)
    end
  end

  describe "log isolation" do
    it "does not accumulate logs in a shared global structure" do
      described_class.tell([:a])
      described_class.pure(1).tell([:b])

      expect(described_class.pure(2).log).to eql([])
    end

    it "does not share the empty log between instances" do
      first = described_class.pure(1)
      second = described_class.pure(2)

      first.log << :mutated

      expect(second.log).to eql([])
    end

    context "with a mutable plain empty value" do
      let(:array_writer) do
        Class.new(described_class) { empty [] }
      end

      it "duplicates the empty log for every instance" do
        first = array_writer.pure(1)
        second = array_writer.pure(2)

        first.log << :mutated

        expect(second.log).to eql([])
      end
    end
  end

  describe "custom log algebra" do
    let(:string_writer) do
      Class.new(described_class) do
        empty -> { +"acc" }
        combine ->(acc, entry) { "#{acc}|#{entry}" }
      end
    end

    it "uses the configured empty and combine" do
      result = string_writer.pure(nil).tell("a").tell("b")

      expect(result.log).to eql("acc|a|b")
    end

    it "respects non-commutative concatenation order" do
      to_left = string_writer.pure(nil).tell("a").bind { string_writer.tell("b") }
      to_right = string_writer.pure(nil).tell("b").bind { string_writer.tell("a") }

      expect(to_left.log).to eql("acc|a|b")
      expect(to_right.log).to eql("acc|b|a")
    end
  end

  describe "mixin" do
    subject(:obj) { Object.new.extend(Dry::Monads[:writer]) }

    it "registers the Writer constructor" do
      expect(obj.Writer(1)).to eql(writer.(1, []))
    end

    it "registers the Tell constructor" do
      expect(obj.Tell([:a])).to eql(writer.(unit, [:a]))
    end

    it "extends Dry::Monads with the constructors" do
      expect(Dry::Monads.Writer(1)).to eql(writer.(1, []))
      expect(Dry::Monads.Tell([:a])).to eql(writer.(unit, [:a]))
    end
  end

  describe "decision with explanation" do
    def check(rule, passed)
      Dry::Monads::Writer.pure(passed).tell([{rule: rule, passed: passed}])
    end

    it "returns the decision value along with the full explanation log" do
      decision = check("amount", true).bind { |amount_ok|
        check("velocity", false).fmap { |velocity_ok| amount_ok && velocity_ok }
      }

      expect(decision.value!).to be(false)
      expect(decision.log).to eql([
        {rule: "amount", passed: true},
        {rule: "velocity", passed: false}
      ])
    end
  end
end
