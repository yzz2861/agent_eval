# frozen_string_literal: true

RSpec.describe(Dry::Monads::Writer) do
  writer = described_class
  unit = Dry::Monads::Unit

  subject { writer.new(1) }

  it_behaves_like "a monad"
  it_behaves_like "a functor"
  it_behaves_like "a constructor"

  describe ".pure" do
    it "wraps a value with an empty log" do
      expect(writer.pure(1)).to eql(writer.new(1, []))
    end

    it "accepts a block" do
      fn = -> x { x }
      expect(writer.pure(&fn)).to eql(writer.new(fn, []))
    end
  end

  describe ".tell" do
    it "records a log fragment with Unit as the value" do
      expect(writer.tell([:a])).to eql(writer.new(unit, [:a]))
    end
  end

  describe "Dry::Monads.Writer" do
    it "builds a writer with an empty log" do
      expect(Dry::Monads.Writer(1)).to eql(writer.pure(1))
    end

    it "raises an error when no value is given" do
      expect { Dry::Monads.Writer() }.to raise_error(ArgumentError)
    end
  end

  describe "mixin" do
    subject(:object) do
      Class.new { include Dry::Monads[:writer] }.new
    end

    it "registers the writer mixin" do
      expect(object.Writer(1)).to eql(writer.pure(1))
    end

    it "exposes the Writer constant" do
      expect(object.class::Writer).to be(writer)
    end
  end

  describe "#value!" do
    it "extracts the value" do
      expect(writer.new(:approved, [:checked]).value!).to be(:approved)
    end
  end

  describe "#log" do
    it "returns the accumulated log" do
      expect(writer.new(:approved, [:checked]).log).to eql([:checked])
    end
  end

  describe "#monad" do
    it "returns the writer class" do
      expect(subject.monad).to be(writer)
    end
  end

  describe "#fmap" do
    it "maps the value and keeps the log" do
      expect(writer.new(1, [:a]).fmap { _1 + 1 }).to eql(writer.new(2, [:a]))
    end
  end

  describe "#bind" do
    it "accepts a callable" do
      expect(subject.bind(-> v { writer.pure(v + 1) })).to eql(writer.pure(2))
    end

    it "appends the log of the sub-computation" do
      result = writer.tell([:a]).bind { writer.tell([:b]) }

      expect(result.log).to eql(%i[a b])
    end

    it "orders entries by execution because combining is not commutative" do
      first = writer.tell([:first])
      second = writer.tell([:second])

      expect(first.bind { second }.log).to eql(%i[first second])
      expect(second.bind { first }.log).to eql(%i[second first])
    end
  end

  describe "empty logs" do
    it "does not share mutable empty logs between instances" do
      one = writer.pure(1)
      another = writer.pure(2)

      expect(one.log).not_to be(another.log)

      one.log << :mutated

      expect(another.log).to eql([])
      expect(writer.pure(3).log).to eql([])
    end

    it "does not write logs to a global array" do
      writer.tell([:a]).bind { writer.tell([:b]) }

      expect(writer.pure(1).log).to eql([])
      expect(writer.new.log).to eql([])
    end
  end

  describe "custom log configuration" do
    let(:string_writer) do
      Class.new(writer) do
        log_empty -> { +"" }
        log_combine ->(acc, fragment) { acc.empty? ? fragment : "#{acc},#{fragment}" }
      end
    end

    it "uses the configured empty log and combinator" do
      result = string_writer.tell("age").bind { string_writer.tell("country") }

      expect(result.log).to eql("age,country")
    end

    it "produces a fresh empty log for every instance" do
      expect(string_writer.pure(1).log).not_to be(string_writer.pure(2).log)
    end

    it "does not leak configuration to the parent class" do
      string_writer.pure(1)

      expect(writer.pure(1).log).to eql([])
    end
  end

  describe "#listen" do
    it "exposes the accumulated log as part of the value and keeps the log" do
      listened = writer.new(1, [:a]).listen

      expect(listened).to eql(writer.new([1, [:a]], [:a]))
    end

    it "observes only the log of the sub-computation" do
      inner = writer.tell([:inner]).bind { writer.pure(1) }.listen

      result = writer.tell([:before]).bind { inner }.bind { |(value, observed)|
        writer.tell([:after]).bind { writer.pure([value, observed]) }
      }

      expect(result.value!).to eql([1, [:inner]])
      expect(result.log).to eql(%i[before inner after])
    end
  end

  describe "#censor" do
    it "transforms only the log of its own computation" do
      result = writer
        .tell([:secret, :public])
        .censor { |log| log - [:secret] }
        .bind { writer.tell([:later]).bind { writer.pure(:ok) } }

      expect(result.value!).to be(:ok)
      expect(result.log).to eql(%i[public later])
    end

    it "accepts a callable" do
      drop_secrets = ->(log) { log - [:secret] }

      expect(writer.tell([:secret]).censor(drop_secrets).log).to eql([])
    end
  end

  describe "#inspect" do
    it "returns the string representation" do
      expect(writer.new(1, [:a]).inspect).to eql("Writer(1, log: [:a])")
      expect(writer.tell([:a]).inspect).to eql("Writer(log: [:a])")
    end
  end

  describe "#===" do
    it "matches writers with equal value and log" do
      expect(writer.new(1, [:a]) === writer.new(1, [:a])).to be(true)
      expect(writer.new(1, [:a]) === writer.new(1, [:b])).to be(false)
      expect(writer.new(1, [:a]) === :other).to be(false)
    end
  end

  describe "pattern matching" do
    subject { writer.new(:approved, [:checked]) }

    it "matches on value and log as an array" do
      expect((subject in Dry::Monads::Writer[:approved, [:checked]])).to be(true)
      expect((subject in Dry::Monads::Writer[:declined, _])).to be(false)
    end

    it "matches on value and log by key" do
      expect(
        (subject in Dry::Monads::Writer[value: :approved, log: Array])
      ).to be(true)
    end

    it "captures the value and the log" do
      case subject
      in Dry::Monads::Writer[Symbol => value, Array => log]
        expect(value).to be(:approved)
        expect(log).to eql([:checked])
      else
        raise "no match"
      end
    end
  end

  describe "a risk control decision" do
    let(:evaluate) do
      lambda do |tx|
        check = ->(name, passed) {
          writer.tell([{rule: name, passed: passed}]).bind { writer.pure(passed) }
        }

        writer.pure([])
          .bind { |reasons|
            check.(:amount_limit, tx[:amount] <= 10_000).bind { |ok|
              writer.pure(ok ? reasons : reasons + [:amount_too_high])
            }
          }
          .bind { |reasons|
            check.(:country_allowed, %w[CN US].include?(tx[:country])).bind { |ok|
              writer.pure(ok ? reasons : reasons + [:country_blocked])
            }
          }
          .fmap { |reasons| reasons.empty? ? :approve : :decline }
      end
    end

    it "returns the decision value along with the full explanation log" do
      result = evaluate.(amount: 20_000, country: "CN")

      expect(result.value!).to be(:decline)
      expect(result.log).to eql([
        {rule: :amount_limit, passed: false},
        {rule: :country_allowed, passed: true}
      ])
    end

    it "approves a clean transaction with a complete trail" do
      result = evaluate.(amount: 100, country: "US")

      expect(result.value!).to be(:approve)
      expect(result.log).to eql([
        {rule: :amount_limit, passed: true},
        {rule: :country_allowed, passed: true}
      ])
    end
  end
end
