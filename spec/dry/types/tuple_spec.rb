# frozen_string_literal: true

RSpec.describe Dry::Types::Tuple do
  subject(:tuple) do
    nominal.tuple(string, integer, rest: float)
  end

  let(:nominal) { Dry::Types["nominal.array"] }
  let(:string) { Dry::Types["string"] }
  let(:integer) { Dry::Types["params.integer"] }
  let(:float) { Dry::Types["params.float"] }

  describe "#call" do
    it "coerces positional values and rest values" do
      expect(tuple.(["event", "2", "1.5", 3.0])).to eql(["event", 2, 1.5, 3.0])
    end

    it "accepts no rest values" do
      expect(tuple.(["event", "2"])).to eql(["event", 2])
    end

    it "reports the index of a missing positional value" do
      expect { tuple.(["event"]) }.to raise_error(
        an_instance_of(Dry::Types::TupleError).and(having_attributes(
          index: 1,
          path: [1],
          message: "[1]: missing tuple element"
        ))
      )
    end

    it "reports the index of an extra value without rest" do
      fixed = nominal.tuple(string, integer)

      expect { fixed.(["event", 2, 3]) }.to raise_error(
        an_instance_of(Dry::Types::TupleError).and(having_attributes(
          index: 2,
          path: [2],
          message: "[2]: unexpected tuple element"
        ))
      )
    end

    it "reports the index of a failed positional coercion" do
      expect { tuple.(["event", "bad"]) }.to raise_error(
        an_instance_of(Dry::Types::TupleError).and(having_attributes(
          index: 1,
          path: [1]
        ))
      )
    end

    it "reports the index of a failed rest coercion" do
      expect { tuple.(["event", "2", "bad"]) }.to raise_error(
        an_instance_of(Dry::Types::TupleError).and(having_attributes(
          index: 2,
          path: [2]
        ))
      )
    end

    it "does not expose a partially coerced array" do
      input = ["event", "bad", "1.5"]

      expect { tuple.(input) }.to raise_error(Dry::Types::TupleError)
      expect(input).to eql(["event", "bad", "1.5"])
    end

    it "preserves the input in a safe failure" do
      input = ["event", "bad", "1.5"]

      result = tuple.(input) { :failure }

      expect(result).to be(:failure)
      expect(input).to eql(["event", "bad", "1.5"])
    end
  end

  describe "#try" do
    it "returns the original input in a failure result" do
      input = ["event", "bad", "1.5"]
      result = tuple.try(input)

      expect(result).to be_failure
      expect(result.input).to equal(input)
    end

    it "reports nested tuple paths" do
      nested = nominal.tuple(integer, tuple)
      result = nested.try(["1", ["event", "bad", "1.5"]])

      expect(result).to be_failure
      expect(result.error.path).to eql([1, 1])
      expect(result.error.message).to start_with("[1][1]:")
    end
  end

  describe "trailing values" do
    it "fills default values from the trailing positions" do
      with_default = nominal.tuple(string, integer.default(0), rest: float)

      expect(with_default.(["event"])).to eql(["event", 0])
      expect(with_default.(["event", "2", "3.0"])).to eql(["event", 2, 3.0])
    end

    it "fills omitted optional trailing positions with nil" do
      with_optional = nominal.tuple(string, integer, integer.optional)

      expect(with_optional.(["event", "2"])).to eql(["event", 2, nil])
      expect(with_optional.(["event", "2", nil])).to eql(["event", 2, nil])
    end

    it "still requires earlier non-default positions" do
      with_default = nominal.tuple(string, integer.default(0), integer)

      expect(with_default.try(["event"])).to be_failure
    end
  end

  describe "#lax" do
    it "coerces valid positions and keeps invalid ones" do
      lax = tuple.lax

      expect(lax.(["event", "bad", "bad", "3.0"])).to eql(["event", "bad", "bad", 3.0])
    end

    it "returns the original input when arity is wrong" do
      fixed = nominal.tuple(string, integer).lax
      input = ["event", 2, 3]

      expect(fixed.(input)).to equal(input)
    end

    it "keeps strict result semantics in #try" do
      result = tuple.lax.try(["event", "bad"])

      expect(result).to be_failure
      expect(result.error.path).to eql([1])
    end
  end

  describe "constraints" do
    it "applies member constraints with tuple index errors" do
      positive_integer = Dry::Types["integer"].constrained(gt: 0)
      constrained_tuple = nominal.tuple(string, positive_integer)

      expect { constrained_tuple.(["event", -1]) }.to raise_error(
        an_instance_of(Dry::Types::TupleError).and(having_attributes(index: 1))
      )
    end

    it "applies outer array constraints after tuple coercion" do
      constrained_tuple = tuple.constrained(min_size: 3)

      expect(constrained_tuple.(["event", "2", "3.0"])).to eql(["event", 2, 3.0])
      expect { constrained_tuple.(["event", "2"]) }.to raise_error(Dry::Types::ConstraintError)
    end
  end

  describe "constructors" do
    it "keeps an outer array constructor" do
      params_tuple = Dry::Types["params.array"].tuple(integer, integer, rest: float)

      expect(params_tuple.(["1", "2", "3.0"])).to eql([1, 2, 3.0])
    end

    it "round-trips lax constructors through the compiler" do
      params_tuple = Dry::Types["params.array"].tuple(integer, integer, rest: float).lax
      compiler = Dry::Types::Compiler.new(Dry::Types)

      expect(compiler.(params_tuple.to_ast)).to eql(params_tuple)
      expect(compiler.(params_tuple.to_ast).(["1", "bad"])).to eql([1, "bad"])
    end
  end

  describe "#to_ast" do
    it "round-trips through the compiler" do
      compiler = Dry::Types::Compiler.new(Dry::Types)

      expect(compiler.(tuple.to_ast)).to eql(tuple)
    end

    it "round-trips default positions through the compiler" do
      with_default = nominal.tuple(string, integer.default(0), rest: float)
      compiler = Dry::Types::Compiler.new(Dry::Types)

      expect(compiler.(with_default.to_ast)).to eql(with_default)
    end

    it "round-trips lax tuples through the compiler" do
      compiler = Dry::Types::Compiler.new(Dry::Types)

      expect(compiler.(tuple.lax.to_ast)).to eql(tuple.lax)
    end
  end

  describe "#to_s" do
    it "prints positional and rest types" do
      expect(tuple.to_s).to eql(
        "#<Dry::Types[Tuple<" \
        "Constrained<Nominal<String> rule=[type?(String)]>, " \
        "Constructor<Nominal<Integer options={namespace: \"params\"}> " \
        "fn=Dry::Types::Coercions::Params.to_int>, " \
        "*Constructor<Nominal<Float options={namespace: \"params\"}> " \
        "fn=Dry::Types::Coercions::Params.to_float>>]>"
      )
    end
  end

  describe "builder" do
    it "builds a tuple from an exported types module" do
      types = Module.new { include Dry.Types(default: :nominal) }
      tuple = types.Tuple(types::String, types::Integer, rest: types::Float)

      expect(tuple).to be_a(Dry::Types::Constrained)
      expect(tuple.(["event", 2, 3.0])).to eql(["event", 2, 3.0])
    end
  end
end
