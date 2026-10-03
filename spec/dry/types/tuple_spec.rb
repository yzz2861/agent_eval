# frozen_string_literal: true

RSpec.describe Dry::Types::Tuple do
  subject(:type) { Dry::Types["nominal.array"].tuple(string, integer, rest: float) }

  let(:string) { Dry::Types["strict.string"] }
  let(:integer) { Dry::Types["coercible.integer"] }
  let(:float) { Dry::Types["coercible.float"] }

  describe "#call" do
    it "coerces fixed positions and rest elements" do
      expect(type.[](["event", "1", "2.5", "3.5"])).to eql(["event", 1, 2.5, 3.5])
    end

    it "allows zero rest elements" do
      expect(type.[](["event", "1"])).to eql(["event", 1])
    end

    it "filters undefined values returned by the rest type" do
      skip_zero = integer.constructor { |value| value.zero? ? Dry::Types::Undefined : value }
      tuple = Dry::Types["nominal.array"].tuple(string, rest: skip_zero)

      expect(tuple.(["event", 1, 0, 2])).to eql(["event", 1, 2])
    end

    it "rejects a non-array input" do
      expect { type.(:event) }.to raise_error(
        Dry::Types::CoercionError, /event is not an array/
      )
    end

    context "without rest" do
      subject(:type) { Dry::Types["nominal.array"].tuple(string, integer) }

      it "rejects extra elements at the first invalid index" do
        expect { type.[](["event", "1", 2]) }.to raise_error(
          Dry::Types::TupleError,
          "Tuple element at [2] is unexpected: tuple requires exactly 2 elements, got 3"
        )
      end
    end

    it "treats an explicit nil rest as no rest" do
      tuple = Dry::Types["nominal.array"].tuple(string, rest: nil)

      expect(tuple.(["event"])).to eql(["event"])
      expect { tuple.(["event", 1]) }.to raise_error(Dry::Types::TupleError, /unexpected/)
    end

    it "reports the index of the first missing fixed element" do
      expect { type.[](["event"]) }.to raise_error(
        Dry::Types::TupleError,
        "Tuple element at [1] is missing: tuple requires at least 2 elements, got 1"
      )
    end

    it "reports the index of a failed fixed-position coercion" do
      expect { type.[](["event", "invalid", "2.5"]) }.to raise_error(
        Dry::Types::TupleError,
        %r{Tuple element at \[1\] is invalid: invalid value for Integer}
      )
    end

    it "reports the index of a failed rest-element coercion" do
      expect { type.[](["event", "1", "2.5", "invalid"]) }.to raise_error(
        Dry::Types::TupleError,
        %r{Tuple element at \[3\] is invalid: invalid value for Float}
      )
    end

    it "does not return a partially coerced array from try" do
      input = ["event", "invalid", "2.5"]

      result = type.try(input)

      expect(result).to be_failure
      expect(result.input).to be(input)
      expect(input).to eql(["event", "invalid", "2.5"])
    end

    it "passes the original array to safe call blocks" do
      input = ["event", "invalid", "2.5"]

      expect(type.(input) { |failure| [:failed, failure] }).to eql([:failed, input])
    end
  end

  describe "#try" do
    it "exposes the failing path" do
      failure = type.try(["event", "invalid", "2.5"]).error

      expect(failure).to be_a(Dry::Types::TupleError)
      expect(failure.path).to eql([1])
    end

    it "preserves the original error as the element error" do
      failure = type.try(["event", "invalid", "2.5"]).error

      expect(failure.cause_error).to be_a(Dry::Types::CoercionError)
    end

    context "with nested tuples" do
      subject(:type) do
        Dry::Types["nominal.array"].tuple(string, coordinates)
      end

      let(:coordinates) do
        Dry::Types["nominal.array"].tuple(integer, integer)
      end

      it "builds a path through every tuple" do
        failure = type.try(["point", ["invalid", "2"]]).error

        expect(failure).to be_a(Dry::Types::TupleError)
        expect(failure.path).to eql([1, 0])
        expect(failure.message).to include("[1][0]")
      end

      it "keeps the complete input immutable from partial output" do
        input = ["point", ["invalid", "2"]]
        failure = type.try(input)

        expect(failure.input).to be(input)
        expect(input).to eql(["point", ["invalid", "2"]])
      end
    end
  end

  describe "default values" do
    it "fills omitted trailing fixed positions" do
      tuple = Dry::Types["nominal.array"].tuple(
        string,
        integer.default(0, shared: true)
      )

      expect(tuple.[](["event"])).to eql(["event", 0])
    end

    it "reports the allowed size range when only trailing defaults can be omitted" do
      tuple = Dry::Types["nominal.array"].tuple(
        string,
        integer.default(0, shared: true)
      )

      expect { tuple.([]) }.to raise_error(
        Dry::Types::TupleError,
        "Tuple element at [0] is missing: tuple requires between 1 and 2 elements, got 0"
      )
    end

    it "fills omitted trailing defaults before rest elements" do
      tuple = Dry::Types["nominal.array"].tuple(
        string,
        integer.default(0, shared: true),
        rest: float
      )

      expect(tuple.[](["event"])).to eql(["event", 0])
      expect(tuple.[](["event", "1", "2.5"])).to eql(["event", 1, 2.5])
    end

    it "does not treat non-trailing defaults as optional positions" do
      tuple = Dry::Types["nominal.array"].tuple(
        integer.default(0, shared: true),
        string
      )

      expect { tuple.([1]) }.to raise_error(
        Dry::Types::TupleError,
        "Tuple element at [1] is missing: tuple requires exactly 2 elements, got 1"
      )
    end

    it "can provide a whole tuple when the input is undefined" do
      tuple = type.default(["event", 0].freeze)

      expect(tuple.()).to eql(["event", 0])
    end
  end

  describe "#constrained" do
    it "reports the index of an element constraint failure" do
      positive_integer = integer.constrained(gt: 0)
      tuple = Dry::Types["nominal.array"].tuple(string, positive_integer)

      expect { tuple.(["event", "-1"]) }.to raise_error(
        Dry::Types::TupleError, /Tuple element at \[1\] is invalid/
      )
    end

    it "applies an outer constraint after the tuple is coerced" do
      tuple = type.constrained(min_size: 4)

      expect(tuple.(["event", "1", "2.5", "3.5"])).to eql(["event", 1, 2.5, 3.5])
      expect { tuple.(["event", "1", "2.5"]) }.to raise_error(
        Dry::Types::ConstraintError
      )
    end
  end

  describe "#lax" do
    subject(:lax_type) { type.lax }

    it "coerces valid elements and keeps an invalid element in its position" do
      expect(lax_type.[](["event", "invalid", "2.5"])).to eql(["event", "invalid", 2.5])
    end

    it "returns the original input for an arity failure" do
      input = ["event", "invalid", "2.5"]

      expect(lax_type.(["event"])).to eql(["event"])
      expect(lax_type.(["event", "1", "2.5", "invalid"])).to eql(["event", 1, 2.5, "invalid"])
      expect(input).to eql(["event", "invalid", "2.5"])
    end

    it "returns the original input for a structural failure without rest" do
      tuple = Dry::Types["nominal.array"].tuple(string, integer).lax
      input = ["event", "1", "extra"]

      expect(tuple.(input)).to be(input)
    end

    it "makes nested tuple members lax recursively" do
      coordinates = Dry::Types["nominal.array"].tuple(integer, integer).lax
      tuple = Dry::Types["nominal.array"].tuple(string, coordinates).lax

      expect(tuple.(["point", ["invalid", "2"]])).to eql(["point", ["invalid", 2]])
    end

    it "keeps default positions" do
      tuple = Dry::Types["nominal.array"].tuple(
        string,
        integer.default(0, shared: true)
      ).lax

      expect(tuple.(["event"])).to eql(["event", 0])
    end
  end

  describe "constructor wrapping" do
    it "converts the input with the enclosing array constructor" do
      tuple = Dry::Types["params.array"].tuple(
        Dry::Types["params.string"],
        Dry::Types["params.integer"],
        rest: Dry::Types["params.float"]
      )

      expect(tuple.("") { :fallback }).to be(:fallback)
      expect(tuple.(["event", "1", "2.5"])).to eql(["event", 1, 2.5])
    end
  end

  describe "#to_ast" do
    let(:nominal_string) { Dry::Types["nominal.string"] }
    let(:nominal_integer) { Dry::Types["nominal.integer"] }
    let(:nominal_float) { Dry::Types["nominal.float"] }

    it "dumps fixed types, rest, and meta" do
      tuple = Dry::Types["nominal.array"].tuple(
        nominal_string,
        nominal_integer,
        rest: nominal_float
      ).meta(key: :value)

      expect(tuple.to_ast).to eql([
        :tuple,
        [
          [nominal_string.to_ast, nominal_integer.to_ast],
          nominal_float.to_ast,
          {key: :value}
        ]
      ])
    end

    it "uses nil for an omitted rest type" do
      tuple = Dry::Types["nominal.array"].tuple(nominal_string, nominal_integer)

      expect(tuple.to_ast).to eql([
        :tuple,
        [[nominal_string.to_ast, nominal_integer.to_ast], nil, {}]
      ])
    end

    it "compiles back to an equivalent type" do
      compiler = Dry::Types::Compiler.new(Dry::Types)

      expect(compiler.(type.to_ast)).to eql(type)
    end

    it "preserves raw class member nodes" do
      compiler = Dry::Types::Compiler.new(Dry::Types)
      tuple = compiler.([:tuple, [[String], nil, {}]])

      expect(tuple.types.first).to be(String)
    end
  end

  describe "#to_s" do
    it "prints fixed types and rest" do
      tuple = Dry::Types["nominal.array"].tuple(
        Dry::Types["nominal.string"],
        Dry::Types["nominal.integer"],
        rest: Dry::Types["nominal.float"]
      )

      expect(tuple.to_s).to eql(
        "#<Dry::Types[Tuple<Nominal<String>, Nominal<Integer>, *Nominal<Float>>]>"
      )
    end

    it "prints meta" do
      tuple = Dry::Types["nominal.array"].tuple(Dry::Types["nominal.string"]).meta(key: :value)

      expect(tuple.to_s).to eql(
        "#<Dry::Types[Tuple<Nominal<String> meta={key: :value}>]>"
      )
    end
  end

  describe "type module builders" do
    it "builds a tuple from exported type constants" do
      mod = Dry::Types()

      tuple = mod.Tuple(mod::String, mod::Integer, rest: mod::Float)

      expect(tuple).to eql(
        Dry::Types["nominal.array"].tuple(mod::String, mod::Integer, rest: mod::Float)
      )
    end

    it "accepts string type identifiers" do
      tuple = Dry::Types["nominal.array"].tuple("strict.string", "coercible.integer")

      expect(tuple.(["event", "1"])).to eql(["event", 1])
    end
  end

  describe "inferrers" do
    it "infers Array as the primitive" do
      inferrer = Dry::Types::PrimitiveInferrer.new

      expect(inferrer[type]).to eql([Array])
    end

    it "infers the array predicate" do
      inferrer = Dry::Types::PredicateInferrer.new

      expect(inferrer[type]).to eql([:array?])
    end
  end
end
