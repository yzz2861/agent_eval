# frozen_string_literal: true

RSpec.describe Dry::Types::Decimal do
  subject(:type) { described_class.new }

  def decimal(value)
    BigDecimal(value)
  end

  it "is registered as decimal.exact" do
    expect(Dry::Types["decimal.exact"]).to be_a(described_class)
  end

  describe "basic coercion" do
    it "parses a decimal string into a BigDecimal" do
      expect(type.call("12.34")).to eql(decimal("12.34"))
    end

    it "parses an integer into a BigDecimal" do
      expect(type.call(12)).to eql(decimal("12"))
    end

    it "passes a BigDecimal through unchanged" do
      value = decimal("12.34")
      expect(type.call(value)).to be(value)
    end

    it "rejects values that cannot become a BigDecimal" do
      expect { type.call(Object.new) }.to raise_error(
        Dry::Types::CoercionError, /cannot be coerced to BigDecimal/
      )
    end
  end

  describe "string handling" do
    %w[12.34 +12.34 -12.34 12. 0.5 .5 0 12345].each do |value|
      it "accepts #{value.inspect}" do
        expect(type.call(value)).to eql(BigDecimal(value))
      end
    end

    %w[1e3 1E3 1.5e-2 1.5E+2 .25e-1].each do |value|
      it "accepts scientific notation #{value.inspect}" do
        expect(type.call(value)).to eql(BigDecimal(value))
      end
    end

    %w[
      abc "" " 12.34" "12.34 " "1.2.3" 1_000 0x10
      NaN Infinity -Infinity +Infinity inf nan
    ].each do |value|
      it "rejects #{value.inspect}" do
        expect { type.call(value) }.to raise_error(
          Dry::Types::CoercionError, /is not a valid decimal string/
        )
      end
    end

    it "does not accept strings that look like booleans" do
      expect { type.call("true") }.to raise_error(Dry::Types::CoercionError)
    end
  end

  describe "finite values" do
    [BigDecimal("NaN"), BigDecimal("Infinity"), BigDecimal("-Infinity")].each do |value|
      it "rejects the BigDecimal #{value}" do
        expect { type.call(value) }.to raise_error(
          Dry::Types::CoercionError, /not a finite decimal value/
        )
      end
    end
  end

  describe "negative zero" do
    it "normalizes a negative zero string to positive zero" do
      result = type.call("-0")
      expect(result).to eql(decimal("0"))
      expect(result.to_s("F")).to eql("0.0")
    end

    it "normalizes a negative zero BigDecimal to positive zero" do
      result = type.call(BigDecimal("-0.000"))
      expect(result).to eql(decimal("0"))
      expect(result.to_s("F")).not_to start_with("-")
    end

    it "preserves genuinely negative values" do
      expect(type.call("-0.01").to_s("F")).to eql("-0.01")
    end
  end

  describe "floats" do
    it "rejects floats by default" do
      expect { type.call(1.23) }.to raise_error(
        Dry::Types::CoercionError, /floats are not accepted by default/
      )
    end

    it "exposes the exact binary expansion when floats are accepted" do
      permissive = type.accepting_float
      expect(permissive.call(0.1).to_s("F")).to eql(
        "0.100000000000000005551115123125783"
      )
    end

    it "does not silently collapse 0.1 + 0.2 to 0.30" do
      permissive = type.accepting_float
      expect(permissive.call(0.1 + 0.2).to_s("F")).to start_with(
        "0.30000000000000004"
      )
    end

    it "keeps exactly representable binary fractions exact" do
      expect(type.accepting_float.call(0.5)).to eql(decimal("0.5"))
    end

    it "rejects NaN and Infinity floats even when floats are accepted" do
      permissive = type.accepting_float
      expect { permissive.call(Float::NAN) }.to raise_error(Dry::Types::CoercionError, /NaN/)
      expect { permissive.call(Float::INFINITY) }.to raise_error(Dry::Types::CoercionError, /Infinity/)
      expect { permissive.call(-Float::INFINITY) }.to raise_error(Dry::Types::CoercionError, /Infinity/)
    end

    it "can be switched back to rejecting floats" do
      expect(type.accepting_float.accepting_float(false).accept_float?).to be(false)
    end
  end

  describe "precision and scale" do
    subject(:money) { type.fixed(precision: 8, scale: 2) }

    it "accepts values that fit the scale exactly" do
      expect(money.call("12.34").to_s("F")).to eql("12.34")
      expect(money.call("12.3").to_s("F")).to eql("12.3")
      expect(money.call("12").to_s("F")).to eql("12.0")
      expect(money.call("0.01").to_s("F")).to eql("0.01")
    end

    it "accepts scientific notation that fits" do
      expect(money.call("1.5E2").to_s("F")).to eql("150.0")
      expect(money.call("1e3").to_s("F")).to eql("1000.0")
    end

    it "rejects inputs with too many fractional digits by default" do
      expect { money.call("12.345") }.to raise_error(
        Dry::Types::CoercionError,
        /12\.345 cannot be represented with scale 2/
      )
    end

    it "rejects scientific values with more precision than the scale" do
      expect { money.call("1.5e-2") }.to raise_error(Dry::Types::CoercionError, /scale 2/)
    end

    it "rejects values that exceed the total precision" do
      expect { money.call("1000000.00") }.to raise_error(
        Dry::Types::CoercionError, /exceeds precision 8/
      )
    end

    it "allows the largest value that fits" do
      expect(money.call("999999.99").to_s("F")).to eql("999999.99")
    end

    it "reports the configured dimensions" do
      expect(money.precision).to be(8)
      expect(money.scale).to be(2)
      expect(money.rounding).to be_nil
      expect(money).to be_fixed
    end

    it "supports a precision-only (integer) type" do
      integer_type = type.fixed(precision: 3, scale: 0)
      expect(integer_type.call("999").to_s("F")).to eql("999.0")
      expect { integer_type.call("1000") }.to raise_error(Dry::Types::CoercionError, /precision 3/)
      expect { integer_type.call("9.9") }.to raise_error(Dry::Types::CoercionError, /scale 0/)
    end
  end

  describe "rounding" do
    subject(:money) { type.fixed(precision: 8, scale: 2) }

    it "does not round unless a mode is selected" do
      expect(money.rounding).to be_nil
      expect { money.call("12.345") }.to raise_error(Dry::Types::CoercionError)
    end

    {
      half_up:    ["12.345", "12.35"],
      half_down:  ["12.345", "12.34"],
      half_even:  ["12.355", "12.36"],
      up:         ["12.341", "12.35"],
      down:       ["12.349", "12.34"],
      floor:      ["-12.341", "-12.35"],
      ceiling:    ["-12.341", "-12.34"]
    }.each do |mode, (input, expected)|
      it "rounds #{input.inspect} to #{expected.inspect} with #{mode}" do
        expect(money.with_rounding(mode).call(input).to_s("F")).to eql(expected)
      end
    end

    it "accepts the BigDecimal integer rounding constants" do
      rounded = money.with_rounding(BigDecimal::ROUND_HALF_UP)
      expect(rounded.call("12.345").to_s("F")).to eql("12.35")
    end

    it "exposes the configured rounding mode" do
      expect(money.with_rounding(:half_up).rounding).to be(BigDecimal::ROUND_HALF_UP)
    end

    it "rejects an unknown symbolic mode" do
      expect { money.with_rounding(:bogus) }.to raise_error(
        ArgumentError, /unknown rounding mode :bogus/
      )
    end

    it "rejects an unknown integer mode" do
      expect { money.with_rounding(99) }.to raise_error(ArgumentError, /unknown rounding mode/)
    end

    it "rejects results that exceed precision after carrying" do
      rounded = money.with_rounding(:up)
      expect { rounded.call("999999.999") }.to raise_error(
        Dry::Types::CoercionError,
        /1000000\.0 exceeds precision 8/
      )
    end

    it "allows a value that carries but still fits" do
      rounded = money.with_rounding(:up)
      expect(rounded.call("12.341").to_s("F")).to eql("12.35")
    end

    it "rounds an integer type" do
      integers = type.fixed(precision: 3, scale: 0, rounding: :half_up)
      expect(integers.call("9.4").to_s("F")).to eql("9.0")
      expect { integers.call("999.9") }.to raise_error(Dry::Types::CoercionError, /precision 3/)
    end

    it "can be configured directly via .fixed" do
      rounded = type.fixed(precision: 8, scale: 2, rounding: :half_up)
      expect(rounded.call("12.345").to_s("F")).to eql("12.35")
    end
  end

  describe "invalid configuration" do
    it "rejects a negative precision" do
      expect { type.fixed(precision: -1) }.to raise_error(
        ArgumentError, /precision must be non-negative/
      )
    end

    it "rejects a scale larger than the precision" do
      expect { type.fixed(precision: 2, scale: 3) }.to raise_error(
        ArgumentError, /scale \(3\) cannot be greater than precision \(2\)/
      )
    end

    it "rejects non-integer dimensions" do
      expect { type.fixed(precision: "big") }.to raise_error(ArgumentError, /precision/)
    end
  end

  describe "#try" do
    subject(:money) { type.fixed(precision: 8, scale: 2) }

    it "returns a success for valid input" do
      result = money.try("12.34")
      expect(result).to be_success
      expect(result.input.to_s("F")).to eql("12.34")
    end

    it "returns a failure carrying the original input and a CoercionError" do
      result = money.try("12.345")
      expect(result).to be_failure
      expect(result.input).to eql("12.345")
      expect(result.error).to be_a(Dry::Types::CoercionError)
      expect(result.error.message).to include("cannot be represented with scale 2")
    end

    it "yields the failure to a block" do
      captured = nil
      money.try("12.345") { |result| captured = result }
      expect(captured).to be_failure
      expect(captured.input).to eql("12.345")
    end

    it "reports invalid floats through the same failure path" do
      result = money.try(1.23)
      expect(result).to be_failure
      expect(result.input).to be(1.23)
      expect(result.error.message).to include("Float")
    end
  end

  describe "#valid?" do
    subject(:money) { type.fixed(precision: 8, scale: 2) }

    it "is true for values that fit" do
      expect(money.valid?("12.34")).to be(true)
      expect(money.valid?(12)).to be(true)
    end

    it "is false for values that need rounding or overflow" do
      expect(money.valid?("12.345")).to be(false)
      expect(money.valid?("1000000")).to be(false)
      expect(money.valid?(1.23)).to be(false)
    end
  end

  describe "in a schema" do
    subject(:schema) { Dry::Types["hash"].schema(amount: money) }

    let(:money) { type.fixed(precision: 8, scale: 2) }

    it "coerces a valid amount" do
      result = schema.call(amount: "12.34")
      expect(result[:amount]).to eql(decimal("12.34"))
    end

    it "raises a SchemaError with the key and value for a bad amount" do
      expect { schema.call(amount: "12.345") }.to raise_error(
        an_instance_of(Dry::Types::SchemaError).and(
          having_attributes(
            key: :amount,
            value: "12.345",
            message: including("cannot be represented with scale 2")
          )
        )
      )
    end

    it "exposes a nested failure from #try" do
      result = schema.try(amount: "12.345")
      expect(result).to be_failure
      nested = result.error.meta[:amount]
      expect(nested).to be_failure
      expect(nested.input).to eql("12.345")
      expect(nested.error.message).to include("scale 2")
    end
  end

  describe "in an array" do
    subject(:list) { Dry::Types["array"].of(money) }

    let(:money) { type.fixed(precision: 8, scale: 2) }

    it "coerces every element" do
      expect(list.call(["12.34", 12, "0.5"])).to eql(
        [decimal("12.34"), decimal("12"), decimal("0.5")]
      )
    end

    it "fails when an element needs rounding" do
      result = list.try(["12.34", "12.345"])
      expect(result).to be_failure
      expect(result.error).to be_a(Dry::Types::CoercionError)
      expect(result.error.message).to include("12.345 cannot be represented with scale 2")
      expect(result.input).to eql([decimal("12.34"), "12.345"])
    end

    it "raises on unsafe call with a bad element" do
      expect { list.call(["not-a-decimal"]) }.to raise_error(
        Dry::Types::CoercionError, /is not a valid decimal string/
      )
    end
  end

  describe "lax behavior" do
    subject(:money) { type.fixed(precision: 8, scale: 2) }

    it "returns the original value when coercion fails" do
      expect(money.lax.call("12.345")).to eql("12.345")
    end

    it "still coerces valid values" do
      expect(money.lax.call("12.34").to_s("F")).to eql("12.34")
    end
  end

  describe "equality and introspection" do
    it "compares equal types by their configuration" do
      expect(type.fixed(precision: 8, scale: 2)).to eql(type.fixed(precision: 8, scale: 2))
    end

    it "distinguishes different rounding modes" do
      money = type.fixed(precision: 8, scale: 2)
      expect(money).not_to eql(money.with_rounding(:half_up))
    end

    it "distinguishes different float policies" do
      expect(type).not_to eql(type.accepting_float)
    end

    it "prints a readable representation" do
      money = type.fixed(precision: 8, scale: 2)
      expect(money.to_s).to eql(
        "#<Dry::Types[Decimal options={precision: 8, scale: 2}]>"
      )
    end

    it "round-trips through the AST compiler" do
      money = type.fixed(precision: 8, scale: 2).with_rounding(:half_up)
      compiler = Dry::Types::Compiler.new(Dry::Types.container)
      restored = compiler.(money.to_ast)
      expect(restored).to eql(money)
      expect(restored.call("12.345").to_s("F")).to eql("12.35")
    end

    it "infers BigDecimal as its primitive" do
      money = type.fixed(precision: 8, scale: 2)
      expect(Dry::Types::PrimitiveInferrer.new[money]).to eql([BigDecimal])
    end

    it "infers the decimal? predicate" do
      money = type.fixed(precision: 8, scale: 2)
      inferrer = Dry::Types::PredicateInferrer.new(Dry::Types.container)
      expect(inferrer[money]).to eql([{type?: BigDecimal}])
    end
  end
end
