# frozen_string_literal: true

RSpec.describe Dry::Types::Decimal do
  subject(:type) { described_class.new(5, 2) }

  def failure_for(value, target = type)
    result = target.try(value)
    expect(result).to be_failure
    result.error
  end

  describe "construction" do
    it "accepts keyword arguments" do
      expect(described_class.new(precision: 6, scale: 3)).to eql(described_class[6, 3])
    end

    it "defaults scale to zero" do
      expect(described_class.new(5).scale).to be(0)
    end

    it "rejects invalid precision and scale" do
      expect { described_class.new(0, 0) }.to raise_error(ArgumentError, /precision/)
      expect { described_class.new(2, 3) }.to raise_error(ArgumentError, /scale/)
    end

    it "accepts scale zero" do
      expect(described_class.new(3, 0)["12"]).to eql(BigDecimal("12"))
    end

    it "rejects unknown rounding modes" do
      expect { described_class.new(5, 2, rounding: :banker_s) }
        .to raise_error(ArgumentError, /unsupported rounding/)
    end

    it "supports float option updates" do
      explicit = described_class.new(5, 2, accept_float: true)
      expect(explicit.with(accept_float: false).accept_float?).to be(false)
    end

    it "can be built through Dry.Types()" do
      module TestDecimal
        include Dry.Types()
      end

      expect(TestDecimal.Decimal(5, 2)).to eql(Dry::Types.Decimal(5, 2))
    end
  end

  describe "exact values" do
    it "accepts strings, integers, and BigDecimal values" do
      expect(type["123.45"]).to eql(BigDecimal("123.45"))
      expect(type[123]).to eql(BigDecimal("123.00"))
      expect(type[BigDecimal("123.4")]).to eql(BigDecimal("123.40"))
    end

    it "accepts and normalizes scientific notation and negative zero" do
      expect(type["1.2345e2"]).to eql(BigDecimal("123.45"))
      expect(type["-0.00"]).to eql(BigDecimal("0.00"))
      expect(type[BigDecimal("-0.00")]).to eql(BigDecimal("0"))
      expect(described_class.new(3, 0)[BigDecimal("-0")]).to eql(BigDecimal("0"))
    end

    it "accepts trailing zero fractional digits without rounding" do
      expect(type["1.200"]).to eql(BigDecimal("1.20"))
    end

    it "rejects values that require rounding by default" do
      expect(failure_for("123.456").message)
        .to include("has more than 2 decimal digits")
      expect(failure_for(BigDecimal("123.456")).message)
        .to include("has more than 2 decimal digits")
    end

    it "checks precision after carrying" do
      expect(described_class.new(5, 2, rounding: :half_up)["99.999"])
        .to eql(BigDecimal("100.00"))

      expect {
        described_class.new(4, 2, rounding: :half_up)["999.999"]
      }.to raise_error(Dry::Types::CoercionError, /999\.999.*exceeds precision 4/m)
    end
  end

  describe "rounding" do
    subject(:type) { described_class.new(5, 2, rounding: :half_up) }

    it "rounds fractional values with the explicitly selected mode" do
      expect(type["123.456"]).to eql(BigDecimal("123.46"))
      expect(type["123.454"]).to eql(BigDecimal("123.45"))
    end

    it "accepts a BigDecimal rounding constant" do
      constant_type = described_class.new(5, 2, rounding: BigDecimal::ROUND_DOWN)
      expect(constant_type["123.459"]).to eql(BigDecimal("123.45"))
    end
  end

  describe "floats" do
    it "rejects Float by default" do
      expect(failure_for(3.12).message).to include("Float values are not accepted")
    end

    context "when accepted" do
      subject(:type) { described_class.new(16, 2, accept_float: true) }

      it "accepts a float whose exact expansion fits" do
        expect(type[1.5]).to eql(BigDecimal("1.50"))
      end

      it "does not hide binary precision errors" do
        expect(failure_for(3.12).message)
          .to include("has more than 2 decimal digits")
      end

      it "rounds only when a rounding mode is configured" do
        rounded = described_class.new(16, 2, accept_float: true, rounding: :half_up)
        expect(rounded[3.12]).to eql(BigDecimal("3.12"))
      end

      it "rejects NaN and Infinity" do
        expect(failure_for(Float::NAN).message).to include("must be finite")
        expect(failure_for(Float::INFINITY).message).to include("must be finite")
        expect(failure_for(-Float::INFINITY).message).to include("must be finite")
      end
    end
  end

  describe "invalid input" do
    %w[foo NaN Infinity -Infinity 1_23 " 1.23" 1.2.3 1.].each do |value|
      it "rejects #{value.inspect}" do
        expect(failure_for(value).message).to include("is not a valid decimal string")
      end
    end

    [nil, true, :"1.23", Object.new].each do |value|
      it "rejects #{value.class}" do
        expect(failure_for(value).message)
          .to include("must be a String, Integer, BigDecimal, or Float")
      end
    end
  end

  describe "integration" do
    it "has a readable inspection and round-trips through AST" do
      expect(type.inspect).to include("Decimal(5, 2, rounding: nil, accept_float: false)")
      expect(Dry::Types::Decimal(5, 2, rounding: :half_up).inspect)
        .to include("rounding: :half_up")

      compiler = Dry::Types::Compiler.new(Dry::Types.container)
      expect(compiler.(type.to_ast)).to eql(type)
    end

    it "infers BigDecimal as the primitive" do
      expect(Dry::Types::PredicateInferrer.new[type]).to eql([:decimal?])
      expect(Dry::Types::PrimitiveInferrer.new[type]).to eql([BigDecimal])
    end
  end

  describe "error paths" do
    it "supports safe call and try" do
      result = type.try("1.234")
      expect(result).to be_failure
      expect(result.input).to eql("1.234")
      expect(type.call("1.234") { |value| value }).to eql("1.234")
    end

    it "keeps schema key errors" do
      schema = Dry::Types["hash"].schema(amount: type)
      result = schema.try(amount: "1.234")

      expect(result).to be_failure
      expect(result.error.meta[:amount].error.message)
        .to include("has more than 2 decimal digits")

      expect { schema.call(amount: "1.234") }
        .to raise_error(Dry::Types::SchemaError, /:amount/)
    end

    it "keeps array member errors" do
      array = Dry::Types["array"].of(type)
      result = array.try(["1.23", "1.234"])

      expect(result).to be_failure
      expect(result.error.message).to include("has more than 2 decimal digits")
    end
  end
end
