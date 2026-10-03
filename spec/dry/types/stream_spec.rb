# frozen_string_literal: true

RSpec.describe Dry::Types::Stream do
  # Single-pass enumerable counting reads and recording #close calls
  counting_enumerable = Class.new do
    attr_reader :reads, :closes

    def initialize(values)
      @values = values
      @reads = 0
      @closes = 0
    end

    def each
      return enum_for(:each) unless block_given?

      @values.each do |value|
        @reads += 1
        yield value
      end
    end

    def close
      @closes += 1
    end
  end

  let(:source) { counting_enumerable.new(%w[1 2 3]) }

  let(:type) { Dry::Types["nominal.stream"].of(Dry::Types["coercible.integer"]) }

  describe ".of" do
    it "builds a member stream type" do
      expect(type).to be_a(Dry::Types::Stream::Member)
      expect(type.member).to eql(Dry::Types["coercible.integer"])
      expect(type.on_error).to be(:halt)
    end

    it "accepts a string member identifier" do
      stream = Dry::Types["nominal.stream"].of("coercible.integer")

      expect(stream.member).to eql(Dry::Types["coercible.integer"])
    end

    it "is available through the type specification syntax" do
      stream = Dry::Types["stream<coercible.integer>"]

      expect(stream).to be_a(Dry::Types::Stream::Member)
    end

    it "rejects unknown error strategies" do
      expect { Dry::Types["nominal.stream"].of(Dry::Types["integer"], on_error: :boom) }
        .to raise_error(ArgumentError, /boom/)
    end
  end

  describe "#call" do
    it "returns a lazy result without consuming the input" do
      result = type.call(source)

      expect(result).to be_a(Dry::Types::Stream::Result)
      expect(result).to be_pending
      expect(source.reads).to be(0)
    end

    it "converts members one by one as the result is iterated" do
      result = type.call(source)

      expect(result.take(2)).to eql([1, 2])
      expect(source.reads).to be(2)
      expect(result).to be_pending
    end

    it "continues iteration where the previous one stopped" do
      result = type.call(source)

      result.take(1)

      expect(result.to_a).to eql([2, 3])
      expect(result).to be_success
    end

    it "marks the result as successful once fully consumed" do
      result = type.call(source)

      expect(result.to_a).to eql([1, 2, 3])
      expect(result).to be_success
      expect(result.status).to be(:success)
      expect(source.reads).to be(3)
    end

    it "cannot be consumed twice" do
      result = type.call(source)
      result.to_a

      expect { result.each { |*| } }.to raise_error(Dry::Types::StreamConsumedError)
    end

    it "raises a coercion error for non-traversable input" do
      expect { type.call(42) }.to raise_error(Dry::Types::CoercionError, /42/)
    end

    it "yields to the block for non-traversable input" do
      expect(type.call(42) { :fallback }).to be(:fallback)
    end
  end

  describe "#valid?" do
    it "does not consume the input" do
      expect(type.valid?(source)).to be(true)
      expect(source.reads).to be(0)
    end

    it "returns false for non-traversable input" do
      expect(type.valid?(42)).to be(false)
    end
  end

  describe "#try" do
    it "returns a lazy success without consuming the input" do
      result = type.try(source)

      expect(result).to be_success
      expect(result.input).to be_a(Dry::Types::Stream::Result)
      expect(source.reads).to be(0)
    end

    it "returns a failure for non-traversable input" do
      expect(type.try(42)).to be_failure
    end

    it "yields the failure to the block" do
      expect(type.try(42) { |failure| "error: #{failure.error}" })
        .to match(/error: 42/)
    end
  end

  describe "#inspect" do
    it "prints the type without consuming anything" do
      expect(type.inspect).to eql(
        "#<Dry::Types[Stream<Constructor<Nominal<Integer> fn=Kernel.Integer>>]>"
      )
    end

    it "prints the error strategy when collecting" do
      collecting = Dry::Types["nominal.stream"].of(Dry::Types["integer"], on_error: :collect)

      expect(collecting.inspect).to include("on_error: :collect")
    end

    it "prints the result status without consuming the input" do
      result = type.call(source)

      expect(result.inspect).to eql("#<Dry::Types::Stream::Result status=pending index=0>")
      expect(source.reads).to be(0)
    end
  end

  describe "halt error strategy" do
    let(:type) { Dry::Types["nominal.stream"].of(Dry::Types["strict.integer"]) }

    let(:source) { counting_enumerable.new([1, "x", 3]) }

    it "raises on the first failing member and records its index" do
      result = type.call(source)

      expect { result.each { |*| } }.to raise_error(Dry::Types::CoercionError, /"x"/)

      expect(result).to be_failure
      expect(result.failure_index).to be(1)
      expect(result.error).to be_a(Dry::Types::CoercionError)
      expect(source.reads).to be(2)
    end

    it "terminates the stream after a failure" do
      result = type.call(source)

      expect { result.each { |*| } }.to raise_error(Dry::Types::CoercionError)
      expect { result.each { |*| } }.to raise_error(Dry::Types::StreamConsumedError, /index 1/)
    end
  end

  describe "collect error strategy" do
    let(:type) do
      Dry::Types["nominal.stream"].of(Dry::Types["strict.integer"], on_error: :collect)
    end

    let(:source) { counting_enumerable.new([1, "x", 3]) }

    it "yields indexed result items instead of raising" do
      items = type.call(source).to_a

      expect(items.map(&:index)).to eql([0, 1, 2])
      expect(items.map(&:success?)).to eql([true, false, true])
      expect(items[0].value).to be(1)
      expect(items[1].value).to be(Dry::Core::Constants::Undefined)
      expect(items[1].error).to be_a(Dry::Types::CoercionError)
      expect(items[2].value).to be(3)
    end

    it "keeps consuming past failures and reports the first failing index" do
      result = type.call(source)
      result.to_a

      expect(source.reads).to be(3)
      expect(result).to be_failure
      expect(result.failure_index).to be(1)
      expect(result.error).to be_a(Dry::Types::CoercionError)
    end

    it "reports success when every member converts" do
      result = type.call(counting_enumerable.new([1, 2, 3]))
      items = result.to_a

      expect(items).to all(be_success)
      expect(result).to be_success
      expect(result.failure_index).to be_nil
    end
  end

  describe "#close" do
    it "closes the underlying source when stopping early" do
      result = type.call(source)
      result.take(1)

      result.close

      expect(source.closes).to be(1)
      expect(result).to be_closed
      expect(result).to be_pending
    end

    it "is idempotent" do
      result = type.call(source)

      result.close
      result.close

      expect(source.closes).to be(1)
    end

    it "prevents further iteration" do
      result = type.call(source)
      result.close

      expect { result.each { |*| } }.to raise_error(Dry::Types::StreamClosedError)
    end

    it "works with sources that do not respond to #close" do
      result = type.call([1, 2, 3].each)
      result.take(1)

      expect(result.close).to be(result)
      expect(result).to be_closed
    end
  end

  describe "Array.of" do
    it "keeps its eager semantics" do
      array = Dry::Types["nominal.array"].of(Dry::Types["coercible.integer"])

      expect(array.(%w[1 2 3])).to eql([1, 2, 3])
    end
  end

  describe "#to_ast" do
    it "round-trips through the compiler" do
      collecting = Dry::Types["nominal.stream"].of(Dry::Types["integer"], on_error: :collect)
      rebuilt = Dry::Types::Compiler.new(Dry::Types).(collecting.to_ast)

      expect(rebuilt).to be_a(Dry::Types::Stream::Member)
      expect(rebuilt.on_error).to be(:collect)
      expect(rebuilt.member).to eql(Dry::Types["integer"])
    end
  end
end
