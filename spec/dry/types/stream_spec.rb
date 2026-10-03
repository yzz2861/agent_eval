# frozen_string_literal: true

RSpec.describe Dry::Types::Stream do
  subject(:stream) do
    Dry::Types["nominal.stream"].of(Dry::Types["coercible.integer"])
  end

  let(:source_class) do
    Class.new(Enumerator) do
      attr_reader :reads, :close_count

      def initialize(values)
        @values = values
        @index = 0
        @reads = 0
        @close_count = 0

        super() do |yielder|
          while @index < @values.length
            value = @values.fetch(@index)
            @index += 1
            @reads += 1
            yielder << value
          end
        end
      end

      def close
        @close_count += 1
      end
    end
  end

  describe "#of" do
    it "converts members lazily as the result is consumed" do
      source = source_class.new(%w[1 2 3])
      result = stream.(source)

      expect(source.reads).to be(0)
      expect(result).to be_pending

      expect(result.first).to be(1)
      expect(source.reads).to be(1)
    end

    it "can consume the entire stream successfully" do
      source = source_class.new(%w[1 2 3])
      result = stream.(source)

      expect(result.to_a).to eql([1, 2, 3])
      expect(result).to be_succeeded
      expect(source.reads).to be(3)
      expect(source.close_count).to be(0)
    end

    it "preserves a single traversal when iteration resumes after an early stop" do
      source = source_class.new(%w[1 2 3 4])
      result = stream.(source)

      values = []
      result.each do |value|
        values << value
        break if value == 2
      end
      result.each { |value| values << value }

      expect(values).to eql([1, 2, 3, 4])
      expect(source.reads).to be(4)
      expect(result).to be_succeeded
    end

    it "closes the source when the caller stops before the stream is consumed" do
      source = source_class.new(%w[1 2 3])
      result = stream.(source)

      result.first
      result.close

      expect(result).to be_closed
      expect(source.close_count).to be(1)
      expect(source.reads).to be(1)
    end

    it "stops at the first failing member in raise mode" do
      source = source_class.new(["1", "bad", "3"])
      result = stream.(source)

      expect { result.to_a }.to raise_error(Dry::Types::CoercionError)
      expect(result).to be_failed
      expect(result.failure_index).to be(1)
      expect(result.error).to be_a(Dry::Types::CoercionError)
      expect(source.reads).to be(2)
    end

    it "does not resume after a failure in raise mode" do
      source = source_class.new(["1", "bad", "3"])
      result = stream.(source)

      expect { result.to_a }.to raise_error(Dry::Types::CoercionError)
      expect { result.to_a }.to raise_error(Dry::Types::CoercionError)
      expect(source.reads).to be(2)
    end

    it "uses the failure returned by a strict member type" do
      strict_stream = Dry::Types["nominal.stream"].of(
        Dry::Types["strict.integer"],
        on_error: :continue
      )
      source = source_class.new([1, "bad", 3])
      result = strict_stream.(source)

      items = result.to_a

      expect(items[1].error).to be_a(Dry::Types::ConstraintError)
      expect(result.failure_index).to be(1)
      expect(source.reads).to be(3)
    end

    it "continues and yields indexed result items in continue mode" do
      continuing = stream.of(Dry::Types["coercible.integer"], on_error: :continue)
      source = source_class.new(["1", "bad", "3"])
      result = continuing.(source)

      items = result.to_a

      expect(items.map(&:index)).to eql([0, 1, 2])
      expect(items.select(&:success?).map(&:value)).to eql([1, 3])
      expect(items[1]).to be_failure
      expect(items[1].value).to eql("bad")
      expect(result).to be_failed
      expect(result.failure_indices).to eql([1])
      expect(source.reads).to be(3)
    end

    it "keeps index positions after undefined members are omitted" do
      member = Dry::Types["nominal.string"].constructor do |value|
        if value == "skip"
          Dry::Types::Undefined
        else
          value
        end
      end
      source = source_class.new(["a", "skip", "b"])
      result = stream.of(member, on_error: :continue).(source)

      items = result.to_a

      expect(items.map(&:index)).to eql([0, 2])
      expect(items.map(&:value)).to eql(%w[a b])
      expect(result).to be_succeeded
    end

    it "does not consume the stream during inspect or valid?" do
      source = source_class.new(%w[1 bad])
      result = stream.(source)

      expect(result.inspect).to include("status=pending")
      expect(stream.inspect).to include("Stream")
      expect(stream.valid?(source)).to be(true)
      expect(source.reads).to be(0)
      expect(result).to be_pending
    end
  end

  describe "input wrapping" do
    it "accepts Enumerator::Lazy" do
      result = stream.((1..3).lazy.map(&:to_s))

      expect(result).to be_pending
      expect(result.first(2)).to eql([1, 2])
      expect(result).to be_pending
    end

    it "reports non-enumerator input without consuming it" do
      failure = stream.try(%w[1 2])

      expect(failure).to be_failure
      expect { stream.([]) }.to raise_error(Dry::Types::CoercionError)
      expect(stream).not_to be_valid([])
      expect(stream).to be_valid([].to_enum)
    end

    it "is built independently from eager arrays" do
      array = Dry::Types["array"].of(Dry::Types["coercible.integer"])

      expect(array.call(["1", "2"])).to eql([1, 2])
      expect(Dry::Types["nominal.array"]).to be_a(Dry::Types::Nominal)
      expect(stream).to be_a(described_class::Member)
    end

    it "preserves the lazy result through a constructor" do
      constructed = stream.constructor(&:to_enum)
      source = source_class.new(%w[1 2 3])
      result = constructed.(source)

      expect(result).to be_pending
      expect(result.first).to be(1)
      expect(source.reads).to be(1)
    end
  end

  describe "registration and printing" do
    it "is available through a module builder" do
      mod = Dry.Types(default: :strict)

      built = mod.Stream(mod::Integer)

      expect(built).to be_a(Dry::Types::Constrained)
      expect(built.type).to be_a(described_class::Member)
    end

    it "prints without streaming" do
      expect(stream.to_s).to eql(
        "#<Dry::Types[Stream<Constructor<Nominal<Integer> fn=Kernel.Integer>" \
        " options={on_error: :raise}>]>"
      )
    end

    it "preserves the error mode through AST compilation" do
      continuing = stream.of(Dry::Types["coercible.integer"], on_error: :continue)
      compiler = Dry::Types::Compiler.new(Dry::Types)

      expect(compiler.(continuing.to_ast).on_error).to be(:continue)
    end

    it "preserves the error mode when members are relaxed" do
      continuing = stream.of(Dry::Types["coercible.integer"], on_error: :continue)

      expect(continuing.lax.type.on_error).to be(:continue)
    end
  end
end
