# frozen_string_literal: true

RSpec.describe Dry::Types::DiscriminatedUnion do
  subject(:type) { described_class.new(:kind, branches) }

  let(:types) { Dry.Types() }

  let(:left_constructors) { Hash.new(0) }
  let(:right_constructors) { Hash.new(0) }
  let(:left_defaults) { Hash.new(0) }
  let(:right_defaults) { Hash.new(0) }

  let(:left_schema) do
    Dry::Types["hash"].schema(
      kind: Dry::Types["strict.string"],
      value: Dry::Types["nominal.string"].default do
        left_defaults[:value] += 1
        "left"
      end
    ).constructor do |input|
      left_constructors[:branch] += 1
      input
    end
  end

  let(:right_schema) do
    Dry::Types["hash"].schema(
      kind: Dry::Types["strict.string"],
      value: Dry::Types["nominal.string"].default do
        right_defaults[:value] += 1
        "right"
      end
    ).constructor do |input|
      right_constructors[:branch] += 1
      input
    end
  end

  let(:branches) do
    {
      "left" => left_schema,
      "right" => right_schema
    }
  end

  describe "branch selection" do
    it "calls only the constructor and default value of the selected branch" do
      expect(type.(kind: "left")).to eql(kind: "left", value: "left")

      expect(left_constructors).to eql(branch: 1)
      expect(right_constructors).to be_empty
      expect(left_defaults).to eql(value: 1)
      expect(right_defaults).to be_empty
    end

    it "keeps choosing branches by tag on subsequent calls" do
      expect(type.(kind: "right")).to eql(kind: "right", value: "right")
      expect(type.(kind: "left")).to eql(kind: "left", value: "left")

      expect(left_constructors).to eql(branch: 1)
      expect(right_constructors).to eql(branch: 1)
      expect(left_defaults).to eql(value: 1)
      expect(right_defaults).to eql(value: 1)
    end

    it "does not evaluate branch constructors or defaults before selecting a branch" do
      expect { type.(kind: "unknown") }.to raise_error(Dry::Types::UnknownTagError)
      expect { type.({}) }.to raise_error(Dry::Types::MissingTagError)

      expect(left_constructors).to be_empty
      expect(right_constructors).to be_empty
      expect(left_defaults).to be_empty
      expect(right_defaults).to be_empty
    end
  end

  describe "tag errors" do
    it "reports a missing tag" do
      result = type.try({})

      expect(result).to be_failure
      expect(result.error).to be_a(Dry::Types::MissingTagError)
      expect(result.error.path).to eql([:kind])
    end

    it "reports an unknown tag when its type matches a defined tag type" do
      expect { type.(kind: "deleted") }.to raise_error(
        Dry::Types::UnknownTagError, /unknown tag "deleted"/m
      )
    end

    it "reports a tag type error without trying branches" do
      result = type.try(kind: 1)

      expect(result).to be_failure
      expect(result.error).to be_a(Dry::Types::InvalidTagError)
      expect(left_constructors).to be_empty
      expect(right_constructors).to be_empty
    end

    it "reports a non-hash input as a tag type error" do
      expect { type.("webhook") }.to raise_error(Dry::Types::InvalidTagError)
    end

    it "returns false for invalid tags without calling branches" do
      expect(type).not_to be === {}
      expect(left_constructors).to be_empty
      expect(right_constructors).to be_empty
    end
  end

  describe "nested tag path" do
    subject(:type) do
      described_class.new(%i[event type], branches)
    end

    before do
      event_schema = Dry::Types["hash"].schema(
        type: Dry::Types["strict.string"]
      )
      branches["created"] = Dry::Types["hash"].schema(
        event: event_schema,
        value: Dry::Types["nominal.string"].default {
          left_defaults[:event_value] = 1 unless left_defaults.key?(:event_value)
          "left"
        }
      ).constructor do |input|
        left_constructors[:nested] = 1
        input
      end
    end

    it "selects a branch from a fixed nested path" do
      expect(type.(event: {type: "created"})).to eql(
        event: {type: "created"}, value: "left"
      )
      expect(right_constructors).to be_empty
    end

    it "reports a missing nested tag" do
      expect { type.(event: {}) }.to raise_error(Dry::Types::MissingTagError)
    end

    it "reports an invalid nested path" do
      expect { type.(event: "webhook") }.to raise_error(Dry::Types::InvalidTagError)
    end
  end

  describe "tag conversion" do
    subject(:type) do
      described_class.new(:kind, {
        created: left_schema,
        updated: right_schema
      }, tag_transform: :to_sym)
    end

    it "uses an explicit conversion rule" do
      expect(type.(kind: "created")).to eql(kind: "created", value: "left")
      expect(right_constructors).to be_empty
    end

    context "without a conversion rule" do
      subject(:type) { described_class.new(:kind, created: left_schema) }

      it "reports a type mismatch instead of implicitly coercing the tag" do
        expect { type.(kind: "created") }.to raise_error(Dry::Types::InvalidTagError)
        expect(left_constructors).to be_empty
      end
    end

    it "accepts a callable conversion rule" do
      callable_type = described_class.new(
        :kind,
        {"created" => left_schema},
        tag_transform: ->(tag) { tag.to_sym.to_s }
      )

      expect(callable_type.(kind: "created")).to eql(
        kind: "created", value: "left"
      )
    end
  end

  describe "definition" do
    it "rejects duplicate tags" do
      expect {
        described_class.new(:kind, [
          ["left", left_schema],
          ["left", right_schema]
        ])
      }.to raise_error(::ArgumentError, 'duplicate tag "left"')
    end

    it "rejects values that are not types" do
      expect {
        described_class.new(:kind, "left" => ->(input) { input })
      }.to raise_error(::ArgumentError, /must be a Dry::Types type/)
    end
  end

  describe "builder" do
    it "defaults the tag path to kind" do
      type = types.DiscriminatedUnion("left" => left_schema)

      expect(type.tag_path).to eql([:kind])
      expect(type.(kind: "left")).to eql(kind: "left", value: "left")
    end

    it "accepts an explicit positional tag with keyword branches" do
      type = types.DiscriminatedUnion(:kind, "left" => left_schema)

      expect(type.tag_path).to eql([:kind])
      expect(type.(kind: "left")).to eql(kind: "left", value: "left")
    end

    it "accepts an explicit path and callable tag conversion" do
      event_schema = Dry::Types["hash"].schema(
        type: Dry::Types["strict.string"]
      )
      branch = Dry::Types["hash"].schema(event: event_schema)
      type = types.DiscriminatedUnion(
        {created: branch},
        path: %i[event type],
        tag_transform: :to_sym
      )

      expect(type.(event: {type: "created"})).to eql(
        event: {type: "created"}
      )
    end
  end

  describe "AST" do
    let(:left_calls) { Hash.new(0) }
    let(:right_calls) { Hash.new(0) }

    let(:roundtrip_left) do
      Dry::Types["hash"].schema(
        event: Dry::Types["hash"].schema(type: Dry::Types["strict.string"]),
        value: Dry::Types["strict.string"]
      ).constructor do |input|
        left_calls[:branch] += 1
        input
      end
    end

    let(:roundtrip_right) do
      Dry::Types["hash"].schema(
        event: Dry::Types["hash"].schema(type: Dry::Types["strict.string"]),
        value: Dry::Types["strict.string"]
      ).constructor do |input|
        right_calls[:branch] += 1
        input
      end
    end

    let(:type) do
      described_class.new(%i[event type], {
        "created" => roundtrip_left,
        "updated" => roundtrip_right
      })
    end

    it "preserves selection after an AST round-trip" do
      ast = type.to_ast
      restored = Dry::Types::Compiler.new(Dry::Types).(ast)

      expect(restored.to_ast).to eql(ast)

      expect(restored.(event: {type: "created"}, value: "yes")).to eql(
        event: {type: "created"}, value: "yes"
      )
      expect(restored.(event: {type: "updated"}, value: "yes")).to eql(
        event: {type: "updated"}, value: "yes"
      )

      expect(left_calls).to eql(branch: 1)
      expect(right_calls).to eql(branch: 1)
    end

    it "preserves a callable tag transform after an AST round-trip" do
      kind_left = Dry::Types["hash"].schema(
        kind: Dry::Types["strict.string"],
        value: Dry::Types["strict.string"]
      ).constructor { |input| left_calls[:kind] += 1; input }
      kind_right = Dry::Types["hash"].schema(
        kind: Dry::Types["strict.string"],
        value: Dry::Types["strict.string"]
      ).constructor { |input| right_calls[:kind] += 1; input }

      callable_type = described_class.new(
        :kind,
        {
          "created" => kind_left,
          "updated" => kind_right
        },
        tag_transform: ->(tag) { tag }
      )
      ast = callable_type.to_ast
      restored = Dry::Types::Compiler.new(Dry::Types).(ast)

      expect(restored.to_ast).to eql(ast)
      expect(restored.(kind: "created", value: "yes")).to eql(
        kind: "created", value: "yes"
      )
      expect(left_calls).to eql(kind: 1)
    end
  end

  describe "ordinary sum" do
    it "keeps trying branches from left to right" do
      calls = Hash.new(0)
      left = Dry::Types["strict.integer"].constructor { |input| calls[:left] += 1; input }
      right = Dry::Types["strict.string"].constructor { |input| calls[:right] += 1; input }

      expect((left | right).("ok")).to eql("ok")
      expect(calls).to eql(left: 1, right: 1)
    end
  end
end
