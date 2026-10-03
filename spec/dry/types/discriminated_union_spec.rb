# frozen_string_literal: true

RSpec.describe Dry::Types::DiscriminatedUnion do
  module Types
    include Dry.Types()
  end

  subject(:type) do
    Types.DiscriminatedUnion(:kind, mapping)
  end

  let(:created_type) { Types::Hash.schema(name: Types::String) }
  let(:updated_type) do
    Types::Hash.schema(name: Types::String, at: Types::String)
  end

  let(:mapping) do
    {"created" => created_type, "updated" => updated_type}
  end

  it_behaves_like "Dry::Types::Nominal without primitive" do
    subject(:type) do
      Types.DiscriminatedUnion(:kind, {"created" => created_type})
    end
  end

  it_behaves_like "a composable constructor"

  it "is frozen" do
    expect(type).to be_frozen
  end

  describe "#call" do
    it "dispatches to the branch matching the tag" do
      expect(type.(kind: "created", name: "a")).to eql(name: "a")
      expect(type.(kind: "updated", name: "a", at: "t")).to eql(name: "a", at: "t")
    end

    it "does not try non-matching branches" do
      expect {
        type.(kind: "created", name: "a", at: "bogus")
      }.not_to raise_error
    end

    it "raises on an unknown tag" do
      expect {
        type.(kind: "deleted", name: "a")
      }.to raise_error(
        Dry::Types::UnknownTagError,
        /unknown discriminator tag "deleted" at :kind/
      )
    end

    it "raises on a missing tag" do
      expect { type.(name: "a") }.to raise_error(
        Dry::Types::MissingTagError,
        /discriminator tag :kind is missing/
      )
    end

    it "raises on a tag of invalid type" do
      expect { type.(kind: 1, name: "a") }.to raise_error(
        Dry::Types::InvalidTagError,
        /discriminator tag at :kind has invalid type Integer/
      )
    end

    it "raises when the input is not a hash" do
      expect { type.("not a hash") }.to raise_error(Dry::Types::MissingTagError)
    end

    it "yields on tag failures in safe mode" do
      expect(type.({kind: "deleted"}) { :fallback }).to be(:fallback)
      expect(type.(name: "a") { :fallback }).to be(:fallback)
    end

    it "does not swallow branch failures in safe mode" do
      expect(type.(kind: "created", name: 1) { :fallback }).to be(:fallback)
    end

    it "re-raises discriminator errors without a block" do
      expect { type.call_safe(kind: "deleted") }.to raise_error(Dry::Types::UnknownTagError)
    end
  end

  describe "#try" do
    it "returns a success for a matching tag" do
      result = type.try(kind: "created", name: "a")

      expect(result).to be_success
      expect(result.input).to eql(name: "a")
    end

    it "returns a failure for an unknown tag without touching branches" do
      result = type.try(kind: "deleted")

      expect(result).to be_failure
      expect(result.error).to be_a(Dry::Types::UnknownTagError)
    end

    it "returns a failure for a missing tag" do
      expect(type.try(name: "a").error).to be_a(Dry::Types::MissingTagError)
    end

    it "returns a failure for a mistyped tag" do
      expect(type.try(kind: nil).error).to be_a(Dry::Types::InvalidTagError)
    end

    it "yields the failure when a block is given" do
      result = type.try(kind: "deleted") { |failure| "got #{failure.error.class}" }

      expect(result).to eql("got Dry::Types::UnknownTagError")
    end

    it "delegates branch-level failures to the selected branch" do
      result = type.try(kind: "created", name: 1)

      expect(result).to be_failure
      expect(result.error).to be_a(Dry::Types::CoercionError)
    end
  end

  describe "#===" do
    it "matches only inputs whose selected branch accepts the value" do
      expect(type).to be === {kind: "created", name: "a"}
      expect(type).not_to be === {kind: "deleted"}
      expect(type).not_to be === {kind: "created", name: 1}
    end
  end

  describe "nested tag paths" do
    subject(:type) do
      Types.DiscriminatedUnion([:metadata, :type], {"created" => created_type})
    end

    it "reads the tag from the nested path" do
      expect(type.(metadata: {type: "created"}, name: "a")).to eql(name: "a")
    end

    it "reports the full path when a segment is missing" do
      expect { type.(metadata: {}) }.to raise_error(
        Dry::Types::MissingTagError,
        /:metadata -> :type/
      )
    end

    it "reports a missing tag when an intermediate value is not a hash" do
      expect { type.(metadata: "nope") }.to raise_error(Dry::Types::MissingTagError)
    end

    it "supports string segments" do
      nested = Types.DiscriminatedUnion(
        ["metadata", "type"],
        {"created" => Dry::Types["strict.hash"]}
      )

      expect(
        nested.("metadata" => {"type" => "created"}, "name" => "a")
      ).to eql("metadata" => {"type" => "created"}, "name" => "a")
    end
  end

  describe "explicit tag_transform" do
    subject(:type) do
      Types.DiscriminatedUnion(
        :kind,
        {created: created_type},
        tag_transform: :to_sym.to_proc
      )
    end

    it "applies the transform before looking up the branch" do
      expect(type.(kind: "created", name: "a")).to eql(name: "a")
    end

    it "normalizes declared tag values as well" do
      expect(type.tags).to eql([:created])
    end

    it "raises when the transform returns a non-tag value" do
      expect {
        Types.DiscriminatedUnion(
          :kind,
          {created: created_type},
          tag_transform: ->(_value) { 5 }
        )
      }.to raise_error(ArgumentError, /tag_transform must return a Symbol or a String/)
    end

    it "does not transform tags implicitly" do
      strict = Types.DiscriminatedUnion(:kind, {created: created_type})

      expect { strict.(kind: "created") }.to raise_error(Dry::Types::UnknownTagError)
    end
  end

  describe "definition-time validation" do
    it "fails on duplicate tag values after transform" do
      expect {
        Types.DiscriminatedUnion(
          :kind,
          {:created => created_type, "created" => updated_type},
          tag_transform: :to_s.to_proc
        )
      }.to raise_error(ArgumentError, /duplicate discriminator tag/)
    end

    it "fails on non-symbol/string tags" do
      expect {
        Types.DiscriminatedUnion(:kind, {1 => created_type})
      }.to raise_error(ArgumentError, /tag values must be Symbols or Strings/)
    end

    it "fails when a branch is not a type" do
      expect {
        Types.DiscriminatedUnion(:kind, {created: :not_a_type})
      }.to raise_error(ArgumentError, /must be a Dry::Types type/) do |error|
        # :not_a_type resolves to a symbol in this context
        expect(error.message).not_to be_nil
      end
    end

    it "fails on an empty mapping" do
      expect {
        Types.DiscriminatedUnion(:kind, {})
      }.to raise_error(ArgumentError, /non-empty Hash/)
    end

    it "fails on an invalid tag path" do
      expect {
        Types.DiscriminatedUnion([:kind, 1], {created: created_type})
      }.to raise_error(ArgumentError, /tag path segments must be Symbols or Strings/)
    end
  end

  describe "side effects" do
    it "runs only the selected branch constructor and never the others" do
      calls = Hash.new(0)

      build_branch = lambda { |tag|
        Types::Hash.schema(name: Types::String).constructor { |input|
          calls[tag] += 1
          input
        }
      }

      tagged = Types.DiscriminatedUnion(:kind, {
        a: build_branch.call(:a),
        b: build_branch.call(:b)
      })

      tagged.(kind: :a, name: "x")
      tagged.try(kind: :b, name: "y")
      tagged.try(kind: :unknown)

      expect(calls).to eql(a: 1, b: 1)
    end

    it "does not evaluate branch default values before branch selection" do
      default_evaluations = Hash.new(0)

      build_branch = lambda { |name|
        default_type = Types::String.default(proc { "x" }).constructor { |value|
          default_evaluations[name] += 1
          value
        }
        Types::Hash.schema(name: default_type)
      }

      tagged = Types.DiscriminatedUnion(:kind, {
        a: build_branch.call(:a),
        b: build_branch.call(:b)
      })

      tagged.try(kind: :unknown)
      tagged.(kind: :a)

      expect(default_evaluations).to eql(a: 1)
    end
  end

  describe "#branch_for" do
    it "returns the branch type without applying it" do
      expect(type.branch_for(kind: "created")).to be(created_type)
      expect(type.branch_for(kind: "updated")).to be(updated_type)
    end
  end

  describe "#to_ast and round-trip" do
    it "dumps the union to a discriminated_union AST node" do
      ast = type.to_ast

      expect(ast[0]).to be(:discriminated_union)
      expect(ast[1][0]).to eql([:kind])
      expect(ast[1][1].map(&:first)).to eql(%w[created updated])
    end

    it "round-trips through the compiler preserving dispatch" do
      compiler = Dry::Types::Compiler.new(Dry::Types)
      restored = compiler.(type.to_ast)

      expect(restored).to eql(type)
      expect(restored.(kind: "created", name: "a")).to eql(name: "a")

      expect { restored.(kind: "deleted") }.to raise_error(Dry::Types::UnknownTagError)
      expect { restored.(name: "a") }.to raise_error(Dry::Types::MissingTagError)
    end

    it "round-trips nested paths and meta" do
      nested = Types.DiscriminatedUnion(
        [:metadata, :type],
        {created: created_type}
      ).meta(source: :webhook)

      compiler = Dry::Types::Compiler.new(Dry::Types)
      restored = compiler.(nested.to_ast)

      expect(restored).to eql(nested)
      expect(restored.tag_path).to eql(%i[metadata type])
      expect(restored.meta).to eql(source: :webhook)
      expect(restored.(metadata: {type: :created}, name: "a")).to eql(name: "a")
    end

    it "round-trips the explicit tag transform" do
      tagged = Types.DiscriminatedUnion(
        :kind,
        {created: created_type},
        tag_transform: :to_sym.to_proc
      )

      compiler = Dry::Types::Compiler.new(Dry::Types)
      restored = compiler.(tagged.to_ast)

      expect(restored.(kind: "created", name: "a")).to eql(name: "a")
    end

    it "round-trips a method-object tag transform" do
      coercer = Object.new
      def coercer.coerce(tag) = tag.to_s

      tagged = Types.DiscriminatedUnion(
        :kind,
        {"created" => created_type},
        tag_transform: coercer.method(:coerce)
      )

      compiler = Dry::Types::Compiler.new(Dry::Types)
      restored = compiler.(tagged.to_ast)

      expect(restored.(kind: :created, name: "a")).to eql(name: "a")
    end

    it "preserves dispatch and side effects after an AST round-trip" do
      calls = Hash.new(0)

      counting = created_type.constructor { |input|
        calls[:created] += 1
        input
      }

      tagged = Types.DiscriminatedUnion(:kind, {
        "created" => counting,
        "updated" => updated_type
      })

      restored = Dry::Types::Compiler.new(Dry::Types).(tagged.to_ast)

      restored.(kind: "created", name: "a")
      restored.try(kind: "updated", name: "a", at: "t")
      restored.try(kind: :missing)

      expect(calls).to eql(created: 1)
    end
  end

  describe "#to_s" do
    it "prints the tag path and branches" do
      expect(type.to_s).to start_with(
        "#<Dry::Types[DiscriminatedUnion<tag=:kind branches={"
      )
    end
  end

  describe "composition" do
    it "stays a plain Sum when composed with |" do
      sum = type | Types::String

      expect(sum).to be_a(Dry::Types::Sum)
      expect(sum.("plain string")).to eql("plain string")
    end
  end
end
