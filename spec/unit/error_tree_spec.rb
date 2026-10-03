# frozen_string_literal: true

RSpec.describe(Dry::Monads::ErrorTree) do
  subject(:tree) { described_class.new(errors) }

  let(:errors) do
    {
      [:name] => :blank,
      [:addresses, described_class::Index[0], :street] => [:blank, :short]
    }
  end

  describe ".new" do
    it "wraps a single error with an array" do
      expect(tree[[:name]]).to eql([:blank])
    end

    it "keeps several errors for the same path" do
      expect(tree[[:addresses, described_class::Index[0], :street]])
        .to eql([:blank, :short])
    end

    it "coerces integer segments to indices" do
      built = described_class.new({ [:addresses, 0, :street] => :blank })

      expect(built.errors.keys)
        .to eql([[:addresses, described_class::Index[0], :street]])
    end

    it "accepts a block with a mutable builder" do
      original = Object.new

      built = described_class.new do |builder|
        builder.add([:name], :blank)
        builder.add([:name], original)
      end

      expect(built[[:name]]).to eql([:blank, original])
    end

    it "is frozen" do
      expect(tree).to be_frozen
      expect(tree.errors).to be_frozen
    end
  end

  describe ".build" do
    it "is an alias for the constructor" do
      expect(described_class.build(errors)).to eql(tree)
    end
  end

  describe "::Index" do
    subject(:index) { described_class::Index }

    it "coerces integers" do
      expect(index[2]).to eql(index.new(2))
      expect(index[2].value).to be(2)
      expect(index["3"].value).to be(3)
    end

    it "keeps an existing index as is" do
      existing = index[4]
      expect(index[existing]).to be(existing)
    end

    it "distinguishes indices from object keys" do
      keyed = described_class.new({ [0] => :from_index, [:a] => :from_key })

      expect(keyed.errors.keys).to eql([[index[0]], [:a]])
      expect(index[0]).not_to eql(:a)
    end

    it "has a readable inspection" do
      expect(index[1].inspect).to eql("Index[1]")
    end
  end

  describe "#add" do
    it "appends errors to an existing path" do
      updated = tree.add([:name], :taken)

      expect(updated[[:name]]).to eql([:blank, :taken])
    end

    it "registers errors at a new path" do
      updated = tree.add([:age], :negative)

      expect(updated[[:age]]).to eql([:negative])
      expect(updated[[:name]]).to eql([:blank])
    end

    it "accepts several errors" do
      updated = tree.add([:name], :taken, :other)

      expect(updated[[:name]]).to eql([:blank, :taken, :other])
    end

    it "does not mutate the original tree" do
      tree.add([:age], :negative)

      expect(tree.errors).not_to have_key([:age])
      expect(tree[[:name]]).to eql([:blank])
    end

    it "keeps the original error objects" do
      error = Object.new
      updated = tree.add([:name], error)

      expect(updated[[:name]].last).to be(error)
    end
  end

  describe "#prepend" do
    it "prefixes every path" do
      prefixed = tree.prepend(:form)

      expect(prefixed.errors.keys).to eql(
        [
          [:form, :name],
          [:form, :addresses, described_class::Index[0], :street]
        ]
      )
    end

    it "coerces integer prefixes to indices" do
      prefixed = tree.prepend(1, :addresses)

      expect(prefixed.errors.keys.first)
        .to eql([described_class::Index[1], :addresses, :name])
    end

    it "returns self for an empty prefix" do
      expect(tree.prepend).to be(tree)
    end

    it "does not mutate the original tree" do
      tree.prepend(:form)

      expect(tree.errors.keys.first).to eql([:name])
    end
  end

  describe "#+" do
    let(:left) do
      described_class.new(
        { [:name] => [:blank], [:age] => [:negative] }
      )
    end

    let(:right) do
      described_class.new(
        { [:name] => [:taken], [:email] => :invalid }
      )
    end

    it "keeps the stable order of paths and errors" do
      expect((left + right).errors).to eql(
        {
          [:name] => [:blank, :taken],
          [:age] => [:negative],
          [:email] => [:invalid]
        }
      )
    end

    it "does not mutate either operand" do
      left_before = left.errors.dup
      right_before = right.errors.dup

      _merged = left + right

      expect(left.errors).to eql(left_before)
      expect(right.errors).to eql(right_before)
    end

    it "does not lose or copy error objects" do
      error = Object.new
      other = described_class.new({ [:name] => error })

      expect((left + other)[[:name]]).to eql([:blank, error])
      expect((left + other)[[:name]].last).to be(error)
    end

    it "is associative" do
      third = described_class.new({ [:age] => :too_old })

      expect((left + right) + third).to eql(left + (right + third))
    end

    it "wraps a bare error at the root path" do
      merged = described_class.new.+(:boom)

      expect(merged[[]]).to eql([:boom])
    end
  end

  describe "#empty?" do
    it "is false for a tree with errors" do
      expect(tree).not_to be_empty
    end

    it "is true for an empty tree" do
      expect(described_class.new).to be_empty
    end
  end

  describe "#inspect" do
    it "includes the errors" do
      expect(described_class.new({ [:name] => :blank }).inspect)
        .to eql("ErrorTree({[:name] => [:blank]})")
    end
  end

  describe "equality" do
    it "compares trees by their errors" do
      expect(described_class.new(errors)).to eql(tree)
    end

    it "takes the error order into account" do
      reordered = described_class.new(
        {
          [:addresses, described_class::Index[0], :street] => [:short, :blank],
          [:name] => :blank
        }
      )

      expect(reordered).not_to eql(tree)
    end
  end

  describe described_class::Mixin do
    subject(:context) { Class.new { include Dry::Monads[:error_tree] }.new }

    it "provides an ErrorTree constructor" do
      expect(context.ErrorTree { |builder| builder.add([:name], :blank) })
        .to eql(Dry::Monads::ErrorTree.new({ [:name] => :blank }))
    end
  end
end
