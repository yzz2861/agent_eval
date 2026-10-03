# frozen_string_literal: true

RSpec.describe(Dry::Monads::Validated::ErrorTree) do
  tree = described_class
  key = described_class::Key
  index = described_class::Index

  describe "path segments" do
    it "wraps object keys and array indices with different types" do
      expect(key[:foo]).to eql(key[:foo])
      expect(index[0]).to eql(index[0])
      expect(key[0]).not_to eql(index[0])
      expect(key[0]).not_to eql(index[0].value)
    end

    it "is frozen" do
      expect(key[:foo]).to be_frozen
      expect(index[0]).to be_frozen
      expect(key["foo"].value).to be_frozen
    end

    it "coerces index values to integers" do
      expect(index["2"]).to eql(index[2])
    end

    it "has readable inspect output" do
      expect(key[:foo].inspect).to eql("Key(:foo)")
      expect(index[1].inspect).to eql("Index(1)")
    end

    it "tells apart an index and a key with the same value" do
      errors = tree.new([[0, :array], [:"0", :object]])

      expect(errors[[index[0]]]).to eql([:array])
      expect(errors[[key[:"0"]]]).to eql([:object])
      expect(errors.paths).to eql([[index[0]], [key[:"0"]]])
    end
  end

  describe ".new" do
    it "builds an empty tree" do
      expect(tree.new).to be_empty
      expect(tree[]).to eql(tree.new)
      expect(tree::EMPTY).to eql(tree.new)
    end

    it "attaches a single error to a path" do
      errors = tree.new(:name => :blank)

      expect(errors[[:name]]).to eql([:blank])
      expect(errors[:name]).to eql([:blank])
      expect(errors[[key[:name]]]).to eql([:blank])
    end

    it "attaches several errors to the same path via an Array value" do
      errors = tree.new(:name => [:blank, :taken])

      expect(errors[:name]).to eql([:blank, :taken])
      expect(errors.size).to be(2)
    end

    it "uses pairs to attach an error that is itself an Array" do
      list_error = %i[a b]
      errors = tree.new([[:name, list_error]])

      expect(errors[:name]).to eql([list_error])
    end

    it "builds nested paths from symbols and integers" do
      errors = tree.new([[[:addresses, 0, :street], :blank]])

      expect(errors.paths).to eql([[key[:addresses], index[0], key[:street]]])
    end

    it "attaches errors to the root path" do
      expect(tree.new([[tree::ROOT_PATH, :oops]])[]).to eql([:oops])
      expect(tree.new([[tree::ROOT_PATH, :oops]])[tree::ROOT_PATH]).to eql([:oops])
    end

    it "copies another tree without sharing error arrays" do
      source = tree.new(:name => :blank)
      copy = tree.new(source)

      expect(copy).to eql(source)
      expect(copy[:name]).not_to equal(source[:name])
    end

    it "duplicates and freezes string keys" do
      raw = +"name"
      errors = tree.new(raw => :blank)
      raw << "!"

      expect(errors.paths).to eql([[key["name"]]])
      expect(errors.paths.first.first.value).to be_frozen
    end

    it "rejects values that cannot be path segments" do
      expect { tree.new([[Object.new, :x]] => :y) }.to raise_error(ArgumentError)
    end

    it "rejects malformed sources" do
      expect { tree.new(:boom) }.to raise_error(ArgumentError)
      expect { tree.new([:bad]) }.to raise_error(ArgumentError, /pair/)
    end

    it "is frozen" do
      expect(tree.new(:name => :blank)).to be_frozen
    end
  end

  describe "#[]" do
    subject { tree.new(:name => :blank) }

    it "returns an empty frozen array for unknown paths" do
      expect(subject[:unknown]).to be_empty
      expect(subject[:unknown]).to be_frozen
    end

    it "accepts splatted segments" do
      deep = tree.new([[[:address, 0, :street], :blank]])

      expect(deep[:address, 0, :street]).to eql([:blank])
    end
  end

  describe "#fetch" do
    subject { tree.new(:name => :blank) }

    it "returns errors for a known path" do
      expect(subject.fetch(:name)).to eql([:blank])
    end

    it "raises KeyError for an unknown path without a default" do
      expect { subject.fetch(:unknown) }.to raise_error(KeyError)
    end

    it "uses the given default value" do
      expect(subject.fetch(:unknown, [:default])).to eql([:default])
    end

    it "uses the given block" do
      expect(subject.fetch(:unknown) { [:block] }).to eql([:block])
    end
  end

  describe "#merge" do
    it "joins trees path by path" do
      merged = tree.new(:name => :blank).merge(
        tree.new(:age => :bad),
        city: :missing
      )

      expect(merged).to eql(tree.new(
        name: :blank,
        age: :bad,
        city: :missing
      ))
    end

    it "appends errors of the same path in a stable order" do
      merged = tree.new(:name => :blank).merge(tree.new(:name => :taken))

      expect(merged[:name]).to eql([:blank, :taken])
    end

    it "keeps the order in which paths first appear" do
      merged = tree.new(:a => 1, b: 2).merge(tree.new(:c => 3))

      expect(merged.paths).to eql([[key[:a]], [key[:b]], [key[:c]]])
    end

    it "produces the same tree regardless of grouping order" do
      first = tree.new(name: :blank, age: :bad)
      second = tree.new(email: :missing)
      third = tree.new(city: :short)

      expect(first.merge(second).merge(third))
        .to eql(third.merge(second.merge(first)))
    end

    it "does not modify the receiver or the arguments" do
      left = tree.new(:name => :blank)
      right = tree.new(:name => :taken)
      left_snapshot = left.to_h
      right_snapshot = right.to_h

      left.merge(right)

      expect(left.to_h).to eql(left_snapshot)
      expect(right.to_h).to eql(right_snapshot)
    end

    it "preserves the original error objects" do
      error = Object.new
      merged = tree.new.merge(tree.new(:name => error))

      expect(merged[:name].first).to be(error)
    end

    it "can merge several trees at once" do
      expect(tree.merge(tree.new(:a => 1), tree.new(:b => 2), tree.new(:c => 3)))
        .to eql(tree.new(a: 1, b: 2, c: 3))
    end
  end

  describe "#+" do
    it "merges another tree" do
      expect(tree.new(:a => 1) + tree.new(:b => 2))
        .to eql(tree.new(a: 1, b: 2))
    end

    it "appends arrays and lists to the root path" do
      list = Dry::Monads::List[:a, :b]

      expect(tree.new + list).to eql(tree.new([[tree::ROOT_PATH, :a], [tree::ROOT_PATH, :b]]))
      expect(tree.new + [:c]).to eql(tree.new([[tree::ROOT_PATH, :c]]))
      expect(tree.new + :d).to eql(tree.new([[tree::ROOT_PATH, :d]]))
    end
  end

  describe "#prefix" do
    subject { tree.new(:street => :blank, :city => :short) }

    it "prepends a path to every error" do
      expect(subject.prefix(:addresses, 0)).to eql(tree.new(
        [:addresses, 0, :street] => :blank,
        [:addresses, 0, :city] => :short
      ))
    end

    it "accepts a single array argument" do
      expect(subject.prefix([:addresses, 1]))
        .to eql(subject.prefix(:addresses, 1))
    end

    it "prefixes root errors" do
      expect(tree.new([[tree::ROOT_PATH, :bad]]).prefix(:form).paths)
        .to eql([[key[:form]]])
    end

    it "returns self for an empty prefix" do
      expect(subject.prefix).to be(subject)
      expect(subject.prefix([])).to be(subject)
    end

    it "does not mutate the receiver" do
      snapshot = subject.to_h

      subject.prefix(:addresses, 0)

      expect(subject.to_h).to eql(snapshot)
    end
  end

  describe "iteration" do
    subject { tree.new(:a => 1, b: [2, 3]) }

    it "yields path and errors" do
      collected = []
      subject.each { |path, errors| collected << [path, errors] }

      expect(collected).to eql([
        [[key[:a]], [1]],
        [[key[:b]], [2, 3]]
      ])
    end

    it "returns an enumerator without a block" do
      expect(subject.each).to be_an(Enumerator)
    end

    it "returns a mutable-safe hash" do
      hash = subject.to_h
      hash[:new] = [:x]
      hash[[key[:a]]] << :mutated

      expect(subject).not_to be_key(:new)
      expect(subject[:a]).to eql([1])
    end
  end

  describe "equality" do
    it "compares contents" do
      expect(tree.new(:a => [1, 2]))
        .to eql(tree.new([[:a, 1], [:a, 2]]))
      expect(tree.new(:a => 1)).not_to eql(tree.new(:a => 2))
      expect(tree.new(:a => 1)).not_to eql(tree.new(:b => 1))
    end

    it "matches with ===" do
      expect(tree.new(:a => 1)).to be === tree.new(:a => 1)
      expect(tree.new(:a => 1)).not_to be === tree.new(:a => 2)
      expect(tree.new(:a => 1)).not_to be === :other
    end
  end

  describe "#inspect" do
    it "shows the mapping" do
      expect(tree.new.inspect).to eql("ErrorTree({})")
      expect(tree.new(:a => 1).inspect)
        .to eql("ErrorTree({#{[key[:a]].inspect} => [1]})")
    end
  end
end
