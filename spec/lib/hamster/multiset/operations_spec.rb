require "spec_helper"

describe Hamster::Multiset do
  let(:left) { MS.new([:a, :a, :a, :b, :b, :c]) }
  let(:right) { MS.new([:a, :a, :b, :d]) }

  describe "#sum" do
    it "adds the multiplicities of both operands" do
      expect((left + right).to_hash).to eq(a: 5, b: 3, c: 1, d: 1)
    end

    it "adds the sizes of both operands" do
      expect((left + right).size).to eq(left.size + right.size)
    end

    it "accepts a Ruby hash of counts" do
      expect((left + { a: 1, d: 2 }).to_hash).to eq(a: 4, b: 2, c: 1, d: 2)
    end

    it "accepts a Hamster::Hash of counts" do
      expect((left + H[a: 1]).multiplicity(:a)).to eq(4)
    end

    it "rejects invalid count tables" do
      expect { left + { a: -1 } }.to raise_error(ArgumentError)
      expect { left + { a: 1.5 } }.to raise_error(ArgumentError)
    end

    it "raises TypeError for non-coercible operands" do
      expect { left + [:a] }.to raise_error(TypeError)
      expect { left + 1 }.to raise_error(TypeError)
    end

    it "leaves both operands unchanged" do
      left + right
      expect(left.to_hash).to eq(a: 3, b: 2, c: 1)
      expect(right.to_hash).to eq(a: 2, b: 1, d: 1)
    end
  end

  describe "#union" do
    it "keeps the maximum multiplicity of each value" do
      expect((left | right).to_hash).to eq(a: 3, b: 2, c: 1, d: 1)
    end

    it "has the sum of the maxima as its size" do
      expect((left | right).size).to eq(7)
    end

    it "is idempotent with itself" do
      expect(left | left).to eq(left)
    end
  end

  describe "#intersection" do
    it "keeps the minimum multiplicity of each shared value" do
      expect((left & right).to_hash).to eq(a: 2, b: 1)
    end

    it "drops values absent from either operand" do
      expect((left & MS[:d]).to_hash).to eq({})
    end

    it "has the sum of the minima as its size" do
      expect((left & right).size).to eq(3)
    end

    it "is idempotent with itself" do
      expect(left & left).to eq(left)
    end
  end

  describe "#difference" do
    it "subtracts multiplicities, truncating at zero" do
      expect((left - right).to_hash).to eq(a: 1, b: 1, c: 1)
    end

    it "never produces negative counts" do
      result = MS[:a] - MS[:a, :a, :a]
      expect(result).to be_empty
      expect(result.size).to eq(0)
    end

    it "removes values whose count reaches zero" do
      result = MS[:a, :a] - MS[:a, :a]
      expect(result.distinct_count).to eq(0)
      expect(result.to_hash).to eq({})
    end

    it "computes the shortage between two batches" do
      ordered = MS.new([:apple, :apple, :apple, :pear])
      shipped = MS.new([:apple, :pear, :pear])
      expect((ordered - shipped).to_hash).to eq(apple: 2)
      expect((shipped - ordered).to_hash).to eq(pear: 1)
    end

    it "accepts a Ruby hash of counts" do
      expect((left - { a: 2 }).multiplicity(:a)).to eq(1)
    end
  end

  describe "operand coercion" do
    it "treats zero counts in hash operands as absent" do
      expect((left & { a: 0, b: 2 }).to_hash).to eq(b: 2)
    end

    it "rejects invalid counts in hash operands for every operation" do
      expect { left | { a: -1 } }.to raise_error(ArgumentError)
      expect { left & { a: 2.0 } }.to raise_error(ArgumentError)
      expect { left - { a: nil } }.to raise_error(ArgumentError)
    end
  end
end

