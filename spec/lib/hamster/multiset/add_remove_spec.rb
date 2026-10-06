require "spec_helper"

describe Hamster::Multiset do
  describe "#add" do
    it "increments the multiplicity of a value" do
      multiset = MS[:a].add(:a)
      expect(multiset.multiplicity(:a)).to eq(2)
      expect(multiset.size).to eq(2)
    end

    it "adds multiple occurrences at once" do
      expect(MS.empty.add(:a, 5).multiplicity(:a)).to eq(5)
    end

    it "returns self when adding zero occurrences" do
      multiset = MS[:a]
      expect(multiset.add(:a, 0)).to equal(multiset)
    end

    it "is aliased as #<<" do
      expect((MS[:a] << :b).to_hash).to eq(a: 1, b: 1)
    end

    it "leaves the receiver unchanged" do
      multiset = MS[:a]
      multiset.add(:a, 3)
      expect(multiset.multiplicity(:a)).to eq(1)
    end

    it "rejects negative counts" do
      expect { MS[:a].add(:a, -1) }.to raise_error(ArgumentError)
    end

    it "rejects non-integer counts" do
      expect { MS[:a].add(:a, 0.5) }.to raise_error(ArgumentError)
      expect { MS[:a].add(:a, "1") }.to raise_error(ArgumentError)
      expect { MS[:a].add(:a, nil) }.to raise_error(ArgumentError)
    end
  end

  describe "#remove" do
    it "decrements the multiplicity of a value" do
      multiset = MS[:a, :a, :a].remove(:a)
      expect(multiset.multiplicity(:a)).to eq(2)
      expect(multiset.size).to eq(2)
    end

    it "removes multiple occurrences at once" do
      expect(MS[:a, :a, :a].remove(:a, 2).multiplicity(:a)).to eq(1)
    end

    it "deletes the value entirely when the count reaches zero" do
      multiset = MS[:a, :a, :b].remove(:a, 2)
      expect(multiset).not_to include(:a)
      expect(multiset.multiplicity(:a)).to eq(0)
      expect(multiset.distinct_count).to eq(1)
      expect(multiset.to_hash).to eq(b: 1)
    end

    it "truncates at zero when removing more than is present" do
      multiset = MS[:a, :b].remove(:a, 10)
      expect(multiset.to_hash).to eq(b: 1)
      expect(multiset.size).to eq(1)
    end

    it "returns self when the value is absent" do
      multiset = MS[:a]
      expect(multiset.remove(:b)).to equal(multiset)
    end

    it "returns self when removing zero occurrences" do
      multiset = MS[:a]
      expect(multiset.remove(:a, 0)).to equal(multiset)
    end

    it "leaves the receiver unchanged" do
      multiset = MS[:a, :a]
      multiset.remove(:a)
      expect(multiset.multiplicity(:a)).to eq(2)
    end

    it "rejects negative counts" do
      expect { MS[:a].remove(:a, -2) }.to raise_error(ArgumentError)
    end

    it "rejects non-integer counts" do
      expect { MS[:a].remove(:a, 1.5) }.to raise_error(ArgumentError)
    end
  end

  describe "#delete" do
    it "removes all occurrences of a value" do
      multiset = MS[:a, :a, :a, :b].delete(:a)
      expect(multiset.to_hash).to eq(b: 1)
      expect(multiset.size).to eq(1)
    end

    it "returns self when the value is absent" do
      multiset = MS[:a]
      expect(multiset.delete(:b)).to equal(multiset)
    end
  end
end

