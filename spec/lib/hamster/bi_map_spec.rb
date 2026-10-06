require "spec_helper"
require "hamster/bi_map"

describe Hamster::BiMap do
  let(:bi_map) { Hamster::BiMap[:a => 1, :b => 2] }

  describe "construction and lookup" do
    it "looks up keys from both sides" do
      expect(bi_map[:a]).to eq(1)
      expect(bi_map[:b]).to eq(2)
      expect(bi_map.inverse[1]).to eq(:a)
      expect(bi_map.inverse[2]).to eq(:b)
    end

    it "supports nil as both a key and a value" do
      map = Hamster::BiMap.new([[nil, :external], [:internal, nil]])

      expect(map[nil]).to eq(:external)
      expect(map[:internal]).to be_nil
      expect(map.inverse[:external]).to be_nil
      expect(map.inverse[nil]).to eq(:internal)
      expect(map.key?(nil)).to eq(true)
      expect(map.value?(nil)).to eq(true)
    end

    it "duplicates and freezes mutable string keys and values" do
      key = "internal"
      value = "external"
      map = Hamster::BiMap.new([[key, value]])
      key.upcase!
      value.upcase!

      expect(map["internal"]).to eq("external")
      expect(map.inverse["external"]).to eq("internal")
    end

    it "supports distinct keys and values with custom hash collisions" do
      key_a = DeterministicHash.new("a", 100)
      key_b = DeterministicHash.new("b", 100)
      value_a = DeterministicHash.new("x", 200)
      value_b = DeterministicHash.new("y", 200)
      map = Hamster::BiMap.new([[key_a, value_a], [key_b, value_b]])

      expect(map[key_a]).to eql(value_a)
      expect(map[key_b]).to eql(value_b)
      expect(map.inverse[value_a]).to eql(key_a)
      expect(map.inverse[value_b]).to eql(key_b)
    end

    it "rejects duplicate values during construction" do
      expect { Hamster::BiMap.new([[:a, 1], [:b, 1]]) }
        .to raise_error(ArgumentError, /duplicate value/)
    end
  end

  describe "#inverse" do
    it "shares the two indexes without copying the mappings" do
      expect(bi_map.inverse.instance_variable_get(:@forward))
        .to be(bi_map.instance_variable_get(:@reverse))
      expect(bi_map.inverse.instance_variable_get(:@reverse))
        .to be(bi_map.instance_variable_get(:@forward))
    end

    it "returns the same object when inverted twice" do
      expect(bi_map.inverse.inverse).to be(bi_map)
    end

    it "iterates and converts in the inverse direction" do
      expect(bi_map.inverse.to_hash).to eq(1 => :a, 2 => :b)
      expect(bi_map.inverse.keys).to eq(Hamster::Set[1, 2])
      expect(bi_map.inverse.values).to eq(Hamster::Set[:a, :b])
    end

    it "preserves inverse orientation after a modification" do
      changed = bi_map.inverse.put(3, :c)

      expect(changed[3]).to eq(:c)
      expect(changed.inverse[:c]).to eq(3)
      expect(changed.inverse).to eql(Hamster::BiMap[:a => 1, :b => 2, :c => 3])
    end
  end

  describe "#put" do
    it "overwrites an existing key and removes its old inverse mapping" do
      changed = bi_map.put(:a, 3)

      expect(changed).to eql(Hamster::BiMap[:a => 3, :b => 2])
      expect(changed.inverse[3]).to eq(:a)
      expect(changed.inverse.key?(1)).to eq(false)
    end

    it "rejects a value already owned by another key" do
      expect { bi_map.put(:a, 2) }
        .to raise_error(ArgumentError, /already associated/)
    end

    it "forces replacement of the key that owns the value" do
      changed = bi_map.force_put(:a, 2)

      expect(changed).to eql(Hamster::BiMap[:a => 2])
      expect(changed.inverse[2]).to eq(:a)
      expect(changed.key?(:b)).to eq(false)
    end

    it "returns the original object for an identical association" do
      expect(bi_map.put(:a, 1)).to be(bi_map)
    end

    it "leaves the original map queryable from both sides after failure" do
      expect { bi_map.put(:a, 2) }.to raise_error(ArgumentError)

      expect(bi_map[:a]).to eq(1)
      expect(bi_map[:b]).to eq(2)
      expect(bi_map.inverse[1]).to eq(:a)
      expect(bi_map.inverse[2]).to eq(:b)
    end
  end

  describe "#merge" do
    it "allows two existing values to be exchanged as one transaction" do
      changed = bi_map.merge([[:a, 2], [:b, 1]])

      expect(changed.to_hash).to eq(:a => 2, :b => 1)
      expect(changed.inverse.to_hash).to eq(2 => :a, 1 => :b)
    end

    it "overwrites two existing relationships in one batch" do
      changed = bi_map.merge([[:a, 3], [:b, 4]])

      expect(changed).to eql(Hamster::BiMap[:a => 3, :b => 4])
      expect(changed.inverse[3]).to eq(:a)
      expect(changed.inverse[4]).to eq(:b)
      expect(changed.inverse.key?(1)).to eq(false)
      expect(changed.inverse.key?(2)).to eq(false)
    end

    it "accepts a Ruby Hash and copies mutable string keys and values" do
      key = "a"
      value = 3
      changed = bi_map.merge(key => value)
      key.upcase!

      expect(changed["a"]).to eq(3)
      expect(changed["A"]).to be_nil
    end

    it "rejects duplicate values within the same batch" do
      expect { bi_map.merge([[:a, 3], [:b, 3]]) }
        .to raise_error(ArgumentError, /duplicate value/)
    end

    it "rejects duplicate inverse values within an inverse batch" do
      expect { bi_map.inverse.merge([[1, :a], [2, :a]]) }
        .to raise_error(ArgumentError, /duplicate value/)
      expect(bi_map.to_hash).to eq(:a => 1, :b => 2)
    end

    it "does not leave a partial mapping after a value conflict" do
      expect { bi_map.merge([[:a, 3], [:c, 2]]) }
        .to raise_error(ArgumentError, /already associated/)

      expect(bi_map.to_hash).to eq(:a => 1, :b => 2)
      expect(bi_map.inverse.to_hash).to eq(1 => :a, 2 => :b)
      expect(bi_map.key?(:c)).to eq(false)
      expect(bi_map.value?(3)).to eq(false)
    end

    it "can displace existing owners while applying the complete batch" do
      changed = bi_map.merge([[:a, 2], [:c, 3]], :force => true)

      expect(changed).to eql(Hamster::BiMap[:a => 2, :c => 3])
      expect(changed.inverse[2]).to eq(:a)
      expect(changed.inverse[3]).to eq(:c)
      expect(changed.key?(:b)).to eq(false)
    end
  end

  describe "deletion" do
    it "removes both directions by key" do
      changed = bi_map.delete(:a)

      expect(changed).to eql(Hamster::BiMap[:b => 2])
      expect(changed.inverse.key?(1)).to eq(false)
    end

    it "removes both directions by value" do
      changed = bi_map.delete_value(1)

      expect(changed).to eql(Hamster::BiMap[:b => 2])
      expect(changed.key?(:a)).to eq(false)
    end

    it "preserves inverse orientation when deleting from either side" do
      changed = bi_map.inverse.delete(1)

      expect(changed.to_hash).to eq(2 => :b)
      expect(changed.inverse).to eql(Hamster::BiMap[:b => 2])
    end

    it "preserves inverse orientation when deleting by opposite-side value" do
      changed = bi_map.inverse.delete_value(:a)

      expect(changed.to_hash).to eq(2 => :b)
      expect(changed.inverse).to eql(Hamster::BiMap[:b => 2])
    end
  end

  describe "immutability" do
    it "does not support assignment" do
      expect { bi_map[:a] = 3 }
        .to raise_error(NoMethodError, /Hamster::BiMap.*`put'/)
    end

    it "keeps the previous version unchanged after successful modification" do
      changed = bi_map.put(:c, 3)

      expect(changed).to eql(Hamster::BiMap[:a => 1, :b => 2, :c => 3])
      expect(bi_map).to eql(Hamster::BiMap[:a => 1, :b => 2])
      expect(bi_map[:c]).to be_nil
      expect(bi_map.inverse[3]).to be_nil
      expect(bi_map.inverse[1]).to eq(:a)
    end
  end

  describe "marshaling" do
    it "preserves bidirectional lookup after loading" do
      loaded = Marshal.load(Marshal.dump(bi_map))

      expect(loaded[:a]).to eq(1)
      expect(loaded.inverse[1]).to eq(:a)
      expect(loaded).to eql(bi_map)
    end
  end
end
