require "spec_helper"
require "hamster/bi_map"

describe Hamster::BiMap do
  let(:map) { Hamster::BiMap[a: 1, b: 2] }

  it "looks up entries from both sides" do
    expect(map[:a]).to eq(1)
    expect(map[:b]).to eq(2)
    expect(map.inverse[1]).to eq(:a)
    expect(map.inverse[2]).to eq(:b)
    expect(map.key(1)).to eq(:a)
  end

  it "keeps the original map and inverse queryable after updates" do
    updated = map.put(:c, 3)

    expect(map.to_hash).to eq(a: 1, b: 2)
    expect(map.inverse.to_hash).to eq(1 => :a, 2 => :b)
    expect(updated.to_hash).to eq(a: 1, b: 2, c: 3)
    expect(updated.inverse.to_hash).to eq(1 => :a, 2 => :b, 3 => :c)
  end

  it "returns a copy-free inverse view" do
    expect(map.inverse.instance_variable_get(:@forward)).to equal(
      map.instance_variable_get(:@forward)
    )
    expect(map.inverse.instance_variable_get(:@reverse)).to equal(
      map.instance_variable_get(:@reverse)
    )
    expect(map.inverse.inverse).to equal(map)
    expect(map.inverse.inverse).to be(map)
  end

  it "supports nil on both sides" do
    nil_map = Hamster::BiMap.new([[nil, :external], [:internal, nil]])

    expect(nil_map[nil]).to eq(:external)
    expect(nil_map[:internal]).to be_nil
    expect(nil_map.inverse[:external]).to be_nil
    expect(nil_map.inverse[nil]).to eq(:internal)
    expect(nil_map.key(nil)).to eq(:internal)
    expect(nil_map.value?(nil)).to eq(true)
  end

  it "supports custom hash collisions for keys and values" do
    key_one = DeterministicHash.new("one", 7)
    key_two = DeterministicHash.new("two", 7)
    value_one = DeterministicHash.new("alpha", 9)
    value_two = DeterministicHash.new("beta", 9)
    collision_map = Hamster::BiMap.new([[key_one, value_one], [key_two, value_two]])

    expect(collision_map[key_one]).to eql(value_one)
    expect(collision_map[key_two]).to eql(value_two)
    expect(collision_map.inverse[value_one]).to eql(key_one)
    expect(collision_map.inverse[value_two]).to eql(key_two)
  end

  describe "conflicts" do
    it "rejects duplicate values during construction" do
      expect { Hamster::BiMap[a: 1, b: 1] }.to raise_error(
        Hamster::BiMap::DuplicateValueError
      )
    end

    it "rejects a value already owned by another key" do
      expect { map.put(:c, 2) }.to raise_error(
        Hamster::BiMap::DuplicateValueError
      )
      expect(map.to_hash).to eq(a: 1, b: 2)
      expect(map.inverse.to_hash).to eq(1 => :a, 2 => :b)
    end

    it "force replaces the two existing relationships around a value conflict" do
      forced = map.force_put(:a, 2)

      expect(forced.to_hash).to eq(a: 2)
      expect(forced.inverse.to_hash).to eq(2 => :a)
      expect(forced.key?(2)).to eq(false)
      expect(forced.inverse.key?(1)).to eq(false)
      expect(map.to_hash).to eq(a: 1, b: 2)
    end

    it "does not leave a partial mapping when a batch value conflict fails" do
      expect { map.put_all([[:c, 3], [:d, 3]]) }.to raise_error(
        Hamster::BiMap::DuplicateValueError
      )

      expect(map).to eql(Hamster::BiMap[a: 1, b: 2])
      expect(map.inverse).to eql(Hamster::BiMap[a: 1, b: 2].inverse)
    end
  end

  describe "batch changes" do
    it "allows two existing values to be swapped" do
      swapped = map.put_all([[:a, 2], [:b, 1]])

      expect(swapped.to_hash).to eq(a: 2, b: 1)
      expect(swapped.inverse.to_hash).to eq(2 => :a, 1 => :b)
    end

    it "allows a swap to be started from the inverse view" do
      swapped = map.inverse.put_all([[1, :b], [2, :a]])

      expect(swapped.to_hash).to eq(1 => :b, 2 => :a)
      expect(swapped.inverse.to_hash).to eq(a: 2, b: 1)
      expect(swapped.inverse).to eql(Hamster::BiMap[a: 2, b: 1])
    end

    it "allows cyclic replacement without forcing" do
      cycle_map = Hamster::BiMap[a: 1, b: 2, c: 3]
      rotated = cycle_map.put_all([[:a, 2], [:b, 3], [:c, 1]])

      expect(rotated.inverse.to_hash).to eq(2 => :a, 3 => :b, 1 => :c)
    end

    it "atomically replaces displaced relationships when forced" do
      forced = map.put_all([[:a, 2], [:c, 4]], true)

      expect(forced.to_hash).to eq(a: 2, c: 4)
      expect(forced.inverse.to_hash).to eq(2 => :a, 4 => :c)
    end

    it "validates construction from the final mapping when repeated keys form a swap" do
      swapped = Hamster::BiMap.new([[:a, 1], [:b, 2], [:a, 2], [:b, 1]])

      expect(swapped).to eql(Hamster::BiMap[a: 2, b: 1])
    end
  end

  describe "deletion" do
    it "removes a relationship from both sides" do
      deleted = map.delete(:a)

      expect(deleted.to_hash).to eq(b: 2)
      expect(deleted.inverse.to_hash).to eq(2 => :b)
    end

    it "supports deletion through the inverse view" do
      deleted = map.inverse.delete(1)

      expect(deleted).to eql(Hamster::BiMap[b: 2].inverse)
      expect(deleted.inverse).to eql(Hamster::BiMap[b: 2])
    end

    it "returns the canonical empty map when the last relationship is removed" do
      single = Hamster::BiMap[a: 1]

      expect(single.delete(:a)).to equal(Hamster::EmptyBiMap)
      expect(single.inverse.delete(1)).to equal(Hamster::EmptyBiMap.inverse)
    end
  end

  it "is immutable" do
    expect(map).to be_frozen
    expect(map.inverse).to be_frozen
    expect { map[:a] = 9 }.to raise_error(NoMethodError)
  end

  it "preserves inverse orientation through marshalling" do
    reloaded = Marshal.load(Marshal.dump(map.inverse))

    expect(reloaded).to eql(map.inverse)
    expect(reloaded.inverse).to eql(map)
    expect(reloaded[1]).to eq(:a)
    expect(reloaded.inverse[:b]).to eq(2)
  end
end
