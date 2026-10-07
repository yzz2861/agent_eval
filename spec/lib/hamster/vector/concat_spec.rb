require "spec_helper"
require "hamster/vector"

describe Hamster::Vector do
  def chunks(vector)
    node = vector.instance_variable_get(:@root)
    rope_node = Hamster::Vector.const_get(:RopeNode)
    chunk_class = Hamster::Vector.const_get(:VectorChunk)

    traverse = lambda do |current|
      if current.is_a?(rope_node)
        traverse.call(current.left) + traverse.call(current.right)
      else
        [current].select { |item| item.is_a?(chunk_class) }
      end
    end

    traverse.call(node)
  end

  def leaf_at(vector, index)
    node = vector.instance_variable_get(:@root)
    bitshift = vector.instance_variable_get(:@levels) * 5

    while bitshift > 0
      node = node[(index >> bitshift) & 31]
      bitshift -= 5
    end

    node
  end

  def trie_node_at(vector, index, bitshift)
    node = vector.instance_variable_get(:@root)
    current = vector.instance_variable_get(:@levels) * 5

    while current > bitshift
      node = node[(index >> current) & 31]
      current -= 5
    end

    node
  end

  [:+, :concat].each do |method|
    describe "##{method}" do
      let(:vector) { V.new(1..100) }

      it "preserves the original" do
        vector.concat([1,2,3])
        expect(vector).to eql(V.new(1..100))
      end

      it "appends the elements in the other enumerable" do
        expect(vector.concat([1,2,3])).to eql(V.new((1..100).to_a + [1,2,3]))
        expect(vector.concat(1..1000)).to eql(V.new((1..100).to_a + (1..1000).to_a))
        expect(vector.concat(1..200).size).to eq(300)
        expect(vector.concat(vector)).to eql(V.new((1..100).to_a * 2))
        expect(vector.concat(V.empty)).to eql(vector)
        expect(V.empty.concat(vector)).to eql(vector)
      end

      [1, 31, 32, 33, 1023, 1024, 1025].each do |size|
        context "on a #{size}-item vector" do
          it "works the same" do
            vector = V.new(1..size)
            result = vector.concat((size+1)..size+10)
            expect(result.size).to eq(size + 10)
            expect(result).to eql(V.new(1..(size+10)))
          end
        end
      end
    end
  end

  describe "structural sharing" do
    it "keeps both large tries intact without converting them to an Array" do
      left = V.new(1..2000)
      right = V.new(2001..4000)
      result = left.concat(right)

      expect(chunks(result).map(&:vector)).to eq([left, right])
      expect(chunks(result).map(&:offset)).to eq([0, 0])
      expect(chunks(result).map(&:length)).to eq([2000, 2000])
      expect(result).to eql(V.new(1..4000))
    end

    it "handles empty operands and different tree heights" do
      small = V.new(1..31)
      large = V.new(1..2000)
      shifted_large = V.new(32..2031)

      expect(small.concat(V.empty)).to equal(small)
      expect(V.empty.concat(large)).to eql(large)

      result = small.concat(shifted_large)
      expect(chunks(result).map(&:vector)).to eq([small, shifted_large])
      expect(result.to_a).to eq((1..2031).to_a)
    end

    it "shares unfilled prefixes and suffixes across multiple tree levels" do
      original = V.new(1..2000)

      [0, 1, 31, 32, 33, 1023, 1024, 1025, 1999].each do |index|
        inserted = [:a, :b]
        result = original.insert(index, *inserted)
        sources = chunks(result).map(&:vector)
        expected = (1..2000).to_a.insert(index, *inserted)

        expect(sources).to include(original)
        expect(result.to_a).to eq(expected)
        expect(result.get(index)).to eq(:a)
        expect(result.get(index + 1)).to eq(:b)
        expect(result.get(index + 2)).to eq(original.get(index))
        expect(result.slice(index, 2)).to eql(V[:a, :b])
      end
    end

    it "rebuilds only the inserted vector and rope spine around an internal boundary" do
      original = V.new(1..2000)
      result = original.insert(1024, :marker)
      prefix = result.slice(0, 1024)
      suffix = result.slice(1025, 975)
      prefix_chunk = chunks(prefix).first
      suffix_chunk = chunks(suffix).first

      expect(prefix_chunk.vector).to equal(original)
      expect(suffix_chunk.vector).to equal(original)
      expect(leaf_at(prefix_chunk.vector, 1023)).to equal(leaf_at(original, 1023))
      expect(leaf_at(suffix_chunk.vector, 1024)).to equal(leaf_at(original, 1024))
      expect(result.slice(1022, 5)).to eql(V[1023, 1024, :marker, 1025, 1026])
    end

    it "keeps unchanged sides of a cross-level replacement and rebuilds only the rope spine" do
      original = V.new(1..2000)
      result = original.fill(:x, 1008, 32)
      prefix = result.slice(0, 1008)
      suffix = result.slice(1040, 960)
      prefix_chunk = chunks(prefix).first
      suffix_chunk = chunks(suffix).first

      expect(chunks(prefix).map(&:vector)).to eq([original])
      expect(chunks(suffix).map(&:vector)).to eq([original])
      expect(trie_node_at(prefix_chunk.vector, 0, 5)).to equal(trie_node_at(original, 0, 5))
      expect(trie_node_at(suffix_chunk.vector, 1040, 5)).to equal(trie_node_at(original, 1040, 5))
      expect(leaf_at(suffix_chunk.vector, 1040)).to equal(leaf_at(original, 1040))
      expect(prefix.to_a).to eq((1..1008).to_a)
      expect(suffix.to_a).to eq((1041..2000).to_a)
      expect(result.slice(1006, 36)).to eql(V.new([1007, 1008] + Array.new(32, :x) + [1041, 1042]))
    end

    it "shares the suffix after deleting through a tree boundary" do
      original = V.new(1..2000)
      result = original.delete_at(1024)
      suffix = result.slice(1024, 975)
      suffix_chunk = chunks(suffix).first

      expect(result.to_a).to eq((1..2000).to_a - [1025])
      expect(suffix_chunk.vector).to equal(original)
      expect(leaf_at(suffix_chunk.vector, 1025)).to equal(leaf_at(original, 1025))
    end

    it "supports get, put, and slice after concatenation at leaf and internal boundaries" do
      left = V.new(1..1024)
      right = V.new(1025..2000)
      result = left.concat(right)
      updated = result.put(1024, :changed)
      sliced = result.slice(1000, 48)

      expect(result.get(1023)).to eq(1024)
      expect(result.get(1024)).to eq(1025)
      expect(updated.get(1024)).to eq(:changed)
      expect(updated.slice(1023, 3)).to eql(V[1024, :changed, 1026])
      expect(sliced.to_a).to eq((1001..1048).to_a)
      expect(chunks(result).map(&:vector)).to eq([left, right])
    end
  end
end
