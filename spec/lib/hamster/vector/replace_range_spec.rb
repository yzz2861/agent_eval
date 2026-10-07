require "spec_helper"
require "hamster/vector"

describe Hamster::Vector do
  describe "#replace_range" do
    def root_of(vector)
      vector.instance_variable_get(:@root)
    end

    it "replaces a segment in the middle" do
      expect(V[1, 2, 3, 4, 5].replace_range(1, 2, V[:a, :b, :c])).to eql(V[1, :a, :b, :c, 4, 5])
    end

    it "inserts without removing anything when length is zero" do
      expect(V[1, 2, 3].replace_range(1, 0, V[:a])).to eql(V[1, :a, 2, 3])
    end

    it "appends when from is equal to the size" do
      expect(V[1, 2].replace_range(2, 0, V[3, 4])).to eql(V[1, 2, 3, 4])
    end

    it "replaces the whole vector" do
      expect(V[1, 2, 3].replace_range(0, 3, V[:a, :b])).to eql(V[:a, :b])
    end

    it "accepts any array-like replacement" do
      expect(V[1, 2, 3, 4].replace_range(1, 2, [:a, :b, :c])).to eql(V[1, :a, :b, :c, 4])
      expect(V[1, 2, 3, 4].replace_range(1, 2, 100..102)).to eql(V[1, 100, 101, 102, 4])
    end

    it "clamps a length which extends past the end" do
      expect(V[1, 2, 3, 4].replace_range(2, 100, V[:a])).to eql(V[1, 2, :a])
    end

    it "counts a negative from back from the end" do
      expect(V[1, 2, 3, 4].replace_range(-2, 2, V[:a])).to eql(V[1, 2, :a])
    end

    it "works on an empty vector" do
      expect(V.empty.replace_range(0, 0, V[1, 2, 3])).to eql(V[1, 2, 3])
      expect(V.empty.replace_range(0, 0, [])).to eql(V.empty)
    end

    it "raises an IndexError when from is out of bounds" do
      expect { V[1, 2, 3].replace_range(4, 0, V[]) }.to raise_error(IndexError)
      expect { V[1, 2, 3].replace_range(-4, 0, V[]) }.to raise_error(IndexError)
    end

    it "raises an IndexError for a negative length" do
      expect { V[1, 2, 3].replace_range(1, -1, V[]) }.to raise_error(IndexError)
    end

    it "does not modify the receiver or the replacement" do
      vector = V[1, 2, 3, 4, 5]
      middle = V[:a, :b]
      vector.replace_range(1, 2, middle)
      expect(vector).to eql(V[1, 2, 3, 4, 5])
      expect(middle).to eql(V[:a, :b])
    end

    # a 2100-item vector has a 2-level trie with a partially filled last
    # leaf, so cuts at these positions cross leaf boundaries, the level-1
    # boundary at item 1024, and partially filled edge nodes
    context "across node boundaries" do
      let(:base) { V.new(0...2100) }

      [0, 1, 31, 32, 33, 100, 1023, 1024, 1025, 2100].each do |from|
        [0, 1, 5, 32, 33, 100].each do |length|
          [0, 1, 10, 32, 40].each do |middle_size|
            it "replaces #{length} items at #{from} with #{middle_size} items" do
              middle = (10000...(10000 + middle_size)).to_a
              expected = (0...2100).to_a
              expected[from, [length, 2100 - from].min] = middle
              result = base.replace_range(from, length, V.new(middle))
              expect(result.size).to eq(expected.size)
              expect(result).to eql(V.new(expected))
            end
          end
        end
      end
    end

    context "structural sharing" do
      it "shares the untouched prefix and suffix when replacing a segment" do
        base = V.new(0...2048) # two full subtrees of 1024 items
        result = base.replace_range(1024, 32, V.new(9000...9032))
        expect(result).to eql(V.new((0...1024).to_a + (9000...9032).to_a + (1056...2048).to_a))
        # the whole left subtree is reused by reference
        expect(root_of(result)[0]).to be(root_of(base)[0])
        # and every suffix leaf, including the one at the cut point
        expect(root_of(result)[1][1]).to be(root_of(base)[1][1])
        expect(root_of(result)[1][31]).to be(root_of(base)[1][31])
      end

      it "shares the prefix when inserting a small segment into a big vector" do
        base = V.new(0...2048)
        result = base.replace_range(1024, 0, V[:a, :b, :c])
        expect(result.size).to eq(2051)
        expect(result[1023]).to eq(1023)
        expect(result[1024, 3]).to eql(V[:a, :b, :c])
        expect(result[1027]).to eq(1024)
        # everything before the insertion point is one shared subtree;
        # the suffix leaves are re-chunked because inserting 3 items
        # shifts every later item off the 32-item grid
        expect(root_of(result)[0]).to be(root_of(base)[0])
      end

      it "shares suffix leaves when the segment size does not change" do
        base = V.new(0...128) # 4 full leaves
        result = base.replace_range(10, 10, V.new(100...110))
        expect(result).to eql(V.new((0...10).to_a + (100...110).to_a + (20...128).to_a))
        # only the leaf containing the cut is rebuilt; the other leaves
        # of the suffix are reused by reference
        expect(root_of(result)[0]).not_to be(root_of(base)[0])
        expect(root_of(result)[1]).to be(root_of(base)[1])
        expect(root_of(result)[2]).to be(root_of(base)[2])
        expect(root_of(result)[3]).to be(root_of(base)[3])
      end
    end

    context "result semantics" do
      let(:result) { V.new(0...2100).replace_range(1000, 50, V.new(10000...10070)) }

      it "supports get, put and slice as usual" do
        expect(result.size).to eq(2120)
        expect(result.get(0)).to eq(0)
        expect(result.get(999)).to eq(999)
        expect(result.get(1000)).to eq(10000)
        expect(result.get(1069)).to eq(10069)
        expect(result.get(1070)).to eq(1050)
        expect(result.get(-1)).to eq(2099)
        expect(result.get(2120)).to be_nil
        expect(result.put(1000, :x).get(1000)).to eq(:x)
        expect(result[1065, 10]).to eql(V[10065, 10066, 10067, 10068, 10069, 1050, 1051, 1052, 1053, 1054])
        expect(result[1065..1074]).to eql(V[10065, 10066, 10067, 10068, 10069, 1050, 1051, 1052, 1053, 1054])
      end
    end
  end
end
