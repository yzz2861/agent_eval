require "spec_helper"
require "hamster/vector"

describe Hamster::Vector do
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

  describe "structural sharing when concatenating vectors" do
    def root_of(vector)
      vector.instance_variable_get(:@root)
    end

    # sizes cover: empty, a partial leaf, exactly one full leaf, one leaf
    # plus one item, several leaves, and trees of different heights
    [0, 1, 31, 32, 33, 63, 64, 65, 100, 1023, 1024, 1025, 2080].each do |left_size|
      [0, 1, 31, 32, 33, 100, 1024, 1025].each do |right_size|
        context "#{left_size} items plus #{right_size} items" do
          it "concatenates correctly" do
            left  = V.new(0...left_size)
            right = V.new(left_size...(left_size + right_size))
            result = left + right
            expect(result.size).to eq(left_size + right_size)
            expect(result).to eql(V.new(0...(left_size + right_size)))
          end
        end
      end
    end

    it "does not convert either vector to an array" do
      klass = Class.new(Hamster::Vector) do
        def to_a
          raise "should not flatten the vector to concatenate"
        end
      end
      result = klass.new(1..50) + klass.new(51..150)
      expect(result.each.to_a).to eq((1..150).to_a)
    end

    it "does not modify either original" do
      left  = V.new(0...1024)
      right = V.new(1024...2048)
      left + right
      expect(left).to eql(V.new(0...1024))
      expect(right).to eql(V.new(1024...2048))
    end

    it "shares whole subtrees of both sides across tree-level boundaries" do
      left  = V.new(0...32768) # a complete 2-level tree
      right = V.new(32768...65536)
      result = left + right
      expect(result).to eql(V.new(0...65536))
      # the level-1 subtrees of both tries are reused by reference, and
      # the last subtree of each side is reassembled from its (shared) leaves
      expect(root_of(result)[0][0]).to be(root_of(left)[0])
      expect(root_of(result)[0][30]).to be(root_of(left)[30])
      expect(root_of(result)[0][31][0]).to be(root_of(left)[31][0])
      expect(root_of(result)[1][0]).to be(root_of(right)[0])
      expect(root_of(result)[1][30]).to be(root_of(right)[30])
      expect(root_of(result)[1][31][0]).to be(root_of(right)[31][0])
    end

    it "shares every leaf when the left side ends on a leaf boundary" do
      left  = V.new(0...1024)
      right = V.new(1024...2048)
      result = left + right
      32.times do |i|
        expect(root_of(result)[0][i]).to be(root_of(left)[i])
        expect(root_of(result)[1][i]).to be(root_of(right)[i])
      end
    end

    it "shares the tall subtrees of a taller right side" do
      left  = V.new(0...1024)         # 1 level
      right = V.new(1024...33792)     # 2 levels
      result = left + right
      expect(result).to eql(V.new(0...33792))
      # right's full level-1 subtrees are reused by reference
      expect(root_of(result)[0][1]).to be(root_of(right)[0])
      expect(root_of(result)[0][31]).to be(root_of(right)[30])
    end

    it "only rebuilds the seam when the left side has a partially filled leaf" do
      left  = V.new(0...1057) # 33 full leaves, then a leaf holding 1 item
      right = V.new(1057...1157)
      result = left + right
      expect(result).to eql(V.new(0...1157))
      # left's full level-1 subtree and its other full leaves are shared;
      # only the partial leaf at the seam (and the nodes above it) are rebuilt
      expect(root_of(result)[0]).to be(root_of(left)[0])
      expect(root_of(result)[1][0]).to be(root_of(left)[1][0])
    end

    it "supports get, put and slice on the concatenated result" do
      result = V.new(0...1030) + V.new(1030...2080)
      expect(result.get(0)).to eq(0)
      expect(result.get(1029)).to eq(1029)
      expect(result.get(1030)).to eq(1030)
      expect(result.get(-1)).to eq(2079)
      expect(result.get(2080)).to be_nil
      expect(result.put(1030, :x).get(1030)).to eq(:x)
      expect(result[1025, 10]).to eql(V.new(1025...1035))
      expect(result[1025..1035]).to eql(V.new(1025..1035))
    end
  end
end
