require "spec_helper"
require "hamster/zipper"

describe Hamster::Zipper do
  let(:root) do
    H[
      :a => H[:x => 1, :y => 2],
      :b => V[10, 20, 30],
      :c => "keep"
    ]
  end
  let(:zipper) { Hamster::Zipper.new(root) }

  describe ".new" do
    it "focuses on the root" do
      expect(zipper.focus).to eq(root)
      expect(zipper.root?).to be(true)
    end

    it "is immutable" do
      expect(zipper).to be_frozen
      expect(zipper.down(:a)).to be_frozen
    end
  end

  describe "#down" do
    it "descends into a hash by key" do
      expect(zipper.down(:a).focus).to eq(H[:x => 1, :y => 2])
    end

    it "descends into a vector by zero-based index" do
      expect(zipper.down(:b).down(2).focus).to eq(30)
    end

    it "treats an integer locator as a key when the focus is a hash" do
      z = Hamster::Zipper.new(H[0 => :zero, 1 => :one]).down(1)
      expect(z.focus).to eq(:one)
    end

    it "never treats a locator as a key when the focus is a vector" do
      expect { Hamster::Zipper.new(V[:a, :b]).down(:a) }.to raise_error(IndexError)
    end

    it "raises KeyError for a missing hash key" do
      expect { zipper.down(:missing) }.to raise_error(KeyError)
    end

    it "raises IndexError for an out-of-range vector index" do
      v = zipper.down(:b)
      expect { v.down(3) }.to raise_error(IndexError)
      expect { v.down(-1) }.to raise_error(IndexError)
    end

    it "raises IndexError when descending into an empty vector" do
      expect { Hamster::Zipper.new(V[]).down(0) }.to raise_error(IndexError)
    end

    it "raises Error when the focus is not a collection" do
      expect { zipper.down(:c).down(0) }.to raise_error(Hamster::Zipper::Error)
    end

    it "tracks the path from the root" do
      expect(zipper.down(:b).down(1).path).to eq(V[:b, 1])
    end
  end

  describe "#up" do
    it "moves the focus back to the parent" do
      z = zipper.down(:b).down(1).up
      expect(z.focus).to eq(V[10, 20, 30])
      expect(z.up.focus).to eq(root)
    end

    it "rebuilds the parent with edits made below" do
      z = zipper.down(:a).down(:x).replace(99).up
      expect(z.focus).to eq(H[:x => 99, :y => 2])
    end

    it "raises Error at the root" do
      expect { zipper.up }.to raise_error(Hamster::Zipper::Error, /root/)
    end
  end

  describe "#next_sibling and #previous_sibling" do
    it "moves between vector elements by position" do
      z = zipper.down(:b).down(0)
      expect(z.next_sibling.focus).to eq(20)
      expect(z.next_sibling.next_sibling.focus).to eq(30)
      expect(z.next_sibling.next_sibling.previous_sibling.focus).to eq(20)
    end

    it "moves between hash values by key order" do
      hash = H[:a => 1, :b => 2, :c => 3]
      keys = hash.keys.to_a
      z = Hamster::Zipper.new(hash).down(keys[0]).next_sibling
      expect(z.focus).to eq(hash.get(keys[1]))
      expect(z.next_sibling.focus).to eq(hash.get(keys[2]))
      expect(z.next_sibling.previous_sibling.focus).to eq(hash.get(keys[1]))
    end

    it "preserves edits made to siblings when moving on" do
      z = zipper.down(:b).down(0).replace(11).next_sibling.replace(21)
      expect(z.root[:b]).to eq(V[10, 21, 30])
    end

    it "raises Error past the last sibling" do
      z = zipper.down(:b).down(2)
      expect { z.next_sibling }.to raise_error(Hamster::Zipper::Error, /last/)
    end

    it "raises Error before the first sibling" do
      z = zipper.down(:b).down(0)
      expect { z.previous_sibling }.to raise_error(Hamster::Zipper::Error, /first/)
    end

    it "raises Error at the edges of a hash parent" do
      hash = H[:a => 1, :b => 2]
      keys = hash.keys.to_a
      z = Hamster::Zipper.new(hash)
      expect { z.down(keys[0]).previous_sibling }.to raise_error(Hamster::Zipper::Error)
      expect { z.down(keys[1]).next_sibling }.to raise_error(Hamster::Zipper::Error)
    end

    it "raises Error at the root" do
      expect { zipper.next_sibling }.to raise_error(Hamster::Zipper::Error, /root/)
      expect { zipper.previous_sibling }.to raise_error(Hamster::Zipper::Error, /root/)
    end
  end

  describe "#replace and #modify" do
    it "replaces the focus" do
      z = zipper.down(:c).replace("changed")
      expect(z.focus).to eq("changed")
      expect(z.root).to eq(root.put(:c, "changed"))
    end

    it "replaces the focus with the result of a block" do
      z = zipper.down(:b).down(1).modify { |n| n * 10 }
      expect(z.root[:b]).to eq(V[10, 200, 30])
    end

    it "can replace the root itself" do
      expect(zipper.replace(V[1]).root).to eq(V[1])
    end

    it "leaves the original structure untouched" do
      zipper.down(:a).down(:x).replace(99)
      expect(root).to eq(H[:a => H[:x => 1, :y => 2], :b => V[10, 20, 30], :c => "keep"])
    end
  end

  describe "#insert" do
    it "puts a key/value into a hash focus" do
      z = zipper.down(:a).insert(:z, 26)
      expect(z.focus).to eq(H[:x => 1, :y => 2, :z => 26])
      expect(z.root[:a]).to eq(H[:x => 1, :y => 2, :z => 26])
    end

    it "inserts an item at an index of a vector focus" do
      z = zipper.down(:b).insert(1, 15)
      expect(z.focus).to eq(V[10, 15, 20, 30])
      expect(z.root[:b]).to eq(V[10, 15, 20, 30])
    end

    it "raises Error when the focus does not support insertion" do
      expect { zipper.down(:c).insert(0, 1) }.to raise_error(Hamster::Zipper::Error)
    end
  end

  describe "#delete" do
    it "raises Error at the root" do
      expect { zipper.delete }.to raise_error(Hamster::Zipper::Error, /root/)
    end

    context "with a vector parent" do
      let(:zipper) { Hamster::Zipper.new(H[:v => V[:a, :b, :c]]) }

      it "moves the focus to the element which slid into the vacated index" do
        z = zipper.down(:v).down(0).delete
        expect(z.focus).to eq(:b)
        expect(z.root).to eq(H[:v => V[:b, :c]])
      end

      it "moves the focus to the former left sibling when deleting the last element" do
        z = zipper.down(:v).down(2).delete
        expect(z.focus).to eq(:b)
        expect(z.root).to eq(H[:v => V[:a, :b]])
      end

      it "moves the focus to the parent when the vector becomes empty" do
        z = Hamster::Zipper.new(V[:a]).down(0).delete
        expect(z.focus).to eq(V[])
        expect(z.root?).to be(true)
        expect(z.root).to eq(V[])
      end

      it "can keep editing from the new focus" do
        z = zipper.down(:v).down(0).delete.replace(:B)
        expect(z.root).to eq(H[:v => V[:B, :c]])
      end
    end

    context "with a hash parent" do
      it "moves the focus to the parent hash with the key removed" do
        z = Hamster::Zipper.new(H[:a => 1, :b => 2]).down(:a).delete
        expect(z.focus).to eq(H[:b => 2])
        expect(z.root).to eq(H[:b => 2])
      end

      it "does not use positional rules for hash keys" do
        hash = H[:a => 1, :b => 2, :c => 3]
        z = Hamster::Zipper.new(hash).down(:b).delete
        expect(z.focus).to be_a(Hamster::Hash)
        expect(z.focus).to eq(H[:a => 1, :c => 3])
      end
    end
  end

  describe "immutability" do
    it "never modifies the receiver" do
      z = zipper.down(:a)
      z.down(:x).replace(99)
      z.up
      expect(z.focus).to eq(H[:x => 1, :y => 2])
      expect(z.root).to eq(root)
    end

    it "can fork two independent edits from the same position" do
      z = zipper.down(:a)
      z1 = z.down(:x).replace(10)
      z2 = z.down(:y).replace(20)
      expect(z1.root[:a]).to eq(H[:x => 10, :y => 2])
      expect(z2.root[:a]).to eq(H[:x => 1, :y => 20])
      expect(z.root).to eq(root)
    end
  end

  describe "#root" do
    it "returns an equal root when nothing was modified" do
      expect(zipper.down(:a).down(:x).up.up.root).to eq(root)
    end

    it "reflects edits made anywhere along the path" do
      z = zipper.down(:b).down(2).replace(31)
      expect(z.root).to eq(H[:a => H[:x => 1, :y => 2], :b => V[10, 20, 31], :c => "keep"])
    end

    it "only rebuilds the ancestors of the focus, sharing all other subtrees" do
      new_root = zipper.down(:a).down(:x).replace(99).root
      expect(new_root).to eq(H[:a => H[:x => 99, :y => 2], :b => V[10, 20, 30], :c => "keep"])
      expect(new_root[:b]).to equal(root[:b])
      expect(new_root[:c]).to equal(root[:c])
      expect(new_root[:a]).not_to equal(root[:a])
    end

    it "shares untouched subtrees after vector edits" do
      new_root = zipper.down(:b).down(0).replace(11).root
      expect(new_root[:a]).to equal(root[:a])
      expect(new_root[:b]).not_to equal(root[:b])
    end

    it "shares untouched subtrees after deletion" do
      new_root = zipper.down(:b).down(0).delete.root
      expect(new_root).to eq(H[:a => H[:x => 1, :y => 2], :b => V[20, 30], :c => "keep"])
      expect(new_root[:a]).to equal(root[:a])
      expect(new_root[:c]).to equal(root[:c])
    end

    it "shares untouched subtrees between two forks of the same zipper" do
      z = zipper.down(:a)
      r1 = z.down(:x).replace(10).root
      r2 = z.down(:y).replace(20).root
      expect(r1[:b]).to equal(root[:b])
      expect(r2[:b]).to equal(root[:b])
      expect(r1[:b]).to equal(r2[:b])
    end
  end
end
