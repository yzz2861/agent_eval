require "spec_helper"
require "hamster/cursor"

describe Hamster::Cursor do
  let(:root) { H["a" => V[1, 2, 3], "b" => 4] }
  let(:cursor) { Hamster::Cursor.new(root).down("a").down(1) }

  describe "#replace" do
    it "returns a cursor focused on the new node" do
      expect(cursor.replace(99).focus).to eql(99)
    end

    it "keeps the same position" do
      expect(cursor.replace(99).path).to eql(V["a", 1])
    end

    it "leaves the original cursor unchanged" do
      cursor.replace(99)
      expect(cursor.focus).to eql(2)
    end

    it "is reflected in the rebuilt root" do
      expect(cursor.replace(99).to_root).to eql(H["a" => V[1, 99, 3], "b" => 4])
    end

    it "allows two cursors to fork from the same position" do
      fork_a = cursor.replace("A")
      fork_b = cursor.replace("B")
      expect(fork_a.to_root).to eql(H["a" => V[1, "A", 3], "b" => 4])
      expect(fork_b.to_root).to eql(H["a" => V[1, "B", 3], "b" => 4])
      expect(cursor.to_root).to eql(root)
    end
  end

  describe "#modify" do
    it "replaces the focus with the result of the block" do
      expect(cursor.modify { |value| value * 10 }.focus).to eql(20)
    end

    it "yields the current focus" do
      expect { |probe| cursor.modify(&probe) }.to yield_with_args(2)
    end

    it "leaves the original cursor unchanged" do
      cursor.modify { |value| value * 10 }
      expect(cursor.focus).to eql(2)
    end
  end
end
