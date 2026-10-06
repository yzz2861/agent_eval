require "spec_helper"
require "hamster/cursor"

describe Hamster::Cursor do
  let(:root) { H["hash" => H["x" => 1], "vector" => V["a", "b", "c"]] }
  let(:cursor) { Hamster::Cursor.new(root) }
  let(:hash_cursor) { cursor.down("hash") }
  let(:vector_cursor) { cursor.down("vector") }

  describe "#put" do
    it "stores the value under the key in the focused hash" do
      expect(hash_cursor.put("y", 2).focus).to eql(H["x" => 1, "y" => 2])
    end

    it "supports the block form" do
      expect(hash_cursor.put("x") { |old| old * 10 }.focus).to eql(H["x" => 10])
    end

    it "keeps the focus on the updated hash" do
      updated = hash_cursor.put("y", 2)
      expect(updated.path).to eql(V["hash"])
      expect(updated.to_root).to eql(H["hash" => H["x" => 1, "y" => 2],
                                       "vector" => V["a", "b", "c"]])
    end

    it "raises Hamster::Cursor::Error on a Vector focus" do
      expect { vector_cursor.put("x", 1) }.to raise_error(Hamster::Cursor::Error)
    end

    it "leaves the original cursor unchanged" do
      hash_cursor.put("y", 2)
      expect(hash_cursor.focus).to eql(H["x" => 1])
    end
  end

  describe "#insert" do
    it "inserts items into the focused vector" do
      expect(vector_cursor.insert(1, "X", "Y").focus).to eql(V["a", "X", "Y", "b", "c"])
    end

    it "keeps the focus on the updated vector" do
      expect(vector_cursor.insert(0, "X").path).to eql(V["vector"])
    end

    it "raises Hamster::Cursor::Error on a Hash focus" do
      expect { hash_cursor.insert(0, "X") }.to raise_error(Hamster::Cursor::Error)
    end

    it "leaves the original cursor unchanged" do
      vector_cursor.insert(0, "X")
      expect(vector_cursor.focus).to eql(V["a", "b", "c"])
    end
  end

  describe "#delete" do
    it "removes the key from the focused hash" do
      expect(hash_cursor.delete("x").focus).to eql(H[])
    end

    it "keeps the focus on the hash when the key is missing" do
      expect(hash_cursor.delete("nope").focus).to eql(H["x" => 1])
    end

    it "raises Hamster::Cursor::Error on a Vector focus" do
      expect { vector_cursor.delete(0) }.to raise_error(Hamster::Cursor::Error)
    end

    it "leaves the original cursor unchanged" do
      hash_cursor.delete("x")
      expect(hash_cursor.focus).to eql(H["x" => 1])
    end
  end

  describe "#delete_at" do
    it "removes the element at the index from the focused vector" do
      expect(vector_cursor.delete_at(1).focus).to eql(V["a", "c"])
    end

    it "supports negative indices" do
      expect(vector_cursor.delete_at(-1).focus).to eql(V["a", "b"])
    end

    it "raises Hamster::Cursor::Error on a Hash focus" do
      expect { hash_cursor.delete_at(0) }.to raise_error(Hamster::Cursor::Error)
    end

    it "leaves the original cursor unchanged" do
      vector_cursor.delete_at(1)
      expect(vector_cursor.focus).to eql(V["a", "b", "c"])
    end
  end
end
