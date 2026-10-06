require "spec_helper"
require "hamster/cursor"

describe Hamster::Cursor do
  describe "#down" do
    let(:root) do
      H[
        "hash"   => H["x" => 1, "y" => 2],
        "vector" => V["a", "b", "c"],
        "scalar" => 42
      ]
    end
    let(:cursor) { Hamster::Cursor.new(root) }

    context "on a Hash focus" do
      it "treats the argument as a key and focuses the associated value" do
        expect(cursor.down("hash").focus).to eql(H["x" => 1, "y" => 2])
      end

      it "records the key in the path" do
        expect(cursor.down("hash").path).to eql(V["hash"])
      end

      it "raises KeyError for a missing key" do
        expect { cursor.down("nope") }.to raise_error(KeyError)
      end

      it "does not confuse an Integer argument with a vector position" do
        hash = H[0 => "zero"]
        expect(Hamster::Cursor.new(hash).down(0).focus).to eql("zero")
      end
    end

    context "on a Vector focus" do
      let(:vector_cursor) { cursor.down("vector") }

      it "treats the argument as an index and focuses the element" do
        expect(vector_cursor.down(1).focus).to eql("b")
      end

      it "records the index in the path" do
        expect(vector_cursor.down(1).path).to eql(V["vector", 1])
      end

      it "normalizes negative indices" do
        expect(vector_cursor.down(-1).focus).to eql("c")
        expect(vector_cursor.down(-1).path).to eql(V["vector", 2])
      end

      it "raises IndexError when the index is out of bounds" do
        expect { vector_cursor.down(3) }.to raise_error(IndexError)
        expect { vector_cursor.down(-4) }.to raise_error(IndexError)
      end

      it "raises IndexError on an empty vector" do
        expect { Hamster::Cursor.new(V[]).down(0) }.to raise_error(IndexError)
      end

      it "raises TypeError when the argument is not an Integer" do
        expect { vector_cursor.down("a") }.to raise_error(TypeError)
      end
    end

    context "on a non-collection focus" do
      it "raises Hamster::Cursor::Error" do
        expect { cursor.down("scalar").down("anything") }
          .to raise_error(Hamster::Cursor::Error)
      end
    end

    it "can chain descents through mixed nesting" do
      nested = H["a" => V[H["b" => 1]]]
      expect(Hamster::Cursor.new(nested).down("a").down(0).down("b").focus).to eql(1)
    end

    it "increases the depth" do
      expect(cursor.down("hash").down("x").depth).to eql(2)
    end

    it "leaves the original cursor unchanged" do
      cursor.down("hash")
      expect(cursor.focus).to equal(root)
      expect(cursor.root?).to be(true)
    end
  end
end
