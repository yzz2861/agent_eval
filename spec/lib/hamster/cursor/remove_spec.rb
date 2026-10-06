require "spec_helper"
require "hamster/cursor"

describe Hamster::Cursor do
  describe "#remove" do
    let(:root) { H["a" => V["x", "y", "z"], "b" => H["k" => 1], "c" => 3] }
    let(:cursor) { Hamster::Cursor.new(root) }

    context "with a Hash parent" do
      let(:removed) { cursor.down("b").remove }

      it "moves the focus up to the parent" do
        expect(removed.path).to eql(V[])
        expect(removed.root?).to be(true)
      end

      it "deletes the key from the parent hash" do
        expect(removed.focus).to eql(H["a" => V["x", "y", "z"], "c" => 3])
      end

      it "is reflected in the rebuilt root" do
        expect(removed.to_root).to eql(H["a" => V["x", "y", "z"], "c" => 3])
      end
    end

    context "with a Vector parent" do
      let(:removed) { cursor.down("a").down(1).remove }

      it "moves the focus up to the parent vector" do
        expect(removed.path).to eql(V["a"])
        expect(removed.focus).to eql(V["x", "z"])
      end

      it "shifts later siblings down by one position" do
        # "z" used to be at index 2; after removing index 1 it sits at index 1
        expect(removed.down(1).focus).to eql("z")
      end

      it "is reflected in the rebuilt root" do
        expect(removed.to_root)
          .to eql(H["a" => V["x", "z"], "b" => H["k" => 1], "c" => 3])
      end
    end

    context "at the root" do
      it "raises Hamster::Cursor::Error" do
        expect { cursor.remove }.to raise_error(Hamster::Cursor::Error)
      end
    end

    it "leaves the original cursor unchanged" do
      child = cursor.down("b")
      child.remove
      expect(child.focus).to eql(H["k" => 1])
      expect(cursor.to_root).to eql(root)
    end
  end
end
