require "spec_helper"
require "hamster/cursor"

describe Hamster::Cursor do
  describe "#up" do
    let(:root) { H["a" => V[1, 2, 3], "b" => 4] }
    let(:cursor) { Hamster::Cursor.new(root) }

    context "below the root" do
      it "moves the focus back to the parent" do
        expect(cursor.down("a").up.focus).to eql(root)
      end

      it "rebuilds the parent with a replaced focus" do
        parent = cursor.down("a").down(0).replace(99).up
        expect(parent.focus).to eql(V[99, 2, 3])
      end

      it "restores the full root when climbed repeatedly" do
        expect(cursor.down("a").down(0).replace(99).up.up.focus)
          .to eql(H["a" => V[99, 2, 3], "b" => 4])
      end

      it "shortens the path" do
        expect(cursor.down("a").down(0).up.path).to eql(V["a"])
      end

      it "leaves the original cursor unchanged" do
        child = cursor.down("a")
        child.up
        expect(child.focus).to eql(V[1, 2, 3])
      end
    end

    context "at the root" do
      it "raises Hamster::Cursor::Error" do
        expect { cursor.up }.to raise_error(Hamster::Cursor::Error)
      end
    end
  end
end
