require "spec_helper"
require "hamster/cursor"

describe Hamster::Cursor do
  describe ".new" do
    let(:root) { H["a" => V[1, 2], "b" => 3] }
    let(:cursor) { Hamster::Cursor.new(root) }

    it "focuses on the given node" do
      expect(cursor.focus).to equal(root)
    end

    it "starts at the root" do
      expect(cursor.root?).to be(true)
    end

    it "starts with depth 0" do
      expect(cursor.depth).to eql(0)
    end

    it "starts with an empty path" do
      expect(cursor.path).to eql(V[])
    end

    it "is frozen" do
      expect(cursor).to be_frozen
    end
  end
end
