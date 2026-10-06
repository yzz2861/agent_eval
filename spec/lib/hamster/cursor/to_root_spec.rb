require "spec_helper"
require "hamster/cursor"

describe Hamster::Cursor do
  describe "#to_root" do
    let(:untouched_hash) { H["keep" => V[1, 2, 3]] }
    let(:untouched_vector) { V["a", "b"] }
    let(:root) do
      H[
        "hash"   => untouched_hash,
        "vector" => V[10, V[20, 21], 12],
        "other"  => untouched_vector
      ]
    end
    let(:cursor) { Hamster::Cursor.new(root) }

    context "at the root" do
      it "returns the focus itself" do
        expect(cursor.to_root).to equal(root)
      end
    end

    context "with no modifications" do
      it "returns the identical root object, rebuilding nothing" do
        expect(cursor.down("vector").down(1).down(0).to_root).to equal(root)
      end
    end

    context "after replacing a deeply nested node" do
      let(:new_root) do
        cursor.down("vector").down(1).down(0).replace(99).to_root
      end

      it "produces the expected structure" do
        expect(new_root).to eql(
          H["hash" => untouched_hash, "vector" => V[10, V[99, 21], 12], "other" => untouched_vector]
        )
      end

      it "shares untouched sibling branches with the original" do
        expect(new_root.get("hash")).to equal(untouched_hash)
        expect(new_root.get("other")).to equal(untouched_vector)
      end

      it "shares untouched elements inside the rebuilt branch" do
        expect(new_root.get("vector").get(0)).to eql(10)
        expect(new_root.get("vector").get(1).get(1)).to eql(21)
      end

      it "rebuilds only the ancestors along the path" do
        expect(new_root.get("vector")).not_to equal(root.get("vector"))
        expect(new_root.get("vector").get(1)).not_to equal(root.get("vector").get(1))
      end

      it "leaves the original root untouched" do
        new_root
        expect(root).to eql(
          H["hash" => untouched_hash, "vector" => V[10, V[20, 21], 12], "other" => untouched_vector]
        )
      end
    end

    context "after removing a node" do
      it "shares untouched branches with the original" do
        new_root = cursor.down("hash").remove.to_root
        expect(new_root).to eql(H["vector" => V[10, V[20, 21], 12], "other" => untouched_vector])
        expect(new_root.get("vector")).to equal(root.get("vector"))
        expect(new_root.get("other")).to equal(untouched_vector)
      end
    end

    context "with two cursors forked from the same position" do
      it "lets each fork rebuild independently while sharing untouched branches" do
        pivot = cursor.down("vector").down(1)
        fork_a = pivot.down(0).replace("A").to_root
        fork_b = pivot.down(1).replace("B").to_root

        expect(fork_a.get("vector").get(1)).to eql(V["A", 21])
        expect(fork_b.get("vector").get(1)).to eql(V[20, "B"])
        expect(fork_a.get("hash")).to equal(untouched_hash)
        expect(fork_b.get("hash")).to equal(untouched_hash)
        expect(root.get("vector").get(1)).to eql(V[20, 21])
      end
    end
  end
end
