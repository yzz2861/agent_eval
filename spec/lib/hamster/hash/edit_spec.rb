require "spec_helper"
require "hamster/hash"

describe Hamster::Hash do
  describe "#edit" do
    let(:hash) { H["a" => 1, "b" => 2] }

    it "returns one immutable hash with all editor changes" do
      result = hash.edit do |editor|
        editor.put("c", 3)
        editor["d"] = 4
        editor.put("b") { |value| value + 20 }
      end

      expect(result).to eql(H["a" => 1, "b" => 22, "c" => 3, "d" => 4])
      expect(result).to be_frozen
      expect(hash).to eql(H["a" => 1, "b" => 2])
    end

    it "supports reads, deletes, and clearing" do
      result = hash.edit do |editor|
        expect(editor["a"]).to eq(1)
        expect(editor.size).to eq(2)
        editor.delete("a")
        editor.delete("missing")
        expect(editor.key?("a")).to be(false)
        expect(editor).not_to be_empty
        editor.clear
        expect(editor).to be_empty
      end

      expect(result).to eql(H.empty)
      expect(result).to be(Hamster::EmptyHash)
    end

    it "returns the original hash when no changes are made" do
      result = hash.edit do |editor|
        editor.put("a", 1)
      end

      expect(result).to be(hash)
    end

    it "leaves the original hash unchanged when the block raises" do
      expect do
        hash.edit do |editor|
          editor.put("c", 3)
          raise "boom"
        end
      end.to raise_error("boom")

      expect(hash).to eql(H["a" => 1, "b" => 2])
      expect(hash).to be_frozen
    end

    it "does not allow a saved editor to be used after the block" do
      saved_editor = nil
      hash.edit { |editor| saved_editor = editor }

      expect { saved_editor.put("c", 3) }.to raise_error(RuntimeError, /only be used/)
      expect(hash).to eql(H["a" => 1, "b" => 2])
    end

    it "does not allow the editor to be used from another thread" do
      saved_editor = nil
      queue = Queue.new
      hash.edit do |editor|
        saved_editor = editor
        Thread.new do
          begin
            editor.put("c", 3)
            queue.push(nil)
          rescue ThreadError => error
            queue.push(error)
          end
        end.join
      end

      expect(queue.pop.message).to match(/only be used on the thread/)
    end

    it "does not mutate trie nodes shared with the original hash" do
      original_root = hash.instance_variable_get(:@trie)
      original_entries = original_root.instance_variable_get(:@entries)

      hash.edit do |editor|
        editor.put("a", 99)
        editor.put("c", 3)
      end

      expect(original_entries).not_to be_frozen
      expect(hash["a"]).to eq(1)
      expect(hash.size).to eq(2)
    end

    it "preserves hash behavior when keys collide and entries are removed" do
      first = DeterministicHash.new("a", 1)
      second = DeterministicHash.new("b", 1)
      colliding_hash = H[first => 1, second => 2]

      result = colliding_hash.edit do |editor|
        editor.delete(first)
        editor.put(second, 22)
      end

      expect(result[first]).to be_nil
      expect(result[second]).to eq(22)
      expect(result.size).to eq(1)
    end

    it "requires a block" do
      expect { hash.edit }.to raise_error(LocalJumpError)
    end

    it "does not allow the edit lifecycle to be ended manually" do
      expect do
        hash.edit { |editor| editor.result(hash.class, nil) }
      end.to raise_error(NoMethodError)
    end

    it "reuses trie nodes along a long update chain" do
      measure_tries = lambda do |block|
        GC.start
        GC.disable
        before = ObjectSpace.each_object(Hamster::Trie).count
        block.call
        after = ObjectSpace.each_object(Hamster::Trie).count - before
        GC.enable
        after
      end

      operation = proc do
        updated = hash
        1000.times do |index|
          updated = updated.put(index.to_s, index)
        end
      end
      persistent = measure_tries.call(operation)
      edited_nodes = nil
      operation = proc do
        hash.edit do |editor|
          1000.times { |index| editor.put(index.to_s, index) }
          edited_nodes = editor.instance_variable_get(:@session).nodes.size
        end
      end
      measure_tries.call(operation)

      expect(edited_nodes).to be < persistent
      expect(edited_nodes).to be <= 400
    end
  end
end
