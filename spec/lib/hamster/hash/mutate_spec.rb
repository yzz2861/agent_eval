require "spec_helper"
require "hamster/hash"

describe Hamster::Hash do
  describe "#mutate" do
    let(:hash) { H["A" => 1, "B" => 2, "C" => 3] }

    # Count the number of Hamster::Trie nodes allocated while running the
    # given block.
    def count_trie_allocations
      count = 0
      original = Hamster::Trie.instance_method(:initialize)
      Hamster::Trie.send(:define_method, :initialize) do |*args|
        count += 1
        original.bind(self).call(*args)
      end
      yield
      count
    ensure
      Hamster::Trie.send(:define_method, :initialize, original)
    end

    it "returns a Hamster::Hash with all edits applied" do
      result = hash.mutate do |m|
        m.put("D", 4)
        m.store("E", 5)
        m["F"] = 6
        m.delete("A")
      end
      expect(result).to be_a(Hamster::Hash)
      expect(result).to eql(H["B" => 2, "C" => 3, "D" => 4, "E" => 5, "F" => 6])
    end

    it "leaves the original hash unchanged" do
      hash.mutate { |m| m.put("D", 4).delete("A") }
      expect(hash).to eql(H["A" => 1, "B" => 2, "C" => 3])
    end

    it "returns the same class of hash it was called on" do
      subclass = Class.new(Hamster::Hash)
      expect(subclass.new(a: 1).mutate { |m| m.put(:b, 2) }).to be_a(subclass)
    end

    it "supports reading the in-progress contents inside the block" do
      hash.mutate do |m|
        expect(m.get("A")).to eq(1)
        expect(m["B"]).to eq(2)
        expect(m.key?("C")).to be true
        expect(m.include?("ZZZ")).to be false
        expect(m.size).to eq(3)
        expect(m.empty?).to be false
        m.put("A", 100)
        expect(m.get("A")).to eq(100)
        expect(m.size).to eq(3)
      end
    end

    it "supports put with a block to transform the current value" do
      result = hash.mutate { |m| m.put("A") { |value| value * 10 } }
      expect(result).to eql(H["A" => 10, "B" => 2, "C" => 3])
    end

    it "returns the removed value from delete, or nil if the key is missing" do
      hash.mutate do |m|
        expect(m.delete("B")).to eq(2)
        expect(m.delete("ZZZ")).to be_nil
      end
    end

    it "preserves the default proc" do
      with_default = Hamster::Hash.new { |key| key * 2 }
      result = with_default.mutate { |m| m.put(1, 1) }
      expect(result[5]).to eq(10)
    end

    it "duplicates and freezes unfrozen string keys" do
      key = "mutable".dup
      result = hash.mutate { |m| m.put(key, 1) }
      expect(key).not_to be_frozen
      expect(result.key?("mutable")).to be true
    end

    context "when the block raises" do
      it "propagates the error and keeps no changes" do
        expect {
          hash.mutate { |m| m.put("D", 4); raise "boom" }
        }.to raise_error("boom")
        expect(hash).to eql(H["A" => 1, "B" => 2, "C" => 3])
      end

      it "invalidates the editor" do
        editor = nil
        hash.mutate { |m| editor = m; raise "boom" } rescue nil
        expect { editor.put("D", 4) }.to raise_error(Hamster::TransientError)
      end
    end

    context "when the editor escapes the block" do
      it "raises TransientError on mutation" do
        editor = nil
        hash.mutate { |m| editor = m }
        expect { editor.put("D", 4) }.to raise_error(Hamster::TransientError)
        expect { editor.delete("A") }.to raise_error(Hamster::TransientError)
      end

      it "raises TransientError on reads" do
        editor = nil
        hash.mutate { |m| editor = m }
        expect { editor.get("A") }.to raise_error(Hamster::TransientError)
        expect { editor.size }.to raise_error(Hamster::TransientError)
        expect { editor.key?("A") }.to raise_error(Hamster::TransientError)
      end
    end

    it "raises TransientError when used from a different thread" do
      hash.mutate do |m|
        error = Thread.new {
          begin
            m.put("D", 4)
            nil
          rescue => e
            e
          end
        }.value
        expect(error).to be_a(Hamster::TransientError)
      end
    end

    it "supports nested mutate blocks without invalidating the outer editor" do
      inner_editor = nil
      result = hash.mutate do |outer|
        outer.put("O", 0)
        inner_result = hash.mutate { |inner| inner_editor = inner; inner.put("I", 9) }
        expect(inner_result).to eql(H["A" => 1, "B" => 2, "C" => 3, "I" => 9])
        expect { inner_editor.put("X", 0) }.to raise_error(Hamster::TransientError)
        outer.put("P", 1)
      end
      expect(result).to eql(H["A" => 1, "B" => 2, "C" => 3, "O" => 0, "P" => 1])
    end

    context "with colliding keys" do
      it "applies puts and deletes correctly" do
        keys = 100.times.map { |i| DeterministicHash.new(i, i % 4) }
        result = H.empty.mutate do |m|
          keys.each { |k| m.put(k, k.value) }
        end
        expect(result.size).to eq(100)
        keys.each { |k| expect(result.get(k)).to eq(k.value) }

        result = result.mutate do |m|
          keys.each_with_index { |k, i| m.delete(k) if i.even? }
        end
        expect(result.size).to eq(50)
        keys.each_with_index do |k, i|
          if i.even?
            expect(result.key?(k)).to be false
          else
            expect(result.get(k)).to eq(k.value)
          end
        end
      end
    end

    it "matches RubyHash behavior across a long sequence of mixed edits" do
      reference = {}
      result = H.empty.mutate do |m|
        2000.times do |i|
          key = "key-#{i % 300}"
          if i % 3 == 0
            m.delete(key)
            reference.delete(key)
          else
            m.put(key, i)
            reference[key] = i
          end
        end
      end
      expect(result.size).to eq(reference.size)
      expect(result).to eq(reference)
    end

    describe "node allocations" do
      it "allocates far fewer trie nodes than an equivalent chain of persistent updates" do
        base = H.empty
        200.times { |i| base = base.put("key-#{i}", i) }
        updates = 1000

        persistent_count = count_trie_allocations do
          h = base
          updates.times { |i| h = h.put("key-#{i % 200}", i) }
        end

        transient_count = count_trie_allocations do
          base.mutate do |m|
            updates.times { |i| m.put("key-#{i % 200}", i) }
          end
        end

        expect(transient_count).to be < persistent_count / 5
      end

      it "allocates far fewer trie nodes than building a hash key by key" do
        keys = 500.times.map { |i| "key-#{i}" }

        persistent_count = count_trie_allocations do
          h = H.empty
          keys.each { |k| h = h.put(k, 1) }
        end

        transient_count = count_trie_allocations do
          H.empty.mutate { |m| keys.each { |k| m.put(k, 1) } }
        end

        expect(transient_count).to be < persistent_count / 5
      end
    end
  end
end
