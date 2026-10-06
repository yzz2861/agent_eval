require "spec_helper"
require "hamster/vector"

describe Hamster::Vector do
  describe "#mutate" do
    let(:vector) { V["A", "B", "C"] }

    # Count the total number of objects allocated while running the given
    # block.
    def count_allocations
      GC.start
      before = GC.stat[:total_allocated_objects]
      yield
      GC.stat[:total_allocated_objects] - before
    end

    it "returns a Hamster::Vector with all edits applied" do
      result = vector.mutate do |m|
        m.set(0, "a")
        m[1] = "b"
        m.push("D")
        m << "E"
        m.pop
      end
      expect(result).to be_a(Hamster::Vector)
      expect(result).to eql(V["a", "b", "C", "D"])
    end

    it "leaves the original vector unchanged" do
      vector.mutate { |m| m.set(0, "a"); m.push("D"); m.pop }
      expect(vector).to eql(V["A", "B", "C"])
    end

    it "returns the same class of vector it was called on" do
      subclass = Class.new(Hamster::Vector)
      expect(subclass.new([1]).mutate { |m| m.push(2) }).to be_a(subclass)
    end

    it "supports reading the in-progress contents inside the block" do
      vector.mutate do |m|
        expect(m.get(0)).to eq("A")
        expect(m[1]).to eq("B")
        expect(m[-1]).to eq("C")
        expect(m[10]).to be_nil
        expect(m.size).to eq(3)
        expect(m.empty?).to be false
        m.set(0, "a")
        expect(m.get(0)).to eq("a")
      end
    end

    it "supports negative indexes for set" do
      expect(vector.mutate { |m| m.set(-1, "Z") }).to eql(V["A", "B", "Z"])
    end

    it "fills with nils when setting past the end" do
      expect(vector.mutate { |m| m.set(4, "E") }).to eql(V["A", "B", "C", nil, "E"])
    end

    it "raises IndexError for an out-of-bounds negative index" do
      expect { vector.mutate { |m| m.set(-4, "x") } }.to raise_error(IndexError)
    end

    it "returns the stored item from set" do
      vector.mutate do |m|
        expect(m.set(0, "a")).to eq("a")
        expect(m[1] = "b").to eq("b")
      end
    end

    it "returns the removed item from pop, or nil when empty" do
      vector.mutate do |m|
        expect(m.pop).to eq("C")
        expect(m.pop).to eq("B")
        expect(m.pop).to eq("A")
        expect(m.pop).to be_nil
      end
    end

    it "grows across block boundaries" do
      result = V.empty.mutate { |m| 2000.times { |i| m.push(i) } }
      expect(result).to eql(V.new((0...2000).to_a))
      expect(result.size).to eq(2000)
      expect(result.last).to eq(1999)
    end

    it "shrinks across block boundaries" do
      base = V.new((1..100).to_a)
      result = base.mutate { |m| 90.times { m.pop } }
      expect(result).to eql(V.new((1..10).to_a))
      expect(result.size).to eq(10)
    end

    it "can pop everything" do
      result = vector.mutate { |m| m.pop until m.empty? }
      expect(result).to eql(V.empty)
    end

    it "can push after popping everything" do
      result = vector.mutate do |m|
        m.pop until m.empty?
        m.push("x")
        m.push("y")
      end
      expect(result).to eql(V["x", "y"])
    end

    it "behaves like a Ruby Array across a long sequence of mixed edits" do
      base = V.new((0...50).to_a)
      result = base.mutate do |m|
        1000.times { |i| m.set(i % 50, i) }
        100.times { |i| m.push(i) }
        30.times { m.pop }
        m.set(-1, :last)
      end
      expected = (950..999).to_a + (0..68).to_a + [:last]
      expect(result.to_a).to eq(expected)
      expect(result).to eql(V.new(expected))
    end

    context "when the block raises" do
      it "propagates the error and keeps no changes" do
        expect {
          vector.mutate { |m| m.push("D"); raise "boom" }
        }.to raise_error("boom")
        expect(vector).to eql(V["A", "B", "C"])
      end

      it "invalidates the editor" do
        editor = nil
        vector.mutate { |m| editor = m; raise "boom" } rescue nil
        expect { editor.push("D") }.to raise_error(Hamster::TransientError)
      end
    end

    context "when the editor escapes the block" do
      it "raises TransientError on mutation" do
        editor = nil
        vector.mutate { |m| editor = m }
        expect { editor.push("D") }.to raise_error(Hamster::TransientError)
        expect { editor.set(0, "a") }.to raise_error(Hamster::TransientError)
        expect { editor.pop }.to raise_error(Hamster::TransientError)
      end

      it "raises TransientError on reads" do
        editor = nil
        vector.mutate { |m| editor = m }
        expect { editor.get(0) }.to raise_error(Hamster::TransientError)
        expect { editor.size }.to raise_error(Hamster::TransientError)
      end
    end

    it "raises TransientError when used from a different thread" do
      vector.mutate do |m|
        error = Thread.new {
          begin
            m.push("D")
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
      result = vector.mutate do |outer|
        outer.push("O")
        inner_result = vector.mutate { |inner| inner_editor = inner; inner.push("I") }
        expect(inner_result).to eql(V["A", "B", "C", "I"])
        expect { inner_editor.push("X") }.to raise_error(Hamster::TransientError)
        outer.push("P")
      end
      expect(result).to eql(V["A", "B", "C", "O", "P"])
    end

    it "produces a vector which supports further persistent updates" do
      result = vector.mutate { |m| 100.times { |i| m.push(i) } }
      expect(result.add("more").last).to eq("more")
      expect(result.pop.size).to eq(102)
      expect(result.put(0, "first").first).to eq("first")
      expect(result.to_a.size).to eq(103)
    end

    describe "object allocations" do
      it "allocates far fewer objects than an equivalent chain of persistent updates" do
        base = V.new((0...100).to_a)
        updates = 2000

        persistent_count = count_allocations do
          v = base
          updates.times { |i| v = v.put(i % 100, i) }
        end

        transient_count = count_allocations do
          base.mutate do |m|
            updates.times { |i| m.set(i % 100, i) }
          end
        end

        expect(transient_count).to be < persistent_count / 3
      end

      it "allocates far fewer objects than building a vector item by item" do
        items = 1000.times.to_a

        persistent_count = count_allocations do
          v = V.empty
          items.each { |i| v = v.add(i) }
        end

        transient_count = count_allocations do
          V.empty.mutate { |m| items.each { |i| m.push(i) } }
        end

        expect(transient_count).to be < persistent_count / 3
      end
    end
  end
end
