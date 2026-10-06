require "spec_helper"
require "hamster/vector"

describe Hamster::Vector do
  describe "#edit" do
    let(:vector) { V[1, 2, 3] }

    it "returns one immutable vector with all editor changes" do
      result = vector.edit do |editor|
        editor.put(0, 10)
        editor.add(4)
        editor << 5
        editor.put(-1) { |value| value * 10 }
      end

      expect(result).to eql(V[10, 2, 3, 4, 50])
      expect(result).to be_frozen
      expect(vector).to eql(V[1, 2, 3])
    end

    it "supports block reads, padding, size, and enumeration" do
      result = vector.edit do |editor|
        expect(editor[0]).to eq(1)
        expect(editor.fetch(-1)).to eq(3)
        expect(editor.size).to eq(3)
        editor.put(5, 6)
        expect(editor.to_a).to eq([1, 2, 3, nil, nil, 6])
      end

      expect(result).to eql(V[1, 2, 3, nil, nil, 6])
    end

    it "returns the original vector when no changes are made" do
      result = vector.edit do |editor|
        editor.put(0, 1)
      end

      expect(result).to be(vector)
    end

    it "leaves the original vector unchanged when the block raises" do
      expect do
        vector.edit do |editor|
          editor.add(4)
          raise "boom"
        end
      end.to raise_error("boom")

      expect(vector).to eql(V[1, 2, 3])
      expect(vector).to be_frozen
    end

    it "does not allow a saved editor to be used after the block" do
      saved_editor = nil
      vector.edit { |editor| saved_editor = editor }

      expect { saved_editor.add(4) }.to raise_error(RuntimeError, /only be used/)
      expect(vector).to eql(V[1, 2, 3])
    end

    it "does not allow the editor to be used from another thread" do
      queue = Queue.new
      vector.edit do |editor|
        Thread.new do
          begin
            editor.add(4)
            queue.push(nil)
          rescue ThreadError => error
            queue.push(error)
          end
        end.join
      end

      expect(queue.pop.message).to match(/only be used on the thread/)
    end

    it "does not mutate array nodes shared with the original vector" do
      original_root = vector.instance_variable_get(:@root)

      result = vector.edit do |editor|
        editor.put(0, 99)
        editor.add(4)
      end

      expect(original_root).to eq([1, 2, 3])
      expect(original_root).to be_frozen
      expect(result.to_a).to eq([99, 2, 3, 4])
    end

    it "creates one leaf per full block instead of a path per update" do
      edited_node_count = nil
      result = V.empty.edit do |editor|
        1000.times { |index| editor.add(index) }
        edited_node_count = editor.instance_variable_get(:@session).nodes.count
      end

      persistent_arrays = nil
      GC.start
      GC.disable
      before = ObjectSpace.each_object(Array).count
      updated = V.empty
      1000.times { |index| updated = updated.add(index) }
      persistent_arrays = ObjectSpace.each_object(Array).count - before
      GC.enable

      expect(result.to_a).to eq((0...1000).to_a)
      expect(edited_node_count).to eq(33)
      expect(persistent_arrays).to be >= 2000
    end

    it "requires a block" do
      expect { vector.edit }.to raise_error(LocalJumpError)
    end

    it "does not allow the edit lifecycle to be ended manually" do
      expect do
        vector.edit { |editor| editor.result(vector.class) }
      end.to raise_error(NoMethodError)
    end
  end
end
