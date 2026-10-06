# encoding: ascii-8bit
require 'spec_helper'
require 'stringio'
require 'tempfile'

describe MessagePack::StreamingWriter do
  # An IO-like destination that only supports #write (no #pos/#seek),
  # like a pipe or a socket.
  class NonSeekableSink
    attr_reader :bytes

    def initialize
      @bytes = +"".b
    end

    def write(string)
      @bytes << string
      string.bytesize
    end

    def flush
      self
    end
  end

  # An enumerable that can be iterated exactly once, proving the
  # implementation never pre-counts elements.
  class OneShotEnumerable
    include Enumerable

    def initialize(values)
      @values = values
      @used = false
    end

    def each
      raise "iterated twice: elements were counted in advance" if @used
      @used = true
      @values.each { |v| yield v }
    end
  end

  def unpack_all(bytes)
    unpacker = MessagePack::Unpacker.new
    unpacker.feed(bytes)
    unpacker.each.to_a
  end

  let(:values) { (1..10).to_a }

  describe "with a seekable IO" do
    let(:io) { StringIO.new("".b) }
    let(:packer) { MessagePack::Packer.new(io) }

    it "writes an array whose size is unknown upfront" do
      count = packer.write_streaming_array do |array|
        values.each { |v| array.write(v) }
      end
      packer.flush

      expect(count).to eq(values.size)
      expect(unpack_all(io.string)).to eq([values])
    end

    it "always reserves a 32-bit header, valid at every width boundary" do
      [0, 1, 15, 16, 65535, 65536].each do |size|
        io = StringIO.new("".b)
        packer = MessagePack::Packer.new(io)
        packer.write_streaming_array do |array|
          size.times { |i| array.write(i) }
        end
        packer.flush

        expect(io.string.getbyte(0)).to eq(0xdd)
        expect(MessagePack.unpack(io.string)).to eq((0...size).to_a)
      end
    end

    it "supports maps via write_pair and alternating writes" do
      packer.write_streaming_map do |map|
        map.write_pair("a", 1)
        map.write("b")
        map.write(2)
      end
      packer.flush

      expect(io.string.getbyte(0)).to eq(0xdf)
      expect(MessagePack.unpack(io.string)).to eq({"a" => 1, "b" => 2})
    end

    it "supports nested streaming collections" do
      packer.write_streaming_array do |array|
        array.write(1)
        array.write_streaming_map do |map|
          map.write("nested")
          map.write_streaming_array do |inner|
            inner.write(true)
            inner.write(nil)
          end
        end
        array.write_streaming_array do |inner|
          inner.write("x")
        end
      end
      packer.flush

      expect(MessagePack.unpack(io.string)).to eq([1, {"nested" => [true, nil]}, ["x"]])
    end

    it "keeps surrounding values intact" do
      packer.write("before")
      packer.write_streaming_array { |array| array.write(1) }
      packer.write("after")
      packer.flush

      expect(unpack_all(io.string)).to eq(["before", [1], "after"])
    end

    it "rolls the IO back when the enumerator raises midway" do
      packer.write("prefix")
      expect {
        packer.write_streaming_array do |array|
          values.each do |v|
            raise "boom" if v == 4
            array.write(v)
          end
        end
      }.to raise_error("boom")

      expect(unpack_all(io.string)).to eq(["prefix"])
    end

    it "refuses to commit a map with a dangling key" do
      expect {
        packer.write_streaming_map do |map|
          map.write("key-without-value")
        end
      }.to raise_error(MessagePack::StreamingWriter::IncompleteMapError)

      expect(io.string).to be_empty
    end

    it "rejects writes after the collection is finished" do
      writer = nil
      packer.write_streaming_array { |array| writer = array }
      expect { writer.write(1) }.to raise_error(MessagePack::StreamingWriter::Error)
    end

    it "rolls back a real file, truncating the partial collection" do
      Tempfile.open("streaming") do |file|
        packer = MessagePack::Packer.new(file)
        packer.write("prefix")
        expect {
          packer.write_streaming_array do |array|
            array.write(1)
            raise "boom"
          end
        }.to raise_error("boom")
        packer.flush

        file.rewind
        expect(unpack_all(file.read)).to eq(["prefix"])
      end
    end
  end

  describe "with a non-seekable stream" do
    let(:sink) { NonSeekableSink.new }
    let(:packer) { MessagePack::Packer.new(sink) }

    it "writes an array whose size is unknown upfront" do
      count = packer.write_streaming_array do |array|
        values.each { |v| array << v }
      end
      packer.flush

      expect(count).to eq(values.size)
      expect(unpack_all(sink.bytes)).to eq([values])
    end

    it "emits a minimal-width header at every width boundary" do
      {
        0 => 0x90,
        15 => 0x9f,
        16 => 0xdc,
        65535 => 0xdc,
        65536 => 0xdd,
      }.each do |size, first_byte|
        sink = NonSeekableSink.new
        packer = MessagePack::Packer.new(sink)
        packer.write_streaming_array do |array|
          size.times { |i| array.write(i) }
        end
        packer.flush

        expect(sink.bytes.getbyte(0)).to eq(first_byte)
        expect(MessagePack.unpack(sink.bytes)).to eq((0...size).to_a)
      end
    end

    it "emits minimal-width map headers" do
      packer.write_streaming_map do |map|
        16.times { |i| map.write_pair("k#{i}", i) }
      end
      packer.flush

      expect(sink.bytes.getbyte(0)).to eq(0xde)
      expect(MessagePack.unpack(sink.bytes)).to eq(
        (0...16).map { |i| ["k#{i}", i] }.to_h
      )
    end

    it "supports nested streaming collections" do
      packer.write_streaming_map do |map|
        map.write("list")
        map.write_streaming_array do |array|
          array.write(1)
          array.write_streaming_map do |inner|
            inner.write_pair("deep", true)
          end
        end
      end
      packer.flush

      expect(MessagePack.unpack(sink.bytes)).to eq({"list" => [1, {"deep" => true}]})
    end

    it "writes nothing when the enumerator raises midway" do
      expect {
        packer.write_streaming_array do |array|
          values.each do |v|
            raise "boom" if v == 4
            array.write(v)
          end
        end
      }.to raise_error("boom")

      expect(sink.bytes).to be_empty
    end

    it "refuses to commit a map with a dangling key and writes nothing" do
      expect {
        packer.write_streaming_map do |map|
          map.write_pair("a", 1)
          map.write("lonely-key")
        end
      }.to raise_error(MessagePack::StreamingWriter::IncompleteMapError)

      expect(sink.bytes).to be_empty
    end

    it "keeps custom ext type registrations while staging" do
      stub_const("Point", Struct.new(:x, :y))
      packer.register_type(0x10, Point) { |point| [point.x, point.y].pack("C2") }
      packer.write_streaming_array do |array|
        array.write(Point.new(1, 2))
      end
      packer.flush

      unpacker = MessagePack::Unpacker.new
      unpacker.register_type(0x10) { |data| data.unpack("C2") }
      unpacker.feed(sink.bytes)
      expect(unpacker.each.to_a).to eq([[[1, 2]]])
    end
  end

  describe "with a packer without IO" do
    it "collects into the packer buffer" do
      packer = MessagePack::Packer.new
      packer.write_streaming_array do |array|
        values.each { |v| array.write(v) }
      end

      expect(MessagePack.unpack(packer.to_str)).to eq(values)
    end
  end

  describe "with a one-shot enumerable" do
    it "never iterates the source twice (seekable)" do
      io = StringIO.new("".b)
      packer = MessagePack::Packer.new(io)
      packer.write_streaming_array do |array|
        OneShotEnumerable.new(values).each { |v| array.write(v) }
      end
      packer.flush

      expect(MessagePack.unpack(io.string)).to eq(values)
    end

    it "never iterates the source twice (non-seekable)" do
      sink = NonSeekableSink.new
      packer = MessagePack::Packer.new(sink)
      packer.write_streaming_map do |map|
        OneShotEnumerable.new(values).each { |v| map.write_pair(v, v * 2) }
      end
      packer.flush

      expect(MessagePack.unpack(sink.bytes)).to eq(values.map { |v| [v, v * 2] }.to_h)
    end
  end
end
