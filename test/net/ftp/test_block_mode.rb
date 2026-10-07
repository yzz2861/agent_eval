# frozen_string_literal: true

require "net/ftp"
require "test/unit"

class FTPBlockModeTest < Test::Unit::TestCase
  BM = Net::FTP::BlockMode

  # Builds a wire frame using only Array#pack, independently of the
  # BlockMode encoder, so the fixture validates the documented wire
  # format rather than echoing the implementation.
  def self.frame(flags, payload)
    payload = payload.b
    [flags, payload.bytesize].pack("Cn") << payload
  end

  def frame(flags, payload)
    self.class.frame(flags, payload)
  end
  private :frame

  DATA1 = (0..99).map(&:chr).join.b
  DATA2 = (100..199).map(&:chr).join.b
  DATA3 = (200..255).map(&:chr).join.b

  # A few hundred bytes of fixed wire data exercising every descriptor:
  #   data (flags 0)
  #   data + EOR  (record 1 ends)
  #   data (flags 0, record 2 starts)
  #   restart marker (0x10, stands alone)
  #   data (flags 0, record 2 continues)
  #   data + EOR  (record 2 ends)
  #   zero length data + EOR (an empty record)
  #   zero length data + EOR + EOF (final block)
  FIXTURE = [
    frame(0x00, DATA1),
    frame(0x80, DATA2),
    frame(0x00, DATA3),
    frame(0x10, "CHKPT0001"),
    frame(0x00, "tail-part"),
    frame(0x80, "tail-end"),
    frame(0x80, ""),
    frame(0xc0, ""),
  ].join.b

  def test_fixture_size_is_bounded
    assert_operator FIXTURE.bytesize, :<, 600
    assert_operator FIXTURE.bytesize, :>, 300
  end

  def test_decode_fixed_fixture
    events = BM.decode(FIXTURE)
    assert_equal([:data, :data, :data, :restart_marker, :data, :data,
                  :data, :data], events.map(&:type))
    assert_equal(DATA1, events[0].payload)
    assert_equal(false, events[0].end_of_record?)
    assert_equal(DATA2, events[1].payload)
    assert_equal(true, events[1].end_of_record?)
    assert_equal(DATA3, events[2].payload)
    assert_equal("CHKPT0001", events[3].payload)
    assert_equal(true, events[3].restart_marker?)
    assert_equal("tail-part", events[4].payload)
    assert_equal("tail-end", events[5].payload)
    assert_equal(true, events[5].end_of_record?)
    assert_equal("", events[6].payload)
    assert_equal(true, events[6].end_of_record?)
    assert_equal("", events[7].payload)
    assert_equal(true, events[7].end_of_record?)
    assert_equal(true, events[7].end_of_file?)
    assert_equal(false, events[7].suspected_errors?)
  end

  def test_decode_with_arbitrary_tcp_fragments
    [1, 2, 3, 5, 7, 64, 256, FIXTURE.bytesize].each do |slice|
      decoder = BM::Decoder.new
      events = []
      offset = 0
      while offset < FIXTURE.bytesize
        decoder.feed(FIXTURE.byteslice(offset, slice)) { |e| events << e }
        offset += slice
      end
      decoder.finish
      assert_equal(BM.decode(FIXTURE).map(&:type), events.map(&:type),
                   "slicing by #{slice}")
      assert_equal(BM.decode(FIXTURE).map(&:payload), events.map(&:payload),
                   "payloads slicing by #{slice}")
    end
  end

  def test_decode_byte_by_byte
    decoder = BM::Decoder.new
    events = []
    FIXTURE.each_byte do |byte|
      decoder.feed(byte.chr) { |e| events << e }
    end
    decoder.finish
    assert_equal(8, events.size)
    assert(decoder.end_of_file?)
  end

  def test_decode_partial_header_then_rest
    decoder = BM::Decoder.new
    events = []
    decoder.feed(FIXTURE.byteslice(0, 2)) { |e| events << e }
    assert_equal([], events)
    decoder.feed(FIXTURE.byteslice(2, FIXTURE.bytesize - 2)) do |e|
      events << e
    end
    decoder.finish
    assert_equal(8, events.size)
  end

  def test_decode_truncated_header
    assert_raise(Net::FTPProtoError) do
      decoder = BM::Decoder.new
      decoder.feed("\x80".b)
      decoder.finish
    end
  end

  def test_decode_truncated_body
    wire = frame(0x00, "abcdef")
    [4, 5, 6, 8].each do |cut|
      assert_raise(Net::FTPProtoError, "cut at #{cut}") do
        decoder = BM::Decoder.new
        decoder.feed(wire.byteslice(0, cut)) {}
        decoder.feed(nil) {}
        decoder.finish
      end
    end
  end

  def test_decode_reserved_descriptor_bit
    wire = frame(0x01, "x")
    assert_raise(Net::FTPProtoError) { BM.decode(wire) }
  end

  def test_decode_unknown_descriptor_bit
    wire = frame(0x08, "x")
    assert_raise(Net::FTPProtoError) { BM.decode(wire) }
  end

  def test_decode_restart_marker_with_eor
    wire = frame(0x90, "m1")
    assert_raise(Net::FTPProtoError) { BM.decode(wire) }
  end

  def test_decode_restart_marker_with_eof
    wire = frame(0x50, "m1")
    assert_raise(Net::FTPProtoError) { BM.decode(wire) }
  end

  def test_decode_empty_restart_marker
    wire = frame(0x10, "")
    assert_raise(Net::FTPProtoError) { BM.decode(wire) }
  end

  def test_decode_non_printable_restart_marker
    wire = frame(0x10, "bad\x00marker")
    assert_raise(Net::FTPProtoError) { BM.decode(wire) }
  end

  def test_decode_data_after_eof
    wire = frame(0x40, "") + frame(0x00, "extra")
    assert_raise(Net::FTPProtoError) { BM.decode(wire) }
  end

  def test_decode_header_after_eof
    wire = frame(0x40, "") + frame(0x40, "")
    assert_raise(Net::FTPProtoError) { BM.decode(wire) }
  end

  def test_decode_missing_eof
    wire = frame(0x80, "record")
    assert_raise(Net::FTPProtoError) { BM.decode(wire) }
  end

  def test_decode_close_without_any_block
    decoder = BM::Decoder.new
    assert_raise(Net::FTPProtoError) { decoder.finish }
  end

  def test_suspected_errors_flag
    wire = frame(0x60, "oops")
    events = BM.decode(wire)
    assert_equal(true, events[0].suspected_errors?)
    assert_equal(true, events[0].end_of_file?)
    assert_equal("oops", events[0].payload)
  end

  def test_encode_data_wire_format
    assert_equal([0x80, 0x00, 0x03].pack("C3") + "abc".b,
                 BM.encode_data("abc", BM::DESCRIPTOR_END_OF_RECORD))
  end

  def test_encode_data_max_length
    body = "x" * BM::MAX_BLOCK_LENGTH
    frame_data = BM.encode_data(body, 0)
    assert_equal(BM::MAX_BLOCK_LENGTH + 3, frame_data.bytesize)
    assert_equal(body, frame_data.byteslice(3, BM::MAX_BLOCK_LENGTH))
  end

  def test_encode_data_too_large
    assert_raise(ArgumentError) do
      BM.encode_data("x" * (BM::MAX_BLOCK_LENGTH + 1), 0)
    end
  end

  def test_encode_data_rejects_restart_flag
    assert_raise(ArgumentError) do
      BM.encode_data("x", BM::DESCRIPTOR_RESTART_MARKER)
    end
  end

  def test_encode_data_rejects_reserved_flag
    assert_raise(ArgumentError) { BM.encode_data("x", 1) }
  end

  def test_encode_restart_marker
    wire = BM.encode_restart_marker("M-42")
    assert_equal([0x10, 0x00, 0x04].pack("C3") + "M-42".b, wire)
  end

  def test_encode_restart_marker_validation
    assert_raise(ArgumentError) { BM.encode_restart_marker("") }
    assert_raise(ArgumentError) { BM.encode_restart_marker("bad\n") }
    assert_raise(ArgumentError) do
      BM.encode_restart_marker("x" * (BM::MAX_BLOCK_LENGTH + 1))
    end
  end

  def test_encode_records_bounded_blocks
    frames = []
    BM.encode_records(["hello", "world!"], 3) { |f| frames << f }
    flags_lengths = frames.map do |f|
      [f.getbyte(0), (f.getbyte(1) << 8) | f.getbyte(2), f.bytesize - 3]
    end
    assert_equal([
      [0x00, 3, 3], # hel
      [0x80, 2, 2], # lo (EOR)
      [0x00, 3, 3], # wor
      [0xc0, 3, 3], # ld! (EOR + EOF merged)
    ], flags_lengths)
    events = BM.decode(frames.join)
    assert_equal("hello".b, events[0].payload + events[1].payload)
    assert_equal("world!".b, events[2].payload + events[3].payload)
  end

  def test_encode_records_empty_records_and_empty_file
    frames = []
    BM.encode_records([], 10) { |f| frames << f }
    assert_equal(1, frames.size)
    assert_equal([0x40, 0x00, 0x00].pack("C3"), frames.first)

    frames = []
    BM.encode_records([""], 10) { |f| frames << f }
    events = BM.decode(frames.join)
    assert_equal([:data], events.map(&:type))
    assert_equal("", events[0].payload)
    assert(events[0].end_of_record?)
    assert(events[0].end_of_file?)
  end

  def test_encode_records_with_restart_marker
    frames = []
    records = [BM.record("a"), BM.restart_marker("R1"), BM.record("b")]
    BM.encode_records(records, 10) { |f| frames << f }
    events = BM.decode(frames.join)
    assert_equal([:data, :restart_marker, :data], events.map(&:type))
    assert_equal("R1", events[1].payload)
    assert(events[2].end_of_file?)
  end

  def test_encode_records_rejects_bad_blocksize
    assert_raise(ArgumentError) do
      BM.encode_records(["x"], 0) {}
    end
    assert_raise(ArgumentError) do
      BM.encode_records(["x"], BM::MAX_BLOCK_LENGTH + 1) {}
    end
  end

  def test_encode_records_rejects_bad_event
    assert_raise(ArgumentError) do
      BM.encode_records([42]) {}
    end
  end

  def test_roundtrip_records_spanning_blocks
    records = ["a" * (65535 * 2 + 7), "", "last"]
    wire = String.new.b
    BM.encode_records(records, 4096) { |f| wire << f }
    events = BM.decode(wire)
    assembled = []
    current = String.new.b
    events.each do |event|
      next unless event.data?
      current << event.payload
      if event.end_of_record?
        assembled << current
        current = String.new.b
      end
    end
    assert_equal(records, assembled)
  end

  def test_event_predicates
    event = BM::Event.new(type: :data, payload: "x".b)
    event.descriptor_flags = BM::DESCRIPTOR_SUSPECTED_ERRORS
    assert(event.data?)
    assert(!event.record?)
    assert(!event.restart_marker?)
    assert(event.suspected_errors?)
    assert(!event.end_of_record?)
    marker = BM.restart_marker("m")
    assert(marker.restart_marker?)
  end
end
