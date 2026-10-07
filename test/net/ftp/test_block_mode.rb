# frozen_string_literal: true

require "net/ftp"
require "test/unit"
require "stringio"

class FTPBlockModeTest < Test::Unit::TestCase
  EOR = Net::FTP::BlockMode::END_OF_RECORD
  EOF = Net::FTP::BlockMode::END_OF_DATA
  RESTART = Net::FTP::BlockMode::RESTART_MARKER
  ERRORF = Net::FTP::BlockMode::BLOCK_ERROR

  FIXTURE_DIR = File.expand_path("../fixtures/block_mode", __dir__)

  def frame(descriptor, body)
    [descriptor, body.bytesize].pack("Cn") << body
  end

  def decode(wire, mode: :records, chunk: 1)
    decoder = Net::FTP::BlockMode::BlockDecoder.new(mode: mode)
    events = []
    wire.bytes.each_slice(chunk) do |bytes|
      decoder.feed(bytes.pack("C*")) { |event, data| events << [event, data] }
    end
    decoder.finish
    events
  end

  def encode(records, block_size: 4)
    output = StringIO.new(String.new(encoding: Encoding::ASCII_8BIT))
    encoder = Net::FTP::BlockMode::BlockEncoder.new(output, block_size: block_size)
    records.each { |record| encoder.write_record(record) }
    encoder.finish
    output.string
  end

  # ---- fixture interop ----

  def test_fixture_decodes_records
    wire = File.binread(File.join(FIXTURE_DIR, "sample.bin"))
    meta = eval(File.read(File.join(FIXTURE_DIR, "sample.meta.rb")),
                binding, __FILE__, __LINE__)

    [1, 2, 3, 7, 64, wire.bytesize].each do |chunk|
      events = decode(wire, mode: :records, chunk: chunk)
      assert_equal(
        [[:record, meta[:record1]],
         [:restart_marker, meta[:marker]],
         [:record, meta[:record2]],
         [:record, meta[:trailing]],
         [:eof, nil]],
        events,
        "chunk size #{chunk}"
      )
    end
  end

  def test_fixture_bytes_mode_excludes_marker
    wire = File.binread(File.join(FIXTURE_DIR, "sample.bin"))
    meta = eval(File.read(File.join(FIXTURE_DIR, "sample.meta.rb")),
                binding, __FILE__, __LINE__)

    events = decode(wire, mode: :bytes, chunk: 5)
    data = events.select { |event, _| event == :data }.map(&:last).join
    markers = events.select { |event, _| event == :restart_marker }
    assert_equal(meta[:record1] + meta[:record2] + meta[:trailing],
                 data)
    assert_equal([[:restart_marker, meta[:marker]]], markers)
    assert_equal(:eof, events.last.first)
    assert_not_match(/checkpoint/, data)
  end

  def test_fixture_blocks_mode_exposes_descriptors
    wire = File.binread(File.join(FIXTURE_DIR, "sample.bin"))
    events = decode(wire, mode: :blocks, chunk: 11)
    descriptors = events.map { |event, (d, _)| event == :block ? d : nil }.compact
    assert_equal([0, 0, EOR, EOR, EOR | EOF], descriptors)
    assert_equal(:eof, events.last.first)
    assert_equal([[:restart_marker, "checkpoint-7"]],
                 events.select { |event, _| event == :restart_marker })
  end

  def test_fixture_eof_block_carrying_data
    wire = File.binread(File.join(FIXTURE_DIR,
                                  "sample_eof_with_data.bin"))
    events = decode(wire, mode: :records, chunk: 3)
    assert_equal(:eof, events.last.first)
    records = events.select { |event, _| event == :record }.map(&:last)
    assert_equal(2, records.size)
    assert_equal("tail-data-cccccccc", records.last)
  end

  # ---- encoder ----

  def test_encoder_record_bounded_blocks
    wire = encode(["ab", "cdefg"], block_size: 4)
    expected = frame(EOR, "ab") <<
               frame(0, "cdef") << frame(EOR, "g") <<
               frame(EOF, "")
    assert_equal(expected.b, wire)
  end

  def test_encoder_exact_multiple_emits_empty_eor_then_eof
    wire = encode(["abcd"], block_size: 4)
    expected = frame(0, "abcd") << frame(EOR, "") << frame(EOF, "")
    assert_equal(expected.b, wire)
  end

  def test_encoder_bytes_and_marker_and_eof
    output = StringIO.new(String.new(encoding: Encoding::ASCII_8BIT))
    encoder = Net::FTP::BlockMode::BlockEncoder.new(output, block_size: 3)
    encoder.write("xyz")
    encoder.write_restart_marker("m")
    encoder.finish
    expected = frame(0, "xyz") << frame(RESTART, "m") <<
               frame(EOF, "")
    assert_equal(expected.b, output.string)
  end

  def test_encoder_marker_flushes_pending_data
    output = StringIO.new(String.new(encoding: Encoding::ASCII_8BIT))
    encoder = Net::FTP::BlockMode::BlockEncoder.new(output, block_size: 10)
    encoder.write("partial")
    encoder.write_restart_marker("m")
    encoder.finish
    assert_equal(frame(0, "partial") << frame(RESTART, "m") <<
                 frame(EOF, ""),
                 output.string)
  end

  def test_encoder_finish_is_idempotently_closed
    output = StringIO.new
    encoder = Net::FTP::BlockMode::BlockEncoder.new(output)
    encoder.finish
    assert_equal(true, encoder.closed?)
    assert_raise(IOError) { encoder.finish }
    assert_raise(IOError) { encoder.write("x") }
    assert_raise(IOError) { encoder.write_record("x") }
    assert_raise(IOError) { encoder.write_restart_marker("x") }
  end

  def test_encoder_invalid_arguments
    output = StringIO.new
    assert_raise(ArgumentError) {
      Net::FTP::BlockMode::BlockEncoder.new(output, block_size: 0)
    }
    assert_raise(ArgumentError) {
      Net::FTP::BlockMode::BlockEncoder.new(
        output, block_size: Net::FTP::BlockMode::MAX_BLOCK_SIZE + 1)
    }
    encoder = Net::FTP::BlockMode::BlockEncoder.new(output)
    assert_raise(ArgumentError) { encoder.write_restart_marker("") }
    assert_raise(ArgumentError) { encoder.write_restart_marker("bad\x00") }
    assert_raise(ArgumentError) { encoder.write_restart_marker("bad\xff") }
  end

  def test_encoder_max_block_size
    output = StringIO.new(String.new(encoding: Encoding::ASCII_8BIT))
    encoder = Net::FTP::BlockMode::BlockEncoder.new(output)
    data = "x" * (Net::FTP::BlockMode::MAX_BLOCK_SIZE + 10)
    encoder.write(data)
    encoder.finish
    wire = output.string
    counts = []
    offset = 0
    while offset + 3 <= wire.bytesize
      descriptor = wire.getbyte(offset)
      count = (wire.getbyte(offset + 1) << 8) | wire.getbyte(offset + 2)
      assert(count <= Net::FTP::BlockMode::MAX_BLOCK_SIZE)
      counts << [descriptor, count]
      offset += 3 + count
    end
    assert_equal(offset, wire.bytesize)
    assert_equal([[0, 65535], [EOF, 10]], counts)
  end

  # ---- decoder validation ----

  def test_record_spanning_multiple_blocks
    wire = frame(0, "ab") << frame(0, "cd") << frame(EOR, "ef") <<
           frame(EOF, "")
    assert_equal([[:record, "abcdef"], [:eof, nil]],
                 decode(wire, chunk: 2))
  end

  def test_unterminated_record_flushed_by_eof
    wire = frame(0, "ab") << frame(EOF, "")
    events = decode(wire, mode: :records, chunk: 4)
    assert_equal([[:record, "ab"], [:eof, nil]], events)
  end

  def test_truncated_header
    assert_raise(Net::FTPBlockTruncated) { decode("\x20\x00") }
  end

  def test_truncated_body
    wire = frame(EOR, "abc")
    assert_raise(Net::FTPBlockTruncated) {
      decode(wire.byteslice(0, 4), chunk: 1)
    }
  end

  def test_data_after_eof
    wire = String.new.b << frame(EOF, "") << "x"
    assert_raise(Net::FTPBlockDataAfterEOF) { decode(wire) }
  end

  def test_reserved_descriptor_bits
    wire = String.new(encoding: Encoding::ASCII_8BIT)
    wire << "\x01\x00\x00" << frame(EOF, "")
    assert_raise(Net::FTPBlockProtocolError) { decode(wire) }
  end

  def test_error_descriptor_alone
    wire = frame(ERRORF, "disk full") << frame(EOF, "")
    err = assert_raise(Net::FTPBlockError) { decode(wire) }
    assert_match(/disk full/, err.message)
  end

  def test_error_descriptor_with_other_flags
    wire = frame(ERRORF | EOR, "") << frame(EOF, "")
    assert_raise(Net::FTPBlockProtocolError) { decode(wire) }
  end

  def test_restart_marker_with_eof_flags_invalid
    wire = frame(RESTART | EOF, "m")
    assert_raise(Net::FTPBlockProtocolError) { decode(wire) }
  end

  def test_malformed_marker
    wire = frame(RESTART, "bad\x00") << frame(EOF, "")
    assert_raise(Net::FTPBlockProtocolError) { decode(wire) }
  end

  def test_zero_length_data_block_invalid
    wire = frame(0, "") << frame(EOF, "")
    assert_raise(Net::FTPBlockProtocolError) { decode(wire) }
  end

  def test_empty_eor_and_eof_blocks_are_valid
    wire = frame(EOR, "") << frame(EOF, "")
    events = decode(wire, mode: :records)
    assert_equal([[:record, ""], [:eof, nil]], events)
  end

  def test_finish_without_eof
    decoder = Net::FTP::BlockMode::BlockDecoder.new
    decoder.feed(frame(0, "abc")) { |_, _| }
    assert_raise(Net::FTPBlockTruncated) { decoder.finish }
  end

  def test_decoder_invalid_mode
    assert_raise(ArgumentError) {
      Net::FTP::BlockMode::BlockDecoder.new(mode: :nope)
    }
  end

  def test_feed_requires_block
    decoder = Net::FTP::BlockMode::BlockDecoder.new
    assert_raise(ArgumentError) { decoder.feed("x") }
  end

  def test_feed_stream_reads_io_until_eof
    wire = frame(EOR, "rec") << frame(EOF, "")
    decoder = Net::FTP::BlockMode::BlockDecoder.new(mode: :records)
    events = []
    decoder.feed_stream(StringIO.new(wire), read_size: 2) { |e, d|
      events << [e, d]
    }
    decoder.finish
    assert_equal([[:record, "rec"], [:eof, nil]], events)
  end

  # ---- round trip ----

  def test_round_trip_records
    records = ["one", "two", "", "a" * 1000]
    wire = encode(records, block_size: 37)
    events = decode(wire, mode: :records, chunk: 13)
    assert_equal(records.map { |r| [:record, r] } << [:eof, nil], events)
  end
end
