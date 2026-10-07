# frozen_string_literal: true

require "net/ftp"
require "test/unit"
require "stringio"

# FTP integration tests for Block Mode (MODE B) that do not bind any real
# socket: transfercmd and the control responses are stubbed so a fake data
# connection stands in for the TCP pair, which can still be "split" into
# arbitrary reads.
class FTPBlockModeIntegrationTest < Test::Unit::TestCase
  EOR = Net::FTP::BlockMode::END_OF_RECORD
  EOF = Net::FTP::BlockMode::END_OF_DATA
  RESTART = Net::FTP::BlockMode::RESTART_MARKER

  class FakeConnection
    def initialize(payload = String.new.b)
      @io = StringIO.new(String(payload).b)
      @written = String.new(encoding: Encoding::ASCII_8BIT)
      @closed = false
    end

    attr_reader :written

    def read(len, *)
      @io.read(len)
    end

    def write(data)
      @written << data
      data.bytesize
    end

    def shutdown(*); end

    def read_timeout=(_); end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  def frame(descriptor, body)
    [descriptor, body.bytesize].pack("Cn") << body
  end

  def build_ftp(payload)
    ftp = Net::FTP.new
    ftp.instance_variable_set(:@logged_in, true)
    conn = FakeConnection.new(payload)
    ftp.define_singleton_method(:transfercmd) { |*_| conn }
    ftp.define_singleton_method(:voidresp) { }
    ftp.define_singleton_method(:voidcmd) { |_| }
    [ftp, conn]
  end

  def test_default_transfer_mode_is_stream
    ftp = Net::FTP.new
    assert_equal(:stream, ftp.transfer_mode)
    assert_equal(true, ftp.send(:stream_mode?))
  end

  def test_initialize_with_transfer_mode_option
    ftp = Net::FTP.new(nil, transfer_mode: :block)
    assert_equal(:block, ftp.transfer_mode)
    assert_raise(ArgumentError) { Net::FTP.new(nil, transfer_mode: :bogus) }
  end

  def test_transfer_mode_setter_sends_mode_command_when_logged_in
    sent = []
    ftp = Net::FTP.new
    ftp.instance_variable_set(:@logged_in, true)
    ftp.define_singleton_method(:voidcmd) { |cmd| sent << cmd }
    ftp.transfer_mode = :block
    ftp.transfer_mode = :stream
    ftp.transfer_mode = :stream
    assert_equal(["MODE B", "MODE S"], sent)
  end

  def test_transfer_mode_setter_no_command_before_login
    ftp = Net::FTP.new
    ftp.define_singleton_method(:voidcmd) { |_| flunk "no command expected" }
    assert_nothing_raised { ftp.transfer_mode = :block }
    assert_equal(:block, ftp.transfer_mode)
  end

  def test_retrbinary_in_block_mode_strips_framing
    payload = frame(0, "hello ") << frame(EOR, "world") <<
              frame(RESTART, "m9") << frame(EOF, "")
    ftp, _conn = build_ftp(payload)
    ftp.transfer_mode = :block
    received = []
    ftp.retrbinary("RETR x", 4) { |data| received << data }
    assert_equal("hello world", received.join)
    assert_equal(:block, ftp.transfer_mode)
  end

  def test_retrbinary_stream_mode_passes_bytes_untouched
    payload = frame(EOR, "abc") # treated as raw bytes in stream mode
    ftp, _conn = build_ftp(payload)
    received = []
    ftp.retrbinary("RETR x", 16) { |data| received << data }
    assert_equal(payload, received.join)
  end

  def test_retrbinary_abnormal_close_without_eof
    payload = frame(0, "abc") # no end-of-data block
    ftp, _conn = build_ftp(payload)
    ftp.transfer_mode = :block
    assert_raise(Net::FTPBlockTruncated) {
      ftp.retrbinary("RETR x", 16) { }
    }
  end

  def test_retrbinary_truncated_block
    payload = frame(EOR, "abc").byteslice(0, 4)
    ftp, _conn = build_ftp(payload)
    ftp.transfer_mode = :block
    assert_raise(Net::FTPBlockTruncated) {
      ftp.retrbinary("RETR x", 16) { }
    }
  end

  def test_retrblocks_record_events
    payload = frame(0, "a") << frame(0, "b") << frame(EOR, "c") <<
              frame(RESTART, "r1") << frame(EOR | EOF, "last")
    ftp, _conn = build_ftp(payload)
    events = []
    ftp.retrblocks("RETR x") { |event, data| events << [event, data] }
    assert_equal([[:record, "abc"], [:restart_marker, "r1"],
                  [:record, "last"], [:eof, nil]], events)
    # retrblocks does not mutate the session's configured mode
    assert_equal(:stream, ftp.transfer_mode)
  end

  def test_retrblocks_bytes_mode
    payload = frame(0, "ab") << frame(RESTART, "m") << frame(EOR | EOF, "c")
    ftp, _conn = build_ftp(payload)
    events = []
    ftp.retrblocks("RETR x", mode: :bytes) { |e, d| events << [e, d] }
    assert_equal([[:data, "ab"], [:restart_marker, "m"],
                  [:data, "c"], [:eof, nil]], events)
  end

  def test_retrblocks_blocks_mode
    payload = frame(0, "ab") << frame(RESTART, "m") << frame(EOR | EOF, "c")
    ftp, _conn = build_ftp(payload)
    events = []
    ftp.retrblocks("RETR x", mode: :blocks) { |e, d| events << [e, d] }
    assert_equal([[:block, [0, "ab"]], [:restart_marker, "m"],
                  [:block, [EOR | EOF, "c"]], [:eof, nil]], events)
  end

  def test_retrblocks_data_after_eof
    payload = frame(EOF, "") << frame(EOR, "late")
    ftp, _conn = build_ftp(payload)
    assert_raise(Net::FTPBlockDataAfterEOF) {
      ftp.retrblocks("RETR x") { }
    }
  end

  def test_storbinary_in_block_mode_frames_data_and_eof
    ftp, conn = build_ftp("")
    ftp.transfer_mode = :block
    input = StringIO.new("a" * (65535 + 5))
    ftp.storbinary("STOR x", input, 1000)
    wire = conn.written
    # three bounded frames: two full-size and one EOF-carrying remainder
    offset = 0
    frames = []
    while offset + 3 <= wire.bytesize
      descriptor = wire.getbyte(offset)
      count = (wire.getbyte(offset + 1) << 8) | wire.getbyte(offset + 2)
      frames << [descriptor, count]
      offset += 3 + count
    end
    assert_equal(offset, wire.bytesize)
    assert_equal([[0, 1000]] * 65 + [[EOF, 540]], frames)
  end

  def test_storbinary_empty_file_just_eof
    ftp, conn = build_ftp("")
    ftp.transfer_mode = :block
    ftp.storbinary("STOR x", StringIO.new(""), 512)
    assert_equal(frame(EOF, ""), conn.written)
  end

  def test_storblocks_with_records_and_marker
    ftp, conn = build_ftp("")
    items = [[:record, "abcde"], [:restart_marker, "rp"],
             [:record, "f"]]
    ftp.storblocks("STOR x", items, blocksize: 3)
    expected = frame(0, "abc") << frame(EOR, "de") <<
               frame(RESTART, "rp") << frame(EOR, "f") <<
               frame(EOF, "")
    assert_equal(expected, conn.written)
  end

  def test_storblocks_rejects_unknown_event
    ftp, _conn = build_ftp("")
    assert_raise(ArgumentError) {
      ftp.storblocks("STOR x", [[:nope, "x"]]) { }
    }
  end

  def test_storblocks_from_lazy_enumerator
    ftp, conn = build_ftp("")
    generated = []
    enumerator = Enumerator.new do |y|
      3.times { |i| generated << i; y << [:record, "r#{i}"] }
    end
    ftp.storblocks("STOR x", enumerator, blocksize: 10)
    assert_equal([0, 1, 2], generated)
    expected = frame(EOR, "r0") << frame(EOR, "r1") <<
               frame(EOR, "r2") << frame(EOF, "")
    assert_equal(expected, conn.written)
  end

  def test_storrecords_convenience
    ftp, conn = build_ftp("")
    ftp.storrecords("STOR x", ["one", "two"], blocksize: 2)
    expected = frame(0, "on") << frame(EOR, "e") <<
               frame(0, "tw") << frame(EOR, "o") << frame(EOF, "")
    assert_equal(expected, conn.written)
  end

  def test_mode_cannot_change_during_transfer
    ftp = Net::FTP.new
    ftp.instance_variable_set(:@logged_in, true)
    ftp.instance_variable_set(:@transferring, true)
    assert_raise(Net::FTPError) { ftp.transfer_mode = :block }
  end

  def test_retrlines_rejected_in_block_mode
    ftp = Net::FTP.new
    ftp.transfer_mode = :block
    assert_raise(Net::FTPError) { ftp.retrlines("LIST") { } }
  end

  def test_storlines_rejected_in_block_mode
    ftp = Net::FTP.new
    ftp.transfer_mode = :block
    assert_raise(Net::FTPError) { ftp.storlines("LIST", StringIO.new("x")) }
  end

  def test_upload_download_round_trip
    output = StringIO.new(String.new(encoding: Encoding::ASCII_8BIT))
    encoder = Net::FTP::BlockMode::BlockEncoder.new(output, block_size: 7)
    records = ["record-one", "r2", "x" * 100]
    records.each { |r| encoder.write_record(r) }
    encoder.write_restart_marker("point")
    encoder.finish

    ftp, _conn = build_ftp(output.string)
    events = []
    ftp.retrblocks("RETR x", mode: :records) { |e, d| events << [e, d] }
    assert_equal(records.map { |r| [:record, r] } +
                 [[:restart_marker, "point"], [:eof, nil]],
                 events)
  end
end
