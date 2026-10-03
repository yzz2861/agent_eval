# -*- coding: utf-8 -*-
# frozen_string_literal: true

require_relative "../helper"

class TestCSVNonBlockingWriter < Test::Unit::TestCase
  include CSVHelper

  # A fake non-blocking receiver.  It accepts at most +chunk_size+ bytes
  # per write_nonblock call, and only while it has budget granted via
  # #allow (simulating the socket becoming writable).  Otherwise it
  # reports :wait_writable, like IO#write_nonblock(exception: false).
  class FakeReceiver
    attr_reader :output

    def initialize(chunk_size)
      @chunk_size = chunk_size
      @output = +"".b
      @budget = 0
    end

    def allow(n_bytes)
      @budget += n_bytes
    end

    def write_nonblock(chunk, exception: false)
      return :wait_writable if @budget.zero?

      n_bytes = [chunk.bytesize, @budget, @chunk_size].min
      @output << chunk.byteslice(0, n_bytes)
      @budget -= n_bytes
      n_bytes
    end
  end

  class RaisingReceiver
    def initialize(error)
      @error = error
    end

    def write_nonblock(chunk, exception: false)
      raise @error
    end
  end

  class WouldBlock < StandardError
    include IO::WaitWritable
  end

  def rows
    [
      ["id", "na\"me", "日本語", nil, ""],
      ["1", "comma,inside", "café", "line\nbreak", "tab\there"],
      ["2", %Q["quoted"], "\r\n", "末尾", "x"],
    ]
  end

  def expected_output(**options)
    CSV.generate(**options) do |csv|
      rows.each do |row|
        csv << row
      end
    end
  end

  # Grants the receiver +window+ bytes at a time, resuming the writer
  # whenever it reports :wait_writable, until it reports :done.
  def drive(writer, receiver, window)
    statuses = []
    loop do
      receiver.allow(window)
      status = writer.write(receiver)
      statuses << status
      case status
      when :done
        break
      when :wait_writable
        # keep pumping
      else
        flunk("unexpected status: #{status.inspect}")
      end
    end
    statuses
  end

  def generate_with_receiver(chunk_size, window, **options)
    writer = CSV::NonBlockingWriter.new(rows.each, **options)
    receiver = FakeReceiver.new(chunk_size)
    drive(writer, receiver, window)
    receiver.output.b
  end

  def test_output_matches_normal_writer
    [
      [1, 1],     # one byte at a time, pause after every byte
      [2, 5],     # short writes inside quote escapes and multibyte chars
      [7, 3],
      [1024, 1024],
    ].each do |chunk_size, window|
      assert_equal(expected_output.b,
                   generate_with_receiver(chunk_size, window),
                   "chunk_size=#{chunk_size} window=#{window}")
    end
  end

  def test_output_matches_normal_writer_with_options
    options_list = [
      {headers: ["id", "name", "city", "note", "flag"], write_headers: true},
      {force_quotes: true},
      {col_sep: ";", row_sep: "\r\n"},
      {encoding: "UTF-8", write_headers: true, headers: %w[a b c d e]},
      {write_nil_value: "NULL", write_empty_value: "EMPTY"},
    ]
    options_list.each do |options|
      assert_equal(expected_output(**options).b,
                   generate_with_receiver(3, 4, **options),
                   "options=#{options.inspect}")
    end
  end

  def test_headers_written_exactly_once
    options = {headers: ["id", "name"], write_headers: true}
    output = generate_with_receiver(1, 1, **options)
    assert_equal(1, output.scan("id,name").size)
    assert(output.start_with?("id,name\n"))
  end

  def test_next_row_not_pulled_before_current_row_flushed
    pulled = 0
    enumerator = Enumerator.new do |yielder|
      rows.each do |row|
        pulled += 1
        yielder << row
      end
    end
    writer = CSV::NonBlockingWriter.new(enumerator)
    receiver = FakeReceiver.new(1024)

    receiver.allow(3) # less than one full line
    assert_equal(:wait_writable, writer.write(receiver))
    assert_equal(1, pulled)

    receiver.allow(1024)
    assert_equal(:done, writer.write(receiver))
    assert_equal(rows.size, pulled)
  end

  def test_row_not_pulled_before_headers_flushed
    pulled = 0
    enumerator = Enumerator.new do |yielder|
      pulled += 1
      yielder << ["1", "2"]
    end
    writer = CSV::NonBlockingWriter.new(enumerator,
                                        headers: %w[a b],
                                        write_headers: true)
    receiver = FakeReceiver.new(1024)

    receiver.allow(2) # header line "a,b\n" is longer
    assert_equal(:wait_writable, writer.write(receiver))
    assert_equal(0, pulled)
  end

  def test_wait_writable_is_not_an_error
    writer = CSV::NonBlockingWriter.new(rows.each)
    receiver = FakeReceiver.new(4)
    assert_equal(:wait_writable, writer.write(receiver))
    assert_equal("", receiver.output)
    assert_false(writer.done?)

    receiver.allow(1024)
    assert_equal(:done, writer.write(receiver))
    assert_equal(expected_output.b, receiver.output.b)
  end

  def test_io_wait_writable_exception_is_temporary
    writer = CSV::NonBlockingWriter.new(rows.each)
    assert_equal(:wait_writable,
                 writer.write(RaisingReceiver.new(WouldBlock.new)))
    assert_false(writer.done?)
  end

  def test_permanent_error_is_raised
    writer = CSV::NonBlockingWriter.new(rows.each)
    assert_raise(Errno::EPIPE) do
      writer.write(RaisingReceiver.new(Errno::EPIPE))
    end

    writer = CSV::NonBlockingWriter.new(rows.each)
    assert_raise(IOError) do
      writer.write(RaisingReceiver.new(IOError.new("closed stream")))
    end
  end

  def test_done_is_sticky
    writer = CSV::NonBlockingWriter.new(rows.each)
    receiver = FakeReceiver.new(1024)
    receiver.allow(1 << 20)
    assert_equal(:done, writer.write(receiver))
    assert_true(writer.done?)
    output = receiver.output.dup
    assert_equal(:done, writer.write(receiver))
    assert_equal(output, receiver.output)
  end

  def test_empty_rows
    writer = CSV::NonBlockingWriter.new([].each)
    receiver = FakeReceiver.new(1)
    receiver.allow(1)
    assert_equal(:done, writer.write(receiver))
    assert_equal("", receiver.output)
  end

  def test_empty_rows_with_headers
    writer = CSV::NonBlockingWriter.new([].each,
                                        headers: %w[a b],
                                        write_headers: true)
    receiver = FakeReceiver.new(2)
    drive(writer, receiver, 1)
    assert_equal("a,b\n".b, receiver.output)
  end

  def test_lineno_counts_consumed_rows
    writer = CSV::NonBlockingWriter.new(rows.each)
    receiver = FakeReceiver.new(1024)
    receiver.allow(1 << 20)
    writer.write(receiver)
    assert_equal(rows.size, writer.lineno)
  end

  def test_resume_does_not_duplicate_bytes
    writer = CSV::NonBlockingWriter.new(rows.each)
    receiver = FakeReceiver.new(3)
    expected = expected_output.b
    expected.bytesize.times do
      receiver.allow(1)
      status = writer.write(receiver)
      break if status == :done
    end
    receiver.allow(1 << 20)
    writer.write(receiver)
    assert_equal(expected, receiver.output.b)
    assert_equal(expected.bytesize, receiver.output.bytesize)
  end
end
