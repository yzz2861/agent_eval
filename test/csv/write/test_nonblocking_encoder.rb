# -*- coding: utf-8 -*-
# frozen_string_literal: false

require_relative "../helper"

class TestCSVWriteNonblockingEncoder < Test::Unit::TestCase
  class ChunkedNonblockingWriter
    attr_reader :written, :write_arguments

    def initialize(limit: 1, wait_every: nil, result: nil)
      @written = String.new.b
      @limit = limit
      @wait_every = wait_every
      @result = result
      @write_count = 0
      @write_arguments = []
    end

    def write_nonblock(chunk, exception: false)
      @write_count += 1
      @write_arguments << [chunk, exception]
      return :wait_writable if @wait_every && @write_count % @wait_every == 0
      return @result unless @result.nil?

      count = [chunk.bytesize, @limit].min
      @written << chunk.byteslice(0, count)
      count
    end
  end

  class PartialNonblockingWriter
    attr_reader :written

    def initialize(limit)
      @written = String.new.b
      @limits = [limit]
    end

    def write_nonblock(chunk, exception: false)
      limit = @limits.first
      if limit && @written.bytesize >= limit
        return :wait_writable
      end

      count = if limit
                [chunk.bytesize, limit - @written.bytesize].min
              else
                chunk.bytesize
              end
      @written << chunk.byteslice(0, count)
      count
    end

    def resume
      @limits.shift
    end

    def allow(limit)
      @limits << limit
    end
  end

  def test_resumes_short_writes_across_escapes_and_multibyte_characters
    rows = [["あ", "quote \" value"], ["second", "row"]]
    expected = CSV.generate_lines(rows)
    writer = ChunkedNonblockingWriter.new(limit: 1)
    encoder = CSV::NonblockingEncoder.new(rows.each)

    assert_equal(:complete, drain(encoder, writer))
    assert_equal(expected.b, writer.written)
  end

  def test_resumes_after_temporary_unwritable_output
    rows = [["あ", "quote \" value"], ["second", "row"]]
    expected = CSV.generate_lines(rows)
    first_row = CSV.generate_line(rows[0])
    writer = ChunkedNonblockingWriter.new(limit: 1, wait_every: 3)
    encoder = CSV::NonblockingEncoder.new(rows.each)

    status = encoder.resume(writer)
    assert_equal(:wait_writable, status)
    assert_equal(false, writer.write_arguments.first.last)
    assert_equal(first_row.bytesize - writer.written.bytesize,
                 encoder.bytes_pending)
    assert_not_equal(expected.b, writer.written)

    status = encoder.resume(writer)
    while status == :wait_writable
      status = encoder.resume(writer)
    end

    assert_equal(:complete, status)
    assert_equal(0, encoder.bytes_pending)
    assert_equal(expected.b, writer.written)
  end

  def test_does_not_read_next_row_until_current_row_is_written
    consumed = []
    rows = Enumerator.new do |yielder|
      ["first long row", "second long row", "third long row"].each do |row|
        consumed << row
        yielder << [row, row.reverse]
      end
    end
    writer = PartialNonblockingWriter.new(5)
    encoder = CSV::NonblockingEncoder.new(rows)
    first_row = CSV.generate_line(["first long row", "gnor wol tsrif"])

    assert_equal([], consumed)
    assert_equal(:wait_writable, encoder.resume(writer))
    assert_equal(["first long row"], consumed)
    assert_equal(5, writer.written.bytesize)

    writer.allow(first_row.bytesize - 5)
    writer.resume
    status = encoder.resume(writer)
    assert_equal(:wait_writable, status)
    assert_equal(["first long row"], consumed)
    assert_equal(first_row.bytesize - 5, writer.written.bytesize)
    assert_equal(5, encoder.bytes_pending)

    writer.allow(nil)
    writer.resume
    drain(encoder, writer)
    assert_equal(["first long row", "second long row", "third long row"],
                 consumed)
  end

  def test_writes_headers_only_once
    options = {
      headers: ["名前", "メモ"],
      write_headers: true,
      force_quotes: true,
    }
    rows = [["あ", "quote \" value"], ["second", "row"]]
    expected = CSV.generate_lines(rows, **options)
    writer = ChunkedNonblockingWriter.new(limit: 1, wait_every: 5)
    encoder = CSV::NonblockingEncoder.new(rows.each, **options)

    drain(encoder, writer)

    assert_equal(expected.b, writer.written)
    assert_equal(1, writer.written.scan("名前".b).length)
  end

  def test_writes_dynamic_headers_only_once
    rows = [["name", "note"], ["a", "quote \" value"]]
    options = {headers: true, write_headers: true}
    expected = CSV.generate_lines(rows, **options)
    writer = ChunkedNonblockingWriter.new(limit: 1, wait_every: 3)
    encoder = CSV::NonblockingEncoder.new(rows.each, **options)

    drain(encoder, writer)

    assert_equal(expected.b, writer.written)
    assert_equal(1, writer.written.scan("name,note".b).length)
  end

  def test_accepts_a_write_receiver_block
    rows = [["あ"], ["ok"]]
    expected = CSV.generate_lines(rows)
    chunks = []
    writer = ChunkedNonblockingWriter.new(limit: 2, wait_every: 4)
    encoder = CSV::NonblockingEncoder.new(rows.each)

    loop do
      status = encoder.resume do |chunk|
        chunks << chunk
        writer.write_nonblock(chunk, exception: true)
      end
      break unless status == :wait_writable
    end

    assert_equal(expected.b, writer.written)
    assert_equal(true, writer.write_arguments.first.last)
    assert_equal(true, chunks.any? {|chunk| chunk.encoding == Encoding::BINARY})
  end

  def test_block_temporary_exception_is_resumable_and_permanent_exception_fails
    rows = [["あ"], ["ok"]]
    expected = CSV.generate_lines(rows)
    writer = ChunkedNonblockingWriter.new(limit: 1, wait_every: 4)
    encoder = CSV::NonblockingEncoder.new(rows.each)
    temporary = true

    status = encoder.resume do |chunk|
      result = writer.write_nonblock(chunk, exception: false)
      if temporary && result == :wait_writable
        raise IO::EAGAINWaitWritable, "temporary"
      end
      result
    end
    assert_equal(:wait_writable, status)
    temporary = false

    loop do
      status = encoder.resume do |chunk|
        writer.write_nonblock(chunk, exception: false)
      end
      break if status == :complete
    end
    assert_equal(expected.b, writer.written)

    failed_encoder = CSV::NonblockingEncoder.new([["ok"]].each)
    assert_raise(Errno::EPIPE) do
      failed_encoder.resume do |chunk|
        raise Errno::EPIPE, "permanent"
      end
    end
    assert_equal(:failed, failed_encoder.status)
  end

  def test_distinguishes_temporary_and_permanent_errors
    temporary_writer = Object.new
    def temporary_writer.write_nonblock(chunk, exception: false)
      :wait_writable
    end
    permanent_writer = Object.new
    def permanent_writer.write_nonblock(chunk, exception: false)
      :EPIPE
    end

    temporary_encoder = CSV::NonblockingEncoder.new([["ok"]].each)
    assert_equal(:wait_writable,
                 temporary_encoder.resume(temporary_writer))
    assert_equal(:wait_writable, temporary_encoder.status)
    assert_equal(false, temporary_encoder.complete?)

    permanent_encoder = CSV::NonblockingEncoder.new([["ok"]].each)
    assert_raise(Errno::EPIPE) do
      permanent_encoder.resume(permanent_writer)
    end
    assert_equal(:failed, permanent_encoder.status)
    assert_raise(CSV::NonblockingEncoder::PermanentWriteError) do
      permanent_encoder.resume(permanent_writer)
    end
  end

  def test_rejects_invalid_short_write_count
    writer = ChunkedNonblockingWriter.new(result: 2)
    encoder = CSV::NonblockingEncoder.new([["ok"]].each)

    assert_raise(CSV::NonblockingEncoder::PermanentWriteError) do
      encoder.resume(writer)
    end
    assert_equal(:failed, encoder.status)
  end

  def test_row_generation_error_is_permanent
    rows = Enumerator.new do |yielder|
      yielder << ["ok"]
      raise "generation failed"
    end
    writer = ChunkedNonblockingWriter.new(limit: 1)
    encoder = CSV::NonblockingEncoder.new(rows)

    assert_raise(RuntimeError) do
      encoder.resume(writer)
    end
    assert_equal(:failed, encoder.status)
  end

  private
  def drain(encoder, writer)
    loop do
      status = encoder.resume(writer)
      return status unless status == :wait_writable
    end
  end

end
