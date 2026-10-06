# coding: UTF-8
# frozen_string_literal: true
require 'logger'
require 'stringio'
require 'tempfile'

class TestOctetCountingLogDevice < Test::Unit::TestCase
  class PartialIO
    attr_reader :writes

    def initialize(chunk_size)
      @chunk_size = chunk_size
      @buffer = String.new.force_encoding(Encoding::BINARY)
      @writes = 0
    end

    def write(data)
      @writes += 1
      chunk = data.byteslice(0, @chunk_size)
      @buffer << chunk
      chunk.bytesize
    end

    def close
    end

    def string
      @buffer
    end
  end

  def test_frames_two_utf8_messages_using_final_byte_length
    io = StringIO.new.binmode
    formatter = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: '1', msgid: 'event',
      structured_data: {'meta' => {'request' => 'one'}}
    )
    logger = Logger.new(io, framing: :octet_counting, formatter: formatter)

    logger.info('第一条')
    logger.warn('第二条消息')

    frames = read_frames(io.string)
    assert_equal(2, frames.length)
    assert_equal('第一条', remove_bom(frames[0]))
    assert_equal('第二条消息', remove_bom(frames[1]))
  ensure
    logger&.close
  end

  def test_short_write_continues_without_resending_the_frame
    io = PartialIO.new(3)
    logdev = Logger::LogDevice.new(io, framing: :octet_counting)
    message = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: '1', msgid: 'event'
    ).call('INFO', Time.utc(2026, 10, 6), nil, '中文')

    bytes_written = logdev.write(message)
    expected_frame = "#{message.bytesize} #{message}".b

    assert_equal(message.bytesize + message.bytesize.to_s.bytesize + 1, bytes_written)
    assert_equal(1, read_frames(io.string).length)
    assert_equal(expected_frame, io.string)
    assert_operator(io.writes, :>, 1)
  ensure
    logdev&.close
  end

  def test_default_log_device_does_not_add_frame_prefix
    io = StringIO.new.binmode
    logdev = Logger::LogDevice.new(io)

    logdev.write('中文消息\n')

    assert_equal('中文消息\n'.b, io.string)
  ensure
    logdev&.close
  end

  def test_octet_counting_file_omits_unframed_header
    file = Tempfile.new('logger-octet-counting')
    path = file.path
    file.close
    logdev = Logger::LogDevice.new(path, framing: :octet_counting)

    logdev.write('中文')
    logdev.close

    assert_equal("6 中文".b, File.binread(path))
  ensure
    file&.close(true)
  end

  def test_octet_counting_wrapper_enables_framing
    io = StringIO.new.binmode
    logdev = Logger::OctetCountingLogDevice.new(io)

    logdev.write('中文')

    assert_equal("6 中文".b, io.string)
  ensure
    logdev&.close
  end

  def test_rejects_unknown_framing
    assert_raise(ArgumentError) do
      Logger::LogDevice.new(StringIO.new, framing: :newline)
    end
  end

  private

  def read_frames(data)
    frames = []
    offset = 0
    while offset < data.bytesize
      length_end = data.index(' ', offset)
      length = Integer(data.byteslice(offset, length_end - offset))
      payload_start = length_end + 1
      frames << data.byteslice(payload_start, length).force_encoding(Encoding::UTF_8)
      offset = payload_start + length
    end
    frames
  end

  def remove_bom(payload)
    payload.sub(/\A.*(?:-|\]) \uFEFF/m, '')
  end
end
