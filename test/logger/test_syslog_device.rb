# frozen_string_literal: true
require 'logger'
require 'stringio'

class TestSyslogDevice < Test::Unit::TestCase
  class PartialWriter
    attr_reader :writes

    def initialize(limit)
      @limit = limit
      @writes = []
    end

    def write(message)
      written = [message.bytesize, @limit].min
      @writes << message.byteslice(0, written)
      written
    end

    def close
    end

    def result
      @writes.join
    end
  end

  def test_octet_counting_preserves_two_multibyte_frame_boundaries
    io = StringIO.new
    io.binmode
    device = Logger::SyslogDevice.new(io)
    formatter = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: 'pid', msgid: 'id'
    )
    time = Time.utc(2026, 10, 6, 12, 34, 56, 123456)

    first = formatter.call(Logger::INFO, time, nil, '你好')
    second = formatter.call(Logger::ERROR, time, nil, '世界')
    device.write(first)
    device.write(second)

    frames = parse_frames(io.string)
    assert_equal [first, second], frames
  end

  def test_logger_integration_with_two_multibyte_messages
    io = StringIO.new
    io.binmode
    formatter = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: 'pid', msgid: 'id'
    )
    logger = Logger.new(
      Logger::SyslogDevice.new(io), formatter: formatter
    )
    logger.info('你好')
    logger.error('世界')

    frames = parse_frames(io.string)
    assert_equal 2, frames.length
    assert_equal "\xEF\xBB\xBF你好".b, frames[0].byteslice(-9, 9)
    assert_equal "\xEF\xBB\xBF世界".b, frames[1].byteslice(-9, 9)
  end

  def test_short_write_continues_from_offset_instead_of_restarting_frame
    writer = PartialWriter.new(3)
    device = Logger::SyslogDevice.new(writer)
    message = '<134>1 hello'.b

    device.write(message)

    expected = "#{message.bytesize} #{message}".b
    assert_equal expected, writer.result
    assert_equal ['12 '.b, '<13'.b, '4>1'.b, ' he'.b, 'llo'.b], writer.writes
  end

  def test_short_write_does_not_restart_second_frame
    writer = PartialWriter.new(5)
    device = Logger::SyslogDevice.new(writer)

    device.write('你好'.b)
    first_writes = writer.writes.length
    device.write('世界'.b)

    frames = parse_frames(writer.result)
    assert_equal ['你好'.b, '世界'.b], frames
    assert_equal '6 '.b, writer.writes[first_writes].byteslice(0, 2)
  end

  private

  def parse_frames(data)
    frames = []
    offset = 0

    while offset < data.bytesize
      length_end = data.index(' '.b, offset)
      length = Integer(data.byteslice(offset, length_end - offset))
      payload_start = length_end + 1
      frames << data.byteslice(payload_start, length)
      offset = payload_start + length
    end

    frames
  end
end
