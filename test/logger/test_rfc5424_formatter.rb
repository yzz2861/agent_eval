# coding: UTF-8
# frozen_string_literal: true
require 'logger'

class TestRFC5424Formatter < Test::Unit::TestCase
  def test_formats_message_with_structured_data
    formatter = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: '123', msgid: 'event',
      hostname: 'host', facility: 16,
      structured_data: {
        'origin' => {
          'software' => %q{quoted"\\bracketed]value},
          'plain' => '中文',
        }
      }
    )

    result = formatter.call('INFO', Time.utc(2026, 10, 6, 1, 2, 3, 123456), nil, '中文')

    assert_equal(
      '<134>1 2026-10-06T01:02:03.123456Z host app 123 event ' \
      '[origin software="quoted\\"\\\\bracketed\\]value" plain="中文"]' \
      " \uFEFF中文",
      result
    )
    assert_equal(Encoding::UTF_8, result.encoding)
  end

  def test_uses_nil_values_and_logger_severities
    formatter = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: 1, msgid: 'event'
    )

    [
      [Logger::DEBUG, '<15>1'],
      [Logger::INFO, '<14>1'],
      [Logger::WARN, '<12>1'],
      [Logger::ERROR, '<11>1'],
      [Logger::FATAL, '<10>1'],
      [Logger::UNKNOWN, '<8>1'],
    ].each do |severity, prefix|
      assert_match(/\A#{Regexp.escape(prefix)} \S+ - app 1 event - /,
                   formatter.call(severity, Time.now, nil, 'message'))
    end
  end

  def test_rejects_invalid_header_fields
    valid = {app_name: 'app', procid: '1', msgid: 'event'}

    assert_invalid_header(valid, :app_name, ' ')
    assert_invalid_header(valid, :app_name, 'a' * 49)
    assert_invalid_header(valid, :app_name, '中文')
    assert_invalid_header(valid, :procid, 'a b')
    assert_invalid_header(valid, :msgid, "a\x7f".b)
    assert_invalid_header(valid, :hostname, 'a' * 256)
  end

  def test_rejects_invalid_structured_data
    base = {app_name: 'app', procid: '1', msgid: 'event'}

    assert_raise(ArgumentError) do
      Logger::RFC5424Formatter.new(**base, structured_data: {})
    end
    assert_raise(ArgumentError) do
      Logger::RFC5424Formatter.new(**base, structured_data: {'bad id' => {}})
    end
    assert_raise(ArgumentError) do
      Logger::RFC5424Formatter.new(**base, structured_data: {'id' => {'bad name' => 'value'}})
    end
    assert_raise(ArgumentError) do
      Logger::RFC5424Formatter.new(**base, structured_data: {'id=' => {}})
    end
    assert_raise(ArgumentError) do
      Logger::RFC5424Formatter.new(**base, structured_data: {'id]' => {}})
    end
    assert_raise(ArgumentError) do
      Logger::RFC5424Formatter.new(**base, structured_data: {'id"' => {}})
    end
    assert_raise(ArgumentError) do
      Logger::RFC5424Formatter.new(
        **base, structured_data: {'id' => {'name' => 'first', :name => 'second'}}
      )
    end
  end

  def test_accepts_structured_data_element_without_parameters
    formatter = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: '1', msgid: 'event',
      structured_data: {'timeQuality' => nil}
    )

    result = formatter.call('INFO', Time.utc(2026, 10, 6), nil, 'message')

    assert_match(/ \[timeQuality\] \uFEFFmessage\z/, result)
  end

  def test_accepts_structured_data_arrays
    formatter = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: '1', msgid: 'event',
      structured_data: [
        ['first', {'name' => 'one'}],
        ['second', nil],
      ]
    )

    result = formatter.call('INFO', Time.utc(2026, 10, 6), nil, 'message')

    assert_match(/ \[first name="one"\]\[second\] \uFEFFmessage\z/, result)

    formatter = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: '1', msgid: 'event',
      structured_data: [['single', {'name' => 'one'}]]
    )

    assert_match(/ \[single name="one"\] \uFEFFmessage\z/,
                 formatter.call('INFO', Time.utc(2026, 10, 6), nil, 'message'))
  end

  def test_rejects_invalid_utf8_message
    formatter = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: '1', msgid: 'event'
    )

    assert_raise(Encoding::UndefinedConversionError) do
      formatter.call('INFO', Time.now, nil, "\xff".b)
    end
  end

  def test_rejects_invalid_severity
    formatter = Logger::RFC5424Formatter.new(
      app_name: 'app', procid: '1', msgid: 'event'
    )

    assert_raise(ArgumentError) do
      formatter.call(6, Time.now, nil, 'message')
    end
    assert_raise(ArgumentError) do
      formatter.call('TRACE', Time.now, nil, 'message')
    end
  end

  private

  def assert_invalid_header(valid, name, value)
    assert_raise(ArgumentError) do
      Logger::RFC5424Formatter.new(**valid.merge(name => value))
    end
  end
end
