# frozen_string_literal: true
require 'logger'

class TestRFC5424Formatter < Test::Unit::TestCase
  def fixed_time
    Time.utc(2026, 10, 6, 12, 34, 56, 123456)
  end

  def formatter(**options)
    defaults = {
      app_name: 'billing',
      procid: 1234,
      msgid: 'payment',
      structured_data: {'meta@1234' => {'request_id' => 'abc'}},
      hostname: 'host.example',
      facility: 16,
    }
    Logger::RFC5424Formatter.new(**defaults.merge(options))
  end

  def test_formats_rfc5424_message
    result = formatter.call(Logger::INFO, fixed_time, nil, 'charged ¥100')

    assert_equal Encoding::BINARY, result.encoding
    assert_match(%r{\A<134>1 2026-10-06T12:34:56\.123456\+00:00 host\.example billing 1234 payment \[meta@1234 request_id="abc"\]}, result)
    assert_predicate result, :valid_encoding?
    assert_include result, "\xEF\xBB\xBFcharged \xC2\xA5100".b
  end

  def test_escapes_structured_data_parameter_values
    structured_data = {
      'meta@1234' => {'detail' => 'quote: " backslash: \\ bracket: ]'}
    }

    result = formatter(structured_data: structured_data)
      .call(Logger::INFO, fixed_time, nil, 'ok')

    assert_include(
      result,
      'detail="quote: \\" backslash: \\\\ bracket: \\]"'.b
    )
  end

  def test_nil_structured_data_uses_nil_value
    result = formatter(structured_data: nil)
      .call(Logger::WARN, fixed_time, nil, '')

    assert_match(/ 1234 payment -\z/, result)
  end

  def test_message_supplies_per_message_metadata
    message = Logger::RFC5424Formatter::Message.new(
      'charged ¥100',
      msgid: 'refund',
      structured_data: {'event@1234' => {'id' => 'xyz'}}
    )

    result = formatter.call(Logger::INFO, fixed_time, nil, message)

    assert_include result, ' billing 1234 refund [event@1234 id="xyz"]'.b
    assert_include result, "\xEF\xBB\xBFcharged \xC2\xA5100".b
  end

  def test_invalid_message_metadata_is_rejected_before_sending
    io = Object.new
    io.define_singleton_method(:write) do |_message|
      @sent = true
    end
    io.define_singleton_method(:close) {}
    io.define_singleton_method(:sent?) { @sent == true }
    device = Logger::SyslogDevice.new(io)
    message = Logger::RFC5424Formatter::Message.new(
      'ok', msgid: 'bad id'
    )

    assert_raise(ArgumentError) do
      device.write(formatter.call(Logger::INFO, fixed_time, nil, message))
    end
    refute_predicate io, :sent?
  end

  def test_rejects_invalid_header_fields_before_sending
    assert_raise(ArgumentError) do
      formatter(app_name: 'bad app')
    end
    assert_raise(ArgumentError) do
      formatter(app_name: 'a' * 49)
    end
    assert_raise(ArgumentError) do
      formatter(hostname: "bad\nhost")
    end
    assert_raise(ArgumentError) do
      formatter(procid: 'bad' + "\u0000")
    end
    assert_raise(ArgumentError) do
      formatter(msgid: 'bad id')
    end
    assert_raise(ArgumentError) do
      formatter(facility: 24)
    end
  end

  def test_rejects_invalid_structured_data_names_and_values
    assert_raise(ArgumentError) do
      formatter(structured_data: {'bad id' => {}})
    end
    assert_raise(ArgumentError) do
      formatter(structured_data: {'id@1234' => {'bad=name' => 'value'}})
    end
    assert_raise(ArgumentError) do
      formatter(
        structured_data: {
          'id@1234' => {'bad' => "\xff".dup.force_encoding(Encoding::UTF_8)}
        }
      )
    end
    assert_raise(ArgumentError) do
      formatter(structured_data: [[nil, {}]])
    end
    assert_raise(ArgumentError) do
      formatter(structured_data: {'id@1234' => {nil => 'value'}})
    end
  end
end
