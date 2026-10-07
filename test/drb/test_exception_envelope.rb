# frozen_string_literal: false
require_relative 'drbtest'
require 'stringio'

module DRbTests

class LocalEnvelopeOnlyError < RuntimeError
  def _dump(_limit)
    raise RuntimeError, 'custom Marshal hook ran'
  end

  def marshal_dump
    raise RuntimeError, 'custom Marshal hook ran'
  end
end

class LocalCyclicCauseError < RuntimeError
  def initialize(message, cause = nil)
    super(message)
    @cyclic_cause = cause
  end

  def cause
    @cyclic_cause
  end
end

class LocalBadFormattingError < RuntimeError
  def message
    raise RuntimeError, 'message formatting failed'
  end

  def backtrace
    raise RuntimeError, 'backtrace formatting failed'
  end
end

class LocalMutableCauseError < RuntimeError
  def cause=(cause)
    @chain_cause = cause
  end

  def cause
    @chain_cause
  end
end

class TestDRbExceptionEnvelope < Test::Unit::TestCase
  def setup
    @message = DRb::DRbMessage.new(load_limit: DRb::DRbServer.make_config[:load_limit],
                                  argc_limit: 256,
                                  exception_envelope: true)
  end

  def test_unknown_exception_class_uses_metadata_without_marshal_hooks
    error = make_exception(LocalEnvelopeOnlyError, 'business failure on server') do |exception|
      exception.set_backtrace(['server.rb:1:in `business_method`'])
    end
    failure = round_trip(error)

    assert_instance_of(DRb::RemoteFailure, failure)
    assert(!failure.is_a?(DRb::DRbConnError))
    assert_equal('DRbTests::LocalEnvelopeOnlyError', failure.remote_class)
    assert_equal('business failure on server', failure.remote_message)
    assert_equal(['server.rb:1:in `business_method`'], failure.remote_backtrace)
    assert_nil(failure.remote_cause)
    assert_not_predicate(failure, :truncated?)
  end

  def test_cyclic_cause_has_repeated_marker
    first = LocalCyclicCauseError.new('first cyclic cause')
    second = LocalCyclicCauseError.new('second cyclic cause', first)
    first.instance_variable_set(:@cyclic_cause, second)
    failure = round_trip(second)

    assert_equal('second cyclic cause', failure.remote_message)
    assert_equal('first cyclic cause', failure.remote_cause.remote_message)
    repeated = failure.remote_cause.remote_cause
    assert_equal('(exception cause repeated)', repeated.remote_message)
    assert_predicate(repeated, :repeated?)
    assert_predicate(failure, :repeated?)
    assert_not_predicate(failure, :truncated?)
  end

  def test_message_and_backtrace_failures_use_fallback_descriptions
    error = make_exception(LocalBadFormattingError, 'original message')
    failure = round_trip(error)

    assert_equal('(exception message unavailable)', failure.remote_message)
    assert_equal(['... (truncated)'], failure.remote_backtrace)
    assert_predicate(failure, :truncated?)
  end

  def test_cause_depth_is_limited_and_marked
    failure = round_trip(make_exception_chain(21))

    count = 0
    current = failure
    while current
      count += 1
      current = current.remote_cause
    end

    assert_equal(10, count)
    assert_predicate(failure, :truncated?)
  end

  def test_total_bytes_are_limited_and_marked
    error = make_exception(RuntimeError, 'x' * 200_000)
    io = StringIO.new
    @message.send_reply(io, false, error)
    wire_bytes = io.string.bytesize
    io.rewind
    failure = @message.recv_reply(io).last

    assert_operator(wire_bytes, :<=, DRb::DRbMessage::EXCEPTION_ENVELOPE_MAX_BYTES)
    assert(failure.remote_message.end_with?('... (truncated)'))
    assert_predicate(failure, :truncated?)
  end

  def test_default_protocol_still_marshals_exceptions
    default_message = DRb::DRbMessage.new(load_limit: 1024 * 1024, argc_limit: 256)
    error = make_exception(RuntimeError, 'default protocol')

    assert_instance_of(RuntimeError, round_trip(error, default_message))
  end

  private

  def make_exception(klass, message)
    begin
      raise klass, message
    rescue => error
      yield(error) if block_given?
      error
    end
  end

  def make_exception_chain(count)
    errors = count.times.map do |index|
      error = LocalMutableCauseError.new("cause #{index}")
      error.set_backtrace([])
      error
    end
    errors.each_cons(2) { |error, cause| error.cause = cause }
    errors.first
  end

  def round_trip(error, message = @message)
    io = StringIO.new
    message.send_reply(io, false, error)
    io.rewind
    message.recv_reply(io).last
  end
end

class TestDRbExceptionEnvelopeService < Test::Unit::TestCase
  include DRbBase
  def skip_without_tcp
    unless tcp_available?
      @omitted = true
      omit
    end
  end

  def tcp_available?
    socket = TCPServer.new('localhost', 0)
    socket.close
    true
  rescue SystemCallError
    false
  end

  def setup
    skip_without_tcp
    @drb_service ||= DRbService.new(exception_envelope: true)
    super
    setup_service('ut_exception_envelope.rb')
  end

  def test_unknown_business_class_from_other_process
    error = assert_raise(DRb::RemoteFailure) do
      @there.unknown_error
    end

    assert_equal('DRbTests::EnvelopeOnlyError', error.remote_class)
    assert_equal('business failure on server', error.remote_message)
    assert(error.remote_backtrace.any? { |line| line.include?('ut_exception_envelope.rb') })
    assert(error.backtrace.any? { |line| line.include?(__FILE__) })
    assert_not_equal(error.backtrace, error.remote_backtrace)
    assert_nil(error.remote_cause)
    assert_not_predicate(error, :truncated?)
  end
end

end
