# frozen_string_literal: false
require_relative 'drbtest'

module DRbTests

  DRbService.add_service_command('ut_envelope.rb')

  # Unit tests for DRb::ExceptionEnvelope and DRb::RemoteFailure.
  # These do not need a running service.
  class TestExceptionEnvelopeUnit < Test::Unit::TestCase
    class HookedError < RuntimeError
      def _dump(*)        raise 'marshal hook must not run'; end
      def self._load(*)   raise 'marshal hook must not run'; end
      def marshal_dump;   raise 'marshal hook must not run'; end
      def marshal_load(*) raise 'marshal hook must not run'; end
    end

    class BadFormatError < RuntimeError
      def message
        raise 'message formatting is broken'
      end

      def backtrace
        raise 'backtrace is broken'
      end
    end

    def capture_chain(depth)
      raise_chain(depth)
    rescue RuntimeError => error
      error
    end

    def raise_chain(depth)
      raise RuntimeError, 'innermost cause' if depth.zero?
      begin
        raise_chain(depth - 1)
      rescue RuntimeError
        raise RuntimeError, "cause level #{depth}"
      end
    end

    def test_capture_carries_only_plain_data
      error = HookedError.new('secret')
      error.set_backtrace(["app.rb:1:in `work'", "app.rb:2:in `run'"])
      envelope = DRb::ExceptionEnvelope.capture(error)
      assert_equal('DRbTests::TestExceptionEnvelopeUnit::HookedError', envelope.class_name)
      assert_equal('secret', envelope.message)
      assert_equal(["app.rb:1:in `work'", "app.rb:2:in `run'"], envelope.backtrace)
      assert_nil(envelope.cause)
      assert_equal([], envelope.truncated)
      assert_equal(false, envelope.truncated?)
    end

    def test_capture_never_marshals_the_exception
      envelope = DRb::ExceptionEnvelope.capture(HookedError.new('secret'))
      # The envelope itself must survive a Marshal round trip without
      # touching the original exception's hooks.
      loaded = Marshal.load(Marshal.dump(envelope))
      assert_equal('secret', loaded.message)
    end

    def test_capture_cyclic_cause
      first = RuntimeError.new('first')
      second = RuntimeError.new('second')
      first.define_singleton_method(:cause) { second }
      second.define_singleton_method(:cause) { first }
      envelope = DRb::ExceptionEnvelope.capture(first)
      assert_equal('first', envelope.message)
      assert_equal('second', envelope.cause.message)
      cycle = envelope.cause.cause
      assert_include(cycle.truncated, :cause_cycle)
      assert_equal(true, cycle.truncated?)
      assert_nil(cycle.cause)
    end

    def test_capture_depth_limit
      envelope = DRb::ExceptionEnvelope.capture(capture_chain(20), :max_depth => 3)
      node = envelope
      depth = 0
      while node.cause
        node = node.cause
        depth += 1
      end
      assert_equal(3, depth)
      assert_include(node.truncated, :cause_depth)
    end

    def test_capture_byte_limit_marks_truncation
      error = RuntimeError.new('x' * 100_000)
      envelope = DRb::ExceptionEnvelope.capture(error, :max_bytes => 1024)
      assert_operator(envelope.message.bytesize, :<=, 1024)
      assert_include(envelope.message, DRb::ExceptionEnvelope::TRUNCATION_MARKER)
      assert_include(envelope.truncated, :message)
    end

    def test_capture_backtrace_line_limit
      error = RuntimeError.new('boom')
      error.set_backtrace(Array.new(200) { |i| "app.rb:#{i}:in `work'" })
      envelope = DRb::ExceptionEnvelope.capture(error, :max_backtrace_lines => 10)
      assert_include(envelope.truncated, :backtrace)
      assert_equal(DRb::ExceptionEnvelope::TRUNCATION_MARKER, envelope.backtrace.last)
      assert_operator(envelope.backtrace.size, :<=, 11)
    end

    def test_capture_message_formatting_failure_falls_back
      envelope = DRb::ExceptionEnvelope.capture(BadFormatError.new)
      assert_match(/message unavailable/, envelope.message)
      assert_equal([], envelope.backtrace)
    end

    def test_capture_unreadable_cause
      error = RuntimeError.new('no cause for you')
      error.define_singleton_method(:cause) { raise 'cause is broken' }
      envelope = DRb::ExceptionEnvelope.capture(error)
      assert_nil(envelope.cause)
      assert_include(envelope.truncated, :cause_unreadable)
    end

    def test_remote_failure_is_not_a_transport_error
      envelope = DRb::ExceptionEnvelope.capture(capture_chain(2))
      failure = DRb::RemoteFailure.new(envelope)
      assert_kind_of(DRb::DRbError, failure)
      assert_not_kind_of(DRb::DRbConnError, failure)
      assert_equal('RuntimeError', failure.remote_class_name)
      assert_equal(envelope.backtrace, failure.remote_backtrace)
    end

    def test_raise_from_envelope_rebuilds_cause_chain_and_boundary
      envelope = DRb::ExceptionEnvelope.capture(capture_chain(2))
      local = ["client.rb:9:in `call'"]
      error = assert_raise(DRb::RemoteFailure) do
        DRb::RemoteFailure.raise_from_envelope(envelope, 'druby://example:1234', local)
      end
      assert_kind_of(DRb::RemoteFailure, error.cause)
      assert_kind_of(DRb::RemoteFailure, error.cause.cause)
      assert_nil(error.cause.cause.cause)

      boundary = DRb::RemoteFailure::REMOTE_LOCAL_BOUNDARY
      index = error.backtrace.index(boundary)
      assert_not_nil(index)
      assert_match(/\A\(druby:\/\/example:1234\) /, error.backtrace.first)
      assert_equal(local.first, error.backtrace[index + 1])
    end
  end

  # End-to-end tests against a service running with
  # :exception_envelope enabled (ut_envelope.rb).
  class TestExceptionEnvelopeService < Test::Unit::TestCase
    include DRbBase

    def setup
      super
      setup_service 'ut_envelope.rb'
    end

    def test_unknown_class_becomes_remote_failure
      error = assert_raise(DRb::RemoteFailure) { @there.business_failure }
      assert_equal('DRbTests::EnvelopeFront::BusinessError', error.remote_class_name)
      assert_include(error.message, 'business failure 42')
      assert_not_empty(error.remote_backtrace)
    end

    def test_marshal_hooks_are_not_run
      error = assert_raise(DRb::RemoteFailure) { @there.hooked_failure }
      assert_equal('DRbTests::EnvelopeFront::HookedError', error.remote_class_name)
      assert_include(error.message, 'hooks must not run')
    end

    def test_bad_format_failure_falls_back
      error = assert_raise(DRb::RemoteFailure) { @there.bad_format_failure }
      assert_match(/message unavailable/, error.message)
      assert_equal([], error.remote_backtrace)
    end

    def test_cyclic_cause_is_truncated
      error = assert_raise(DRb::RemoteFailure) { @there.cyclic_cause_failure }
      assert_include(error.message, 'first link')
      assert_include(error.cause.message, 'second link')
      cycle = error.cause.cause
      assert_kind_of(DRb::RemoteFailure, cycle)
      assert_include(cycle.truncated, :cause_cycle)
      assert_nil(cycle.cause)
    end

    def test_deep_cause_chain_is_truncated
      error = assert_raise(DRb::RemoteFailure) { @there.deep_cause_failure }
      depth = 0
      node = error
      while node.cause
        node = node.cause
        depth += 1
      end
      assert_equal(DRb::ExceptionEnvelope::DEFAULT_MAX_DEPTH, depth)
      assert_include(node.truncated, :cause_depth)
    end

    def test_huge_message_is_truncated
      error = assert_raise(DRb::RemoteFailure) { @there.huge_message_failure }
      limit = DRb::ExceptionEnvelope::DEFAULT_MAX_BYTES
      assert_operator(error.message.bytesize, :<=, limit + 100)
      assert_include(error.message, DRb::ExceptionEnvelope::TRUNCATION_MARKER)
      assert_include(error.truncated, :message)
    end

    def test_backtrace_keeps_remote_local_boundary
      error = assert_raise(DRb::RemoteFailure) { @there.business_failure }
      boundary = DRb::RemoteFailure::REMOTE_LOCAL_BOUNDARY
      index = error.backtrace.index(boundary)
      assert_not_nil(index)
      assert_match(/\A\(druby:\/\//, error.backtrace.first)
      assert_include(error.backtrace[index + 1], 'test_exception_envelope.rb')
    end

    def test_transport_error_is_not_a_remote_failure
      assert_raise(DRb::DRbConnError) { @there.echo('1' * 8192) }
    end
  end

  # The default protocol (no :exception_envelope) must be unchanged.
  class TestExceptionEnvelopeCompat < Test::Unit::TestCase
    include DRbBase

    def setup
      super
      setup_service 'ut_drb.rb'
    end

    def test_default_protocol_is_unchanged
      # An error whose class is unknown to the client is still
      # reported as DRbUnknownError...
      assert_raise(DRb::DRbUnknownError) { @there.unknown_error }
      # ...and a client-known error still arrives as its own class.
      assert_raise(NoMethodError) { @there.remote_no_method_error }
    end
  end
end
