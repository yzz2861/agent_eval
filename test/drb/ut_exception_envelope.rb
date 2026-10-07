# frozen_string_literal: false
require 'drb/drb'
require 'drb/extserv'

module DRbTests

class EnvelopeOnlyError < RuntimeError
  def _dump(_limit)
    raise RuntimeError, 'custom Marshal hook ran'
  end

  def marshal_dump
    raise RuntimeError, 'custom Marshal hook ran'
  end
end

class CyclicCauseError < RuntimeError
  def initialize(message, cause)
    super(message)
    @cyclic_cause = cause
  end

  def cause
    @cyclic_cause
  end
end

class BadFormattingError < RuntimeError
  def message
    raise RuntimeError, 'message formatting failed'
  end

  def backtrace
    raise RuntimeError, 'backtrace formatting failed'
  end
end

class MutableCauseError < RuntimeError
  def cause=(cause)
    @chain_cause = cause
  end

  def cause
    @chain_cause
  end
end

class ExceptionEnvelopeService
  include DRbUndumped

  def unknown_error
    raise EnvelopeOnlyError, 'business failure on server'
  end

  def cyclic_cause_error
    first = CyclicCauseError.new('first cyclic cause', nil)
    second = CyclicCauseError.new('second cyclic cause', first)
    first.instance_variable_set(:@cyclic_cause, second)
    raise second
  end

  def bad_formatting_error
    raise BadFormattingError, 'original message'
  end

  def long_cause_error
    errors = 21.times.map do |index|
      error = MutableCauseError.new("cause #{index}")
      error.set_backtrace([])
      error
    end
    errors.each_cons(2) { |error, cause| error.cause = cause }
    raise errors.first
  end

  def large_error
    raise RuntimeError, 'x' * 200_000
  end
end

end

if __FILE__ == $0
  def ARGV.shift
    it = super()
    raise "usage: #{$0} <manager-uri> <name>" unless it
    it
  end

  DRb.start_service('druby://localhost:0',
                    DRbTests::ExceptionEnvelopeService.new,
                    exception_envelope: true)
  es = DRb::ExtServ.new(ARGV.shift, ARGV.shift)
  DRb.thread.join
  es.stop_service if es.alive?
end
