# frozen_string_literal: false
require 'drb/drb'
require 'drb/extserv'

module DRbTests

  # Front object for the exception envelope tests.  The error
  # classes defined here are intentionally not available in the
  # client process.
  class EnvelopeFront
    include DRbUndumped

    class BusinessError < RuntimeError
      attr_reader :code

      def initialize(code)
        @code = code
        super("business failure #{code}")
      end
    end

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

    def business_failure
      raise BusinessError, 42
    end

    def hooked_failure
      raise HookedError, 'hooks must not run'
    end

    def bad_format_failure
      raise BadFormatError
    end

    def cyclic_cause_failure
      first = RuntimeError.new('first link')
      second = RuntimeError.new('second link')
      first.define_singleton_method(:cause) { second }
      second.define_singleton_method(:cause) { first }
      raise first
    end

    def deep_cause_failure
      chain(32)
    end

    def huge_message_failure
      raise BusinessError, 'x' * (1024 * 1024)
    end

    def echo(arg)
      arg
    end

    private

    def chain(depth)
      raise RuntimeError, 'innermost cause' if depth.zero?
      begin
        chain(depth - 1)
      rescue RuntimeError
        raise RuntimeError, "cause level #{depth}"
      end
    end
  end
end

if __FILE__ == $0
  def ARGV.shift
    it = super()
    raise "usage: #{$0} <manager-uri> <name>" unless it
    it
  end

  DRb::DRbServer.default_load_limit(4096)
  DRb.start_service('druby://localhost:0', DRbTests::EnvelopeFront.new,
                    :exception_envelope => true)
  es = DRb::ExtServ.new(ARGV.shift, ARGV.shift)
  DRb.thread.join
  es.stop_service if es.alive?
end
