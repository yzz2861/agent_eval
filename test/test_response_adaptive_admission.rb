# frozen_string_literal: true

require_relative "helper"
require "puma/response"
require "puma/adaptive_admission"
require "puma/thread_pool"
require "puma/log_writer"

class TestResponseAdaptiveAdmission < PumaTest
  parallelize_me!

  class ResponseHost
    include Puma::Response

    attr_accessor :app, :thread_pool, :early_hints, :log_writer

    def initialize(app, thread_pool)
      @app = app
      @thread_pool = thread_pool
      @early_hints = false
      @log_writer = Puma::LogWriter.strings
    end

    def closed_socket?(_socket)
      false
    end

    def lowlevel_error(error, _env, status)
      [status, {}, [error.message]]
    end

    def prepare_response(status, _headers, _body, _requests, _client)
      status
    end
  end

  class Pool
    attr_reader :admission

    def initialize(admission)
      @admission = admission
    end

    def with_force_shutdown
      yield
    end
  end

  FakeIOBuffer = Struct.new do
    def reset; end
  end

  Client = Struct.new(:env, :io, :hijacked) do
    def io_buffer
      @io_buffer ||= FakeIOBuffer.new
    end

    def tempfile_close; end
  end

  def host(app, **options)
    clock = Class.new do
      attr_reader :now

      def initialize
        @now = 0.0
      end

      def advance(seconds)
        @now += seconds
      end

      def call
        @now
      end
    end.new
    admission = Puma::AdaptiveAdmission.new(
      { min_samples: 2, failure_threshold: 0.5, cooldown: 0 }.merge(options),
      max_threads: 2,
      clock: clock
    )
    [ResponseHost.new(app, Pool.new(admission)), admission, clock]
  end

  def request(clock)
    env = {}
    client = Client.new(env, nil, false)
    clock.advance(1)
    [client, env]
  end

  def test_application_500_reduces_admission
    host, admission, clock = host(->(_env) { [500, {}, ["failure"]] })

    2.times do
      client, = request(clock)
      assert_equal 500, host.handle_request(nil, client, 1)
    end

    assert_equal 1, admission.limit
  end

  def test_application_503_does_not_reduce_admission
    host, admission, clock = host(->(_env) { [503, {}, ["unavailable"]] })
    2.times do
      client, = request(clock)
      assert_equal 503, host.handle_request(nil, client, 1)
    end

    assert_equal 2, admission.limit
  end

  def test_application_exception_reduces_admission
    host, admission, clock = host(->(_env) { raise "boom" })
    2.times do
      client, = request(clock)
      assert_equal 500, host.handle_request(nil, client, 1)
    end

    assert_equal 1, admission.limit
  end
end
