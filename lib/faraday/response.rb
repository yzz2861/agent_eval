# frozen_string_literal: true

require 'forwardable'

module Faraday
  # Response represents an HTTP response from making an HTTP request.
  class Response
    extend Forwardable
    extend MiddlewareRegistry

    class << self
      # Configures how exceptions raised by +on_complete+ observers are
      # handled. Must be a callable receiving +(|error, response|)+.
      # When set, observer errors are handed to the collector and never
      # raised to the caller of {#finish}. When +nil+ (the default),
      # the first observer error is re-raised after all observers have
      # run, preserving the middleware error contract (e.g. RaiseError).
      # Errors are always recorded in {Response#completion_errors}.
      attr_writer :completion_error_handler

      # @return [#call, nil] the configured completion error handler.
      def completion_error_handler
        if instance_variable_defined?(:@completion_error_handler)
          @completion_error_handler
        elsif superclass.respond_to?(:completion_error_handler)
          superclass.completion_error_handler
        end
      end
    end

    def initialize(env = nil)
      @env = Env.from(env) if env
      @on_complete_callbacks = []
      @completion_errors = []
      @observers_processed = !env.nil?
    end

    attr_reader :env

    # Exceptions raised by +on_complete+ observers, in the order they
    # were raised. Populated regardless of the configured
    # {Response.completion_error_handler}.
    #
    # @return [Array<StandardError>]
    attr_reader :completion_errors

    def status
      finished? ? env.status : nil
    end

    def reason_phrase
      finished? ? env.reason_phrase : nil
    end

    def headers
      finished? ? env.response_headers : {}
    end

    def_delegator :headers, :[]

    def body
      finished? ? env.body : nil
    end

    def url
      finished? ? env.url : nil
    end

    def finished?
      !!env
    end

    # Whether all +on_complete+ observers registered so far have been
    # processed. This is the second of two completion milestones:
    # {#finished?} marks "the response has completed" (the env is
    # available), while +observers_processed?+ marks "all completion
    # observers have run".
    #
    # @return [Boolean]
    def observers_processed?
      @observers_processed
    end

    # Registers an observer to be called with the response env once the
    # response finishes.
    #
    # Observers run in registration order. An observer may register
    # further observers; those are appended to the current run and
    # execute after all previously registered observers. If the
    # response has already finished and all observers have been
    # processed, the observer runs immediately. In every case an
    # observer runs exactly once, and an exception it raises is
    # recorded in {#completion_errors} and reported to
    # {Response.completion_error_handler} without preventing the
    # remaining observers from running.
    #
    # @yieldparam env [Faraday::Env] the finished response env
    # @return [self]
    def on_complete(&block)
      if observers_processed?
        error = run_observer(block)
        raise error if error
      else
        @on_complete_callbacks << block
      end
      self
    end

    # Marks the response as finished and processes all registered
    # observers. A response can only finish once.
    #
    # All observers run even if some of them raise. Unless a custom
    # {Response.completion_error_handler} is configured, the first
    # observer error is then re-raised; the response keeps its original
    # status and body either way.
    #
    # @param env [Faraday::Env, Hash] the response env
    # @return [self]
    # @raise [RuntimeError] if the response has already finished
    def finish(env)
      raise 'response already finished' if finished?

      @env = env.is_a?(Env) ? env : Env.from(env)
      process_observers
      self
    end

    def success?
      finished? && env.success?
    end

    def to_hash
      {
        status: status, body: body,
        response_headers: headers,
        url: url
      }
    end

    # because @on_complete_callbacks cannot be marshalled
    def marshal_dump
      finished? ? to_hash : nil
    end

    def marshal_load(env)
      @env = Env.from(env)
      @on_complete_callbacks = []
      @completion_errors = []
      @observers_processed = true
    end

    # Expand the env with more properties, without overriding existing ones.
    # Useful for applying request params after restoring a marshalled Response.
    def apply_request(request_env)
      raise "response didn't finish yet" unless finished?

      @env = Env.from(request_env).update(@env)
      self
    end

    private

    # Runs registered observers in registration order. Observers
    # registered while this loop runs are appended to the queue and
    # picked up here, so ordering stays deterministic.
    def process_observers
      first_error = nil
      index = 0
      while (callback = @on_complete_callbacks[index])
        error = run_observer(callback)
        first_error ||= error
        index += 1
      end
      @on_complete_callbacks.clear
      @observers_processed = true
      raise first_error if first_error
    end

    # Runs a single observer, recording and reporting any error it
    # raises.
    #
    # @return [StandardError, nil] the unhandled error, if no
    #   completion_error_handler is configured to absorb it
    def run_observer(callback)
      callback.call(@env)
      nil
    rescue StandardError => e
      @completion_errors << e
      handler = self.class.completion_error_handler
      handler&.call(e, self)
      handler ? nil : e
    end
  end
end

require 'faraday/response/json'
require 'faraday/response/logger'
require 'faraday/response/raise_error'
