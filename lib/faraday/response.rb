# frozen_string_literal: true

require 'forwardable'
require 'thread'

module Faraday
  # Response represents an HTTP response from making an HTTP request.
  class Response
    # Stores exceptions raised by completion observers.
    class ErrorCollector
      def initialize(errors = [])
        @errors = errors
      end

      def call(error, response = nil)
        @errors << [error, response]
      end

      def errors
        @errors.map(&:first)
      end

      def to_a
        @errors
      end
    end

    extend Forwardable
    extend MiddlewareRegistry

    class << self
      # @return [#call, #<<, nil] Receives exceptions raised by observers.
      attr_accessor :default_error_collector
    end

    # @param env [Faraday::Env, Hash, nil] Existing finalized environment.
    # @param error_collector [#call, #<<, nil] Per-response observer error
    #   collector. Defaults to {default_error_collector}, then an
    #   {ErrorCollector}.
    def initialize(
      env = nil,
      positional_error_collector = nil,
      error_collector: nil,
      completion_error_collector: nil,
      **env_attributes
    )
      env = env_attributes if env.nil? && !env_attributes.empty?
      @env = Env.from(env) if env
      @on_complete_callbacks = []
      @completion_observers = []
      @completion_mutex = Mutex.new
      @completion_condition = ConditionVariable.new
      @dispatching_completion_observers = false
      @completion_observers_processed = finished?
      @error_collector = completion_error_collector ||
                         error_collector ||
                         positional_error_collector ||
                         self.class.default_error_collector ||
                         ErrorCollector.new
    end

    attr_reader :env
    attr_accessor :error_collector

    alias completion_error_collector error_collector
    alias completion_error_collector= error_collector=

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

    # @return [Boolean] whether the response environment has been assigned.
    #   This becomes true before completion observers are processed.
    def finished?
      !!env
    end

    # Registers an observer that receives the finalized response environment.
    #
    # Observers registered before {#finish} run after the legacy
    # {#on_complete} middleware chain, in FIFO order. Observers added by an
    # observer are appended to that same FIFO queue. Observers registered when
    # no dispatch is active run immediately.
    #
    # @yieldparam env [Faraday::Env] Final response environment.
    # @return [Response] self
    def on_finished(&observer)
      return self unless observer

      start_dispatch = false
      @completion_mutex.synchronize do
        if finished? && !@dispatching_completion_observers
          start_dispatch = true
          @dispatching_completion_observers = true
          @completion_observers_processed = false
        end
        @completion_observers << observer
      end

      dispatch_completion_observers if start_dispatch
      self
    end

    alias on_finish on_finished
    alias on_completion on_finish

    # Waits for the active or pending initial observer dispatch to finish.
    #
    # @param timeout [Numeric, nil] Maximum seconds to wait.
    # @return [Response, nil] self if processing completed, nil on timeout.
    def wait_for_completion_observers(timeout = nil)
      deadline = timeout ? monotonic_time + timeout : nil

      @completion_mutex.synchronize do
        until @completion_observers_processed
          remaining = deadline ? deadline - monotonic_time : nil
          return nil if remaining && !remaining.positive?

          @completion_condition.wait(@completion_mutex, remaining)
        end
      end
      self
    end

    # @return [Boolean] whether every observer in the latest dispatch has run.
    #   This remains false between response finalization and observer drain.
    def completion_observers_processed?
      @completion_observers_processed
    end

    alias observers_complete? completion_observers_processed?
    alias complete? completion_observers_processed?

    # Registers a middleware completion callback. This existing API remains
    # responsible for response-processing middleware and keeps its historical
    # exception behavior; plugins that only observe the result should use
    # {#on_finish}.
    def on_complete(&block)
      if finished?
        yield(env)
      else
        @on_complete_callbacks << block
      end
      self
    end

    # Assigns the response environment exactly once, then runs middleware and
    # observers. {#finished?} is true as soon as the environment is assigned,
    # while {#completion_observers_processed?} becomes true only after the
    # observer queue drains.
    def finish(env)
      @completion_mutex.synchronize do
        raise 'response already finished' if finished?

        @env = env.is_a?(Env) ? env : Env.from(env)
        @dispatching_completion_observers = true
        @completion_observers_processed = false
      end

      begin
        @on_complete_callbacks.each { |callback| callback.call(@env) }
      ensure
        dispatch_completion_observers
      end
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
      initialize
      @env = Env.from(env)
      @completion_observers_processed = true
    end

    # Expand the env with more properties, without overriding existing ones.
    # Useful for applying request params after restoring a marshalled Response.
    def apply_request(request_env)
      raise "response didn't finish yet" unless finished?

      @env = Env.from(request_env).update(@env)
      self
    end

    private

    def dispatch_completion_observers
      collector_failure = nil
      environment = nil

      loop do
        observer = @completion_mutex.synchronize do
          @completion_observers.shift
        end
        break unless observer

        environment ||= observer_environment
        begin
          observer.call(environment)
        rescue StandardError => error
          collector_failure =
            report_completion_error(error) || collector_failure
        end
      end
    ensure
      @completion_mutex.synchronize do
        @dispatching_completion_observers = false
        @completion_observers_processed = true
        @completion_condition.broadcast
      end
      raise collector_failure if collector_failure
    end

    def report_completion_error(error)
      if @error_collector.respond_to?(:call)
        call_error_collector(error)
      elsif @error_collector.respond_to?(:<<)
        @error_collector << error
        nil
      else
        raise TypeError, 'error collector must respond to #call or #<<'
      end
    rescue StandardError => collector_error
      collector_error
    end

    def call_error_collector(error)
      if @error_collector.respond_to?(:arity) && @error_collector.arity == 1
        @error_collector.call(error)
      else
        @error_collector.call(error, self)
      end
      nil
    end

    def monotonic_time
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def observer_environment
      environment = Env.from(@env)
      environment.response = nil
      freeze_environment(environment)
      observer_response = self.class.new(environment)
      environment.response = observer_response
      observer_response.env.response = observer_response
      environment.freeze
      observer_response.freeze
      environment
    end

    def freeze_environment(environment)
      environment.members.each do |attribute|
        value = environment.public_send(attribute)
        next if attribute == :response || value.nil?

        environment.public_send(
          :"#{attribute}=", immutable_environment_value(value)
        )
      end

      environment.custom_members.each do |key, value|
        environment.custom_members[key] = immutable_environment_value(value)
      end
    end

    def immutable_environment_value(value)
      case value
      when Options
        value.class.from(value).tap do |copy|
          copy.each do |key, member_value|
            next if member_value.nil?

            copy[key] = immutable_environment_value(member_value)
          end
        end.freeze
      when Hash
        value.each_with_object(value.class.new) do |(key, member_value), copy|
          copy_key = immutable_environment_value(key)
          copy[copy_key] = immutable_environment_value(member_value)
        end.freeze
      when Array
        value.map { |item| immutable_environment_value(item) }.freeze
      when String
        value.dup.freeze
      when URI::Generic
        value.dup.freeze
      else
        value
      end
    end
  end
end

require 'faraday/response/json'
require 'faraday/response/logger'
require 'faraday/response/raise_error'
