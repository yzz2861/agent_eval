# frozen_string_literal: true

module Faraday
  # Base class for all Faraday adapters. Adapters are
  # responsible for fulfilling a Faraday request.
  class Adapter
    extend MiddlewareRegistry

    CONTENT_LENGTH = 'Content-Length'

    # Capability for streaming response bodies through the +on_data+ request
    # option (see {Faraday::Env#stream_response}).
    STREAMING_RESPONSES = :streaming_responses

    # Capability for running multiple requests concurrently.
    PARALLEL = :parallel

    # Capability for configuring certificate verification (+verify+,
    # +verify_mode+, +cert_store+, +ca_file+, +ca_path+).
    TLS_VERIFY = :tls_verify

    # Capability for setting the minimum TLS version (+min_version+).
    TLS_MIN_VERSION = :tls_min_version

    # Capability for setting the maximum TLS version (+max_version+).
    # Also implies support for the legacy +version+ SSL option.
    TLS_MAX_VERSION = :tls_max_version

    # Capability for configuring the cipher list (+ciphers+).
    TLS_CIPHERS = :tls_ciphers

    # Capability for client certificate authentication (+client_cert+,
    # +client_key+, +certificate+, +private_key+).
    TLS_CLIENT_CERT = :tls_client_cert

    # Capability for configuring the certificate verification depth
    # (+verify_depth+).
    TLS_VERIFY_DEPTH = :tls_verify_depth

    TIMEOUT_KEYS = {
      read: :read_timeout,
      open: :open_timeout,
      write: :write_timeout
    }.freeze

    class << self
      # Declares that this adapter supports the given capabilities. The
      # declaration is inherited by subclasses, which can extend it with their
      # own. Adapters that never declare anything support no capabilities.
      #
      # @example
      #   class MyAdapter < Faraday::Adapter
      #     supports_capabilities Faraday::Adapter::STREAMING_RESPONSES
      #   end
      #
      # @param capabilities [Array<Symbol>] capabilities supported by the
      #        adapter. Prefer using the constants defined on {Adapter} when
      #        possible, but adapter gems may introduce their own symbols.
      # @return [Array<Symbol>] all capabilities declared on this adapter,
      #         including inherited ones.
      def supports_capabilities(*capabilities)
        @declared_capabilities.concat(capabilities.flatten.map(&:to_sym))
        @declared_capabilities.uniq!
        declared_capabilities
      end
      alias supports_capability supports_capabilities

      # @return [Array<Symbol>] capabilities declared for this adapter,
      #   including capabilities inherited from parent adapters.
      def declared_capabilities
        @declared_capabilities.dup
      end

      # Checks whether the adapter declares support for all the given
      # capabilities. Missing declarations are treated as unknown and
      # therefore *not* supported.
      #
      # @param capabilities [Array<Symbol>] required capabilities.
      # @return [Boolean] true only if every given capability was declared.
      def supports_capabilities?(*capabilities)
        required = capabilities.flatten.map(&:to_sym)
        required.all? do |capability|
          @declared_capabilities.include?(capability)
        end
      end
      alias supports_capability? supports_capabilities?

      # @return [Array<Symbol>] capabilities from +required+ that this adapter
      #   does not declare.
      def missing_capabilities(*required)
        required.flatten.map(&:to_sym).uniq.reject do |capability|
          @declared_capabilities.include?(capability)
        end
      end

      def inherited(subclass)
        super
        inherited_capabilities = @declared_capabilities.dup
        subclass.instance_variable_set(:@declared_capabilities,
                                      inherited_capabilities)
      end
    end

    @declared_capabilities = []

    # This module marks an Adapter as supporting parallel requests.
    module Parallelism
      attr_writer :supports_parallel

      def supports_parallel?
        @supports_parallel
      end

      def inherited(subclass)
        super
        subclass.supports_parallel = supports_parallel?
      end
    end

    extend Parallelism

    self.supports_parallel = false

    def initialize(_app = nil, opts = {}, &block)
      @app = lambda(&:response)
      @connection_options = opts
      @config_block = block
    end

    # @return [Array<Symbol>] capabilities declared by this adapter class.
    def declared_capabilities
      self.class.declared_capabilities
    end

    # @param capabilities [Array<Symbol>] required capabilities.
    # @return [Boolean] true only if every capability was declared.
    def supports_capabilities?(*capabilities)
      self.class.supports_capabilities?(*capabilities)
    end
    alias supports_capability? supports_capabilities?

    # Yields or returns an adapter's configured connection. Depends on
    # #build_connection being defined on this adapter.
    #
    # @param env [Faraday::Env, Hash] The env object for a faraday request.
    #
    # @return The return value of the given block, or the HTTP connection object
    #         if no block is given.
    def connection(env)
      conn = build_connection(env)
      return conn unless block_given?

      yield conn
    end

    # Close any persistent connections. The adapter should still be usable
    # after calling close.
    def close
      # Possible implementation:
      #   @app.close if @app.respond_to?(:close)
    end

    def call(env)
      env.clear_body if env.needs_body?
      env.response = Response.new
    end

    private

    def save_response(env, status, body, headers = nil, reason_phrase = nil, finished: true)
      env.status = status
      env.body = body
      env.reason_phrase = reason_phrase&.to_s&.strip
      env.response_headers = Utils::Headers.new.tap do |response_headers|
        response_headers.update headers unless headers.nil?
        yield(response_headers) if block_given?
      end

      env.response.finish(env) unless env.parallel? || !finished
      env.response
    end

    # Fetches either a read, write, or open timeout setting. Defaults to the
    # :timeout value if a more specific one is not given.
    #
    # @param type [Symbol] Describes which timeout setting to get: :read,
    #                      :write, or :open.
    # @param options [Hash] Hash containing Symbol keys like :timeout,
    #                       :read_timeout, :write_timeout, or :open_timeout
    #
    # @return [Integer, nil] Timeout duration in seconds, or nil if no timeout
    #                        has been set.
    def request_timeout(type, options)
      key = TIMEOUT_KEYS.fetch(type) do
        msg = "Expected :read, :write, :open. Got #{type.inspect} :("
        raise ArgumentError, msg
      end
      options[key] || options[:timeout]
    end
  end
end

require 'faraday/adapter/test'
