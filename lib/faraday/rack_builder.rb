# frozen_string_literal: true

require 'faraday/adapter_registry'

module Faraday
  # A Builder that processes requests into responses by passing through an inner
  # middleware stack (heavily inspired by Rack).
  #
  # @example
  #   Faraday::Connection.new(url: 'http://httpbingo.org') do |builder|
  #     builder.request  :url_encoded  # Faraday::Request::UrlEncoded
  #     builder.adapter  :net_http     # Faraday::Adapter::NetHttp
  #   end
  class RackBuilder
    # Used to detect missing arguments
    NO_ARGUMENT = Object.new

    LOCK_ERR = "can't modify middleware stack after making a request"
    MISSING_ADAPTER_ERROR = "An attempt to run a request with a Faraday::Connection without adapter has been made.\n" \
                            "Please set Faraday.default_adapter or provide one when initializing the connection.\n" \
                            'For more info, check https://lostisland.github.io/faraday/usage/.'

    attr_accessor :handlers

    # Error raised when trying to modify the stack after calling `lock!`
    class StackLocked < RuntimeError; end

    # borrowed from ActiveSupport::Dependencies::Reference &
    # ActionDispatch::MiddlewareStack::Middleware
    class Handler
      REGISTRY = Faraday::AdapterRegistry.new

      attr_reader :name

      def initialize(klass, *args, **kwargs, &block)
        @name = klass.to_s
        REGISTRY.set(klass) if klass.respond_to?(:name)
        @args = args
        @kwargs = kwargs
        @block = block
      end

      def klass
        REGISTRY.get(@name)
      end

      def inspect
        @name
      end

      def ==(other)
        if other.is_a? Handler
          name == other.name
        elsif other.respond_to? :name
          klass == other
        else
          @name == other.to_s
        end
      end

      def build(app = nil)
        klass.new(app, *@args, **@kwargs, &@block)
      end
    end

    def initialize(&block)
      @adapter = nil
      @handlers = []
      @required_capabilities = []
      build(&block)
    end

    def initialize_dup(original)
      super
      @adapter = original.adapter
      @handlers = original.handlers.dup
      @required_capabilities = original.required_capabilities.dup
    end

    def build
      raise_if_locked
      block_given? ? yield(self) : request(:url_encoded)
      adapter(Faraday.default_adapter, **Faraday.default_adapter_options) unless @adapter
    end

    def [](idx)
      @handlers[idx]
    end

    # Locks the middleware stack to ensure no further modifications are made.
    def lock!
      @handlers.freeze
    end

    def locked?
      @handlers.frozen?
    end

    def use(klass, ...)
      if klass.is_a? Symbol
        use_symbol(Faraday::Middleware, klass, ...)
      else
        raise_if_locked
        raise_if_adapter(klass)
        @handlers << self.class::Handler.new(klass, ...)
      end
    end

    def request(key, ...)
      use_symbol(Faraday::Request, key, ...)
    end

    def response(...)
      use_symbol(Faraday::Response, ...)
    end

    def adapter(klass = NO_ARGUMENT, *args, **kwargs, &block)
      return @adapter if klass == NO_ARGUMENT || klass.nil?

      klass = Faraday::Adapter.lookup_middleware(klass) if klass.is_a?(Symbol)
      @adapter = self.class::Handler.new(klass, *args, **kwargs, &block)
      @adapter
    end

    # @return [Array<Symbol>] capabilities the configured adapter must declare.
    attr_reader :required_capabilities

    # Declares capabilities the adapter must support for the lifetime of
    # the connection. Fixed requirements are validated once the connection
    # (and its adapter) has been configured.
    #
    # @param capabilities [Array<Symbol>] required capabilities.
    # @return [Array<Symbol>] the full list of required capabilities.
    def require_capabilities(*capabilities)
      @required_capabilities.concat(capabilities.flatten.map(&:to_sym)).uniq!
      @required_capabilities
    end

    # Validates that the configured adapter declares all fixed connection
    # capabilities. Called when the connection is built and again lazily when
    # the stack is compiled.
    #
    # @raise [Faraday::MissingCapabilitiesError] if a required capability is
    #   not declared by the adapter.
    def verify_capabilities!
      ensure_capabilities!(@required_capabilities, scope: 'connection')
    end

    ## methods to push onto the various positions in the stack:

    def insert(index, ...)
      raise_if_locked
      index = assert_index(index)
      handler = self.class::Handler.new(...)
      @handlers.insert(index, handler)
    end

    alias insert_before insert

    def insert_after(index, ...)
      index = assert_index(index)
      insert(index + 1, ...)
    end

    def swap(index, ...)
      raise_if_locked
      index = assert_index(index)
      @handlers.delete_at(index)
      insert(index, ...)
    end

    def delete(handler)
      raise_if_locked
      @handlers.delete(handler)
    end

    # Processes a Request into a Response by passing it through this Builder's
    # middleware stack.
    #
    # @param connection [Faraday::Connection]
    # @param request [Faraday::Request]
    #
    # @return [Faraday::Response]
    def build_response(connection, request)
      ensure_capabilities!(request_capabilities(request), scope: 'request')
      app.call(build_env(connection, request))
    end

    # The "rack app" wrapped in middleware. All requests are sent here.
    #
    # The builder is responsible for creating the app object. After this,
    # the builder gets locked to ensure no further modifications are made
    # to the middleware stack.
    #
    # Returns an object that responds to `call` and returns a Response.
    def app
      @app ||= begin
        lock!
        ensure_adapter!
        ensure_capabilities!(required_capabilities, scope: 'connection')
        to_app
      end
    end

    def to_app
      # last added handler is the deepest and thus closest to the inner app
      # adapter is always the last one
      @handlers.reverse.inject(@adapter.build) do |app, handler|
        handler.build(app)
      end
    end

    def ==(other)
      other.is_a?(self.class) &&
        @handlers == other.handlers &&
        @adapter == other.adapter
    end

    # ENV Keys
    # :http_method - a symbolized request HTTP method (:get, :post)
    # :body   - the request body that will eventually be converted to a string.
    # :url    - URI instance for the current request.
    # :status           - HTTP response status code
    # :request_headers  - hash of HTTP Headers to be sent to the server
    # :response_headers - Hash of HTTP headers from the server
    # :parallel_manager - sent if the connection is in parallel mode
    # :request - Hash of options for configuring the request.
    #   :timeout      - open/read timeout Integer in seconds
    #   :open_timeout - read timeout Integer in seconds
    #   :proxy        - Hash of proxy options
    #     :uri        - Proxy Server URI
    #     :user       - Proxy server username
    #     :password   - Proxy server password
    # :ssl - Hash of options for configuring SSL requests.
    def build_env(connection, request)
      exclusive_url = connection.build_exclusive_url(
        request.path, request.params,
        request.options.params_encoder
      )

      Env.new(request.http_method, request.body, exclusive_url,
              request.options, request.headers, connection.ssl,
              connection.parallel_manager)
    end

    private

    def adapter_klass
      @adapter&.klass
    end

    # Extracts the per-request required capabilities, tolerating request
    # option objects that predate the capability feature.
    def request_capabilities(request)
      options = request.options
      return [] unless options.respond_to?(:required_capabilities, true)

      options.required_capabilities || []
    end

    def ensure_capabilities!(capabilities, scope:)
      return if Array(capabilities).empty?

      ensure_adapter!
      missing = adapter_klass.missing_capabilities(capabilities)
      return if missing.empty?

      raise Faraday::MissingCapabilitiesError.new(@adapter.name, missing,
                                                 scope: scope)
    end

    def raise_if_locked
      raise StackLocked, LOCK_ERR if locked?
    end

    def raise_if_adapter(klass)
      return unless klass <= Faraday::Adapter

      raise 'Adapter should be set using the `adapter` method, not `use`'
    end

    def ensure_adapter!
      raise MISSING_ADAPTER_ERROR unless @adapter
    end

    def adapter_set?
      !@adapter.nil?
    end

    def use_symbol(mod, key, ...)
      use(mod.lookup_middleware(key), ...)
    end

    def assert_index(index)
      idx = index.is_a?(Integer) ? index : @handlers.index(index)
      raise "No such handler: #{index.inspect}" unless idx

      idx
    end
  end
end
