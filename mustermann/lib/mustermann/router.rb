# frozen_string_literal: true
require 'mustermann'
require 'mustermann/set'

module Mustermann
  # An extremely simple, Rack-compatible router implementation using {Mustermann::Set} for pattern matching.
  #
    # @example Basic usage
  #   require 'mustermann/router'
  #
  #   router = Mustermann::Router.new do
  #     get "/hello/:name" do |env|
  #       name = env["mustermann.match"][:name]
  #       [200, { "content-type" => "text/plain" }, ["Hello, #{name}!"]]
  #     end
  #   end
  #
    #   # in config.ru
    #   use Rack::Head
    #   run router
    #
    # @example Method negotiation
    #   router = Mustermann::Router.new(method_negotiation: true) do
    #     get  "/users" do |env|
    #       [200, { "content-type" => "text/plain" }, ["users"]]
    #     end
    #     post "/users" do |env|
    #       [201, { "content-type" => "text/plain" }, []]
    #     end
    #   end
    #
    #   # PUT /users => 405 with Allow: GET, HEAD, POST, OPTIONS
    #   # OPTIONS /users => 200 with the same Allow header
    #   # HEAD /users => GET response with an empty body
  #
  # @example Routing to other applications
  #   router = Mustermann::Router.new do
  #     get  "/users",     MyApp::Users::Index
  #     get  "/users/:id", MyApp::Users::Show
  #     post "/users",     MyApp::Users::Create
  #     fallback           MyApp::NotFound
  #   end
  #
  #   router.path_for(MyApp::Users::Show, id: 42) # => "/users/42"
  #
  # @example As middleware
  #   use Mustermann::Router do
  #     get("/up") { [200, { "content-type" => "text/plain" }, ["Up!"]] }
  #   end
  #
  #   run MyApp
  #
  # @see Mustermann::Set
  # @see https://rack.github.io/rack/
  class Router
    NOT_FOUND = [404, { "content-type" => "text/plain", "x-cascade" => "pass" }, ["Not found"]].freeze
    VERBS     = %w[GET POST PUT PATCH DELETE OPTIONS LINK UNLINK].freeze
    HEAD      = "HEAD"
    METHODS   = [VERBS.first, HEAD, *VERBS.drop(1)].freeze
    private_constant :VERBS, :HEAD, :METHODS, :NOT_FOUND

    class HeadBody
      def initialize(body)
        @body   = body
        @closed = false
      end

      def each
      end

      def close
        return if @closed
        @closed = true
        @body.close if @body.respond_to?(:close)
      end
    end

    private_constant :HeadBody

    # Initializes a new router.
    # @param key [String] The key under which the route match will be stored in the Rack environment hash (default: "mustermann.match").
    # @param method_negotiation [Boolean] Whether to return 405 with an accurate Allow header,
    #   answer OPTIONS automatically, and fall back from HEAD to GET.
    # @param options [Hash] Options to be passed to the Mustermann patterns.
    def initialize(fallback = nil, key: "mustermann.match", method_negotiation: false, **options, &block)
      @key                = key
      @method_negotiation = method_negotiation
      methods             = method_negotiation ? METHODS : VERBS
      @sets               = methods.to_h { |verb| [verb, Set.new(**options)] }
      @fallback = fallback || ->(env) { NOT_FOUND.dup }

      define_singleton_method(:head) { |*args, **opts, &block| route(HEAD, *args, **opts, &block) } if method_negotiation

      if block_given?
        instance_exec(&block)
        @sets.each_value(&:optimize!)
      end
    end

    # @param env [Hash] The Rack environment hash for the request.
    # @return [Array] The Rack response array (status, headers, body).
    def call(env)
      return call_with_method_negotiation(env) if @method_negotiation

      request_method = env["REQUEST_METHOD"] || "GET"
      request_method = "GET" if request_method == "HEAD"
      if routes = @sets[request_method] and match = routes.match(env["PATH_INFO"] || "/")
        return dispatch(match, env)
      end
      @fallback.call(env)
    end

    def fallback(fallback = nil, &block) = @fallback = fallback || block || @fallback

    # Adds a route for the given verb and pattern, with the given target.
    #
    # @note Shorthand methods, like `get`, `post`, etc. are defined for all supported verbs.
    #   Enabling `method_negotiation` also defines `head` on the router instance.
    #
    # @param verb [String] HTTP verb (e.g. "GET", "POST")
    # @param pattern [String, Mustermann::Pattern] Pattern string or Mustermann pattern (e.g. "/users/:id")
    # @param target [#call, nil] The Rack application or middleware to call when the route matches. Can be passed a block as well.
    # @yield [env] Block to be used as the target if no explicit target is given.
    # @yieldparam env [Hash] The Rack environment hash for the request.
    # @return [void]
    def route(verb, pattern, target = nil, **options, &block)
      raise ArgumentError, "need to provide target, :to or a block" unless target || block
      raise ArgumentError, "unknown verb: #{verb}" unless @sets.key?(verb)
      @sets[verb].add(pattern, target || block)
    end

    # Helps generate links
    #
    # @param app [#call] The Rack application or middleware for which to generate the path.
    # @param (see Mustermann::Expander#expand)
    # @return [String] The generated path.
    def path_for(app, behavior = nil, params = EMPTY_HASH)
      set = @sets.values.find { |s| s.has_value?(app) } || @sets[VERBS.first]
      set.expand(app, behavior, params)
    end

    VERBS.each do |verb|
      define_method(verb.downcase) { |*args, **opts, &block| route(verb, *args, **opts, &block) }
    end

    private

    def call_with_method_negotiation(env)
      path           = env["PATH_INFO"] || "/"
      request_method = env["REQUEST_METHOD"] || "GET"

      case request_method
      when HEAD
        call_head(path, env)
      when "OPTIONS"
        call_options(path, env)
      else
        match = @sets[request_method]&.match(path)
        match ? dispatch(match, env) : reject_or_fallback(path, env)
      end
    end

    def call_head(path, env)
      match = @sets[HEAD]&.match(path) || @sets["GET"]&.match(path)
      return without_body(dispatch(match, env)) if match

      allowed_methods = allowed_methods(path)
      allowed_methods ? method_not_allowed(allowed_methods) : @fallback.call(env)
    end

    def call_options(path, env)
      match = @sets["OPTIONS"]&.match(path)
      return dispatch(match, env) if match

      allowed_methods = allowed_methods(path)
      allowed_methods ? options_response(allowed_methods) : @fallback.call(env)
    end

    def reject_or_fallback(path, env)
      allowed_methods = allowed_methods(path)
      allowed_methods ? method_not_allowed(allowed_methods) : @fallback.call(env)
    end

    def dispatch(match, env)
      env[@key] = match
      match.value.call(env)
    end

    def without_body(response)
      status, headers, body = response
      [status, headers, HeadBody.new(body)]
    end

    def allowed_methods(path)
      methods = METHODS.select { |verb| @sets[verb]&.match(path) }
      return nil if methods.empty?

      methods << HEAD if methods.include?("GET")
      methods << "OPTIONS"
      METHODS & methods
    end

    def options_response(allowed_methods)
      [200, { "allow" => allowed_methods.join(", ") }, []]
    end

    def method_not_allowed(allowed_methods)
      headers = {
        "content-type" => "text/plain",
        "allow"       => allowed_methods.join(", ")
      }
      [405, headers, ["Method not allowed"]]
    end
  end
end
