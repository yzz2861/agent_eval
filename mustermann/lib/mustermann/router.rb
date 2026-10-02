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
  # @example Optional HTTP method negotiation
  #   router = Mustermann::Router.new(method_negotiation: true) do
  #     get "/users" do |_env|
  #       [200, { "content-type" => "text/plain" }, ["users"]]
  #     end
  #
  #     head "/secret" do |_env|
  #       [200, { "x-exists" => "yes" }, []]
  #     end
  #   end
  #
  #   # path exists, method unsupported      => 405 with an accurate Allow header
  #   # unknown path                        => 404 (or the fallback)
  #   # explicit HEAD route wins over GET   => GET is only used as a fallback
  #   # HEAD responses get their body stripped and closed, like Rack::Head
  #   # OPTIONS is answered automatically with the same candidate rules
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
    VERBS     = %w[GET HEAD POST PUT PATCH DELETE OPTIONS LINK UNLINK].freeze

    # Order used when building the Allow header (HEAD and OPTIONS are added
    # implicitly where appropriate, see {#allowed_methods}).
    ALLOW_ORDER = %w[GET HEAD POST PUT PATCH DELETE OPTIONS LINK UNLINK].freeze
    private_constant :VERBS, :NOT_FOUND

    # Initializes a new router.
    # @param key [String] The key under which the route match will be stored in the Rack environment hash (default: "mustermann.match").
    # @param method_negotiation [Boolean] Whether to enable HTTP method negotiation.
    #   When enabled, requests to a known path with an unsupported method get a
    #   405 response with an accurate Allow header, HEAD requests prefer an
    #   explicit HEAD route and fall back to GET otherwise (stripping and closing
    #   the response body), and OPTIONS requests are answered automatically using
    #   the same candidate rules. Unknown paths still hit the fallback.
    #   Defaults to +false+, preserving the legacy behavior where HEAD is routed
    #   like GET and unsupported methods fall through to the fallback.
    # @param options [Hash] Options to be passed to the Mustermann patterns.
    def initialize(fallback = nil, key: "mustermann.match", method_negotiation: false, **options, &block)
      @key      = key
      @sets     = VERBS.to_h { |verb| [verb, Set.new(**options)] }
      @fallback = fallback || ->(env) { NOT_FOUND.dup }
      @method_negotiation = method_negotiation

      if block_given?
        instance_exec(&block)
        @sets.each_value(&:optimize!)
      end
    end

    # @param env [Hash] The Rack environment hash for the request.
    # @return [Array] The Rack response array (status, headers, body).
    def call(env)
      @method_negotiation ? call_with_negotiation(env) : call_without_negotiation(env)
    end

    def fallback(fallback = nil, &block) = @fallback = fallback || block || @fallback

    # All HTTP methods supported for the given path, in Allow-header order.
    #
    # Only inspects the registered patterns and never invokes a target
    # application. HEAD is included when an explicit HEAD route or a GET route
    # matches, and OPTIONS is included for every known path (it is answered
    # automatically unless an explicit OPTIONS route exists).
    #
    # @param path [String] The request path.
    # @return [Array<String>] The allowed HTTP methods, or an empty array when
    #   the path is unknown.
    def allowed_methods(path)
      matched = ALLOW_ORDER.to_h { |verb| [verb, @sets[verb].match(path)] }
      return EMPTY_ARRAY unless matched.values.any?
      matched["HEAD"] = true if matched["HEAD"].nil? && matched["GET"]
      matched["OPTIONS"] = true
      ALLOW_ORDER.select { |verb| matched[verb] }
    end

    # Adds a route for the given verb and pattern, with the given target.
    #
    # @note Shorthand methods, like `get`, `post`, etc. dynamically are defined for all supported verbs.
    #
    # @param verb [String] HTTP verb (e.g. "GET", "POST")
    # @param pattern [String, Mustermann::Pattern] Pattern string or Mustermann pattern (e.g. "/users/:id")
    # @param target [#call, nil] The Rack application or middleware to call when the route matches. Can be passed a block as well.
    # @yield [env] Block to be used as the target if no explicit target is given.
    # @yieldparam env [Hash] The Rack environment hash for the request.
    # @return [void]
    def route(verb, pattern, target = nil, **options, &block)
      raise ArgumentError, "need to provide target, :to or a block" unless target || block
      raise ArgumentError, "unknown verb: #{verb}" unless VERBS.include?(verb)
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

    def call_without_negotiation(env)
      request_method = env["REQUEST_METHOD"] || "GET"
      request_method = "GET" if request_method == "HEAD"
      if routes = @sets[request_method] and match = routes.match(env["PATH_INFO"] || "/")
        dispatch(match, env)
      else
        @fallback.call(env)
      end
    end

    def call_with_negotiation(env)
      path           = env["PATH_INFO"] || "/"
      request_method = env["REQUEST_METHOD"] || "GET"

      if match = @sets[request_method]&.match(path)
        return dispatch(match, env, head: request_method == "HEAD")
      end

      if request_method == "HEAD" and match = @sets["GET"].match(path)
        return dispatch(match, env, head: true)
      end

      allowed = allowed_methods(path)
      return @fallback.call(env) if allowed.empty?

      if request_method == "OPTIONS"
        return [200, { "content-type" => "text/plain", "allow" => allowed.join(", ") }, []]
      end

      [405, { "content-type" => "text/plain", "allow" => allowed.join(", ") }, ["Method Not Allowed"]]
    end

    # Runs the matched target and strips the response body for HEAD requests,
    # mirroring Rack::Head: the target application is called exactly once, the
    # original body is closed when it responds to #close, and an empty body is
    # returned in its place.
    def dispatch(match, env, head: false)
      env[@key] = match
      status, headers, body = match.value.call(env)
      if head
        body.close if body.respond_to?(:close)
        [status, headers, []]
      else
        [status, headers, body]
      end
    end
  end
end
