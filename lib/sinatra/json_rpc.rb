# frozen_string_literal: true

require 'json'
require 'sinatra/base'

module Sinatra
  # = Sinatra::JSONRPC
  #
  # Optional JSON-RPC 2.0 dispatcher for Sinatra routes.
  #
  # Methods are exposed through an explicit registry; the dispatcher never
  # calls arbitrary Ruby methods based on the client supplied +method+ name.
  # Both positional (Array) and named (Hash) parameters are supported, as
  # well as notifications (requests without an +id+ member) and batches.
  #
  # == Usage
  #
  #     require 'sinatra/base'
  #     require 'sinatra/json_rpc'
  #
  #     class App < Sinatra::Base
  #       register Sinatra::JSONRPC
  #
  #       json_rpc '/rpc' do
  #         register('sum') { |a, b| a + b }
  #         register('greet') { |name:| "Hello, #{name}!" }
  #
  #         map_error AccountLocked, code: -32001, message: 'Account locked'
  #       end
  #     end
  #
  # You can also dispatch manually inside any route:
  #
  #     post '/rpc' do
  #       json_rpc_dispatch MyApp::RPC_REGISTRY
  #     end
  #
  # == Semantics
  #
  # * A request without an +id+ member is a notification and never produces
  #   a response member, even if the handler raises. A request with
  #   +"id": null+ is a regular request and gets a response with +id: null+.
  # * String and numeric ids are returned with their original JSON type.
  # * Batch members are processed independently: one invalid member does not
  #   affect the others, and notifications contribute no response members.
  # * Positional params (Array) are splatted into the handler, named params
  #   (Hash) are passed as keyword arguments with symbolized keys.
  # * Errors are mapped to JSON-RPC error objects: parse errors (-32700),
  #   invalid requests (-32600), unknown methods (-32601), invalid params
  #   (-32602) and internal errors (-32603). Business exceptions can be
  #   mapped to custom codes via Registry#map_error or the
  #   +json_rpc_error_map+ setting.
  module JSONRPC
    VERSION = '2.0'

    PARSE_ERROR      = -32_700
    INVALID_REQUEST  = -32_600
    METHOD_NOT_FOUND = -32_601
    INVALID_PARAMS   = -32_602
    INTERNAL_ERROR   = -32_603

    # JSON-RPC error object. Handlers may raise this (or a subclass)
    # directly to respond with a specific code, message and data.
    class Error < StandardError
      attr_reader :code, :data

      def initialize(code, message, data = nil)
        @code = code
        @data = data
        super(message)
      end

      def to_h
        hash = { code: code, message: message }
        hash[:data] = data unless data.nil?
        hash
      end
    end

    class ParseError < Error
      def initialize(message = 'Parse error', data = nil)
        super(PARSE_ERROR, message, data)
      end
    end

    class InvalidRequest < Error
      def initialize(message = 'Invalid Request', data = nil)
        super(INVALID_REQUEST, message, data)
      end
    end

    class MethodNotFound < Error
      def initialize(message = 'Method not found', data = nil)
        super(METHOD_NOT_FOUND, message, data)
      end
    end

    class InvalidParams < Error
      def initialize(message = 'Invalid params', data = nil)
        super(INVALID_PARAMS, message, data)
      end
    end

    class InternalError < Error
      def initialize(message = 'Internal error', data = nil)
        super(INTERNAL_ERROR, message, data)
      end
    end

    # Explicit registry of callable JSON-RPC methods. Lookup is a plain
    # Hash fetch, so client input can never trigger arbitrary Ruby methods.
    class Registry
      attr_reader :error_map

      def initialize
        @methods = {}
        @error_map = {}
      end

      # Registers a method under +name+. The handler is any callable.
      # Positional params are splatted in, named params are passed as
      # keyword arguments.
      def register(name, callable = nil, &block)
        handler = callable || block
        raise ArgumentError, 'a callable handler is required' unless handler.respond_to?(:call)

        @methods[name.to_s] = handler
        self
      end

      def registered?(name)
        @methods.key?(name.to_s)
      end

      def names
        @methods.keys
      end

      def fetch(name)
        @methods[name]
      end

      # Maps an exception class to a JSON-RPC error. The mapping can be an
      # Integer code, a [code, message] pair, the :code/:message keywords,
      # or a block receiving the exception and returning any of the former
      # (or a Hash with :code/:message/:data).
      def map_error(exception_class, code = nil, message = nil, &block)
        if code.is_a?(Hash)
          options = code
          code = options[:code]
          message = options[:message]
        end
        @error_map[exception_class] = block || (message.nil? ? code : [code, message])
        self
      end
    end

    # Parses and dispatches JSON-RPC 2.0 payloads against a Registry.
    class Dispatcher
      attr_reader :registry

      def initialize(registry)
        @registry = registry
      end

      # Handles a raw request body. Returns [status, body] where body is a
      # JSON string, or nil when there is nothing to respond (notifications
      # only), in which case status is 204.
      def handle(body, error_map: {})
        payload = JSON.parse(body)
        response = dispatch_payload(payload, error_map)
        response.nil? ? [204, nil] : [200, JSON.generate(response)]
      rescue JSON::ParserError
        [200, JSON.generate(error_response(nil, ParseError.new))]
      end

      private

      def dispatch_payload(payload, error_map)
        if payload.is_a?(Array)
          return error_response(nil, InvalidRequest.new) if payload.empty?

          responses = payload.filter_map { |item| process(item, error_map) }
          responses.empty? ? nil : responses
        else
          process(payload, error_map)
        end
      end

      # Processes a single request object. Returns a response Hash, or nil
      # for notifications.
      def process(item, error_map)
        return error_response(nil, InvalidRequest.new) unless item.is_a?(Hash)

        id = item['id']
        return error_response(nil, InvalidRequest.new('Invalid request id')) unless valid_id?(id)
        return error_response(id, InvalidRequest.new('Invalid JSON-RPC version')) unless item['jsonrpc'] == VERSION

        method_name = item['method']
        return error_response(id, InvalidRequest.new('Invalid method')) unless method_name.is_a?(String)

        notification = !item.key?('id')
        handler = registry.fetch(method_name)
        return notification ? nil : error_response(id, MethodNotFound.new) unless handler

        begin
          result = invoke(handler, item['params'])
          JSON.generate(result) # ensure the result is serializable
          notification ? nil : success_response(id, result)
        rescue StandardError => e
          return nil if notification

          error_response(id, classify(e, error_map))
        end
      end

      def invoke(handler, params)
        case params
        when nil   then handler.call
        when Array
          arity = handler.arity
          if arity >= 0 && arity != params.length
            raise InvalidParams, "wrong number of arguments (given #{params.length}, expected #{arity})"
          end

          handler.call(*params)
        when Hash  then handler.call(**params.transform_keys(&:to_sym))
        else raise InvalidParams, 'Params must be an Array or an Object'
        end
      end

      def classify(error, error_map)
        return error if error.is_a?(Error)

        mapped = lookup_mapping(registry.error_map.merge(error_map), error)
        return resolve_mapping(mapped, error) if mapped
        return InvalidParams.new(error.message) if error.is_a?(ArgumentError)

        InternalError.new
      end

      def lookup_mapping(map, error)
        error.class.ancestors.each do |klass|
          return map[klass] if map.key?(klass)
        end
        nil
      end

      def resolve_mapping(mapped, error)
        mapped = mapped.call(error) if mapped.respond_to?(:call)
        case mapped
        when Error   then mapped
        when Integer then Error.new(mapped, error.message)
        when Array   then Error.new(mapped[0], mapped[1] || error.message, mapped[2])
        when Hash    then Error.new(mapped[:code], mapped[:message] || error.message, mapped[:data])
        else InternalError.new
        end
      end

      def valid_id?(id)
        id.nil? || id.is_a?(String) || id.is_a?(Numeric)
      end

      def success_response(id, result)
        { jsonrpc: VERSION, result: result, id: id }
      end

      def error_response(id, error)
        { jsonrpc: VERSION, error: error.to_h, id: id }
      end
    end

    module Helpers
      # Dispatches the current request body against a
      # Sinatra::JSONRPC::Dispatcher (or Registry) and responds with the
      # JSON-RPC result. Responds with 204 and an empty body when the
      # payload contains only notifications.
      def json_rpc_dispatch(target)
        dispatcher = target.is_a?(JSONRPC::Dispatcher) ? target : JSONRPC::Dispatcher.new(target)
        status_code, payload = dispatcher.handle(request.body.read, error_map: settings.json_rpc_error_map)
        content_type :json
        status status_code
        body payload || ''
      end
    end

    module ClassMethods
      # Defines a POST route at +path+ that dispatches JSON-RPC 2.0
      # requests. Methods are registered on an explicit registry, either
      # passed via :registry or built from the given block:
      #
      #     json_rpc '/rpc' do
      #       register('sum') { |a, b| a + b }
      #     end
      #
      # Returns the registry so it can be reused elsewhere.
      def json_rpc(path, registry: nil, **options, &block)
        reg = registry || JSONRPC::Registry.new
        reg.instance_eval(&block) if block
        dispatcher = JSONRPC::Dispatcher.new(reg)
        post(path, **options) { json_rpc_dispatch(dispatcher) }
        reg
      end
    end

    def self.registered(base)
      base.set :json_rpc_error_map, {}
      base.helpers Helpers
      base.extend ClassMethods
    end
  end
end
