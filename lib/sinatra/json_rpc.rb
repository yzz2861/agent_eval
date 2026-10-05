# frozen_string_literal: true

require 'json'
require 'sinatra/base'

module Sinatra
  # = Sinatra::JsonRpc
  #
  # <tt>Sinatra::JsonRpc</tt> adds an optional JSON-RPC 2.0 dispatcher that
  # can be mounted on any route. Methods are exposed through an explicit
  # registry, so a client-supplied +method+ name is never used to call
  # arbitrary Ruby methods on the application.
  #
  # == Usage
  #
  #     require "sinatra/base"
  #     require "sinatra/json_rpc"
  #
  #     class MyApp < Sinatra::Base
  #       register Sinatra::JsonRpc
  #
  #       rpc_method "sum" do |a, b|          # positional params
  #         a + b
  #       end
  #
  #       rpc_method "greet" do |name:|       # named params
  #         "hello, #{name}"
  #       end
  #
  #       post "/rpc" do
  #         json_rpc_call
  #       end
  #     end
  #
  # Handlers registered with +rpc_method+ receive positional parameters when
  # the client sends a JSON array, and keyword parameters when the client
  # sends a JSON object.
  #
  # == Notifications and batches
  #
  # A request object without an +id+ member is a notification and never
  # produces a response, even if the handler raises. An +id+ of +null+ is a
  # regular request and is answered with a +null+ id. String and numeric ids
  # are returned with their original type. Batch requests are answered with
  # an array of responses in request order; a broken entry does not affect
  # the others, and notifications contribute no entry. When nothing has to be
  # answered (only notifications), the route responds with 204 No Content.
  #
  # == Error mapping
  #
  # Protocol errors (parse error, invalid request, unknown method, invalid
  # params) and exceptions raised by handlers are translated to JSON-RPC
  # error objects. The translation can be customized with the
  # <tt>:json_rpc_error_map</tt> setting. Keys may be exception classes or
  # the symbols +:parse_error+, +:invalid_request+, +:method_not_found+,
  # +:invalid_params+ and +:internal_error+. Values may be an Integer code,
  # a Hash with +:code+, +:message+ and optional +:data+, or a callable
  # receiving the exception and returning either of those:
  #
  #     set :json_rpc_error_map,
  #         ArgumentError => { code: -32602 },
  #         MyApp::QuotaExceeded => { code: -32001, message: "quota exceeded" },
  #         :internal_error => ->(error) { { code: -32000, data: error.class.name } }
  #
  # Unmapped exceptions are reported as -32603 "Internal error" without
  # leaking the exception message.
  module JsonRpc
    JSON_RPC_VERSION = '2.0'

    # Base class for JSON-RPC protocol errors.
    class Error < StandardError
      CODE = -32_603
      MESSAGE = 'Internal error'

      attr_reader :code, :data

      def initialize(message = nil, code: nil, data: nil)
        super(message || self.class::MESSAGE)
        @code = code || self.class::CODE
        @data = data
      end
    end

    class ParseError < Error
      CODE = -32_700
      MESSAGE = 'Parse error'
    end

    class InvalidRequest < Error
      CODE = -32_600
      MESSAGE = 'Invalid Request'
    end

    class MethodNotFound < Error
      CODE = -32_601
      MESSAGE = 'Method not found'
    end

    class InvalidParams < Error
      CODE = -32_602
      MESSAGE = 'Invalid params'
    end

    class InternalError < Error
      CODE = -32_603
      MESSAGE = 'Internal error'
    end

    ERROR_SYMBOLS = {
      ParseError => :parse_error,
      InvalidRequest => :invalid_request,
      MethodNotFound => :method_not_found,
      InvalidParams => :invalid_params,
      InternalError => :internal_error
    }.freeze

    # Explicit name => callable registry. The only way a client can reach
    # application code; method names are never turned into Ruby sends.
    class Registry
      def initialize
        @handlers = {}
      end

      def register(name, callable = nil, &block)
        handler = callable || block
        raise ArgumentError, 'a callable handler is required' unless handler.respond_to?(:call)

        @handlers[name.to_s] = handler
      end

      def [](name)
        @handlers[name]
      end

      def names
        @handlers.keys
      end
    end
    # Parses and dispatches JSON-RPC 2.0 payloads against a Registry.
    class Dispatcher
      def initialize(registry, error_map = {})
        @registry = registry
        @error_map = error_map || {}
      end

      # Returns the response object (Hash or Array) to serialize, or nil when
      # the payload must not be answered (notifications only).
      def call(raw_body)
        payload =
          begin
            ::JSON.parse(raw_body.to_s)
          rescue ::JSON::ParserError
            return error_response(ParseError.new, nil)
          end

        dispatch(payload)
      end

      private

      def dispatch(payload)
        if payload.is_a?(::Array)
          return error_response(InvalidRequest.new('Invalid Request: empty batch'), nil) if payload.empty?

          responses = payload.map { |item| handle(item) }.compact
          responses.empty? ? nil : responses
        else
          handle(payload)
        end
      end

      def handle(item)
        return error_response(InvalidRequest.new, nil) unless item.is_a?(::Hash)

        id = item['id'] if item.key?('id')
        notification = !item.key?('id')

        if item.key?('id') && !valid_id?(id)
          return error_response(InvalidRequest.new('Invalid Request: id must be a String, Number or Null'), nil)
        end

        if (error = validate_request(item))
          return error_response(error, id)
        end

        begin
          result = execute(item)
          notification ? nil : success_response(result, id)
        rescue StandardError => e
          notification ? nil : error_response(e, id)
        end
      end

      def validate_request(item)
        if item['jsonrpc'] != JSON_RPC_VERSION
          InvalidRequest.new('Invalid Request: jsonrpc must be "2.0"')
        elsif !item['method'].is_a?(::String)
          InvalidRequest.new('Invalid Request: method must be a String')
        elsif item.key?('params') && !item['params'].is_a?(::Array) && !item['params'].is_a?(::Hash)
          InvalidRequest.new('Invalid Request: params must be an Array or an Object')
        end
      end

      def valid_id?(id)
        id.nil? || id.is_a?(::String) || id.is_a?(::Numeric)
      end

      def execute(item)
        handler = @registry[item['method']]
        raise MethodNotFound, "Method not found: #{item['method']}" unless handler

        begin
          case (params = item['params'])
          when nil     then invoke(handler, [])
          when ::Array then invoke(handler, params)
          when ::Hash  then handler.call(**symbolize_keys(params))
          end
        rescue ArgumentError => e
          raise InvalidParams, e.message
        end
      end

      # Blocks are lenient about missing arguments, so enforce the arity of
      # positional calls explicitly to report invalid params reliably.
      def invoke(handler, args)
        arity = handler.arity
        if (arity >= 0 && args.length != arity) || (arity < 0 && args.length < ~arity)
          raise ArgumentError, "wrong number of arguments (given #{args.length}, expected #{arity < 0 ? "#{~arity}+" : arity})"
        end

        handler.call(*args)
      end

      def symbolize_keys(hash)
        hash.each_with_object({}) { |(key, value), memo| memo[key.to_sym] = value }
      end

      def success_response(result, id)
        { 'jsonrpc' => JSON_RPC_VERSION, 'result' => result, 'id' => id }
      end

      def error_response(exception, id)
        { 'jsonrpc' => JSON_RPC_VERSION, 'error' => error_hash(exception), 'id' => id }
      end

      def error_hash(exception)
        mapping = find_mapping(exception)
        mapped = !mapping.nil?
        mapping = mapping.call(exception) if mapping.respond_to?(:call)

        case mapping
        when ::Hash
          hash = {
            'code' => mapping.fetch(:code) { default_code(exception) },
            'message' => mapping.fetch(:message) { default_message(exception, mapped) }
          }
          hash['data'] = mapping[:data] if mapping.key?(:data)
          hash
        when ::Integer
          { 'code' => mapping, 'message' => default_message(exception, mapped) }
        else
          hash = { 'code' => default_code(exception), 'message' => default_message(exception, mapped) }
          hash['data'] = exception.data if exception.is_a?(Error) && exception.data
          hash
        end
      end

      def find_mapping(exception)
        exception.class.ancestors.each do |klass|
          return @error_map[klass] if @error_map.key?(klass)
        end
        symbol = ERROR_SYMBOLS[exception.class]
        symbol ||= :internal_error unless exception.is_a?(Error)
        symbol ? @error_map[symbol] : nil
      end

      def default_code(exception)
        exception.is_a?(Error) ? exception.code : InternalError::CODE
      end

      def default_message(exception, mapped)
        return exception.message if exception.is_a?(Error) || mapped

        InternalError::MESSAGE
      end
    end

    module Helpers
      # Dispatches the JSON-RPC payload (the request body by default) and
      # renders the response. Answers 204 No Content when the payload
      # consists solely of notifications.
      def json_rpc_call(payload = request.body.read)
        response = JsonRpc::Dispatcher.new(settings.json_rpc_methods, settings.json_rpc_error_map).call(payload)
        if response.nil?
          status 204
          body ''
        else
          content_type :json
          ::JSON.generate(response)
        end
      end
    end

    def self.registered(app)
      app.set :json_rpc_methods, JsonRpc::Registry.new
      app.set :json_rpc_error_map, {}
      app.helpers Helpers
    end

    # Registers a JSON-RPC method. The handler is called with positional
    # arguments for array params and keyword arguments for object params.
    def rpc_method(name, callable = nil, &block)
      settings.json_rpc_methods.register(name, callable, &block)
    end
  end
end
