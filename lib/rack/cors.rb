# frozen_string_literal: true

require 'logger'
require_relative 'cors/resources'
require_relative 'cors/resource'
require_relative 'cors/origin'
require_relative 'cors/result'
require_relative 'cors/version'

module Rack
  class Cors
    HTTP_ORIGIN   = 'HTTP_ORIGIN'
    HTTP_X_ORIGIN = 'HTTP_X_ORIGIN'

    HTTP_ACCESS_CONTROL_REQUEST_METHOD  = 'HTTP_ACCESS_CONTROL_REQUEST_METHOD'
    HTTP_ACCESS_CONTROL_REQUEST_HEADERS = 'HTTP_ACCESS_CONTROL_REQUEST_HEADERS'

    PATH_INFO      = 'PATH_INFO'
    REQUEST_METHOD = 'REQUEST_METHOD'

    RACK_LOGGER = 'rack.logger'
    RACK_CORS   =
      # retaining the old key for backwards compatibility
      ENV_KEY = 'rack.cors'

    RACK_CORS_ORIGIN = 'rack.cors.origin'

    OPTIONS     = 'OPTIONS'

    DEFAULT_VARY_HEADERS = ['Origin'].freeze

    STRICT_ORIGIN_OPTION_KEYS = %i[strict_origin_check strict_origins strict_origin].freeze
    INVALID_ORIGIN_LOG_VALUE = '[invalid origin]'.freeze

    def initialize(app, opts = {}, &block)
      @app = app
      @debug_mode = !!opts[:debug]
      @strict_origin_check = STRICT_ORIGIN_OPTION_KEYS.any? { |key| opts[key] }
      @logger = @logger_proc = nil

      logger = opts[:logger]
      if logger
        if logger.respond_to? :call
          @logger_proc = opts[:logger]
        else
          @logger = logger
        end
      end

      return unless block_given?

      if block.arity == 1
        block.call(self)
      else
        instance_eval(&block)
      end
    end

    def debug?
      @debug_mode
    end

    def strict_origin_check?
      @strict_origin_check
    end

    def allow(&block)
      all_resources << (resources = Resources.new(strict_origin_check?))

      if block.arity == 1
        block.call(resources)
      else
        resources.instance_eval(&block)
      end
    end

    def call(env)
      env[HTTP_ORIGIN] ||= env[HTTP_X_ORIGIN] if env[HTTP_X_ORIGIN]

      origin_valid = evaluate_origin(env)

      path = evaluate_path(env)

      add_headers = nil
      if env[HTTP_ORIGIN]
        debug(env) do
          ['Incoming Headers:',
           "  Origin: #{debug_value(origin_for_debug(env))}",
           "  Path-Info: #{debug_value(path)}",
           "  Access-Control-Request-Method: #{debug_value(env[HTTP_ACCESS_CONTROL_REQUEST_METHOD])}",
           "  Access-Control-Request-Headers: #{debug_value(env[HTTP_ACCESS_CONTROL_REQUEST_HEADERS])}"].join("\n")
        end

        if env[REQUEST_METHOD] == OPTIONS && env[HTTP_ACCESS_CONTROL_REQUEST_METHOD]
          return [400, {}, []] unless Rack::Utils.valid_path?(path)

          unless origin_valid
            result = Result.preflight(env)
            result.miss(Result::MISS_INVALID_ORIGIN)
            return [200, {}, []]
          end

          headers = process_preflight(env, path)
          debug(env) do
            "Preflight Headers:\n" +
              headers.collect { |key, value| "  #{debug_value(key)}: #{debug_value(value)}" }.join("\n")
          end
          return [200, headers, []]
        else
          add_headers = origin_valid ? process_cors(env, path) : invalid_origin(env)
        end
      else
        Result.miss(env, Result::MISS_NO_ORIGIN)
      end

      # This call must be done BEFORE calling the app because for some reason
      # env[PATH_INFO] gets changed after that and it won't match. (At least
      # in rails 4.1.6)
      vary_resource = resource_for_path(path)

      status, headers, body = @app.call env

      if add_headers
        headers = add_headers.merge(headers)
        debug(env) do
          add_headers.each_pair do |key, value|
            headers["x-rack-cors-original-#{key}"] = value if headers.key?(key)
          end
        end
      end

      # Vary header should ALWAYS mention Origin if there's ANY chance for the
      # response to be different depending on the Origin header value.
      # Better explained here: http://www.fastly.com/blog/best-practices-for-using-the-vary-header/
      if vary_resource
        vary = headers['vary']
        cors_vary_headers = if vary_resource.vary_headers&.any?
                              vary_resource.vary_headers
                            else
                              DEFAULT_VARY_HEADERS
                            end
        headers['vary'] = ((vary ? [vary].flatten.map { |v| v.split(/,\s*/) }.flatten : []) + cors_vary_headers).uniq.join(', ')
      end

      result = env[ENV_KEY]
      result.append_header(headers) if debug? && result

      [status, headers, body]
    end

    protected

    def debug(env, message = nil, &block)
      (@logger || select_logger(env)).debug(message, &block) if debug?
    end

    def debug_value(value)
      value.inspect
    end

    def origin_for_debug(env)
      strict_origin_check? ? env[RACK_CORS_ORIGIN] || INVALID_ORIGIN_LOG_VALUE : env[HTTP_ORIGIN]
    end

    def select_logger(env)
      @logger = if @logger_proc
                  logger_proc = @logger_proc
                  @logger_proc = nil
                  logger_proc.call

                elsif defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
                  Rails.logger

                elsif env[RACK_LOGGER]
                  env[RACK_LOGGER]

                else
                  ::Logger.new(STDOUT).tap { |logger| logger.level = ::Logger::Severity::DEBUG }
                end
    end

    def evaluate_path(env)
      path = env[PATH_INFO]

      if path
        path = Rack::Utils.unescape_path(path)

        path = Rack::Utils.clean_path_info(path) if Rack::Utils.valid_path?(path)
      end

      path
    end

    def all_resources
      @all_resources ||= []
    end

    def evaluate_origin(env)
      return true unless strict_origin_check?
      return true unless env[HTTP_ORIGIN]

      serialized = Origin.serialize(env[HTTP_ORIGIN])
      return false unless serialized

      env[RACK_CORS_ORIGIN] = serialized
      true
    end

    def invalid_origin(env)
      Result.miss(env, Result::MISS_INVALID_ORIGIN)
      nil
    end

    def process_preflight(env, path)
      result = Result.preflight(env)

      resource, error = match_resource(path, env)
      unless resource
        result.miss(error)
        return {}
      end

      resource.process_preflight(env, result)
    end

    def process_cors(env, path)
      resource, error = match_resource(path, env)
      if resource
        Result.hit(env)
        cors = resource.to_headers(env)
        cors

      else
        Result.miss(env, error)
        nil
      end
    end

    def resource_for_path(path_info)
      all_resources.each do |r|
        found = r.resource_for_path(path_info)
        return found if found
      end
      nil
    end

    def match_resource(path, env)
      origin = env[RACK_CORS_ORIGIN] || env[HTTP_ORIGIN]

      origin_matched = false
      all_resources.each do |r|
        next unless r.allow_origin?(origin, env)

        origin_matched = true
        found = r.match_resource(path, env)
        return [found, nil] if found
      end

      [nil, origin_matched ? Result::MISS_NO_PATH : Result::MISS_NO_ORIGIN]
    end
  end
end
