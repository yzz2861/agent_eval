# frozen_string_literal: true

require 'logger'
require_relative 'cors/resources'
require_relative 'cors/resource'
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

    OPTIONS     = 'OPTIONS'

    DEFAULT_VARY_HEADERS = ['Origin'].freeze

    COMBINE_FIRST_MATCH = :first_match
    COMBINE_INTERSECT   = :intersect
    COMBINE_MODES       = [COMBINE_FIRST_MATCH, COMBINE_INTERSECT].freeze

    def initialize(app, opts = {}, &block)
      @app = app
      @debug_mode = !!opts[:debug]
      @combine = opts[:combine] || COMBINE_FIRST_MATCH
      unless COMBINE_MODES.include?(@combine)
        raise ArgumentError,
              "unknown :combine mode #{@combine.inspect}; expected one of #{COMBINE_MODES.inspect}"
      end
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

      validate_intersection_configuration! if @combine == COMBINE_INTERSECT
    end

    def debug?
      @debug_mode
    end

    def intersect?
      @combine == COMBINE_INTERSECT
    end

    def allow(&block)
      all_resources << (resources = Resources.new)

      if block.arity == 1
        block.call(resources)
      else
        resources.instance_eval(&block)
      end
    end

    def call(env)
      env[HTTP_ORIGIN] ||= env[HTTP_X_ORIGIN] if env[HTTP_X_ORIGIN]

      path = evaluate_path(env)

      add_headers = nil
      if env[HTTP_ORIGIN]
        debug(env) do
          ['Incoming Headers:',
           "  Origin: #{env[HTTP_ORIGIN]}",
           "  Path-Info: #{path}",
           "  Access-Control-Request-Method: #{env[HTTP_ACCESS_CONTROL_REQUEST_METHOD]}",
           "  Access-Control-Request-Headers: #{env[HTTP_ACCESS_CONTROL_REQUEST_HEADERS]}"].join("\n")
        end

        if env[REQUEST_METHOD] == OPTIONS && env[HTTP_ACCESS_CONTROL_REQUEST_METHOD]
          return [400, {}, []] unless Rack::Utils.valid_path?(path)

          headers = process_preflight(env, path)
          debug(env) do
            "Preflight Headers:\n" +
              headers.collect { |kv| "  #{kv.join(': ')}" }.join("\n")
          end
          return [200, headers, []]
        else
          add_headers = process_cors(env, path)
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
      return match_resource_intersect(path, env) if intersect?

      origin = env[HTTP_ORIGIN]

      origin_matched = false
      all_resources.each do |r|
        next unless r.allow_origin?(origin, env)

        origin_matched = true
        found = r.match_resource(path, env)
        return [found, nil] if found
      end

      [nil, origin_matched ? Result::MISS_NO_PATH : Result::MISS_NO_ORIGIN]
    end

    def match_resource_intersect(path, env)
      origin = env[HTTP_ORIGIN]

      # Only (allow-block, resource) pairs whose path AND request-time
      # conditions (the :if proc) match take part in the intersection.
      covering_blocks = 0
      allowing_blocks = 0
      matched = []

      all_resources.each do |block|
        found = block.resources.select { |r| r.match?(path, env) }
        next if found.empty?

        covering_blocks += 1
        next unless block.allow_origin?(origin, env)

        allowing_blocks += 1
        matched.concat(found)
      end

      return [nil, Result::MISS_NO_PATH] if covering_blocks.zero?

      # An origin must be permitted by every allow block covering the path.
      return [nil, Result::MISS_NO_ORIGIN] unless allowing_blocks == covering_blocks

      combined = Resource.combine(matched)

      # Empty method intersection is an explicit deny even for actual
      # (non-preflight) requests.
      return [nil, Result::MISS_DENY_METHOD] if combined.methods.empty?

      [combined, nil]
    end

    # Surface contradictions that can be proven without seeing a request.
    # Decisions depending on a request (origins given as Regexp/Proc, :if
    # blocks, wildcard path overlap) are deferred to request time.
    def validate_intersection_configuration!
      groups = Hash.new { |hash, key| hash[key] = [] }

      all_resources.each do |block|
        block.resources.each do |resource|
          next if resource.if_proc

          groups[resource.path] << { block: block, resource: resource }
        end
      end

      groups.each_value do |members|
        next if members.length < 2

        validate_method_intersection!(members.map { |m| m[:resource] })
        validate_origin_intersection!(members)
      end
    end

    def validate_method_intersection!(resources)
      explicit = resources.reject(&:any_methods)
      return if explicit.length < 2

      intersection = explicit.map(&:methods).reduce(:&)
      return unless intersection.empty?

      raise Resource::CorsMisconfigurationError,
            'Intersection mode is enabled but resources covering the same '
            'path have no HTTP methods in common.  The empty intersection '
            'would deny every request.'
    end

    def validate_origin_intersection!(members)
      return if members.any? { |m| m[:block].public_resources? }

      literal_sets = members.map do |m|
        block = m[:block]
        next if block.origin_rules.any? { |origin| origin.is_a?(Regexp) || origin.is_a?(Proc) }

        block.origin_rules.grep(String)
      end

      return if literal_sets.any?(&:nil?)
      return if literal_sets.any?(&:empty?)
      return unless literal_sets.reduce(:&).empty?

      raise Resource::CorsMisconfigurationError,
            'Intersection mode is enabled but allow blocks covering the same '
            'path permit no common origin.  The empty intersection would '
            'deny every request.'
    end
  end
end
