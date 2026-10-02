# frozen_string_literal: true

require 'logger'
require_relative 'cors/resources'
require_relative 'cors/resource'
require_relative 'cors/combined_resource'
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

    # :first_match keeps the historical behavior: the first resource whose
    # path matches wins. :intersection combines every matching resource by
    # intersecting their methods, headers and origin permissions.
    COMBINE_MODES = %i[first_match intersection].freeze

    def initialize(app, opts = {}, &block)
      @app = app
      @debug_mode = !!opts[:debug]
      @logger = @logger_proc = nil
      @combine = opts.fetch(:combine, :first_match)

      unless COMBINE_MODES.include?(@combine)
        raise ArgumentError, "unknown :combine option #{@combine.inspect}; expected one of #{COMBINE_MODES.map(&:inspect).join(', ')}"
      end

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

      validate_configuration!
    end

    def debug?
      @debug_mode
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
        if resource.respond_to?(:deny_methods?) && resource.deny_methods?
          Result.miss(env, Result::MISS_DENY_METHOD)
          nil
        else
          Result.hit(env)
          resource.to_headers(env)
        end

      else
        Result.miss(env, error)
        nil
      end
    end

    def resource_for_path(path_info)
      if @combine == :intersection
        matched = all_resources.flat_map { |r| r.resources_matching_path(path_info) }
        return matched.empty? ? nil : CombinedResource.new(matched)
      end

      all_resources.each do |r|
        found = r.resource_for_path(path_info)
        return found if found
      end
      nil
    end

    def match_resource(path, env)
      return match_resource_intersection(path, env) if @combine == :intersection

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

    def match_resource_intersection(path, env)
      matched = all_resources.flat_map { |r| r.resources_for_path(path, env) }

      if matched.empty?
        origin_matched = all_resources.any? { |r| r.allow_origin?(env[HTTP_ORIGIN], env) }
        return [nil, origin_matched ? Result::MISS_NO_PATH : Result::MISS_NO_ORIGIN]
      end

      unless matched.all? { |resource| resource.owner.allow_origin?(env[HTTP_ORIGIN], env) }
        return [nil, Result::MISS_NO_ORIGIN]
      end

      [CombinedResource.new(matched), nil]
    end

    # Raises for contradictory static configuration that can be detected
    # without an actual request. Decisions involving Proc origins, Regexp
    # paths or :if guards are resolved at request time.
    def validate_configuration!
      return unless @combine == :intersection

      owned_resources = all_resources.flat_map do |block|
        block.resources.map { |resource| [resource, block] }
      end

      all_resources.each do |block|
        next if block.resources.empty?
        next if block.public_resources?
        next unless block.concrete_origin_candidates == []

        raise Resource::CorsMisconfigurationError,
              'combine: :intersection requires at least one origin per allow block that declares resources'
      end

      owned_resources.each_with_index do |(resource, block), index|
        if resource.methods.empty?
          raise Resource::CorsMisconfigurationError,
                "combine: :intersection cannot grant any methods for resource #{resource.path.inspect}: methods list is empty"
        end

        owned_resources[(index + 1)..].each do |(other, other_block)|
          next if resource.if_proc || other.if_proc

          next unless paths_overlap?(resource.path_glob, other.path_glob)

          if (resource.methods & other.methods).empty?
            raise Resource::CorsMisconfigurationError,
                  "combine: :intersection denies everything: resources #{resource.path.inspect} and #{other.path.inspect} overlap but share no allowed methods"
          end

          next if block.equal?(other_block)
          next if origins_can_overlap?(block, other_block)

          raise Resource::CorsMisconfigurationError,
                "combine: :intersection denies everything: allow blocks governing #{resource.path.inspect} and #{other.path.inspect} have disjoint origins"
        end
      end
    end

    # true: provably overlap, false: provably disjoint, nil: cannot decide
    # without a request (e.g. Regexp paths, embedded wildcards).
    def paths_overlap?(path_a, path_b)
      return nil unless path_a.respond_to?(:to_str) && path_b.respond_to?(:to_str)

      variants_a = glob_variants(path_a.to_str)
      variants_b = glob_variants(path_b.to_str)

      results = variants_a.product(variants_b).map { |a, b| globs_overlap?(a, b) }
      return true if results.include?(true)
      return false if results.all?(false)

      nil
    end

    # A trailing '/*' also matches the directory itself, so each glob
    # represents either one or two concrete segment lists.
    def glob_variants(path)
      segments = path.split('/').reject(&:empty?)
      variants = [segments]
      if segments.length == 1 && segments.first == '*'
        variants << []
      elsif segments.length > 1 && segments.last == '*'
        variants << segments[0..-2]
      end
      variants
    end

    def globs_overlap?(segments_a, segments_b)
      return false unless segments_a.length == segments_b.length

      segments_a.zip(segments_b).each do |a, b|
        result = segments_overlap?(a, b)
        return result if result == false || result.nil?
      end
      true
    end

    def segments_overlap?(segment_a, segment_b)
      if segment_a == '*' || segment_b == '*'
        true
      elsif literal_segment?(segment_a) && literal_segment?(segment_b)
        segment_a == segment_b
      else
        nil
      end
    end

    def literal_segment?(segment)
      !segment.include?('*') && !segment.include?(':')
    end

    def origins_can_overlap?(block_a, block_b)
      return true if block_a.public_resources? || block_b.public_resources?

      origins_a = block_a.concrete_origin_candidates
      origins_b = block_b.concrete_origin_candidates
      return true if origins_a.nil? || origins_b.nil?

      origins_a.any? { |origin| block_b.allow_origin?(origin, {}) } ||
        origins_b.any? { |origin| block_a.allow_origin?(origin, {}) }
    end
  end
end
