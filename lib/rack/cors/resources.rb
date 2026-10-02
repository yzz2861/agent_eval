# frozen_string_literal: true

require_relative 'resources/cors_misconfiguration_error'

module Rack
  class Cors
    class Resources
      # Value object describing how a request origin matched the configured
      # origin rules. Carries the per-origin decisions (credentials, max_age)
      # declared by the winning rule.
      class OriginMatch
        attr_reader :credentials, :max_age

        def initialize(wildcard:, credentials: nil, max_age: nil)
          @wildcard = wildcard
          @credentials = credentials
          @max_age = max_age
        end

        def wildcard?
          @wildcard
        end
      end

      # A single origin rule: a matcher (exact string, regexp, proc or the
      # '*' wildcard) plus optional per-origin decisions declared through the
      # hash DSL (e.g. origins 'https://admin.example.com' => { credentials: true }).
      class OriginRule
        OPTION_KEYS = %i[credentials max_age].freeze

        # Specificity tiers used to deterministically pick a single winning
        # rule when several rules match the same origin. Lower wins; ties are
        # broken by declaration order. The wildcard always loses to any
        # specific rule, no matter where it was declared.
        SPECIFICITY_EXACT    = 0
        SPECIFICITY_REGEXP   = 1
        SPECIFICITY_PROC     = 2
        SPECIFICITY_WILDCARD = 3

        attr_reader :specificity

        def self.extract_options(options)
          unknown = options.keys.map(&:to_sym) - OPTION_KEYS
          raise ArgumentError, "unknown origin option(s): #{unknown.join(', ')}" unless unknown.empty?

          OPTION_KEYS.each_with_object({}) do |key, extracted|
            extracted[key] = options[key] if options.key?(key)
            extracted[key] = options[key.to_s] if extracted[key].nil? && options.key?(key.to_s)
          end
        end

        def initialize(matcher, specificity, options = {})
          @matcher = matcher
          @specificity = specificity
          @options = options
        end

        def wildcard?
          @specificity == SPECIFICITY_WILDCARD
        end

        # Returns the effective options hash when the rule matches the given
        # source, nil otherwise. A proc may return a boolean (legacy behavior)
        # or a hash with per-origin decisions (structured match result).
        def match(source, env)
          return @options if wildcard?

          case @matcher
          when Proc
            result = @matcher.call(source, env)
            return nil unless result

            result.is_a?(Hash) ? @options.merge(self.class.extract_options(result)) : @options
          when Regexp
            source =~ @matcher ? @options : nil
          else
            source == @matcher ? @options : nil
          end
        end
      end

      attr_reader :resources

      def initialize
        @origins = []
        @resources = []
        @public_resources = false
      end

      def origins(*args, &blk)
        @origins = args.flatten.reject { |s| s == '' }.flat_map do |n|
          if n.is_a?(Hash)
            n.map { |matcher, options| build_rule(matcher, options) }
          else
            build_rule(n)
          end
        end
        @origins.push(build_rule(blk)) if blk
      end

      def resource(path, opts = {})
        @resources << Resource.new(public_resources?, path, opts)
      end

      def public_resources?
        @public_resources
      end

      def allow_origin?(source, env = {})
        return true if public_resources?

        !match_origin(source, env).nil?
      end

      # Returns the OriginMatch for the winning rule, or nil when no rule
      # matches. When several rules match, the most specific one wins
      # (exact string > regexp > proc > wildcard); declaration order breaks
      # ties within the same tier.
      def match_origin(source, env = {})
        best_rule = nil
        best_options = nil

        @origins.each do |rule|
          options = rule.match(source, env)
          next unless options

          if best_rule.nil? || rule.specificity < best_rule.specificity
            best_rule = rule
            best_options = options
          end
        end

        return nil unless best_rule

        OriginMatch.new(
          wildcard: best_rule.wildcard?,
          credentials: best_options[:credentials],
          max_age: best_options[:max_age]
        )
      end

      def match_resource(path, env)
        @resources.detect { |r| r.match?(path, env) }
      end

      def resource_for_path(path)
        @resources.detect { |r| r.matches_path?(path) }
      end

      protected

      def build_rule(matcher, options = nil)
        opts = OriginRule.extract_options(options || {})

        case matcher
        when Proc
          OriginRule.new(matcher, OriginRule::SPECIFICITY_PROC, opts)
        when Regexp
          OriginRule.new(matcher, OriginRule::SPECIFICITY_REGEXP, opts)
        when '*'
          @public_resources = true
          raise Resource::CorsMisconfigurationError if opts[:credentials]

          OriginRule.new(matcher, OriginRule::SPECIFICITY_WILDCARD, opts)
        when %r{^[a-z][a-z0-9.+-]*://}
          OriginRule.new(matcher, OriginRule::SPECIFICITY_EXACT, opts)
        else
          OriginRule.new(
            Regexp.compile("^[a-z][a-z0-9.+-]*:\\\/\\\/#{Regexp.quote(matcher)}$"),
            OriginRule::SPECIFICITY_EXACT,
            opts
          )
        end
      end
    end
  end
end
