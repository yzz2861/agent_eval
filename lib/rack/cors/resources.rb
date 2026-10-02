# frozen_string_literal: true

require_relative 'resources/cors_misconfiguration_error'
require_relative 'origin_result'

module Rack
  class Cors
    class Resources
      # Higher specificity wins when several origin rules match the same
      # source. Within the same rank the earlier declaration wins. This keeps
      # a wildcard listed before a trusted-site rule from opening up
      # credentials for that site.
      RULE_RANK = {
        exact: 0,
        regexp: 1,
        proc: 2,
        wildcard: 3
      }.freeze

      attr_reader :resources

      def initialize
        @origins = []
        @resources = []
        @public_resources = false
      end

      def origins(*args, &blk)
        @origins = []
        @public_resources = false

        args.flatten.reject { |s| s == '' }.each do |n|
          add_origin(n)
        end
        add_origin(blk) if blk
      end

      def resource(path, opts = {})
        @resources << Resource.new(public_resources?, wildcard_origins?, path, opts)
      end

      # True only when every declared origin rule is the '*' wildcard. Such a
      # resource answers with Access-Control-Allow-Origin: * and cannot carry
      # credentials.
      def public_resources?
        @public_resources
      end

      def allow_origin?(source, env = {})
        !match_origin(source, env).nil?
      end

      # Evaluates every origin rule for +source+ and returns the structured
      # OriginResult chosen by specificity (exact string, then Regexp, then
      # block, with '*' last). Returns nil when no rule matches.
      def match_origin(source, env = {})
        ranked_origins.each do |entry|
          matched = evaluate_origin(entry, source, env)
          next if matched.nil? || matched == false

          result = build_origin_result(source, entry, matched)
          result.validate!
          return result
        end

        nil
      end

      def match_resource(path, env)
        @resources.detect { |r| r.match?(path, env) }
      end

      def resource_for_path(path)
        @resources.detect { |r| r.matches_path?(path) }
      end

      private

      def add_origin(origin)
        case origin
        when '*'
          @origins << { rank: RULE_RANK[:wildcard], rule: origin }
        when Proc
          @origins << { rank: RULE_RANK[:proc], rule: origin }
        when Regexp
          @origins << { rank: RULE_RANK[:regexp], rule: origin }
        when %r{^[a-z][a-z0-9.+-]*://}
          @origins << { rank: RULE_RANK[:exact], rule: origin }
        else
          pattern = Regexp.compile("^[a-z][a-z0-9.+-]*:\\/\\/#{Regexp.quote(origin)}$")
          @origins << { rank: RULE_RANK[:regexp], rule: pattern }
        end

        # A configuration is "public" only when every rule is a wildcard: a
        # wildcard mixed with more specific rules may still answer with
        # credentials for trusted sites.
        @public_resources = @origins.any? && @origins.all? { |o| o[:rank] == RULE_RANK[:wildcard] }
      end

      def wildcard_origins?
        @origins.any? { |o| o[:rank] == RULE_RANK[:wildcard] }
      end

      def ranked_origins
        @origins.sort_by { |o| o[:rank] }
      end

      def evaluate_origin(entry, source, env)
        case entry[:rank]
        when RULE_RANK[:wildcard]
          true
        when RULE_RANK[:proc]
          entry[:rule].call(source, env)
        when RULE_RANK[:regexp]
          source =~ entry[:rule] ? true : nil
        else
          source == entry[:rule] ? true : nil
        end
      end

      def build_origin_result(source, entry, matched)
        options = {}

        if matched.is_a?(Hash)
          options[:credentials] = matched[:credentials] unless matched[:credentials].nil?
          options[:max_age] = matched[:max_age] unless matched[:max_age].nil?
        end

        options[:public] = true if entry[:rank] == RULE_RANK[:wildcard]

        OriginResult.new(source, options)
      end
    end
  end
end
