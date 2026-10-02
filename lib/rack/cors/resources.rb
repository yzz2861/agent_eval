# frozen_string_literal: true

require_relative 'resources/cors_misconfiguration_error'

module Rack
  class Cors
    class Resources
      attr_reader :resources

      def initialize
        @origin_literals = []
        @origin_hosts = []
        @origin_regexps = []
        @origin_procs = []
        @resources = []
        @public_resources = false
      end

      def origins(*args, &blk)
        args.flatten.reject { |s| s == '' }.each do |n|
          case n
          when Proc then @origin_procs << n
          when Regexp then @origin_regexps << n
          when '*'
            @public_resources = true
          when %r{^[a-z][a-z0-9.+-]*://}
            @origin_literals << n
          else
            @origin_hosts << n
          end
        end
        @origin_procs << blk if blk
      end

      def resource(path, opts = {})
        @resources << Resource.new(public_resources?, path, opts).tap { |r| r.owner = self }
      end

      def public_resources?
        @public_resources
      end

      def allow_origin?(source, env = {})
        return true if public_resources?

        origin_procs.any? { |origin| origin.call(source, env) } ||
          origin_literals.any? { |origin| origin == source } ||
          origin_regexps.any? { |origin| source =~ origin } ||
          origin_hosts.any? { |host| host_pattern(host) =~ source }
      end

      # Concrete origin strings used to detect provably-disjoint origin rules
      # at initialization time. Returns nil when the block contains Proc-,
      # Regexp- or wildcard-based origins, which can only be evaluated at
      # request time.
      def concrete_origin_candidates
        return nil unless origin_procs.empty? && origin_regexps.empty?
        return nil if origin_hosts.any? { |host| host.include?('*') || host.include?('?') }

        origin_literals + origin_hosts.map { |host| "http://#{host}" }
      end

      def resources_for_path(path, env = {})
        @resources.select { |r| r.match?(path, env) }
      end

      def resources_matching_path(path)
        @resources.select { |r| r.matches_path?(path) }
      end

      def match_resource(path, env)
        @resources.detect { |r| r.match?(path, env) }
      end

      def resource_for_path(path)
        @resources.detect { |r| r.matches_path?(path) }
      end

      protected

      attr_reader :origin_literals, :origin_hosts, :origin_regexps, :origin_procs

      def host_pattern(host)
        @host_patterns ||= {}
        @host_patterns[host] ||= Regexp.compile("^[a-z][a-z0-9.+-]*:\\/\\/#{Regexp.quote(host)}$")
      end
    end
  end
end
