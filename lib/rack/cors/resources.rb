# frozen_string_literal: true

require_relative 'resources/cors_misconfiguration_error'

module Rack
  class Cors
    class Resources
      NULL_ORIGIN = :null

      attr_reader :resources

      def initialize(strict_origin_check = false)
        @strict_origin_check = strict_origin_check
        @origins = []
        @resources = []
        @public_resources = false
        @null_origin = false
      end

      def origins(*args, &blk)
        @origins = args.flatten.reject { |s| s == '' }.map do |n|
          case n
          when Proc, Regexp
            n
          when NULL_ORIGIN
            null_origin!
          when 'null'
            @strict_origin_check ? null_origin! : compiled_origin(n)
          when '*'
            @public_resources = true
            n
          else
            configured_origin(n)
          end
        end.flatten
        @origins.push(blk) if blk
      end

      def resource(path, opts = {})
        @resources << Resource.new(public_resources?, path, opts, strict_origin_check: @strict_origin_check)
      end

      def public_resources?
        @public_resources
      end

      def allow_origin?(source, env = {})
        source = source.to_s

        if source == Origin::NULL
          return false if @strict_origin_check && !@null_origin
          return true if public_resources?
        end

        return true if public_resources?

        !!@origins.detect do |origin|
          if origin.is_a?(Proc)
            origin.call(source, env)
          elsif origin.is_a?(Regexp)
            source =~ origin
          elsif origin == NULL_ORIGIN
            source == Origin::NULL
          else
            source == origin
          end
        end
      end

      def match_resource(path, env)
        @resources.detect { |r| r.match?(path, env) }
      end

      def resource_for_path(path)
        @resources.detect { |r| r.matches_path?(path) }
      end

      private

      def null_origin!
        @null_origin = true
        NULL_ORIGIN
      end

      def configured_origin(value)
        if value =~ %r{\A[a-zA-Z][a-zA-Z0-9+.-]*://}
          return value unless @strict_origin_check

          serialized = Origin.serialize(value)
          raise ArgumentError, "#{value.inspect} is not a valid serialized origin" unless serialized

          serialized
        else
          @strict_origin_check ? strict_bare_origin(value) : compiled_origin(value)
        end
      end

      def compiled_origin(value)
        Regexp.compile("^[a-z][a-z0-9.+-]*:\\/\\/#{Regexp.quote(value)}$")
      end

      def strict_bare_origin(value)
        host, port = bare_host_and_port(value)
        pattern = Regexp.quote(host)
        source_pattern = "[a-z][a-z0-9.+-]*://#{pattern}"
        pattern_source =
          if port
            default_schemes = Origin::DEFAULT_PORTS.select { |_, default_port| default_port == port }.keys
            alternatives = ["#{source_pattern}:#{port}"]
            alternatives << "(?:#{default_schemes.join('|')})://#{pattern}" if default_schemes.any?
            alternatives.join('|')
          else
            source_pattern
          end

        Regexp.compile(%r{\A(?:#{pattern_source})\z})
      end

      def bare_host_and_port(value)
        if value.start_with?('[')
          match = %r{\A\[(?<address>[^\[\]]+)\](?::(?<port>\d{1,5}))?\z}.match(value)
          raise ArgumentError, "#{value.inspect} is not a valid origin host" unless match

          address = IPAddr.new(match[:address])
          raise ArgumentError, "#{value.inspect} is not a valid origin host" unless address.ipv6?

          ["[#{address}]", match[:port]&.to_i]
        else
          match = %r{\A(?<host>[^:]*)(?::(?<port>\d{1,5}))?\z}.match(value)
          raise ArgumentError, "#{value.inspect} is not a valid origin host" unless match
          raise ArgumentError, "#{value.inspect} is not a valid origin host" if value.count(':') > 1

          [match[:host].downcase, match[:port]&.to_i]
        end
      rescue IPAddr::InvalidAddressError
        raise ArgumentError, "#{value.inspect} is not a valid origin host"
      end
    end
  end
end
