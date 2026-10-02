# frozen_string_literal: true

require 'ipaddr'

module Rack
  class Cors
    class Origin
      NULL = 'null'.freeze

      DEFAULT_PORTS = {
        'http' => 80,
        'https' => 443,
        'ws' => 80,
        'wss' => 443,
        'ftp' => 21
      }.freeze

      SPECIAL_SCHEMES = DEFAULT_PORTS.keys.freeze

      SCHEME = %r{\A([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)\z}.freeze
      HOST_AND_PORT = %r{\A(?<host>[^:]*)(?::(?<port>\d{1,5}))?\z}.freeze
      DOMAIN = %r{\A(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*\.?\z}.freeze
      OPAQUE_HOST = %r{\A(?:[a-z0-9\-._~!$&'()*+;=]|%[0-9a-fA-F]{2})*\z}.freeze
      IPV4 = %r{\A(?:\d{1,3}\.){3}\d{1,3}\z}.freeze

      def self.serialize(value)
        return unless value.is_a?(String)
        return NULL if value == NULL
        return if value =~ /[^!-~]/ || value.include?(',')

        match = SCHEME.match(value)
        return unless match

        scheme = match[1].downcase
        remainder = match[2]
        return if remainder.include?('@') || remainder.include?('?') || remainder.include?('#')

        host, port = host_and_port(scheme, remainder)
        return unless host
        return unless valid_port?(port)

        port_number = port ? Integer(port) : nil
        port_number = nil if DEFAULT_PORTS[scheme] == port_number

        "#{scheme}://#{host}" + (port_number ? ":#{port_number}" : '')
      end

      def self.host_and_port(scheme, remainder)
        if remainder.start_with?('[')
          ipv6_host_and_port(remainder)
        else
          regular_host_and_port(scheme, remainder)
        end
      end
      private_class_method :host_and_port

      def self.ipv6_host_and_port(remainder)
        match = %r{\A\[(?<address>[^\[\]]+)\](?::(?<port>\d{1,5}))?\z}.match(remainder)
        return unless match

        address = IPAddr.new(match[:address])
        return unless address.ipv6?

        ["[#{address}]", match[:port]]
      rescue IPAddr::InvalidAddressError
        nil
      end
      private_class_method :ipv6_host_and_port

      def self.regular_host_and_port(scheme, remainder)
        match = HOST_AND_PORT.match(remainder)
        return unless match
        return unless remainder.count(':') == (match[:port] ? 1 : 0)

        host = match[:host].downcase
        return if SPECIAL_SCHEMES.include?(scheme) && host.empty?
        return unless valid_host?(scheme, host)

        [host, match[:port]]
      end
      private_class_method :regular_host_and_port

      def self.valid_host?(scheme, host)
        if SPECIAL_SCHEMES.include?(scheme)
          valid_special_host?(host)
        else
          OPAQUE_HOST.match?(host)
        end
      end
      private_class_method :valid_host?

      def self.valid_special_host?(host)
        return true if DOMAIN.match?(host)
        return false unless IPV4.match?(host)

        address = IPAddr.new(host)
        address.ipv4? && address.to_s == host
      rescue IPAddr::InvalidAddressError
        false
      end
      private_class_method :valid_special_host?

      def self.valid_port?(port)
        port.nil? || (!port.start_with?('0') && Integer(port) <= 65535)
      end
      private_class_method :valid_port?
    end
  end
end
