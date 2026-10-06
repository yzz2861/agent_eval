# frozen_string_literal: true
module Slim
  class InvalidNamespacePrefixError < StandardError; end
  class DuplicateAttributeError < StandardError; end

  module XMLNamespaces
    XMLNS_NAMESPACE = 'http://www.w3.org/2000/xmlns/'
    XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace'
    DYNAMIC_NAMESPACE = Object.new.freeze
    UNBOUND_NAMESPACE = Object.new.freeze
    QNAME_REGEX = /\A(?:([^:]+):)?([^:]+)\z/

    class Scope
      attr_reader :bindings

      def initialize(bindings = nil)
        @bindings = bindings || {nil => UNBOUND_NAMESPACE, 'xml' => XML_NAMESPACE}
      end

      def child(declarations)
        Scope.new(bindings.merge(declarations))
      end

      def concrete_bindings
        bindings.reject { |_, uri| uri.equal?(DYNAMIC_NAMESPACE) }
      end

      def static_resolve(qname, is_attribute)
        prefix, local = qname[QNAME_REGEX, 1], qname[QNAME_REGEX, 2]
        return nil unless local

        if prefix
          return nil unless bindings.key?(prefix)
          uri = bindings[prefix]
          return nil if uri.equal?(UNBOUND_NAMESPACE)
        elsif !is_attribute
          return nil unless bindings.key?(nil)
          uri = bindings[nil]
          return nil if uri.equal?(UNBOUND_NAMESPACE)
        else
          uri = nil
        end

        [uri, local]
      end
    end

    class Context
      def initialize(static_bindings)
        static_bindings = static_bindings.map do |prefix, uri|
          [prefix, uri == '' ? UNBOUND_NAMESPACE : uri]
        end.to_h
        @frames = [static_bindings]
      end

      def capture(bindings:)
        bindings = bindings.map { |prefix, uri| [prefix, uri == '' ? UNBOUND_NAMESPACE : uri] }.to_h
        @frames << @frames.last.merge(bindings)
        begin
          yield
        ensure
          @frames.pop
        end
      end

      def dynamic_frame!
        @frames << @frames.last.dup
        self
      end

      def pop_frame!
        @frames.pop
        self
      end

      def bind(prefix)
        @frames.reverse_each do |bindings|
          return bindings[prefix] if bindings.key?(prefix)
        end
        DYNAMIC_NAMESPACE
      end

      def resolve(qname, is_attribute, current_bindings = nil)
        prefix, local = qname[QNAME_REGEX, 1], qname[QNAME_REGEX, 2]
        raise InvalidNamespacePrefixError, "Invalid XML name '#{qname}'" unless local
        bindings = current_bindings.nil? ? nil : @frames.last.merge(current_bindings)

        if prefix
          uri = bindings && bindings.key?(prefix) ? bindings[prefix] : bind(prefix)
          raise InvalidNamespacePrefixError, "Unbound XML namespace prefix '#{prefix}'" if uri.equal?(UNBOUND_NAMESPACE)
          if uri.equal?(DYNAMIC_NAMESPACE)
            raise InvalidNamespacePrefixError, "Unbound XML namespace prefix '#{prefix}'"
          end
        elsif !is_attribute
          uri = bindings && bindings.key?(nil) ? bindings[nil] : bind(nil)
          if uri.equal?(DYNAMIC_NAMESPACE) || uri.equal?(UNBOUND_NAMESPACE)
            raise InvalidNamespacePrefixError, 'Unbound default XML namespace'
          end
        else
          uri = nil
        end

        [uri, local]
      end
    end

    def self.declaration?(name)
      name == 'xmlns' || name.start_with?('xmlns:')
    end

    def self.declaration_prefix(name)
      name == 'xmlns' ? nil : name[6..-1]
    end

    def self.static_literal(value)
      return nil unless value.is_a?(Array)
      case value[0]
      when :escape
        static_literal(value[2])
      when :static
        value[1].is_a?(String) ? value[1] : nil
      when :slim
        return nil unless value[1] == :interpolate && value[2].is_a?(String)
        value[2] =~ /(?<!\\)#\{/ ? nil : value[2]
      when :multi
        parts = value[1..-1]
        return nil if parts.empty? || !parts.all? { |part| part.is_a?(Array) && part[0] == :static && part[1].is_a?(String) }
        parts.map { |part| part[1] }.join
      end
    end
  end
end
