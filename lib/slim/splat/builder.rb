# frozen_string_literal: true
require 'cgi'
module Slim
  class InvalidAttributeNameError < StandardError; end
  class XMLNamespaceError < StandardError; end
  module Splat
    # @api private
    class Builder
      # https://html.spec.whatwg.org/multipage/syntax.html#attributes-2
      INVALID_ATTRIBUTE_NAME_REGEX = /[ \0"'>\/=]/

      def initialize(options, parent = nil, xml_namespaces = false, dynamic = false)
        @options = options
        @parent = parent
        @xml_namespaces = xml_namespaces
        @attrs = {}
        @declarations = {}
        @entries = []
        @static_tag = nil
        @finalized = false
        @dynamic = dynamic
      end

      def code_attr(name, escape, value)
        return xml_code_attr(name, escape, value) if @xml_namespaces
        if delim = @options[:merge_attrs][name]
          value = Array === value ? value.join(delim) : value.to_s
          attr(name, escape_html(escape, value)) unless value.empty?
        elsif @options[:hyphen_attrs].include?(name) && Hash === value
          hyphen_attr(name, escape, value)
        elsif value != false && value != nil
          attr(name, escape_html(escape, value))
        end
      end

      def splat_attrs(splat)
        splat.each do |name, value|
          code_attr(name.to_s, true, value)
        end
      end

      def attr(name, value)
        return xml_attr(name, value) if @xml_namespaces
        if name =~ INVALID_ATTRIBUTE_NAME_REGEX
          raise InvalidAttributeNameError, "Invalid attribute name '#{name}' was rendered"
        end
        if @attrs[name]
          if delim = @options[:merge_attrs][name]
            @attrs[name] = @attrs[name].to_s + delim + value.to_s
          else
            raise("Multiple #{name} attributes specified")
          end
        else
          @attrs[name] = value
        end
      end

      def static_tag(name)
        @static_tag = name
      end

      def xmlns_attr(name, value)
        store_declaration(name, value)
      end

      def current_scope
        finalize
        @scope
      end

      def build_tag(&block)
        return xml_build_tag(&block) if @xml_namespaces
        tag = @attrs.delete('tag').to_s
        tag = @options[:default_tag] if tag.empty?
        if block
          content = capture_block_content(&block)
          "<#{tag}#{build_attrs}>#{content}</#{tag}>"
        else
          "<#{tag}#{build_attrs} />"
        end
      end

      def build_attrs
        attrs = @options[:sort_attrs] ? @attrs.sort_by(&:first) : @attrs
        attrs.map do |k, v|
          if v == true
            if @options[:format] == :xhtml
              " #{k}=#{@options[:attr_quote]}#{@options[:attr_quote]}"
            else
              " #{k}"
            end
          else
            " #{k}=#{@options[:attr_quote]}#{v}#{@options[:attr_quote]}"
          end
        end.join
      end

      private

      def xml_code_attr(name, escape, value)
        if name == 'tag'
          attr(name, value) unless value == false || value.nil?
        elsif declaration_name?(name)
          store_declaration(name, value)
        elsif @options[:hyphen_attrs].include?(name) && Hash === value
          hyphen_attr(name, escape, value)
        elsif value == false || value.nil?
        elsif delim = @options[:merge_attrs][name]
          value = Array === value ? value.join(delim) : value.to_s
          @entries << [name, escape_html(escape, value)] unless value.empty?
        elsif value != false && value != nil
          validate_name(name)
          @entries << [name, escape_html(escape, value)]
        end
      end

      def xml_attr(name, value)
        if name == 'tag'
          @attrs[name] = value
        elsif declaration_name?(name)
          store_declaration(name, value)
        else
          validate_name(name)
          @entries << [name, value]
        end
      end

      def xml_build_tag(&block)
        finalize
        if block
          content = capture_block_content(&block)
          "<#{@tag_name}#{build_xml_attrs}>#{content}</#{@tag_name}>"
        else
          "<#{@tag_name}#{build_xml_attrs} />"
        end
      end

      def finalize
        return if @finalized
        @finalized = true

        parent_scope = @parent.is_a?(Builder) ? @parent.current_scope : @parent
        bindings = parent_scope ? parent_scope.bindings.dup : {}
        declarations = {}
        @declarations.each do |name, value|
          prefix = declaration_prefix(name)
          value = CGI.unescapeHTML(value.to_s)
          if prefix && (prefix == 'xmlns' || value.empty? || prefix == 'xml')
            raise XMLNamespaceError, "Invalid XML namespace declaration #{name}"
          end
          raise XMLNamespaceError, "Multiple namespace #{prefix.inspect} declarations" if declarations.key?(prefix)
          declarations[prefix] = value
          bindings[prefix] = value
        end
        @scope = ::Slim::XMLNamespaces::Scope.new(bindings)

        tag = @attrs.delete('tag') || @static_tag || @options[:default_tag]
        tag = @options[:default_tag] if tag.to_s.empty?
        dynamic_tag = @attrs.key?('tag') ? false : @dynamic
        _, @tag_name = resolve_name(tag.to_s, :element, @scope.bindings, dynamic_tag)

        @xml_attrs = {}
        @entries.each do |name, value|
          key, qname = resolve_name(name, :attribute, @scope.bindings, false)
          if @xml_attrs.key?(key)
            raise XMLNamespaceError, "Multiple #{name} attributes specified"
          end
          @xml_attrs[key] = [qname, value]
        end
      end

      def build_xml_attrs
        declaration_attrs = @declarations.sort_by(&:first).map do |name, value|
          " #{name}=#{@options[:attr_quote]}#{escape_xml_value(value)}#{@options[:attr_quote]}"
        end.join
        attrs = @options[:sort_attrs] ? @xml_attrs.sort_by { |_, (name, _)| name } : @xml_attrs
        declaration_attrs + attrs.map do |_, (name, value)|
          if value == true
            " #{name}=#{@options[:attr_quote]}#{@options[:attr_quote]}"
          else
            " #{name}=#{@options[:attr_quote]}#{value}#{@options[:attr_quote]}"
          end
        end.join
      end

      def resolve_name(name, type, bindings = nil, dynamic = false)
        prefix, local = split_qname(name)
        bindings ||= @scope.bindings
        unless local && (prefix.nil? || prefix == 'xml' || bindings.key?(prefix) || (type == :element && dynamic))
          raise XMLNamespaceError, "Unbound XML namespace prefix #{(prefix || name).inspect}"
        end
        if type == :attribute && prefix.nil?
          [[nil, local], local]
        elsif (type == :attribute || type == :element) && prefix == 'xmlns'
          raise XMLNamespaceError, "Invalid XML attribute name #{name}"
        else
          uri = prefix == 'xml' ? XMLNamespaces::Scope::BUILTIN[prefix] : bindings[prefix]
          uri = nil if type == :element && prefix.nil?
          [[uri, local], name]
        end
      end

      def split_qname(name)
        validate_name(name)
        parts = name.split(':'.freeze)
        return [nil, nil] if parts.size > 2 || parts.include?('')
        return [nil, parts.first] if parts.size == 1
        parts
      end

      def validate_name(name)
        if name.to_s =~ INVALID_ATTRIBUTE_NAME_REGEX || name.to_s.empty?
          raise InvalidAttributeNameError, "Invalid attribute name '#{name}' was rendered"
        end
      end

      def declaration_name?(name)
        name == 'xmlns' || name.start_with?('xmlns:')
      end

      def declaration_prefix(name)
        name == 'xmlns' ? nil : name.split(':', 3)[1]
      end

      def store_declaration(name, value)
        unless declaration_name?(name) && (name == 'xmlns' || name.split(':'.freeze).size == 2)
          raise XMLNamespaceError, "Invalid XML namespace declaration #{name}"
        end
        if value == false || value.nil?
          raise XMLNamespaceError, "Invalid XML namespace declaration #{name}"
        end
        if @declarations.key?(name)
          raise "Multiple #{name} attributes specified"
        end
        @declarations[name] = value
      end

      def escape_xml_value(value)
        Temple::Utils.escape_html(value)
      end

      # Captures block content using the appropriate capturing mechanism.
      #
      # If we have Slim capturing disabled and the scope defines the method `capture` (i.e. Rails)
      # we use this method to capture the content.
      #
      # Otherwise we just use normal Slim capturing (yield).
      #
      # See https://github.com/slim-template/slim/issues/591
      #     https://github.com/slim-template/slim#helpers-capturing-and-includes
      def capture_block_content(&block)
        if @options[:disable_capture] && (scope = block.binding.eval('self')).respond_to?(:capture)
          scope.capture(&block)
        else
          yield
        end
      end

      def hyphen_attr(name, escape, value)
        if Hash === value
          if @options[:hyphen_underscore_attrs]
            value.each do |n, v|
              hyphen_attr("#{name}-#{n.to_s.tr('_', '-')}", escape, v)
            end
          else
            value.each do |n, v|
              hyphen_attr("#{name}-#{n}", escape, v)
            end
          end
        else
          attr(name, escape_html(escape, value))
        end
      end

      def escape_html(escape, value)
        return value if !escape || value == true
        @options[:use_html_safe] ? Temple::Utils.escape_html_safe(value) : Temple::Utils.escape_html(value)
      end
    end
  end
end
