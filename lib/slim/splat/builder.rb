# frozen_string_literal: true
module Slim
  class InvalidAttributeNameError < StandardError; end
  module Splat
    # @api private
    class Builder
      # https://html.spec.whatwg.org/multipage/syntax.html#attributes-2
      INVALID_ATTRIBUTE_NAME_REGEX = /[ \0"'>\/=]/

      def initialize(options)
        @options = options
        @attrs = {}
        @namespace_context = nil
        if xml_namespaces?
          @xml_declarations = {}
          @xml_attrs = []
        end
      end

      attr_accessor :namespace_context

      def code_attr(name, escape, value)
        return xml_code_attr(name, escape, value) if xml_namespaces?

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
        return xml_splat_attrs(splat) if xml_namespaces?

        splat.each do |name, value|
          code_attr(name.to_s, true, value)
        end
      end

      def attr(name, value, use_current_scope = true, static_key = nil)
        return xml_attr(name, value, true, static_key) if xml_namespaces? && static_key
        return xml_attr(name, value, use_current_scope, static_key) if xml_namespaces?

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

      def build_tag(name: nil, &block)
        return xml_build_tag(name, &block) if xml_namespaces?

        tag = @attrs.delete('tag').to_s
        tag = name.to_s if name
        tag = @options[:default_tag] if tag.empty?
        if block
          content = capture_block_content(&block)
          "<#{tag}#{build_attrs}>#{content}</#{tag}>"
        else
          "<#{tag}#{build_attrs} />"
        end
      end

      def build_attrs
        return build_xml_attrs if xml_namespaces?

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

      def xml_namespaces?
        @options[:xml_namespaces]
      end

      def xml_code_attr(name, escape, value)
        if XMLNamespaces.declaration?(name)
          value = '' if value == true
          unless value == false || value.nil?
            xml_declaration(name, value == true ? value : escape_html(escape, value))
          end
        elsif @options[:hyphen_attrs].include?(name) && Hash === value
          hyphen_attr(name, escape, value)
        elsif value != false && value != nil
          xml_attr(name, escape_html(escape, value))
        end
      end

      def xml_splat_attrs(splat)
        splat.each do |name, value|
          xml_code_attr(name.to_s, true, value)
        end
      end

      def xml_attr(name, value, use_current_scope = true, static_key = nil)
        if name =~ INVALID_ATTRIBUTE_NAME_REGEX
          raise InvalidAttributeNameError, "Invalid attribute name '#{name}' was rendered"
        end
        return xml_declaration(name, value) if XMLNamespaces.declaration?(name)
        if name == 'tag'
          @attrs[name] = value.to_s
          return
        end

        @xml_attrs << [name, value, use_current_scope, static_key]
      end

      def xml_declaration(name, value)
        prefix = XMLNamespaces.declaration_prefix(name)
        value = value.to_s

        if prefix == 'xml' && value != XMLNamespaces::XML_NAMESPACE
          raise InvalidNamespacePrefixError, "XML namespace prefix 'xml' cannot be rebound"
        end
        if prefix == 'xmlns'
          raise InvalidNamespacePrefixError, "Invalid XML namespace prefix 'xmlns'"
        end
        if @xml_declarations.key?(prefix)
          raise DuplicateAttributeError, "Multiple #{name} attributes specified"
        end

        @xml_declarations[prefix] = {
          qname: prefix ? "xmlns:#{prefix}" : 'xmlns',
          value: value
        }
      end

      def xml_build_tag(fixed_name, &block)
        dynamic_name = @attrs.delete('tag')
        tag = if fixed_name == '*'
                dynamic_name.to_s
              elsif dynamic_name
                dynamic_name.to_s
              else
                fixed_name.to_s
              end
        @xml_attrs.reject! { |name, _| name == 'tag' } unless fixed_name == '*' || dynamic_name
        tag = @options[:default_tag] if fixed_name == '*' && tag.empty?

        bindings = xml_bindings
        namespace_context.resolve(tag, false, bindings)
        attrs = build_xml_attrs(bindings)

        if block
          content = capture_block_content_with_bindings(&block)
          "<#{tag}#{attrs}>#{content}</#{tag}>"
        else
          "<#{tag}#{attrs} />"
        end
      end

      def build_xml_attrs(bindings)
        entries = @xml_declarations.map do |prefix, declaration|
          [declaration[:qname], declaration[:value], [XMLNamespaces::XMLNS_NAMESPACE, prefix || 'xmlns']]
        end

        seen = @xml_declarations.each_with_object({}) do |(prefix, _), result|
          result[[XMLNamespaces::XMLNS_NAMESPACE, prefix || 'xmlns']] = true
        end

        @xml_attrs.each do |name, value, use_current_scope, static_key|
          key = static_key.nil? ? namespace_context.resolve(name, true, use_current_scope ? bindings : nil) : static_key
          seen[key] = true
          entries << [name, value, key]
        end

        entries = merge_xml_attributes(entries)
        entries = entries.sort_by { |name, _, key| [key.first == XMLNamespaces::XMLNS_NAMESPACE ? 0 : 1, name] } if @options[:sort_attrs]
        entries.map do |name, value, _|
          value = '' if value == true
          " #{name}=#{@options[:attr_quote]}#{value}#{@options[:attr_quote]}"
        end.join
      end

      def xml_bindings
        @xml_declarations.each_with_object({}) do |(prefix, declaration), result|
          result[prefix] = declaration[:value]
        end
      end

      def capture_block_content_with_bindings(&block)
        namespace_context.capture(bindings: xml_bindings) { capture_block_content(&block) }
      end

      def merge_xml_attributes(entries)
        grouped = {}
        entries.each do |name, value, key|
          if grouped.key?(key)
            existing_name, existing_value, _ = grouped[key]
            if existing_name == name && (delim = @options[:merge_attrs][name])
              grouped[key] = [name, existing_value.to_s + delim + value.to_s, key]
            else
              raise DuplicateAttributeError, "Multiple #{existing_name} attributes specified"
            end
          else
            grouped[key] = [name, value, key]
          end
        end
        grouped.values
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
          if xml_namespaces?
            xml_attr(name, escape_html(escape, value))
          else
            attr(name, escape_html(escape, value))
          end
        end
      end

      def escape_html(escape, value)
        return value if !escape || value == true
        @options[:use_html_safe] ? Temple::Utils.escape_html_safe(value) : Temple::Utils.escape_html(value)
      end
    end
  end
end
