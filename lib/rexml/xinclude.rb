# frozen_string_literal: true

require_relative "text"
require_relative "element"
require "uri"

module REXML
  # Expand XInclude elements explicitly.
  module XInclude
    NAMESPACE = "http://www.w3.org/2001/XInclude"

    class Error < StandardError; end
    class ResourceMissing < Error; end
    class RecursiveInclude < Error; end
    class UnsupportedXPointer < Error; end

    class << self
      # Expands all XInclude elements in +node+.
      #
      # +resolver+ is called with an absolute URI string and must return the
      # referenced resource as a String or readable IO. Raise ResourceMissing
      # to make the include use its fallback element. REXML never opens URIs
      # itself.
      def expand(node, resolver = nil, base: nil, &block)
        resolver ||= block
        unless resolver.respond_to?(:call)
          raise ArgumentError, "resolver must respond to #call"
        end

        initial_base = base&.to_s
        inclusion_chain = initial_base ? [initial_base] : []
        expanded_includes = []

        expand_nodes(node.children,
                      resolver,
                      initial_base,
                      inclusion_chain,
                      expanded_includes)
        node
      end

      private

      def expand_included_document(node, resolver, base, chain)
        expand_nodes(node.children, resolver, base, chain, [])
      end

      def expand_nodes(nodes, resolver, initial_base, chain, expanded_includes)
        loop do
          include_element = find_include_in_nodes(nodes, expanded_includes)
          break unless include_element

          expanded_includes << include_element.object_id
          expand_include(include_element,
                          resolver,
                          initial_base,
                          chain,
                          expanded_includes)
        end
      end

      def find_include_in_nodes(nodes, expanded_includes)
        nodes.each do |child|
          next unless child.is_a?(Element)
          if include?(child) && !expanded_includes.include?(child.object_id)
            return child
          end

          found = find_include_in_nodes(child.children, expanded_includes)
          return found if found
        end
        nil
      end

      def include?(element)
        element.namespace == NAMESPACE && element.name == "include"
      end

      def fallback?(element)
        element.namespace == NAMESPACE && element.name == "fallback"
      end

      def expand_include(include_element, resolver, initial_base, chain, expanded_includes)
        parse = include_element["parse"] || "xml"
        unless ["xml", "text"].include?(parse)
          raise Error, "unsupported XInclude parse type: #{parse.inspect}"
        end
        if include_element.attributes.key?("xpointer")
          raise UnsupportedXPointer, "XPointer is not supported"
        end
        if parse == "xml" && include_element.attributes.key?("encoding")
          raise Error, %q(encoding is only allowed for parse="text")
        end

        fallback = validate_children(include_element)
        target_uri = resolve_href(include_element, initial_base)
        if chain.include?(target_uri.to_s)
          raise RecursiveInclude, "recursive XInclude chain: #{target_uri}"
        end
        target_chain = chain + [target_uri.to_s]

        resource = begin
          resolver.call(target_uri.to_s)
        rescue ResourceMissing
          raise unless fallback

          replacement_nodes = fallback.children.map do |child|
            child.is_a?(Parent) ? child.deep_clone : child.clone
          end
          replace(include_element, replacement_nodes)
          expand_nodes(replacement_nodes,
                        resolver,
                        initial_base,
                        target_chain,
                        expanded_includes)
          return
        end

        content = read_resource(resource)
        if parse == "text"
          replace(include_element, [Text.new(content, true, nil, false)])
        else
          replace_xml(include_element,
                      content,
                      target_uri,
                      resolver,
                      target_chain,
                      initial_base,
                      expanded_includes)
        end
      end

      def validate_children(include_element)
        fallback = nil
        include_element.children.each do |child|
          case child
          when Element
            unless fallback?(child)
              raise Error, "unexpected XInclude child: #{child.expanded_name}"
            end
            if fallback
              raise Error, "multiple XInclude fallback elements"
            end
            fallback = child
          when Text
            unless child.value.strip.empty?
              raise Error, "unexpected text in XInclude element"
            end
          end
        end
        fallback
      end

      def resolve_href(include_element, initial_base)
        href = include_element["href"]
        if href.nil?
          raise Error, "XInclude href is required when xpointer is not used"
        end

        current_base = effective_base(include_element, initial_base)
        begin
          href_uri = URI.parse(href)
          if href_uri.relative?
            raise Error, "cannot resolve relative XInclude href without a base URI" if current_base.nil?
            target_uri = URI.parse(current_base).merge(href_uri)
          else
            target_uri = href_uri
          end
        rescue URI::InvalidURIError => error
          raise Error, "invalid XInclude URI: #{error.message}"
        end

        if target_uri.fragment
          raise UnsupportedXPointer, "XPointer fragments are not supported"
        end
        target_uri
      end

      def effective_base(element, initial_base)
        elements = []
        current = element
        while current.is_a?(Element)
          elements << current
          current = current.parent
        end

        base = initial_base
        elements.reverse_each do |current_element|
          xml_base = current_element.attribute("xml:base")&.value
          next unless xml_base

          base = resolve_uri(base, xml_base).to_s
        end
        base
      end

      def resolve_uri(base, reference)
        reference_uri = URI.parse(reference)
        return reference_uri if reference_uri.absolute?
        if base.nil?
          raise Error, "cannot resolve relative URI without a base URI"
        end
        URI.parse(base).merge(reference_uri)
      rescue URI::InvalidURIError => error
        raise Error, "invalid XInclude URI: #{error.message}"
      end

      def read_resource(resource)
        case resource
        when String
          resource
        when nil
          raise Error, "XInclude resolver returned nil"
        else
          unless resource.respond_to?(:read)
            raise ArgumentError, "XInclude resource must be a String or readable IO"
          end
          resource.read
        end
      end

      def replace_xml(include_element, content, target_uri, resolver, chain, initial_base, expanded_includes)
        context = include_element.document&.context || include_element.context || {}
        source = Document.new(content, context)
        if source.root.nil?
          raise ParseException.new("included XML document has no root element")
        end

        expand_included_document(source,
                                  resolver,
                                  target_uri.to_s,
                                  chain)

        source_base = resolve_uri(target_uri, source.root.attribute("xml:base")&.value || "")
        destination_base = effective_base(include_element, initial_base)
        nodes = source.root.children.map do |child|
          copied = child.is_a?(Parent) ? child.deep_clone : child.clone
          if copied.is_a?(Element)
            fix_namespaces(child, copied, include_element)
            fix_base_uri(copied, source_base, destination_base || target_uri.to_s)
          end
          copied
        end
        replace(include_element, nodes)
      end

      def fix_namespaces(original, copied, include_element)
        destination_namespaces = include_element.namespaces
        source_default = original.namespaces.fetch("xmlns", "")
        destination_default = destination_namespaces.fetch("xmlns", "")
        if source_default != destination_default && copied.attribute("xmlns").nil?
          copied.add_attribute("xmlns", source_default)
        end

        inherited_namespaces(original).each do |prefix, uri|
          next if copied.attribute("xmlns:#{prefix}")
          next if destination_namespaces[prefix] == uri

          copied.add_attribute("xmlns:#{prefix}", uri)
        end
      end

      def inherited_namespaces(element,
                               declared_prefixes = own_namespace_prefixes(element),
                               namespaces = {})
        add_inherited_namespace(element, element.prefix, declared_prefixes, namespaces)
        element.attributes.each_attribute do |attribute|
          next if attribute.namespace_declaration?
          add_inherited_namespace(attribute,
                                  attribute.prefix,
                                  declared_prefixes,
                                  namespaces)
        end

        element.children.each do |child|
          next unless child.is_a?(Element)

          child_prefixes = declared_prefixes + own_namespace_prefixes(child)
          inherited_namespaces(child, child_prefixes, namespaces)
        end
        namespaces
      end

      def add_inherited_namespace(node, prefix, declared_prefixes, namespaces)
        return if prefix.nil? || prefix.empty? || declared_prefixes.include?(prefix)

        namespaces[prefix] ||= node.namespace(prefix)
      end

      def own_namespace_prefixes(element)
        prefixes = []
        element.attributes.each_attribute do |attribute|
          if attribute.namespace_declaration? && attribute.name != "xmlns"
            prefixes << attribute.name
          end
        end
        prefixes
      end

      def fix_base_uri(copied, source_base, destination_base)
        existing_base = copied.attribute("xml:base")&.value
        effective_base = if existing_base
          resolve_uri(source_base, existing_base)
        else
          source_base
        end

        if effective_base.to_s == destination_base.to_s
          copied.delete_attribute("xml:base") if existing_base
        else
          copied.add_attribute("xml:base", effective_base.to_s)
        end
      end

      def replace(include_element, nodes)
        if nodes.empty?
          include_element.remove
          return
        end

        include_element.replace_with(nodes.first)
        previous = nodes.first
        nodes[1..].each do |node|
          previous.parent.insert_after(previous, node)
          previous = node
        end
      end
    end
  end

  class Document
    # Expands XInclude elements in this document using the given resolver.
    #
    # The resolver receives an absolute URI string and returns a String or
    # readable IO. Raise REXML::XInclude::ResourceMissing to use an include's
    # fallback element.
    def xinclude(resolver = nil, base: nil, &block)
      XInclude.expand(self, resolver, base: base, &block)
    end
  end
end
