# frozen_string_literal: true

require "uri"

require_relative "document"
require_relative "text"

module REXML
  # Implements explicit {XInclude 1.0}[https://www.w3.org/TR/xinclude/]
  # expansion for an existing REXML document tree.
  #
  # Expansion is never performed implicitly while parsing and the
  # processor never accesses the network or arbitrary local paths by
  # itself. Every referenced resource is fetched through the resolver
  # object supplied by the caller:
  #
  #   resolver = lambda do |uri|
  #     File.read(uri.path) # the caller decides what is accessible
  #   end
  #   REXML::XInclude.expand(document, resolver, base: "file:/doc/main.xml")
  #
  # The resolver receives the resolved absolute URI (a String) and must
  # return the resource content as a String or an IO. It may return
  # +nil+ or raise REXML::XInclude::ResourceError to report that the
  # resource is unavailable; in that case the +xi:fallback+ of the
  # include is used (and the include is dropped when it has none). Any
  # other exception, as well as malformed XML for +parse="xml"+, is a
  # fatal error and is propagated rather than swallowed by fallback.
  #
  # Only +parse="xml"+ (the default) and +parse="text"+ are supported.
  # The +xpointer+ attribute and fragment identifiers in +href+ are not
  # supported yet and cause a fatal REXML::XInclude::UnsupportedError.
  module XInclude
    # The namespace URI of XInclude elements.
    NAMESPACE = "http://www.w3.org/2001/XInclude"

    # Base class of all errors raised by XInclude expansion.
    class Error < StandardError
    end

    # Fatal error: the include construct itself is invalid (unknown
    # +parse+ value, unsupported +xpointer+, broken fallback content,
    # recursive include chain, ...). It is never absorbed by fallback.
    class FatalError < Error
    end

    # The include chain contains a resource that (directly or
    # indirectly) includes itself.
    class InclusionLoopError < FatalError
    end

    # An XPointer / same-document reference or another XInclude feature
    # that this implementation does not support was encountered.
    class UnsupportedError < FatalError
    end

    # A referenced resource could not be obtained or decoded. This is a
    # recoverable error: the include's +xi:fallback+ is used when
    # present, and the include is silently dropped otherwise.
    class ResourceError < Error
    end

    # The content of a +parse="xml"+ resource is not well-formed XML.
    # This is fatal and is *not* absorbed by fallback.
    class ParseError < FatalError
    end

    # :call-seq:
    #   expand(document, resolver = nil, base: nil) -> document
    #   expand(document, base: nil) { |uri| ... } -> document
    #
    # Expands all +xi:include+ elements in +document+ in place and
    # returns the document.
    #
    # +resolver+ (or the block) is called with the resolved absolute
    # URI of every referenced resource and must return a String or an
    # IO. +base+ is the base URI of +document+ itself and is used to
    # resolve relative references when the document has no applicable
    # +xml:base+ attribute.
    def self.expand(document, resolver = nil, base: nil, &block)
      resolver ||= block
      if resolver.nil?
        raise ArgumentError, "a resolver callable or a block is required"
      end
      unless resolver.respond_to?(:call)
        raise ArgumentError, "resolver must respond to #call"
      end
      Processor.new(resolver, base).expand(document)
      document
    end

    class Processor
      def initialize(resolver, base)
        @resolver = resolver
        @base = base
      end

      def expand(document)
        process_children(document, @base ? [@base] : [])
      end

      # Processes includes in an already fetched resource whose own
      # base URI is the last entry of +chain+.
      def expand_resource(document, chain)
        process_children(document, chain)
      end

      private

      def xinclude?(node)
        node.is_a?(Element) &&
          node.name == "include" &&
          node.namespace == NAMESPACE
      end

      def fallback?(node)
        node.is_a?(Element) &&
          node.name == "fallback" &&
          node.namespace == NAMESPACE
      end

      # Processes every include found among the descendants of
      # +parent+. +chain+ holds the resolved URIs of the resources that
      # contain +parent+ (the document base first, if known).
      def process_children(parent, chain)
        stack = parent.children.reverse
        until stack.empty?
          child = stack.pop
          if xinclude?(child)
            process(child, chain)
          elsif child.is_a?(Parent)
            stack.concat(child.children.reverse)
          end
        end
      end

      def process(include, chain)
        validate!(include)
        parse = (include.attribute("parse")&.value || "xml")
        href = include.attribute("href")&.value

        include_base = base_uri_of(include, chain, include_own: true)
        resource_uri = resolve_href(href, include_base)
        own_attribute = include.attributes.get_attribute("xml:base")
        own_base = own_attribute.nil? ? nil : own_attribute.value

        if chain.include?(resource_uri)
          raise InclusionLoopError,
                "recursive include detected: #{resource_uri}"
        end

        content =
          begin
            case parse
            when "xml"
              include_xml(include, resource_uri, chain, own_base)
            when "text"
              include_text(include, resource_uri)
            end
          rescue ResourceError
            use_fallback(include, chain)
          end

        replace_include(include, content)
      end

      def validate!(include)
        parse = include.attribute("parse")&.value
        unless parse.nil? || parse == "xml" || parse == "text"
          raise UnsupportedError,
                "unsupported parse value: #{parse.inspect}"
        end

        xpointer = include.attribute("xpointer")&.value
        unless xpointer.nil? || xpointer.empty?
          raise UnsupportedError, "xpointer is not supported"
        end

        fallback_count = 0
        include.children.each do |child|
          next unless child.is_a?(Element)
          if fallback?(child)
            fallback_count += 1
          else
            raise FatalError,
                  "unexpected element in xi:include: " \
                  "<#{child.name}>"
          end
        end
        if fallback_count > 1
          raise FatalError,
                "xi:include has #{fallback_count} xi:fallback children"
        end
      end

      def resolve_href(href, include_base)
        if href.nil? || href.empty?
          raise UnsupportedError,
                "same-document include is not supported"
        end

        href_uri = begin
          URI.parse(href)
        rescue URI::Error => error
          raise ResourceError, "invalid href #{href.inspect}: #{error.message}"
        end
        if href_uri.fragment
          raise UnsupportedError,
                "fragment identifiers in href are not supported: " \
                "#{href.inspect}"
        end

        if href_uri.relative?
          if include_base.nil?
            raise ResourceError,
                  "cannot resolve relative href #{href.inspect} " \
                  "without a base URI"
          end
          URI.join(include_base, href_uri).to_s
        else
          href_uri.to_s
        end
      end

      # Returns the effective base URI of +element+. xml:base attributes
      # found on the element (when +include_own+) and on its ancestors
      # are applied on top of the base URI of the containing resource
      # (the last entry of +chain_or_base+).
      def base_uri_of(element, chain_or_base, include_own:)
        base =
          if chain_or_base.is_a?(Array)
            chain_or_base.last
          else
            chain_or_base
          end

        segments = []
        node = element
        until node.nil? || node.is_a?(Document)
          if node.equal?(element) && !include_own
            node = node.parent
            next
          end
          segments << node.attribute("xml:base")&.value
          node = node.parent
        end

        segments.reverse_each do |segment|
          next if segment.nil?
          next if base.nil?
          begin
            uri = URI.parse(segment)
          rescue URI::Error
            next
          end
          base =
            if uri.relative?
              URI.join(base, uri).to_s
            else
              uri.to_s
            end
        end
        base
      end

      def fetch(uri, encoding)
        result = @resolver.call(uri)
        if result.nil?
          raise ResourceError, "resource not available: #{uri}"
        end
        data = result.respond_to?(:read) ? result.read : result.to_s
        if encoding
          begin
            data = data.encode(::Encoding::UTF_8, encoding)
            data.force_encoding(::Encoding::UTF_8)
            unless data.valid_encoding?
              raise ::EncodingError,
                    "invalid byte sequence for #{encoding}"
            end
          rescue ::EncodingError, ::Encoding::ConverterNotFoundError => error
            raise ResourceError,
                  "failed to decode #{uri} as #{encoding}: #{error.message}"
          end
        elsif !data.valid_encoding?
          raise ResourceError,
                "resource #{uri} contains bytes invalid for its " \
                "declared encoding (#{data.encoding.name})"
        end
        data
      end

      def include_xml(include, resource_uri, chain, own_base)
        encoding = include.attribute("encoding")&.value
        if encoding
          raise FatalError,
                "encoding attribute is not allowed with parse=xml"
        end
        data = fetch(resource_uri, encoding)
        document = begin
          Document.new(data, include.document&.context || {})
        rescue REXML::ParseException => error
          raise ParseError,
                "malformed XML in #{resource_uri}: #{error.message}"
        end
        elements = document.children.select { |child| child.is_a?(Element) }
        if elements.empty?
          raise ParseError,
                "included resource has no root element: #{resource_uri}"
        elsif elements.size > 1
          raise ParseError,
                "included resource has multiple root elements: #{resource_uri}"
        end

        # Expand nested includes against the included resource before
        # moving its content into the including tree.
        Processor.new(@resolver, resource_uri)
          .expand_resource(document, chain + [resource_uri])

        location_base = base_uri_of(include, chain, include_own: false)
        document.children.select do |child|
          child.is_a?(Element) || child.is_a?(Instruction) ||
            child.is_a?(Comment)
        end.map do |child|
          if child.is_a?(Element)
            fixup_namespaces!(child, include.parent)
            fixup_base!(child, resource_uri, location_base, own_base)
          end
          child.parent = nil
          child
        end
      end

      def include_text(include, resource_uri)
        encoding = include.attribute("encoding")&.value
        data = fetch(resource_uri, encoding)
        # XInclude: sequences of CR and CRLF in a text include are
        # normalized to a single #xA character.
        data = data.gsub("\r\n".b, "\n".b).gsub("\r".b, "\n".b)
        Text.new(data, true)
      end

      # Adds the namespace declarations that are required so that
      # +element+ keeps its meaning after it has been moved to
      # +destination+.
      def fixup_namespaces!(element, destination)
        return unless destination.is_a?(Element)

        destination_namespaces = destination.namespaces

        used_prefixes(element).each do |prefix|
          next if prefix == "xml" || prefix.start_with?("xmlns")
          source_uri = element.namespaces[prefix]
          bound_uri = destination_namespaces[prefix]
          next if source_uri.nil? || source_uri == bound_uri
          element.add_namespace(prefix, source_uri)
        end

        unless element.attribute("xmlns")
          in_scope_default = element.namespaces["xmlns"].to_s
          destination_default = destination_namespaces["xmlns"].to_s
          if !destination_default.empty? && in_scope_default.empty?
            element.add_attribute("xmlns", "")
          end
        end
      end

      # Sets xml:base on +element+ following XInclude base URI fixup.
      # +own_base+ is the value of xml:base on the xi:include element
      # itself; +location_base+ is its base with that attribute excluded.
      def fixup_base!(element, resource_uri, location_base, own_base)
        if own_base
          element.add_attribute("xml:base", own_base)
          return
        end
        return if location_base && same_document_uri?(location_base, resource_uri)

        base_value =
          if location_base
            relative_reference(location_base, resource_uri)
          else
            resource_uri
          end
        element.add_attribute("xml:base", base_value)
      end

      # Collects the prefixes used by element and attribute names in the
      # subtree rooted at +element+.
      def used_prefixes(element, result = {})
        prefix = element.prefix
        result[prefix] = true if prefix && !prefix.empty?
        element.attributes.each_attribute do |attribute|
          name = attribute.expanded_name
          next unless name.include?(":")
          attribute_prefix = name.split(":", 2).first
          result[attribute_prefix] = true if attribute_prefix != "xml"
        end
        element.each_element do |child|
          used_prefixes(child, result)
        end
        result.keys
      end

      def same_document_uri?(base_uri, resource_uri)
        base = URI.parse(base_uri)
        resource = URI.parse(resource_uri)
        base.scheme == resource.scheme &&
          base.userinfo == resource.userinfo &&
          base.host == resource.host &&
          base.port == resource.port &&
          base.opaque == resource.opaque &&
          base.path == resource.path
      rescue URI::Error
        false
      end

      # RFC 3986 section 5.3: express +target+ relative to +base+ when
      # they share scheme and authority; use the absolute target otherwise.
      def relative_reference(base_uri, target_uri)
        base = URI.parse(base_uri)
        target = URI.parse(target_uri)
        return target_uri unless base.scheme == target.scheme &&
                                 base.authority == target.authority

        base_path = base.path.empty? ? "/" : base.path
        target_path = target.path.empty? ? "/" : target.path
        base_segments = base_path.split("/", -1)
        target_segments = target_path.split("/", -1)
        base_segments.pop

        while !base_segments.empty? && target_segments.size > 1 &&
              base_segments.first == target_segments.first
          base_segments.shift
          target_segments.shift
        end

        relative = Array.new(base_segments.size) { ".." }
        relative.concat(target_segments)
        result = relative.join("/")
        query = target.query ? "?#{target.query}" : ""
        "#{result}#{query}"
      rescue URI::Error
        target_uri
      end

      def use_fallback(include, chain)
        fallback = include.children.find { |child| fallback?(child) }
        return nil unless fallback

        fallback.children.dup.each do |child|
          process(child, chain) if xinclude?(child)
        end
        fallback.children.dup
      end

      def replace_include(include, content)
        parent = include.parent
        index = parent.index(include)
        parent.delete(include)

        replacement = content.is_a?(Array) ? content : [content]
        replacement.compact!
        replacement.each_with_index do |node, offset|
          parent[index + offset, 0] = node
        end
      end
    end
  end

  class Document
    # Expands all +xi:include+ elements in this document in place.
    # See XInclude.expand for the meaning of +resolver+ and +base+.
    def expand_xincludes(resolver = nil, base: nil, &block)
      XInclude.expand(self, resolver, base: base, &block)
    end
  end
end
