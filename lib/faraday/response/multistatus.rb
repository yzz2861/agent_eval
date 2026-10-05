# frozen_string_literal: true

require 'rexml/document'
require 'uri'

module Faraday
  class Response
    # Parses WebDAV `207 Multi-Status` response bodies (RFC 4918) into a
    # structured result.
    #
    # The response body is replaced with a {Multistatus::Result} that
    # organizes resources by their absolute href and properties by expanded
    # name (`{namespace}local-name`), so properties sharing a local name but
    # living in different namespaces are never merged together. Each
    # `propstat` keeps its own status line and error description.
    #
    # XML is parsed with REXML, a pure-Ruby parser that performs no network
    # access. Documents containing a `<!DOCTYPE` declaration are rejected,
    # which disables all (internal and external) entity definitions.
    #
    # @example
    #   conn = Faraday.new(url: 'https://dav.example.com') do |f|
    #     f.response :multistatus
    #   end
    #   result = conn.request(:propfind, '/dir/').body
    #   result['https://dav.example.com/dir/file.txt'].propstats.each do |propstat|
    #     puts propstat.status_code
    #     puts propstat['{DAV:}getcontentlength']&.value
    #   end
    class Multistatus < Middleware
      # Namespace URI of WebDAV elements.
      DAV_NAMESPACE = 'DAV:'

      # Matches `application/xml`, `text/xml` and `+xml` suffixed types.
      DEFAULT_CONTENT_TYPE = /\bxml$/

      # Extracts the three-digit code from an HTTP status line.
      STATUS_LINE_PATTERN = %r{HTTP/\d+(?:\.\d+)?\s+(\d{3})}

      # A single WebDAV property, identified by its expanded name.
      class Property
        attr_reader :namespace, :name, :value, :children

        def initialize(namespace:, name:, value: nil, children: [])
          @namespace = namespace
          @name = name
          @value = value
          @children = children
        end

        # Expanded name in James Clark notation: `{namespace}local-name`.
        # Falls back to the bare local name when no namespace is declared.
        # @return [String]
        def expanded_name
          namespace.empty? ? name : "{#{namespace}}#{name}"
        end
      end

      # A `propstat` section: a set of properties sharing one status.
      class PropStat
        attr_accessor :status, :response_description, :error
        attr_reader :properties

        def initialize
          @properties = {}
        end

        # @return [Integer, nil] the code parsed from the status line.
        def status_code
          Multistatus.status_code(status)
        end

        def ok?
          !status_code.nil? && (200..299).cover?(status_code)
        end

        # Adds a property, keyed by expanded name. When the same expanded
        # name appears twice in one `propstat`, the later element wins.
        def add_property(property)
          @properties[property.expanded_name] = property
        end

        # @param expanded_name [String] e.g. `{DAV:}getcontentlength`
        # @return [Property, nil]
        def [](expanded_name)
          @properties[expanded_name]
        end
      end

      # A `response` element: one resource and its `propstat` sections.
      class Resource
        attr_reader :href, :status, :response_description, :propstats

        def initialize(href, status: nil, response_description: nil)
          @href = href
          @status = status
          @response_description = response_description
          @propstats = []
        end

        # @return [Integer, nil] the code parsed from the status line.
        def status_code
          Multistatus.status_code(status)
        end

        # Merges a duplicate `response` element for the same href:
        # propstats are appended in document order, while the resource-level
        # status and description are kept from the first `response` that
        # defines them.
        def merge(other)
          @status = other.status if @status.nil?
          @response_description = other.response_description if @response_description.nil?
          @propstats.concat(other.propstats)
          self
        end
      end

      # The parsed multistatus document: resources keyed by absolute href.
      class Result
        include Enumerable

        attr_reader :resources

        def initialize
          @resources = {}
        end

        # Adds a resource, merging it with the existing entry when another
        # `response` element already resolved to the same href.
        def add(resource)
          existing = @resources[resource.href]
          existing ? existing.merge(resource) : @resources[resource.href] = resource
        end

        # @param href [String] absolute href of the resource
        # @return [Resource, nil]
        def [](href)
          @resources[href]
        end

        def each(&block)
          @resources.each_value(&block)
        end

        def size
          @resources.size
        end

        def empty?
          @resources.empty?
        end
      end

      # Parses the status code out of an HTTP status line.
      # @param status_line [String, nil] e.g. `HTTP/1.1 200 OK`
      # @return [Integer, nil]
      def self.status_code(status_line)
        match = STATUS_LINE_PATTERN.match(status_line.to_s)
        match && match[1].to_i
      end

      def initialize(app = nil, content_type: DEFAULT_CONTENT_TYPE, preserve_raw: false)
        super(app)
        @content_types = Array(content_type)
        @preserve_raw = preserve_raw
      end

      def on_complete(env)
        process_response(env) if parse_response?(env)
      end

      private

      def process_response(env)
        result = parse(env[:body], env[:url])
        return unless result

        env[:raw_body] = env[:body] if @preserve_raw
        env[:body] = result
      rescue StandardError => e
        raise Faraday::ParsingError.new(e, env[:response])
      end

      # @return [Result, nil] nil when the body is not a multistatus document,
      #   in which case the body is left untouched.
      def parse(body, request_url)
        return if body.strip.empty?

        root = parse_xml(body).root
        return unless root && root.name == 'multistatus' && root.namespace == DAV_NAMESPACE

        build_result(root, request_url)
      end

      def parse_xml(body)
        # REXML is pure Ruby and never performs network I/O; rejecting
        # DOCTYPE declarations additionally disables every entity
        # definition, so no external (or internal) entity can be expanded.
        if /<!DOCTYPE/i.match?(body)
          raise 'multistatus responses must not contain a DOCTYPE declaration'
        end

        REXML::Document.new(body)
      end

      def build_result(root, request_url)
        result = Result.new
        root.elements.each do |element|
          result.add(build_resource(element, request_url)) if element.name == 'response'
        end
        result
      end

      def build_resource(element, request_url)
        href = nil
        status = nil
        description = nil
        propstats = []
        element.elements.each do |child|
          case child.name
          when 'href' then href = resolve_href(child.text, request_url)
          when 'status' then status = child.text&.strip
          when 'responsedescription' then description = child.text&.strip
          when 'propstat' then propstats << build_propstat(child)
          end
        end

        resource = Resource.new(href, status: status, response_description: description)
        resource.propstats.concat(propstats)
        resource
      end

      def build_propstat(element)
        propstat = PropStat.new
        element.elements.each do |child|
          case child.name
          when 'prop'
            child.elements.each { |node| propstat.add_property(build_property(node)) }
          when 'status' then propstat.status = child.text&.strip
          when 'responsedescription' then propstat.response_description = child.text&.strip
          when 'error' then propstat.error = child.text&.strip
          end
        end
        propstat
      end

      def build_property(element)
        Property.new(
          namespace: element.namespace,
          name: element.name,
          value: text_value(element),
          children: element.elements.map { |child| build_property(child) }
        )
      end

      def text_value(element)
        text = element.texts.join.strip
        text.empty? ? nil : text
      end

      # Resolves a (possibly relative) href against the request URI.
      # Falls back to the raw href when no request URI is available or the
      # href cannot be resolved.
      def resolve_href(href, request_url)
        href = href.to_s.strip
        return href if href.empty? || request_url.nil?

        URI.join(request_url.to_s, href).to_s
      rescue URI::Error
        href
      end

      def parse_response?(env)
        process_response_type?(env) &&
          env[:body].respond_to?(:to_str)
      end

      def process_response_type?(env)
        type = response_type(env)
        @content_types.empty? || @content_types.any? do |pattern|
          pattern.is_a?(Regexp) ? type.match?(pattern) : type == pattern
        end
      end

      def response_type(env)
        type = env[:response_headers][CONTENT_TYPE].to_s
        type = type.split(';', 2).first if type.index(';')
        type
      end
    end
  end
end

Faraday::Response.register_middleware(multistatus: Faraday::Response::Multistatus)
