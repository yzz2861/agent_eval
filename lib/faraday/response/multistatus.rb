# frozen_string_literal: true

require 'rexml/document'
require 'uri'

module Faraday
  class Response
    # Parses WebDAV 207 Multi-Status response bodies (RFC 4918).
    #
    # A multi-status body carries one <response> element per resource, and
    # each resource groups its properties into <propstat> blocks that have
    # their own status line. This middleware replaces the response body with
    # a {Multistatus::Result} keyed by absolute resource href, where every
    # property is identified by its expanded name ("{namespace-uri}local")
    # so properties sharing a local name in different namespaces never
    # collide, and every propstat keeps its own status and error details.
    #
    # Security: the parser refuses any body containing a DOCTYPE
    # declaration, which disables DTDs, (external) entities and any form of
    # network loading. REXML itself never performs network access.
    #
    # @example
    #   conn = Faraday.new(url: 'https://dav.example.com') do |f|
    #     f.response :multistatus
    #     f.adapter Faraday.default_adapter
    #   end
    #   result = conn.propfind('/folder/').body
    #   result['https://dav.example.com/folder/'].properties
    #   # => { "{DAV:}displayname" => "folder", ... }
    class Multistatus < Middleware
      # Matches an HTTP status line like "HTTP/1.1 404 Not Found".
      STATUS_LINE = %r{\A\s*HTTP/\S+\s+(\d{3})}i

      # Bodies containing a DOCTYPE are rejected outright, see class docs.
      FORBIDDEN_MARKUP = /<!DOCTYPE/i

      # Parsed multi-status document: a set of resources keyed by href.
      class Result
        include Enumerable

        # @return [String, nil] top-level <responsedescription>, if any.
        attr_accessor :response_description

        def initialize
          @resources = {}
        end

        # @return [Hash{String => Resource}] resources by absolute href.
        attr_reader :resources

        # Adds a resource, merging it into an existing entry when the same
        # (resolved) href appears more than once in the document: propstats
        # are appended in document order and non-nil error/description
        # values from the later element take precedence.
        def add(resource)
          if (existing = @resources[resource.href])
            existing.merge!(resource)
          else
            @resources[resource.href] = resource
          end
        end

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

      # A single <response> element: one resource and its propstat groups.
      class Resource
        # @return [String] absolute href, resolved against the request URI.
        attr_reader :href

        # @return [Array<Propstat>] propstat groups in document order.
        attr_reader :propstats

        # @return [String, nil] resource-level <error> description, if any.
        attr_accessor :error

        # @return [String, nil] resource-level <responsedescription>, if any.
        attr_accessor :response_description

        def initialize(href)
          @href = href
          @propstats = []
        end

        # Merged view of all properties across propstats, keyed by expanded
        # name. When the same property appears in several propstats, the
        # value from the last propstat in document order wins. Use
        # {#propstats} when per-propstat status matters.
        def properties
          @propstats.each_with_object({}) { |propstat, acc| acc.merge!(propstat.properties) }
        end

        # @api private
        def merge!(other)
          @propstats.concat(other.propstats)
          @error = other.error if other.error
          @response_description = other.response_description if other.response_description
          self
        end
      end

      # A single <propstat> element: a group of properties plus the status
      # (and optional error info) that applies to them.
      class Propstat
        # @return [Hash{String => String, nil}] properties by expanded name.
        attr_reader :properties

        # @return [String, nil] raw status line, e.g. "HTTP/1.1 200 OK".
        attr_reader :status

        # @return [String, nil] <error> description for this propstat.
        attr_reader :error

        # @return [String, nil] <responsedescription> for this propstat.
        attr_reader :response_description

        def initialize(properties:, status: nil, error: nil, response_description: nil)
          @properties = properties
          @status = status
          @error = error
          @response_description = response_description
        end

        # @return [Integer, nil] numeric status code from the status line.
        def status_code
          match = STATUS_LINE.match(@status.to_s)
          match && match[1].to_i
        end
      end

      def initialize(app = nil, content_type: /\bxml$/, statuses: [207], preserve_raw: false)
        super(app)
        @content_types = Array(content_type)
        @statuses = Array(statuses).map(&:to_i)
        @preserve_raw = preserve_raw
      end

      def on_complete(env)
        process_response(env) if parse_response?(env)
      end

      private

      def process_response(env)
        env[:raw_body] = env[:body] if @preserve_raw
        env[:body] = parse(env[:body], env[:url])
      rescue REXML::ParseException, URI::InvalidURIError => e
        raise Faraday::ParsingError.new(e, env[:response])
      end

      def parse(body, request_url)
        return if body.strip.empty?

        if FORBIDDEN_MARKUP.match?(body)
          raise Faraday::ParsingError.new(
            'DOCTYPE declarations are not allowed in multi-status bodies', nil
          )
        end

        document = REXML::Document.new(body, ignore_whitespace_nodes: :all)
        parse_multistatus(document.root, request_url)
      end

      def parse_multistatus(root, request_url)
        unless root && root.name == 'multistatus'
          raise REXML::ParseException.new('multi-status body must have a <multistatus> root element')
        end

        Result.new.tap do |result|
          root.elements.each do |element|
            case element.name
            when 'response'
              result.add(parse_response_element(element, request_url))
            when 'responsedescription'
              result.response_description = element_text(element)
            end
          end
        end
      end

      def parse_response_element(element, request_url)
        href_element = element.elements.find { |child| child.name == 'href' }
        resource = Resource.new(resolve_href(href_element && element_text(href_element), request_url))

        element.elements.each do |child|
          case child.name
          when 'propstat'
            resource.propstats << parse_propstat(child)
          when 'error'
            resource.error = element_text(child)
          when 'responsedescription'
            resource.response_description = element_text(child)
          end
        end

        resource
      end

      def parse_propstat(element)
        properties = {}
        status = error = response_description = nil

        element.elements.each do |child|
          case child.name
          when 'prop'
            child.elements.each { |prop| properties[expanded_name(prop)] = property_value(prop) }
          when 'status'
            status = element_text(child)
          when 'error'
            error = element_text(child)
          when 'responsedescription'
            response_description = element_text(child)
          end
        end

        Propstat.new(properties: properties, status: status, error: error,
                     response_description: response_description)
      end

      # Clark notation: "{namespace-uri}local". Properties without a
      # namespace keep their bare local name.
      def expanded_name(element)
        namespace = element.namespace
        namespace.empty? ? element.name : "{#{namespace}}#{element.name}"
      end

      # Relative hrefs are resolved against the request URI; absolute hrefs
      # (with or without scheme) are kept as-is.
      def resolve_href(href, request_url)
        return if href.nil?

        base = request_url && URI.parse(request_url.to_s)
        base ? URI.join(base.to_s, href).to_s : href
      end

      def property_value(element)
        element.has_text? ? element.texts.map(&:value).join : nil
      end

      def element_text(element)
        element.has_text? ? element.texts.map(&:value).join.strip : nil
      end

      def parse_response?(env)
        @statuses.include?(env[:status].to_i) &&
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
