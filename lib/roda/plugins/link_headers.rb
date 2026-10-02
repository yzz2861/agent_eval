# frozen-string-literal: true

require 'strscan'
require 'uri'

#
class Roda
  module RodaPlugins
    # The link_headers plugin provides a structured interface for building Link
    # response headers.  It handles URI and quoted parameter encoding, parses
    # existing Link headers so they can be modified, and supports multiple link
    # relations and extension parameters.
    #
    #   plugin :link_headers
    #
    #   route do |r|
    #     link_headers.add '/items?page=3', rel: :next
    #     link_headers.add '/items?page=1', rel: :prev
    #     link_headers.add '/docs', rel: :describedby, title: 'Item documentation'
    #   end
    #
    # A link can have multiple relations:
    #
    #   link_headers.add '/alternate', rel: [:next, :prev]
    #
    # Extension parameters are passed as additional keyword arguments.  Arrays
    # produce repeated parameters, and +true+ produces a valueless parameter:
    #
    #   link_headers.add '/a', rel: :chapter, anchor: '#section', hreflang: ['en', 'fr']
    #   link_headers.add '/b', rel: :preload, as: 'script'
    #   link_headers.add '/c', rel: :describedby, 'title*': "UTF-8'en'%C3%A9"
    #
    # Existing Link values are parsed when the builder is first used.  Unknown
    # extension parameters are retained.  Links are only merged when both the
    # target URI and complete relation set are the same; the same URI used with
    # different relations remains separate.
    #
    # Use #delete to remove links:
    #
    #   link_headers.delete rel: :next
    #   link_headers.delete '/items?page=1', rel: :prev
    #   link_headers.delete '/items'
    #   link_headers.delete
    module LinkHeaders
      RESPONSE_INSTANCE_VARIABLES = [:@link_headers].freeze

      # Represents the collection of link values in a Link header.
      class Builder
        TOKEN = /[!#$%&'*+\-.^_`|~0-9A-Za-z]+/.freeze
        URI_UNSAFE = /[^A-Za-z0-9\-._~!$&'()*+,;=:@\/?\[\]%]/.freeze
        URI_PARSER = defined?(URI::RFC2396_PARSER) ? URI::RFC2396_PARSER : URI::DEFAULT_PARSER
        NO_VALUE = Object.new.freeze

        # The parsed link entries, in header order.
        attr_reader :entries

        def initialize(header_value=nil)
          @entries = []
          Array(header_value).each do |value|
            value = value.to_s
            validate_header_value!(value)
            parse(value) unless value.empty?
          end
        end

        # Add a link for the given URI and relation(s).  Additional keyword
        # arguments are serialized as link parameters.
        def add(uri, rel:, **parameters)
          uri = encode_uri(uri)
          rels = normalize_rels(rel)
          attributes = parameters.map do |name, value|
            name = parameter_name(name)
            Array(value).map do |item|
              raise_invalid_link!("invalid Link parameter value for #{name}: #{item.inspect}") unless valid_parameter_value?(item)
              value = item.equal?(true) ? NO_VALUE : item.to_s
              validate_header_value!(value) unless value.equal?(NO_VALUE)
              quoted = !(name.end_with?('*') && !value.equal?(NO_VALUE) && /\A#{TOKEN.source}\z/.match?(value))
              Entry::Attribute.new(name, value, quoted)
            end
          end.flatten

          replace_attributes!(uri, rels, attributes)
          nil
        end

        # Delete links by relation, URI, or both.  With no arguments, all links
        # are deleted.  When deleting relations from a multi-relation link, only
        # the requested relations are removed.
        def delete(uri=nil, rel: nil)
          if uri.nil? && rel.nil?
            @entries.clear
            return nil
          end

          uri = encode_uri(uri) unless uri.nil?
          rels = rel.nil? ? nil : normalize_rels(rel)

          @entries.each do |entry|
            next unless uri.nil? || entry.uri == uri

            if rels
              next if entry.rels.empty?
              next unless rels.all? { |relation| entry.rels.include?(relation) }
              entry.rels.delete_if { |relation| rels.include?(relation) }
            else
              entry.rels.clear
              entry.attributes.clear
            end
          end

          @entries.reject! { |entry| entry.rels.empty? && entry.attributes.empty? }
          merge_duplicate_entries!
          nil
        end

        # Return the serialized Link header value.
        def header_value
          @entries.map(&:to_s).join(', ')
        end
        alias to_s header_value

        private

        def parse(value)
          scanner = StringScanner.new(value)

          until scanner.eos?
            unless scanner.pos.zero?
              skip_ows(scanner)
              raise_invalid_link!('missing comma between Link values') unless scanner.skip(/,/)
            end

            skip_ows(scanner)
            raise_invalid_link!('missing Link URI') unless scanner.skip(/</)

            uri = scanner.scan(/[^>]+/)
            raise_invalid_link!('missing closing > for Link URI') unless uri && scanner.get_byte == '>'

            rels = []
            attributes = []

            loop do
              skip_ows(scanner)
              break if scanner.eos?

              if scanner.skip(/,/)
                scanner.unscan
                break
              end

              raise_invalid_link!('missing semicolon before Link parameter') unless scanner.skip(/;/)
              skip_ows(scanner)
              name = scanner.scan(TOKEN)
              raise_invalid_link!('invalid Link parameter name') unless name

              if scanner.skip(/=/)
                if scanner.skip(/"/)
                  attribute_value = scan_quoted_string(scanner)
                  quoted = true
                else
                  attribute_value = scanner.scan(TOKEN)
                  quoted = false
                  raise_invalid_link!("invalid Link parameter value for #{name}") unless attribute_value
                end
              else
                attribute_value = NO_VALUE
                quoted = false
              end

              if name.downcase == 'rel'
                raise_invalid_link!('Link rel parameter requires a quoted or token value') if attribute_value.equal?(NO_VALUE)
                raise_invalid_link!('Link rel parameter cannot be repeated') unless rels.empty?
                rels = normalize_rels(attribute_value)
              else
                attributes << Entry::Attribute.new(name, attribute_value, quoted)
              end
            end

            add_parsed_entry(uri, rels, attributes)
          end
        end

        def add_parsed_entry(uri, rels, attributes)
          uri = encode_uri(uri)
          entry = @entries.find { |existing| same_link?(existing, uri, rels) }

          if entry
            entry.attributes.concat(attributes)
          else
            @entries << Entry.new(uri, rels, attributes)
          end
        end

        def merge_duplicate_entries!
          merged = []
          @entries.each do |entry|
            existing = merged.find { |candidate| same_link?(candidate, entry.uri, entry.rels) }
            if existing
              existing.attributes.concat(entry.attributes)
            else
              merged << entry
            end
          end
          @entries = merged
        end

        def replace_attributes!(uri, rels, attributes)
          names = attributes.map { |attribute| attribute.name.downcase }
          entry = @entries.find { |existing| same_link?(existing, uri, rels) }

          if entry
            entry.attributes.reject! { |attribute| names.include?(attribute.name.downcase) }
            entry.attributes.concat(attributes)
          else
            @entries << Entry.new(uri, rels, attributes)
          end
        end

        def same_link?(entry, uri, rels)
          entry.uri == uri && entry.rels.sort == rels.sort
        end

        def normalize_rels(value)
          rels = Array(value).flat_map { |item| item.to_s.split(/[ \t]+/) }
          rels.each { |rel| validate_header_value!(rel) }
          rels.reject!(&:empty?)
          raise_invalid_link!('Link rel is required') if rels.empty?
          rels.map(&:downcase).uniq
        end

        def parameter_name(name)
          name = name.to_s
          raise_invalid_link!("invalid Link parameter name: #{name.inspect}") unless /\A#{TOKEN.source}\z/.match?(name)
          name
        end

        def valid_parameter_value?(value)
          case value
          when true, false, nil, Symbol, String, Numeric
            !value.nil? && value != false
          else
            false
          end
        end

        def scan_quoted_string(scanner)
          value = String.new

          until scanner.eos?
            if scanner.skip(/"/)
              return value
            elsif scanner.skip(/\\/)
              character = scanner.getch
              raise_invalid_link!('invalid quoted string escape') unless character
              value << character
            else
              chunk = scanner.scan(/[^\x00-\x1f\x7f"\\]+/)
              raise_invalid_link!('unterminated quoted string') unless chunk
              value << chunk
            end
          end

          raise_invalid_link!('unterminated quoted string')
        end

        def skip_ows(scanner)
          scanner.skip(/[ \t]*/)
        end

        def encode_uri(uri)
          uri = uri.to_s
          validate_header_value!(uri)
          encoded = URI_PARSER.escape(uri, URI_UNSAFE)
          URI.parse(encoded)
          encoded
        rescue URI::InvalidURIError
          raise_invalid_link!("invalid Link URI: #{uri.inspect}")
        end

        def validate_header_value!(value)
          raise_invalid_link!('Link header values cannot contain carriage returns or line feeds') if /[\r\n\0]/.match?(value)
        end

        def raise_invalid_link!(message)
          raise RodaError, message
        end

        # Represents one link-value and its target attributes.
        class Entry
          attr_accessor :uri, :rels, :attributes

          def initialize(uri, rels, attributes)
            @uri = uri
            @rels = rels
            @attributes = attributes
          end

          def to_s
            value = String.new("<#{uri}>")
            value << '; rel=' << quoted(rels.join(' ')) unless rels.empty?
            attributes.each { |attribute| value << '; ' << attribute.to_s }
            value
          end

          private

          def quoted(value)
            '"' + value.gsub('\\', '\\\\').gsub('"', '\\"') + '"'
          end

          # Represents one parsed or supplied link parameter.
          class Attribute
            NO_VALUE = Builder::NO_VALUE

            attr_reader :name, :value, :quoted

            def initialize(name, value, quoted)
              @name = name
              @value = value
              @quoted = quoted
            end

            def to_s
              return name if value.equal?(NO_VALUE)
              return "#{name}=#{value}" unless quoted
              escaped = value.gsub('\\', '\\\\').gsub('"', '\\"')
              %(#{name}="#{escaped}")
            end
          end
        end
      end

      module InstanceMethods
        # Return the response's Link header builder, yielding it if a block is
        # given.
        def link_headers
          builder = @_response.link_headers
          yield builder if defined?(yield)
          builder
        end
      end

      module ResponseMethods
        def initialize
          super
          @link_headers &&= nil
        end

        # Return the structured builder for this response's Link header.
        def link_headers
          @link_headers ||= Builder.new(headers[RodaResponseHeaders::LINK])
        end

        private

        def set_default_headers
          super

          if @link_headers
            value = @link_headers.header_value
            if value.empty?
              headers.delete(RodaResponseHeaders::LINK)
            else
              headers[RodaResponseHeaders::LINK] = value
            end
          elsif (value = headers[RodaResponseHeaders::LINK])
            Array(value).each do |header_value|
              raise RodaError, 'Link header values cannot contain carriage returns or line feeds' if /[\r\n\0]/.match?(header_value.to_s)
            end
          end
        end
      end
    end

    register_plugin(:link_headers, LinkHeaders)
  end
end
