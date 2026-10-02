# frozen_string_literal: true

require "strscan"

#
class Roda
  module RodaPlugins
    # The link_headers plugin allows Link headers to be built and modified
    # using a structured interface instead of manually joining values:
    #
    #   response.link '/items?page=3', rel: :next
    #   response.link '/items?page=1', rel: :prev
    #   # Link: </items?page=3>; rel="next", </items?page=1>; rel="prev"
    #
    # Multiple relations and extension parameters can be supplied:
    #
    #   response.link "/items?q=a,b", rel: [:next, :last], title: "Items, \"new\""
    #
    # Existing Link header values are parsed before being modified.  Links with
    # the same URI, relation set, and parameters are merged, while links to the
    # same URI with different relations remain separate entries.  Parameters
    # that the plugin does not interpret are retained.
    module LinkHeaders
      PARAMETER_NAME = %r{\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z}.freeze
      PARAMETER_NAME_TOKEN = %r{[!#$%&'*+.^_`|~0-9A-Za-z-]+}.freeze
      TOKEN = %r{\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z}.freeze
      URI_REFERENCE = %r{\A[A-Za-z0-9!$&'()*+,;=:/?@\[\]_~.#%-]+\z}.freeze
      private_constant :PARAMETER_NAME, :PARAMETER_NAME_TOKEN, :TOKEN, :URI_REFERENCE

      # Represents a single Link header value.
      class Link
        attr_reader :uri, :parameters

        def initialize(uri, parameters)
          @uri = uri
          @parameters = parameters
        end

        def rel
          value = parameter("rel")
          value ? value.split(" ") : []
        end

        def parameter(name)
          if parameter = @parameters.find{|key, _| key.downcase == name}
            parameter[1]
          end
        end

        def eql?(other)
          other.is_a?(Link) && uri == other.uri && semantic_parameters == other.semantic_parameters
        end
        alias_method :==, :eql?

        def hash
          [uri, semantic_parameters].hash
        end

        def to_str
          validate_uri!(@uri)
          s = String.new("<") << @uri << ">"
          @parameters.each do |name, value|
            s << "; " << name
            append_parameter_value(s, name, value) unless value.nil?
          end
          s
        end
        alias_method :to_s, :to_str

        protected

        def semantic_rel
          parameter("rel").to_s.split(" ").map do |relation|
            relation_extension?(relation) ? relation : relation.downcase
          end.sort.join(" ")
        end

        def semantic_parameters
          @parameters.map do |name, value|
            value = semantic_rel if name.downcase == "rel"
            [name.downcase, value.nil? ? nil : value.to_s]
          end.sort
        end

        def append_parameter_value(s, name, value)
          value = value.to_s
          reject_header_newlines!(value)
          s << "="

          if name.downcase == "rel"
            s << '"' << value << '"'
          elsif name.end_with?("*") || value =~ TOKEN
            s << value
          else
            s << '"' << value.gsub('\\', '\\\\\\\\').gsub('"', '\\"') << '"'
          end
        end

        def validate_uri!(uri)
          reject_header_newlines!(uri)
          unless uri =~ URI_REFERENCE
            raise RodaError, "invalid Link URI used: #{uri.inspect}"
          end
        end

        def reject_header_newlines!(value)
          if /[\x00\r\n]/ =~ value
            raise RodaError, "invalid newline in Link header value"
          end
        end

        def relation_extension?(relation)
          relation.to_s.include?(":") || relation.to_s.start_with?("/")
        end
        private :relation_extension?
      end

      # Represents the complete Link header for a response.
      class Header
        def initialize
          @links = []
        end

        def self.parse(value)
          header = new
          header.send(:parse, value)
          header
        end

        def add(uri, options)
          options = options.dup
          rel = options.delete(:rel)
          rel = Array(rel).flatten.map(&:to_s)
          raise RodaError, "Link header entry requires a rel parameter" if rel.empty?

          parameters = [["rel", rel.join(" ")]]
          options.each do |name, value|
            next if value == false
            name = name.to_s
            raise RodaError, "invalid Link parameter name used: #{name.inspect}" unless name =~ PARAMETER_NAME
            if value == true
              parameters << [name, nil]
            else
              value = value.to_s
              reject_header_newlines!(value)
              if name.end_with?("*") && value !~ TOKEN
                raise RodaError, "invalid extended Link parameter used: #{name}=#{value.inspect}"
              end
              parameters << [name, value]
            end
          end

          link = Link.new(uri.to_s, parameters)
          link.rel.each {|relation| reject_header_newlines!(relation)}

          if existing = @links.find{|entry| entry.eql?(link)}
            merge_relations!(existing, link)
          else
            @links << link
          end
          self
        end

        def delete(uri = nil, options=OPTS)
          relations = options[:rel] ? Array(options[:rel]).flatten.map(&:to_s) : nil

          @links.reject! do |link|
            next false if uri && link.uri != uri

            if relations
              next false unless link.parameters.assoc("rel")
              remove_relations!(link, relations)
              link.rel.empty?
            else
              true
            end
          end
          self
        end

        def to_str
          @links.map(&:to_s).join(", ")
        end
        alias_method :to_s, :to_str

        private

        def parse(value)
          value = Array(value)
          value.each do |header_value|
            parse_header(header_value.to_s)
          end
        end

        def parse_header(value)
          reject_header_newlines!(value)
          split_links(value).each {|part| parse_link(part)}
        end

        def split_links(value)
          links = []
          start = 0
          depth = 0
          quote = false
          escaped = false

          value.each_char.with_index do |char, index|
            if quote
              if escaped
                escaped = false
              elsif char == '\\'
                escaped = true
              elsif char == '"'
                quote = false
              end
            elsif char == '"'
              quote = true
            elsif char == '<'
              depth += 1
            elsif char == '>'
              depth -= 1 if depth > 0
            elsif char == ',' && depth == 0
              links << value[start...index]
              start = index + 1
            end
          end

          links << value[start..-1]
          links
        end

        def parse_link(value)
          scanner = StringScanner.new(value)
          scanner.skip(/[\t ]*/)
          scanner.scan(/</) or invalid_link!(value)
          uri = scanner.scan_until(/(?=>)/) or invalid_link!(value)
          scanner.get_byte or invalid_link!(value)
          validate_uri!(uri)

          parameters = []
          loop do
            scanner.skip(/[\t ]*/)
            break if scanner.eos?
            scanner.scan(/;/) or invalid_link!(value)
            scanner.skip(/[\t ]*/)
            name = scanner.scan(PARAMETER_NAME_TOKEN) or invalid_link!(value)

            if scanner.scan(/[\t ]*=[\t ]*/)
              parameters << [name, parse_parameter_value(scanner, value)]
            else
              parameters << [name, nil]
            end
          end

          @links << Link.new(uri, parameters)
        end

        def parse_parameter_value(scanner, value)
          if scanner.scan(/"/)
            quoted = scanner.scan(/(?:\\.|[^\\"])*"/m)
            invalid_link!(value) unless quoted
            quoted[0...-1].gsub(/\\(.)/m, '\\1')
          else
            token = scanner.scan(PARAMETER_NAME_TOKEN)
            invalid_link!(value) if token.nil? || token.empty?
            invalid_link!(value) unless scanner.eos? || scanner.scan(/[\t ]*(?=;|,|\z)/)
            token
          end
        end

        def merge_relations!(existing, new_link)
          relations = existing.rel
          new_link.rel.each do |relation|
            relations << relation unless relations.any?{|existing_relation| same_relation?(existing_relation, relation)}
          end
          existing.parameters.assoc("rel")[1] = relations.join(" ")
        end

        def remove_relations!(link, relations)
          rel_parameter = link.parameters.assoc("rel")
          return unless rel_parameter

          remaining = link.rel.reject do |relation|
            relations.any?{|wanted| same_relation?(relation, wanted)}
          end
          rel_parameter[1] = remaining.join(" ")
        end

        def same_relation?(left, right)
          left == right || (!relation_extension?(left) && !relation_extension?(right) && left.downcase == right.downcase)
        end

        def relation_extension?(relation)
          relation.include?(":") || relation.start_with?("/")
        end

        def validate_uri!(uri)
          reject_header_newlines!(uri)
          unless uri =~ URI_REFERENCE
            raise RodaError, "invalid Link header URI: #{uri.inspect}"
          end
        end

        def reject_header_newlines!(value)
          if /[\x00\r\n]/ =~ value
            raise RodaError, "invalid newline in Link header"
          end
        end

        def invalid_link!(value)
          raise RodaError, "invalid Link header value: #{value.inspect}"
        end
      end

      module ResponseMethods
        # Return the structured Link header, initially populated from any Link
        # response header already present.
        def link_headers
          value = @headers[RodaResponseHeaders::LINK]
          if @link_headers.nil? || value != @link_headers.to_s
            @link_headers = value ? Header.parse(value) : Header.new
          end
          @link_headers
        end
        alias_method :links, :link_headers

        # Add a Link header entry for the given URI.
        def link(uri, *args, **options)
          options = args[0].dup if args[0].is_a?(Hash)
          link_headers.add(uri, options)
          set_link_header
          nil
        end

        # Remove Link header entries, optionally restricted by URI and/or relation.
        def delete_link(uri=nil, *args, **options)
          options = args[0] if args[0].is_a?(Hash)
          link_headers.delete(uri, {:rel => options[:rel]})
          set_link_header
          nil
        end

        def finish
          res = super
          write_link_header
          res
        end

        def finish_with_body(body)
          res = super
          write_link_header
          res
        end

        private

        def set_link_header
          value = @link_headers.to_s
          if value.empty?
            @headers.delete(RodaResponseHeaders::LINK)
          else
            @headers[RodaResponseHeaders::LINK] = value
          end
        end

        def write_link_header
          value = @headers[RodaResponseHeaders::LINK]
          if value
            @headers[RodaResponseHeaders::LINK] = Header.parse(value).to_s
          end
        end
      end
    end

    register_plugin(:link_headers, LinkHeaders)
  end
end
