# frozen_string_literal: true

module URI
  class RFC3987_Parser < RFC3986_Parser
    def split(iri)
      iri = String.try_convert(iri) or
        raise InvalidURIError, "bad URI (is not URI?): #{iri.inspect}"

      binary = iri.b
      validate_percent_escapes(binary)
      ascii = binary.gsub(/[^\x00-\x7f]/n) { |character| 'a' * character.bytesize }
      match = RFC3986_URI.match(ascii) || RFC3986_relative_ref.match(ascii)
      unless match
        raise InvalidURIError, "bad URI (is not URI?): #{iri.inspect}"
      end

      if match.names.include?('path-rootless') && match['path-rootless']
        return [
          capture(iri, match, 'scheme'),
          nil, nil, nil, nil, nil,
          capture(iri, match, 'path-rootless', append_query: true, query: match['query']),
          nil,
          capture(iri, match, 'fragment')
        ]
      end

      [
        capture(iri, match, 'scheme'),
        capture(iri, match, 'userinfo'),
        capture(iri, match, 'host'),
        capture(iri, match, 'port'),
        nil,
        capture(iri, match, 'path-abempty') ||
          capture(iri, match, 'path-absolute') ||
          capture(iri, match, 'path-empty') ||
          capture(iri, match, 'path-noscheme') ||
          '',
        nil,
        capture(iri, match, 'query'),
        capture(iri, match, 'fragment')
      ]
    end

    private

    def capture(iri, match, name, append_query: false, query: nil)
      return nil unless match.names.include?(name) && match.begin(name)
      if append_query && query
        start, = match.byteoffset(name)
        _, finish = match.byteoffset('query')
        value = iri.b.byteslice(start...finish)
      else
        start, finish = match.byteoffset(name)
        value = iri.b.byteslice(start...finish)
      end
      value.force_encoding(Encoding::UTF_8)
    end

    def validate_percent_escapes(iri)
      fragment_start = iri.index('#')
      before_fragment = fragment_start ? iri.byteslice(0, fragment_start) : iri
      query_start = before_fragment.index('?')
      end_of_hier_part = query_start || before_fragment.bytesize
      colon = iri.index(':')
      slash = iri.index('/')
      authority_start = iri.index('//')
      hierarchical = colon.nil? || (slash && slash < colon) ||
        (colon && iri.getbyte(colon + 1) == 0x2F)

      if hierarchical
        path_start = if authority_start
                       iri.index('/', authority_start + 2) || end_of_hier_part
                     elsif colon && iri.getbyte(colon + 1) == 0x2F
                       colon + 1
                     else
                       0
                     end
        validate_component(iri, path_start, end_of_hier_part, :path)
      end

      if query_start
        validate_component(iri, query_start + 1, before_fragment.bytesize, :query)
      end
      if fragment_start
        validate_component(iri, fragment_start + 1, iri.bytesize, :fragment)
      end
    end

    def validate_component(iri, start, finish, component)
      return if start >= finish
      IRI.encode_component(iri.byteslice(start, finish - start), component)
    end
  end
end
