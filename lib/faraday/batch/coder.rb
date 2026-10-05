# frozen_string_literal: true

module Faraday
  module Batch
    # Stateless multipart/mixed encoder and decoder.
    #
    # The encoder emits binary-safe multipart messages and verifies that the
    # chosen boundary does not collide with any sub-body. The decoder parses
    # at the byte level, so sub-bodies (including binary payloads) survive a
    # round-trip unchanged.
    module Coder
      module_function

      # Encodes sub-requests into a multipart/mixed message.
      #
      # @param parts [Array<Part, Hash>] Sub-requests, in order.
      # @param boundary [String, nil] Explicit boundary; a collision-free one
      #   is generated when omitted.
      # @return [EncodedBatch]
      # @raise [InvalidPartError] if a part lacks a method or target.
      # @raise [DuplicateContentIdError] if Content-IDs repeat.
      # @raise [BoundaryCollisionError] if an explicit boundary collides.
      def encode_request(parts, boundary: nil)
        parts = coerce_parts(parts)
        if parts.empty?
          raise InvalidPartError, 'cannot encode an empty batch of parts'
        end
        validate_request_parts!(parts)
        ids = parts.map(&:content_id)
        reject_duplicate_ids!(ids)

        sections = parts.map { |part| encode_request_part(part) }
        body, chosen_boundary = assemble(sections, boundary)
        EncodedBatch.new(body, chosen_boundary,
                         content_type_for(chosen_boundary), ids)
      end

      # Encodes sub-responses into a multipart/mixed message. This mirrors the
      # upstream service side and is mainly useful in tests with the built-in
      # test adapter.
      #
      # @param results [Array<PartResult, Hash>] Sub-responses, in any order.
      # @param boundary [String, nil] Explicit boundary.
      # @return [EncodedBatch]
      # @raise [DuplicateContentIdError] if Content-IDs repeat.
      def encode_response(results, boundary: nil)
        results = results.map do |result|
          result.is_a?(PartResult) ? result : PartResult.new(
            result.fetch(:content_id), result[:status], result[:headers], result[:body]
          )
        end
        sections = results.map { |result| encode_response_part(result) }
        body, chosen_boundary = assemble(sections, boundary)
        EncodedBatch.new(body, chosen_boundary,
                         content_type_for(chosen_boundary), results.map(&:content_id))
      end

      # Decodes a multipart/mixed batch request, e.g. on the service side or
      # in a test stub.
      #
      # @param body [String] Raw multipart body.
      # @param content_type [String] Outer Content-Type header value.
      # @return [Array<Part>] Decoded sub-requests, in wire order.
      # @raise [MalformedBatchError] if the message is not parseable.
      # @raise [DuplicateContentIdError] if Content-IDs repeat.
      def decode_request(body, content_type)
        boundary = boundary_from_content_type(content_type)
        sections = multipart_sections(binary(body), boundary)
        parts = sections.map { |section| parse_request_section(section) }
        reject_duplicate_ids!(parts.map(&:content_id))
        parts
      end

      # Decodes a multipart/mixed batch response and correlates the parts to
      # the requested Content-IDs. Every requested ID yields a result; IDs
      # missing from the response yield an explicit missing result.
      #
      # @param body [String] Raw multipart body.
      # @param content_type [String] Outer Content-Type header value.
      # @param content_ids [Array<String, Symbol>] Requested IDs, in order.
      # @param outer_status [Integer, nil] Outer response status.
      # @param outer_headers [Hash{String => String}, nil] Outer headers.
      # @return [BatchResult]
      # @raise [MalformedBatchError] if the message is not parseable.
      # @raise [DuplicateContentIdError] if response Content-IDs repeat.
      def decode_response(body, content_type, content_ids,
                          outer_status: nil, outer_headers: nil)
        boundary = boundary_from_content_type(content_type)
        sections = multipart_sections(binary(body), boundary)
        results = sections.map { |section| parse_response_section(section) }
        reject_duplicate_ids!(results.map(&:content_id))

        by_id = results.each_with_object({}) do |result, hash|
          hash[result.content_id] = result
        end

        ordered = Array(content_ids).map(&:to_s).map do |id|
          by_id[id] || PartResult.missing(
            id,
            outer_status: outer_status,
            outer_response: { status: outer_status, headers: outer_headers, body: body }
          )
        end

        BatchResult.new(ordered,
                        outer_status: outer_status,
                        outer_headers: outer_headers,
                        outer_body: body)
      end

      # @return [String] A random unique Content-ID.
      def generate_content_id
        SecureRandom.hex(8)
      end

      # @param body [#to_s, #read, nil] Value to normalize.
      # @return [String, nil] Binary String, or nil.
      def coerce_body(body)
        return nil if body.nil?

        value = body.respond_to?(:read) ? body.read : body
        return nil if value.nil?

        binary(value.to_s)
      end

      # @param status [Integer, nil] Sub-response HTTP status.
      # @param headers [Hash] Sub-response headers.
      # @param body [String] Sub-response body.
      # @return [Faraday::Error, nil] Error for a 4xx/5xx status, nil otherwise.
      def error_for_status(status, headers, body)
        return nil if status.nil? || Faraday::Env::SuccessfulStatuses.include?(status)
        # 3xx responses are neither successful nor 4xx/5xx errors.
        return nil if status < 400

        klass = STATUS_ERRORS[status]
        klass ||= status >= 500 ? Faraday::ServerError : Faraday::ClientError
        klass.new(status: status, headers: headers, body: body)
      end

      # Builds one PartResult per requested ID marked as missing.
      #
      # @param content_ids [Array<String>] Requested IDs.
      # @param outer_status [Integer, nil] Outer response status.
      # @param outer_headers [Hash, nil] Outer response headers.
      # @param outer_body [String, nil] Outer response body.
      # @return [BatchResult]
      def missing_batch(content_ids, outer_status: nil, outer_headers: nil, outer_body: nil)
        outer_response = { status: outer_status, headers: outer_headers, body: outer_body }
        results = Array(content_ids).map(&:to_s).map do |id|
          PartResult.missing(id,
                             outer_status: outer_status,
                             outer_response: outer_response)
        end
        BatchResult.new(results,
                        outer_status: outer_status,
                        outer_headers: outer_headers,
                        outer_body: outer_body)
      end

      # @param content_type [String] Outer Content-Type header value.
      # @return [Boolean] Whether the value is multipart/mixed.
      def multipart?(content_type)
        return false if content_type.nil?

        media_type = content_type.to_s.split(';', 2).first.to_s.strip.downcase
        media_type == MIME_TYPE
      end

      private

      module_function

      def coerce_parts(parts)
        Array(parts).map do |part|
          part.is_a?(Part) ? part : Part.new(**part)
        end
      end

      def validate_request_parts!(parts)
        parts.each do |part|
          if part.method.nil? || part.method.to_s.strip.empty?
            raise InvalidPartError, "batch part #{part.content_id.inspect} is missing a method"
          end
          if part.path.nil? || part.path.to_s.strip.empty?
            raise InvalidPartError, "batch part #{part.content_id.inspect} is missing a target"
          end
        end
      end

      def reject_duplicate_ids!(ids)
        duplicates = ids.group_by(&:to_s).select { |_, group| group.size > 1 }.keys
        return if duplicates.empty?

        raise DuplicateContentIdError,
              "duplicate Content-ID(s) in batch: #{duplicates.join(', ')}"
      end

      def content_type_for(boundary)
        %(#{MIME_TYPE}; boundary="#{boundary}")
      end

      def generate_boundary
        BOUNDARY_PREFIX + SecureRandom.hex(8)
      end

      # One +[outer_headers, inner_message]+ pair per part, where the inner
      # message already includes its trailing CRLF required by multipart.
      def assemble(sections, explicit_boundary)
        if explicit_boundary
          validate_boundary!(explicit_boundary)
          body = build_body(sections, explicit_boundary)
          verify_boundary!(body, explicit_boundary, sections)
          return [body, explicit_boundary]
        end

        DEFAULT_BOUNDARY_RETRIES.times do
          boundary = generate_boundary
          body = build_body(sections, boundary)
          if safe_boundary?(body, boundary, sections)
            return [body, boundary]
          end
        end

        raise BoundaryCollisionError,
              'could not generate a boundary that does not collide with the part bodies'
      end

      def validate_boundary!(boundary)
        return if boundary.is_a?(String) && !boundary.empty? &&
                  boundary.length <= 69 && boundary.match?(BOUNDARY_VALUE)

        raise BoundaryCollisionError, "invalid multipart boundary: #{boundary.inspect}"
      end

      def safe_boundary?(body, boundary, sections)
        parsed = multipart_sections(body, boundary)
        return false unless delimiter_occurrences(body, boundary) == sections.size + 1

        parsed.size == sections.size &&
          parsed == sections.map { |headers, inner| serialize_section(headers, inner) }
      rescue MalformedBatchError
        false
      end

      # Counts delimiter lines placed at the body start or directly after a
      # CRLF. A sub-body that embeds a complete delimiter line also satisfies
      # that shape and therefore invalidates the boundary.
      def delimiter_occurrences(body, boundary)
        data = binary(body)
        marker = (DASHES + boundary).b
        count = 0
        offset = 0
        while (index = data.index(marker, offset))
          offset = index + marker.bytesize
          at_start = index.zero?
          preceded_by_crlf = !at_start &&
                              data.byteslice(index - CRLF.bytesize, CRLF.bytesize) == CRLF
          after = index + marker.bytesize
          next_byte = data.getbyte(after)
          part_delimited = data.byteslice(after, CRLF.bytesize) == CRLF
          closing_delimited = data.byteslice(after, 2 + CRLF.bytesize) == DASHES + CRLF
          # A boundary char right after the marker means this is only a
          # prefix of a longer delimiter, not a delimiter itself.
          followed = (part_delimited || closing_delimited) &&
                     (next_byte == 0x0D || next_byte == 0x2D)
          count += 1 if (at_start || preceded_by_crlf) && followed
        end
        count
      end

      def verify_boundary!(body, boundary, sections)
        return if safe_boundary?(body, boundary, sections)

        raise BoundaryCollisionError,
              "multipart boundary #{boundary.inspect} collides with a part body"
      end

      def serialize_section(outer_headers, inner)
        section = +''.b
        outer_headers.each { |name, value| section << name << ': ' << value << CRLF }
        section << CRLF
        section << inner
        section << CRLF
        section
      end

      def build_body(sections, boundary)
        output = +''.b
        sections.each do |outer_headers, inner_message|
          output << DASHES << boundary << CRLF
          outer_headers.each { |name, value| output << name << ': ' << value << CRLF }
          output << CRLF
          output << inner_message
          output << CRLF
        end
        output << DASHES << boundary << DASHES << CRLF
      end

      def encode_request_part(part)
        body = part.encoded_body
        headers = Faraday::Utils::Headers.new
        part.headers.each { |name, value| headers[name] = value unless part_managed_header?(name) }
        headers[CONTENT_LENGTH] ||= (body || +'').bytesize.to_s

        request_line = "#{part.method.to_s.upcase} #{part.path} #{HTTP_VERSION}"
        inner = build_http_message(request_line, headers, body)
        outer_headers = {
          CONTENT_TYPE => HTTP_MIME_TYPE,
          CONTENT_ID => cid_header_value(part.content_id)
        }
        [outer_headers, inner]
      end

      def encode_response_part(result)
        headers = Faraday::Utils::Headers.new
        headers.update(result.headers)
        body = binary(result.body || +'')
        headers[CONTENT_LENGTH] ||= body.bytesize.to_s

        reason = HTTP_REASONS[result.status] || 'Reason'
        status_line = "#{HTTP_VERSION} #{result.status} #{reason}"
        inner = build_http_message(status_line, headers, body)
        outer_headers = {
          CONTENT_TYPE => HTTP_MIME_TYPE,
          CONTENT_ID => cid_header_value(result.content_id)
        }
        [outer_headers, inner]
      end

      def part_managed_header?(name)
        name.to_s.downcase == CONTENT_LENGTH.downcase
      end

      def cid_header_value(content_id)
        value = content_id.to_s
        value.start_with?('<') ? value : "<#{value}>"
      end

      # Builds a complete HTTP message (start-line, headers, blank line, body).
      def build_http_message(start_line, headers, body)
        message = +''.b
        message << start_line << CRLF
        headers.each do |name, value|
          message << name.to_s << ': ' << value.to_s << CRLF
        end
        message << CRLF
        message << body if body
        message
      end

      def boundary_from_content_type(content_type)
        header = Faraday::Utils::Headers.new(CONTENT_TYPE => content_type.to_s)
        match = /\bboundary\s*=\s*("([^"]*)"|([^;\s]+))/i.match(header[CONTENT_TYPE].to_s)
        raise MalformedBatchError, 'multipart/mixed message is missing a boundary parameter' unless match

        boundary = binary(match[2] || match[3])
        validate_boundary!(boundary)
        boundary
      end

      # Sequential multipart parser. After each delimiter line it reads the
      # part's outer headers, then skips the inner +application/http+ message
      # by its +Content-Length+ (which the encoder always sets), and finally
      # verifies the transport CRLF and the next delimiter. Working forward
      # this way means sub-bodies may contain any bytes, including complete
      # delimiter lines.
      def multipart_sections(body, boundary)
        data = binary(body)
        delimiter = (DASHES + boundary).b
        sections = []
        offset = find_first_delimiter(data, delimiter)

        loop do
          expect_delimiter_at(data, offset, delimiter) unless sections.empty?
          offset += delimiter.bytesize
          closing, offset = skip_delimiter_suffix(data, offset)
          break if closing

          section, inner_length, _outer_headers = read_section(data, offset, delimiter)
          sections << section
          offset += inner_length
        end

        sections
      end

      def expect_delimiter_at(data, offset, delimiter)
        return if data.byteslice(offset, delimiter.bytesize) == delimiter

        raise MalformedBatchError,
              "expected multipart boundary at byte #{offset}"
      end

      # Locates the first delimiter line. RFC 2046 allows an arbitrary
      # preamble before it; anything past a delimiter embedded in the body is
      # rejected separately through Content-Length framing.
      def find_first_delimiter(data, delimiter)
        index = data.index(delimiter)
        if index.nil?
          raise MalformedBatchError, 'multipart body does not contain the expected boundary'
        end

        after = index + delimiter.bytesize
        valid_line = data.byteslice(after, CRLF.bytesize) == CRLF ||
                     data.byteslice(after, 2 + CRLF.bytesize) == DASHES + CRLF
        unless valid_line
          raise MalformedBatchError, 'multipart body does not contain the expected boundary'
        end

        index
      end

      # @return [Array(Boolean, Integer)] Whether the closing delimiter was
      #   seen and the offset past its suffix (CRLF or +--+ plus CRLF).
      def skip_delimiter_suffix(data, offset)
        if data.byteslice(offset, 2) == DASHES
          expect_fixed(data, offset + 2, CRLF)
          return [true, offset + 2 + CRLF.bytesize]
        end

        [false, offset + CRLF.bytesize].tap do
          expect_fixed(data, offset, CRLF)
        end
      end

      def expect_fixed(data, offset, expected)
        actual = data.byteslice(offset, expected.bytesize)
        return if actual == expected

        raise MalformedBatchError,
              "expected #{expected.inspect} at byte #{offset}, got #{actual.inspect}"
      end

      # Reads one part at +offset+ and returns the section (outer headers plus
      # inner message) together with its byte length.
      def read_section(data, offset, delimiter)
        header_end = data.index(CRLFCRLF, offset)
        raise MalformedBatchError, 'multipart part is missing its header separator' unless header_end

        outer_headers = parse_header_block(data.byteslice(offset, header_end - offset))
        inner_start = header_end + CRLFCRLF.bytesize
        inner_length = inner_message_length(data, inner_start, delimiter)
        section_end = inner_start + inner_length + CRLF.bytesize
        section = data.byteslice(offset, section_end - offset)
        [section, section_end - offset, outer_headers]
      end

      # Returns the byte length of the inner message (headers, blank line and
      # body). Content-Length makes the body boundary unambiguous even when
      # the body contains delimiter lines. When it is missing, the body ends
      # at the transport padding before the next delimiter (bodies cannot
      # contain delimiter lines in that legacy shape).
      def inner_message_length(data, inner_start, delimiter)
        inner_header_end = data.index(CRLFCRLF, inner_start)
        unless inner_header_end
          raise MalformedBatchError, 'inner application/http message is malformed'
        end

        inner_header_block = data.byteslice(inner_start, inner_header_end - inner_start)
        _start_line, inner_header_lines = split_start_line(inner_header_block)
        inner_headers = parse_header_block(inner_header_lines)
        length_value = inner_headers[CONTENT_LENGTH]
        headers_length = (inner_header_end - inner_start) + CRLFCRLF.bytesize
        if length_value
          size = Integer(length_value) rescue nil
          raise MalformedBatchError,
                "invalid Content-Length in inner message: #{length_value.inspect}" if size.nil?

          return headers_length + size
        end

        next_delimiter = data.index(CRLF + delimiter, inner_start + headers_length)
        unless next_delimiter
          raise MalformedBatchError,
                'unterminated inner application/http message without Content-Length'
        end

        next_delimiter - inner_start
      end

      def parse_request_section(section)
        outer_headers, inner = split_section(section)
        content_id = content_id_from_headers(outer_headers)
        start_line, headers, body = parse_http_message(inner)
        method, target = parse_request_line(start_line)
        Part.new(method: method, path: target, headers: headers,
                 body: body.empty? ? nil : body, content_id: content_id)
      end

      def parse_response_section(section)
        outer_headers, inner = split_section(section)
        content_id = content_id_from_headers(outer_headers)
        start_line, headers, body = parse_http_message(inner)
        status = parse_status_line(start_line)
        PartResult.new(content_id, status, headers, body)
      end

      def split_section(section)
        header_block, separator_index = delimited_header_block(section)
        [parse_header_block(header_block),
         section.byteslice(separator_index, section.bytesize - separator_index)]
      end

      # Splits the section payload into the outer header block and the offset
      # of the inner message (at the blank line).
      def delimited_header_block(payload)
        index = payload.index(CRLFCRLF)
        raise MalformedBatchError, 'multipart part is missing its header separator' unless index

        [payload.byteslice(0, index), index + CRLFCRLF.bytesize]
      end

      def parse_header_block(block)
        headers = Faraday::Utils::Headers.new
        block.each_line(CRLF) do |line|
          name, value = line.split(':', 2)
          if name.nil? || value.nil?
            raise MalformedBatchError, "malformed header line: #{line.inspect}"
          end

          headers[name] = value.to_s.strip
        end
        headers
      end

      def content_id_from_headers(headers)
        value = headers[CONTENT_ID]
        raise MalformedBatchError, 'multipart part is missing a Content-ID header' if value.nil?

        value = value.to_s.strip
        value = value[1...-1] if value.start_with?('<') && value.end_with?('>')
        raise MalformedBatchError, 'multipart part has an empty Content-ID header' if value.empty?

        value
      end

      # Returns +[start_line, headers, binary_body]+. With Content-Length the
      # body is sliced byte-exact; without it one trailing transport CRLF is
      # removed.
      def parse_http_message(inner)
        separator_index = inner.index(CRLFCRLF)
        unless separator_index
          raise MalformedBatchError, 'inner application/http message is malformed'
        end

        header_block = inner.byteslice(0, separator_index)
        body_start = separator_index + CRLFCRLF.bytesize
        start_line, header_lines = split_start_line(header_block)
        headers = parse_header_block(header_lines)
        body = inner.byteslice(body_start, inner.bytesize - body_start) || +''.b
        [start_line, headers, trim_inner_body(headers, body)]
      end

      def split_start_line(header_block)
        first_line_end = header_block.index(CRLF)
        if first_line_end
          [header_block.byteslice(0, first_line_end),
           header_block.byteslice(first_line_end + CRLF.bytesize,
                                 header_block.bytesize - first_line_end - CRLF.bytesize)]
        else
          [header_block, +'']
        end
      end

      def trim_inner_body(headers, body)
        length = headers[CONTENT_LENGTH]
        return strip_trailing_crlf(body) if length.nil?

        size = Integer(length) rescue nil
        if size.nil?
          raise MalformedBatchError,
                "invalid Content-Length in inner message: #{length.inspect}"
        end
        raise MalformedBatchError, 'inner message body is shorter than its Content-Length' if size > body.bytesize

        body.byteslice(0, size)
      end

      def strip_trailing_crlf(body)
        body.end_with?(CRLF) ? body.byteslice(0, body.bytesize - CRLF.bytesize) : body
      end

      def parse_request_line(line)
        method, target, version = line.to_s.split(/\s+/, 3)
        if method.nil? || target.nil? || version.nil? || !version.start_with?('HTTP/')
          raise MalformedBatchError, "malformed inner request line: #{line.inspect}"
        end

        [method.downcase.to_sym, target]
      end

      def parse_status_line(line)
        version, raw_status, = String(line).split(/\s+/, 3)
        status = begin
                   Integer(raw_status)
                 rescue ArgumentError, TypeError
                   nil
                 end
        if version.nil? || !version.start_with?('HTTP/') || status.nil?
          raise MalformedBatchError, "malformed inner status line: #{line.inspect}"
        end

        status
      end

      def binary(value)
        value.to_s.dup.force_encoding(Encoding::BINARY)
      end
    end
  end
end
