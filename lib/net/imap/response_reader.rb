# frozen_string_literal: true

module Net
  class IMAP
    # See https://www.rfc-editor.org/rfc/rfc9051#section-2.2.2
    class ResponseReader # :nodoc:
      include NumValidator

      READ_CHUNK_SIZE = 4096

      FETCH_PREFIX = /\A\* (\d+) (FETCH|UIDFETCH) \(/n
      LITERAL_HEADER = /\G(?:~)?\{(\d+)\}\r\n/n
      REFERENCE_MARKER = "\0"

      attr_reader :client
      attr_accessor :literal_receiver

      def initialize(client, sock, literal_receiver: nil, &block)
        @client, @sock = client, sock
        @literal_receiver = literal_receiver || block
        @max_response_size = nil
        @buff = @literal_size = nil
        @literal_references = {}
        @receiver_error = nil
      end

      def read_response_buffer
        @max_response_size = client.max_response_size
        @buff = String.new
        @literal_references = {}
        @receiver_error = nil
        references = nil
        catch :eof do
          while true
            guard_response_too_large!
            read_line
            if literal_size
              destination = literal_destination
              guard_response_too_large! unless destination || @receiver_error
              read_literal(destination)
            else
              guard_response_too_large!
              break
            end
          end
        end
        raise @receiver_error if @receiver_error
        references = @literal_references
        buff
      ensure
        @buff = @literal_size = nil
        @receiver_error = nil
        @literal_references = {} unless references
      end

      def consume_literal_references
        references = @literal_references
        @literal_references = {}
        references
      end

      private

      attr_reader :max_response_size
      attr_reader :buff, :literal_size

      def bytes_read          = buff.bytesize
      def empty?              = buff.empty?
      def done?               = line_done? && !literal_size
      def line_done?          = buff.end_with?(CRLF)

      def get_literal_size(buff)
        buff.end_with?("}\r\n") && buff.rindex(/\{(\d+)\}\r\n\z/n) &&
          coerce_number64($1)
      rescue DataFormatError
        raise DataFormatError, format("invalid response literal size (%s)", $1)
      end

      def read_line
        line = (@sock.gets(CRLF, max_response_remaining) or throw :eof)
        @literal_size = get_literal_size(line)
        buff << line
      end

      def read_literal(destination)
        unless destination
          if @receiver_error
            drain_literal
          else
            literal = String.new(capacity: literal_size)
            buff << (@sock.read(literal_size, literal) or throw :eof)
          end
          return
        end

        read_literal_to(destination)
      ensure
        @literal_size = nil
        @literal_field = nil unless destination
      end

      def literal_destination
        return unless literal_receiver
        info = fetch_literal_info or return
        response = fetch_context(info)
        destination = literal_receiver.call(response, info[:field], literal_size)
        return unless destination
        unless destination.respond_to?(:write)
          raise ArgumentError, "literal receiver must respond to #write"
        end
        @literal_field = info[:field]
        destination
      rescue Exception => error
        @receiver_error ||= error
        nil
      end

      def read_literal_to(destination)
        remaining = literal_size
        reference = FetchData::LiteralReference.new(
          field: @literal_field, bytesize: literal_size, receiver: destination,
        )
        chunk = String.new
        begin
          while remaining > 0
            remaining -= copy_literal_chunk(chunk, remaining)
            destination.write(chunk)
          end
        rescue Exception => error
          @receiver_error ||= error
          while remaining > 0
            remaining -= copy_literal_chunk(chunk, remaining)
          end
        end
        marker_pos = buff.bytesize
        unless @receiver_error
          buff << REFERENCE_MARKER
          @literal_references[marker_pos] = reference
        end
      end

      def copy_literal_chunk(chunk, remaining)
        length = [remaining, READ_CHUNK_SIZE].min
        @sock.read(length, chunk) or throw :eof
        chunk.bytesize
      end

      def drain_literal
        remaining = literal_size
        chunk = String.new
        while remaining > 0
          remaining -= copy_literal_chunk(chunk, remaining)
        end
      end

      def fetch_literal_info
        match = FETCH_PREFIX.match(buff) or return
        pos = match.end(0)
        attr = {}
        while pos < buff.bytesize
          pos += 1 while buff.getbyte(pos) == 32
          field_start = pos
          pos = read_field_name(pos)
          field = buff.byteslice(field_start, pos - field_start)&.upcase
          field = field.sub(/\[\]\z/, "") if field&.start_with?("RFC822")
          return if field.nil? || field.empty? || buff.getbyte(pos) != 32
          pos += 1
          value_start = pos
          pos = skip_value(pos)
          if (header = literal_header(value_start))
            return {
              number: Integer(match[1]),
              type: match[2].upcase,
              field: field,
              attr: attr,
            }
          end
          value, value_end = parse_fetch_value(value_start)
          attr[field] = value if value_end == pos
          return unless pos < buff.bytesize
          case buff.getbyte(pos)
          when 32 then pos += 1
          when 41 then return
          else return
          end
        end
      end

      def read_field_name(pos)
        pos = skip_plain_chars(pos)
        if buff.getbyte(pos) == 91
          pos += 1
          pos += 1 while pos < buff.bytesize && buff.getbyte(pos) != 93
          pos += 1 if buff.getbyte(pos) == 93
          pos = skip_plain_chars(pos)
        end
        pos
      end

      def skip_plain_chars(pos)
        while pos < buff.bytesize
          case buff.getbyte(pos)
          when 32, 40, 41, 34, 91, 93, 123 then break
          else pos += 1
          end
        end
        pos
      end

      def skip_value(pos, depth = 0)
        return pos if pos >= buff.bytesize
        byte = buff.getbyte(pos)
        case byte
        when 40
          skip_value(pos + 1, depth + 1)
        when 41
          depth.zero? ? pos : skip_value(pos + 1, depth - 1)
        when 34
          pos = skip_quoted(pos + 1)
          depth.zero? ? pos : skip_value(pos, depth)
        when 123, 126
          pos = skip_literal(pos)
          depth.zero? ? pos : skip_value(pos, depth)
        when 32
          depth.zero? ? pos : skip_value(pos + 1, depth)
        else
          skip_value(pos + 1, depth)
        end
      end

      def skip_quoted(pos)
        while pos < buff.bytesize
          byte = buff.getbyte(pos)
          if byte == 92
            pos += 2
          elsif byte == 34
            return pos + 1
          else
            pos += 1
          end
        end
        pos
      end

      def skip_literal(pos)
        header = literal_header(pos)
        return pos + 1 unless header
        header_end = header.end(0)
        if @literal_references[header_end]
          header_end + 1
        else
          header_end + Integer(header[1])
        end
      end

      def literal_header(pos)
        return unless buff.getbyte(pos) == 123 || buff.getbyte(pos) == 126
        match = buff.match(LITERAL_HEADER, pos)
        match && match.begin(0) == pos ? match : nil
      end

      def fetch_context(info)
        klass = info[:type] == "UIDFETCH" ? UIDFetchData : FetchData
        klass.new(info[:number], info[:attr])
      end

      def parse_fetch_value(pos)
        case buff.getbyte(pos)
        when 40 then parse_fetch_list(pos)
        when 34 then parse_fetch_quoted(pos)
        when 123, 126
          header = literal_header(pos)
          return [nil, pos] unless header
          value = buff.byteslice(header.end(0), Integer(header[1]))
          [value, header.end(0) + Integer(header[1])]
        else
          stop = pos
          stop += 1 while stop < buff.bytesize &&
            ![32, 41].include?(buff.getbyte(stop))
          value = buff.byteslice(pos, stop - pos)
          value = Integer(value, exception: false) || value
          value = nil if value == "NIL"
          [value, stop]
        end
      end

      def parse_fetch_list(pos)
        items = []
        pos += 1
        until pos >= buff.bytesize || buff.getbyte(pos) == 41
          item, pos = parse_fetch_value(pos)
          items << item unless item.nil?
          pos += 1 if buff.getbyte(pos) == 32
        end
        [items, pos + 1]
      end

      def parse_fetch_quoted(pos)
        value_start = pos + 1
        value_end = skip_quoted(value_start)
        value = buff.byteslice(value_start, value_end - value_start - 1)
        [value, value_end]
      end

      def max_response_remaining = max_response_size &.- bytes_read
      def response_too_large?    = max_response_size &.< min_response_size
      def min_response_size      = bytes_read + min_response_remaining

      def min_response_remaining
        empty? ? 3 : done? ? 0 : (literal_size || 0) + 2
      end

      def guard_response_too_large!
        return unless response_too_large?
        raise ResponseTooLargeError.new(
          max_response_size:, bytes_read:, literal_size:,
        )
      end
    end
  end
end
