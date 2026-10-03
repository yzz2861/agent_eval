# frozen_string_literal: true

module Net
  class IMAP
    # See https://www.rfc-editor.org/rfc/rfc9051#section-2.2.2
    class ResponseReader # :nodoc:
      include NumValidator

      LITERAL_CHUNK_SIZE = 64 << 10

      attr_reader :client
      attr_accessor :literal_receiver

      def initialize(client, sock, parser: ResponseParser.new(config: client.config))
        @client, @sock, @parser = client, sock, parser
        @literal_receiver = nil
        # cached config
        @max_response_size = nil
        # response buffer state
        @buff = nil
        @literal_size = nil
        @streamed_bytes = nil
      end

      def read_response
        unless literal_receiver
          buffer = read_response_buffer
          return nil if buffer.empty?
          return @parser.parse(buffer)
        end
        @max_response_size = client.max_response_size
        @buff = String.new.b
        @literal_size = nil
        @streamed_bytes = 0
        response = nil
        pending_error = nil
        fiber_resume = nil
        catch :eof do
          read_line
          fiber = Fiber.new do
            @parser.parse(buff) {|metadata| Fiber.yield(metadata) }
          end
          while true
            guard_response_too_large!
            event = fiber.resume(fiber_resume)
            fiber_resume = nil
            unless fiber.alive?
              response = event
              break
            end
            begin
              event = {**event, response: event[:response]&.dup}
              destination = offer_literal(event)
            rescue StandardError => error
              pending_error = error
            end
            if destination
              stream_error = stream_literal(event[:bytesize], destination)
              pending_error ||= stream_error
              fiber_resume = destination
            else
              read_literal
            end
            read_line
          end
        end
        raise pending_error if pending_error
        response
      ensure
        @buff = nil
        @literal_size = nil
        @streamed_bytes = nil
      end

      def read_response_buffer
        @max_response_size = client.max_response_size
        @buff = String.new
        catch :eof do
          while true
            guard_response_too_large!
            read_line
            # check before allocating memory for literal
            guard_response_too_large!
            break unless literal_size
            read_literal
          end
        end
        buff
      ensure
        @buff = @literal_size = nil
      end

      private

      # cached config
      attr_reader :max_response_size

      # response buffer state
      attr_reader :buff, :literal_size, :streamed_bytes

      def bytes_read = buff.bytesize + streamed_bytes.to_i
      def empty?     = buff.empty? && streamed_bytes.to_i.zero?
      def done?      = line_done? && !literal_size
      def line_done? = buff.end_with?(CRLF)

      def get_literal_size(buff)
        buff.end_with?("}\r\n") && buff.rindex(/\{(\d+)\}\r\n\z/n) &&
          coerce_number64($1)
      rescue DataFormatError
        raise DataFormatError, format("invalid response literal size (%s)", $1)
      end

      def read_line
        limit = max_response_remaining
        limit = 1 if limit && limit <= 0
        line = +"".b
        until line.end_with?(CRLF)
          chunk = (@sock.gets(CRLF, limit) or throw :eof)
          throw :eof if chunk.empty?
          buff << chunk
          line << chunk
          limit -= chunk.bytesize if limit
          limit = 1 if limit&.zero?
          guard_response_too_large!
        end
        @literal_size = get_literal_size(line)
      end

      def read_literal
        literal = String.new(capacity: literal_size)
        buff << (@sock.read(literal_size, literal) or throw :eof)
      ensure
        @literal_size = nil
      end

      def offer_literal(metadata)
        return unless literal_receiver
        return unless metadata.is_a?(Hash) && metadata[:response]
        literal_receiver.call(**metadata)
      end

      def stream_literal(bytesize, destination)
        remaining = bytesize
        error = nil
        begin
          while remaining.positive?
            chunk = String.new.b
            read_chunk(literal_read_limit(remaining), chunk) or throw :eof
            remaining -= chunk.bytesize
            @streamed_bytes += chunk.bytesize
            destination.write(chunk)
          end
        rescue StandardError => error
          discard_literal(remaining)
        end
        error
      ensure
        @literal_size = nil
      end

      def discard_literal(bytesize)
        while bytesize.positive?
          chunk = String.new.b
          limit = [LITERAL_CHUNK_SIZE, bytesize].min
          read_chunk(limit, chunk) or throw :eof
          bytesize -= chunk.bytesize
        end
      end

      def read_chunk(limit, chunk)
        @sock.readpartial(limit, chunk)
      rescue NoMethodError, NotImplementedError
        @sock.read(limit, chunk)
      end

      def literal_read_limit(bytesize)
        limit = [LITERAL_CHUNK_SIZE, bytesize].min
        return limit unless max_response_size
        remaining = max_response_remaining
        if bytesize > remaining
          raise ResponseTooLargeError.new(
            max_response_size:, bytes_read:, literal_size: bytesize,
          )
        end
        [limit, remaining].min
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
