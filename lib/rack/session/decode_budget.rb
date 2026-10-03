# frozen_string_literal: true

require 'json'
require 'stringio'
require 'zlib'

module Rack
  module Session
    class DecodeBudget
      class Exceeded < StandardError
        attr_reader :reason

        def initialize(reason)
          @reason = reason
          super(reason.to_s)
        end
      end

      def self.coerce(budget)
        case budget
        when nil, DecodeBudget
          budget
        when Hash
          new(**budget)
        else
          raise ArgumentError, 'decode_budget must be a DecodeBudget or Hash'
        end
      end

      attr_reader :max_bytes, :max_depth, :max_nodes, :reason

      def initialize(max_bytes: nil, max_depth: nil, max_nodes: nil)
        @max_bytes = max_bytes
        @max_depth = max_depth
        @max_nodes = max_nodes
        @reason = nil

        validate_integer!(:max_bytes, @max_bytes)
        validate_integer!(:max_depth, @max_depth)
        validate_integer!(:max_nodes, @max_nodes)
      end

      def check_bytesize!(bytesize)
        exceed!(:bytes_exceeded) if @max_bytes && bytesize > @max_bytes
      end

      def check_depth!(depth)
        exceed!(:depth_exceeded) if @max_depth && depth > @max_depth
      end

      def check_nodes!(nodes)
        exceed!(:nodes_exceeded) if @max_nodes && nodes > @max_nodes
      end

      def parse_json(data)
        @reason = nil
        SafeJSONParser.new(StringIO.new(data), self, false).parse!
      end

      def parse_zlib_json(data)
        @reason = nil
        compressed_data, expected_checksum = zlib_payload(data)
        gzip_data = GZIP_HEADER.dup << compressed_data << GZIP_TRAILER
        reader = Zlib::GzipReader.new(StringIO.new(gzip_data))
        parser = SafeJSONParser.new(reader, self, true)
        result = parser.parse!

        unless [parser.checksum].pack('N') == expected_checksum
          raise Zlib::GzipFile::Error, 'invalid zlib checksum'
        end

        result
      ensure
        reader&.close rescue nil
      end

      private

      GZIP_HEADER = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff".b.freeze
      GZIP_TRAILER = "\0".b * 8

      def validate_integer!(name, value)
        return if value.nil?

        unless value.is_a?(Integer) && value >= 0
          raise ArgumentError, "#{name} must be a non-negative Integer or nil"
        end
      end

      def exceed!(reason)
        @reason = reason
        raise Exceeded.new(reason)
      end

      def zlib_payload(data)
        raise Zlib::DataError, 'invalid zlib stream' if data.nil? || data.bytesize < 6

        cmf = data.getbyte(0)
        flags = data.getbyte(1)
        raise Zlib::DataError, 'invalid zlib header' unless (cmf & 0x0f) == 8 && (cmf * 256 + flags) % 31 == 0

        offset = 2
        offset += 4 if (flags & 0x20) == 0x20

        raise Zlib::DataError, 'invalid zlib stream' if data.bytesize < offset + 4

        compressed_data = data.byteslice(offset, data.bytesize - offset - 4)
        expected_checksum = data.byteslice(-4, 4)

        [compressed_data, expected_checksum]
      end

      class SafeJSONParser
        Container = Struct.new(:value, :depth, :key, :state)

        attr_reader :checksum

        def initialize(io, budget, update_checksum)
          @io = io
          @budget = budget
          @update_checksum = update_checksum
          @nodes = 0
          @bytes = 0
          @next_byte = nil
          @checksum = 1
        end

        def parse!
          root = nil
          stack = []

          loop do
            depth = stack.empty? ? 1 : stack.last.depth
            container = stack.last

            if container.nil? || container.state == :value
              value = parse_value(depth)

              if value.is_a?(Container)
                stack << value
                next
              elsif container.nil?
                root = value
                break
              elsif container.value.is_a?(Array)
                container.value << value
              else
                container.value[container.key] = value
              end
            else
              whitespace
              container.key = parse_string
              whitespace
              consume_byte(?:.ord)
              container.state = :value
              next
            end

            loop do
              whitespace
              closing = container.value.is_a?(Array) ? ?].ord : ?}.ord

              if peek_byte == closing
                next_byte!
                value = container.value
                stack.pop

                if stack.empty?
                  root = value
                  break
                end

                parent = stack.last
                if parent.value.is_a?(Array)
                  parent.value << value
                else
                  parent.value[parent.key] = value
                end

                container = parent
                next
              end

              consume_byte(?,.ord)
              container.state = :key if container.value.is_a?(Hash)
              break
            end

            break if root
          end

          whitespace
          unless eof?
            raise JSON::ParserError, 'unexpected data after JSON document'
          end

          root
        end

        private

        def parse_value(depth)
          @budget.check_depth!(depth)
          @nodes += 1
          @budget.check_nodes!(@nodes)

          whitespace
          token = peek_byte
          raise JSON::ParserError, 'unexpected end of JSON document' if token.nil?

          case token
          when ?{.ord then open_container({}, depth, ?{.ord, ?}.ord)
          when ?[.ord then open_container([], depth, ?[.ord, ?].ord)
          when ?".ord then parse_string
          when ?t.ord then parse_literal('true', true)
          when ?f.ord then parse_literal('false', false)
          when ?n.ord then parse_literal('null', nil)
          else parse_number
          end
        end

        def open_container(value, depth, opening, closing)
          consume_byte(opening)
          whitespace

          if peek_byte == closing
            next_byte!
            value
          else
            state = value.is_a?(Hash) ? :key : :value
            Container.new(value, depth + 1, nil, state)
          end
        end

        def parse_string
          consume_byte(?".ord)
          token = String.new.b
          token << ?".ord

          loop do
            byte = next_byte!
            token << byte

            if byte == ?".ord
              return ::JSON.parse(token)
            end

            next unless byte == ?\\.ord

            escaped = next_byte!
            token << escaped
            next unless escaped == 'u'

            4.times { token << next_byte! }
          end
        end

        def parse_number
          number = String.new.b

          number << next_byte! if peek_byte == ?-.ord

          if peek_byte == ?0.ord
            number << next_byte!
          else
            consume_digits!(number)
          end

          if peek_byte == ?..ord
            number << next_byte!
            consume_digits!(number)
          end

          if peek_byte == ?e.ord || peek_byte == ?E.ord
            number << next_byte!
            number << next_byte! if peek_byte == ?+.ord || peek_byte == ?-.ord
            consume_digits!(number)
          end

          if number =~ /[.eE]/
            value = Float(number)
            raise JSON::ParserError, 'invalid number' unless value.finite?
            value
          else
            Integer(number)
          end
        end

        def parse_literal(literal, value)
          literal.each_byte { |byte| consume_byte(byte) }
          value
        end

        def consume_digits!(number)
          start = number.bytesize

          while (byte = peek_byte) && byte >= ?0.ord && byte <= ?9.ord
            number << next_byte!
          end

          raise JSON::ParserError, 'expected digit' if number.bytesize == start
        end

        def whitespace
          while [32, 9, 13, 10].include?(peek_byte)
            next_byte!
          end
        end

        def peek_byte
          return @next_byte unless @next_byte.nil?
          return nil if @io.eof?

          @next_byte = @io.getbyte
        end

        def next_byte!
          byte = peek_byte
          raise JSON::ParserError, 'unexpected end of JSON document' if byte.nil?

          @next_byte = nil
          @bytes += 1
          @budget.check_bytesize!(@bytes)
          if @update_checksum
            @checksum = Zlib.adler32(byte.chr.b, @checksum)
          end
          byte
        end

        def consume_byte(expected)
          actual = next_byte!
          unless actual == expected
            raise JSON::ParserError, 'expected byte'
          end
        end

        def eof?
          @next_byte.nil? && @io.eof?
        end
      end

      private_constant :SafeJSONParser
    end
  end
end
