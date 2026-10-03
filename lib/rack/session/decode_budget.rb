# frozen_string_literal: true

require 'json'
require 'zlib'

require_relative 'abstract/id'

module Rack
  module Session
    class Cookie < Abstract::PersistedSecure
      # Limits JSON decoding by decoded bytes, container depth, and value nodes.
      class DecodeBudget
        # Raised when a session exceeds one of the configured decode limits.
        class Exceeded < StandardError
          attr_reader :reason

          def initialize(reason)
            @reason = reason
            super("session decode budget exceeded: #{reason}")
          end
        end

        BYTE_LIMIT_EXCEEDED = :byte_limit_exceeded
        DEPTH_LIMIT_EXCEEDED = :depth_limit_exceeded
        NODE_LIMIT_EXCEEDED = :node_limit_exceeded

        attr_reader :max_bytes, :max_depth, :max_nodes

        def initialize(bytes:, depth:, nodes:)
          @max_bytes = positive_integer!(bytes, :bytes)
          @max_depth = positive_integer!(depth, :depth)
          @max_nodes = positive_integer!(nodes, :nodes)
        end

        # Validates and parses JSON without allowing Marshal fallback types.
        def parse_json(json)
          check_byte_limit!(json.bytesize)
          check_json_limits!(json)
          ::JSON.parse(json, allow_nan: false)
        end

        def check_base64_byte_limit!(value)
          encoded = value.delete(" \t\r\n")
          explicit_padding = encoded.count('=')
          unpadded_remainder = encoded.bytesize % 4
          implicit_padding = (4 - unpadded_remainder) % 4

          decoded_size = (encoded.bytesize.to_f / 4).ceil * 3 - explicit_padding - implicit_padding
          check_byte_limit!(decoded_size)
        end

        # Inflates data incrementally so compressed cookies cannot expand past
        # the byte budget before JSON parsing begins.
        def inflate(data)
          inflater = ::Zlib::Inflate.new
          inflated = String.new

          data.each_byte do |byte|
            chunk = inflater.inflate(byte.chr)
            check_byte_limit!(inflated.bytesize + chunk.bytesize)
            inflated << chunk
            check_byte_limit!(inflated.bytesize)

            until inflater.finished?
              chunk = inflater.flush_next_out
              break if chunk.empty?

              check_byte_limit!(inflated.bytesize + chunk.bytesize)
              inflated << chunk
              check_byte_limit!(inflated.bytesize)
            end
          end

          raise ::Zlib::BufError unless inflater.finished?
          inflated
        ensure
          inflater&.close
        end

        private

        def positive_integer!(value, name)
          unless value.is_a?(Integer) && value > 0
            raise ArgumentError, "decode budget :#{name} must be a positive Integer"
          end

          value
        end

        def check_byte_limit!(size)
          raise Exceeded, BYTE_LIMIT_EXCEEDED if size > @max_bytes
        end

        def check_json_limits!(json)
          index = 0
          depth = 0
          nodes = 0
          stack = []
          expecting_value = true
          expecting_key = false

          while true
            index = skip_whitespace(json, index)
            raise ::JSON::ParserError, 'unexpected token' if index >= json.bytesize

            if expecting_value
              index, mode = scan_json_value(json, index, stack) do |byte, container|
                nodes += 1
                check_node_limit!(nodes)

                if container
                  depth += 1
                  check_depth!(depth)
                end
              end
              expecting_value = mode == :value
              expecting_key = mode == :key
              break if mode == :complete && stack.empty?
            elsif expecting_key
              raise ::JSON::ParserError, 'unexpected token' unless json.getbyte(index) == 34

              index = scan_json_string(json, index)
              index = skip_whitespace(json, index)
              raise ::JSON::ParserError, 'unexpected token' unless json.getbyte(index) == 58

              index += 1
              expecting_value = true
              expecting_key = false
            else
              byte = json.getbyte(index)

              if byte == 44
                index += 1
                expecting_value = stack.last == :array
                expecting_key = stack.last == :object
              else
                closing = stack.last == :object ? 125 : 93
                raise ::JSON::ParserError, 'unexpected token' unless byte == closing

                stack.pop
                depth -= 1
                index += 1
                break if stack.empty?
              end
            end
          end

          index = skip_whitespace(json, index)
          raise ::JSON::ParserError, 'unexpected token' unless index == json.bytesize
          raise ::JSON::ParserError, 'unexpected token' unless depth.zero?
        end

        def check_node_limit!(nodes)
          raise Exceeded, NODE_LIMIT_EXCEEDED if nodes > @max_nodes
        end

        def check_depth!(depth)
          raise Exceeded, DEPTH_LIMIT_EXCEEDED if depth > @max_depth
        end

        def skip_whitespace(json, index)
          index += 1 while index < json.bytesize && [32, 9, 10, 13].include?(json.getbyte(index))
          index
        end

        def scan_json_value(json, index, stack)
          byte = json.getbyte(index)

          case byte
          when 123
            stack << :object
            after_open = skip_whitespace(json, index + 1)
            if json.getbyte(after_open) == 125
              yield(byte, true)
              [after_open, :empty_open]
            else
              yield(byte, true)
              [after_open, :key]
            end
          when 91
            stack << :array
            after_open = skip_whitespace(json, index + 1)
            if json.getbyte(after_open) == 93
              yield(byte, true)
              [after_open, :empty_open]
            else
              yield(byte, true)
              [after_open, :value]
            end
          when 34
            yield(byte, false)
            [scan_json_string(json, index), :complete]
          when 45, 48..57
            yield(byte, false)
            [scan_json_number(json, index), :complete]
          when 116, 102, 110
            yield(byte, false)
            [scan_json_literal(json, index), :complete]
          else
            raise ::JSON::ParserError, 'unexpected token'
          end
        end

        def scan_json_string(json, index)
          index += 1

          while index < json.bytesize
            byte = json.getbyte(index)
            index += 1

            if byte == 92
              return json.bytesize if index >= json.bytesize

              escaped = json.getbyte(index)
              if escaped == 117
                hex_index = index + 1
                hex = json.byteslice(hex_index, 4)
                raise ::JSON::ParserError, 'unexpected token' unless hex&.match?(/\A[0-9a-fA-F]{4}\z/)

                index = hex_index + 4
              else
                raise ::JSON::ParserError, 'unexpected token' unless
                  [34, 92, 47, 98, 102, 110, 114, 116].include?(escaped)

                index += 1
              end
            elsif byte == 34
              return index
            elsif byte < 32
              raise ::JSON::ParserError, 'unexpected token'
            end
          end

          raise ::JSON::ParserError, 'unexpected token'
        end

        def scan_json_number(json, index)
          index += 1 if json.getbyte(index) == 45

          if json.getbyte(index) == 48
            index += 1
          else
            index += 1 while index < json.bytesize && (48..57).cover?(json.getbyte(index))
          end

          if index < json.bytesize && json.getbyte(index) == 46
            index += 1
            index += 1 while index < json.bytesize && (48..57).cover?(json.getbyte(index))
          end

          if index < json.bytesize && [101, 69].include?(json.getbyte(index))
            index += 1
            index += 1 if [43, 45].include?(json.getbyte(index))
            index += 1 while index < json.bytesize && (48..57).cover?(json.getbyte(index))
          end

          index
        end

        def scan_json_literal(json, index)
          case json.getbyte(index)
          when 116
            literal = 'true'
          when 102
            literal = 'false'
          else
            literal = 'null'
          end

          unless json.byteslice(index, literal.bytesize) == literal
            raise ::JSON::ParserError, 'unexpected token'
          end

          index + literal.bytesize
        end
      end
    end
  end
end
