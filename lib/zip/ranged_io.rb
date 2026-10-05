# frozen_string_literal: true

require_relative 'errors'

module Zip
  # IO adapter for data sources that support byte-range reads. A source must
  # respond to #size, #version, and #read_at(offset, length). #read_at returns
  # either the requested binary string, or [binary_string, version].
  class RangedIO
    READAHEAD_SIZE = 65_536

    attr_reader :size, :version

    def initialize(source, readahead_size: READAHEAD_SIZE)
      unless %i[read_at size version].all? { |method| source.respond_to?(method) }
        raise RangedSourceError,
              'ranged data sources must respond to #read_at, #size and #version'
      end

      @source = source
      @size = Integer(source.size)
      @version = source.version
      @readahead_size = Integer(readahead_size)
      raise RangedSourceError, 'readahead_size must be positive' unless @readahead_size.positive?
      @pos = 0
      clear_buffer
    end

    def tell
      @pos
    end

    def pos
      @pos
    end

    def seek(offset, whence = IO::SEEK_SET)
      new_position = case whence
                     when IO::SEEK_SET then offset
                     when IO::SEEK_CUR then @pos + offset
                     when IO::SEEK_END then @size + offset
                     else raise ArgumentError, "invalid whence: #{whence}"
                     end

      new_position = Integer(new_position)
      raise Errno::EINVAL, 'Invalid argument - negative seek position' if new_position.negative?

      @pos = new_position
      clear_buffer unless buffered?(@pos)
      0
    end

    def eof?
      @pos >= @size
    end

    def read(length = nil)
      length = @size - @pos if length.nil?
      return +''.b if length.zero?
      raise ArgumentError, 'negative length' if length.negative?
      return nil if eof?

      fill_buffer(length)
      chunk = @buffer.byteslice(@pos - @buffer_start, length)
      @pos += chunk.bytesize
      chunk
    end

    def binmode
      self
    end

    def close; end

    def source
      @source
    end

    private

    def buffered?(position)
      position >= @buffer_start && position < @buffer_end
    end

    def clear_buffer
      @buffer = +''.b
      @buffer_start = 0
      @buffer_end = 0
    end

    def fill_buffer(length)
      return if length <= @buffer_end - @pos
      return if @pos >= @size

      request_offset = @pos
      request_length = [@size - request_offset, [length, @readahead_size].max].min
      @buffer = read_range(request_offset, request_length)
      @buffer_start = request_offset
      @buffer_end = request_offset + @buffer.bytesize
    end

    def read_range(offset, length)
      raise RangedSourceError, "offset #{offset} is outside the data source" if offset.negative?
      raise RangedSourceError, "offset #{offset} is outside the data source" if offset >= @size
      raise ArgumentError, 'negative length' if length.negative?
      return +''.b if length.zero?

      data = +request_bytes(offset, length).b
      unless data.bytesize == length
        raise RangedSourceShortReadError.new(offset, length, data.bytesize)
      end

      data
    end

    def request_bytes(offset, length)
      check_version!(@source.version)

      result = @source.read_at(offset, length)
      data, response_version = result
      response_version ||= @source.version if result.is_a?(::String)

      unless data.is_a?(::String)
        raise RangedSourceError, '#read_at must return a binary string or [string, version]'
      end

      check_version!(response_version)
      check_version!(@source.version)
      data
    end

    def check_version!(actual_version)
      return if actual_version == @version

      raise RangedSourceVersionError.new(@version, actual_version)
    end
  end
end
