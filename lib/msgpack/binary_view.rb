module MessagePack
  class BinaryView
    include Enumerable

    def initialize(string, zero_copy = false)
      string = String(string) unless string.is_a?(String)
      unless string.encoding == Encoding::ASCII_8BIT
        raise ArgumentError, "binary view requires an ASCII-8BIT string"
      end

      string = string.dup unless string.frozen?
      initialize_internal(string, zero_copy ? true : false)
      freeze
    end

    def bytesize
      @bytesize
    end
    alias size bytesize
    alias length bytesize

    def empty?
      @bytesize == 0
    end

    def zero_copy?
      @zero_copy
    end

    def [](index, length = nil)
      slice =
        if length.nil?
          case index
          when Range
            first = index.begin.nil? ? 0 : Integer(index.begin)
            first += @bytesize if first < 0
            return nil if first < 0 || first > @bytesize

            last = index.end.nil? ? @bytesize - 1 : Integer(index.end)
            last += @bytesize if last < 0
            return nil if last < 0

            range_length = (index.exclude_end? ? last : last + 1) - first
            range_length = 0 if range_length < 0
            @string.byteslice(first, range_length)
          else
            index = Integer(index)
            index += @bytesize if index < 0
            return nil if index < 0 || index >= @bytesize
            @string.byteslice(index, 1)
          end
        else
          @string.byteslice(Integer(index), Integer(length))
        end

      return nil if slice.nil?
      self.class.allocate.send(:initialize_internal, slice, false)
    end
    alias byteslice []
    alias slice []

    def each
      return enum_for(__method__) unless block_given?
      @string.each_byte { |byte| yield byte }
      self
    end
    alias each_byte each

    def bytes
      @string.bytes
    end

    def write_to(io)
      io.write(@string)
    end

    def to_s
      @string.dup
    end
    alias to_str to_s

    def ==(other)
      case other
      when BinaryView
        @string == other.instance_variable_get(:@string)
      when String
        @string == other.b
      else
        false
      end
    end

    def eql?(other)
      other.is_a?(BinaryView) && @string.eql?(other.instance_variable_get(:@string))
    end

    def hash
      @string.hash
    end

    def inspect
      "#<#{self.class} bytesize=#{@bytesize} zero_copy=#{@zero_copy} #{@string.inspect}>"
    end

    private

    def initialize_internal(string, zero_copy)
      @string = string
      @bytesize = string.bytesize
      @zero_copy = zero_copy && @bytesize > 0
      @string.freeze
      freeze
    end
  end
end
