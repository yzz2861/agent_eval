
require 'stringio'
require 'strscan'

require 'parslet/position'
require 'parslet/source/line_cache'

module Parslet
  # Wraps the input string for parslet.
  #
  class Source
    attr_reader :string, :line_cache

    class ObservationFrame
      attr_reader :maximum, :observed_eof

      def initialize(source, parent=nil)
        @source = source
        @parent = parent
        @maximum = nil
        @observed_eof = false
      end

      def observe(position=nil)
        if position.nil?
          @observed_eof = true
          @parent.observe(nil) if @parent
        else
          @maximum = position if @maximum.nil? || position > @maximum
          @parent.observe(position) if @parent
        end
      end

      def close
        @source.remove_observation_frame(self)
      end
    end

    def initialize(str)
      raise(
        ArgumentError, 
        "Must construct Source with a string like object."
      ) unless str.respond_to?(:to_str)

      @string = str.to_str.dup
      @observation_frames = []
      @str = StringScanner.new(@string)

      # maps 1 => /./m, 2 => /../m, etc...
      @re_cache = Hash.new { |h,k| 
        h[k] = /(.|$){#{k}}/m }

      @line_cache = LineCache.new
      @line_cache.scan_for_line_endings(0, str)
    end

    def push_observation_frame
      parent = @observation_frames.last
      frame = ObservationFrame.new(self, parent)
      @observation_frames << frame
      frame
    end

    def remove_observation_frame(frame)
      @observation_frames.delete(frame)
    end

    def observation_frame_active?(frame)
      @observation_frames.include?(frame)
    end

    def observe(position=nil)
      frame = @observation_frames.last
      frame.observe(position) if frame
    end

    def replace(char_pos, char_length, replacement)
      replacement = replacement.to_str
      start_byte = byte_offset_for_char_offset(char_pos)
      end_byte = byte_offset_for_char_offset(char_pos + char_length)

      if start_byte.nil? || end_byte.nil? ||
           start_byte > end_byte || end_byte > @string.bytesize
        raise ArgumentError, "Invalid replacement range."
      end

      old_eof = @string.bytesize
      old_length = end_byte - start_byte
      new_string = @string.byteslice(0, start_byte).to_s +
        replacement +
        @string.byteslice(end_byte, old_eof - end_byte).to_s
      new_line_cache = @line_cache.dup
      new_line_cache.replace_line_cache(start_byte, old_length, replacement)

      @string = new_string
      @str = StringScanner.new(@string)
      @line_cache = new_line_cache
      @observation_frames.clear

      self
    end
  
    # Checks if the given pattern matches at the current input position. 
    #
    # @param pattern [Regexp] pattern to check for
    # @return [Boolean] true if the pattern matches at #pos
    #
    def matches?(pattern)
      matched = @str.match?(pattern)
      if matched
        observe
      end
      matched
    end
    alias match matches?

    def matches_fixed?(string)
      length = string.bytesize
      observed = @str.rest.bytesize
      if observed < length
        observe
        return false
      end
      observed = length if length < observed
      matched = @str.peek(length) == string
      observe(@str.pos + observed)
      matched
    end

    def matches_single?(pattern)
      matched = @str.match?(pattern)
      if matched
        first_char = @str.peek(1)
        observe(@str.pos + first_char.bytesize)
      else
        if @str.eos?
          observe
        else
          observe(@str.pos)
        end
      end
      matched
    end
    
    # Consumes n characters from the input, returning them as a slice of the
    # input. 
    #
    def consume(n)
      position = self.pos
      requested_to_eof = @str.rest_size < n
      slice_str = @str.scan(@re_cache[n])
      requested_to_eof ? observe : observe(@str.pos)
      slice = Parslet::Slice.new(
        position, 
        slice_str,
        @line_cache)

      return slice
    end
    
    # Returns how many chars remain in the input. 
    #
    def chars_left
      observe
      @str.rest_size
    end

    # Returns how many chars there are between current position and the 
    # string given. If the string given doesn't occur in the source, then 
    # the remaining chars (#chars_left) are returned. 
    #
    # @return [Fixnum] count of chars until str or #chars_left
    #
    def chars_until str
      slice_str = @str.check_until(Regexp.new(Regexp.escape(str)))
      if slice_str
        observe(@str.pos + slice_str.bytesize - str.bytesize)
        slice_str.size - str.size
      else
        observe
        return @str.rest_size
      end
    end
    
    # Position of the parse as a character offset into the original string. 
    #
    # @note Please be aware of encodings at this point. 
    #
    def pos
      Position.new(@str.string, @str.pos)
    end
    def bytepos
      @str.pos
    end

    # @note Please be aware of encodings at this point. 
    #
    def bytepos=(n)
      @str.pos = n
    rescue RangeError
    end

    def eof?
      @str.eos?
    end

    # Returns a <line, column> tuple for the given position. If no position is
    # given, line/column information is returned for the current position
    # given by #pos. 
    #
    def line_and_column(position=nil)
      @line_cache.line_and_column(position || self.bytepos)
    end

  private

    def byte_offset_for_char_offset(char_offset)
      return nil unless char_offset >= 0
      prefix = @string[0, char_offset]
      return nil unless prefix && prefix.length == char_offset
      prefix.bytesize
    end
  end
end
