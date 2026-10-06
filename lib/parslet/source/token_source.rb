require 'parslet/source/line_cache'

class Parslet::TokenSource
  attr_reader :tokens

  def initialize(tokens, source)
    unless source.respond_to?(:to_str)
      raise ArgumentError, "Token input requires the original source string."
    end

    @source = source.to_str
    @line_cache = Parslet::Source::LineCache.new
    @line_cache.scan_for_line_endings(0, @source)
    @tokens = []
    @position = 0

    build_tokens(tokens)
  end

  def current_token
    @tokens[@position]
  end

  def consume(count)
    return empty_slice if @position >= @tokens.size

    first = @tokens[@position]
    stop_index = [@position + count, @tokens.size].min
    last = @tokens[stop_index - 1]
    @position = stop_index

    return first if count == 1

    Parslet::SourceSpan.new(
      first.position,
      source_span(first, last),
      @line_cache,
      Range.new(first.range.begin, last.range.end, true),
      @source)
  end

  def chars_left
    @tokens.size - @position
  end

  def matches?(pattern)
    false
  end
  alias match matches?

  # The parse cursor is a token index. Position objects returned by #pos use
  # byte offsets in the original source instead.
  #
  def bytepos
    @position
  end

  def bytepos=(position)
    @position = position
  end

  def pos
    offset = current_token ? current_token.range.begin : @source.bytesize
    Parslet::Position.new(@source, offset)
  end

  def line_and_column(position=nil)
    if position.nil?
      position = pos
    end

    @line_cache.line_and_column(position, @source)
  end

private

  def build_tokens(tokens)
    previous_start = nil
    previous_end = 0

    tokens.each_with_index do |raw_token, index|
      type, value, range = coerce_token(raw_token, index)
      start_offset, stop_offset = validate_range(
        range,
        index,
        previous_start,
        previous_end)

      @tokens << Parslet::Token.new(
        type,
        value,
        Range.new(start_offset, stop_offset, true),
        @source,
      @line_cache)
      previous_start = start_offset
      previous_end = stop_offset
    end
  end

  def coerce_token(token, index)
    case token
    when Parslet::Token
      [token.type, token.value, token.range]
    when Array
      unless token.size == 3
        raise ArgumentError, "Token ##{index} must be a three element " \
          "array [type, value, range]."
      end

      token
    when Hash
      [token[:type], token[:value], token[:range]]
    else
      unless token.respond_to?(:type) &&
             token.respond_to?(:value) &&
             token.respond_to?(:range)
        raise ArgumentError, "Token ##{index} must be a Parslet::Token, " \
          "an array, or respond to #type, #value and #range."
      end

      [token.type, token.value, token.range]
    end
  end

  def validate_range(range, index, previous_start, previous_end)
    unless range.is_a?(Range) &&
           range.begin.is_a?(Integer) &&
           range.end.is_a?(Integer)
      raise ArgumentError, "Token ##{index} has an invalid byte range: " \
        "#{range.inspect}."
    end

    start_offset = range.begin
    stop_offset = range.end
    stop_offset += 1 unless range.exclude_end?

    if start_offset < 0 || stop_offset > @source.bytesize
      raise ArgumentError, "Token ##{index} range #{range.inspect} is outside " \
        "the original source."
    end

    if start_offset >= stop_offset
      raise ArgumentError, "Token ##{index} range #{range.inspect} is " \
        "reversed or empty."
    end

    if previous_start && start_offset < previous_start
      raise ArgumentError, "Token ##{index} range #{range.inspect} is not " \
        "in source order after the preceding token range."
    end

    if start_offset < previous_end
      raise ArgumentError, "Token ##{index} range #{range.inspect} overlaps " \
        "the preceding token range."
    end

    [start_offset, stop_offset]
  end

  def source_span(first, last)
    @source.byteslice(first.range.begin...last.range.end)
  end

  def empty_slice
    Parslet::Slice.new(
      Parslet::Position.new(@source, @source.bytesize),
      "",
      @line_cache)
  end
end
