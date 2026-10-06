# A lexical token together with its type, semantic value and byte range in
# the original source.
#
# Ranges are half-open byte offsets (for example <tt>0...3</tt>) and are
# independent of token index. This allows whitespace and comments to be
# omitted from the token stream without losing source positions.
#
class Parslet::Token < Parslet::Slice
  attr_reader :type
  attr_reader :value
  attr_reader :range
  attr_reader :source_text

  def initialize(type, value, range, source_text=nil, line_cache=nil)
    @type = type
    @value = value
    @range = range
    @source_text = source_text

    text = source_text || value.to_s
    fragment = source_text ? source_text.byteslice(range) : value.to_s

    super(
      Parslet::Position.new(text, range.begin),
      fragment,
      line_cache)
  end

  # Concatenating two tokens returns the source span covered by them. The
  # span may include skipped text such as whitespace or comments.
  #
  def +(other)
    if other.is_a?(self.class) && source_text
      stop = other.range.end
      stop += 1 unless other.range.exclude_end?

      return Parslet::SourceSpan.new(
        position,
        source_text.byteslice(range.begin...stop),
        line_cache,
        Range.new(range.begin, stop, true),
        source_text)
    end

    super
  end

  def inspect
    "#{self.class.name}(#{type.inspect}, #{value.inspect}, #{range.inspect})"
  end

  def line_and_column
    raise ArgumentError, "No line cache was given, cannot infer line and column." \
      unless line_cache

    line_cache.line_and_column(position.bytepos, source_text)
  end
end

class Parslet::SourceSpan < Parslet::Slice
  attr_reader :range
  attr_reader :source_text

  def initialize(position, string, line_cache, range, source_text)
    super(position, string, line_cache)
    @range = range
    @source_text = source_text
  end

  def +(other)
    if other.is_a?(Parslet::SourceSpan)
      stop = [range.end, other.range.end].max
    elsif other.is_a?(Parslet::Token) && source_text
      stop = other.range.end
      stop += 1 unless other.range.exclude_end?
    else
      return super
    end

    self.class.new(
      position,
      source_text.byteslice(range.begin...stop),
      line_cache,
      Range.new(range.begin, stop, true),
      source_text)
  end

  def line_and_column
    raise ArgumentError, "No line cache was given, cannot infer line and column." \
      unless line_cache

    line_cache.line_and_column(position.bytepos, source_text)
  end
end
