# A Parslet::Source that reports every observation of the input to a
# Parslet::Incremental::Tracker. This is what allows memo entries to know
# exactly which parts of the input they depend on -- including lookahead,
# failed matches and end-of-input checks, not just successfully consumed
# spans.
#
# All positions are byte offsets.
#
class Parslet::Incremental::TrackingSource < Parslet::Source
  attr_accessor :tracker

  # Rebuilds a slice so that it points into this source's text, adding
  # +byte_shift+ to its position. Used when handing out cached results:
  # slices must never reference an older generation of the text.
  #
  def rebase_slice(slice, byte_shift)
    Parslet::Slice.new(
      Parslet::Position.new(@str.string, slice.position.bytepos + byte_shift),
      slice.str,
      @line_cache)
  end

  def consume(n)
    slice = super

    # Note: reading fewer than n characters at end of input only happens
    # while constructing error messages, never in a way that influences
    # parse results, so no length dependency is recorded here.
    @tracker.observe_content(bytepos) if @tracker

    slice
  end

  def matches?(pattern)
    from = bytepos
    size = @str.match?(pattern)

    if @tracker
      if size
        @tracker.observe_content(from + size)
      else
        observe_failed_match(from, pattern)
      end
    end

    size
  end
  alias match matches?

  # Structural observation of the remaining input length (used e.g. by
  # Repetition to decide whether all input was consumed). Tracked: results
  # depend on it.
  #
  def chars_left
    @tracker.observe_length(bytepos) if @tracker
    super
  end

  # Observation of the remaining length purely for error message
  # construction. Untracked: it cannot influence parse results.
  #
  def diagnostic_chars_left
    @str.rest_size
  end

  def chars_until(str)
    from = bytepos
    slice_str = @str.check_until(Regexp.new(Regexp.escape(str)))

    unless slice_str
      if @tracker
        @tracker.observe_content(@str.string.bytesize)
        @tracker.observe_length(from)
      end
      return chars_left
    end

    @tracker.observe_content(from + slice_str.bytesize) if @tracker
    slice_str.size - str.size
  end

  private

  # Records a failed match attempt at +from+. A failed anchored match can
  # in general look arbitrarily far ahead, so we derive the tightest sound
  # bound from the pattern's shape:
  #
  # * literal patterns (produced by Parslet.str) examine at most as many
  #   characters as the literal has;
  # * single character patterns (produced by Parslet.match) examine at
  #   most one character;
  # * anything else is conservatively assumed to examine the rest of the
  #   input.
  #
  # Failing because the input ended additionally observes the input
  # length.
  #
  def observe_failed_match(from, pattern)
    if (literal = literal_pattern(pattern))
      remaining = @str.rest.size
      @tracker.observe_content(
        from + [literal.bytesize, @str.rest_size].min)
      @tracker.observe_length(from) if literal.size > remaining
    elsif single_char_pattern?(pattern)
      if @str.rest_size > 0
        # One character was examined. Edits are always character aligned,
        # so recording a single byte here correctly intersects any edit
        # that touches this character.
        @tracker.observe_content(from + 1)
      else
        @tracker.observe_length(from)
      end
    else
      @tracker.observe_content(@str.string.bytesize)
      @tracker.observe_length(from)
    end
  end

  # If +pattern+ matches exactly one literal string (the kind of pattern
  # Parslet::Atoms::Str builds), returns that string, otherwise nil.
  #
  def literal_pattern(pattern)
    @literal_cache ||= {}
    return @literal_cache[pattern] if @literal_cache.key?(pattern)

    source = pattern.source
    unescaped = source.gsub(/\\(.)/m) { Regexp.last_match(1) }
    literal = (Regexp.escape(unescaped) == source) ? unescaped : nil
    @literal_cache[pattern] = literal
  end

  # True for patterns that always match exactly one character: character
  # classes like [a-z], shorthand classes like \\d and '.'.
  #
  def single_char_pattern?(pattern)
    source = pattern.source
    source == '.' ||
      source =~ /\A\\[a-zA-Z]\z/ ||
      source =~ /\A\[(?:\\.|[^\]])*\]\z/ ?
      true : false
  end
end
