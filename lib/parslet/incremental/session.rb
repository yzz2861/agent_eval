# A stateful parsing session: parses a text, accepts interval edits and
# reparses, reusing memoized results that the edit could not have
# influenced.
#
#   session = Parslet::Incremental::Session.new(parser, text)
#   session.parse
#   session.edit(10, 15, 'replacement')
#   session.parse
#   session.stats # => { hits:, misses:, stores:, invalidated:, shifted: }
#
# Correctness contract: results are always identical to a full parse of
# the current text, including failure positions. Memo entries record
# everything they observed while being computed (consumed input,
# lookahead, failed alternatives, end-of-input checks); an entry is
# reused only when the edit is provably outside all of its observations.
# Slices handed out always reference the current text, never an older
# generation.
#
class Parslet::Incremental::Session
  # The current text.
  attr_reader :text

  # Cumulative cache statistics. Keys:
  #
  # parses::      number of #parse calls
  # hits::        memo entries reused instead of recomputed
  # misses::      atom applications computed (and memoized) fresh
  # stores::      memo entries stored
  # invalidated:: entries dropped by edits
  # shifted::     entries moved across an edit point
  #
  attr_reader :stats

  # @api private
  attr_reader :source, :tracker, :table

  # @param parser [Parslet::Atoms::Base] the parser (or parslet) to run
  # @param text [String] initial text
  #
  def initialize(parser, text)
    @parser = parser
    @text = text.to_str.dup
    @source = Parslet::Incremental::TrackingSource.new(@text)
    @table = Hash.new { |hash, key| hash[key] = {} }
    @tracker = Parslet::Incremental::Tracker.new
    @stats = Hash.new(0)
  end

  # Parses the current text, reusing memoized results where possible.
  # Accepts the same options as Parslet::Atoms::Base#parse.
  #
  # @return the same value a full parse of the current text would return
  # @raise [Parslet::ParseFailed] exactly the failure a full parse would
  #   produce, including its position
  #
  def parse(options={})
    @stats[:parses] += 1

    context = Parslet::Incremental::Context.new(self)
    @source.tracker = @tracker
    @source.bytepos = 0

    success, value = @parser.apply(@source, context, !options[:prefix])

    unless success
      # Failure reporting in parslet works by reparsing with an error
      # reporter; do exactly that so the raised failure -- position
      # included -- is identical to a full parse by construction.
      @parser.parse(@text, options)

      fail 'Incremental parse failed, but a full parse succeeded. ' +        'Please report this bug.'
    end

    @parser.flatten(value)
  end

  # Replaces the character range [start, stop) of the current text with
  # +replacement+ and invalidates all memo entries the edit can
  # influence. Entries before the edit whose observations do not reach
  # the edit are kept; entries entirely after the edit are moved.
  #
  # @param start [Integer] character offset at which the replaced range
  #   starts
  # @param stop [Integer] character offset at which the replaced range
  #   ends (use start == stop for a pure insertion)
  # @param replacement [String] text to insert in place of the range
  #   (use '' for a pure deletion)
  # @return [String] the new text
  #
  def edit(start, stop, replacement)
    replacement = replacement.to_str

    if start < 0 || stop < start || stop > @text.size
      fail ArgumentError,
        "Invalid edit range #{start}...#{stop} for text of size #{@text.size}."
    end

    byte_start = byte_offset(start)
    byte_stop = byte_offset(stop)

    @text = @text[0...start] + replacement + @text[stop..-1]
    @source = Parslet::Incremental::TrackingSource.new(@text)

    remap(byte_start, byte_stop, replacement.bytesize - (byte_stop - byte_start))

    @text
  end

  # Number of memo entries currently held.
  #
  def entry_count
    @table.each_value.inject(0) { |sum, atoms| sum + atoms.size }
  end

  # Resets the cumulative statistics.
  #
  def reset_stats!
    @stats = Hash.new(0)
  end

  private

  def byte_offset(char_offset)
    @text[0...char_offset].bytesize
  end

  # Rebuilds the memo table after an edit replacing [edit_start, edit_end)
  # (byte offsets into the previous text), where the input grew by +delta+
  # bytes.
  #
  def remap(edit_start, edit_end, delta)
    new_table = Hash.new { |hash, key| hash[key] = {} }

    @table.each do |pos, atoms|
      atoms.each do |object_id, entry|
        if entry.invalidated_by?(edit_start, edit_end, delta, pos)
          @stats[:invalidated] += 1
        elsif pos >= edit_end
          # Entirely after the edit: content and observations are
          # unchanged, only their position moves.
          entry.shift!(delta)
          @stats[:shifted] += 1
          new_table[pos + delta][object_id] = entry
        else
          new_table[pos][object_id] = entry
        end
      end
    end

    @table = new_table
  end
end
