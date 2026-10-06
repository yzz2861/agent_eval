# A persistent packrat memo entry: the result of applying one atom at one
# input position, together with everything the parse observed while
# computing it. All positions are byte offsets into the session's current
# text generation.
#
class Parslet::Incremental::Entry
  # [success, value] pair as returned by atom tries.
  attr_reader :result

  # Number of bytes the application consumed.
  attr_reader :advance

  # Highest byte offset (exclusive) whose content was observed.
  attr_reader :max_examined

  # Lowest byte offset from which the remaining length (end of input) was
  # observed, or nil.
  attr_reader :len_from

  # Captures written while this entry was computed (name => value).
  attr_accessor :capture_writes

  def initialize(result, advance, max_examined, len_from, source)
    @result = result
    @advance = advance
    @max_examined = max_examined
    @len_from = len_from
    @source = source
    @byte_shift = 0
    @capture_writes = nil
  end

  # True if replacing the byte range [edit_start, edit_end) (which grows
  # the input by +delta+ bytes) can change this entry's result.
  #
  # +pos+ is the entry's own start position. An entry depends on:
  #
  # * the content of [pos, max_examined) -- invalidated when the edit
  #   touches or moves any of these bytes. Note that a pure insertion
  #   strictly inside that range shifts examined bytes and therefore also
  #   invalidates.
  # * the remaining input length observed from len_from on -- invalidated
  #   when a length-changing edit happens at or after len_from. Edits
  #   before len_from shift the entry together with the observed tail and
  #   leave the remaining length invariant.
  #
  def invalidated_by?(edit_start, edit_end, delta, pos)
    return true if edit_start < max_examined && edit_end > pos
    return true if delta != 0 && len_from && edit_start >= len_from

    false
  end

  # Moves the entry +delta+ bytes forward in the text. The stored result is
  # not rewritten immediately; the shift is accumulated and applied lazily
  # when the entry is reused (see #rebase_to!).
  #
  def shift!(delta)
    @max_examined += delta
    @len_from += delta if @len_from
    @byte_shift += delta
  end

  # Rebinds the stored result (and capture writes) to the given source,
  # applying any accumulated shift, so that slices handed out never point
  # at an older generation of the text.
  #
  def rebase_to!(source)
    return if @byte_shift == 0 && @source.equal?(source)

    success, value = @result
    @result = [
      success,
      Parslet::Incremental.rebase_value(value, source, @byte_shift)
    ]

    if @capture_writes
      @capture_writes = @capture_writes.each_with_object({}) do |(k, v), h|
        h[k] = Parslet::Incremental.rebase_value(v, source, @byte_shift)
      end
    end

    @source = source
    @byte_shift = 0
  end
end
