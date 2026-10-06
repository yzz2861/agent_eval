# A parse context that memoizes into the session's persistent table
# instead of a per-parse transient cache, and that records input
# observations into the session's tracker.
#
# @api private
#
class Parslet::Incremental::Context < Parslet::Atoms::Context
  # A captures scope that reports writes so they can be stored alongside
  # memo entries and replayed when an entry is reused. Without this, a
  # cache hit would skip the Capture atom whose side effect a later
  # dynamic parse depends on.
  #
  class RecordingScope < Parslet::Scope
    attr_accessor :listener

    def []=(key, value)
      listener.capture_written(key, value) if listener
      super
    end
  end

  def initialize(session)
    super(nil) # no error reporter: the fast path of a parse

    @session = session
    @tracker = session.tracker
    @stats = session.stats

    @captures = RecordingScope.new
    @captures.listener = self
  end

  def capture_written(name, value)
    @tracker.observe_write(name, value)
  end

  def try_with_cache(obj, source, consume_all)
    beg = source.bytepos
    atoms = @session.table[beg]

    if (entry = atoms[obj.object_id])
      @stats[:hits] += 1

      # Depending on a cached entry means depending on everything the
      # entry observed: merge its observations into the current frames.
      @tracker.observe_content(entry.max_examined)
      @tracker.observe_length(entry.len_from)

      entry.rebase_to!(@session.source)
      replay_captures(entry)

      result, advance = entry.result, entry.advance
      source.bytepos = beg + advance
      return result
    end

    @stats[:misses] += 1

    @tracker.push_frame
    begin
      result = obj.try(source, self, consume_all)
    ensure
      frame = @tracker.pop_frame
    end

    if obj.cached?
      entry = Parslet::Incremental::Entry.new(
        result,
        source.bytepos - beg,
        frame.max_examined,
        frame.len_from,
        @session.source)
      entry.capture_writes = frame.writes unless frame.writes.empty?
      atoms[obj.object_id] = entry
      @stats[:stores] += 1
    end

    result
  end

  private

  # Reapplies the capture side effects of a cached entry, so that dynamic
  # parses (which are never cached) observe the same captures as in a full
  # parse.
  #
  def replay_captures(entry)
    return unless entry.capture_writes

    entry.capture_writes.each do |name, value|
      @captures[name] = value
    end
  end
end
