module Parslet::Atoms
  # Helper class that implements a transient cache that maps position and
  # parslet object to results. This is used for memoization in the packrat
  # style. 
  #
  # Also, error reporter is stored here and error reporting happens through
  # this class. This makes the reporting pluggable. 
  #
  class Context
    # @param reporter [#err, #err_at] Error reporter (leave empty for default 
    #   reporter)
    def initialize(reporter=Parslet::ErrorReporter::Tree.new)
      @cache = Hash.new { |h, k| h[k] = {} }
      @reporter = reporter
      @captures = Parslet::Scope.new
      @cut_frames = []
      @cut_sequence = 0
    end
    
    # Caches a parse answer for obj at source.pos. Applying the same parslet
    # at one position of input always yields the same result, unless the input
    # has changed. 
    #
    # We need the entire source here so we can ask for how many characters 
    # were consumed by a successful parse. Imitation of such a parse must 
    # advance the input pos by the same amount of bytes.
    #
    def try_with_cache(obj, source, consume_all)
      beg = source.bytepos
        
      # Not in cache yet? Return early.
      unless entry = lookup(obj, beg)
        result = obj.try(source, self, consume_all)
    
        if obj.cached?
          set obj, beg, [result, source.bytepos-beg]
        end
        
        return result
      end

      # the condition in unless has returned true, so entry is not nil.
      result, advance = entry

      # The data we're skipping here has been read before. (since it is in 
      # the cache) PLUS the actual contents are not interesting anymore since
      # we know obj matches at beg. So skip reading.
      source.bytepos = beg + advance
      return result
    end  
    
    # Report an error at a given position. 
    # @see ErrorReporter
    #
    def err_at(*args)
      return [false, @reporter.err_at(*args)] if @reporter
      return [false, nil]
    end
    
    # Report an error. 
    # @see ErrorReporter
    #
    def err(*args)
      return [false, @reporter.err(*args)] if @reporter
      return [false, nil]
    end

    # Report a successful parse.
    # @see ErrorReporter::Contextual
    #
    def succ(*args)
      return [true, @reporter.succ(*args)] if @reporter
      return [true, nil]
    end

    # Returns the current captures made on the input (see
    # Parslet::Atoms::Base#capture). Use as follows: 
    # 
    #   context.captures[:foobar] # => returns capture :foobar
    #
    attr_reader :captures
    
    # Starts a new scope. Use the #scope method of Parslet::Atoms::DSL
    # to call this. 
    #
    def scope
      captures.push
      yield
    ensure
      captures.pop
    end

    # --- Commit point (cut) support -------------------------------
    #
    # Each open alternative owns a frame on the cut frame stack. A commit
    # point marks the innermost frame; the mark tells the owning
    # alternative to stop trying its remaining alternatives. Frames are
    # plain monotonic tokens (nil when unmarked), so marks can be
    # checkpointed, compared and restored cheaply.

    # Opens a new commit frame. Must be balanced with #pop_cut_frame.
    #
    def push_cut_frame
      @cut_frames.push(nil)
    end

    # Closes the innermost commit frame, discarding its mark.
    #
    def pop_cut_frame
      @cut_frames.pop
    end

    # Commits the innermost open choice (see Parslet::Atoms::Cut). Does
    # nothing when no choice is open.
    #
    def cut!
      return if @cut_frames.empty?

      @cut_sequence += 1
      @cut_frames[-1] = @cut_sequence
    end

    # True if the innermost open choice has been committed.
    #
    def cut_committed?
      !@cut_frames.empty? && !@cut_frames.last.nil?
    end

    # Returns a token representing the current commit state. Use together
    # with #cut_since? to detect commits that happened in the meantime.
    #
    def cut_checkpoint
      @cut_sequence
    end

    # True if a commit point was crossed after the given checkpoint was
    # taken and its mark is still pending in one of the currently open
    # choices. Marks of choices that have been left since do not count.
    #
    def cut_since?(checkpoint)
      @cut_frames.any? { |mark| mark && mark > checkpoint }
    end

    # Runs the block in a speculative region: commits crossed inside the
    # block are confined to it and never leak into the enclosing parse.
    #
    def cut_shield
      saved_frames = @cut_frames.dup
      yield
    ensure
      @cut_frames.replace(saved_frames)
    end
    
  private 
    # NOTE These methods use #object_id directly, since that seems to bring the
    # most performance benefit. This is a hot spot; going through
    # Atoms::Base#hash doesn't yield as much.
    #
    def lookup(obj, pos)
      @cache[pos][obj.object_id] 
    end
    def set(obj, pos, val)
      @cache[pos][obj.object_id] = val
    end
  end
end
