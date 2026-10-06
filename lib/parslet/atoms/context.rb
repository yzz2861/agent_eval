module Parslet::Atoms
  # Helper class that implements a transient cache that maps position and
  # parslet object to results. This is used for memoization in the packrat
  # style. 
  #
  # Also, error reporter is stored here and error reporting happens through
  # this class. This makes the reporting pluggable. 
  #
  class Context
    # One frame per enclosing alternative. A frame is its own stable identity
    # (snapshots of the frame stack may outlive speculative parses); the
    # #commits counter records how often a cut fired for the choice.
    class ChoiceFrame
      # Number of times a cut committed this frame. Counting rather than a
      # boolean lets a cached entry tell whether a particular evaluation
      # itself fired one of the cuts even if the frame was already
      # committed when the evaluation started.
      attr_accessor :commits
      def initialize
        @commits = 0
      end

      def committed?
        @commits > 0
      end
    end

    # @param reporter [#err, #err_at] Error reporter (leave empty for default 
    #   reporter)
    def initialize(reporter=Parslet::ErrorReporter::Tree.new)
      @cache = Hash.new { |h, k| h[k] = {} }
      @reporter = reporter
      @captures = Parslet::Scope.new
      # Stack of choice frames, one per enclosing alternative.
      @choice_frames = []
      # Stack of speculative regions (one per running repetition attempt or
      # lookahead). A region that turns out to be a discarded speculation is
      # marked voided; cache entries born in it must not replay their cut.
      @speculative_regions = []
    end

    # Pushes a fresh frame for an alternative that is about to be tried.
    # Returns the frame so the alternative can tell whether it has been
    # committed by a cut while one of its branches was running.
    def push_choice_frame
      frame = ChoiceFrame.new
      @choice_frames.push(frame)
      frame
    end

    # Pops and returns the most recently pushed choice frame.
    def pop_choice_frame
      @choice_frames.pop
    end

    # Takes a snapshot of the current choice frame stack together with the
    # commit counts at this point. Restoring it via #choice_frame_stack=
    # forgets every cut that happened in the meantime, which is what bounds
    # cuts to repetitions and lookaheads. 
    def choice_frame_stack
      @choice_frames.map { |frame| [frame, frame.commits] }
    end

    # Restores a snapshot taken with #choice_frame_stack.
    def choice_frame_stack=(frames)
      frames.each { |frame, commits| frame.commits = commits }
      @choice_frames = frames.map(&:first)
    end

    # Runs a speculative region. The caller marks the returned token voided
    # (token[:voided] = true) if the speculation is discarded: a failed
    # repetition attempt, or any lookahead (which discards even a success).
    # The token can be attached to cached results so cut replay respects the
    # boundary long after the region ended.
    def speculative_region
      token = { :voided => false }
      @speculative_regions.push(token)
      yield(token)
    ensure
      @speculative_regions.pop
    end

    # The region a new cache entry belongs to, or nil for a normal parse.
    def current_speculative_region
      @speculative_regions.last
    end

    # Commits the innermost enclosing alternative. A cut reached outside of
    # every alternative is a no-op. 
    def cut!
      unless @choice_frames.empty?
        @choice_frames[-1].commits += 1
      end
    end

    # True if the innermost enclosing alternative has been committed by a
    # cut. Used by Alternative#try to stop after a committed branch.
    def choice_committed?
      frame = @choice_frames.last
      frame && frame.committed?
    end

    # Whether the given atom owns a choice frame. Only alternatives do; the
    # frame has to surround both the real evaluation and a packrat replay,
    # which is why #try_with_cache asks the atom instead of the other way
    # round.
    def owns_choice_frame?(obj)
      obj.respond_to?(:choice_frame?) && obj.choice_frame?
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
        # Alternatives evaluate with their own fresh frame on the stack.
        if owns_choice_frame?(obj)
          frame = push_choice_frame
          result = obj.try(source, self, consume_all)
          own_commit = frame.committed?
          pop_choice_frame

          # A cut belongs to this alternative alone: the frame is popped
          # and the commit is not propagated to the caller. The committed
          # failure is cached so a replay behaves the same.

          if obj.cached?
            set obj, beg, [result, source.bytepos-beg, own_commit]
          end
          return result
        end

        frames_before = @choice_frames.size
        enclosing_frame = @choice_frames.last
        commits_before = enclosing_frame ? enclosing_frame.commits : 0

        result = obj.try(source, self, consume_all)

        # Did evaluating obj commit a choice that is still on the frame
        # stack afterwards? Such a frame is an alternative that encloses
        # *this invocation* (a choice belonging to obj itself has already
        # been popped). A cut in a successful evaluation is spent, so only
        # failures carry the commit. Remember it so the commit survives a
        # later packrat replay of this entry.
        net_cut = frames_before > 0 &&
          !result.first &&
          @choice_frames.size >= frames_before &&
          @choice_frames[frames_before - 1].equal?(enclosing_frame) &&
          @choice_frames[frames_before - 1].commits > commits_before
        region = current_speculative_region
    
        if obj.cached?
          set obj, beg, [result, source.bytepos-beg, net_cut, region]
        end
        
        return result
      end

      # the condition in unless has returned true, so entry is not nil.
      result, advance, net_cut, region = entry

      if owns_choice_frame?(obj)
        # Reconstruct the alternative's own frame: cached sub-results
        # replayed while unwinding this cached derivation still commit to
        # this level. The commit stays local to the alternative, as in a
        # fresh evaluation.
        frame = push_choice_frame
        frame.commits = 1 if net_cut
        source.bytepos = beg + advance
        pop_choice_frame
        return result
      else
        # Replay the net commit on the innermost enclosing choice, which is
        # the alternative that encloses the replay call just as it enclosed
        # the original call. If the cut was observed inside a speculative
        # attempt that was later discarded (failed repetition iteration,
        # lookahead), the token was marked voided and the cut is not
        # replayed.
        cut! if net_cut && (region.nil? || !region[:voided])
      end

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
