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
    end

    def use_persistent_cache(cache)
      @persistent_cache = cache
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
      frame = source.respond_to?(:push_observation_frame) ?
        source.push_observation_frame :
        Parslet::Atoms::Cache::UnknownSourceFrame.new

      if @persistent_cache
        persistent_entry = @persistent_cache.get(
          obj, source, beg, consume_all, @captures, @reporter, frame)

        if persistent_entry
          result, advance = persistent_entry
          source.bytepos = beg + advance
          frame.close if frame
          return result
        end
        result = obj.try(source, self, consume_all)
        if obj.cached?
          @persistent_cache.set(
            obj, beg, consume_all, @captures, @reporter,
            result, source.bytepos-beg, frame)
        end
      else
        if entry = lookup(obj, beg)
          result, advance = entry
          source.bytepos = beg + advance
          frame.close if frame
          return result
        end

        result = obj.try(source, self, consume_all)

        if obj.cached?
          set obj, beg, [result, source.bytepos-beg]
        end
      end

      frame.close if frame
      return result
    ensure
      frame.close if frame && source.respond_to?(:observation_frame_active?) &&
        source.observation_frame_active?(frame)
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
