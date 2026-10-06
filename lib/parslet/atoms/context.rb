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
      @left_recursion_states = []
      @rule_frames = []
      @growing_left_recursions = {}
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

      if left_recursion_active?
        frame = recursive_rule_frame(obj, beg)
        if frame
          state = frame[:state]
          source.bytepos = beg + state[:advance]
          unless state[:answer].first || @reporter.nil?
            state[:rule_names] ||= involved_rule_names(frame, obj)
            return err_at(
              obj,
              source,
              left_recursion_message(state[:rule_names]),
              beg
            )
          end
          return state[:answer]
        end

        if left_recursive_rule?(obj)
          return grow_left_recursion(obj, source, false, beg)
        end

        return obj.try(source, self, consume_all)
      end

      if left_recursive_rule?(obj)
        return grow_and_cache_left_recursion(obj, source, beg)
      end
        
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

    def attempt_rule(entity, source)
      state = @left_recursion_states.last
      return yield unless state

      @rule_frames.push(
        entity: entity,
        pos: source.bytepos,
        state: state
      )
      yield
    ensure
      @rule_frames.pop if state
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

    def left_recursion_active?
      !@left_recursion_states.empty?
    end

    def left_recursive_rule?(obj)
      obj.respond_to?(:left_recursive?) && obj.left_recursive?
    end

    def recursive_rule_frame(obj, pos)
      state = @growing_left_recursions[[obj.object_id, pos]]
      return unless state

      @rule_frames.find do |frame|
        frame[:entity].equal?(obj) &&
          frame[:pos] == pos &&
          frame[:state].equal?(state)
      end
    end

    def grow_and_cache_left_recursion(obj, source, beg)
      result = grow_left_recursion(obj, source, false, beg)
      set obj, beg, [result, source.bytepos - beg]
      result
    end

    def grow_left_recursion(obj, source, consume_all, beg)
      state = {
        answer: [false, nil],
        advance: 0
      }
      key = [obj.object_id, beg]
      @growing_left_recursions[key] = state
      @left_recursion_states.push(state)

      result = obj.try(source, self, consume_all)
      success, _ = result

      if success
        endpoint = source.bytepos
        update_left_recursion_answer(state, result, endpoint - beg)

        loop do
          source.bytepos = beg
          candidate = obj.try(source, self, consume_all)
          candidate_success, _ = candidate
          candidate_endpoint = source.bytepos

          break unless candidate_success
          break if candidate_endpoint <= endpoint

          result = candidate
          endpoint = candidate_endpoint
          update_left_recursion_answer(state, result, endpoint - beg)
        end
      else
        update_left_recursion_answer(state, result, state[:advance])
      end

      source.bytepos = beg + state[:advance]
      state[:answer]
    ensure
      @left_recursion_states.pop
      @growing_left_recursions.delete(key)
    end

    def update_left_recursion_answer(state, result, advance)
      state[:answer] = result
      state[:advance] = advance
    end

    def involved_rule_names(frame, obj)
      index = @rule_frames.index(frame)
      names = @rule_frames[index..-1].map { |f| f[:entity].name }
      names << obj.name
      names.map(&:to_s).uniq
    end

    def left_recursion_message(names)
      [
        "Left recursive loop involving rules #{names.join(', ')}",
        "; no alternative consumed input."
      ]
    end
  end
end
