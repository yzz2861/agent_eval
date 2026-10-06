module Parslet::Atoms
  class LeftRecursionHead
    attr_accessor :seed, :best, :names, :position

    def initialize(names, position)
      @names = names
      @position = position
      @seed = nil
      @best = nil
    end
  end

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
      @left_recursive_heads = {}
      @active_entities = []
    end

    ACTIVE_ENTITY = :active_entity
    LEFT_RECURSION_PENDING = :left_recursion_pending

    def try_entity(entity, source, consume_all)
      position = source.bytepos
      id = cache_key(entity)

      if entry = lookup(entity, position)
        unless entry == ACTIVE_ENTITY
          if entry == LEFT_RECURSION_PENDING
            active_head(position).names |= active_chain_names
          end
          return replay(entity, source, position, entry)
        end
      end

      head = @left_recursive_heads[head_key(id, position)]
      if head && head.seed
        return replay_result(entity, source, position, head.seed)
      end

      if entity.left_recursive
        return invoke_left_recursive(entity, source, position, id)
      end

      pending_head = active_head(position)
      if pending_head
        return track_entity(entity) do
          set(entity, position, LEFT_RECURSION_PENDING)
          begin
            evaluate_entity(entity, source, false, false)
          ensure
            set(entity, position, LEFT_RECURSION_PENDING)
          end
        end
      end

      evaluate_entity(entity, source, consume_all, true)
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
      return obj.try(source, self, consume_all) if obj.is_a?(Entity)
        
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
    
  private 
    def invoke_left_recursive(entity, source, position, id)
      key = head_key(id, position)
      existing_head = @left_recursive_heads[key]
      if existing_head
        existing_head.names |= active_chain_names
        return replay_result(entity, source, position, existing_head.seed) if existing_head.seed
        return left_recursion_failure(entity, source, position, existing_head)
      end

      head = LeftRecursionHead.new(active_chain_names + [entity.name], position)
      @left_recursive_heads[key] = head
      begin
        result = track_entity(entity) do
          set(entity, position, ACTIVE_ENTITY)
          evaluate_entity_with_isolated_memo(entity, source, position)
        end
        head.seed = [result, source.bytepos - position]

        if !result.first
          failure = left_recursion_failure(entity, source, position, head)
          set(entity, position, [failure, 0])
          return failure
        end

        loop do
          source.bytepos = position
          set(entity, position, ACTIVE_ENTITY)
          result = track_entity(entity) do
            evaluate_entity_with_isolated_memo(entity, source, position)
          end
          new_advance = source.bytepos - position

          break unless result.first && new_advance > advance_of(head.best)

          head.best = [result, new_advance]
          head.seed = head.best
        end

        set(entity, position, head.best)
        replay_result(entity, source, position, head.best)
      ensure
        @left_recursive_heads.delete(key)
      end
    end

    def evaluate_entity(entity, source, consume_all, cache_result)
      beg = source.bytepos
      result = entity.parslet.apply(source, self, consume_all)
      if cache_result && entity.cached?
        set(entity, beg, [result, source.bytepos - beg])
      end
      result
    end

    def evaluate_entity_with_isolated_memo(entity, source, position)
      snapshot = @cache[position].dup
      result = evaluate_entity(entity, source, false, false)
    ensure
      @cache[position] = snapshot
      set(entity, position, ACTIVE_ENTITY)
      result
    end

    def replay(entity, source, position, entry)
      if entry == LEFT_RECURSION_PENDING
        return left_recursion_failure(entity, source, position, active_head(position))
      end

      replay_result(entity, source, position, entry)
    end

    def replay_result(entity, source, position, entry)
      result, advance = entry
      source.bytepos = position + advance
      result
    end

    def active_head(position)
      @left_recursive_heads.values.detect do |head|
        head.position == position
      end
    end

    def active_chain_names
      @active_entities.map { |entity| entity.name }
    end

    def track_entity(entity)
      @active_entities.push(entity)
      yield
    ensure
      @active_entities.pop
    end

    def left_recursion_failure(entity, source, position, head)
      names = (head.names + [entity.name]).uniq.map do |name|
        name.to_s.upcase
      end.join(', ')
      message = "Left recursion in #{names} did not consume input"
      source.bytepos = position
      err(entity, source, message)
    end

    def advance_of(entry)
      entry ? entry.last : -1
    end

    def head_key(id, position)
      [id, position]
    end

    # NOTE These methods use #object_id directly, since that seems to bring the
    # most performance benefit. This is a hot spot; going through
    # Atoms::Base#hash doesn't yield as much.
    #
    def lookup(obj, pos)
      @cache[pos][cache_key(obj)]
    end
    def set(obj, pos, val)
      @cache[pos][cache_key(obj)] = val
    end
    def cache_key(obj)
      obj.is_a?(Entity) ? [:entity, obj.cache_key] : obj.object_id
    end
  end
end
