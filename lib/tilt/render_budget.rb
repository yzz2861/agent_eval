module Tilt
  # Raised when a RenderBudget limit is exceeded while rendering templates.
  class RenderBudgetExceeded < StandardError
    # Maximum number of render chain entries kept in the exception. The
    # chain is truncated to this length so the exception stays small even
    # when the budget allows very deep render chains.
    CHAIN_LIMIT = 32

    # The budget whose limit was exceeded.
    attr_reader :budget

    # Which limit was exceeded, +:depth+ or +:renders+.
    attr_reader :limit

    # The render chain at the point the budget was exceeded, as an array
    # of template identifiers (outermost first). Truncated to CHAIN_LIMIT
    # entries, with a trailing '...' entry if truncation occurred.
    attr_reader :chain

    def initialize(budget, limit, chain)
      @budget = budget
      @limit = limit
      @chain = chain.length > CHAIN_LIMIT ? chain.first(CHAIN_LIMIT) + ['...'] : chain
      detail = if limit == :depth
        "depth #{budget.depth} exceeds max_depth #{budget.max_depth}"
      else
        "render count #{budget.renders} exceeds max_renders #{budget.max_renders}"
      end
      super("Tilt render budget exceeded: #{detail} (chain: #{@chain.join(' -> ')})")
    end
  end

  # An optional budget limiting a single render chain. A budget limits both
  # the nesting depth of Template#render calls and the cumulative number of
  # template renders, and applies across pipeline stages and nested renders
  # (including indirect recursion through blocks/yield).
  #
  # Budgets are not active by default. Activate one for the current fiber
  # with #with:
  #
  #   Tilt::RenderBudget.new(max_depth: 16, max_renders: 100).with do
  #     template.render
  #   end
  #
  # Each fiber has its own current budget, so concurrent fibers are
  # accounted independently. To share a single budget between fibers (or
  # separate render calls), activate the same RenderBudget instance in
  # each place. A shared budget should only be used from a single thread.
  #
  # When a limit is exceeded, RenderBudgetExceeded is raised. Depth is
  # returned when renders exit (normally or via exception), but the
  # cumulative render count is never decremented, so it cannot be bypassed
  # by repeatedly entering and exiting renders.
  class RenderBudget
    # Maximum allowed nesting depth of Template#render calls, or nil.
    attr_reader :max_depth

    # Maximum allowed cumulative number of Template#render calls, or nil.
    attr_reader :max_renders

    # Current render nesting depth.
    attr_reader :depth

    # Cumulative number of renders entered. Never decremented.
    attr_reader :renders

    def initialize(max_depth: nil, max_renders: nil)
      unless max_depth || max_renders
        raise ArgumentError, 'max_depth and/or max_renders required'
      end

      [max_depth, max_renders].compact.each do |limit|
        unless limit.is_a?(Integer) && limit >= 0
          raise ArgumentError, "render budget limits must be non-negative integers: #{limit.inspect}"
        end
      end

      @max_depth = max_depth
      @max_renders = max_renders
      @depth = 0
      @renders = 0
      @chain = []
    end

    # The budget currently active for the calling fiber, if any.
    def self.current
      Thread.current[:tilt_render_budget]
    end

    # Activate the given budget for the calling fiber while running the
    # block, restoring the previously active budget afterwards. The budget
    # may be nil to temporarily disable budgeting.
    def self.with(budget)
      previous = Thread.current[:tilt_render_budget]
      begin
        Thread.current[:tilt_render_budget] = budget
        yield
      ensure
        Thread.current[:tilt_render_budget] = previous
      end
    end

    # Activate this budget for the calling fiber while running the block.
    def with(&block)
      RenderBudget.with(self, &block)
    end

    # @private
    # Record entry into a template render, raising RenderBudgetExceeded if
    # a limit is exceeded. Called by Template#render.
    def enter(template)
      @renders += 1
      @depth += 1
      @chain << template.eval_file

      if (limit = exceeded_limit)
        error = RenderBudgetExceeded.new(self, limit, @chain.dup)
        @depth -= 1
        @chain.pop
        raise error
      end

      nil
    end

    # @private
    # Record exit from a template render. Returns the depth, but never
    # decrements the cumulative render count. Called by Template#render.
    def exit
      @depth -= 1
      @chain.pop
      nil
    end

    private

    def exceeded_limit
      return :depth if @max_depth && @depth > @max_depth
      return :renders if @max_renders && @renders > @max_renders
      nil
    end
  end
end

