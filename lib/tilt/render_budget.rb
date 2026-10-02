# frozen_string_literal: true

module Tilt
  # Fiber-local key used to track the active render budget.
  # @private
  RENDER_BUDGET_KEY = :tilt_render_budget

  # Fiber-local key used to track the active template call chain.
  # @private
  RENDER_BUDGET_CHAIN_KEY = :tilt_render_budget_chain

  # Default upper bound on the number of call-chain entries attached to a
  # {RenderBudgetExceeded} exception, so error messages stay bounded even
  # when a very deep render is attempted.
  DEFAULT_MAX_CHAIN_ENTRIES = 20

  # Raised when a render would exceed the active {RenderBudget}.
  #
  # The exception exposes the budget that was exceeded, which limit was
  # reached (+:depth+ or +:renders+), and a bounded snapshot of the template
  # call chain.
  class RenderBudgetExceeded < StandardError
    # @return [RenderBudget] the budget that was exceeded
    attr_reader :budget

    # @return [Symbol] +:depth+ when the nesting depth limit was reached,
    #   +:renders+ when the cumulative render count limit was reached
    attr_reader :reason

    # @return [Array<String>] bounded snapshot of the template call chain,
    #   outermost call first
    attr_reader :call_chain

    def initialize(message = nil, budget:, reason:, call_chain:) # :nodoc:
      @budget = budget
      @reason = reason
      @call_chain = call_chain.dup
      super(message || default_message)
    end

    private

    def default_message
      limit = reason == :depth ? budget.max_depth : budget.max_renders
      "Tilt render budget exceeded (#{reason} limit of #{limit} reached): " \
        "#{call_chain.join(' -> ')}"
    end
  end

  # An optional rendering budget shared across a single render chain.
  #
  # A RenderBudget bounds two independent dimensions of template rendering:
  #
  # * +max_depth+   - how deeply template renders may nest (via +yield+,
  #    nested +#render+ calls, and pipeline stages). Depth is returned on
  #    every exit, including exceptional exits.
  # * +max_renders+ - the cumulative number of template renders across the
  #    whole chain. This counter only ever increases while the budget is
  #    active, so repeatedly entering and leaving renders cannot reset it.
  #
  # Budget state is tracked per Fiber, so concurrent Fibers render against
  # independent chains by default. The same RenderBudget instance may be
  # shared explicitly (e.g. passed into another Fiber); in that case the
  # cumulative render count is shared and protected by a mutex, while each
  # Fiber still keeps its own nesting depth.
  #
  # Activate a budget with {Tilt.with_render_budget}:
  #
  #   budget = Tilt::RenderBudget.new(max_depth: 10, max_renders: 100)
  #   Tilt.with_render_budget(budget) do
  #     template.render
  #   end
  class RenderBudget
    # Maximum permitted nesting depth, or +nil+ when unlimited.
    attr_reader :max_depth

    # Maximum permitted cumulative number of renders, or +nil+ when
    # unlimited.
    attr_reader :max_renders

    # Cumulative number of renders recorded while the budget has been
    # active. Never decreases.
    attr_reader :render_count

    # @param max_depth [Integer, nil] maximum nesting depth for a single
    #   render chain (+nil+ means unlimited)
    # @param max_renders [Integer, nil] maximum cumulative number of
    #   template renders (+nil+ means unlimited)
    # @param max_chain_entries [Integer] maximum number of call-chain
    #   entries attached when {RenderBudgetExceeded} is raised
    def initialize(max_depth: nil, max_renders: nil,
                   max_chain_entries: DEFAULT_MAX_CHAIN_ENTRIES)
      @max_depth = validate_limit(:max_depth, max_depth)
      @max_renders = validate_limit(:max_renders, max_renders)
      @max_chain_entries = validate_positive_limit(:max_chain_entries,
                                                   max_chain_entries)

      if @max_depth.nil? && @max_renders.nil?
        raise ArgumentError,
              'RenderBudget requires at least one of max_depth or ' \
              'max_renders to be set'
      end

      @render_count = 0
      @mutex = Mutex.new
    end

    # Current nesting depth in the running Fiber.
    #
    # @return [Integer]
    def current_depth
      chain.length
    end

    # Record entering a template render. Raises {RenderBudgetExceeded}
    # before any state is recorded when a limit would be exceeded.
    #
    # @return [void]
    # @api private
    def enter!(template)
      label = template_label(template)

      next_chain = nil
      @mutex.synchronize do
        current_chain = chain
        candidate_chain = current_chain + [label]

        if @max_depth && candidate_chain.length > @max_depth
          raise_exceeded(:depth, candidate_chain)
        end

        if @max_renders && @render_count + 1 > @max_renders
          raise_exceeded(:renders, candidate_chain)
        end

        @render_count += 1
        next_chain = candidate_chain
      end

      Thread.current[RENDER_BUDGET_CHAIN_KEY] = next_chain
      nil
    end

    # Record leaving a template render, restoring the previous depth. Must
    # be called exactly once for every successful {#enter!}, including when
    # rendering raises.
    #
    # @return [void]
    # @api private
    def leave!
      @mutex.synchronize do
        current = chain
        Thread.current[RENDER_BUDGET_CHAIN_KEY] = current[0...-1]
      end
      nil
    end

    private

    def validate_limit(name, value)
      return nil if value.nil?

      unless value.respond_to?(:to_int)
        raise TypeError, "#{name} must be an Integer"
      end

      value = value.to_int
      if value < 0
        raise ArgumentError, "#{name} cannot be negative"
      end

      value
    end

    def validate_positive_limit(name, value)
      value = validate_limit(name, value) || DEFAULT_MAX_CHAIN_ENTRIES
      if value < 1
        raise ArgumentError, "#{name} must be at least 1"
      end

      value
    end

    def chain
      Thread.current[RENDER_BUDGET_CHAIN_KEY] || []
    end

    def template_label(template)
      file = template.respond_to?(:eval_file) ? template.eval_file : nil
      return file if file && file != '(__TEMPLATE__)'

      template.class.name || template.class.inspect
    end

    def raise_exceeded(reason, full_chain)
      bounded = if full_chain.length > @max_chain_entries
                  ['...'] + full_chain.last(@max_chain_entries - 1)
                else
                  full_chain
                end

      raise RenderBudgetExceeded.new(nil,
                                     budget: self,
                                     reason: reason,
                                     call_chain: bounded)
    end
  end
end
