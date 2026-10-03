# frozen_string_literal: true

require_relative 'options_validator'

module StateMachines
  # Evaluates the block given to StateMachines::Machine#parallel_state.  The
  # block defines the orthogonal regions of a parallel (composite) state and,
  # optionally, the completion event that gets fired once every region has
  # reached a final state.
  #
  # == Example
  #
  #   parallel_state :processing do
  #     region :payment do
  #       state :awaiting_payment, initial: true
  #       state :paid
  #     end
  #
  #     region :fulfillment do
  #       state :awaiting_stock, initial: true
  #       state :shipped
  #     end
  #
  #     on_complete :complete_processing
  #   end
  class ParallelStateContext
    # The state machine the parallel state is defined in
    attr_reader :machine

    # The parallel (composite) state being configured
    attr_reader :state

    def initialize(machine, state) # :nodoc:
      @machine = machine
      @state = state
    end

    # Defines a new orthogonal region within the parallel state.  Regions are
    # evaluated -- and their transitions performed -- in the order in which
    # they are defined.
    def region(name, &block)
      raise ArgumentError, 'Must specify a block defining the region states' unless block

      region = Region.new(machine, state, name)
      if state.regions.any? { |existing| existing.name == region.name }
        raise ArgumentError, "Region #{name.inspect} is already defined for state #{state.name.inspect}"
      end

      RegionContext.new(machine, region).instance_eval(&block)

      raise ArgumentError, "Region #{name.inspect} must define at least one state" if region.state_names.empty?

      state.regions << region
      region
    end

    # Configures the event that is fired automatically once every region of
    # the parallel state has reached a final state.  The event must be
    # defined separately on the machine, typically transitioning away from
    # the parallel state.
    def on_complete(event_name)
      state.completion_event = event_name.to_sym
    end
  end

  # Evaluates the block given to ParallelStateContext#region, registering
  # each substate both in the region and in the machine's global state
  # collection so that transitions, callbacks, and predicates can reference
  # them like any other state.
  class RegionContext
    # The state machine the region is defined in
    attr_reader :machine

    # The region being configured
    attr_reader :region

    def initialize(machine, region) # :nodoc:
      @machine = machine
      @region = region
    end

    # Defines a substate within this region.  Accepts the same options as
    # StateMachines::Machine#state, plus:
    # * <tt>:initial</tt> - Whether this is the region's initial substate.
    #   Default is the first state defined in the region.
    def state(name, options = {})
      StateMachines::OptionsValidator.assert_valid_keys!(options, :initial, :value, :cache, :if, :human_name)
      initial = options.delete(:initial) { false }

      region.add_state(name, initial: initial)
      machine.state(name, options)
    end
  end
end
