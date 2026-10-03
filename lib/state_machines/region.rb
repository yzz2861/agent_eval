# frozen_string_literal: true

module StateMachines
  # A Region represents a single orthogonal region within a parallel
  # (composite) state.  Each region owns an ordered set of substates and
  # tracks which of them is its initial substate.  While an object is inside
  # the parent parallel state, every region has exactly one active substate,
  # allowing independent state progress (e.g. payment vs. fulfillment) to be
  # tracked within a single state machine and a single attribute.
  class Region
    # The state machine this region is defined in
    attr_reader :machine

    # The parent parallel state this region belongs to
    attr_reader :state

    # The unique name of the region within its parent state
    attr_reader :name

    # Creates a new orthogonal region for the given parallel state
    def initialize(machine, state, name) # :nodoc:
      @machine = machine
      @state = state
      @name = name.to_sym
      @state_names = []
      @initial_state_name = nil
    end

    # Creates a copy of this region, keeping the ordered list of substates
    def initialize_copy(orig) # :nodoc:
      super
      @state_names = @state_names.dup
    end

    # Rebinds this region to a copied parent state (used when machines are
    # duplicated, e.g. for subclasses of the owner class)
    def copy_for(state) # :nodoc:
      copy = dup
      copy.instance_variable_set(:@machine, state.machine)
      copy.instance_variable_set(:@state, state)
      copy
    end

    # The ordered list of state names defined within this region
    def state_names
      @state_names.dup
    end

    # The ordered list of states defined within this region
    def states
      @state_names.map { |name| machine.states.fetch(name) }
    end

    # Adds a new substate to this region.  The first state added becomes the
    # region's initial state unless one is explicitly marked as initial.
    def add_state(name, initial: false)
      @state_names << name unless @state_names.include?(name)
      @initial_state_name = name if initial || @initial_state_name.nil?
      name
    end

    # The state this region starts in when the parent parallel state is
    # entered
    def initial_state
      machine.states.fetch(@initial_state_name)
    end

    # The name of this region's initial state
    def initial_state_name
      @initial_state_name
    end

    # Determines whether the given state name belongs to this region
    def include?(state_name)
      @state_names.include?(state_name)
    end

    # Generates a nicely formatted description of this region's contents.
    #
    # For example,
    #
    #   region  # => #<StateMachines::Region name=:payment states=[:awaiting_payment, :paid] initial=:awaiting_payment>
    def inspect
      "#<#{self.class} name=#{name.inspect} states=#{@state_names.inspect} initial=#{@initial_state_name.inspect}>"
    end
  end
end
