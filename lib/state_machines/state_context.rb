# frozen_string_literal: true

require_relative 'options_validator'

module StateMachines
  # Represents a module which will get evaluated within the context of a state.
  #
  # Class-level methods are proxied to the owner class, injecting a custom
  # <tt>:if</tt> condition along with method.  This assumes that the method has
  # support for a set of configuration options, including <tt>:if</tt>.  This
  # condition will check that the object's state matches this context's state.
  #
  # Instance-level methods are used to define state-driven behavior on the
  # state's owner class.
  #
  # == Examples
  #
  #   class Vehicle
  #     class << self
  #       attr_accessor :validations
  #
  #       def validate(options, &block)
  #         validations << options
  #       end
  #     end
  #
  #     self.validations = []
  #     attr_accessor :state, :simulate
  #
  #     def moving?
  #       self.class.validations.all? {|validation| validation[:if].call(self)}
  #     end
  #   end
  #
  # In the above class, a simple set of validation behaviors have been defined.
  # Each validation consists of a configuration like so:
  #
  #   Vehicle.validate :unless => :simulate
  #   Vehicle.validate :if => lambda {|vehicle| ...}
  #
  # In order to scope validations to a particular state context, the class-level
  # +validate+ method can be invoked like so:
  #
  #   machine = StateMachines::Machine.new(Vehicle)
  #   context = StateMachines::StateContext.new(machine.state(:first_gear))
  #   context.validate(:unless => :simulate)
  #
  #   vehicle = Vehicle.new     # => #<Vehicle:0xb7ce491c @simulate=nil, @state=nil>
  #   vehicle.moving?           # => false
  #
  #   vehicle.state = 'first_gear'
  #   vehicle.moving?           # => true
  #
  #   vehicle.simulate = true
  #   vehicle.moving?           # => false
  class StateContext < Module
    include EvalHelpers

    # The state machine for which this context's state is defined
    attr_reader :machine

    # Creates a new context for the given state
    def initialize(state)
      @state = state
      @machine = state.machine

      state_name = @state.name
      machine_name = machine.name
      @condition = ->(object) { object.class.state_machine(machine_name).states.matches?(object, state_name) }
    end

    # Creates a new transition that determines what to change the current state
    # to when an event fires from this state.
    #
    # Since this transition is being defined within a state context, you do
    # *not* need to specify the <tt>:from</tt> option for the transition.  For
    # example:
    #
    #   state_machine do
    #     state :parked do
    #       transition :to => :idling, :on => [:ignite, :shift_up]                          # Transitions to :idling
    #       transition :from => [:idling, :parked], :on => :park, :unless => :seatbelt_on?  # Transitions to :parked if seatbelt is off
    #     end
    #   end
    #
    # See StateMachines::Machine#transition for a description of the possible
    # configurations for defining transitions.
    def transition(options)
      StateMachines::OptionsValidator.assert_valid_keys!(options, :from, :to, :on, :if, :unless)
      raise ArgumentError, 'Must specify :on event' unless options[:on]
      raise ArgumentError, 'Must specify either :to or :from state' unless !options[:to] ^ !options[:from]

      machine.transition(options.merge(options[:to] ? { from: @state.name } : { to: @state.name }))
    end

    # Defines callbacks invoked when this state is entered.
    def enter(*callbacks, &block)
      @state.enter(*callbacks, &block)
    end

    # Defines callbacks invoked when this state is exited.
    def exit(*callbacks, &block)
      @state.exit(*callbacks, &block)
    end

    # Declares a nested state. A block with no parameters keeps the existing
    # behavior DSL; a block with one parameter opens the nested state DSL.
    def state(*names, &block)
      return @state if names.empty?

      name = names.first
      options = names.length > 1 && names.last.is_a?(Hash) ? names.pop : {}
      options = options.merge(parent: @state.name)
      child = machine.state(name, options)
      nested_context(child, &block) if block
      child
    end

    alias other_states state

    # Defines an event available to this state and its descendants.
    def event(name, options = {}, &block)
      previous_scope_depth = machine.instance_variable_get(:@state_scope_depth)
      machine.instance_variable_set(:@state_scope_depth, @state.depth + 1)
      machine.event(name, options, &block)
    ensure
      machine.instance_variable_set(:@state_scope_depth, previous_scope_depth)
    end

    alias on event

    # Hooks in condition-merging to methods that don't exist in this module
    def method_missing(*args, &)
      # Get the configuration
      if args.last.is_a?(Hash)
        options = args.last
      else
        args << options = {}
      end

      # Get any existing condition that may need to be merged
      if_condition = options.delete(:if)
      unless_condition = options.delete(:unless)

      # Provide scope access to configuration in case the block is evaluated
      # within the object instance
      proxy = self
      proxy_condition = @condition

      # Replace the configuration condition with the one configured for this
      # proxy, merging together any existing conditions
      options[:if] = lambda do |*condition_args|
        # Block may be executed within the context of the actual object, so
        # it'll either be the first argument or the executing context
        object = condition_args.first || self

        proxy.evaluate_method(object, proxy_condition) &&
          Array(if_condition).all? { |condition| proxy.evaluate_method(object, condition) } &&
          !Array(unless_condition).any? { |condition| proxy.evaluate_method(object, condition) }
      end

      # Evaluate the method on the owner class with the condition proxied
      # through
      machine.owner_class.send(*args, &)
    end

    private

    def nested_context(child, &block)
      if block.arity.zero?
        child.context(&block)
      else
        block.call(NestedStateContext.new(child))
      end
    end
  end

  # DSL used while declaring nested states and their parent-scoped events.
  class NestedStateContext < StateContext
    def state(*names, &block)
      return @state if names.empty?

      name = names.first
      options = names.length > 1 && names.last.is_a?(Hash) ? names.pop : {}
      options = options.merge(parent: @state.name)
      child = machine.state(name, options)
      nested_context(child, &block) if block
      child
    end

    def transition(options)
      options = options.dup
      options[:from] = @state.name unless options.key?(:from)
      machine.transition(options)
    end

    private

    def nested_context(child, &block)
      block.call(NestedStateContext.new(child))
    end
  end
end
